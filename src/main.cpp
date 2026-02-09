#include <algorithm>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <optional>
#include <poll.h>
#include <string_view>
#include <sys/wait.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "cli.hpp"
#include "color.hpp"
#include "output.hpp"
#include "scanner.hpp"
#include "util.hpp"

namespace {

using klint::Scanner;
using klint::ScanResult;
using klint::Severity;
using klint::output::ReportStatus;

constexpr std::size_t kMaxScannerPayloadBytes =
    static_cast<std::size_t>(8) * 1024 * 1024;

ScanResult run_scanner_safe(const Scanner &scanner) {
  try {
    return scanner.func();
  } catch (const std::exception &ex) {
    ScanResult result;
    result.add_error(std::string("exception: ") + ex.what());
    return result;
  } catch (...) {
    ScanResult result;
    result.add_error("exception: unknown");
    return result;
  }
}

std::string errno_message(const std::string &prefix) {
  return prefix + ": " + std::strerror(errno);
}

bool set_nonblocking(int fd) {
  int flags = ::fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    return false;
  }
  return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

bool write_all(int fd, std::string_view data) {
  std::size_t written = 0;
  while (written < data.size()) {
    ssize_t n = ::write(fd, data.data() + written, data.size() - written);
    if (n > 0) {
      written += static_cast<std::size_t>(n);
      continue;
    }
    if (n == -1 && errno == EINTR) {
      continue;
    }
    return false;
  }
  return true;
}

bool drain_fd_nonblocking(int fd, std::string &out, bool &eof,
                          std::string &error, std::size_t max_capture_bytes) {
  char buffer[4096];
  while (true) {
    ssize_t n = ::read(fd, buffer, sizeof(buffer));
    if (n > 0) {
      std::size_t chunk = static_cast<std::size_t>(n);
      if (chunk > max_capture_bytes || out.size() > max_capture_bytes - chunk) {
        error = "scanner payload exceeded capture limit (" +
                std::to_string(max_capture_bytes) + " bytes)";
        return false;
      }
      out.append(buffer, chunk);
      continue;
    }
    if (n == 0) {
      eof = true;
      return true;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return true;
    }
    error = errno_message("read scanner payload");
    return false;
  }
}

std::optional<Severity> parse_severity(std::string_view text) {
  if (text == "info") {
    return Severity::Info;
  }
  if (text == "warning") {
    return Severity::Warning;
  }
  if (text == "critical") {
    return Severity::Critical;
  }
  return std::nullopt;
}

std::optional<pid_t> parse_ppid_from_stat(std::string_view stat_line) {
  std::size_t close_paren = stat_line.rfind(')');
  if (close_paren == std::string_view::npos ||
      close_paren + 2 >= stat_line.size()) {
    return std::nullopt;
  }

  std::size_t pos = close_paren + 2;
  if (pos >= stat_line.size()) {
    return std::nullopt;
  }
  ++pos;

  while (pos < stat_line.size() &&
         std::isspace(static_cast<unsigned char>(stat_line[pos]))) {
    ++pos;
  }
  if (pos >= stat_line.size()) {
    return std::nullopt;
  }

  std::size_t start = pos;
  while (pos < stat_line.size() &&
         !std::isspace(static_cast<unsigned char>(stat_line[pos]))) {
    ++pos;
  }
  if (start == pos) {
    return std::nullopt;
  }

  int ppid = 0;
  auto [ptr, ec] =
      std::from_chars(stat_line.data() + start, stat_line.data() + pos, ppid);
  if (ec != std::errc{} || ptr != stat_line.data() + pos || ppid <= 0) {
    return std::nullopt;
  }
  return static_cast<pid_t>(ppid);
}

std::optional<pid_t> read_ppid(pid_t pid) {
  auto stat_data =
      klint::util::read_file("/proc/" + std::to_string(pid) + "/stat");
  if (!stat_data) {
    return std::nullopt;
  }
  return parse_ppid_from_stat(*stat_data);
}

std::vector<pid_t> collect_descendants(pid_t root) {
  std::unordered_map<pid_t, std::vector<pid_t>> children;
  DIR *proc_dir = ::opendir("/proc");
  if (!proc_dir) {
    return {};
  }

  while (true) {
    errno = 0;
    dirent *entry = ::readdir(proc_dir);
    if (!entry) {
      break;
    }

    std::string_view name(entry->d_name);
    if (name.empty()) {
      continue;
    }

    int pid_value = 0;
    auto [ptr, ec] =
        std::from_chars(name.data(), name.data() + name.size(), pid_value);
    if (ec != std::errc{} || ptr != name.data() + name.size() ||
        pid_value <= 0) {
      continue;
    }

    pid_t pid = static_cast<pid_t>(pid_value);
    if (pid == root) {
      continue;
    }
    auto ppid = read_ppid(pid);
    if (!ppid) {
      continue;
    }
    children[*ppid].push_back(pid);
  }

  ::closedir(proc_dir);

  std::vector<pid_t> descendants;
  std::vector<pid_t> stack = {root};
  while (!stack.empty()) {
    pid_t current = stack.back();
    stack.pop_back();

    auto it = children.find(current);
    if (it == children.end()) {
      continue;
    }
    for (pid_t child : it->second) {
      descendants.push_back(child);
      stack.push_back(child);
    }
  }
  return descendants;
}

void kill_descendants(pid_t root) {
  auto descendants = collect_descendants(root);
  for (pid_t pid : descendants) {
    if (::getpgid(pid) == pid) {
      (void)::kill(-pid, SIGKILL);
    }
  }
  for (pid_t pid : descendants) {
    (void)::kill(pid, SIGKILL);
  }
}

nlohmann::json scan_result_to_json(const ScanResult &result) {
  nlohmann::json root;
  root["findings"] = nlohmann::json::array();
  for (const auto &finding : result.findings) {
    nlohmann::json finding_json;
    finding_json["severity"] = std::string(klint::to_string(finding.severity));
    finding_json["summary"] = finding.summary;
    if (finding.detail) {
      finding_json["detail"] = *finding.detail;
    }
    if (!finding.evidence.empty()) {
      nlohmann::json evidence_json = nlohmann::json::array();
      for (const auto &evidence : finding.evidence) {
        evidence_json.push_back(
            {{"key", evidence.first}, {"value", evidence.second}});
      }
      finding_json["evidence"] = std::move(evidence_json);
    }
    root["findings"].push_back(std::move(finding_json));
  }

  root["errors"] = nlohmann::json::array();
  for (const auto &error : result.errors) {
    root["errors"].push_back(error);
  }
  return root;
}

std::optional<ScanResult> scan_result_from_json(const nlohmann::json &root,
                                                std::string &error) {
  if (!root.is_object()) {
    error = "scanner payload is not a JSON object";
    return std::nullopt;
  }

  auto findings_it = root.find("findings");
  auto errors_it = root.find("errors");
  if (findings_it == root.end() || !findings_it->is_array() ||
      errors_it == root.end() || !errors_it->is_array()) {
    error = "scanner payload is missing findings/errors arrays";
    return std::nullopt;
  }

  ScanResult result;
  for (const auto &entry : *findings_it) {
    if (!entry.is_object()) {
      error = "scanner payload finding is not an object";
      return std::nullopt;
    }

    auto summary_it = entry.find("summary");
    auto severity_it = entry.find("severity");
    if (summary_it == entry.end() || !summary_it->is_string() ||
        severity_it == entry.end() || !severity_it->is_string()) {
      error = "scanner payload finding is missing summary/severity";
      return std::nullopt;
    }

    auto severity = parse_severity(severity_it->get<std::string>());
    if (!severity) {
      error = "scanner payload contains an unknown severity";
      return std::nullopt;
    }

    klint::Finding finding(*severity, summary_it->get<std::string>());

    auto detail_it = entry.find("detail");
    if (detail_it != entry.end()) {
      if (!detail_it->is_string()) {
        error = "scanner payload detail is not a string";
        return std::nullopt;
      }
      finding.with_detail(detail_it->get<std::string>());
    }

    auto evidence_it = entry.find("evidence");
    if (evidence_it != entry.end()) {
      if (!evidence_it->is_array()) {
        error = "scanner payload evidence is not an array";
        return std::nullopt;
      }
      for (const auto &item : *evidence_it) {
        if (!item.is_object()) {
          error = "scanner payload evidence item is not an object";
          return std::nullopt;
        }
        auto key_it = item.find("key");
        auto value_it = item.find("value");
        if (key_it == item.end() || !key_it->is_string() ||
            value_it == item.end() || !value_it->is_string()) {
          error = "scanner payload evidence item is missing key/value";
          return std::nullopt;
        }
        finding.with_evidence(key_it->get<std::string>(),
                              value_it->get<std::string>());
      }
    }

    result.add_finding(std::move(finding));
  }

  for (const auto &entry : *errors_it) {
    if (!entry.is_string()) {
      error = "scanner payload error entry is not a string";
      return std::nullopt;
    }
    result.add_error(entry.get<std::string>());
  }

  return result;
}

[[noreturn]] void scanner_child_main(const Scanner &scanner, int payload_fd) {
  try {
    ScanResult result = run_scanner_safe(scanner);
    nlohmann::json payload = scan_result_to_json(result);
    std::string serialized = payload.dump();
    if (!write_all(payload_fd, serialized)) {
      ::close(payload_fd);
      _exit(125);
    }
    ::close(payload_fd);
    _exit(0);
  } catch (...) {
    ::close(payload_fd);
    _exit(125);
  }
}

void kill_scanner_process_tree(pid_t pid) {
  if (pid <= 0) {
    return;
  }
  kill_descendants(pid);
  if (::getpgid(pid) == pid) {
    (void)::kill(-pid, SIGKILL);
  }
  (void)::kill(pid, SIGKILL);
}

enum class TimedRunStatus {
  Completed,
  Timeout,
  Failed,
};

struct TimedRunResult {
  TimedRunStatus status = TimedRunStatus::Failed;
  std::optional<ScanResult> result;
  std::string error;
};

TimedRunResult run_with_timeout(const Scanner &scanner,
                                std::chrono::seconds timeout) {
  TimedRunResult outcome;
  try {
    int result_pipe[2];
    if (::pipe2(result_pipe, O_CLOEXEC) != 0) {
      outcome.error = errno_message("pipe2");
      return outcome;
    }

    pid_t pid = ::fork();
    if (pid == -1) {
      outcome.error = errno_message("fork");
      ::close(result_pipe[0]);
      ::close(result_pipe[1]);
      return outcome;
    }

    if (pid == 0) {
      ::close(result_pipe[0]);
      (void)::setpgid(0, 0);
      scanner_child_main(scanner, result_pipe[1]);
    }

    ::close(result_pipe[1]);
    (void)::setpgid(pid, pid);

    if (!set_nonblocking(result_pipe[0])) {
      outcome.error = errno_message("fcntl O_NONBLOCK");
      kill_scanner_process_tree(pid);
      int status = 0;
      while (::waitpid(pid, &status, 0) == -1 && errno == EINTR) {
      }
      ::close(result_pipe[0]);
      return outcome;
    }

    std::string payload;
    bool eof = false;
    int status = 0;
    bool child_reaped = false;
    auto deadline = std::chrono::steady_clock::now() + timeout;

    while (true) {
      std::string read_error;
      if (!drain_fd_nonblocking(result_pipe[0], payload, eof, read_error,
                                kMaxScannerPayloadBytes)) {
        outcome.error = std::move(read_error);
        kill_scanner_process_tree(pid);
        if (!child_reaped) {
          while (::waitpid(pid, &status, 0) == -1 && errno == EINTR) {
          }
        }
        ::close(result_pipe[0]);
        return outcome;
      }

      if (!child_reaped) {
        pid_t waited = ::waitpid(pid, &status, WNOHANG);
        if (waited == pid) {
          child_reaped = true;
        } else if (waited == -1) {
          if (errno == EINTR) {
            continue;
          }
          outcome.error = errno_message("waitpid");
          kill_scanner_process_tree(pid);
          while (::waitpid(pid, &status, 0) == -1 && errno == EINTR) {
          }
          ::close(result_pipe[0]);
          return outcome;
        }
      }

      if (child_reaped && eof) {
        break;
      }

      auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        kill_scanner_process_tree(pid);
        if (!child_reaped) {
          while (::waitpid(pid, &status, 0) == -1 && errno == EINTR) {
          }
        }
        ::close(result_pipe[0]);
        outcome.status = TimedRunStatus::Timeout;
        return outcome;
      }

      auto remaining =
          std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
      int wait_ms =
          static_cast<int>(std::min<std::chrono::milliseconds>(
                               remaining, std::chrono::milliseconds(50))
                               .count());
      if (wait_ms < 0) {
        wait_ms = 0;
      }

      pollfd pfd = {};
      pfd.fd = result_pipe[0];
      pfd.events = POLLIN | POLLHUP;
      int poll_result = ::poll(&pfd, 1, wait_ms);
      if (poll_result == -1 && errno != EINTR) {
        outcome.error = errno_message("poll");
        kill_scanner_process_tree(pid);
        while (::waitpid(pid, &status, 0) == -1 && errno == EINTR) {
        }
        ::close(result_pipe[0]);
        return outcome;
      }
    }

    if (!child_reaped) {
      while (::waitpid(pid, &status, 0) == -1 && errno == EINTR) {
      }
    }
    ::close(result_pipe[0]);

    if (!WIFEXITED(status)) {
      if (WIFSIGNALED(status)) {
        outcome.error = "scanner process terminated by signal " +
                        std::to_string(static_cast<int>(WTERMSIG(status)));
      } else {
        outcome.error = "scanner process did not exit cleanly";
      }
      return outcome;
    }
    if (WEXITSTATUS(status) != 0) {
      outcome.error = "scanner process exited with code " +
                      std::to_string(static_cast<int>(WEXITSTATUS(status)));
      return outcome;
    }

    if (payload.empty()) {
      outcome.error = "scanner process produced empty payload";
      return outcome;
    }

    nlohmann::json parsed = nlohmann::json::parse(payload, nullptr, false);
    if (parsed.is_discarded()) {
      outcome.error = "scanner process produced invalid payload";
      return outcome;
    }

    std::string parse_error;
    auto result = scan_result_from_json(parsed, parse_error);
    if (!result) {
      outcome.error = std::move(parse_error);
      return outcome;
    }

    outcome.status = TimedRunStatus::Completed;
    outcome.result = std::move(*result);
    return outcome;
  } catch (const std::exception &ex) {
    outcome.error =
        std::string("timeout orchestration exception: ") + ex.what();
    return outcome;
  } catch (...) {
    outcome.error = "timeout orchestration exception: unknown";
    return outcome;
  }
}

} // namespace

int main(int argc, char **argv) {
  try {
    auto parsed = klint::cli::parse_args(argc, argv);
    if (!parsed) {
      std::cerr << parsed.error() << "\n";
      return 2;
    }

    klint::cli::Options options = std::move(parsed.value());

    if (options.help) {
      std::cout << klint::cli::usage(argv[0]);
      return 0;
    }

    klint::color::init(options.no_color ||
                       options.mode == klint::cli::OutputMode::Json);

    auto scanners = klint::registry();

    if (options.list) {
      klint::output::print_scanner_list(scanners);
      return 0;
    }

    std::unordered_set<std::string> known;
    known.reserve(scanners.size());
    for (const auto *scanner : scanners) {
      known.emplace(scanner->name);
    }

    auto validate_names = [&](const std::vector<std::string> &names) -> bool {
      for (const auto &name : names) {
        if (!known.contains(name)) {
          std::cerr << "Unknown scanner: " << name << "\n";
          return false;
        }
      }
      return true;
    };

    if (!validate_names(options.include_scanners) ||
        !validate_names(options.exclude_scanners)) {
      return 2;
    }

    std::unordered_set<std::string> include_set(
        options.include_scanners.begin(), options.include_scanners.end());
    std::unordered_set<std::string> exclude_set(
        options.exclude_scanners.begin(), options.exclude_scanners.end());

    if (::geteuid() != 0) {
      std::cerr << "klint must be run as root.\n";
      return 2;
    }

    std::vector<klint::output::ScannerReport> reports;
    bool any_findings = false;
    bool any_errors_or_timeouts = false;

    for (const auto *scanner : scanners) {
      std::string name(scanner->name);

      if (!include_set.empty() && !include_set.contains(name)) {
        continue;
      }
      if (exclude_set.contains(name)) {
        continue;
      }

      klint::output::ScannerReport report;
      report.scanner = name;
      report.categories.reserve(scanner->categories.size());
      for (auto category : scanner->categories) {
        report.categories.emplace_back(klint::to_string(category));
      }

      auto unmet = scanner->unmet_requirements();
      if (!unmet.empty()) {
        report.status = ReportStatus::Skipped;
        report.skip_reason = klint::util::join(unmet, ", ");
      } else {
        auto run = run_with_timeout(
            *scanner, std::chrono::seconds(options.timeout_seconds));
        if (run.status == TimedRunStatus::Timeout) {
          report.status = ReportStatus::Timeout;
        } else if (run.status == TimedRunStatus::Completed && run.result) {
          report.result = std::move(*run.result);
          bool has_errors = report.result->has_errors();
          bool has_findings = report.result->has_findings();
          if (has_errors) {
            report.status = ReportStatus::Error;
          } else if (has_findings) {
            report.status = ReportStatus::Findings;
          } else {
            report.status = ReportStatus::Clean;
          }
          any_findings = any_findings || has_findings;
          any_errors_or_timeouts = any_errors_or_timeouts || has_errors;
        } else {
          report.status = ReportStatus::Error;
          report.result = ScanResult{};
          if (!run.error.empty()) {
            report.result->add_error(std::move(run.error));
          } else {
            report.result->add_error("scanner execution failed");
          }
          any_errors_or_timeouts = true;
        }
      }

      switch (report.status) {
      case ReportStatus::Findings:
        any_findings = true;
        break;
      case ReportStatus::Error:
      case ReportStatus::Timeout:
        any_errors_or_timeouts = true;
        break;
      case ReportStatus::Clean:
      case ReportStatus::Skipped:
        break;
      }

      if (options.mode == klint::cli::OutputMode::Json) {
        reports.push_back(std::move(report));
      } else {
        klint::output::print_text_report(report);
      }
    }

    if (options.mode == klint::cli::OutputMode::Json) {
      try {
        nlohmann::json json_doc = klint::output::reports_to_json(reports);
        std::cout << json_doc.dump(2) << "\n";
      } catch (const std::exception &ex) {
        nlohmann::json error_doc = {{"error", ex.what()}};
        std::cout << error_doc.dump() << "\n";
        return 2;
      } catch (...) {
        nlohmann::json error_doc = {{"error", "unknown"}};
        std::cout << error_doc.dump() << "\n";
        return 2;
      }
    }

    if (any_errors_or_timeouts) {
      return 2;
    }
    if (any_findings) {
      return 1;
    }
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "fatal: " << ex.what() << "\n";
    return 2;
  } catch (...) {
    std::cerr << "fatal: unknown exception\n";
    return 2;
  }
}
