#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <csignal>
#include <cstddef>
#include <cstring>
#include <dirent.h>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unordered_set>
#include <vector>

#include "scanner.hpp"

namespace {

using klint::Category;
using klint::Finding;
using klint::Registrar;
using klint::Requirement;
using klint::Scanner;
using klint::ScanResult;
using klint::Severity;
using klint::util::join;
using klint::util::read_file;
using klint::util::split_lines;
using klint::util::walk_dir_bounded;

constexpr std::size_t kMaxExamples = 20;
constexpr std::size_t kMaxCollectionErrors = 32;
constexpr std::size_t kMaxCgroupEntries = 300000;
constexpr std::size_t kPidProbeHeadroom = 4096;
constexpr std::size_t kMinPidProbeLimit = 32768;
constexpr std::size_t kMaxPidProbeLimit = 262144;
constexpr std::size_t kPidProbePerVisiblePid = 16;

struct Snapshot {
  std::unordered_set<pid_t> proc_pids;
  std::unordered_set<pid_t> hidden_stat_visible;
  std::unordered_set<pid_t> hidden_kill_only;
  std::unordered_set<pid_t> hidden_permission_denied;
  std::unordered_set<pid_t> cgroup_only;
  std::size_t kill_existing = 0;
  std::size_t kill_eperm = 0;
  std::size_t thread_tids_ignored = 0;
  std::size_t cgroup_files_scanned = 0;
  bool cgroup_available = false;
  std::size_t pid_max = 0;
  std::size_t pid_scan_target = 0;
  std::size_t pid_scan_limit = 0;
  bool pid_scan_clamped = false;
  std::optional<std::size_t> ns_last_pid;
  std::optional<std::size_t> loadavg_running;
  std::optional<std::size_t> loadavg_total;
  std::vector<std::string> errors;
  std::size_t suppressed_errors = 0;
};

struct HiddenPidAnalysis {
  std::size_t zombie_count = 0;
  std::size_t nested_pid_namespace_count = 0;
  std::size_t nspid_mismatch_count = 0;
  std::vector<std::string> examples;
};

std::string_view trim(std::string_view input) {
  while (!input.empty() &&
         std::isspace(static_cast<unsigned char>(input.front()))) {
    input.remove_prefix(1);
  }
  while (!input.empty() &&
         std::isspace(static_cast<unsigned char>(input.back()))) {
    input.remove_suffix(1);
  }
  return input;
}

void add_collection_error(Snapshot &snapshot, std::string message) {
  if (snapshot.errors.size() < kMaxCollectionErrors) {
    snapshot.errors.push_back(std::move(message));
  } else {
    ++snapshot.suppressed_errors;
  }
}

bool is_missing_file_error(int error_number) {
  return error_number == ENOENT || error_number == ENOTDIR;
}

std::optional<pid_t> parse_pid(std::string_view text) {
  text = trim(text);
  if (text.empty()) {
    return std::nullopt;
  }
  int value = 0;
  auto [ptr, ec] =
      std::from_chars(text.data(), text.data() + text.size(), value);
  if (ec != std::errc{} || ptr != text.data() + text.size() || value <= 0) {
    return std::nullopt;
  }
  return static_cast<pid_t>(value);
}

std::optional<std::size_t> parse_size(std::string_view text) {
  text = trim(text);
  if (text.empty()) {
    return std::nullopt;
  }
  std::size_t value = 0;
  auto [ptr, ec] =
      std::from_chars(text.data(), text.data() + text.size(), value);
  if (ec != std::errc{} || ptr != text.data() + text.size()) {
    return std::nullopt;
  }
  return value;
}

std::optional<pid_t> parse_tgid_from_status(std::string_view status_text) {
  for (const auto &line : split_lines(status_text)) {
    std::string_view view = trim(line);
    if (!view.starts_with("Tgid:")) {
      continue;
    }
    auto parsed = parse_pid(view.substr(5));
    if (parsed) {
      return parsed;
    }
    return std::nullopt;
  }
  return std::nullopt;
}

std::optional<std::size_t> read_pid_max(Snapshot &snapshot,
                                        std::size_t fallback) {
  auto data = read_file("/proc/sys/kernel/pid_max");
  if (!data) {
    add_collection_error(snapshot, data.error());
    return fallback;
  }
  auto value = parse_size(*data);
  if (!value || *value == 0) {
    add_collection_error(snapshot,
                         "parse /proc/sys/kernel/pid_max: invalid value");
    return fallback;
  }
  std::size_t pid_limit =
      static_cast<std::size_t>(std::numeric_limits<pid_t>::max());
  if (*value > pid_limit) {
    add_collection_error(
        snapshot, "/proc/sys/kernel/pid_max exceeds pid_t range; clamping");
    return pid_limit;
  }
  return *value;
}

std::optional<std::size_t> read_ns_last_pid(Snapshot &snapshot) {
  int error_number = 0;
  auto data = read_file("/proc/sys/kernel/ns_last_pid", &error_number);
  if (!data) {
    if (!is_missing_file_error(error_number)) {
      add_collection_error(snapshot, data.error());
    }
    return std::nullopt;
  }
  auto value = parse_size(*data);
  if (!value) {
    add_collection_error(snapshot,
                         "parse /proc/sys/kernel/ns_last_pid: invalid value");
    return std::nullopt;
  }
  return value;
}

std::size_t saturating_add(std::size_t lhs, std::size_t rhs) {
  if (lhs > std::numeric_limits<std::size_t>::max() - rhs) {
    return std::numeric_limits<std::size_t>::max();
  }
  return lhs + rhs;
}

std::size_t saturating_mul(std::size_t lhs, std::size_t rhs) {
  if (lhs == 0 || rhs == 0) {
    return 0;
  }
  if (lhs > std::numeric_limits<std::size_t>::max() / rhs) {
    return std::numeric_limits<std::size_t>::max();
  }
  return lhs * rhs;
}

struct PidScanPlan {
  std::size_t target = 0;
  std::size_t limit = 0;
  bool clamped = false;
};

PidScanPlan determine_pid_scan_limit(const Snapshot &snapshot,
                                     std::size_t pid_max,
                                     std::size_t highest_visible_pid) {
  std::size_t target = kMinPidProbeLimit;
  target =
      std::max(target, saturating_add(highest_visible_pid, kPidProbeHeadroom));
  if (snapshot.ns_last_pid) {
    target = std::max(target,
                      saturating_add(*snapshot.ns_last_pid, kPidProbeHeadroom));
  }
  for (pid_t pid : snapshot.cgroup_only) {
    if (pid > 0) {
      target = std::max(target, saturating_add(static_cast<std::size_t>(pid),
                                               kPidProbeHeadroom));
    }
  }

  target = std::min(target, pid_max);

  std::size_t visible_count =
      saturating_add(snapshot.proc_pids.size(), snapshot.cgroup_only.size());
  std::size_t adaptive_budget = saturating_add(
      kMinPidProbeLimit,
      saturating_mul(visible_count,
                     static_cast<std::size_t>(kPidProbePerVisiblePid)));
  std::size_t hard_cap = std::min(pid_max, kMaxPidProbeLimit);
  std::size_t budget =
      std::min(hard_cap, std::max(kMinPidProbeLimit, adaptive_budget));

  PidScanPlan plan;
  plan.target = target;
  plan.limit = std::min(target, budget);
  plan.clamped = plan.limit < plan.target;
  return plan;
}

void collect_proc_pids(Snapshot &snapshot) {
  DIR *proc_dir = ::opendir("/proc");
  if (!proc_dir) {
    add_collection_error(snapshot,
                         "opendir /proc: " + std::string(std::strerror(errno)));
    return;
  }

  while (true) {
    errno = 0;
    dirent *entry = ::readdir(proc_dir);
    if (!entry) {
      if (errno != 0) {
        add_collection_error(snapshot, "readdir /proc: " +
                                           std::string(std::strerror(errno)));
      }
      break;
    }

    std::string_view name(entry->d_name);
    auto pid = parse_pid(name);
    if (!pid) {
      continue;
    }
    snapshot.proc_pids.insert(*pid);
  }

  ::closedir(proc_dir);
}

void collect_cgroup_pids(Snapshot &snapshot) {
  struct stat root_stat{};
  if (::stat("/sys/fs/cgroup", &root_stat) != 0) {
    if (!is_missing_file_error(errno)) {
      add_collection_error(snapshot, "stat /sys/fs/cgroup: " +
                                         std::string(std::strerror(errno)));
    }
    return;
  }
  if (!S_ISDIR(root_stat.st_mode)) {
    return;
  }
  snapshot.cgroup_available = true;

  std::unordered_set<pid_t> cgroup_pids;

  auto walk_errors = walk_dir_bounded(
      "/sys/fs/cgroup", kMaxCgroupEntries,
      [&](const std::string &path, const struct stat &st) {
        if (!S_ISREG(st.st_mode) || !path.ends_with("/cgroup.procs")) {
          return;
        }

        ++snapshot.cgroup_files_scanned;
        int error_number = 0;
        auto data = read_file(path, &error_number);
        if (!data) {
          if (!is_missing_file_error(error_number)) {
            add_collection_error(snapshot, data.error());
          }
          return;
        }

        for (const auto &line : split_lines(*data)) {
          auto pid = parse_pid(line);
          if (!pid) {
            continue;
          }
          cgroup_pids.insert(*pid);
        }
      },
      32);

  for (const auto &error : walk_errors) {
    add_collection_error(snapshot, error);
  }

  for (pid_t pid : cgroup_pids) {
    if (!snapshot.proc_pids.contains(pid)) {
      snapshot.cgroup_only.insert(pid);
    }
  }
}

void collect_loadavg(Snapshot &snapshot) {
  auto loadavg_data = read_file("/proc/loadavg");
  if (!loadavg_data) {
    add_collection_error(snapshot, loadavg_data.error());
    return;
  }

  std::vector<std::string> lines = split_lines(*loadavg_data);
  if (lines.empty()) {
    return;
  }
  std::string_view first_line = trim(lines.front());
  if (first_line.empty()) {
    return;
  }

  std::size_t field_start = 0;
  std::size_t field_index = 0;
  while (field_start < first_line.size()) {
    while (field_start < first_line.size() &&
           std::isspace(static_cast<unsigned char>(first_line[field_start]))) {
      ++field_start;
    }
    if (field_start >= first_line.size()) {
      break;
    }
    std::size_t field_end = field_start;
    while (field_end < first_line.size() &&
           !std::isspace(static_cast<unsigned char>(first_line[field_end]))) {
      ++field_end;
    }
    if (field_index == 3) {
      std::string_view tasks_field =
          first_line.substr(field_start, field_end - field_start);
      std::size_t slash = tasks_field.find('/');
      if (slash != std::string_view::npos) {
        auto running = parse_size(tasks_field.substr(0, slash));
        auto total = parse_size(tasks_field.substr(slash + 1));
        if (running) {
          snapshot.loadavg_running = running;
        }
        if (total) {
          snapshot.loadavg_total = total;
        }
      }
      return;
    }
    ++field_index;
    field_start = field_end;
  }
}

Snapshot collect_snapshot() {
  Snapshot snapshot;
  collect_proc_pids(snapshot);
  collect_loadavg(snapshot);
  collect_cgroup_pids(snapshot);

  pid_t max_seen = 1;
  for (pid_t pid : snapshot.proc_pids) {
    if (pid > max_seen) {
      max_seen = pid;
    }
  }
  for (pid_t pid : snapshot.cgroup_only) {
    if (pid > max_seen) {
      max_seen = pid;
    }
  }

  std::size_t fallback_pid_max = std::max<std::size_t>(
      kMinPidProbeLimit, static_cast<std::size_t>(max_seen + 1024));
  auto pid_max = read_pid_max(snapshot, fallback_pid_max);
  if (!pid_max || *pid_max == 0) {
    return snapshot;
  }

  snapshot.pid_max = *pid_max;
  snapshot.ns_last_pid = read_ns_last_pid(snapshot);
  PidScanPlan pid_scan_plan = determine_pid_scan_limit(
      snapshot, *pid_max, static_cast<std::size_t>(max_seen));
  snapshot.pid_scan_target = pid_scan_plan.target;
  snapshot.pid_scan_limit = pid_scan_plan.limit;
  snapshot.pid_scan_clamped = pid_scan_plan.clamped;
  if (snapshot.pid_scan_limit == 0) {
    return snapshot;
  }

  for (std::size_t pid_value = 1; pid_value <= snapshot.pid_scan_limit;
       ++pid_value) {
    pid_t pid = static_cast<pid_t>(pid_value);
    errno = 0;
    if (::kill(pid, 0) != 0) {
      if (errno != EPERM) {
        continue;
      }
      ++snapshot.kill_eperm;
    }

    ++snapshot.kill_existing;
    if (snapshot.proc_pids.contains(pid)) {
      continue;
    }

    std::string proc_path = "/proc/" + std::to_string(pid);
    struct stat st{};
    if (::stat(proc_path.c_str(), &st) == 0) {
      if (!S_ISDIR(st.st_mode)) {
        snapshot.hidden_kill_only.insert(pid);
        continue;
      }
    } else if (errno == EACCES || errno == EPERM) {
      snapshot.hidden_permission_denied.insert(pid);
      continue;
    }

    int status_error = 0;
    auto status_data = read_file(proc_path + "/status", &status_error);
    if (status_data) {
      auto tgid = parse_tgid_from_status(*status_data);
      if (tgid && *tgid != pid) {
        ++snapshot.thread_tids_ignored;
        continue;
      }
      snapshot.hidden_stat_visible.insert(pid);
      continue;
    }

    if (status_error == EACCES || status_error == EPERM) {
      snapshot.hidden_permission_denied.insert(pid);
      continue;
    }

    if (!is_missing_file_error(status_error)) {
      add_collection_error(snapshot, status_data.error());
    }

    snapshot.hidden_kill_only.insert(pid);
  }

  return snapshot;
}

std::unordered_set<pid_t>
set_intersection(const std::unordered_set<pid_t> &lhs,
                 const std::unordered_set<pid_t> &rhs) {
  const auto *small = &lhs;
  const auto *large = &rhs;
  if (lhs.size() > rhs.size()) {
    small = &rhs;
    large = &lhs;
  }

  std::unordered_set<pid_t> out;
  out.reserve(small->size());
  for (pid_t pid : *small) {
    if (large->contains(pid)) {
      out.insert(pid);
    }
  }
  return out;
}

std::unordered_set<pid_t> set_difference(const std::unordered_set<pid_t> &lhs,
                                         const std::unordered_set<pid_t> &rhs) {
  std::unordered_set<pid_t> out;
  out.reserve(lhs.size());
  for (pid_t pid : lhs) {
    if (!rhs.contains(pid)) {
      out.insert(pid);
    }
  }
  return out;
}

std::vector<pid_t> sorted_pids(const std::unordered_set<pid_t> &set) {
  std::vector<pid_t> out(set.begin(), set.end());
  std::sort(out.begin(), out.end());
  return out;
}

std::string summarize_pid_examples(const std::unordered_set<pid_t> &set) {
  if (set.empty()) {
    return "-";
  }
  std::vector<pid_t> sorted = sorted_pids(set);
  std::size_t count = std::min(sorted.size(), kMaxExamples);
  std::vector<std::string> preview;
  preview.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    preview.push_back(std::to_string(sorted[i]));
  }
  std::string summary = join(preview, ", ");
  if (sorted.size() > count) {
    summary.append(" (+");
    summary.append(std::to_string(sorted.size() - count));
    summary.append(" more)");
  }
  return summary;
}

std::optional<char> parse_proc_state(std::string_view stat_line) {
  std::size_t close_paren = stat_line.rfind(')');
  if (close_paren == std::string_view::npos ||
      close_paren + 2 >= stat_line.size()) {
    return std::nullopt;
  }
  return stat_line[close_paren + 2];
}

std::optional<std::size_t> parse_nspid_depth(std::string_view status_text,
                                             pid_t pid, bool &mismatch) {
  for (const auto &line : split_lines(status_text)) {
    std::string_view view = trim(line);
    if (!view.starts_with("NSpid:")) {
      continue;
    }
    std::string_view values = trim(view.substr(6));
    if (values.empty()) {
      return std::nullopt;
    }

    std::size_t depth = 0;
    bool first_seen = false;
    while (!values.empty()) {
      std::size_t split = values.find_first_of(" \t");
      std::string_view token =
          split == std::string_view::npos ? values : values.substr(0, split);
      token = trim(token);
      if (!token.empty()) {
        auto parsed = parse_pid(token);
        if (parsed) {
          ++depth;
          if (!first_seen) {
            first_seen = true;
            if (*parsed != pid) {
              mismatch = true;
            }
          }
        }
      }
      if (split == std::string_view::npos) {
        break;
      }
      values = trim(values.substr(split + 1));
    }
    if (depth > 0) {
      return depth;
    }
    return std::nullopt;
  }
  return std::nullopt;
}

std::optional<std::string> read_process_name(pid_t pid) {
  auto comm = read_file("/proc/" + std::to_string(pid) + "/comm");
  if (!comm) {
    return std::nullopt;
  }
  std::vector<std::string> lines = split_lines(*comm);
  if (lines.empty()) {
    return std::nullopt;
  }
  std::string_view name = trim(lines.front());
  if (name.empty()) {
    return std::nullopt;
  }
  return std::string(name);
}

HiddenPidAnalysis analyze_hidden_pids(const std::unordered_set<pid_t> &pids) {
  HiddenPidAnalysis analysis;
  if (pids.empty()) {
    return analysis;
  }

  std::vector<pid_t> sorted = sorted_pids(pids);
  analysis.examples.reserve(std::min(sorted.size(), kMaxExamples));

  for (pid_t pid : sorted) {
    auto stat_data = read_file("/proc/" + std::to_string(pid) + "/stat");
    if (stat_data) {
      auto state = parse_proc_state(*stat_data);
      if (state && *state == 'Z') {
        ++analysis.zombie_count;
      }
    }

    auto status_data = read_file("/proc/" + std::to_string(pid) + "/status");
    if (status_data) {
      bool mismatch = false;
      auto depth = parse_nspid_depth(*status_data, pid, mismatch);
      if (mismatch) {
        ++analysis.nspid_mismatch_count;
      }
      if (depth && *depth > 1) {
        ++analysis.nested_pid_namespace_count;
      }
    }

    if (analysis.examples.size() < kMaxExamples) {
      std::string item = std::to_string(pid);
      if (auto name = read_process_name(pid)) {
        item.append(":");
        item.append(*name);
      }
      analysis.examples.push_back(std::move(item));
    }
  }

  return analysis;
}

std::string summarize_string_examples(const std::vector<std::string> &items,
                                      std::size_t total_count) {
  if (items.empty()) {
    return "-";
  }
  std::string summary = join(items, ", ");
  if (total_count > items.size()) {
    summary.append(" (+");
    summary.append(std::to_string(total_count - items.size()));
    summary.append(" more)");
  }
  return summary;
}

void add_snapshot_errors(ScanResult &result, const Snapshot &snapshot) {
  for (const auto &error : snapshot.errors) {
    result.add_error(error);
  }
  if (snapshot.suppressed_errors > 0) {
    result.add_error("suppressed collection errors: " +
                     std::to_string(snapshot.suppressed_errors));
  }
}

ScanResult run() {
  ScanResult result;
  Snapshot initial = collect_snapshot();
  add_snapshot_errors(result, initial);

  auto hidden_stat_visible = initial.hidden_stat_visible;
  auto hidden_kill_only = initial.hidden_kill_only;
  auto hidden_permission_denied = initial.hidden_permission_denied;
  auto cgroup_only = initial.cgroup_only;

  std::size_t suppressed_transient = 0;
  bool revalidated = false;
  Snapshot final_snapshot = initial;

  bool has_mismatch = !hidden_stat_visible.empty() ||
                      !hidden_kill_only.empty() ||
                      !hidden_permission_denied.empty() || !cgroup_only.empty();

  if (has_mismatch) {
    Snapshot second = collect_snapshot();
    add_snapshot_errors(result, second);
    if (!second.proc_pids.empty() && second.pid_max > 0) {
      revalidated = true;
      final_snapshot = second;

      auto persistent_hidden_stat_visible =
          set_intersection(hidden_stat_visible, second.hidden_stat_visible);
      suppressed_transient +=
          hidden_stat_visible.size() - persistent_hidden_stat_visible.size();
      hidden_stat_visible = std::move(persistent_hidden_stat_visible);

      auto persistent_hidden_kill_only =
          set_intersection(hidden_kill_only, second.hidden_kill_only);
      suppressed_transient +=
          hidden_kill_only.size() - persistent_hidden_kill_only.size();
      hidden_kill_only = std::move(persistent_hidden_kill_only);

      auto persistent_hidden_permission_denied = set_intersection(
          hidden_permission_denied, second.hidden_permission_denied);
      suppressed_transient += hidden_permission_denied.size() -
                              persistent_hidden_permission_denied.size();
      hidden_permission_denied = std::move(persistent_hidden_permission_denied);

      auto persistent_cgroup_only =
          set_intersection(cgroup_only, second.cgroup_only);
      suppressed_transient +=
          cgroup_only.size() - persistent_cgroup_only.size();
      cgroup_only = std::move(persistent_cgroup_only);
    } else {
      result.add_error(
          "second hidden_processes snapshot unusable; keeping initial results");
    }
  }

  auto cgroup_and_hidden_stat =
      set_intersection(cgroup_only, hidden_stat_visible);
  auto cgroup_only_residual = set_difference(cgroup_only, hidden_stat_visible);
  auto cgroup_and_kill_only =
      set_intersection(cgroup_only_residual, hidden_kill_only);
  cgroup_only_residual =
      set_difference(cgroup_only_residual, cgroup_and_kill_only);
  hidden_kill_only = set_difference(hidden_kill_only, cgroup_and_kill_only);

  if (!hidden_stat_visible.empty()) {
    HiddenPidAnalysis analysis = analyze_hidden_pids(hidden_stat_visible);
    Finding finding(
        Severity::Critical,
        "Processes hidden from /proc directory listing but reachable by PID");
    finding
        .with_detail(
            revalidated
                ? "PIDs persisted across two snapshots and were discoverable "
                  "via direct PID probing while absent from /proc readdir "
                  "output."
                : "PIDs were discoverable via direct PID probing while absent "
                  "from /proc readdir output.")
        .with_evidence("hidden_pid_count",
                       std::to_string(hidden_stat_visible.size()))
        .with_evidence("examples",
                       summarize_string_examples(analysis.examples,
                                                 hidden_stat_visible.size()))
        .with_evidence("probe_method", "kill(0)+stat(/proc/<pid>)")
        .with_evidence("pid_max_scanned",
                       std::to_string(final_snapshot.pid_scan_limit))
        .with_evidence("pid_max", std::to_string(final_snapshot.pid_max))
        .with_evidence("revalidated", revalidated ? "1" : "0");
    if (analysis.zombie_count > 0) {
      finding.with_evidence("hidden_zombies",
                            std::to_string(analysis.zombie_count));
    }
    if (analysis.nested_pid_namespace_count > 0) {
      finding.with_evidence(
          "hidden_nested_pid_namespaces",
          std::to_string(analysis.nested_pid_namespace_count));
    }
    if (analysis.nspid_mismatch_count > 0) {
      finding.with_evidence("hidden_nspid_mismatches",
                            std::to_string(analysis.nspid_mismatch_count));
    }
    if (!cgroup_and_hidden_stat.empty()) {
      finding.with_evidence("also_present_in_cgroup_procs",
                            std::to_string(cgroup_and_hidden_stat.size()));
    }
    result.add_finding(std::move(finding));
  }

  if (!cgroup_and_kill_only.empty()) {
    Finding finding(Severity::Critical,
                    "PIDs in cgroup.procs and kill sweep missing from /proc");
    finding
        .with_detail(revalidated
                         ? "PIDs persisted in cgroup.procs and responded to "
                           "kill(0), but were absent from /proc readdir."
                         : "PIDs in cgroup.procs responded to kill(0), but "
                           "were absent from /proc readdir.")
        .with_evidence("pid_count", std::to_string(cgroup_and_kill_only.size()))
        .with_evidence("examples",
                       summarize_pid_examples(cgroup_and_kill_only));
    result.add_finding(std::move(finding));
  }

  if (!cgroup_only_residual.empty()) {
    Finding finding(
        Severity::Warning,
        "PIDs present in cgroup.procs but missing from /proc listing");
    finding
        .with_detail(revalidated
                         ? "Cross-view mismatch between cgroup task files and "
                           "/proc readdir persisted across snapshots."
                         : "Cross-view mismatch between cgroup task files and "
                           "/proc readdir.")
        .with_evidence("pid_count", std::to_string(cgroup_only_residual.size()))
        .with_evidence("examples",
                       summarize_pid_examples(cgroup_only_residual));
    result.add_finding(std::move(finding));
  }

  if (!hidden_kill_only.empty()) {
    Finding finding(
        Severity::Warning,
        "PIDs respond to kill(0) but are absent from /proc enumeration");
    finding
        .with_detail(revalidated
                         ? "PIDs persisted across snapshots and reported as "
                           "existing by kill(0), but were not visible in "
                           "/proc readdir."
                         : "PIDs were reported as existing by kill(0), but "
                           "were not visible in /proc readdir.")
        .with_evidence("pid_count", std::to_string(hidden_kill_only.size()))
        .with_evidence("examples", summarize_pid_examples(hidden_kill_only));
    result.add_finding(std::move(finding));
  }

  if (!hidden_permission_denied.empty()) {
    Finding finding(Severity::Info,
                    "PID probe saw EPERM/EACCES for non-enumerated PIDs");
    finding
        .with_detail("PIDs were detected by kill(0) but direct /proc lookups "
                     "returned permission errors; this can happen with strict "
                     "procfs visibility settings.")
        .with_evidence("pid_count",
                       std::to_string(hidden_permission_denied.size()))
        .with_evidence("examples",
                       summarize_pid_examples(hidden_permission_denied));
    result.add_finding(std::move(finding));
  }

  if (final_snapshot.loadavg_total &&
      final_snapshot.proc_pids.size() > *final_snapshot.loadavg_total) {
    Finding finding(Severity::Warning,
                    "/proc/loadavg task total is lower than /proc PID count");
    finding
        .with_detail("The total task count reported by /proc/loadavg should be "
                     "at least as large as the number of visible /proc PID "
                     "entries.")
        .with_evidence("proc_pid_count",
                       std::to_string(final_snapshot.proc_pids.size()))
        .with_evidence("loadavg_total_tasks",
                       std::to_string(*final_snapshot.loadavg_total));
    result.add_finding(std::move(finding));
  }

  if (suppressed_transient > 0) {
    Finding finding(Severity::Info, "Transient PID mismatches suppressed");
    finding
        .with_detail("A second snapshot was used to reduce race noise from "
                     "short-lived processes.")
        .with_evidence("suppressed_mismatches",
                       std::to_string(suppressed_transient));
    result.add_finding(std::move(finding));
  }

  if (result.has_findings()) {
    Finding summary(Severity::Info, "Process cross-view summary");
    summary
        .with_detail("Cross-view inventory from /proc readdir, kill(0) probe, "
                     "cgroup.procs, and /proc/loadavg.")
        .with_evidence("proc_pids",
                       std::to_string(final_snapshot.proc_pids.size()))
        .with_evidence("kill_existing",
                       std::to_string(final_snapshot.kill_existing))
        .with_evidence("kill_eperm", std::to_string(final_snapshot.kill_eperm))
        .with_evidence("thread_tids_ignored",
                       std::to_string(final_snapshot.thread_tids_ignored))
        .with_evidence("cgroup_available",
                       final_snapshot.cgroup_available ? "1" : "0")
        .with_evidence("cgroup_files_scanned",
                       std::to_string(final_snapshot.cgroup_files_scanned))
        .with_evidence("pid_max_scanned",
                       std::to_string(final_snapshot.pid_scan_limit))
        .with_evidence("pid_probe_target",
                       std::to_string(final_snapshot.pid_scan_target))
        .with_evidence("pid_probe_clamped",
                       final_snapshot.pid_scan_clamped ? "1" : "0")
        .with_evidence("pid_max", std::to_string(final_snapshot.pid_max));
    if (final_snapshot.ns_last_pid) {
      summary.with_evidence("ns_last_pid",
                            std::to_string(*final_snapshot.ns_last_pid));
    }
    if (final_snapshot.loadavg_running) {
      summary.with_evidence("loadavg_running_tasks",
                            std::to_string(*final_snapshot.loadavg_running));
    }
    if (final_snapshot.loadavg_total) {
      summary.with_evidence("loadavg_total_tasks",
                            std::to_string(*final_snapshot.loadavg_total));
    }
    result.add_finding(std::move(summary));
  }

  return result;
}

constexpr std::array<Category, 1> kCategories = {Category::Process};
const std::array<Requirement, 0> kRequirements = {};

static Registrar reg_{Scanner{
    .name = "hidden_processes",
    .func = run,
    .categories = kCategories,
    .requirements = kRequirements,
}};

} // namespace
