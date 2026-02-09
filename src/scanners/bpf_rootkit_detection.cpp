#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include <nlohmann/json.hpp>

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
using klint::util::run_command;
using klint::util::split_lines;
using klint::util::walk_dir_bounded;

constexpr std::size_t kMaxExamples = 20;
constexpr std::size_t kMaxBpffsEntries = 200000;
constexpr std::size_t kMaxProcEntries = 200000;
constexpr std::size_t kMaxFdEntries = 2000000;
constexpr std::chrono::milliseconds kBpftoolTimeout = std::chrono::seconds(8);

enum class MatchKind {
  Prefix,
  Contains,
  Exact,
};

struct TargetPattern {
  std::string_view tag;
  std::string_view pattern;
  MatchKind kind;
};

constexpr std::array<TargetPattern, 35> kSensitiveTargetPatterns = {{
    {"syscall", "__x64_sys_getdents64", MatchKind::Contains},
    {"syscall", "__ia32_sys_getdents64", MatchKind::Contains},
    {"syscall", "__x64_sys_getdents", MatchKind::Contains},
    {"syscall", "sys_enter_getdents64", MatchKind::Contains},
    {"signal", "__x64_sys_kill", MatchKind::Contains},
    {"signal", "sys_enter_kill", MatchKind::Contains},
    {"exec", "__x64_sys_execve", MatchKind::Contains},
    {"exec", "__x64_sys_execveat", MatchKind::Contains},
    {"exec", "sys_enter_execve", MatchKind::Contains},
    {"cred", "commit_creds", MatchKind::Contains},
    {"cred", "prepare_kernel_cred", MatchKind::Contains},
    {"module", "do_init_module", MatchKind::Contains},
    {"module", "do_finit_module", MatchKind::Contains},
    {"module", "sys_init_module", MatchKind::Contains},
    {"module", "sys_finit_module", MatchKind::Contains},
    {"vfs", "iterate_dir", MatchKind::Contains},
    {"vfs", "filldir", MatchKind::Contains},
    {"vfs", "vfs_readdir", MatchKind::Contains},
    {"vfs", "proc_pid_readdir", MatchKind::Contains},
    {"vfs", "security_inode", MatchKind::Contains},
    {"net", "tcp4_seq_show", MatchKind::Contains},
    {"net", "tcp6_seq_show", MatchKind::Contains},
    {"net", "udp4_seq_show", MatchKind::Contains},
    {"net", "udp6_seq_show", MatchKind::Contains},
    {"net", "inet_bind", MatchKind::Contains},
    {"net", "inet_accept", MatchKind::Contains},
    {"net", "security_socket_", MatchKind::Contains},
    {"lsm", "security_", MatchKind::Prefix},
    {"lsm", "lsm/", MatchKind::Contains},
    {"bpf", "__x64_sys_bpf", MatchKind::Contains},
    {"bpf", "bpf_prog_load", MatchKind::Contains},
    {"bpf", "bpf_map_", MatchKind::Contains},
    {"proc", "task_prctl", MatchKind::Contains},
    {"proc", "sched_process_exec", MatchKind::Contains},
    {"proc", "sched_process_fork", MatchKind::Contains},
}};

constexpr std::array<std::string_view, 9> kSuspiciousNameTokens = {
    "rootkit", "bpfdoor", "backdoor", "stealth", "hidden",
    "conceal", "cloak",   "reptile",  "ebpfkit"};

constexpr std::array<std::string_view, 13> kHighRiskProgramTypes = {
    "kprobe",     "tracepoint", "raw_tracepoint", "raw_tracepoint_writable",
    "tracing",    "lsm",        "perf_event",     "syscall",
    "ext",        "fentry",     "fexit",          "fmod_ret",
    "struct_ops",
};

constexpr std::array<std::string_view, 12> kNetworkProgramTypes = {
    "xdp",         "sched_cls",        "sched_act",      "cgroup_skb",
    "cgroup_sock", "cgroup_sock_addr", "cgroup_sockopt", "sk_skb",
    "sk_msg",      "sock_ops",         "flow_dissector", "netfilter",
};

constexpr std::array<std::string_view, 18> kLikelyLegitOwnerPrefixes = {
    "cilium",    "calico",    "falco", "tracee",  "bpftrace", "bcc",
    "inspektor", "kubescape", "pixie", "parca",   "datadog",  "newrelic",
    "sysdig",    "aws-node",  "kube-", "systemd", "tetragon", "bpftool",
};

struct ProgramInfo {
  std::uint64_t id = 0;
  std::string type = "unknown";
  std::string name = "(unnamed)";
  std::vector<std::uint64_t> map_ids;
  std::vector<std::uint32_t> pids;
  std::vector<std::string> owners;
  std::vector<std::string> context_strings;
  std::size_t link_count = 0;
};

struct MapInfo {
  std::uint64_t id = 0;
  std::string type = "unknown";
  std::string name = "(unnamed)";
  std::vector<std::uint32_t> pids;
  std::vector<std::string> owners;
};

struct LinkInfo {
  std::uint64_t id = 0;
  std::uint64_t prog_id = 0;
  std::string type = "unknown";
  std::vector<std::string> context_strings;
};

struct ProgramSnapshot {
  std::vector<ProgramInfo> programs;
  bool pid_metadata_available = false;
};

struct MapSnapshot {
  std::vector<MapInfo> maps;
  bool pid_metadata_available = false;
};

struct BpffsSnapshot {
  bool present = false;
  bool canonical_mount = false;
  std::vector<std::string> bpf_mount_points;
  std::vector<std::string> noncanonical_mounts;
  std::vector<std::string> suspicious_paths;
  std::size_t entries_scanned = 0;
  bool truncated = false;
  std::vector<std::string> errors;
};

struct ProcFdSnapshot {
  bool available = false;
  std::unordered_map<std::uint32_t, std::size_t> pid_fd_counts;
  std::unordered_map<std::uint32_t, std::string> pid_comms;
  std::size_t pids_scanned = 0;
  std::size_t fds_scanned = 0;
  std::size_t permission_denied = 0;
  bool truncated = false;
  std::vector<std::string> errors;
};

struct HardeningSnapshot {
  std::optional<long long> unprivileged_bpf_disabled;
  std::optional<long long> jit_enable;
  std::optional<long long> jit_harden;
  std::optional<long long> jit_kallsyms;
  std::vector<std::string> errors;
};

struct ProgramAssessment {
  std::vector<std::string> critical_examples;
  std::vector<std::string> warning_examples;
  std::size_t ownerless_sensitive = 0;
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

std::string trim_copy(std::string_view input) {
  return std::string(trim(input));
}

bool is_missing_file_error(int error_number) {
  return error_number == ENOENT || error_number == ENOTDIR;
}

std::string to_lower_copy(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (char c : text) {
    out.push_back(
        static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  }
  return out;
}

bool is_digits(std::string_view text) {
  if (text.empty()) {
    return false;
  }
  for (char c : text) {
    if (!std::isdigit(static_cast<unsigned char>(c))) {
      return false;
    }
  }
  return true;
}

std::optional<std::uint64_t> parse_uint64(std::string_view text, int base) {
  text = trim(text);
  if (text.empty()) {
    return std::nullopt;
  }
  std::string buffer(text);
  char *end = nullptr;
  errno = 0;
  unsigned long long value = std::strtoull(buffer.c_str(), &end, base);
  if (errno != 0 || end == buffer.c_str() || *end != '\0') {
    return std::nullopt;
  }
  return static_cast<std::uint64_t>(value);
}

std::optional<long long> parse_int64(std::string_view text, int base) {
  text = trim(text);
  if (text.empty()) {
    return std::nullopt;
  }
  std::string buffer(text);
  char *end = nullptr;
  errno = 0;
  long long value = std::strtoll(buffer.c_str(), &end, base);
  if (errno != 0 || end == buffer.c_str() || *end != '\0') {
    return std::nullopt;
  }
  return value;
}

template <std::size_t N>
bool contains_literal(const std::array<std::string_view, N> &values,
                      std::string_view needle) {
  return std::find(values.begin(), values.end(), needle) != values.end();
}

void push_error_limited(std::vector<std::string> &errors, std::string message,
                        std::size_t max_errors = 20) {
  if (errors.size() >= max_errors) {
    return;
  }
  errors.push_back(std::move(message));
}

std::vector<std::string_view> split_ws(std::string_view text) {
  std::vector<std::string_view> tokens;
  std::size_t pos = 0;
  while (pos < text.size()) {
    while (pos < text.size() &&
           std::isspace(static_cast<unsigned char>(text[pos]))) {
      ++pos;
    }
    if (pos >= text.size()) {
      break;
    }
    std::size_t end = pos;
    while (end < text.size() &&
           !std::isspace(static_cast<unsigned char>(text[end]))) {
      ++end;
    }
    tokens.push_back(text.substr(pos, end - pos));
    pos = end;
  }
  return tokens;
}

std::string summarize_list(std::vector<std::string> items) {
  if (items.empty()) {
    return "-";
  }
  std::sort(items.begin(), items.end());
  items.erase(std::unique(items.begin(), items.end()), items.end());
  std::size_t count = std::min(items.size(), kMaxExamples);
  std::vector<std::string> preview(items.begin(), items.begin() + count);
  std::string summary = join(preview, ", ");
  if (items.size() > count) {
    summary.append(" (+");
    summary.append(std::to_string(items.size() - count));
    summary.append(" more)");
  }
  return summary;
}

std::string summarize_blob(std::string_view text, std::size_t limit = 220) {
  std::string value = trim_copy(text);
  if (value.size() <= limit) {
    return value;
  }
  value.resize(limit);
  value.append("...");
  return value;
}

void append_unique(std::vector<std::string> &values, std::string value,
                   std::size_t max_size = 96) {
  value = trim_copy(value);
  if (value.empty() || values.size() >= max_size) {
    return;
  }
  if (std::find(values.begin(), values.end(), value) != values.end()) {
    return;
  }
  values.push_back(std::move(value));
}

std::optional<std::uint64_t> json_to_u64(const nlohmann::json &value) {
  if (value.is_number_unsigned()) {
    return value.get<std::uint64_t>();
  }
  if (value.is_number_integer()) {
    auto signed_value = value.get<long long>();
    if (signed_value < 0) {
      return std::nullopt;
    }
    return static_cast<std::uint64_t>(signed_value);
  }
  if (value.is_string()) {
    return parse_uint64(value.get<std::string>(), 10);
  }
  return std::nullopt;
}

std::optional<std::uint32_t> json_to_u32(const nlohmann::json &value) {
  auto parsed = json_to_u64(value);
  if (!parsed || *parsed > static_cast<std::uint64_t>(UINT32_MAX)) {
    return std::nullopt;
  }
  return static_cast<std::uint32_t>(*parsed);
}

std::string json_string_field(const nlohmann::json &object,
                              std::string_view key,
                              std::string_view fallback = "") {
  if (!object.is_object()) {
    return std::string(fallback);
  }
  auto it = object.find(std::string(key));
  if (it == object.end() || !it->is_string()) {
    return std::string(fallback);
  }
  return it->get<std::string>();
}

void collect_json_strings(const nlohmann::json &node,
                          std::vector<std::string> &out, std::size_t depth = 0,
                          std::size_t max_items = 64) {
  if (out.size() >= max_items || depth > 6) {
    return;
  }

  if (node.is_string()) {
    append_unique(out, node.get<std::string>(), max_items);
    return;
  }

  if (node.is_array()) {
    for (const auto &entry : node) {
      if (out.size() >= max_items) {
        break;
      }
      collect_json_strings(entry, out, depth + 1, max_items);
    }
    return;
  }

  if (!node.is_object()) {
    return;
  }

  for (const auto &entry : node.items()) {
    if (out.size() >= max_items) {
      break;
    }
    if (entry.key() == "xlated_prog_insns" ||
        entry.key() == "jited_prog_insns" || entry.key() == "line_info" ||
        entry.key() == "func_info") {
      continue;
    }
    collect_json_strings(entry.value(), out, depth + 1, max_items);
  }
}

void parse_pid_entries(const nlohmann::json &node,
                       std::vector<std::uint32_t> &pids,
                       std::vector<std::string> &owners) {
  if (!node.is_array()) {
    return;
  }

  std::unordered_set<std::uint32_t> seen;
  for (const auto &entry : node) {
    std::optional<std::uint32_t> pid;
    std::string comm;
    if (entry.is_object()) {
      auto pid_it = entry.find("pid");
      if (pid_it != entry.end()) {
        pid = json_to_u32(*pid_it);
      }
      auto comm_it = entry.find("comm");
      if (comm_it != entry.end() && comm_it->is_string()) {
        comm = comm_it->get<std::string>();
      }
    } else {
      pid = json_to_u32(entry);
    }

    if (!pid || !seen.insert(*pid).second) {
      continue;
    }
    pids.push_back(*pid);
    if (comm.empty()) {
      owners.push_back(std::to_string(*pid));
    } else {
      owners.push_back(comm + "(" + std::to_string(*pid) + ")");
    }
  }
}

const nlohmann::json *array_root(const nlohmann::json &root,
                                 std::string_view preferred_key) {
  if (root.is_array()) {
    return &root;
  }
  if (!root.is_object()) {
    return nullptr;
  }

  if (!preferred_key.empty()) {
    auto it = root.find(std::string(preferred_key));
    if (it == root.end() || !it->is_array()) {
      return nullptr;
    }
    return &(*it);
  }

  for (const auto &entry : root.items()) {
    if (entry.value().is_array()) {
      return &(entry.value());
    }
  }
  return nullptr;
}

std::optional<nlohmann::json>
run_bpftool_json(const std::vector<std::string> &args, std::string_view label,
                 ScanResult &result) {
  auto output = run_command(args, kBpftoolTimeout);
  if (!output) {
    result.add_error(std::string(label) + ": " + output.error());
    return std::nullopt;
  }

  if (output->exit_code != 0) {
    std::string error = std::string(label) + " exited with code " +
                        std::to_string(output->exit_code);
    if (!output->stderr_data.empty()) {
      error.append(": ");
      error.append(summarize_blob(output->stderr_data));
    } else if (!output->stdout_data.empty()) {
      error.append(": ");
      error.append(summarize_blob(output->stdout_data));
    }
    result.add_error(std::move(error));
    return std::nullopt;
  }

  if (output->stdout_truncated || output->stderr_truncated) {
    result.add_error(std::string(label) +
                     ": output truncated at capture limit");
    return std::nullopt;
  }

  if (output->stdout_data.empty()) {
    result.add_error(std::string(label) + ": empty stdout");
    return std::nullopt;
  }

  nlohmann::json parsed =
      nlohmann::json::parse(output->stdout_data, nullptr, false);
  if (parsed.is_discarded()) {
    result.add_error(std::string(label) + ": invalid JSON output");
    return std::nullopt;
  }
  return parsed;
}

std::optional<nlohmann::json>
run_bpftool_json_quiet(const std::vector<std::string> &args) {
  auto output = run_command(args, kBpftoolTimeout);
  if (!output || output->exit_code != 0 || output->stdout_data.empty() ||
      output->stdout_truncated || output->stderr_truncated) {
    return std::nullopt;
  }
  nlohmann::json parsed =
      nlohmann::json::parse(output->stdout_data, nullptr, false);
  if (parsed.is_discarded()) {
    return std::nullopt;
  }
  return parsed;
}

ProgramSnapshot parse_programs(const nlohmann::json &root, ScanResult &result) {
  ProgramSnapshot snapshot;
  const auto *rows = array_root(root, "programs");
  if (!rows) {
    result.add_error("bpftool prog show: unexpected JSON shape");
    return snapshot;
  }

  snapshot.programs.reserve(rows->size());
  std::unordered_set<std::uint64_t> seen_ids;
  std::size_t malformed = 0;

  for (const auto &row : *rows) {
    if (!row.is_object()) {
      ++malformed;
      continue;
    }

    auto id_it = row.find("id");
    if (id_it == row.end()) {
      ++malformed;
      continue;
    }
    auto id = json_to_u64(*id_it);
    if (!id || !seen_ids.insert(*id).second) {
      if (!id) {
        ++malformed;
      }
      continue;
    }

    ProgramInfo program;
    program.id = *id;
    program.type = to_lower_copy(json_string_field(row, "type", "unknown"));
    program.name = json_string_field(row, "name", "(unnamed)");

    auto map_ids_it = row.find("map_ids");
    if (map_ids_it != row.end() && map_ids_it->is_array()) {
      std::unordered_set<std::uint64_t> seen_map_ids;
      for (const auto &map_id : *map_ids_it) {
        auto parsed_id = json_to_u64(map_id);
        if (!parsed_id || !seen_map_ids.insert(*parsed_id).second) {
          continue;
        }
        program.map_ids.push_back(*parsed_id);
      }
    }

    auto pids_it = row.find("pids");
    if (pids_it != row.end()) {
      snapshot.pid_metadata_available = true;
      parse_pid_entries(*pids_it, program.pids, program.owners);
    }

    collect_json_strings(row, program.context_strings);
    snapshot.programs.push_back(std::move(program));
  }

  if (malformed > 0) {
    result.add_error("bpftool prog show: skipped " + std::to_string(malformed) +
                     " malformed entries");
  }

  return snapshot;
}

MapSnapshot parse_maps(const nlohmann::json &root, ScanResult &result) {
  MapSnapshot snapshot;
  const auto *rows = array_root(root, "maps");
  if (!rows) {
    result.add_error("bpftool map show: unexpected JSON shape");
    return snapshot;
  }

  snapshot.maps.reserve(rows->size());
  std::unordered_set<std::uint64_t> seen_ids;
  std::size_t malformed = 0;

  for (const auto &row : *rows) {
    if (!row.is_object()) {
      ++malformed;
      continue;
    }

    auto id_it = row.find("id");
    if (id_it == row.end()) {
      ++malformed;
      continue;
    }
    auto id = json_to_u64(*id_it);
    if (!id || !seen_ids.insert(*id).second) {
      if (!id) {
        ++malformed;
      }
      continue;
    }

    MapInfo map;
    map.id = *id;
    map.type = to_lower_copy(json_string_field(row, "type", "unknown"));
    map.name = json_string_field(row, "name", "(unnamed)");

    auto pids_it = row.find("pids");
    if (pids_it != row.end()) {
      snapshot.pid_metadata_available = true;
      parse_pid_entries(*pids_it, map.pids, map.owners);
    }

    snapshot.maps.push_back(std::move(map));
  }

  if (malformed > 0) {
    result.add_error("bpftool map show: skipped " + std::to_string(malformed) +
                     " malformed entries");
  }

  return snapshot;
}

std::optional<std::uint64_t> extract_link_prog_id(const nlohmann::json &row) {
  auto prog_id_it = row.find("prog_id");
  if (prog_id_it != row.end()) {
    auto parsed = json_to_u64(*prog_id_it);
    if (parsed) {
      return parsed;
    }
  }

  auto prog_it = row.find("prog");
  if (prog_it != row.end() && prog_it->is_object()) {
    auto nested_id = prog_it->find("id");
    if (nested_id != prog_it->end()) {
      return json_to_u64(*nested_id);
    }
  }
  return std::nullopt;
}

std::vector<LinkInfo> parse_links(const nlohmann::json &root,
                                  ScanResult &result) {
  std::vector<LinkInfo> links;
  const auto *rows = array_root(root, "links");
  if (!rows) {
    result.add_error("bpftool link show: unexpected JSON shape");
    return links;
  }

  links.reserve(rows->size());
  std::unordered_set<std::uint64_t> seen_ids;
  std::size_t malformed = 0;

  for (const auto &row : *rows) {
    if (!row.is_object()) {
      ++malformed;
      continue;
    }

    auto id_it = row.find("id");
    if (id_it == row.end()) {
      ++malformed;
      continue;
    }
    auto id = json_to_u64(*id_it);
    auto prog_id = extract_link_prog_id(row);
    if (!id || !prog_id || !seen_ids.insert(*id).second) {
      if (!id || !prog_id) {
        ++malformed;
      }
      continue;
    }

    LinkInfo link;
    link.id = *id;
    link.prog_id = *prog_id;
    link.type = to_lower_copy(json_string_field(row, "type", "unknown"));
    collect_json_strings(row, link.context_strings);
    links.push_back(std::move(link));
  }

  if (malformed > 0) {
    result.add_error("bpftool link show: skipped " + std::to_string(malformed) +
                     " malformed entries");
  }

  return links;
}

bool is_bpf_fd_target(std::string_view target) {
  std::string lower = to_lower_copy(target);
  return lower.starts_with("anon_inode:bpf") ||
         lower.starts_with("anon_inode:[bpf");
}

std::string comm_for_pid(std::uint32_t pid) {
  int error_number = 0;
  auto comm =
      read_file("/proc/" + std::to_string(pid) + "/comm", &error_number);
  if (!comm) {
    return {};
  }
  return trim_copy(*comm);
}

std::optional<std::string> readlink_full(const std::string &path,
                                         int &error_number) {
  constexpr std::size_t kInitialSize = 256;
  constexpr std::size_t kMaxSize = 16384;

  std::size_t size = kInitialSize;
  while (size <= kMaxSize) {
    std::string buffer(size, '\0');
    errno = 0;
    ssize_t len = ::readlink(path.c_str(), buffer.data(), buffer.size());
    if (len < 0) {
      error_number = errno;
      return std::nullopt;
    }
    std::size_t used = static_cast<std::size_t>(len);
    if (used < buffer.size()) {
      error_number = 0;
      buffer.resize(used);
      return buffer;
    }
    size *= 2;
  }

  error_number = ENAMETOOLONG;
  return std::nullopt;
}

ProcFdSnapshot collect_proc_fd_snapshot() {
  ProcFdSnapshot snapshot;

  DIR *proc = ::opendir("/proc");
  if (!proc) {
    snapshot.errors.push_back("opendir /proc: " +
                              std::string(std::strerror(errno)));
    return snapshot;
  }
  snapshot.available = true;

  while (true) {
    errno = 0;
    dirent *pid_entry = ::readdir(proc);
    if (!pid_entry) {
      if (errno != 0) {
        push_error_limited(snapshot.errors,
                           "readdir /proc: " +
                               std::string(std::strerror(errno)));
      }
      break;
    }

    std::string_view pid_name(pid_entry->d_name);
    if (!is_digits(pid_name)) {
      continue;
    }

    if (snapshot.pids_scanned >= kMaxProcEntries) {
      snapshot.truncated = true;
      break;
    }
    ++snapshot.pids_scanned;

    auto pid_opt = parse_uint64(pid_name, 10);
    if (!pid_opt || *pid_opt > static_cast<std::uint64_t>(UINT32_MAX)) {
      continue;
    }
    std::uint32_t pid = static_cast<std::uint32_t>(*pid_opt);

    std::string fd_dir = "/proc/" + std::string(pid_name) + "/fd";
    DIR *fd = ::opendir(fd_dir.c_str());
    if (!fd) {
      if (errno == EACCES || errno == EPERM) {
        ++snapshot.permission_denied;
      } else if (!is_missing_file_error(errno)) {
        push_error_limited(snapshot.errors,
                           "opendir " + fd_dir + ": " +
                               std::string(std::strerror(errno)));
      }
      continue;
    }

    std::size_t bpf_fd_count = 0;
    while (true) {
      errno = 0;
      dirent *fd_entry = ::readdir(fd);
      if (!fd_entry) {
        if (errno != 0) {
          push_error_limited(snapshot.errors,
                             "readdir " + fd_dir + ": " +
                                 std::string(std::strerror(errno)));
        }
        break;
      }

      std::string_view fd_name(fd_entry->d_name);
      if (fd_name == "." || fd_name == ".." || !is_digits(fd_name)) {
        continue;
      }

      if (snapshot.fds_scanned >= kMaxFdEntries) {
        snapshot.truncated = true;
        break;
      }
      ++snapshot.fds_scanned;

      std::string link_path = fd_dir + "/" + std::string(fd_name);
      int link_error = 0;
      auto target = readlink_full(link_path, link_error);
      if (!target) {
        if (link_error == EACCES || link_error == EPERM ||
            is_missing_file_error(link_error)) {
          continue;
        }
        push_error_limited(snapshot.errors,
                           "readlink " + link_path + ": " +
                               std::string(std::strerror(link_error)));
        continue;
      }
      if (is_bpf_fd_target(*target)) {
        ++bpf_fd_count;
      }
    }

    ::closedir(fd);

    if (bpf_fd_count > 0) {
      snapshot.pid_fd_counts.emplace(pid, bpf_fd_count);
      std::string comm = comm_for_pid(pid);
      if (!comm.empty()) {
        snapshot.pid_comms.emplace(pid, std::move(comm));
      }
    }

    if (snapshot.truncated) {
      break;
    }
  }

  ::closedir(proc);
  return snapshot;
}

void parse_mountinfo(BpffsSnapshot &snapshot) {
  int error_number = 0;
  auto data = read_file("/proc/self/mountinfo", &error_number);
  if (!data) {
    if (!is_missing_file_error(error_number)) {
      snapshot.errors.push_back(data.error());
    }
    return;
  }

  for (const auto &line : split_lines(*data)) {
    if (line.empty()) {
      continue;
    }

    std::string_view line_view(line);
    std::size_t sep = line_view.find(" - ");
    if (sep == std::string::npos) {
      continue;
    }

    std::string_view left = line_view.substr(0, sep);
    std::string_view right = line_view.substr(sep + 3);
    auto left_tokens = split_ws(left);
    auto right_tokens = split_ws(right);
    if (left_tokens.size() < 5 || right_tokens.empty()) {
      continue;
    }

    std::string_view mount_point = left_tokens[4];
    std::string_view fs_type = right_tokens[0];
    if (fs_type != "bpf") {
      continue;
    }

    snapshot.bpf_mount_points.emplace_back(mount_point);
    if (mount_point == "/sys/fs/bpf") {
      snapshot.canonical_mount = true;
    } else {
      snapshot.noncanonical_mounts.emplace_back(mount_point);
    }
  }
}

std::optional<std::string> suspicious_bpffs_reason(std::string_view path) {
  std::string lower = to_lower_copy(path);
  std::string_view lower_view(lower);
  std::size_t start = 0;
  while (start < lower_view.size()) {
    while (start < lower_view.size() && lower_view[start] == '/') {
      ++start;
    }
    if (start >= lower_view.size()) {
      break;
    }
    std::size_t end = lower_view.find('/', start);
    if (end == std::string::npos) {
      end = lower_view.size();
    }
    std::string_view segment = lower_view.substr(start, end - start);
    if (!segment.empty() && segment.front() == '.') {
      return std::string("hidden_segment");
    }
    for (auto token : kSuspiciousNameTokens) {
      if (segment.find(token) != std::string_view::npos) {
        return std::string("name_token:") + std::string(token);
      }
    }
    if (segment.size() > 120) {
      return std::string("segment_too_long");
    }
    start = end + 1;
  }
  return std::nullopt;
}

BpffsSnapshot collect_bpffs_snapshot() {
  BpffsSnapshot snapshot;

  struct stat st{};
  if (::stat("/sys/fs/bpf", &st) == 0) {
    snapshot.present = S_ISDIR(st.st_mode);
  } else if (!is_missing_file_error(errno)) {
    snapshot.errors.push_back("stat /sys/fs/bpf: " +
                              std::string(std::strerror(errno)));
  }

  parse_mountinfo(snapshot);

  if (!snapshot.present) {
    return snapshot;
  }

  auto errors = walk_dir_bounded(
      "/sys/fs/bpf", kMaxBpffsEntries,
      [&](const std::string &path, const struct stat &) {
        ++snapshot.entries_scanned;
        auto reason = suspicious_bpffs_reason(path);
        if (!reason) {
          return;
        }
        if (snapshot.suspicious_paths.size() >= kMaxExamples) {
          return;
        }
        snapshot.suspicious_paths.push_back(path + " (" + *reason + ")");
      },
      24);

  if (snapshot.entries_scanned >= kMaxBpffsEntries) {
    snapshot.truncated = true;
  }
  for (auto &error : errors) {
    push_error_limited(snapshot.errors, std::move(error));
  }

  return snapshot;
}

std::optional<long long> read_sysctl_int(const std::string &path,
                                         std::vector<std::string> &errors) {
  int error_number = 0;
  auto data = read_file(path, &error_number);
  if (!data) {
    if (!is_missing_file_error(error_number)) {
      push_error_limited(errors, data.error());
    }
    return std::nullopt;
  }

  auto value = parse_int64(*data, 10);
  if (!value) {
    push_error_limited(errors, "failed to parse integer from " + path);
  }
  return value;
}

HardeningSnapshot collect_hardening_snapshot() {
  HardeningSnapshot snapshot;
  snapshot.unprivileged_bpf_disabled = read_sysctl_int(
      "/proc/sys/kernel/unprivileged_bpf_disabled", snapshot.errors);
  snapshot.jit_enable =
      read_sysctl_int("/proc/sys/net/core/bpf_jit_enable", snapshot.errors);
  snapshot.jit_harden =
      read_sysctl_int("/proc/sys/net/core/bpf_jit_harden", snapshot.errors);
  snapshot.jit_kallsyms =
      read_sysctl_int("/proc/sys/net/core/bpf_jit_kallsyms", snapshot.errors);
  return snapshot;
}

bool is_likely_legit_owner(std::string_view owner) {
  std::string lower = to_lower_copy(owner);
  for (auto prefix : kLikelyLegitOwnerPrefixes) {
    if (lower.starts_with(prefix)) {
      return true;
    }
  }
  return false;
}

bool owners_look_legit(const ProgramInfo &program) {
  if (program.owners.empty()) {
    return false;
  }
  for (const auto &owner : program.owners) {
    if (!is_likely_legit_owner(owner)) {
      return false;
    }
  }
  return true;
}

bool match_pattern(std::string_view value, const TargetPattern &pattern) {
  switch (pattern.kind) {
  case MatchKind::Prefix:
    return value.starts_with(pattern.pattern);
  case MatchKind::Contains:
    return value.find(pattern.pattern) != std::string_view::npos;
  case MatchKind::Exact:
    return value == pattern.pattern;
  }
  return false;
}

std::vector<std::string> sensitive_tags(const ProgramInfo &program) {
  std::unordered_set<std::string_view> tags;
  for (const auto &entry : program.context_strings) {
    std::string lower = to_lower_copy(entry);
    for (const auto &pattern : kSensitiveTargetPatterns) {
      if (match_pattern(lower, pattern)) {
        tags.insert(pattern.tag);
      }
    }
  }
  std::vector<std::string> out;
  out.reserve(tags.size());
  for (auto tag : tags) {
    out.emplace_back(tag);
  }
  std::sort(out.begin(), out.end());
  return out;
}

std::vector<std::string> suspicious_name_tokens(std::string_view name) {
  std::vector<std::string> tokens;
  std::string lower = to_lower_copy(name);
  for (auto token : kSuspiciousNameTokens) {
    if (lower.find(token) != std::string_view::npos) {
      tokens.emplace_back(token);
    }
  }
  return tokens;
}

std::string summarize_owners(const ProgramInfo &program) {
  if (program.owners.empty()) {
    return "none";
  }
  std::size_t count =
      std::min(program.owners.size(), static_cast<std::size_t>(2));
  std::vector<std::string> preview(program.owners.begin(),
                                   program.owners.begin() + count);
  std::string summary = join(preview, ",");
  if (program.owners.size() > count) {
    summary.append(",+");
    summary.append(std::to_string(program.owners.size() - count));
  }
  return summary;
}

std::string
format_program_example(const ProgramInfo &program,
                       const std::vector<std::string> &tags,
                       const std::vector<std::string> &name_tokens) {
  std::string out = "id=" + std::to_string(program.id) +
                    " type=" + program.type + " name=" + program.name +
                    " owners=" + summarize_owners(program) +
                    " links=" + std::to_string(program.link_count);
  if (!tags.empty()) {
    out.append(" tags=");
    out.append(join(tags, "|"));
  }
  if (!name_tokens.empty()) {
    out.append(" tokens=");
    out.append(join(name_tokens, "|"));
  }
  return out;
}

void correlate_links(std::vector<ProgramInfo> &programs,
                     const std::vector<LinkInfo> &links) {
  std::unordered_map<std::uint64_t, std::size_t> index;
  index.reserve(programs.size());
  for (std::size_t i = 0; i < programs.size(); ++i) {
    index.emplace(programs[i].id, i);
  }

  for (const auto &link : links) {
    auto it = index.find(link.prog_id);
    if (it == index.end()) {
      continue;
    }
    ProgramInfo &program = programs[it->second];
    ++program.link_count;
    for (const auto &entry : link.context_strings) {
      append_unique(program.context_strings, entry, 128);
    }
  }
}

ProgramAssessment assess_programs(const std::vector<ProgramInfo> &programs,
                                  bool pid_metadata_available) {
  ProgramAssessment assessment;

  for (const auto &program : programs) {
    bool high_risk = contains_literal(kHighRiskProgramTypes, program.type);
    bool network_type = contains_literal(kNetworkProgramTypes, program.type);
    bool ownerless = pid_metadata_available && program.pids.empty();
    bool owners_known = owners_look_legit(program);
    bool owner_anomaly = pid_metadata_available && (ownerless || !owners_known);
    auto tags = sensitive_tags(program);
    auto tokens = suspicious_name_tokens(program.name);

    bool has_sensitive_tags = !tags.empty();
    bool suspicious_name = !tokens.empty();

    bool critical = high_risk && ownerless && has_sensitive_tags;
    bool warning =
        (!critical && ((high_risk && has_sensitive_tags && owner_anomaly) ||
                       (high_risk && ownerless && program.link_count == 0) ||
                       (suspicious_name &&
                        (high_risk || network_type || has_sensitive_tags))));

    if (ownerless && has_sensitive_tags && high_risk) {
      ++assessment.ownerless_sensitive;
    }

    if (critical) {
      assessment.critical_examples.push_back(
          format_program_example(program, tags, tokens));
      continue;
    }
    if (warning) {
      assessment.warning_examples.push_back(
          format_program_example(program, tags, tokens));
    }
  }

  return assessment;
}

void add_hardening_findings(ScanResult &result,
                            const HardeningSnapshot &snapshot) {
  std::vector<std::string> issues;

  if (snapshot.unprivileged_bpf_disabled &&
      *snapshot.unprivileged_bpf_disabled <= 0) {
    issues.push_back("unprivileged_bpf_disabled=0 (unprivileged BPF enabled)");
  }
  if (snapshot.jit_enable && *snapshot.jit_enable == 2) {
    issues.push_back("bpf_jit_enable=2 (debug mode exposes JIT details)");
  }
  if (snapshot.jit_enable && *snapshot.jit_enable > 0 && snapshot.jit_harden &&
      *snapshot.jit_harden == 0) {
    issues.push_back("bpf_jit_harden=0 while JIT is enabled");
  }
  if (snapshot.jit_kallsyms && *snapshot.jit_kallsyms > 0) {
    issues.push_back("bpf_jit_kallsyms enabled");
  }

  if (issues.empty()) {
    return;
  }

  Finding finding(Severity::Warning, "Permissive BPF hardening settings");
  finding
      .with_detail("Kernel BPF hardening sysctls are configured in a way "
                   "that can increase stealth and exploitability.")
      .with_evidence("issues", summarize_list(issues));

  if (snapshot.unprivileged_bpf_disabled) {
    finding.with_evidence("unprivileged_bpf_disabled",
                          std::to_string(*snapshot.unprivileged_bpf_disabled));
  }
  if (snapshot.jit_enable) {
    finding.with_evidence("bpf_jit_enable",
                          std::to_string(*snapshot.jit_enable));
  }
  if (snapshot.jit_harden) {
    finding.with_evidence("bpf_jit_harden",
                          std::to_string(*snapshot.jit_harden));
  }
  if (snapshot.jit_kallsyms) {
    finding.with_evidence("bpf_jit_kallsyms",
                          std::to_string(*snapshot.jit_kallsyms));
  }

  result.add_finding(std::move(finding));
}

void add_bpffs_findings(ScanResult &result, const BpffsSnapshot &snapshot,
                        std::size_t objects_loaded) {
  if (snapshot.present && !snapshot.canonical_mount && objects_loaded > 0) {
    Finding finding(Severity::Warning, "BPF objects loaded without canonical "
                                       "/sys/fs/bpf mount");
    finding
        .with_detail("BPF objects are present but /sys/fs/bpf is not mounted "
                     "as bpffs; persistence visibility may be reduced.")
        .with_evidence("objects_loaded", std::to_string(objects_loaded));
    if (!snapshot.bpf_mount_points.empty()) {
      finding.with_evidence("bpf_mount_points",
                            summarize_list(snapshot.bpf_mount_points));
    }
    result.add_finding(std::move(finding));
  }

  if (!snapshot.noncanonical_mounts.empty()) {
    Finding finding(Severity::Warning,
                    "Additional non-canonical bpffs mounts detected");
    finding
        .with_detail("Unexpected bpffs mount points can be used to pin BPF "
                     "objects outside standard inspection paths.")
        .with_evidence("mount_points",
                       summarize_list(snapshot.noncanonical_mounts));
    result.add_finding(std::move(finding));
  }

  if (!snapshot.suspicious_paths.empty()) {
    Finding finding(Severity::Warning, "Suspicious bpffs pin path names");
    finding
        .with_detail("Pin paths under /sys/fs/bpf include hidden or suspicious "
                     "segments commonly used for stealth naming.")
        .with_evidence("entries_scanned",
                       std::to_string(snapshot.entries_scanned))
        .with_evidence("examples", summarize_list(snapshot.suspicious_paths));
    if (snapshot.truncated) {
      finding.with_evidence("scan_truncated", "1");
    }
    result.add_finding(std::move(finding));
  }
}

struct LinkIntegrityMismatches {
  std::unordered_map<std::string, std::string> unknown_link_refs;
  std::unordered_map<std::string, std::string> missing_map_refs;
};

LinkIntegrityMismatches
collect_link_integrity_mismatches(const std::vector<ProgramInfo> &programs,
                                  const std::vector<MapInfo> &maps,
                                  const std::vector<LinkInfo> &links) {
  LinkIntegrityMismatches mismatches;

  std::unordered_set<std::uint64_t> known_prog_ids;
  known_prog_ids.reserve(programs.size());
  for (const auto &program : programs) {
    known_prog_ids.insert(program.id);
  }

  std::unordered_set<std::uint64_t> known_map_ids;
  known_map_ids.reserve(maps.size());
  for (const auto &map : maps) {
    known_map_ids.insert(map.id);
  }

  for (const auto &link : links) {
    if (known_prog_ids.contains(link.prog_id)) {
      continue;
    }
    std::string key = "link:" + std::to_string(link.id) +
                      ":prog:" + std::to_string(link.prog_id);
    std::string value = "link=" + std::to_string(link.id) +
                        " prog=" + std::to_string(link.prog_id) +
                        " type=" + link.type;
    mismatches.unknown_link_refs.emplace(std::move(key), std::move(value));
  }

  for (const auto &program : programs) {
    for (auto map_id : program.map_ids) {
      if (known_map_ids.contains(map_id)) {
        continue;
      }
      std::string key = "prog:" + std::to_string(program.id) +
                        ":map:" + std::to_string(map_id);
      std::string value = "prog=" + std::to_string(program.id) +
                          " name=" + program.name +
                          " map=" + std::to_string(map_id);
      mismatches.missing_map_refs.emplace(std::move(key), std::move(value));
    }
  }

  return mismatches;
}

bool has_link_integrity_mismatches(const LinkIntegrityMismatches &mismatches) {
  return !mismatches.unknown_link_refs.empty() ||
         !mismatches.missing_map_refs.empty();
}

LinkIntegrityMismatches
intersect_mismatches(const LinkIntegrityMismatches &lhs,
                     const LinkIntegrityMismatches &rhs) {
  LinkIntegrityMismatches out;
  for (const auto &[key, value] : lhs.unknown_link_refs) {
    if (rhs.unknown_link_refs.contains(key)) {
      out.unknown_link_refs.emplace(key, value);
    }
  }
  for (const auto &[key, value] : lhs.missing_map_refs) {
    if (rhs.missing_map_refs.contains(key)) {
      out.missing_map_refs.emplace(key, value);
    }
  }
  return out;
}

std::vector<std::string>
mismatch_examples(const std::unordered_map<std::string, std::string> &items) {
  std::vector<std::string> out;
  out.reserve(items.size());
  for (const auto &[_, value] : items) {
    out.push_back(value);
  }
  std::sort(out.begin(), out.end());
  return out;
}

void add_link_integrity_findings(ScanResult &result,
                                 const LinkIntegrityMismatches &mismatches,
                                 bool reconciled,
                                 std::size_t suppressed_unknown,
                                 std::size_t suppressed_missing) {
  if (!mismatches.unknown_link_refs.empty()) {
    Finding finding(reconciled ? Severity::Critical : Severity::Warning,
                    "BPF links reference unknown program IDs");
    finding
        .with_detail(
            reconciled
                ? "Persistent across two snapshots: bpftool link inventory "
                  "contains program references absent from the bpftool program "
                  "inventory."
                : "bpftool link inventory contains program references absent "
                  "from "
                  "the program inventory. This can be transient if inventories "
                  "change during collection.")
        .with_evidence("unknown_reference_count",
                       std::to_string(mismatches.unknown_link_refs.size()))
        .with_evidence("examples", summarize_list(mismatch_examples(
                                       mismatches.unknown_link_refs)));
    if (reconciled) {
      finding.with_evidence("snapshots", "2");
      if (suppressed_unknown > 0) {
        finding.with_evidence("suppressed_transient_unknown_refs",
                              std::to_string(suppressed_unknown));
      }
    }
    result.add_finding(std::move(finding));
  }

  if (!mismatches.missing_map_refs.empty()) {
    Finding finding(Severity::Warning,
                    "BPF programs reference missing map IDs");
    finding
        .with_detail(
            reconciled
                ? "Persistent across two snapshots: program-to-map references "
                  "include map IDs absent from the map inventory."
                : "Program-to-map references include map IDs absent from the "
                  "map "
                  "inventory. This can be transient if inventories change "
                  "during "
                  "collection.")
        .with_evidence("missing_reference_count",
                       std::to_string(mismatches.missing_map_refs.size()))
        .with_evidence("examples", summarize_list(mismatch_examples(
                                       mismatches.missing_map_refs)));
    if (reconciled) {
      finding.with_evidence("snapshots", "2");
      if (suppressed_missing > 0) {
        finding.with_evidence("suppressed_transient_missing_refs",
                              std::to_string(suppressed_missing));
      }
    }
    result.add_finding(std::move(finding));
  }
}

void add_behavior_findings(ScanResult &result,
                           const ProgramAssessment &assessment) {
  if (!assessment.critical_examples.empty()) {
    Finding finding(Severity::Critical,
                    "Ownerless high-risk BPF hooks on sensitive targets");
    finding
        .with_detail("High-risk BPF program types are attached to sensitive "
                     "kernel targets while lacking live owner PIDs.")
        .with_evidence("count",
                       std::to_string(assessment.critical_examples.size()))
        .with_evidence("examples",
                       summarize_list(assessment.critical_examples));
    result.add_finding(std::move(finding));
  }

  if (!assessment.warning_examples.empty()) {
    Finding finding(Severity::Warning,
                    "Suspicious BPF hook characteristics requiring triage");
    finding
        .with_detail("Loaded BPF programs show risky attachment patterns, "
                     "owner anomalies, or suspicious naming.")
        .with_evidence("count",
                       std::to_string(assessment.warning_examples.size()))
        .with_evidence("examples", summarize_list(assessment.warning_examples));
    result.add_finding(std::move(finding));
  }
}

void add_proc_fd_correlation_finding(ScanResult &result,
                                     const ProcFdSnapshot &snapshot,
                                     const std::vector<ProgramInfo> &programs,
                                     const std::vector<MapInfo> &maps,
                                     bool pid_metadata_available,
                                     std::size_t ownerless_sensitive_count) {
  if (!snapshot.available || !pid_metadata_available) {
    return;
  }

  std::unordered_set<std::uint32_t> known_owner_pids;
  for (const auto &program : programs) {
    for (auto pid : program.pids) {
      known_owner_pids.insert(pid);
    }
  }
  for (const auto &map : maps) {
    for (auto pid : map.pids) {
      known_owner_pids.insert(pid);
    }
  }

  if (known_owner_pids.empty()) {
    return;
  }

  std::vector<std::string> unknown_owner_examples;
  std::size_t unknown_owner_count = 0;
  for (const auto &[pid, fd_count] : snapshot.pid_fd_counts) {
    if (known_owner_pids.contains(pid)) {
      continue;
    }
    ++unknown_owner_count;
    if (unknown_owner_examples.size() >= kMaxExamples) {
      continue;
    }
    std::string line = "pid=" + std::to_string(pid);
    auto comm_it = snapshot.pid_comms.find(pid);
    if (comm_it != snapshot.pid_comms.end()) {
      line.append(" comm=");
      line.append(comm_it->second);
    }
    line.append(" bpf_fds=");
    line.append(std::to_string(fd_count));
    unknown_owner_examples.push_back(std::move(line));
  }

  if (unknown_owner_count == 0) {
    return;
  }

  Severity severity = Severity::Warning;
  if (ownerless_sensitive_count > 0 && unknown_owner_count >= 3) {
    severity = Severity::Critical;
  }

  Finding finding(severity,
                  "Processes with BPF anon inode FDs missing from bpftool "
                  "owner metadata");
  finding
      .with_detail("Some processes hold anon_inode:bpf* descriptors but are "
                   "absent from bpftool-reported program/map owners.")
      .with_evidence("unknown_pid_count", std::to_string(unknown_owner_count))
      .with_evidence("known_owner_pid_count",
                     std::to_string(known_owner_pids.size()))
      .with_evidence("examples", summarize_list(unknown_owner_examples))
      .with_evidence("proc_pids_scanned", std::to_string(snapshot.pids_scanned))
      .with_evidence("proc_fds_scanned", std::to_string(snapshot.fds_scanned));
  if (snapshot.permission_denied > 0) {
    finding.with_evidence("proc_permission_denied",
                          std::to_string(snapshot.permission_denied));
  }
  if (snapshot.truncated) {
    finding.with_evidence("proc_scan_truncated", "1");
  }

  result.add_finding(std::move(finding));
}

ScanResult run() {
  ScanResult result;

  HardeningSnapshot hardening = collect_hardening_snapshot();
  for (const auto &error : hardening.errors) {
    result.add_error(error);
  }
  add_hardening_findings(result, hardening);

  BpffsSnapshot bpffs = collect_bpffs_snapshot();
  for (const auto &error : bpffs.errors) {
    result.add_error(error);
  }

  auto prog_json = run_bpftool_json({"bpftool", "-j", "prog", "show"},
                                    "bpftool prog show", result);
  auto map_json = run_bpftool_json({"bpftool", "-j", "map", "show"},
                                   "bpftool map show", result);
  auto link_json = run_bpftool_json({"bpftool", "-j", "link", "show"},
                                    "bpftool link show", result);

  ProgramSnapshot program_snapshot;
  if (prog_json) {
    program_snapshot = parse_programs(*prog_json, result);
  }

  MapSnapshot map_snapshot;
  if (map_json) {
    map_snapshot = parse_maps(*map_json, result);
  }

  std::vector<LinkInfo> links;
  if (link_json) {
    links = parse_links(*link_json, result);
  }

  correlate_links(program_snapshot.programs, links);
  LinkIntegrityMismatches link_mismatches = collect_link_integrity_mismatches(
      program_snapshot.programs, map_snapshot.maps, links);
  bool link_mismatches_reconciled = false;
  std::size_t suppressed_unknown = 0;
  std::size_t suppressed_missing = 0;

  if (has_link_integrity_mismatches(link_mismatches)) {
    auto prog_json_second =
        run_bpftool_json_quiet({"bpftool", "-j", "prog", "show"});
    auto map_json_second =
        run_bpftool_json_quiet({"bpftool", "-j", "map", "show"});
    auto link_json_second =
        run_bpftool_json_quiet({"bpftool", "-j", "link", "show"});

    if (prog_json_second && map_json_second && link_json_second) {
      ScanResult scratch;
      ProgramSnapshot program_second =
          parse_programs(*prog_json_second, scratch);
      MapSnapshot map_second = parse_maps(*map_json_second, scratch);
      auto links_second = parse_links(*link_json_second, scratch);
      correlate_links(program_second.programs, links_second);

      auto second_mismatches = collect_link_integrity_mismatches(
          program_second.programs, map_second.maps, links_second);
      auto persistent =
          intersect_mismatches(link_mismatches, second_mismatches);

      suppressed_unknown = link_mismatches.unknown_link_refs.size() -
                           persistent.unknown_link_refs.size();
      suppressed_missing = link_mismatches.missing_map_refs.size() -
                           persistent.missing_map_refs.size();
      link_mismatches = std::move(persistent);
      link_mismatches_reconciled = true;
    }
  }

  add_link_integrity_findings(result, link_mismatches,
                              link_mismatches_reconciled, suppressed_unknown,
                              suppressed_missing);

  ProgramAssessment assessment = assess_programs(
      program_snapshot.programs, program_snapshot.pid_metadata_available);
  add_behavior_findings(result, assessment);

  std::size_t object_count = program_snapshot.programs.size() +
                             map_snapshot.maps.size() + links.size();
  add_bpffs_findings(result, bpffs, object_count);

  bool pid_metadata_available = program_snapshot.pid_metadata_available ||
                                map_snapshot.pid_metadata_available;
  bool should_collect_proc_fds = pid_metadata_available && object_count > 0;

  if (should_collect_proc_fds) {
    ProcFdSnapshot proc_fd_snapshot = collect_proc_fd_snapshot();
    for (const auto &error : proc_fd_snapshot.errors) {
      result.add_error(error);
    }
    add_proc_fd_correlation_finding(
        result, proc_fd_snapshot, program_snapshot.programs, map_snapshot.maps,
        pid_metadata_available, assessment.ownerless_sensitive);
  }

  return result;
}

constexpr std::array<Category, 4> kCategories = {
    Category::Kernel, Category::Network, Category::Persistence,
    Category::Process};
const std::array<Requirement, 1> kRequirements = {
    Requirement::external_tool("bpftool"),
};

static Registrar reg_{Scanner{
    .name = "bpf_rootkit_detection",
    .func = run,
    .categories = kCategories,
    .requirements = kRequirements,
}};

} // namespace
