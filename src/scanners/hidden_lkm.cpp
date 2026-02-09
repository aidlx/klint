#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <string>
#include <string_view>
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
const std::unordered_set<std::string> kModuleExclusions = {"bpf"};

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

bool is_missing_file_error(int error_number) {
  return error_number == ENOENT || error_number == ENOTDIR;
}

std::unordered_set<std::string> parse_proc_modules(std::string_view data) {
  std::unordered_set<std::string> modules;
  for (const auto &line : split_lines(data)) {
    std::string_view view = trim(line);
    if (view.empty()) {
      continue;
    }
    std::size_t end = view.find_first_of(" \t");
    if (end == std::string_view::npos) {
      modules.emplace(view);
    } else if (end > 0) {
      modules.emplace(view.substr(0, end));
    }
  }
  return modules;
}

std::unordered_set<std::string> parse_kallsyms_modules(std::string_view data) {
  std::unordered_set<std::string> modules;
  for (const auto &line : split_lines(data)) {
    std::string_view view = trim(line);
    if (view.empty()) {
      continue;
    }
    if (view.back() != ']') {
      continue;
    }
    std::size_t open = view.rfind('[');
    if (open == std::string_view::npos || open + 1 >= view.size()) {
      continue;
    }
    std::string_view name = view.substr(open + 1, view.size() - open - 2);
    name = trim(name);
    if (name.empty()) {
      continue;
    }
    if (name.find(' ') != std::string_view::npos) {
      continue;
    }
    modules.emplace(name);
  }
  return modules;
}

struct SysModuleSnapshot {
  std::unordered_set<std::string> modules;
  std::vector<std::string> errors;
  bool available = false;
};

SysModuleSnapshot read_sys_modules() {
  SysModuleSnapshot snapshot;

  struct stat root_stat{};
  if (::stat("/sys/module", &root_stat) != 0) {
    if (!is_missing_file_error(errno)) {
      snapshot.errors.push_back("stat /sys/module: " +
                                std::string(std::strerror(errno)));
    }
    return snapshot;
  }
  if (!S_ISDIR(root_stat.st_mode)) {
    return snapshot;
  }
  snapshot.available = true;

  snapshot.errors = walk_dir_bounded(
      "/sys/module", 65536,
      [&](const std::string &path, const struct stat &st) {
        if (!S_ISDIR(st.st_mode)) {
          return;
        }
        std::size_t slash = path.find_last_of('/');
        if (slash == std::string::npos || slash + 1 >= path.size()) {
          return;
        }
        snapshot.modules.emplace(path.substr(slash + 1));
      },
      0);

  for (const auto &error : snapshot.errors) {
    if (error.starts_with("opendir /sys/module")) {
      snapshot.available = false;
      snapshot.modules.clear();
      break;
    }
  }

  return snapshot;
}

std::vector<std::string>
set_difference(const std::unordered_set<std::string> &lhs,
               const std::unordered_set<std::string> &rhs) {
  std::vector<std::string> diff;
  diff.reserve(lhs.size());
  for (const auto &item : lhs) {
    if (!rhs.contains(item)) {
      diff.push_back(item);
    }
  }
  std::sort(diff.begin(), diff.end());
  return diff;
}

std::string summarize_list(const std::vector<std::string> &items) {
  if (items.empty()) {
    return "-";
  }
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

void apply_module_exclusions(std::unordered_set<std::string> &modules) {
  if (modules.empty() || kModuleExclusions.empty()) {
    return;
  }
  for (const auto &name : kModuleExclusions) {
    modules.erase(name);
  }
}

ScanResult run() {
  ScanResult result;

  auto proc_data = read_file("/proc/modules");
  if (!proc_data) {
    result.add_error(proc_data.error());
  }

  auto ksym_data = read_file("/proc/kallsyms");
  if (!ksym_data) {
    result.add_error(ksym_data.error());
  }

  SysModuleSnapshot sys_snapshot = read_sys_modules();
  for (const auto &error : sys_snapshot.errors) {
    result.add_error(error);
  }

  if (!ksym_data) {
    return result;
  }

  bool proc_available = proc_data.has_value();
  bool sys_available = sys_snapshot.available;

  std::unordered_set<std::string> proc_modules;
  if (proc_available) {
    proc_modules = parse_proc_modules(*proc_data);
  }

  std::unordered_set<std::string> ksym_modules =
      parse_kallsyms_modules(*ksym_data);

  if (proc_available && !proc_modules.empty() && ksym_modules.empty()) {
    result.add_error("kallsyms did not expose module symbols; check "
                     "kernel.kptr_restrict or CONFIG_KALLSYMS");
    return result;
  }

  if (ksym_modules.empty()) {
    return result;
  }

  std::unordered_set<std::string> proc_set = std::move(proc_modules);
  std::unordered_set<std::string> sys_set = std::move(sys_snapshot.modules);
  apply_module_exclusions(ksym_modules);
  apply_module_exclusions(proc_set);
  apply_module_exclusions(sys_set);

  if (ksym_modules.empty()) {
    return result;
  }

  std::vector<std::string> missing_both;
  if (proc_available && sys_available) {
    std::unordered_set<std::string> proc_union = proc_set;
    for (const auto &item : sys_set) {
      proc_union.insert(item);
    }

    for (const auto &item : ksym_modules) {
      if (!proc_union.contains(item)) {
        missing_both.push_back(item);
      }
    }
    std::sort(missing_both.begin(), missing_both.end());
  }

  if (!missing_both.empty()) {
    Finding finding(Severity::Critical,
                    "Kallsyms modules missing from procfs and sysfs");
    finding
        .with_detail("Modules appear in /proc/kallsyms but are absent from "
                     "/proc/modules and /sys/module.")
        .with_evidence("missing_count", std::to_string(missing_both.size()))
        .with_evidence("examples", summarize_list(missing_both));
    if (proc_set.empty() && sys_set.empty()) {
      finding.with_evidence("source_note",
                            "procfs/sysfs module inventories are empty");
    }
    result.add_finding(std::move(finding));
  }

  std::vector<std::string> missing_proc;
  if (proc_available) {
    missing_proc = set_difference(ksym_modules, proc_set);
    if (!missing_both.empty()) {
      std::unordered_set<std::string> both_set(missing_both.begin(),
                                               missing_both.end());
      std::vector<std::string> filtered;
      filtered.reserve(missing_proc.size());
      for (const auto &item : missing_proc) {
        if (!both_set.contains(item)) {
          filtered.push_back(item);
        }
      }
      missing_proc.swap(filtered);
    }
  }

  if (!missing_proc.empty()) {
    Finding finding(Severity::Warning,
                    "Kallsyms modules missing from /proc/modules");
    finding
        .with_detail("Modules appear in /proc/kallsyms but are absent from "
                     "/proc/modules.")
        .with_evidence("missing_count", std::to_string(missing_proc.size()))
        .with_evidence("examples", summarize_list(missing_proc));
    if (!sys_available) {
      finding.with_evidence("note",
                            "/sys/module unavailable; procfs-only comparison");
    }
    result.add_finding(std::move(finding));
  }

  if (sys_available) {
    std::vector<std::string> missing_sys =
        set_difference(ksym_modules, sys_set);
    if (!missing_both.empty()) {
      std::unordered_set<std::string> both_set(missing_both.begin(),
                                               missing_both.end());
      std::vector<std::string> filtered;
      filtered.reserve(missing_sys.size());
      for (const auto &item : missing_sys) {
        if (!both_set.contains(item)) {
          filtered.push_back(item);
        }
      }
      missing_sys.swap(filtered);
    }

    if (!missing_sys.empty()) {
      Finding finding(Severity::Warning,
                      "Kallsyms modules missing from /sys/module");
      finding
          .with_detail("Modules appear in /proc/kallsyms but are absent from "
                       "/sys/module.")
          .with_evidence("missing_count", std::to_string(missing_sys.size()))
          .with_evidence("examples", summarize_list(missing_sys));
      if (!proc_available) {
        finding.with_evidence(
            "note", "/proc/modules unavailable; sysfs-only comparison");
      }
      result.add_finding(std::move(finding));
    }
  }

  if (result.has_findings()) {
    std::string proc_modules_count =
        proc_available ? std::to_string(proc_set.size()) : "unavailable";
    std::string sys_modules_count =
        sys_available ? std::to_string(sys_set.size()) : "unavailable";
    result.add_finding(
        Finding(Severity::Info, "Module inventory summary")
            .with_detail("Counts reflect data sources used for the comparison.")
            .with_evidence("kallsyms_modules",
                           std::to_string(ksym_modules.size()))
            .with_evidence("proc_modules", proc_modules_count)
            .with_evidence("sys_modules", sys_modules_count));
  }

  return result;
}

constexpr std::array<Category, 1> kCategories = {Category::Kernel};
const std::array<Requirement, 0> kRequirements = {};

static Registrar reg_{Scanner{
    .name = "hidden_lkm",
    .func = run,
    .categories = kCategories,
    .requirements = kRequirements,
}};

} // namespace
