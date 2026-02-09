#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "critical_kernel_patterns.hpp"
#include "scanner.hpp"

namespace {

using klint::Category;
using klint::Finding;
using klint::Registrar;
using klint::Requirement;
using klint::Scanner;
using klint::ScanResult;
using klint::Severity;
using klint::patterns::CriticalPattern;
using klint::patterns::MatchKind;
using klint::util::join;
using klint::util::read_file;
using klint::util::split_lines;

constexpr std::size_t kMaxExamples = 20;
constexpr auto &kCriticalPatterns = klint::patterns::kCriticalKernelPatterns;

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

std::optional<bool> parse_bool(std::string_view text) {
  std::string_view value = trim(text);
  if (value.empty()) {
    return std::nullopt;
  }
  if (value == "0" || value == "N" || value == "n" || value == "off" ||
      value == "OFF") {
    return false;
  }
  if (value == "1" || value == "Y" || value == "y" || value == "on" ||
      value == "ON") {
    return true;
  }
  if (std::isdigit(static_cast<unsigned char>(value.front()))) {
    return value.front() != '0';
  }
  return std::nullopt;
}

std::string bool_label(const std::optional<bool> &value) {
  if (!value) {
    return "unknown";
  }
  return *value ? "1" : "0";
}

struct Tokens {
  std::string_view first;
  std::string_view second;
};

std::optional<Tokens> split_first_two_fields(std::string_view line) {
  line = trim(line);
  if (line.empty() || line.front() == '#') {
    return std::nullopt;
  }

  std::size_t first_end = line.find_first_of(" \t");
  if (first_end == std::string_view::npos) {
    return std::nullopt;
  }
  std::size_t second_start = line.find_first_not_of(" \t", first_end);
  if (second_start == std::string_view::npos) {
    return std::nullopt;
  }
  std::size_t second_end = line.find_first_of(" \t", second_start);
  if (second_end == std::string_view::npos) {
    second_end = line.size();
  }
  return Tokens{line.substr(0, first_end),
                line.substr(second_start, second_end - second_start)};
}

struct ProbeSpec {
  char type = 'p';
  std::string group;
  std::string event;
};

std::optional<ProbeSpec> parse_probe_spec(std::string_view token) {
  token = trim(token);
  if (token.empty()) {
    return std::nullopt;
  }
  char type = token.front();
  if (type != 'p' && type != 'r') {
    return std::nullopt;
  }
  std::string_view rest = token.substr(1);
  if (!rest.empty() && rest.front() == ':') {
    rest.remove_prefix(1);
  }
  std::string_view group;
  std::string_view event;
  if (rest.empty()) {
    group = "kprobes";
    event = "unknown";
  } else {
    std::size_t slash = rest.find('/');
    if (slash == std::string_view::npos) {
      group = "kprobes";
      event = rest;
    } else {
      group = rest.substr(0, slash);
      event = rest.substr(slash + 1);
    }
  }
  group = trim(group);
  event = trim(event);
  if (group.empty()) {
    group = "kprobes";
  }
  if (event.empty()) {
    event = "unknown";
  }
  return ProbeSpec{type, std::string(group), std::string(event)};
}

bool is_symbol_like(std::string_view symbol) {
  symbol = trim(symbol);
  if (symbol.empty()) {
    return false;
  }
  unsigned char first = static_cast<unsigned char>(symbol.front());
  if (!std::isalpha(first) && symbol.front() != '_') {
    return false;
  }
  for (char c : symbol) {
    if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '.' ||
          c == '$')) {
      return false;
    }
  }
  return true;
}

std::string normalize_symbol(std::string_view target) {
  std::string_view view = trim(target);
  if (view.empty()) {
    return {};
  }
  std::size_t colon = view.find(':');
  if (colon != std::string_view::npos && colon + 1 < view.size()) {
    view = view.substr(colon + 1);
  }
  std::size_t cut = view.find_first_of("+-@");
  if (cut != std::string_view::npos) {
    view = view.substr(0, cut);
  }
  cut = view.find('%');
  if (cut != std::string_view::npos) {
    view = view.substr(0, cut);
  }
  return std::string(trim(view));
}

bool match_pattern(std::string_view entry, const CriticalPattern &pattern) {
  switch (pattern.kind) {
  case MatchKind::Prefix:
    if (entry.starts_with(pattern.pattern)) {
      return true;
    }
    return false;
  case MatchKind::Contains:
    return entry.find(pattern.pattern) != std::string_view::npos;
  case MatchKind::Exact:
    return entry == pattern.pattern;
  }
  return false;
}

std::vector<std::string> match_tags(std::string_view entry) {
  std::unordered_set<std::string_view> tags;
  for (const auto &pattern : kCriticalPatterns) {
    if (match_pattern(entry, pattern)) {
      tags.insert(pattern.tag);
    }
  }
  std::vector<std::string> out;
  out.reserve(tags.size());
  for (auto tag : tags) {
    out.emplace_back(tag);
  }
  return out;
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

std::string summarize_tag_counts(
    const std::unordered_map<std::string, std::size_t> &counts) {
  if (counts.empty()) {
    return "-";
  }
  std::vector<std::pair<std::string, std::size_t>> items;
  items.reserve(counts.size());
  for (const auto &entry : counts) {
    items.push_back(entry);
  }
  std::sort(items.begin(), items.end(), [](const auto &lhs, const auto &rhs) {
    if (lhs.second != rhs.second) {
      return lhs.second > rhs.second;
    }
    return lhs.first < rhs.first;
  });
  std::vector<std::string> parts;
  parts.reserve(items.size());
  for (const auto &item : items) {
    parts.push_back(item.first + ":" + std::to_string(item.second));
  }
  return join(parts, ", ");
}

std::optional<std::string> find_tracefs_root(ScanResult &result) {
  const std::array<std::string, 2> kCandidates = {"/sys/kernel/tracing",
                                                  "/sys/kernel/debug/tracing"};

  std::vector<std::string> errors;
  auto try_root = [&](const std::string &root) -> bool {
    int read_error = 0;
    auto data = read_file(root + "/current_tracer", &read_error);
    if (data) {
      return true;
    }
    if (!is_missing_file_error(read_error)) {
      errors.push_back(data.error());
    }
    return false;
  };

  for (const auto &root : kCandidates) {
    if (try_root(root)) {
      return root;
    }
  }

  auto mounts = read_file("/proc/mounts");
  if (!mounts) {
    errors.push_back(mounts.error());
  } else {
    for (const auto &line : split_lines(*mounts)) {
      std::string_view view = trim(line);
      if (view.empty()) {
        continue;
      }
      std::string_view fields[3];
      std::size_t pos = 0;
      bool ok = true;
      for (std::size_t i = 0; i < 3; ++i) {
        while (pos < view.size() && view[pos] == ' ') {
          ++pos;
        }
        if (pos >= view.size()) {
          ok = false;
          break;
        }
        std::size_t end = view.find(' ', pos);
        if (end == std::string_view::npos) {
          end = view.size();
        }
        fields[i] = view.substr(pos, end - pos);
        pos = end;
      }
      if (!ok) {
        continue;
      }
      std::string_view mount_point = fields[1];
      std::string_view fstype = fields[2];
      if (fstype == "tracefs") {
        std::string root(mount_point);
        if (try_root(root)) {
          return root;
        }
      } else if (fstype == "debugfs") {
        std::string root = std::string(mount_point) + std::string("/tracing");
        if (try_root(root)) {
          return root;
        }
      }
    }
  }

  for (const auto &error : errors) {
    result.add_error(error);
  }
  result.add_error(
      "tracefs not available; cannot inspect kprobe configuration");
  return std::nullopt;
}

struct ProbeMatch {
  ProbeSpec spec;
  std::string symbol;
  std::optional<bool> enabled;
  std::vector<std::string> tags;
};

std::optional<bool> read_enable_file(const std::string &path,
                                     ScanResult &result,
                                     std::size_t &missing_enable,
                                     std::size_t &enable_errors) {
  int read_error = 0;
  auto data = read_file(path, &read_error);
  if (!data) {
    if (is_missing_file_error(read_error)) {
      ++missing_enable;
      return std::nullopt;
    }
    ++enable_errors;
    result.add_error(data.error());
    return std::nullopt;
  }
  return parse_bool(*data);
}

std::optional<bool> combine_enable_state(std::optional<bool> event_enable,
                                         std::optional<bool> group_enable,
                                         std::optional<bool> global_enable) {
  if (event_enable.has_value() && !*event_enable) {
    return false;
  }
  if (group_enable.has_value() && !*group_enable) {
    return false;
  }
  if (global_enable.has_value() && !*global_enable) {
    return false;
  }
  if (!event_enable || !group_enable || !global_enable) {
    return std::nullopt;
  }
  return true;
}

std::string format_example(const ProbeMatch &match) {
  std::string type = match.spec.type == 'r' ? "kretprobe" : "kprobe";
  std::string name = match.spec.group + "/" + match.spec.event;
  std::string status = "unknown";
  if (match.enabled) {
    status = *match.enabled ? "enabled" : "disabled";
  }
  return type + ":" + name + "->" + match.symbol + " (" + status + ")";
}

ScanResult run() {
  ScanResult result;

  auto tracefs_root = find_tracefs_root(result);
  if (!tracefs_root) {
    return result;
  }

  std::string kprobe_path = *tracefs_root + "/kprobe_events";
  int read_error = 0;
  auto data = read_file(kprobe_path, &read_error);
  if (!data) {
    if (is_missing_file_error(read_error)) {
      result.add_error(
          "kprobe_events unavailable; check CONFIG_KPROBE_EVENTS or tracefs "
          "mount");
    } else {
      result.add_error(data.error());
    }
    return result;
  }

  std::size_t total_events = 0;
  std::size_t unparsed_entries = 0;
  std::size_t non_symbol_targets = 0;
  std::size_t enabled_sensitive = 0;
  std::size_t disabled_sensitive = 0;
  std::size_t unknown_sensitive = 0;
  std::size_t missing_event_enable = 0;
  std::size_t missing_group_enable = 0;
  std::size_t missing_global_enable = 0;
  std::size_t enable_errors = 0;

  std::optional<bool> global_enable =
      read_enable_file(*tracefs_root + "/events/enable", result,
                       missing_global_enable, enable_errors);

  std::unordered_map<std::string, std::optional<bool>> group_enable_cache;
  auto get_group_enable = [&](const std::string &group) -> std::optional<bool> {
    auto it = group_enable_cache.find(group);
    if (it != group_enable_cache.end()) {
      return it->second;
    }
    std::string path = *tracefs_root + "/events/" + group + "/enable";
    auto value =
        read_enable_file(path, result, missing_group_enable, enable_errors);
    group_enable_cache.emplace(group, value);
    return value;
  };

  std::unordered_map<std::string, std::size_t> tag_counts;
  std::vector<ProbeMatch> sensitive;

  for (const auto &line : split_lines(*data)) {
    std::string_view view = trim(line);
    if (view.empty() || view.front() == '#') {
      continue;
    }

    auto tokens = split_first_two_fields(view);
    if (!tokens) {
      ++unparsed_entries;
      continue;
    }

    auto spec = parse_probe_spec(tokens->first);
    if (!spec) {
      ++unparsed_entries;
      continue;
    }
    ++total_events;

    std::string symbol = normalize_symbol(tokens->second);
    if (!is_symbol_like(symbol)) {
      ++non_symbol_targets;
      continue;
    }

    auto tags = match_tags(symbol);
    if (tags.empty()) {
      continue;
    }

    ProbeMatch match;
    match.spec = std::move(*spec);
    match.symbol = std::move(symbol);
    match.tags = std::move(tags);
    std::string event_enable_path = *tracefs_root + "/events/" +
                                    match.spec.group + "/" + match.spec.event +
                                    "/enable";
    auto event_enable = read_enable_file(event_enable_path, result,
                                         missing_event_enable, enable_errors);
    auto group_enable = get_group_enable(match.spec.group);
    match.enabled =
        combine_enable_state(event_enable, group_enable, global_enable);

    if (!match.enabled.has_value()) {
      ++unknown_sensitive;
    } else if (*match.enabled) {
      ++enabled_sensitive;
    } else {
      ++disabled_sensitive;
    }

    for (const auto &tag : match.tags) {
      ++tag_counts[tag];
    }
    sensitive.push_back(std::move(match));
  }

  if (sensitive.empty()) {
    return result;
  }

  Severity severity = Severity::Warning;
  if (disabled_sensitive > 0 && enabled_sensitive == 0 &&
      unknown_sensitive == 0) {
    severity = Severity::Info;
  }

  Finding finding(
      severity,
      "Sensitive kprobe events detected (source attribution unavailable)");
  finding.with_detail(
      "Kprobe events target sensitive syscall, credential, module, VFS, or "
      "network paths. This is a heuristic signal only: the scanner does not "
      "map probes to owning tooling, so legitimate tracing/security agents can "
      "match this pattern.");

  finding.with_evidence("tracefs_root", *tracefs_root)
      .with_evidence("kprobe_events_path", kprobe_path)
      .with_evidence("total_events", std::to_string(total_events))
      .with_evidence("sensitive_events", std::to_string(sensitive.size()))
      .with_evidence("enabled_sensitive", std::to_string(enabled_sensitive))
      .with_evidence("disabled_sensitive", std::to_string(disabled_sensitive))
      .with_evidence("unknown_state_sensitive",
                     std::to_string(unknown_sensitive))
      .with_evidence("sensitive_categories", summarize_tag_counts(tag_counts))
      .with_evidence("attribution", "unavailable");
  if (global_enable.has_value()) {
    finding.with_evidence("events_enable", bool_label(global_enable));
  }

  std::vector<std::string> examples;
  examples.reserve(std::min(sensitive.size(), kMaxExamples));
  std::size_t count = std::min(sensitive.size(), kMaxExamples);
  for (std::size_t i = 0; i < count; ++i) {
    examples.push_back(format_example(sensitive[i]));
  }
  finding.with_evidence("examples", summarize_list(examples));

  if (non_symbol_targets > 0) {
    finding.with_evidence("non_symbol_targets",
                          std::to_string(non_symbol_targets));
  }
  if (unparsed_entries > 0) {
    finding.with_evidence("unparsed_entries", std::to_string(unparsed_entries));
  }
  if (missing_event_enable > 0) {
    finding.with_evidence("missing_event_enable_files",
                          std::to_string(missing_event_enable));
  }
  if (missing_group_enable > 0) {
    finding.with_evidence("missing_group_enable_files",
                          std::to_string(missing_group_enable));
  }
  if (missing_global_enable > 0) {
    finding.with_evidence("missing_global_enable_files",
                          std::to_string(missing_global_enable));
  }
  if (enable_errors > 0) {
    finding.with_evidence("enable_read_errors", std::to_string(enable_errors));
  }

  result.add_finding(std::move(finding));
  return result;
}

constexpr std::array<Category, 1> kCategories = {Category::Kernel};
const std::array<Requirement, 0> kRequirements = {};

static Registrar reg_{Scanner{
    .name = "unknown_kprobes",
    .func = run,
    .categories = kCategories,
    .requirements = kRequirements,
}};

} // namespace
