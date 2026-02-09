#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <fnmatch.h>
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

struct FilterEntry {
  std::string value;
  bool negated = false;
};

std::vector<FilterEntry> parse_filter_entries(std::string_view data) {
  std::vector<FilterEntry> entries;
  std::unordered_set<std::string> seen;
  for (const auto &line : split_lines(data)) {
    std::string_view view = trim(line);
    if (view.empty() || view.front() == '#') {
      continue;
    }
    bool negated = false;
    if (view.front() == '!') {
      negated = true;
      view.remove_prefix(1);
      view = trim(view);
      if (view.empty()) {
        continue;
      }
    }
    std::size_t end = view.find_first_of(" \t");
    if (end != std::string_view::npos) {
      view = view.substr(0, end);
    }
    if (view.empty()) {
      continue;
    }
    std::string entry(view);
    std::string dedupe_key;
    dedupe_key.reserve(entry.size() + 1);
    dedupe_key.push_back(negated ? '!' : '+');
    dedupe_key.append(entry);
    if (seen.insert(dedupe_key).second) {
      entries.push_back(FilterEntry{std::move(entry), negated});
    }
  }
  return entries;
}

bool is_glob_pattern(std::string_view pattern) {
  return pattern.find_first_of("*?[") != std::string_view::npos;
}

bool glob_match(std::string_view pattern, std::string_view value) {
  std::string pattern_copy(pattern);
  std::string value_copy(value);
  return ::fnmatch(pattern_copy.c_str(), value_copy.c_str(), 0) == 0;
}

bool is_simple_glob_pattern(std::string_view pattern) {
  return pattern.find('[') == std::string_view::npos &&
         pattern.find('\\') == std::string_view::npos;
}

bool simple_glob_overlap(std::string_view lhs, std::string_view rhs) {
  struct State {
    std::size_t lhs_pos = 0;
    std::size_t rhs_pos = 0;
  };

  const std::size_t lhs_len = lhs.size();
  const std::size_t rhs_len = rhs.size();
  std::vector<unsigned char> seen((lhs_len + 1) * (rhs_len + 1), 0);
  std::vector<State> stack;

  auto state_index = [rhs_len](std::size_t lhs_pos, std::size_t rhs_pos) {
    return lhs_pos * (rhs_len + 1) + rhs_pos;
  };

  auto push_state = [&](std::size_t lhs_pos, std::size_t rhs_pos) {
    std::size_t idx = state_index(lhs_pos, rhs_pos);
    if (seen[idx]) {
      return;
    }
    seen[idx] = 1;
    stack.push_back(State{lhs_pos, rhs_pos});
  };

  push_state(0, 0);

  auto consumes_any = [](char token) { return token == '*' || token == '?'; };

  while (!stack.empty()) {
    State state = stack.back();
    stack.pop_back();

    if (state.lhs_pos == lhs_len && state.rhs_pos == rhs_len) {
      return true;
    }

    if (state.lhs_pos < lhs_len && lhs[state.lhs_pos] == '*') {
      push_state(state.lhs_pos + 1, state.rhs_pos);
    }
    if (state.rhs_pos < rhs_len && rhs[state.rhs_pos] == '*') {
      push_state(state.lhs_pos, state.rhs_pos + 1);
    }

    if (state.lhs_pos >= lhs_len || state.rhs_pos >= rhs_len) {
      continue;
    }

    char lhs_token = lhs[state.lhs_pos];
    char rhs_token = rhs[state.rhs_pos];
    bool lhs_any = consumes_any(lhs_token);
    bool rhs_any = consumes_any(rhs_token);

    bool compatible = false;
    if (lhs_any || rhs_any) {
      compatible = true;
    } else if (lhs_token == rhs_token) {
      compatible = true;
    }
    if (!compatible) {
      continue;
    }

    std::size_t next_lhs = lhs_token == '*' ? state.lhs_pos : state.lhs_pos + 1;
    std::size_t next_rhs = rhs_token == '*' ? state.rhs_pos : state.rhs_pos + 1;

    if (next_lhs != state.lhs_pos || next_rhs != state.rhs_pos) {
      push_state(next_lhs, next_rhs);
    }
  }

  return false;
}

std::string glob_witness(std::string_view pattern, char wildcard_fill,
                         bool star_empty) {
  std::string out;
  out.reserve(pattern.size());

  for (std::size_t i = 0; i < pattern.size(); ++i) {
    char c = pattern[i];
    if (c == '*') {
      if (!star_empty) {
        out.push_back(wildcard_fill);
      }
      continue;
    }
    if (c == '?') {
      out.push_back(wildcard_fill);
      continue;
    }
    if (c == '\\' && i + 1 < pattern.size()) {
      out.push_back(pattern[++i]);
      continue;
    }
    if (c == '[') {
      std::size_t close = pattern.find(']', i + 1);
      if (close == std::string_view::npos) {
        out.push_back(c);
        continue;
      }
      std::size_t class_pos = i + 1;
      if (class_pos < close &&
          (pattern[class_pos] == '!' || pattern[class_pos] == '^')) {
        ++class_pos;
      }
      if (class_pos < close && pattern[class_pos] == ']') {
        ++class_pos;
      }
      char selected = wildcard_fill;
      if (class_pos < close) {
        selected = pattern[class_pos];
      }
      out.push_back(selected);
      i = close;
      continue;
    }

    out.push_back(c);
  }

  return out;
}

bool glob_overlap_fallback(std::string_view lhs, std::string_view rhs) {
  const std::array<std::pair<char, bool>, 4> configs = {{
      {'a', true},
      {'a', false},
      {'x', true},
      {'x', false},
  }};

  for (const auto &[fill, star_empty] : configs) {
    std::string candidate = glob_witness(lhs, fill, star_empty);
    if (glob_match(lhs, candidate) && glob_match(rhs, candidate)) {
      return true;
    }
  }
  for (const auto &[fill, star_empty] : configs) {
    std::string candidate = glob_witness(rhs, fill, star_empty);
    if (glob_match(lhs, candidate) && glob_match(rhs, candidate)) {
      return true;
    }
  }

  return false;
}

bool filters_overlap(std::string_view lhs, std::string_view rhs) {
  lhs = trim(lhs);
  rhs = trim(rhs);
  if (lhs.empty() || rhs.empty()) {
    return false;
  }
  if (lhs == rhs) {
    return true;
  }

  bool lhs_glob = is_glob_pattern(lhs);
  bool rhs_glob = is_glob_pattern(rhs);

  if (lhs_glob && rhs_glob) {
    if (is_simple_glob_pattern(lhs) && is_simple_glob_pattern(rhs)) {
      return simple_glob_overlap(lhs, rhs);
    }
    return glob_overlap_fallback(lhs, rhs);
  }

  if (lhs_glob && glob_match(lhs, rhs)) {
    return true;
  }
  if (rhs_glob && glob_match(rhs, lhs)) {
    return true;
  }
  return false;
}

bool match_pattern(std::string_view entry, const CriticalPattern &pattern) {
  switch (pattern.kind) {
  case MatchKind::Prefix:
    if (entry.starts_with(pattern.pattern)) {
      return true;
    }
    if (entry.find_first_of("*?[") != std::string_view::npos) {
      std::string prefix_glob(pattern.pattern);
      prefix_glob.push_back('*');
      return filters_overlap(entry, prefix_glob);
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

struct FilterFile {
  std::vector<FilterEntry> entries;
  bool present = false;
};

std::size_t positive_entry_count(const FilterFile &file) {
  std::size_t count = 0;
  for (const auto &entry : file.entries) {
    if (!entry.negated && !trim(entry.value).empty()) {
      ++count;
    }
  }
  return count;
}

bool is_excluded_by_notrace(std::string_view entry, const FilterFile &notrace) {
  for (const auto &exclude : notrace.entries) {
    if (exclude.negated) {
      continue;
    }
    if (filters_overlap(entry, exclude.value)) {
      return true;
    }
  }
  return false;
}

bool is_global_filter(const FilterFile &file) {
  if (!file.present) {
    return false;
  }
  if (file.entries.empty()) {
    return true;
  }
  bool has_positive = false;
  for (const auto &entry : file.entries) {
    if (entry.negated) {
      continue;
    }
    std::string_view view = trim(entry.value);
    if (view.empty()) {
      continue;
    }
    has_positive = true;
    if (view == "*" || view == ".*") {
      return true;
    }
  }
  (void)has_positive;
  return false;
}

std::optional<std::string> read_checked(const std::string &path,
                                        ScanResult &result, bool required) {
  int read_error = 0;
  auto data = read_file(path, &read_error);
  if (!data) {
    if (required || !is_missing_file_error(read_error)) {
      result.add_error(data.error());
    }
    return std::nullopt;
  }
  return std::move(*data);
}

FilterFile read_filter_file(const std::string &path, ScanResult &result) {
  FilterFile out;
  auto data = read_checked(path, result, false);
  if (!data) {
    return out;
  }
  out.present = true;
  out.entries = parse_filter_entries(*data);
  return out;
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
      "tracefs not available; cannot inspect ftrace configuration");
  return std::nullopt;
}

ScanResult run() {
  ScanResult result;

  auto tracefs_root = find_tracefs_root(result);
  if (!tracefs_root) {
    return result;
  }

  auto current_tracer_data =
      read_checked(*tracefs_root + "/current_tracer", result, true);
  if (!current_tracer_data) {
    return result;
  }
  std::string current_tracer = std::string(trim(*current_tracer_data));
  if (current_tracer.empty()) {
    current_tracer = "unknown";
  }

  auto tracing_on_data =
      read_checked(*tracefs_root + "/tracing_on", result, false);
  std::optional<bool> tracing_on;
  if (tracing_on_data) {
    tracing_on = parse_bool(*tracing_on_data);
  }

  std::optional<bool> ftrace_enabled;
  auto ftrace_enabled_data =
      read_checked(*tracefs_root + "/ftrace_enabled", result, false);
  if (!ftrace_enabled_data) {
    ftrace_enabled_data =
        read_checked("/proc/sys/kernel/ftrace_enabled", result, false);
  }
  if (ftrace_enabled_data) {
    ftrace_enabled = parse_bool(*ftrace_enabled_data);
  }

  FilterFile ftrace_filter =
      read_filter_file(*tracefs_root + "/set_ftrace_filter", result);
  FilterFile graph_filter =
      read_filter_file(*tracefs_root + "/set_graph_function", result);
  FilterFile ftrace_notrace =
      read_filter_file(*tracefs_root + "/set_ftrace_notrace", result);
  FilterFile graph_notrace =
      read_filter_file(*tracefs_root + "/set_graph_notrace", result);

  std::unordered_map<std::string, std::size_t> tag_counts;
  std::vector<std::string> critical_examples;
  std::size_t function_critical_suppressed = 0;
  std::size_t graph_critical_suppressed = 0;

  auto add_matches = [&](const FilterFile &filter, const FilterFile &notrace,
                         std::string_view label,
                         std::size_t &suppressed_count) {
    for (const auto &entry : filter.entries) {
      if (entry.negated) {
        continue;
      }
      if (is_excluded_by_notrace(entry.value, notrace)) {
        ++suppressed_count;
        continue;
      }
      auto tags = match_tags(entry.value);
      if (tags.empty()) {
        continue;
      }
      critical_examples.push_back(std::string(label) + ":" + entry.value);
      for (const auto &tag : tags) {
        ++tag_counts[tag];
      }
    }
  };

  add_matches(ftrace_filter, ftrace_notrace, "function",
              function_critical_suppressed);
  add_matches(graph_filter, graph_notrace, "graph", graph_critical_suppressed);

  bool tracer_function = current_tracer == "function";
  bool tracer_graph = current_tracer == "function_graph";
  bool global_trace = false;
  if (tracer_function && is_global_filter(ftrace_filter)) {
    global_trace = true;
  }
  if (tracer_graph && is_global_filter(graph_filter)) {
    global_trace = true;
  }

  bool has_critical = !critical_examples.empty();
  if (!global_trace && !has_critical) {
    return result;
  }

  bool active = tracing_on.value_or(false);
  bool tracing_unknown = !tracing_on.has_value();
  bool function_active = (tracer_function || tracer_graph) && active;

  Severity severity = Severity::Warning;
  if (function_active && (global_trace || has_critical)) {
    severity = Severity::Critical;
  } else if (!active && !tracing_unknown) {
    severity = Severity::Info;
  }

  std::string summary;
  if (global_trace) {
    if (function_active) {
      summary = "Ftrace function tracing active without filters";
    } else if (tracing_unknown) {
      summary = "Ftrace function tracing configured without filters "
                "(activity unknown)";
    } else {
      summary = "Ftrace function tracing configured without filters "
                "(currently disabled)";
    }
  } else {
    if (function_active) {
      summary = "Ftrace filters target critical kernel paths";
    } else if (tracing_unknown) {
      summary = "Ftrace critical filter configuration detected "
                "(activity unknown)";
    } else {
      summary = "Ftrace critical filter configuration detected "
                "(currently disabled)";
    }
  }

  Finding finding(severity, std::move(summary));

  if (global_trace) {
    if (function_active) {
      finding.with_detail(
          "Function tracing is active with an empty filter, so all kernel "
          "functions are traced, including sensitive paths.");
    } else {
      finding.with_detail(
          "Function tracing has an empty filter configured, which would trace "
          "all kernel functions if enabled.");
    }
  } else {
    finding.with_detail(
        "Ftrace filters include syscall, credential, module, VFS, or network "
        "symbols. Unexpected hooks here can redirect execution.");
  }

  finding.with_evidence("tracefs_root", *tracefs_root)
      .with_evidence("current_tracer", current_tracer)
      .with_evidence("tracing_on", bool_label(tracing_on));

  if (ftrace_enabled) {
    finding.with_evidence("ftrace_enabled", bool_label(ftrace_enabled));
  }

  if (ftrace_filter.present) {
    finding.with_evidence("function_filter_count",
                          std::to_string(positive_entry_count(ftrace_filter)));
  }
  if (graph_filter.present) {
    finding.with_evidence("graph_filter_count",
                          std::to_string(positive_entry_count(graph_filter)));
  }
  if (ftrace_notrace.present && positive_entry_count(ftrace_notrace) > 0) {
    finding.with_evidence("function_notrace_count",
                          std::to_string(positive_entry_count(ftrace_notrace)));
  }
  if (graph_notrace.present && positive_entry_count(graph_notrace) > 0) {
    finding.with_evidence("graph_notrace_count",
                          std::to_string(positive_entry_count(graph_notrace)));
  }
  if (function_critical_suppressed > 0) {
    finding.with_evidence("function_critical_suppressed_by_notrace",
                          std::to_string(function_critical_suppressed));
  }
  if (graph_critical_suppressed > 0) {
    finding.with_evidence("graph_critical_suppressed_by_notrace",
                          std::to_string(graph_critical_suppressed));
  }

  if (has_critical) {
    finding
        .with_evidence("critical_categories", summarize_tag_counts(tag_counts))
        .with_evidence("critical_examples", summarize_list(critical_examples));
  }

  result.add_finding(std::move(finding));
  return result;
}

constexpr std::array<Category, 1> kCategories = {Category::Kernel};
const std::array<Requirement, 0> kRequirements = {};

static Registrar reg_{Scanner{
    .name = "ftrace_redirection",
    .func = run,
    .categories = kCategories,
    .requirements = kRequirements,
}};

} // namespace
