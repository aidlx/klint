#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <dirent.h>
#include <sys/utsname.h>
#include <unistd.h>

#if defined(__x86_64__)
#include <sched.h>
#endif

#include "kcore_reader.hpp"
#include "scanner.hpp"

namespace {

using klint::Category;
using klint::Finding;
using klint::Registrar;
using klint::Requirement;
using klint::Scanner;
using klint::ScanResult;
using klint::Severity;
using klint::kcore::KcoreImage;
using klint::kcore::load_kcore;
using klint::kcore::read_kcore_range;
using klint::kcore::read_le;
using klint::util::join;
using klint::util::read_file;
using klint::util::split_lines;

constexpr std::size_t kMaxExamples = 24;
constexpr std::size_t kMaxCpuSamples = 64;
constexpr std::size_t kPrologueReadBytes = 16;

struct Range {
  std::uint64_t start = 0;
  std::uint64_t end = 0;
};

struct NamedRange {
  std::string name;
  Range range;
};

struct ModuleRange {
  std::string name;
  std::uint64_t start = 0;
  std::uint64_t end = 0;
};

struct SymbolInfo {
  std::uint64_t addr = 0;
  char type = '?';
  std::string name;
  std::string module;
};

struct SymbolIndex {
  std::vector<SymbolInfo> symbols;
  std::vector<const SymbolInfo *> sorted_all;
  std::vector<const SymbolInfo *> sorted_core;
  std::unordered_map<std::string, std::uint64_t> name_to_addr;
  std::string source;
};

enum class EntrypointKind {
  Msr,
  IdtVector,
  IdtInt80,
};

enum class TargetLocation {
  Null,
  KernelText,
  Module,
  Unknown,
};

struct TargetSpec {
  std::string source;
  EntrypointKind kind = EntrypointKind::IdtVector;
  std::uint64_t addr = 0;
  bool null_allowed = false;
};

struct TargetAssessment {
  TargetSpec target;
  TargetLocation location = TargetLocation::Unknown;
  std::string symbol;
  std::string module;
  bool expected_checked = false;
  bool expected_entry_range = true;
  bool suspicious_trampoline = false;
  std::string trampoline_pattern;
  std::string prologue_hex;
};

struct MsrSpec {
  const char *name = "";
  std::uint32_t id = 0;
  bool optional = false;
};

struct MsrSample {
  int cpu = -1;
  std::uint64_t value = 0;
};

struct MsrCollection {
  std::vector<TargetSpec> targets;
  std::vector<std::string> mismatch_notes;
  std::size_t cpus_sampled = 0;
  std::size_t read_errors = 0;
  std::size_t missing_devices = 0;
  std::size_t permission_errors = 0;
};

struct IdtGate {
  std::size_t vector = 0;
  std::uint64_t target = 0;
  std::uint16_t selector = 0;
  std::uint8_t type = 0;
  bool present = false;
};

struct ScanStats {
  std::size_t msr_targets = 0;
  std::size_t idt_vectors_total = 0;
  std::size_t idt_vectors_present = 0;
  std::size_t idt_targets = 0;
  bool idt_access_restricted = false;
  std::size_t prologue_read_failures = 0;
  std::size_t msr_cpus_sampled = 0;
  std::size_t msr_read_errors = 0;
  std::size_t msr_missing_devices = 0;
  std::size_t msr_permission_errors = 0;
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

bool parse_uint64(std::string_view text, int base, std::uint64_t &out) {
  text = trim(text);
  if (text.empty()) {
    return false;
  }
  std::string buffer(text);
  char *end = nullptr;
  errno = 0;
  unsigned long long value = std::strtoull(buffer.c_str(), &end, base);
  if (errno != 0 || end == buffer.c_str() || *end != '\0') {
    return false;
  }
  out = static_cast<std::uint64_t>(value);
  return true;
}

std::string format_hex(std::uint64_t value, std::size_t width_bytes) {
  std::ostringstream oss;
  oss << "0x" << std::hex << std::nouppercase << std::setfill('0')
      << std::setw(static_cast<int>(width_bytes * 2)) << value;
  return oss.str();
}

std::string format_range(const Range &range, std::size_t width_bytes) {
  if (range.start == 0 && range.end == 0) {
    return "-";
  }
  return format_hex(range.start, width_bytes) + "-" +
         format_hex(range.end, width_bytes);
}

std::optional<std::string_view> next_token(std::string_view line,
                                           std::size_t &pos) {
  while (pos < line.size() &&
         std::isspace(static_cast<unsigned char>(line[pos]))) {
    ++pos;
  }
  if (pos >= line.size()) {
    return std::nullopt;
  }
  std::size_t start = pos;
  while (pos < line.size() &&
         !std::isspace(static_cast<unsigned char>(line[pos]))) {
    ++pos;
  }
  return line.substr(start, pos - start);
}

bool is_text_symbol_type(char type) { return type == 't' || type == 'T'; }

bool in_range(const Range &range, std::uint64_t addr) {
  return addr >= range.start && addr < range.end;
}

void finalize_symbol_index(SymbolIndex &index) {
  index.sorted_all.clear();
  index.sorted_core.clear();
  index.sorted_all.reserve(index.symbols.size());
  index.sorted_core.reserve(index.symbols.size());

  for (const auto &symbol : index.symbols) {
    if (symbol.addr == 0) {
      continue;
    }
    index.sorted_all.push_back(&symbol);
    if (symbol.module.empty()) {
      index.sorted_core.push_back(&symbol);
    }
  }

  auto by_addr = [](const SymbolInfo *lhs, const SymbolInfo *rhs) {
    return lhs->addr < rhs->addr;
  };
  std::sort(index.sorted_all.begin(), index.sorted_all.end(), by_addr);
  std::sort(index.sorted_core.begin(), index.sorted_core.end(), by_addr);
}

SymbolIndex parse_symbol_data(std::string_view data, std::string source) {
  SymbolIndex index;
  index.source = std::move(source);

  for (const auto &line : split_lines(data)) {
    std::string_view view = trim(line);
    if (view.empty()) {
      continue;
    }

    std::size_t pos = 0;
    auto addr_token = next_token(view, pos);
    auto type_token = next_token(view, pos);
    auto name_token = next_token(view, pos);
    if (!addr_token || !type_token || !name_token) {
      continue;
    }

    std::uint64_t addr = 0;
    if (!parse_uint64(*addr_token, 16, addr)) {
      continue;
    }

    std::string_view module_token;
    auto extra_token = next_token(view, pos);
    if (extra_token && extra_token->size() >= 2 &&
        extra_token->front() == '[' && extra_token->back() == ']') {
      module_token = extra_token->substr(1, extra_token->size() - 2);
    }

    SymbolInfo symbol;
    symbol.addr = addr;
    symbol.type = (*type_token).empty() ? '?' : (*type_token)[0];
    symbol.name = std::string(*name_token);
    if (!module_token.empty()) {
      symbol.module = std::string(module_token);
    }

    if (symbol.addr != 0 && !index.name_to_addr.contains(symbol.name)) {
      index.name_to_addr.emplace(symbol.name, symbol.addr);
    }
    index.symbols.push_back(std::move(symbol));
  }

  finalize_symbol_index(index);
  return index;
}

std::optional<std::int64_t> address_delta(std::uint64_t lhs,
                                          std::uint64_t rhs) {
  if (lhs >= rhs) {
    std::uint64_t diff = lhs - rhs;
    if (diff >
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
      return std::nullopt;
    }
    return static_cast<std::int64_t>(diff);
  }

  std::uint64_t diff = rhs - lhs;
  if (diff >
      static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
    return std::nullopt;
  }
  return -static_cast<std::int64_t>(diff);
}

bool add_signed_offset(std::uint64_t input, std::int64_t offset,
                       std::uint64_t &output) {
  if (offset >= 0) {
    std::uint64_t positive = static_cast<std::uint64_t>(offset);
    if (input > std::numeric_limits<std::uint64_t>::max() - positive) {
      return false;
    }
    output = input + positive;
    return true;
  }

  std::uint64_t negative = static_cast<std::uint64_t>(-offset);
  if (input < negative) {
    return false;
  }
  output = input - negative;
  return true;
}

bool apply_symbol_slide(SymbolIndex &index, std::int64_t slide) {
  for (auto &symbol : index.symbols) {
    if (symbol.addr == 0) {
      continue;
    }
    std::uint64_t shifted = 0;
    if (!add_signed_offset(symbol.addr, slide, shifted)) {
      return false;
    }
    symbol.addr = shifted;
  }

  index.name_to_addr.clear();
  for (const auto &symbol : index.symbols) {
    if (symbol.addr == 0 || index.name_to_addr.contains(symbol.name)) {
      continue;
    }
    index.name_to_addr.emplace(symbol.name, symbol.addr);
  }
  finalize_symbol_index(index);
  return true;
}

std::optional<std::int64_t> infer_kaslr_slide(const SymbolIndex &runtime,
                                              const SymbolIndex &system_map) {
  constexpr std::array<std::string_view, 10> kAnchors = {
      "_stext",
      "_text",
      "startup_64",
      "__start_text",
      "_sinittext",
      "__entry_text_start",
      "__irqentry_text_start",
      "entry_SYSCALL_64",
      "__x64_sys_read",
      "linux_banner",
  };

  std::unordered_map<std::int64_t, std::size_t> histogram;
  for (auto name : kAnchors) {
    auto runtime_it = runtime.name_to_addr.find(std::string(name));
    auto system_it = system_map.name_to_addr.find(std::string(name));
    if (runtime_it == runtime.name_to_addr.end() ||
        system_it == system_map.name_to_addr.end()) {
      continue;
    }
    if (runtime_it->second == 0 || system_it->second == 0) {
      continue;
    }
    auto delta = address_delta(runtime_it->second, system_it->second);
    if (!delta) {
      continue;
    }
    ++histogram[*delta];
  }

  if (histogram.empty()) {
    return std::nullopt;
  }

  std::optional<std::int64_t> best_slide;
  std::size_t best_count = 0;
  for (const auto &[slide, count] : histogram) {
    if (count > best_count) {
      best_count = count;
      best_slide = slide;
    }
  }
  if (!best_slide) {
    return std::nullopt;
  }

  std::size_t matches = 0;
  std::size_t mismatches = 0;
  for (const auto &symbol : system_map.symbols) {
    if (symbol.addr == 0 || !symbol.module.empty()) {
      continue;
    }
    auto runtime_it = runtime.name_to_addr.find(symbol.name);
    if (runtime_it == runtime.name_to_addr.end() || runtime_it->second == 0) {
      continue;
    }
    auto delta = address_delta(runtime_it->second, symbol.addr);
    if (!delta) {
      continue;
    }
    if (*delta == *best_slide) {
      ++matches;
    } else {
      ++mismatches;
    }
    if (matches >= 32) {
      break;
    }
  }

  if (matches < 4 || matches <= mismatches) {
    return std::nullopt;
  }

  return best_slide;
}

bool relocate_system_map_with_kallsyms(SymbolIndex &system_map) {
  auto runtime_data = read_file("/proc/kallsyms");
  if (!runtime_data) {
    return false;
  }

  SymbolIndex runtime = parse_symbol_data(*runtime_data, "/proc/kallsyms");
  auto slide = infer_kaslr_slide(runtime, system_map);
  if (!slide) {
    return false;
  }

  return apply_symbol_slide(system_map, *slide);
}

std::optional<std::string> uname_release() {
  struct utsname uts;
  if (::uname(&uts) != 0) {
    return std::nullopt;
  }
  return std::string(uts.release);
}

std::optional<SymbolIndex> load_symbol_index(std::string &source_label) {
  auto kallsyms = read_file("/proc/kallsyms");
  if (kallsyms) {
    SymbolIndex index = parse_symbol_data(*kallsyms, "/proc/kallsyms");
    if (!index.sorted_core.empty()) {
      source_label = "/proc/kallsyms";
      return index;
    }
  }

  auto release = uname_release();
  if (!release) {
    return std::nullopt;
  }

  std::array<std::string, 2> candidates = {
      "/boot/System.map-" + *release,
      "/lib/modules/" + *release + "/System.map",
  };

  for (const auto &path : candidates) {
    auto data = read_file(path);
    if (!data) {
      continue;
    }
    SymbolIndex index = parse_symbol_data(*data, path);
    if (index.sorted_core.empty()) {
      continue;
    }
    if (!relocate_system_map_with_kallsyms(index)) {
      continue;
    }
    source_label = path + " (kaslr-adjusted)";
    return index;
  }

  return std::nullopt;
}

std::optional<SymbolIndex> build_symbol_index(ScanResult &result) {
  std::string source;
  auto index = load_symbol_index(source);
  if (!index) {
    result.add_error("failed to load kernel symbols from /proc/kallsyms or "
                     "System.map");
    return std::nullopt;
  }
  index->source = source.empty() ? "<unknown>" : source;
  return index;
}

std::optional<std::uint64_t> find_symbol_address(const SymbolIndex &index,
                                                 std::string_view name) {
  auto it = index.name_to_addr.find(std::string(name));
  if (it == index.name_to_addr.end()) {
    return std::nullopt;
  }
  if (it->second == 0) {
    return std::nullopt;
  }
  return it->second;
}

std::optional<Range> compute_kernel_text_range(const SymbolIndex &index) {
  std::uint64_t min_addr = 0;
  std::uint64_t max_addr = 0;
  bool found = false;

  for (const auto &symbol : index.symbols) {
    if (symbol.addr == 0 || !symbol.module.empty() ||
        !is_text_symbol_type(symbol.type)) {
      continue;
    }
    if (!found) {
      min_addr = symbol.addr;
      max_addr = symbol.addr;
      found = true;
    } else {
      min_addr = std::min(min_addr, symbol.addr);
      max_addr = std::max(max_addr, symbol.addr);
    }
  }

  if (!found) {
    return std::nullopt;
  }

  std::uint64_t end = max_addr;
  if (end < std::numeric_limits<std::uint64_t>::max() - 4096) {
    end += 4096;
  }
  return Range{min_addr, end};
}

std::optional<Range> build_symbol_pair_range(const SymbolIndex &index,
                                             std::string_view start_name,
                                             std::string_view end_name) {
  auto start = find_symbol_address(index, start_name);
  auto end = find_symbol_address(index, end_name);
  if (!start || !end || *start == 0 || *end == 0 || *end <= *start) {
    return std::nullopt;
  }
  return Range{*start, *end};
}

std::vector<NamedRange> build_expected_entry_ranges(const SymbolIndex &index) {
  constexpr std::array<std::pair<std::string_view, std::string_view>, 4>
      kRangePairs = {{
          {"__entry_text_start", "__entry_text_end"},
          {"__irqentry_text_start", "__irqentry_text_end"},
          {"__softirqentry_text_start", "__softirqentry_text_end"},
          {"__noinstr_text_start", "__noinstr_text_end"},
      }};

  std::vector<NamedRange> ranges;
  ranges.reserve(kRangePairs.size());

  for (const auto &[start_name, end_name] : kRangePairs) {
    auto range = build_symbol_pair_range(index, start_name, end_name);
    if (!range) {
      continue;
    }
    ranges.push_back(NamedRange{
        .name = std::string(start_name) + ".." + std::string(end_name),
        .range = *range,
    });
  }
  return ranges;
}

std::string_view strip_module_token(std::string_view token) {
  token = trim(token);
  while (!token.empty()) {
    unsigned char ch = static_cast<unsigned char>(token.back());
    if (std::isalnum(ch)) {
      break;
    }
    token.remove_suffix(1);
  }
  return token;
}

bool looks_like_module_address_token(std::string_view token) {
  token = trim(token);
  if (token.empty()) {
    return false;
  }
  if (token.starts_with("0x") || token.starts_with("0X")) {
    return true;
  }
  return token.find_first_of("abcdefABCDEF") != std::string_view::npos;
}

std::optional<std::uint64_t>
parse_module_address(const std::vector<std::string_view> &tokens) {
  for (auto it = tokens.rbegin(); it != tokens.rend(); ++it) {
    std::string_view token = strip_module_token(*it);
    if (token.empty() || !looks_like_module_address_token(token)) {
      continue;
    }
    std::uint64_t addr = 0;
    if (parse_uint64(token, 16, addr) && addr != 0) {
      return addr;
    }
  }
  return std::nullopt;
}

std::vector<ModuleRange> load_module_ranges(ScanResult &result) {
  std::vector<ModuleRange> modules;
  auto data = read_file("/proc/modules");
  if (!data) {
    result.add_error(data.error());
    return modules;
  }

  for (const auto &line : split_lines(*data)) {
    std::string_view view = trim(line);
    if (view.empty()) {
      continue;
    }
    std::vector<std::string_view> tokens;
    std::size_t pos = 0;
    while (auto token = next_token(view, pos)) {
      tokens.push_back(*token);
    }
    if (tokens.size() < 6) {
      continue;
    }

    std::uint64_t size = 0;
    if (!parse_uint64(tokens[1], 10, size)) {
      continue;
    }
    auto addr = parse_module_address(tokens);
    if (!addr || *addr == 0 || size == 0) {
      continue;
    }
    if (*addr > std::numeric_limits<std::uint64_t>::max() - size) {
      continue;
    }

    modules.push_back(ModuleRange{
        .name = std::string(tokens[0]),
        .start = *addr,
        .end = *addr + size,
    });
  }

  return modules;
}

const ModuleRange *find_module_range(const std::vector<ModuleRange> &modules,
                                     std::uint64_t addr) {
  for (const auto &module : modules) {
    if (addr >= module.start && addr < module.end) {
      return &module;
    }
  }
  return nullptr;
}

const SymbolInfo *resolve_symbol(const std::vector<const SymbolInfo *> &sorted,
                                 std::uint64_t addr) {
  constexpr std::uint64_t kMaxTailResolveDistance = 4096;

  if (sorted.empty()) {
    return nullptr;
  }
  auto next = std::upper_bound(sorted.begin(), sorted.end(), addr,
                               [](std::uint64_t value, const SymbolInfo *sym) {
                                 return value < sym->addr;
                               });
  if (next == sorted.begin()) {
    return nullptr;
  }
  auto it = next;
  --it;
  const SymbolInfo *symbol = *it;

  if (!symbol || symbol->addr == 0 || addr < symbol->addr) {
    return nullptr;
  }
  if (next != sorted.end()) {
    if (addr >= (*next)->addr) {
      return nullptr;
    }
    return symbol;
  }

  if (addr - symbol->addr > kMaxTailResolveDistance) {
    return nullptr;
  }
  return symbol;
}

bool parse_cpu_id(std::string_view token, int &out) {
  token = trim(token);
  if (token.empty()) {
    return false;
  }
  for (char c : token) {
    if (!std::isdigit(static_cast<unsigned char>(c))) {
      return false;
    }
  }
  long value = std::strtol(std::string(token).c_str(), nullptr, 10);
  if (value < 0 || value > std::numeric_limits<int>::max()) {
    return false;
  }
  out = static_cast<int>(value);
  return true;
}

std::vector<int> parse_cpu_list(std::string_view text) {
  std::unordered_set<int> seen;
  std::vector<int> cpus;
  for (auto &line : split_lines(text)) {
    std::string_view view = trim(line);
    if (view.empty()) {
      continue;
    }
    std::size_t start = 0;
    while (start < view.size()) {
      std::size_t end = view.find(',', start);
      if (end == std::string_view::npos) {
        end = view.size();
      }
      std::string_view token = trim(view.substr(start, end - start));
      if (!token.empty()) {
        std::size_t dash = token.find('-');
        if (dash == std::string_view::npos) {
          int cpu = -1;
          if (parse_cpu_id(token, cpu) && seen.insert(cpu).second) {
            cpus.push_back(cpu);
          }
        } else {
          std::string_view first = token.substr(0, dash);
          std::string_view second = token.substr(dash + 1);
          int lo = -1;
          int hi = -1;
          if (parse_cpu_id(first, lo) && parse_cpu_id(second, hi) && hi >= lo) {
            for (int cpu = lo; cpu <= hi; ++cpu) {
              if (seen.insert(cpu).second) {
                cpus.push_back(cpu);
              }
              if (cpus.size() >= kMaxCpuSamples) {
                return cpus;
              }
            }
          }
        }
      }
      if (end >= view.size()) {
        break;
      }
      start = end + 1;
    }
  }

  std::sort(cpus.begin(), cpus.end());
  if (cpus.size() > kMaxCpuSamples) {
    cpus.resize(kMaxCpuSamples);
  }
  return cpus;
}

std::vector<int> discover_online_cpus() {
  auto online = read_file("/sys/devices/system/cpu/online");
  if (online) {
    auto cpus = parse_cpu_list(*online);
    if (!cpus.empty()) {
      return cpus;
    }
  }
  return {0};
}

bool is_missing_msr_error(int error_number) {
  return error_number == ENOENT || error_number == ENODEV ||
         error_number == ENXIO || error_number == ENOTDIR;
}

bool is_permission_error(int error_number) {
  return error_number == EACCES || error_number == EPERM;
}

std::optional<std::uint64_t> read_msr_value(int cpu, std::uint32_t msr,
                                            int &error_number) {
  error_number = 0;
  std::string path = "/dev/cpu/" + std::to_string(cpu) + "/msr";
  int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd == -1) {
    error_number = errno;
    return std::nullopt;
  }

  std::uint64_t value = 0;
  ssize_t n = ::pread(fd, &value, sizeof(value), static_cast<off_t>(msr));
  if (n != static_cast<ssize_t>(sizeof(value))) {
    error_number = n < 0 ? errno : EIO;
    ::close(fd);
    return std::nullopt;
  }

  ::close(fd);
  return value;
}

std::string summarize_cpu_set(const std::vector<int> &cpus) {
  if (cpus.empty()) {
    return "none";
  }
  std::vector<std::string> labels;
  labels.reserve(std::min<std::size_t>(cpus.size(), 8));
  std::size_t limit = std::min<std::size_t>(cpus.size(), 8);
  for (std::size_t i = 0; i < limit; ++i) {
    labels.push_back(std::to_string(cpus[i]));
  }
  if (cpus.size() > limit) {
    labels.push_back("+" + std::to_string(cpus.size() - limit) + "more");
  }
  return join(labels, ",");
}

MsrCollection collect_msr_targets(const std::vector<int> &cpus,
                                  const MsrSpec &spec) {
  MsrCollection out;
  std::vector<MsrSample> samples;
  samples.reserve(cpus.size());

  for (int cpu : cpus) {
    int error_number = 0;
    auto value = read_msr_value(cpu, spec.id, error_number);
    if (value) {
      samples.push_back(MsrSample{.cpu = cpu, .value = *value});
      continue;
    }
    if (is_missing_msr_error(error_number)) {
      ++out.missing_devices;
    } else if (is_permission_error(error_number)) {
      ++out.permission_errors;
    } else {
      ++out.read_errors;
    }
  }

  if (samples.empty()) {
    return out;
  }

  out.cpus_sampled = samples.size();
  std::unordered_map<std::uint64_t, std::vector<int>> value_to_cpus;
  value_to_cpus.reserve(samples.size());
  for (const auto &sample : samples) {
    value_to_cpus[sample.value].push_back(sample.cpu);
  }

  for (auto &[value, value_cpus] : value_to_cpus) {
    std::sort(value_cpus.begin(), value_cpus.end());
    out.targets.push_back(TargetSpec{
        .source =
            std::string(spec.name) + " cpu=" + summarize_cpu_set(value_cpus),
        .kind = EntrypointKind::Msr,
        .addr = value,
        .null_allowed = spec.optional && value == 0,
    });
  }

  if (value_to_cpus.size() > 1) {
    std::vector<std::string> mismatch_parts;
    mismatch_parts.reserve(value_to_cpus.size());
    for (const auto &[value, value_cpus] : value_to_cpus) {
      mismatch_parts.push_back(format_hex(value, 8) + "@cpu{" +
                               summarize_cpu_set(value_cpus) + "}");
    }
    std::sort(mismatch_parts.begin(), mismatch_parts.end());
    out.mismatch_notes.push_back(std::string(spec.name) + ":" +
                                 join(mismatch_parts, ";"));
  }

  return out;
}

std::string idt_vector_name(std::size_t vector) {
  switch (vector) {
  case 0:
    return "DE";
  case 1:
    return "DB";
  case 2:
    return "NMI";
  case 3:
    return "BP";
  case 4:
    return "OF";
  case 5:
    return "BR";
  case 6:
    return "UD";
  case 7:
    return "NM";
  case 8:
    return "DF";
  case 10:
    return "TS";
  case 11:
    return "NP";
  case 12:
    return "SS";
  case 13:
    return "GP";
  case 14:
    return "PF";
  case 16:
    return "MF";
  case 17:
    return "AC";
  case 18:
    return "MC";
  case 19:
    return "XM";
  case 20:
    return "VE";
  case 21:
    return "CP";
  case 28:
    return "HV";
  case 29:
    return "VC";
  case 30:
    return "SX";
  case 128:
    return "INT80";
  default:
    return "";
  }
}

#if defined(__x86_64__)
struct [[gnu::packed]] IdtrX86_64 {
  std::uint16_t limit;
  std::uint64_t base;
};

std::optional<IdtrX86_64> read_idtr() {
  IdtrX86_64 idtr{};
  asm volatile("sidt %0" : "=m"(idtr));
  return idtr;
}
#endif

std::vector<IdtGate> parse_idt_table(std::span<const std::uint8_t> data) {
  std::vector<IdtGate> gates;
  if (data.size() < 16) {
    return gates;
  }
  std::size_t count = std::min<std::size_t>(256, data.size() / 16);
  gates.reserve(count);

  for (std::size_t i = 0; i < count; ++i) {
    const std::uint8_t *entry = data.data() + i * 16;
    std::uint16_t offset_low = static_cast<std::uint16_t>(read_le(entry, 2));
    std::uint16_t selector = static_cast<std::uint16_t>(read_le(entry + 2, 2));
    std::uint8_t type_attr = entry[5];
    std::uint16_t offset_mid =
        static_cast<std::uint16_t>(read_le(entry + 6, 2));
    std::uint32_t offset_high =
        static_cast<std::uint32_t>(read_le(entry + 8, 4));

    bool present = (type_attr & 0x80) != 0;
    std::uint8_t type = type_attr & 0x0f;
    std::uint64_t target = static_cast<std::uint64_t>(offset_low) |
                           (static_cast<std::uint64_t>(offset_mid) << 16) |
                           (static_cast<std::uint64_t>(offset_high) << 32);

    gates.push_back(IdtGate{
        .vector = i,
        .target = target,
        .selector = selector,
        .type = type,
        .present = present,
    });
  }

  return gates;
}

std::string format_idt_source(std::size_t vector, std::uint16_t selector) {
  std::string source = "IDT[" + std::to_string(vector);
  std::string name = idt_vector_name(vector);
  if (!name.empty()) {
    source.append(":");
    source.append(name);
  }
  source.append("] sel=");
  source.append(format_hex(selector, 2));
  return source;
}

bool should_check_expected_entry_range(EntrypointKind kind) {
  return kind == EntrypointKind::Msr || kind == EntrypointKind::IdtInt80;
}

bool should_check_trampoline(EntrypointKind kind) {
  return kind == EntrypointKind::Msr || kind == EntrypointKind::IdtInt80;
}

std::string bytes_to_hex(std::span<const std::uint8_t> bytes) {
  std::ostringstream oss;
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    if (i > 0) {
      oss << " ";
    }
    oss << std::hex << std::nouppercase << std::setfill('0') << std::setw(2)
        << static_cast<unsigned>(bytes[i]);
  }
  return oss.str();
}

std::optional<std::string>
detect_trampoline_pattern(std::span<const std::uint8_t> bytes) {
  if (bytes.empty()) {
    return std::nullopt;
  }

  std::size_t off = 0;
  if (bytes.size() >= 4 && bytes[0] == 0xf3 && bytes[1] == 0x0f &&
      bytes[2] == 0x1e && (bytes[3] == 0xfa || bytes[3] == 0xfb)) {
    off = 4;
  }
  if (off >= bytes.size()) {
    return std::nullopt;
  }

  std::uint8_t op0 = bytes[off];
  if (op0 == 0xe9) {
    return std::string("jmp_rel32");
  }
  if (op0 == 0xeb) {
    return std::string("jmp_rel8");
  }
  if (op0 == 0xea) {
    return std::string("jmp_far");
  }
  if (off + 2 <= bytes.size() && op0 == 0xff &&
      (bytes[off + 1] == 0x25 || bytes[off + 1] == 0x24)) {
    return std::string("jmp_indirect");
  }
  if (off + 12 <= bytes.size() && (bytes[off] == 0x48 || bytes[off] == 0x49) &&
      (bytes[off + 1] & 0xf8) == 0xb8 && bytes[off + 10] == 0xff &&
      (bytes[off + 11] & 0xf8) == 0xe0) {
    return std::string("movabs_jmp_reg");
  }
  if (off + 6 <= bytes.size() && op0 == 0x68 && bytes[off + 5] == 0xc3) {
    return std::string("push_imm32_ret");
  }
  if (off + 3 <= bytes.size() && op0 == 0x6a && bytes[off + 2] == 0xc3) {
    return std::string("push_imm8_ret");
  }
  return std::nullopt;
}

std::string_view target_location_label(TargetLocation location) {
  switch (location) {
  case TargetLocation::Null:
    return "null";
  case TargetLocation::KernelText:
    return "kernel";
  case TargetLocation::Module:
    return "module";
  case TargetLocation::Unknown:
    return "unknown";
  }
  return "unknown";
}

std::string format_assessment(const TargetAssessment &assessment,
                              std::size_t ptr_size) {
  std::string out = assessment.target.source + "->" +
                    format_hex(assessment.target.addr, ptr_size) + " loc=" +
                    std::string(target_location_label(assessment.location));
  if (!assessment.symbol.empty()) {
    out.append(" sym=");
    out.append(assessment.symbol);
  }
  if (!assessment.module.empty()) {
    out.append(" mod=");
    out.append(assessment.module);
  }
  if (assessment.expected_checked && !assessment.expected_entry_range) {
    out.append(" expected=out_of_entry_text");
  }
  if (assessment.suspicious_trampoline) {
    out.append(" tramp=");
    out.append(assessment.trampoline_pattern);
    if (!assessment.prologue_hex.empty()) {
      out.append(" bytes=");
      out.append(assessment.prologue_hex);
    }
  }
  return out;
}

bool address_in_named_ranges(const std::vector<NamedRange> &ranges,
                             std::uint64_t addr) {
  for (const auto &range : ranges) {
    if (in_range(range.range, addr)) {
      return true;
    }
  }
  return false;
}

std::string summarize_named_ranges(const std::vector<NamedRange> &ranges,
                                   std::size_t ptr_size) {
  if (ranges.empty()) {
    return "unavailable";
  }

  std::vector<std::string> parts;
  parts.reserve(ranges.size());
  for (const auto &range : ranges) {
    parts.push_back(range.name + ":" + format_range(range.range, ptr_size));
  }
  return join(parts, ", ");
}

TargetAssessment assess_target(const TargetSpec &target,
                               const SymbolIndex &symbols,
                               const std::optional<Range> &kernel_text,
                               const std::vector<NamedRange> &entry_ranges,
                               const std::vector<ModuleRange> &modules,
                               const std::optional<KcoreImage> &kcore,
                               ScanStats &stats) {
  TargetAssessment assessment;
  assessment.target = target;

  if (target.addr == 0) {
    assessment.location = TargetLocation::Null;
    return assessment;
  }

  const ModuleRange *module_range = find_module_range(modules, target.addr);
  const SymbolInfo *symbol = resolve_symbol(symbols.sorted_all, target.addr);
  if (symbol) {
    assessment.symbol = symbol->name;
    if (!symbol->module.empty()) {
      assessment.module = symbol->module;
    }
  }
  if (module_range && assessment.module.empty()) {
    assessment.module = module_range->name;
  }
  if (!assessment.module.empty()) {
    assessment.location = TargetLocation::Module;
  } else if (kernel_text && in_range(*kernel_text, target.addr)) {
    assessment.location = TargetLocation::KernelText;
  } else if (symbol && symbol->module.empty() &&
             is_text_symbol_type(symbol->type)) {
    assessment.location = TargetLocation::KernelText;
  } else {
    assessment.location = TargetLocation::Unknown;
  }

  if (assessment.location == TargetLocation::KernelText &&
      should_check_expected_entry_range(target.kind) && !entry_ranges.empty()) {
    assessment.expected_checked = true;
    assessment.expected_entry_range =
        address_in_named_ranges(entry_ranges, target.addr);
  }

  if (assessment.location == TargetLocation::KernelText &&
      should_check_trampoline(target.kind) && kcore) {
    auto prologue = read_kcore_range(*kcore, target.addr, kPrologueReadBytes);
    if (!prologue || prologue->empty()) {
      ++stats.prologue_read_failures;
    } else {
      std::size_t shown = std::min<std::size_t>(prologue->size(), 8);
      assessment.prologue_hex =
          bytes_to_hex(std::span<const std::uint8_t>(prologue->data(), shown));
      auto trampoline = detect_trampoline_pattern(*prologue);
      if (trampoline) {
        assessment.suspicious_trampoline = true;
        assessment.trampoline_pattern = *trampoline;
      }
    }
  }

  return assessment;
}

std::vector<TargetSpec> collect_idt_targets(const KcoreImage &kcore,
                                            ScanResult &result,
                                            ScanStats &stats) {
  std::vector<TargetSpec> targets;
#if defined(__x86_64__)
  auto idtr = read_idtr();
  if (!idtr) {
    result.add_error("read IDTR with sidt failed");
    return targets;
  }
  if (idtr->base == 0 || idtr->limit == 0) {
    stats.idt_access_restricted = true;
    return targets;
  }
  std::size_t table_size = static_cast<std::size_t>(idtr->limit) + 1;
  if (table_size < 16 || table_size > 4096) {
    result.add_error("IDT size from IDTR is invalid");
    return targets;
  }

  auto idt_raw = read_kcore_range(kcore, idtr->base, table_size);
  if (!idt_raw) {
    result.add_error("failed to read IDT table from /proc/kcore");
    return targets;
  }

  auto gates = parse_idt_table(*idt_raw);
  stats.idt_vectors_total = gates.size();

  for (const auto &gate : gates) {
    if (!gate.present) {
      continue;
    }
    ++stats.idt_vectors_present;
    if (gate.target == 0) {
      continue;
    }

    bool gate_type_ok = gate.type == 0xE || gate.type == 0xF;
    if (!gate_type_ok) {
      continue;
    }

    EntrypointKind kind = gate.vector == 128 ? EntrypointKind::IdtInt80
                                             : EntrypointKind::IdtVector;
    targets.push_back(TargetSpec{
        .source = format_idt_source(gate.vector, gate.selector),
        .kind = kind,
        .addr = gate.target,
    });
  }
  stats.idt_targets = targets.size();
#else
  (void)kcore;
  result.add_error("IDT analysis is supported only on x86_64");
#endif
  return targets;
}

ScanResult run() {
  ScanResult result;

#if !defined(__x86_64__)
  result.add_error(
      "kernel_entrypoint_integrity is implemented for x86_64 only");
  return result;
#else
  auto symbols = build_symbol_index(result);
  if (!symbols) {
    return result;
  }

  auto kernel_text = compute_kernel_text_range(*symbols);
  if (!kernel_text) {
    result.add_error("failed to compute kernel text range from symbols");
  }
  auto entry_ranges = build_expected_entry_ranges(*symbols);
  auto modules = load_module_ranges(result);

  std::optional<KcoreImage> kcore;
  auto kcore_result = load_kcore();
  if (!kcore_result) {
    result.add_error(kcore_result.error());
    result.add_error(
        "IDT/prologue checks skipped because /proc/kcore is unavailable");
  } else {
    kcore = std::move(*kcore_result);
  }

  ScanStats stats;
  std::vector<TargetSpec> targets;

  const std::array<MsrSpec, 3> kMsrs = {{
      MsrSpec{.name = "IA32_LSTAR", .id = 0xC0000082u, .optional = false},
      MsrSpec{.name = "IA32_CSTAR", .id = 0xC0000083u, .optional = true},
      MsrSpec{.name = "IA32_SYSENTER_EIP", .id = 0x00000176u, .optional = true},
  }};

  auto cpus = discover_online_cpus();
  std::vector<std::string> msr_mismatch_notes;

  for (const auto &spec : kMsrs) {
    auto msr = collect_msr_targets(cpus, spec);
    stats.msr_cpus_sampled += msr.cpus_sampled;
    stats.msr_read_errors += msr.read_errors;
    stats.msr_missing_devices += msr.missing_devices;
    stats.msr_permission_errors += msr.permission_errors;
    stats.msr_targets += msr.targets.size();

    if (!msr.mismatch_notes.empty()) {
      for (auto &note : msr.mismatch_notes) {
        msr_mismatch_notes.push_back(std::move(note));
      }
    }

    if (msr.targets.empty() && !spec.optional) {
      result.add_error(std::string("unable to read ") + spec.name +
                       " from /dev/cpu/*/msr");
    }

    for (auto &target : msr.targets) {
      targets.push_back(std::move(target));
    }
  }

  if (kcore) {
    auto idt_targets = collect_idt_targets(*kcore, result, stats);
    for (auto &target : idt_targets) {
      targets.push_back(std::move(target));
    }
  }

  if (targets.empty()) {
    result.add_error(
        "no syscall/interrupt entrypoint targets could be evaluated");
    return result;
  }

  std::vector<TargetAssessment> assessments;
  assessments.reserve(targets.size());
  for (const auto &target : targets) {
    assessments.push_back(assess_target(target, *symbols, kernel_text,
                                        entry_ranges, modules, kcore, stats));
  }

  std::size_t null_targets = 0;
  std::size_t optional_null_targets = 0;
  std::size_t outside_kernel = 0;
  std::size_t module_targets = 0;
  std::size_t outside_entry_range = 0;
  std::size_t suspicious_trampolines = 0;
  std::size_t unresolved_symbols = 0;

  std::vector<std::string> critical_examples;
  std::vector<std::string> warning_examples;
  critical_examples.reserve(kMaxExamples);
  warning_examples.reserve(kMaxExamples);

  std::size_t ptr_size = kcore ? kcore->ptr_size : 8;
  for (const auto &assessment : assessments) {
    if (assessment.location == TargetLocation::Null) {
      if (assessment.target.null_allowed) {
        ++optional_null_targets;
        continue;
      }
      ++null_targets;
      if (critical_examples.size() < kMaxExamples) {
        critical_examples.push_back(format_assessment(assessment, ptr_size));
      }
      continue;
    }
    if (assessment.location == TargetLocation::Module) {
      ++module_targets;
      if (critical_examples.size() < kMaxExamples) {
        critical_examples.push_back(format_assessment(assessment, ptr_size));
      }
      continue;
    }
    if (assessment.location == TargetLocation::Unknown) {
      ++outside_kernel;
      if (critical_examples.size() < kMaxExamples) {
        critical_examples.push_back(format_assessment(assessment, ptr_size));
      }
      continue;
    }
    if (assessment.location == TargetLocation::KernelText &&
        assessment.symbol.empty()) {
      ++unresolved_symbols;
    }
    if (assessment.expected_checked && !assessment.expected_entry_range) {
      ++outside_entry_range;
      if (warning_examples.size() < kMaxExamples) {
        warning_examples.push_back(format_assessment(assessment, ptr_size));
      }
    }
    if (assessment.suspicious_trampoline) {
      ++suspicious_trampolines;
      if (warning_examples.size() < kMaxExamples) {
        warning_examples.push_back(format_assessment(assessment, ptr_size));
      }
    }
  }

  bool has_msr_mismatch = !msr_mismatch_notes.empty();
  bool has_anomaly = null_targets > 0 || outside_kernel > 0 ||
                     module_targets > 0 || outside_entry_range > 0 ||
                     suspicious_trampolines > 0 || has_msr_mismatch;
  if (!has_anomaly) {
    return result;
  }

  Severity severity = Severity::Warning;
  if (null_targets > 0 || outside_kernel > 0 || module_targets > 0) {
    severity = Severity::Critical;
  }

  Finding finding(severity, "Kernel entrypoint integrity anomalies detected");
  finding.with_detail(
      "Syscall entry MSRs and IDT vectors should resolve to expected core "
      "kernel entry text. Targets that point into modules, outside kernel "
      "text, or through trampoline-like prologues can indicate pre-table "
      "hooking.");

  finding.with_evidence("symbol_source", symbols->source)
      .with_evidence("targets_checked", std::to_string(assessments.size()))
      .with_evidence("msr_targets", std::to_string(stats.msr_targets))
      .with_evidence("idt_targets", std::to_string(stats.idt_targets))
      .with_evidence("idt_vectors_total",
                     std::to_string(stats.idt_vectors_total))
      .with_evidence("idt_vectors_present",
                     std::to_string(stats.idt_vectors_present))
      .with_evidence("null_targets", std::to_string(null_targets))
      .with_evidence("outside_kernel", std::to_string(outside_kernel))
      .with_evidence("module_targets", std::to_string(module_targets))
      .with_evidence("outside_entry_ranges",
                     std::to_string(outside_entry_range))
      .with_evidence("suspicious_trampolines",
                     std::to_string(suspicious_trampolines));

  if (stats.idt_access_restricted) {
    finding.with_evidence("idt_status", "sidt_restricted_or_masked");
  }

  if (optional_null_targets > 0) {
    finding.with_evidence("optional_null_targets",
                          std::to_string(optional_null_targets));
  }

  if (kernel_text) {
    finding.with_evidence("kernel_text_range",
                          format_range(*kernel_text, ptr_size));
  }
  finding.with_evidence("entry_ranges",
                        summarize_named_ranges(entry_ranges, ptr_size));

  if (unresolved_symbols > 0) {
    finding.with_evidence("unresolved_symbols",
                          std::to_string(unresolved_symbols));
  }
  if (stats.prologue_read_failures > 0) {
    finding.with_evidence("prologue_read_failures",
                          std::to_string(stats.prologue_read_failures));
  }
  if (stats.msr_cpus_sampled > 0) {
    finding.with_evidence("msr_cpu_samples",
                          std::to_string(stats.msr_cpus_sampled));
  }
  if (stats.msr_missing_devices > 0) {
    finding.with_evidence("msr_missing_devices",
                          std::to_string(stats.msr_missing_devices));
  }
  if (stats.msr_permission_errors > 0) {
    finding.with_evidence("msr_permission_errors",
                          std::to_string(stats.msr_permission_errors));
  }
  if (stats.msr_read_errors > 0) {
    finding.with_evidence("msr_read_errors",
                          std::to_string(stats.msr_read_errors));
  }

  if (!msr_mismatch_notes.empty()) {
    std::sort(msr_mismatch_notes.begin(), msr_mismatch_notes.end());
    finding.with_evidence("msr_value_mismatch", join(msr_mismatch_notes, ", "));
  }
  if (!critical_examples.empty()) {
    finding.with_evidence("critical_examples", join(critical_examples, ", "));
  }
  if (!warning_examples.empty()) {
    finding.with_evidence("warning_examples", join(warning_examples, ", "));
  }

  result.add_finding(std::move(finding));
  return result;
#endif
}

constexpr std::array<Category, 1> kCategories = {Category::Kernel};
const std::array<Requirement, 0> kRequirements = {};

static Registrar reg_{Scanner{
    .name = "kernel_entrypoint_integrity",
    .func = run,
    .categories = kCategories,
    .requirements = kRequirements,
}};

} // namespace
