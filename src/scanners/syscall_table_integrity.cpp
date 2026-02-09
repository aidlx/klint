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
#include <vector>

#include <sys/utsname.h>
#include <unistd.h>

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

constexpr std::size_t kMaxExamples = 20;
constexpr std::size_t kFallbackEntries = 512;
constexpr std::size_t kMaxEntriesHardLimit = 4096;

struct Range {
  std::uint64_t start = 0;
  std::uint64_t end = 0;
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

struct TableSpec {
  std::string name;
  std::uint64_t addr = 0;
};

enum class EntryLocation {
  Null,
  KernelText,
  Module,
  Unknown,
};

struct EntryAnalysis {
  std::size_t index = 0;
  std::uint64_t addr = 0;
  EntryLocation location = EntryLocation::Unknown;
  std::string symbol;
  std::string module;
  bool syscall_like = false;
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

bool is_syscall_symbol(std::string_view name) {
  static constexpr std::array<std::string_view, 12> kPrefixes = {
      "__x64_sys_",
      "__ia32_sys_",
      "__x32_sys_",
      "__arm64_sys_",
      "__se_sys_",
      "__do_sys_",
      "__do_compat_sys_",
      "compat_sys_",
      "__compat_sys_",
      "sys_",
      "SyS_",
      "sys32_",
  };
  for (auto prefix : kPrefixes) {
    if (name.starts_with(prefix)) {
      return true;
    }
  }
  return false;
}

bool is_text_symbol_type(char type) { return type == 't' || type == 'T'; }

bool is_weak_symbol_type(char type) { return type == 'w' || type == 'W'; }

std::string_view location_label(EntryLocation location) {
  switch (location) {
  case EntryLocation::Null:
    return "null";
  case EntryLocation::KernelText:
    return "kernel";
  case EntryLocation::Module:
    return "module";
  case EntryLocation::Unknown:
    return "unknown";
  }
  return "unknown";
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

bool has_usable_syscall_table_symbols(const SymbolIndex &index) {
  constexpr std::array<std::string_view, 4> kTableNames = {
      "sys_call_table",
      "ia32_sys_call_table",
      "x32_sys_call_table",
      "compat_sys_call_table",
  };

  for (auto name : kTableNames) {
    auto it = index.name_to_addr.find(std::string(name));
    if (it != index.name_to_addr.end() && it->second != 0) {
      return true;
    }
  }
  return false;
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
  constexpr std::array<std::string_view, 8> kAnchors = {
      "_stext",     "_text",          "startup_64",     "__start_text",
      "_sinittext", "__x64_sys_read", "sys_call_table", "linux_banner",
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
  std::optional<SymbolIndex> fallback_kallsyms;
  auto kallsyms = read_file("/proc/kallsyms");
  if (kallsyms) {
    SymbolIndex index = parse_symbol_data(*kallsyms, "/proc/kallsyms");
    if (has_usable_syscall_table_symbols(index)) {
      source_label = "/proc/kallsyms";
      return index;
    }
    fallback_kallsyms = std::move(index);
  }

  auto release = uname_release();
  if (!release) {
    if (fallback_kallsyms) {
      source_label = "/proc/kallsyms";
      return std::move(*fallback_kallsyms);
    }
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
    if (has_usable_syscall_table_symbols(index) &&
        relocate_system_map_with_kallsyms(index)) {
      source_label = path + " (kaslr-adjusted)";
      return index;
    }
  }
  if (fallback_kallsyms) {
    source_label = "/proc/kallsyms";
    return fallback_kallsyms;
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

  index->source = source;
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

std::vector<TableSpec> find_syscall_tables(const SymbolIndex &index,
                                           ScanResult &result) {
  constexpr std::array<std::string_view, 4> kNames = {
      "sys_call_table",
      "ia32_sys_call_table",
      "x32_sys_call_table",
      "compat_sys_call_table",
  };

  std::vector<TableSpec> tables;
  for (auto name : kNames) {
    auto addr = find_symbol_address(index, name);
    if (addr) {
      tables.push_back(TableSpec{std::string(name), *addr});
    }
  }

  if (tables.empty()) {
    result.add_error(
        "sys_call_table symbols not found or not addressable in symbol "
        "source; kernel pointers may be restricted");
  }
  return tables;
}

std::optional<Range> compute_kernel_text_range(const SymbolIndex &index) {
  std::uint64_t min_addr = 0;
  std::uint64_t max_addr = 0;
  bool found = false;

  for (const auto &symbol : index.symbols) {
    if (symbol.addr == 0 || !symbol.module.empty()) {
      continue;
    }
    if (symbol.type != 't' && symbol.type != 'T') {
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
    if (!addr) {
      continue;
    }
    if (*addr == 0 || size == 0) {
      continue;
    }
    if (*addr > std::numeric_limits<std::uint64_t>::max() - size) {
      continue;
    }

    ModuleRange range;
    range.name = std::string(tokens[0]);
    range.start = *addr;
    range.end = *addr + size;
    modules.push_back(std::move(range));
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

std::vector<std::uint64_t>
decode_pointers(const std::vector<std::uint8_t> &data, std::size_t ptr_size) {
  std::vector<std::uint64_t> entries;
  if (ptr_size == 0) {
    return entries;
  }
  std::size_t count = data.size() / ptr_size;
  entries.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    entries.push_back(read_le(data.data() + i * ptr_size, ptr_size));
  }
  return entries;
}

std::optional<std::size_t> syscall_count_hint(const SymbolIndex &symbols,
                                              const TableSpec &table,
                                              std::size_t ptr_size) {
  if (ptr_size == 0 || symbols.sorted_all.empty()) {
    return std::nullopt;
  }

  auto by_addr = [](const SymbolInfo *sym, std::uint64_t value) {
    return sym->addr < value;
  };
  auto table_it =
      std::lower_bound(symbols.sorted_all.begin(), symbols.sorted_all.end(),
                       table.addr, by_addr);
  if (table_it == symbols.sorted_all.end() || (*table_it)->addr != table.addr) {
    return std::nullopt;
  }

  auto next_it = table_it;
  ++next_it;
  if (next_it == symbols.sorted_all.end()) {
    return std::nullopt;
  }
  if ((*next_it)->addr <= table.addr) {
    return std::nullopt;
  }

  std::uint64_t span_bytes = (*next_it)->addr - table.addr;
  std::size_t entries = static_cast<std::size_t>(span_bytes / ptr_size);
  if (entries < 128) {
    return std::nullopt;
  }
  if (entries > kMaxEntriesHardLimit) {
    return kMaxEntriesHardLimit;
  }
  return entries;
}

EntryAnalysis analyze_entry(std::size_t index, std::uint64_t addr,
                            const SymbolIndex &symbols,
                            const std::optional<Range> &kernel_text,
                            const std::vector<ModuleRange> &modules) {
  EntryAnalysis entry;
  entry.index = index;
  entry.addr = addr;
  if (addr == 0) {
    entry.location = EntryLocation::Null;
    return entry;
  }

  const ModuleRange *module = find_module_range(modules, addr);
  const SymbolInfo *sym = resolve_symbol(symbols.sorted_all, addr);
  if (sym) {
    entry.symbol = sym->name;
    entry.syscall_like = is_syscall_symbol(sym->name);
    if (!sym->module.empty()) {
      entry.module = sym->module;
    }
  }

  if (module && entry.module.empty()) {
    entry.module = module->name;
  }

  if (!entry.module.empty()) {
    entry.location = EntryLocation::Module;
    return entry;
  }

  bool in_kernel_text =
      !kernel_text || (addr >= kernel_text->start && addr < kernel_text->end);
  if (sym && sym->module.empty() && in_kernel_text) {
    if (is_text_symbol_type(sym->type) ||
        (entry.syscall_like && is_weak_symbol_type(sym->type))) {
      entry.location = EntryLocation::KernelText;
      return entry;
    }
  }

  entry.location = EntryLocation::Unknown;
  return entry;
}

std::size_t trim_invalid_tail(const std::vector<EntryAnalysis> &entries) {
  if (entries.empty()) {
    return 0;
  }

  std::size_t last_valid = entries.size();
  for (std::size_t i = entries.size(); i > 0; --i) {
    if (entries[i - 1].location == EntryLocation::KernelText ||
        entries[i - 1].location == EntryLocation::Module) {
      last_valid = i;
      break;
    }
  }

  if (last_valid == entries.size()) {
    return entries.size();
  }

  std::size_t invalid_tail = entries.size() - last_valid;
  if (invalid_tail >= 32 && invalid_tail >= entries.size() / 8) {
    return last_valid;
  }

  return entries.size();
}

std::size_t
trim_non_kernel_window_tail(const std::vector<EntryAnalysis> &entries) {
  constexpr std::size_t kWindow = 64;
  constexpr std::size_t kStartAfter = 128;

  if (entries.size() <= kStartAfter + kWindow) {
    return entries.size();
  }

  for (std::size_t start = kStartAfter; start + kWindow <= entries.size();
       ++start) {
    bool has_kernel_window_entry = false;
    for (std::size_t i = start; i < start + kWindow; ++i) {
      if (entries[i].location == EntryLocation::KernelText) {
        has_kernel_window_entry = true;
        break;
      }
    }
    if (!has_kernel_window_entry) {
      return start;
    }
  }
  return entries.size();
}

std::string format_example(const EntryAnalysis &entry, std::size_t ptr_size) {
  std::string out = "idx=" + std::to_string(entry.index) +
                    " addr=" + format_hex(entry.addr, ptr_size) +
                    " loc=" + std::string(location_label(entry.location));
  if (!entry.symbol.empty()) {
    out.append(" sym=");
    out.append(entry.symbol);
  }
  if (!entry.module.empty()) {
    out.append(" mod=");
    out.append(entry.module);
  }
  return out;
}

std::optional<Finding> analyze_table(const TableSpec &table,
                                     const SymbolIndex &symbols,
                                     const std::optional<Range> &kernel_text,
                                     const std::vector<ModuleRange> &modules,
                                     const KcoreImage &kcore,
                                     ScanResult &result) {
  auto count_hint = syscall_count_hint(symbols, table, kcore.ptr_size);
  std::size_t entries_to_read = count_hint.value_or(kFallbackEntries);
  std::string count_source = count_hint ? "symbol_span" : "fallback";
  if (entries_to_read > kMaxEntriesHardLimit) {
    entries_to_read = kMaxEntriesHardLimit;
    count_source = "symbol_span_clamped";
  }

  auto raw =
      read_kcore_range(kcore, table.addr, entries_to_read * kcore.ptr_size);
  if (!raw) {
    result.add_error("failed to read sys_call_table entries from /proc/kcore");
    return std::nullopt;
  }

  auto entries = decode_pointers(*raw, kcore.ptr_size);
  if (entries.empty()) {
    result.add_error("sys_call_table read returned no entries");
    return std::nullopt;
  }

  std::vector<EntryAnalysis> analyses;
  analyses.reserve(entries.size());
  for (std::size_t i = 0; i < entries.size(); ++i) {
    analyses.push_back(
        analyze_entry(i, entries[i], symbols, kernel_text, modules));
  }

  std::size_t trimmed = trim_invalid_tail(analyses);
  if (trimmed < analyses.size()) {
    analyses.resize(trimmed);
    count_source = count_source + "+trimmed";
  }

  std::size_t window_trimmed = trim_non_kernel_window_tail(analyses);
  if (window_trimmed < analyses.size()) {
    analyses.resize(window_trimmed);
    count_source = count_source + "+window";
  }

  std::size_t outside_kernel = 0;
  std::size_t module_targets = 0;
  std::size_t non_syscall_kernel = 0;
  std::size_t null_entries = 0;
  std::size_t unknown_symbols = 0;

  std::vector<std::string> examples;
  examples.reserve(kMaxExamples);

  for (const auto &entry : analyses) {
    if (entry.location == EntryLocation::Null) {
      ++null_entries;
      continue;
    }
    if (entry.location == EntryLocation::Unknown) {
      ++outside_kernel;
      if (examples.size() < kMaxExamples) {
        examples.push_back(format_example(entry, kcore.ptr_size));
      }
      continue;
    }
    if (entry.location == EntryLocation::Module) {
      ++module_targets;
      if (examples.size() < kMaxExamples) {
        examples.push_back(format_example(entry, kcore.ptr_size));
      }
      continue;
    }
    if (entry.location == EntryLocation::KernelText) {
      if (entry.symbol.empty()) {
        ++unknown_symbols;
      } else if (!entry.syscall_like) {
        ++non_syscall_kernel;
        if (examples.size() < kMaxExamples) {
          examples.push_back(format_example(entry, kcore.ptr_size));
        }
      }
    }
  }

  if (outside_kernel == 0 && module_targets == 0 && non_syscall_kernel == 0) {
    return std::nullopt;
  }

  Severity severity = Severity::Warning;
  if (outside_kernel > 0 || module_targets > 0) {
    severity = Severity::Critical;
  }

  Finding finding(severity, "Syscall table integrity anomalies detected");
  finding.with_detail(
      "Syscall table entries should resolve to core kernel syscall handlers. "
      "Entries that point outside kernel text or into modules can indicate "
      "tampering.");

  finding.with_evidence("table", table.name)
      .with_evidence("table_address", format_hex(table.addr, kcore.ptr_size))
      .with_evidence("entries_scanned", std::to_string(analyses.size()))
      .with_evidence("count_source", count_source)
      .with_evidence("outside_kernel", std::to_string(outside_kernel))
      .with_evidence("module_targets", std::to_string(module_targets))
      .with_evidence("non_syscall_kernel", std::to_string(non_syscall_kernel));

  if (null_entries > 0) {
    finding.with_evidence("null_entries", std::to_string(null_entries));
  }
  if (unknown_symbols > 0) {
    finding.with_evidence("unknown_symbols", std::to_string(unknown_symbols));
  }
  if (kernel_text) {
    finding.with_evidence("kernel_text_range",
                          format_range(*kernel_text, kcore.ptr_size));
  }
  if (!examples.empty()) {
    finding.with_evidence("examples", join(examples, ", "));
  }

  return finding;
}

ScanResult run() {
  ScanResult result;

  auto symbols = build_symbol_index(result);
  if (!symbols) {
    return result;
  }

  auto tables = find_syscall_tables(*symbols, result);
  if (tables.empty()) {
    return result;
  }

  auto kernel_text = compute_kernel_text_range(*symbols);
  auto modules = load_module_ranges(result);

  auto kcore_result = load_kcore();
  if (!kcore_result) {
    result.add_error(kcore_result.error());
    return result;
  }
  KcoreImage kcore = std::move(*kcore_result);

  for (const auto &table : tables) {
    auto finding =
        analyze_table(table, *symbols, kernel_text, modules, kcore, result);
    if (finding) {
      result.add_finding(std::move(*finding));
    }
  }

  return result;
}

constexpr std::array<Category, 1> kCategories = {Category::Kernel};
const std::array<Requirement, 0> kRequirements = {};

static Registrar reg_{Scanner{
    .name = "syscall_table_integrity",
    .func = run,
    .categories = kCategories,
    .requirements = kRequirements,
}};

} // namespace
