#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <dirent.h>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <unistd.h>

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

constexpr std::size_t kMaxExamples = 20;
constexpr std::size_t kMaxPidEntries = 200000;
constexpr std::size_t kMaxFdEntries = 2000000;
constexpr std::size_t kMinMismatchesForPidConfirmation = 4;

struct SocketInfo {
  std::string proto;
  std::string local;
  std::string remote;
  std::string state;
};

using SocketMap = std::unordered_map<std::uint64_t, SocketInfo>;

struct ProcSnapshot {
  SocketMap sockets;
  std::size_t tables_available = 0;
};

struct SsSnapshot {
  SocketMap sockets;
  bool available = false;
};

struct PidSnapshot {
  std::unordered_set<std::uint64_t> inodes;
  std::size_t pids_scanned = 0;
  std::size_t fds_scanned = 0;
  std::size_t permission_denied = 0;
  bool truncated = false;
  bool available = false;
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

bool is_missing_file_error(int error_number) {
  return error_number == ENOENT || error_number == ENOTDIR;
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

std::string to_lower_copy(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (char c : text) {
    out.push_back(
        static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  }
  return out;
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

std::optional<std::uint64_t> parse_decimal_with_suffix(std::string_view text) {
  text = trim(text);
  if (text.empty()) {
    return std::nullopt;
  }

  std::size_t pos = 0;
  while (pos < text.size() &&
         std::isdigit(static_cast<unsigned char>(text[pos]))) {
    ++pos;
  }
  if (pos == 0) {
    return std::nullopt;
  }

  for (std::size_t i = pos; i < text.size(); ++i) {
    unsigned char ch = static_cast<unsigned char>(text[i]);
    if (ch == ',' || ch == ')' || ch == ']' || ch == '}' || ch == ';') {
      continue;
    }
    return std::nullopt;
  }

  return parse_uint64(text.substr(0, pos), 10);
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return 10 + (c - 'a');
  }
  if (c >= 'A' && c <= 'F') {
    return 10 + (c - 'A');
  }
  return -1;
}

bool parse_hex_byte(std::string_view text, unsigned char &out) {
  if (text.size() != 2) {
    return false;
  }
  int hi = hex_value(text[0]);
  int lo = hex_value(text[1]);
  if (hi < 0 || lo < 0) {
    return false;
  }
  out = static_cast<unsigned char>((hi << 4) | lo);
  return true;
}

std::optional<std::string> hex_to_ipv4(std::string_view hex) {
  if (hex.size() != 8) {
    return std::nullopt;
  }
  std::array<unsigned char, 4> bytes{};
  for (std::size_t i = 0; i < 4; ++i) {
    if (!parse_hex_byte(hex.substr((3 - i) * 2, 2), bytes[i])) {
      return std::nullopt;
    }
  }
  char buffer[INET_ADDRSTRLEN];
  if (!::inet_ntop(AF_INET, bytes.data(), buffer, sizeof(buffer))) {
    return std::nullopt;
  }
  return std::string(buffer);
}

std::optional<std::string> hex_to_ipv6(std::string_view hex) {
  if (hex.size() != 32) {
    return std::nullopt;
  }
  std::array<unsigned char, 16> bytes{};
  for (std::size_t word = 0; word < 4; ++word) {
    for (std::size_t b = 0; b < 4; ++b) {
      std::size_t offset = word * 8 + (3 - b) * 2;
      if (!parse_hex_byte(hex.substr(offset, 2), bytes[word * 4 + b])) {
        return std::nullopt;
      }
    }
  }
  char buffer[INET6_ADDRSTRLEN];
  if (!::inet_ntop(AF_INET6, bytes.data(), buffer, sizeof(buffer))) {
    return std::nullopt;
  }
  return std::string(buffer);
}

std::string format_endpoint(std::string_view ip, std::uint64_t port,
                            bool ipv6) {
  if (ipv6) {
    return "[" + std::string(ip) + "]:" + std::to_string(port);
  }
  return std::string(ip) + ":" + std::to_string(port);
}

std::optional<std::string> parse_proc_endpoint(std::string_view input,
                                               bool ipv6) {
  std::size_t colon = input.find(':');
  if (colon == std::string_view::npos) {
    return std::nullopt;
  }
  std::string_view addr_hex = input.substr(0, colon);
  std::string_view port_hex = input.substr(colon + 1);
  auto port = parse_uint64(port_hex, 16);
  if (!port) {
    return std::nullopt;
  }
  std::optional<std::string> ip;
  if (ipv6) {
    ip = hex_to_ipv6(addr_hex);
  } else {
    ip = hex_to_ipv4(addr_hex);
  }
  if (!ip) {
    return std::nullopt;
  }
  return format_endpoint(*ip, *port, ipv6);
}

std::string normalize_hex_state(std::string_view state) {
  std::string out;
  out.reserve(state.size());
  for (char c : state) {
    out.push_back(
        static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
  }
  if (out.size() == 1) {
    out.insert(out.begin(), '0');
  }
  return out;
}

std::string tcp_state_label(std::string_view state_hex) {
  std::string key = normalize_hex_state(state_hex);
  if (key == "01") {
    return "ESTABLISHED";
  }
  if (key == "02") {
    return "SYN_SENT";
  }
  if (key == "03") {
    return "SYN_RECV";
  }
  if (key == "04") {
    return "FIN_WAIT1";
  }
  if (key == "05") {
    return "FIN_WAIT2";
  }
  if (key == "06") {
    return "TIME_WAIT";
  }
  if (key == "07") {
    return "CLOSE";
  }
  if (key == "08") {
    return "CLOSE_WAIT";
  }
  if (key == "09") {
    return "LAST_ACK";
  }
  if (key == "0A") {
    return "LISTEN";
  }
  if (key == "0B") {
    return "CLOSING";
  }
  if (key == "0C") {
    return "NEW_SYN_RECV";
  }
  return key;
}

std::string join_tokens(const std::vector<std::string_view> &tokens,
                        std::size_t start) {
  if (start >= tokens.size()) {
    return {};
  }
  std::string out(tokens[start]);
  for (std::size_t i = start + 1; i < tokens.size(); ++i) {
    out.push_back(' ');
    out.append(tokens[i]);
  }
  return out;
}

struct ProcHeaderIndex {
  int local = -1;
  int remote = -1;
  int state = -1;
  int inode = -1;
};

std::optional<ProcHeaderIndex> parse_proc_header(std::string_view line) {
  auto tokens = split_ws(line);
  if (tokens.empty()) {
    return std::nullopt;
  }
  ProcHeaderIndex index;
  for (std::size_t i = 0; i < tokens.size(); ++i) {
    std::string label = to_lower_copy(tokens[i]);
    if (label == "local_address") {
      index.local = static_cast<int>(i);
    } else if (label == "rem_address" || label == "remote_address") {
      index.remote = static_cast<int>(i);
    } else if (label == "st") {
      index.state = static_cast<int>(i);
    } else if (label == "inode") {
      index.inode = static_cast<int>(i);
    }
  }
  if (index.local < 0 || index.remote < 0 || index.state < 0 ||
      index.inode < 0) {
    return std::nullopt;
  }
  return index;
}

void add_proc_inet_table(const std::string &path, std::string_view proto,
                         bool ipv6, ProcSnapshot &snapshot,
                         ScanResult &result) {
  int read_error = 0;
  auto data = read_file(path, &read_error);
  if (!data) {
    if (!is_missing_file_error(read_error)) {
      result.add_error(data.error());
    }
    return;
  }

  auto lines = split_lines(*data);
  if (lines.empty()) {
    return;
  }

  auto header = parse_proc_header(lines.front());
  if (!header) {
    result.add_error("unexpected header in " + path);
    return;
  }

  snapshot.tables_available++;

  for (std::size_t i = 1; i < lines.size(); ++i) {
    std::string_view line = trim(lines[i]);
    if (line.empty()) {
      continue;
    }
    auto tokens = split_ws(line);
    if (tokens.size() <=
        static_cast<std::size_t>(std::max(
            {header->local, header->remote, header->state, header->inode}))) {
      continue;
    }
    auto inode = parse_uint64(tokens[header->inode], 10);
    if (!inode || *inode == 0) {
      continue;
    }

    std::string local;
    std::string remote;

    auto local_parsed = parse_proc_endpoint(tokens[header->local], ipv6);
    if (local_parsed) {
      local = *local_parsed;
    } else {
      local = std::string(tokens[header->local]);
    }

    auto remote_parsed = parse_proc_endpoint(tokens[header->remote], ipv6);
    if (remote_parsed) {
      remote = *remote_parsed;
    } else {
      remote = std::string(tokens[header->remote]);
    }

    std::string state = std::string(tokens[header->state]);
    if (proto.rfind("tcp", 0) == 0) {
      state = tcp_state_label(tokens[header->state]);
    }

    snapshot.sockets.emplace(*inode,
                             SocketInfo{std::string(proto), std::move(local),
                                        std::move(remote), std::move(state)});
  }
}

void add_proc_unix_table(const std::string &path, ProcSnapshot &snapshot,
                         ScanResult &result) {
  int read_error = 0;
  auto data = read_file(path, &read_error);
  if (!data) {
    if (!is_missing_file_error(read_error)) {
      result.add_error(data.error());
    }
    return;
  }

  auto lines = split_lines(*data);
  if (lines.empty()) {
    return;
  }

  auto header_tokens = split_ws(lines.front());
  if (header_tokens.empty()) {
    return;
  }

  int inode_index = -1;
  int state_index = -1;
  int path_index = -1;
  for (std::size_t i = 0; i < header_tokens.size(); ++i) {
    std::string label = to_lower_copy(header_tokens[i]);
    if (label == "inode") {
      inode_index = static_cast<int>(i);
    } else if (label == "st") {
      state_index = static_cast<int>(i);
    } else if (label == "path") {
      path_index = static_cast<int>(i);
    }
  }

  if (inode_index < 0) {
    result.add_error("unexpected header in " + path);
    return;
  }

  snapshot.tables_available++;

  for (std::size_t i = 1; i < lines.size(); ++i) {
    std::string_view line = trim(lines[i]);
    if (line.empty()) {
      continue;
    }
    auto tokens = split_ws(line);
    if (tokens.size() <= static_cast<std::size_t>(inode_index)) {
      continue;
    }
    auto inode = parse_uint64(tokens[inode_index], 10);
    if (!inode || *inode == 0) {
      continue;
    }

    std::string state;
    if (state_index >= 0 &&
        tokens.size() > static_cast<std::size_t>(state_index)) {
      state = std::string(tokens[state_index]);
    }

    std::string path_value;
    if (path_index >= 0 &&
        tokens.size() > static_cast<std::size_t>(path_index)) {
      path_value = join_tokens(tokens, static_cast<std::size_t>(path_index));
    }

    snapshot.sockets.emplace(
        *inode,
        SocketInfo{"unix", std::move(path_value), {}, std::move(state)});
  }
}

ProcSnapshot read_proc_sockets(ScanResult &result) {
  ProcSnapshot snapshot;
  constexpr std::array<std::pair<std::string_view, bool>, 6> kTables = {{
      {"/proc/net/tcp", false},
      {"/proc/net/tcp6", true},
      {"/proc/net/udp", false},
      {"/proc/net/udp6", true},
      {"/proc/net/raw", false},
      {"/proc/net/raw6", true},
  }};

  for (const auto &entry : kTables) {
    std::string proto(entry.first);
    proto.erase(0, proto.find_last_of('/') + 1);
    add_proc_inet_table(std::string(entry.first), proto, entry.second, snapshot,
                        result);
  }

  add_proc_unix_table("/proc/net/unix", snapshot, result);
  return snapshot;
}

std::optional<std::uint64_t> parse_ss_inode(std::string_view token) {
  if (token.starts_with("ino:")) {
    return parse_decimal_with_suffix(token.substr(4));
  }
  if (token.starts_with("inode:")) {
    return parse_decimal_with_suffix(token.substr(6));
  }
  return std::nullopt;
}

bool is_ss_metadata_token(std::string_view token) {
  return token.starts_with("users:") || token.starts_with("uid:") ||
         token.starts_with("ino:") || token.starts_with("inode:") ||
         token.starts_with("sk:") || token.starts_with("cgroup:") ||
         token.starts_with("v6only:") || token.starts_with("timer:") ||
         token.starts_with("ts");
}

bool looks_like_ss_inet_endpoint(std::string_view token) {
  if (token.empty() || is_ss_metadata_token(token)) {
    return false;
  }
  if (token == "*" || token == "*:*") {
    return true;
  }
  if (token.starts_with('[') && token.find("]:") != std::string_view::npos) {
    return true;
  }
  return token.find(':') != std::string_view::npos;
}

std::optional<std::pair<std::size_t, std::size_t>>
find_ss_inet_endpoint_indices(const std::vector<std::string_view> &tokens) {
  std::size_t local_index = std::string_view::npos;
  for (std::size_t i = 2; i < tokens.size(); ++i) {
    if (!looks_like_ss_inet_endpoint(tokens[i])) {
      continue;
    }
    if (local_index == std::string_view::npos) {
      local_index = i;
      continue;
    }
    return std::pair<std::size_t, std::size_t>{local_index, i};
  }
  return std::nullopt;
}

void add_ss_inet_sockets(std::string_view data, SsSnapshot &snapshot,
                         std::size_t &parsed_count) {
  for (const auto &line : split_lines(data)) {
    std::string_view view = trim(line);
    if (view.empty()) {
      continue;
    }
    auto tokens = split_ws(view);
    if (tokens.size() < 2) {
      continue;
    }

    std::optional<std::uint64_t> inode;
    for (const auto &token : tokens) {
      inode = parse_ss_inode(token);
      if (inode) {
        break;
      }
    }
    if (!inode || *inode == 0) {
      continue;
    }

    SocketInfo info;
    info.proto = std::string(tokens[0]);
    info.state = std::string(tokens[1]);
    auto endpoints = find_ss_inet_endpoint_indices(tokens);
    if (endpoints) {
      info.local = std::string(tokens[endpoints->first]);
      info.remote = std::string(tokens[endpoints->second]);
    }
    snapshot.sockets.emplace(*inode, std::move(info));
    ++parsed_count;
  }
}

std::size_t ss_metadata_start(const std::vector<std::string_view> &tokens,
                              std::size_t from) {
  for (std::size_t i = from; i < tokens.size(); ++i) {
    if (is_ss_metadata_token(tokens[i])) {
      return i;
    }
  }
  return tokens.size();
}

std::optional<std::uint64_t>
parse_ss_unix_inode(const std::vector<std::string_view> &tokens,
                    std::size_t &index) {
  for (std::size_t i = 0; i < tokens.size(); ++i) {
    auto inode = parse_ss_inode(tokens[i]);
    if (inode && *inode != 0) {
      index = i;
      return inode;
    }
  }

  if (tokens.size() >= 7) {
    std::size_t candidate = tokens.size() - 3;
    auto inode = parse_uint64(tokens[candidate], 10);
    if (inode && *inode != 0) {
      index = candidate;
      return inode;
    }
  }

  return std::nullopt;
}

std::string join_token_slice(const std::vector<std::string_view> &tokens,
                             std::size_t start, std::size_t end) {
  if (start >= end || end > tokens.size()) {
    return {};
  }
  std::string out(tokens[start]);
  for (std::size_t i = start + 1; i < end; ++i) {
    out.push_back(' ');
    out.append(tokens[i]);
  }
  return out;
}

void add_ss_unix_sockets(std::string_view data, SsSnapshot &snapshot,
                         std::size_t &parsed_count) {
  for (const auto &line : split_lines(data)) {
    std::string_view view = trim(line);
    if (view.empty()) {
      continue;
    }
    auto tokens = split_ws(view);
    if (tokens.size() < 5) {
      continue;
    }

    std::string_view proto = tokens[0];
    if (!proto.starts_with("u_") && proto != "unix") {
      continue;
    }

    std::size_t inode_index = 0;
    auto inode = parse_ss_unix_inode(tokens, inode_index);
    if (!inode || *inode == 0 || inode_index < 4) {
      continue;
    }

    SocketInfo info;
    info.proto = std::string(proto);
    info.state = std::string(tokens[1]);
    std::size_t field_end = ss_metadata_start(tokens, 4);
    if (inode_index >= 4 && inode_index < field_end) {
      if (inode_index > 4) {
        info.local = join_token_slice(tokens, 4, inode_index);
      }
      if (inode_index + 1 < field_end) {
        info.remote = join_token_slice(tokens, inode_index + 1, field_end);
      }
    } else {
      info.local = std::string(tokens[4]);
      if (field_end > 5) {
        info.remote = join_token_slice(tokens, 5, field_end);
      }
    }
    snapshot.sockets.emplace(*inode, std::move(info));
    ++parsed_count;
  }
}

void add_ss_command_error(ScanResult &result, const std::string &cmd_name,
                          int exit_code, std::string_view stderr_data) {
  std::string message =
      cmd_name + " exited with code " + std::to_string(exit_code);
  std::string_view stderr_trimmed = trim(stderr_data);
  if (!stderr_trimmed.empty()) {
    message.append(": ");
    message.append(stderr_trimmed);
  }
  result.add_error(std::move(message));
}

SsSnapshot read_ss_sockets(ScanResult &result) {
  SsSnapshot snapshot;
  std::size_t parsed_count = 0;
  bool had_output = false;

  auto inet_output =
      run_command({"ss", "-H", "-n", "-a", "-t", "-u", "-w", "-e"});
  if (!inet_output) {
    result.add_error(inet_output.error());
    return snapshot;
  }
  if (inet_output->exit_code != 0) {
    add_ss_command_error(result, "ss(inet)", inet_output->exit_code,
                         inet_output->stderr_data);
    return snapshot;
  }
  if (inet_output->stdout_truncated || inet_output->stderr_truncated) {
    result.add_error("ss(inet) output truncated at capture limit");
    return snapshot;
  }
  if (!inet_output->stdout_data.empty()) {
    had_output = true;
  }
  add_ss_inet_sockets(inet_output->stdout_data, snapshot, parsed_count);

  auto unix_output = run_command({"ss", "-H", "-n", "-a", "-x", "-e"});
  if (!unix_output) {
    result.add_error(unix_output.error());
    return snapshot;
  }
  if (unix_output->exit_code != 0) {
    add_ss_command_error(result, "ss(unix)", unix_output->exit_code,
                         unix_output->stderr_data);
    return snapshot;
  }
  if (unix_output->stdout_truncated || unix_output->stderr_truncated) {
    result.add_error("ss(unix) output truncated at capture limit");
    return snapshot;
  }
  if (!unix_output->stdout_data.empty()) {
    had_output = true;
  }
  add_ss_unix_sockets(unix_output->stdout_data, snapshot, parsed_count);

  if (had_output && parsed_count == 0) {
    result.add_error("ss output did not include parsable socket inode data");
    return snapshot;
  }

  snapshot.available = true;
  return snapshot;
}

bool is_numeric(std::string_view text) {
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

std::optional<std::uint64_t> parse_socket_inode(std::string_view target) {
  constexpr std::string_view prefix = "socket:[";
  if (!target.starts_with(prefix)) {
    return std::nullopt;
  }
  std::size_t start = prefix.size();
  std::size_t end = target.find(']', start);
  if (end == std::string_view::npos || end <= start) {
    return std::nullopt;
  }
  return parse_uint64(target.substr(start, end - start), 10);
}

std::optional<std::string> readlink_full(const std::string &path) {
  constexpr std::size_t kInitialSize = 256;
  constexpr std::size_t kMaxSize = 16384;

  std::size_t buffer_size = kInitialSize;
  while (buffer_size <= kMaxSize) {
    std::string buffer(buffer_size, '\0');
    ssize_t len = ::readlink(path.c_str(), buffer.data(), buffer.size());
    if (len <= 0) {
      return std::nullopt;
    }

    std::size_t used = static_cast<std::size_t>(len);
    if (used < buffer.size()) {
      buffer.resize(used);
      return buffer;
    }

    buffer_size *= 2;
  }

  return std::nullopt;
}

bool is_unix_proto(std::string_view proto) {
  return proto == "unix" || proto.starts_with("u_");
}

std::size_t count_unix_sockets(const SocketMap &sockets) {
  std::size_t count = 0;
  for (const auto &entry : sockets) {
    if (is_unix_proto(entry.second.proto)) {
      ++count;
    }
  }
  return count;
}

std::size_t count_unix_intersection(const SocketMap &lhs,
                                    const SocketMap &rhs) {
  std::size_t count = 0;
  for (const auto &entry : lhs) {
    if (!is_unix_proto(entry.second.proto)) {
      continue;
    }
    auto it = rhs.find(entry.first);
    if (it != rhs.end() && is_unix_proto(it->second.proto)) {
      ++count;
    }
  }
  return count;
}

void remove_unix_sockets(SocketMap &sockets) {
  for (auto it = sockets.begin(); it != sockets.end();) {
    if (is_unix_proto(it->second.proto)) {
      it = sockets.erase(it);
    } else {
      ++it;
    }
  }
}

bool unix_comparison_unreliable(const ProcSnapshot &proc_snapshot,
                                const SsSnapshot &ss_snapshot) {
  std::size_t proc_unix = count_unix_sockets(proc_snapshot.sockets);
  std::size_t ss_unix = count_unix_sockets(ss_snapshot.sockets);
  if (proc_unix < 64 || ss_unix < 16) {
    return false;
  }

  std::size_t min_size = std::min(proc_unix, ss_unix);
  if (min_size == 0) {
    return false;
  }

  std::size_t overlap =
      count_unix_intersection(proc_snapshot.sockets, ss_snapshot.sockets);
  return overlap * 4 < min_size;
}

PidSnapshot read_pid_sockets() {
  PidSnapshot snapshot;
  DIR *proc_dir = ::opendir("/proc");
  if (!proc_dir) {
    return snapshot;
  }
  snapshot.available = true;

  bool readdir_failed = false;
  bool stop = false;
  while (!stop) {
    errno = 0;
    dirent *entry = ::readdir(proc_dir);
    if (!entry) {
      if (errno != 0) {
        readdir_failed = true;
      }
      break;
    }
    std::string name(entry->d_name);
    if (!is_numeric(name)) {
      continue;
    }
    if (snapshot.pids_scanned >= kMaxPidEntries) {
      snapshot.truncated = true;
      break;
    }
    ++snapshot.pids_scanned;

    std::string fd_path = "/proc/" + name + "/fd";
    DIR *fd_dir = ::opendir(fd_path.c_str());
    if (!fd_dir) {
      if (errno == EACCES || errno == EPERM) {
        ++snapshot.permission_denied;
        continue;
      }
      continue;
    }

    while (!stop) {
      errno = 0;
      dirent *fd_entry = ::readdir(fd_dir);
      if (!fd_entry) {
        if (errno != 0) {
          readdir_failed = true;
        }
        break;
      }
      std::string fd_name(fd_entry->d_name);
      if (fd_name == "." || fd_name == "..") {
        continue;
      }
      if (snapshot.fds_scanned >= kMaxFdEntries) {
        snapshot.truncated = true;
        stop = true;
        break;
      }
      ++snapshot.fds_scanned;

      std::string link_path = fd_path + "/" + fd_name;
      auto target = readlink_full(link_path);
      if (!target) {
        continue;
      }
      auto inode = parse_socket_inode(*target);
      if (inode && *inode != 0) {
        snapshot.inodes.insert(*inode);
      }
    }

    ::closedir(fd_dir);
  }

  ::closedir(proc_dir);
  if (readdir_failed) {
    snapshot.truncated = true;
  }

  return snapshot;
}

std::vector<std::uint64_t> map_difference(const SocketMap &lhs,
                                          const SocketMap &rhs) {
  std::vector<std::uint64_t> diff;
  diff.reserve(lhs.size());
  for (const auto &item : lhs) {
    if (!rhs.contains(item.first)) {
      diff.push_back(item.first);
    }
  }
  std::sort(diff.begin(), diff.end());
  return diff;
}

std::vector<std::uint64_t>
intersect_with_pid(const std::vector<std::uint64_t> &inodes,
                   const std::unordered_set<std::uint64_t> &pid_set) {
  std::vector<std::uint64_t> out;
  out.reserve(inodes.size());
  for (auto inode : inodes) {
    if (pid_set.contains(inode)) {
      out.push_back(inode);
    }
  }
  return out;
}

std::vector<std::uint64_t>
intersect_lists(const std::vector<std::uint64_t> &lhs,
                const std::vector<std::uint64_t> &rhs) {
  std::unordered_set<std::uint64_t> rhs_set(rhs.begin(), rhs.end());
  std::vector<std::uint64_t> out;
  out.reserve(lhs.size());
  for (auto inode : lhs) {
    if (rhs_set.contains(inode)) {
      out.push_back(inode);
    }
  }
  std::sort(out.begin(), out.end());
  return out;
}

bool inode_token_in_text(std::string_view data, std::string_view inode_text) {
  for (const auto &line : split_lines(data)) {
    std::string_view view = trim(line);
    if (view.empty() || view.find(inode_text) == std::string_view::npos) {
      continue;
    }
    auto tokens = split_ws(view);
    for (auto token : tokens) {
      if (token == inode_text) {
        return true;
      }
    }
  }
  return false;
}

std::vector<std::string> load_proc_tables_raw() {
  constexpr std::array<std::string_view, 7> kTables = {{
      "/proc/net/tcp",
      "/proc/net/tcp6",
      "/proc/net/udp",
      "/proc/net/udp6",
      "/proc/net/raw",
      "/proc/net/raw6",
      "/proc/net/unix",
  }};

  std::vector<std::string> tables;
  tables.reserve(kTables.size());
  for (auto path : kTables) {
    auto data = read_file(std::string(path));
    if (!data) {
      continue;
    }
    tables.push_back(std::move(*data));
  }
  return tables;
}

bool inode_present_in_proc_tables_raw(std::uint64_t inode,
                                      const std::vector<std::string> &tables) {
  std::string inode_text = std::to_string(inode);
  for (const auto &data : tables) {
    if (inode_token_in_text(data, inode_text)) {
      return true;
    }
  }
  return false;
}

std::vector<std::uint64_t>
reconcile_with_proc_raw(const std::vector<std::uint64_t> &inodes,
                        const std::vector<std::string> &raw_tables,
                        std::size_t &suppressed_count) {
  suppressed_count = 0;
  std::vector<std::uint64_t> out;
  out.reserve(inodes.size());
  for (auto inode : inodes) {
    if (inode_present_in_proc_tables_raw(inode, raw_tables)) {
      ++suppressed_count;
      continue;
    }
    out.push_back(inode);
  }
  return out;
}

std::string describe_socket(std::uint64_t inode, const SocketInfo &info) {
  std::string out = info.proto;
  if (!info.state.empty()) {
    out.append(" ");
    out.append(info.state);
  }
  if (!info.local.empty()) {
    out.append(" ");
    out.append(info.local);
  }
  if (!info.remote.empty()) {
    out.append(" -> ");
    out.append(info.remote);
  }
  out.append(" (ino:");
  out.append(std::to_string(inode));
  out.append(")");
  return out;
}

std::string summarize_inodes(const std::vector<std::uint64_t> &inodes,
                             const SocketMap &map) {
  if (inodes.empty()) {
    return "-";
  }
  std::size_t count = std::min(inodes.size(), kMaxExamples);
  std::vector<std::string> preview;
  preview.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    auto inode = inodes[i];
    auto it = map.find(inode);
    if (it != map.end()) {
      preview.push_back(describe_socket(inode, it->second));
    } else {
      preview.push_back("ino:" + std::to_string(inode));
    }
  }
  std::string summary = join(preview, ", ");
  if (inodes.size() > count) {
    summary.append(" (+");
    summary.append(std::to_string(inodes.size() - count));
    summary.append(" more)");
  }
  return summary;
}

void add_mismatch_finding(ScanResult &result,
                          const std::vector<std::uint64_t> &inodes,
                          const SocketMap &source_map,
                          const PidSnapshot &pid_snapshot, std::string summary,
                          std::string detail) {
  if (inodes.empty()) {
    return;
  }

  auto confirmed = pid_snapshot.available
                       ? intersect_with_pid(inodes, pid_snapshot.inodes)
                       : std::vector<std::uint64_t>{};
  bool confirmed_any = !confirmed.empty();

  Severity severity = confirmed_any ? Severity::Critical : Severity::Warning;
  Finding finding(severity, std::move(summary));

  if (confirmed_any) {
    detail.append(" PID file descriptor inventory confirms these sockets are "
                  "referenced by running processes.");
  }
  finding.with_detail(std::move(detail));
  finding.with_evidence("mismatch_count", std::to_string(inodes.size()));
  finding.with_evidence("examples", summarize_inodes(inodes, source_map));

  if (pid_snapshot.available) {
    finding.with_evidence("pidfd_confirmed", std::to_string(confirmed.size()));
    finding.with_evidence("pidfd_pids_scanned",
                          std::to_string(pid_snapshot.pids_scanned));
    finding.with_evidence("pidfd_fds_scanned",
                          std::to_string(pid_snapshot.fds_scanned));
    if (pid_snapshot.permission_denied > 0) {
      finding.with_evidence("pidfd_permission_denied",
                            std::to_string(pid_snapshot.permission_denied));
    }
    if (pid_snapshot.truncated) {
      finding.with_evidence("pidfd_scan_truncated", "1");
    }
    if (confirmed_any) {
      finding.with_evidence("pidfd_examples",
                            summarize_inodes(confirmed, source_map));
    }
  } else {
    finding.with_evidence("pidfd_confirmed", "unavailable");
  }

  result.add_finding(std::move(finding));
}

void add_summary_finding(ScanResult &result, const ProcSnapshot &proc_snapshot,
                         const SsSnapshot &ss_snapshot,
                         const PidSnapshot &pid_snapshot, bool unix_excluded) {
  if (!result.has_findings()) {
    return;
  }
  Finding finding(Severity::Info, "Socket inventory summary");
  finding.with_detail("Counts reflect data sources used for the comparison.");
  finding.with_evidence("procfs_sockets",
                        std::to_string(proc_snapshot.sockets.size()));
  finding.with_evidence("netlink_sockets",
                        std::to_string(ss_snapshot.sockets.size()));
  if (pid_snapshot.available) {
    finding.with_evidence("pidfd_sockets",
                          std::to_string(pid_snapshot.inodes.size()));
  } else {
    finding.with_evidence("pidfd_sockets", "unavailable");
  }
  if (unix_excluded) {
    finding.with_evidence("unix_comparison", "excluded_unreliable_ss_mapping");
  }
  result.add_finding(std::move(finding));
}

ScanResult run() {
  ScanResult result;

  ProcSnapshot proc_snapshot = read_proc_sockets(result);
  if (proc_snapshot.tables_available == 0) {
    return result;
  }

  SsSnapshot ss_snapshot = read_ss_sockets(result);
  if (!ss_snapshot.available) {
    return result;
  }

  bool unix_excluded = false;
  if (unix_comparison_unreliable(proc_snapshot, ss_snapshot)) {
    remove_unix_sockets(proc_snapshot.sockets);
    remove_unix_sockets(ss_snapshot.sockets);
    unix_excluded = true;
  }
  PidSnapshot pid_snapshot;

  auto netlink_minus_proc =
      map_difference(ss_snapshot.sockets, proc_snapshot.sockets);
  auto proc_minus_netlink =
      map_difference(proc_snapshot.sockets, ss_snapshot.sockets);

  std::size_t netlink_raw_suppressed = 0;
  if (!netlink_minus_proc.empty()) {
    auto raw_proc_tables = load_proc_tables_raw();
    netlink_minus_proc = reconcile_with_proc_raw(
        netlink_minus_proc, raw_proc_tables, netlink_raw_suppressed);
  }

  if (!netlink_minus_proc.empty() || !proc_minus_netlink.empty()) {
    ProcSnapshot proc_second = read_proc_sockets(result);
    SsSnapshot ss_second = read_ss_sockets(result);
    if (proc_second.tables_available > 0 && ss_second.available) {
      bool second_unix_unreliable =
          unix_comparison_unreliable(proc_second, ss_second);
      if (unix_excluded || second_unix_unreliable) {
        remove_unix_sockets(proc_second.sockets);
        remove_unix_sockets(ss_second.sockets);
        unix_excluded = true;
      }

      auto netlink_minus_proc_second =
          map_difference(ss_second.sockets, proc_second.sockets);
      auto proc_minus_netlink_second =
          map_difference(proc_second.sockets, ss_second.sockets);

      netlink_minus_proc =
          intersect_lists(netlink_minus_proc, netlink_minus_proc_second);
      proc_minus_netlink =
          intersect_lists(proc_minus_netlink, proc_minus_netlink_second);

      if (!netlink_minus_proc.empty()) {
        std::size_t second_raw_suppressed = 0;
        auto raw_proc_tables = load_proc_tables_raw();
        netlink_minus_proc = reconcile_with_proc_raw(
            netlink_minus_proc, raw_proc_tables, second_raw_suppressed);
        netlink_raw_suppressed += second_raw_suppressed;
      }

      proc_snapshot = std::move(proc_second);
      ss_snapshot = std::move(ss_second);
    }
  }

  std::size_t mismatch_count =
      netlink_minus_proc.size() + proc_minus_netlink.size();
  if (mismatch_count >= kMinMismatchesForPidConfirmation) {
    pid_snapshot = read_pid_sockets();
  }

  add_mismatch_finding(
      result, netlink_minus_proc, ss_snapshot.sockets, pid_snapshot,
      "Sockets visible via netlink but missing from /proc/net",
      "Netlink (ss) reports sockets that are not listed in procfs. This can "
      "indicate sockets hidden from /proc/net; short-lived sockets can also "
      "cause transient mismatches.");

  add_mismatch_finding(
      result, proc_minus_netlink, proc_snapshot.sockets, pid_snapshot,
      "Sockets visible in /proc/net but missing from netlink",
      "Procfs lists sockets that are not returned by netlink (ss). This can "
      "indicate filtering of netlink diagnostics or tampering; short-lived "
      "sockets can also cause transient mismatches.");

  if (netlink_raw_suppressed > 0) {
    Finding finding(Severity::Info, "Socket mismatch reconciliation");
    finding
        .with_detail("Mismatches that resolved in raw /proc/net text were "
                     "suppressed to reduce parser and timing noise.")
        .with_evidence("netlink_minus_proc_suppressed",
                       std::to_string(netlink_raw_suppressed));
    result.add_finding(std::move(finding));
  }

  add_summary_finding(result, proc_snapshot, ss_snapshot, pid_snapshot,
                      unix_excluded);

  return result;
}

constexpr std::array<Category, 1> kCategories = {Category::Network};
const std::array<Requirement, 1> kRequirements = {
    Requirement::external_tool("ss")};

static Registrar reg_{Scanner{
    .name = "hidden_network_sockets",
    .func = run,
    .categories = kCategories,
    .requirements = kRequirements,
}};

} // namespace
