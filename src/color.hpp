#pragma once

#include <unistd.h>

#include <cstdlib>
#include <string>
#include <string_view>

namespace klint::color {

inline bool &enabled_flag() {
  static bool enabled = true;
  return enabled;
}

inline void init(bool force_no_color) {
  bool enabled = true;
  if (force_no_color) {
    enabled = false;
  }
  if (std::getenv("NO_COLOR") != nullptr) {
    enabled = false;
  }
  if (!isatty(STDOUT_FILENO)) {
    enabled = false;
  }
  enabled_flag() = enabled;
}

inline std::string wrap(std::string_view input, const char *code) {
  if (!enabled_flag()) {
    return std::string(input);
  }
  std::string out;
  out.reserve(input.size() + 8);
  out.append(code);
  out.append(input.data(), input.size());
  out.append("\x1b[0m");
  return out;
}

inline std::string red(std::string_view input) {
  return wrap(input, "\x1b[31m");
}

inline std::string yellow(std::string_view input) {
  return wrap(input, "\x1b[33m");
}

inline std::string green(std::string_view input) {
  return wrap(input, "\x1b[32m");
}

inline std::string bold(std::string_view input) {
  return wrap(input, "\x1b[1m");
}

inline std::string dim(std::string_view input) {
  return wrap(input, "\x1b[2m");
}

} // namespace klint::color
