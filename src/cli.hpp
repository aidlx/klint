#pragma once

#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace klint::cli {

enum class OutputMode {
  Text,
  Json,
};

struct Options {
  OutputMode mode = OutputMode::Text;
  bool list = false;
  bool help = false;
  bool no_color = false;
  int timeout_seconds = 30;
  std::vector<std::string> include_scanners;
  std::vector<std::string> exclude_scanners;
};

std::expected<Options, std::string> parse_args(int argc, char **argv);

std::string usage(std::string_view program);

} // namespace klint::cli
