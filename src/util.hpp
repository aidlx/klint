#pragma once

#include <sys/stat.h>

#include <chrono>
#include <expected>
#include <functional>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace klint::util {

struct CommandOutput {
  std::string stdout_data;
  std::string stderr_data;
  bool stdout_truncated = false;
  bool stderr_truncated = false;
  int exit_code = 0;
};

std::expected<std::string, std::string> read_file(const std::string &path,
                                                  int *error_number = nullptr);

std::expected<CommandOutput, std::string>
run_command(const std::vector<std::string> &args,
            std::chrono::milliseconds timeout = std::chrono::seconds(30));

bool tool_exists(const std::string &tool);

using DirVisitor =
    std::function<void(const std::string &path, const struct stat &st)>;

std::vector<std::string> walk_dir_bounded(
    const std::string &root, std::size_t max_entries, const DirVisitor &visitor,
    std::size_t max_depth = std::numeric_limits<std::size_t>::max());

std::vector<std::string> split_lines(std::string_view text);

std::string join(const std::vector<std::string> &parts, std::string_view delim);

std::string join(std::span<const std::string> parts, std::string_view delim);

} // namespace klint::util
