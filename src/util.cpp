#include "util.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstring>
#include <deque>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace klint::util {

namespace {

constexpr std::size_t kMaxCapturedStreamBytes =
    static_cast<std::size_t>(8) * 1024 * 1024;

constexpr std::array<std::string_view, 6> kTrustedRootPathDirs = {
    "/usr/local/sbin", "/usr/local/bin", "/usr/sbin",
    "/usr/bin",        "/sbin",          "/bin",
};

std::string errno_message(const std::string &prefix) {
  return prefix + ": " + std::strerror(errno);
}

std::string errno_message_with(const std::string &prefix, int error_number) {
  return prefix + ": " + std::strerror(error_number);
}

bool set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    return false;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

bool set_cloexec(int fd) {
  int flags = fcntl(fd, F_GETFD, 0);
  if (flags == -1) {
    return false;
  }
  return fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

bool create_pipe_cloexec(int pipefd[2], std::string &error,
                         std::string_view label) {
  if (::pipe2(pipefd, O_CLOEXEC) == 0) {
    return true;
  }

  if (errno != ENOSYS) {
    error = errno_message("pipe " + std::string(label));
    return false;
  }

  if (::pipe(pipefd) != 0) {
    error = errno_message("pipe " + std::string(label));
    return false;
  }
  if (!set_cloexec(pipefd[0]) || !set_cloexec(pipefd[1])) {
    error = errno_message("fcntl FD_CLOEXEC " + std::string(label));
    ::close(pipefd[0]);
    ::close(pipefd[1]);
    return false;
  }

  return true;
}

bool is_executable_file(const std::string &path) {
  struct stat st;
  if (::stat(path.c_str(), &st) != 0) {
    return false;
  }
  if (!S_ISREG(st.st_mode)) {
    return false;
  }
  return ::access(path.c_str(), X_OK) == 0;
}

bool path_segment_allowed(std::string_view segment, bool secure_path) {
  if (segment.empty()) {
    return false;
  }
  if (!secure_path) {
    return true;
  }
  return segment.front() == '/';
}

std::optional<std::string>
resolve_root_executable_path(const std::string &tool) {
  for (std::string_view segment : kTrustedRootPathDirs) {
    std::string candidate = std::string(segment) + "/" + tool;
    if (is_executable_file(candidate)) {
      return candidate;
    }
  }
  return std::nullopt;
}

std::optional<std::string> resolve_executable_path(const std::string &tool,
                                                   bool secure_path) {
  if (tool.empty()) {
    return std::nullopt;
  }
  if (tool.find('/') != std::string::npos) {
    if (is_executable_file(tool)) {
      return tool;
    }
    return std::nullopt;
  }

  if (secure_path) {
    return resolve_root_executable_path(tool);
  }

  const char *path_env = std::getenv("PATH");
  if (!path_env) {
    return std::nullopt;
  }

  std::string_view path_view(path_env);
  std::size_t start = 0;
  while (start <= path_view.size()) {
    std::size_t end = path_view.find(':', start);
    if (end == std::string_view::npos) {
      end = path_view.size();
    }

    std::string_view segment = path_view.substr(start, end - start);
    if (path_segment_allowed(segment, false)) {
      std::string candidate = std::string(segment) + "/" + tool;
      if (is_executable_file(candidate)) {
        return candidate;
      }
    }

    if (end == path_view.size()) {
      break;
    }
    start = end + 1;
  }

  return std::nullopt;
}

void read_from_fd(int fd, std::string &out, bool &closed, bool &truncated,
                  std::string &error, std::size_t max_capture_bytes) {
  char buffer[4096];
  while (true) {
    ssize_t n = ::read(fd, buffer, sizeof(buffer));
    if (n > 0) {
      std::size_t chunk = static_cast<std::size_t>(n);
      if (out.size() >= max_capture_bytes) {
        truncated = true;
        continue;
      }

      std::size_t remaining = max_capture_bytes - out.size();
      if (chunk > remaining) {
        out.append(buffer, remaining);
        truncated = true;
      } else {
        out.append(buffer, chunk);
      }
      continue;
    }
    if (n == 0) {
      closed = true;
      return;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return;
    }
    if (error.empty()) {
      error = errno_message("read command stream");
    }
    closed = true;
    return;
  }
}

void kill_process_tree(pid_t pid) {
  if (pid <= 0) {
    return;
  }
  std::unordered_map<pid_t, std::vector<pid_t>> children;
  DIR *proc_dir = ::opendir("/proc");
  if (proc_dir) {
    while (true) {
      errno = 0;
      dirent *entry = ::readdir(proc_dir);
      if (!entry) {
        break;
      }

      std::string_view name(entry->d_name);
      int child_value = 0;
      auto [pid_ptr, pid_ec] =
          std::from_chars(name.data(), name.data() + name.size(), child_value);
      if (pid_ec != std::errc{} || pid_ptr != name.data() + name.size() ||
          child_value <= 0 || child_value == pid) {
        continue;
      }

      auto stat_data =
          read_file("/proc/" + std::to_string(child_value) + "/stat");
      if (!stat_data) {
        continue;
      }

      std::string_view stat_line(*stat_data);
      std::size_t close_paren = stat_line.rfind(')');
      if (close_paren == std::string_view::npos ||
          close_paren + 2 >= stat_line.size()) {
        continue;
      }

      std::size_t pos = close_paren + 2;
      if (pos >= stat_line.size()) {
        continue;
      }
      ++pos;
      while (pos < stat_line.size() &&
             std::isspace(static_cast<unsigned char>(stat_line[pos]))) {
        ++pos;
      }
      if (pos >= stat_line.size()) {
        continue;
      }

      std::size_t start = pos;
      while (pos < stat_line.size() &&
             !std::isspace(static_cast<unsigned char>(stat_line[pos]))) {
        ++pos;
      }

      int ppid_value = 0;
      auto [ppid_ptr, ppid_ec] = std::from_chars(
          stat_line.data() + start, stat_line.data() + pos, ppid_value);
      if (ppid_ec != std::errc{} || ppid_ptr != stat_line.data() + pos ||
          ppid_value <= 0) {
        continue;
      }

      children[static_cast<pid_t>(ppid_value)].push_back(
          static_cast<pid_t>(child_value));
    }
    ::closedir(proc_dir);
  }

  std::vector<pid_t> descendants;
  std::vector<pid_t> stack = {pid};
  while (!stack.empty()) {
    pid_t current = stack.back();
    stack.pop_back();
    auto it = children.find(current);
    if (it == children.end()) {
      continue;
    }
    for (pid_t child : it->second) {
      descendants.push_back(child);
      stack.push_back(child);
    }
  }

  for (pid_t child : descendants) {
    if (::getpgid(child) == child) {
      (void)::kill(-child, SIGKILL);
    }
  }
  for (pid_t child : descendants) {
    (void)::kill(child, SIGKILL);
  }

  if (::getpgid(pid) == pid) {
    (void)::kill(-pid, SIGKILL);
  }
  (void)::kill(pid, SIGKILL);
}

} // namespace

std::expected<std::string, std::string> read_file(const std::string &path,
                                                  int *error_number) {
  if (error_number) {
    *error_number = 0;
  }

  int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd == -1) {
    int saved_errno = errno;
    if (error_number) {
      *error_number = saved_errno;
    }
    return std::unexpected(errno_message_with("open " + path, saved_errno));
  }

  std::string data;
  char buffer[8192];
  while (true) {
    ssize_t n = ::read(fd, buffer, sizeof(buffer));
    if (n > 0) {
      data.append(buffer, static_cast<std::size_t>(n));
      continue;
    }
    if (n == 0) {
      break;
    }
    if (errno == EINTR) {
      continue;
    }
    int saved_errno = errno;
    ::close(fd);
    if (error_number) {
      *error_number = saved_errno;
    }
    return std::unexpected(errno_message_with("read " + path, saved_errno));
  }

  ::close(fd);
  return data;
}

std::expected<CommandOutput, std::string>
run_command(const std::vector<std::string> &args,
            std::chrono::milliseconds timeout) {
  if (args.empty()) {
    return std::unexpected("run_command: empty args");
  }
  if (timeout <= std::chrono::milliseconds::zero()) {
    return std::unexpected("run_command: timeout must be positive");
  }

  bool secure_path = (::geteuid() == 0);
  auto command_path = resolve_executable_path(args[0], secure_path);
  if (!command_path) {
    std::string message = "run_command: executable not found: " + args[0];
    if (secure_path) {
      message += " (root command lookup uses trusted system directories only)";
    }
    return std::unexpected(std::move(message));
  }

  int out_pipe[2];
  int err_pipe[2];
  std::string pipe_error;
  if (!create_pipe_cloexec(out_pipe, pipe_error, "stdout")) {
    return std::unexpected(std::move(pipe_error));
  }
  if (!create_pipe_cloexec(err_pipe, pipe_error, "stderr")) {
    ::close(out_pipe[0]);
    ::close(out_pipe[1]);
    return std::unexpected(std::move(pipe_error));
  }

  pid_t pid = fork();
  if (pid == -1) {
    ::close(out_pipe[0]);
    ::close(out_pipe[1]);
    ::close(err_pipe[0]);
    ::close(err_pipe[1]);
    return std::unexpected(errno_message("fork"));
  }

  if (pid == 0) {
    (void)::setpgid(0, 0);
    if (::dup2(out_pipe[1], STDOUT_FILENO) == -1 ||
        ::dup2(err_pipe[1], STDERR_FILENO) == -1) {
      _exit(127);
    }
    ::close(out_pipe[0]);
    ::close(out_pipe[1]);
    ::close(err_pipe[0]);
    ::close(err_pipe[1]);

    std::vector<char *> argv;
    argv.reserve(args.size() + 1);
    for (const auto &arg : args) {
      argv.push_back(const_cast<char *>(arg.c_str()));
    }
    argv.push_back(nullptr);
    ::execv(command_path->c_str(), argv.data());
    _exit(127);
  }

  ::close(out_pipe[1]);
  ::close(err_pipe[1]);
  (void)::setpgid(pid, pid);

  if (!set_nonblocking(out_pipe[0])) {
    std::string error = errno_message("fcntl O_NONBLOCK stdout");
    ::close(out_pipe[0]);
    ::close(err_pipe[0]);
    kill_process_tree(pid);
    int status = 0;
    while (::waitpid(pid, &status, 0) == -1 && errno == EINTR) {
    }
    return std::unexpected(error);
  }
  if (!set_nonblocking(err_pipe[0])) {
    std::string error = errno_message("fcntl O_NONBLOCK stderr");
    ::close(out_pipe[0]);
    ::close(err_pipe[0]);
    kill_process_tree(pid);
    int status = 0;
    while (::waitpid(pid, &status, 0) == -1 && errno == EINTR) {
    }
    return std::unexpected(error);
  }

  CommandOutput output;
  bool out_closed = false;
  bool err_closed = false;
  bool out_truncated = false;
  bool err_truncated = false;
  std::string io_error;
  bool kill_child = false;
  bool command_timed_out = false;
  auto deadline = std::chrono::steady_clock::now() + timeout;

  while (!out_closed || !err_closed) {
    pollfd poll_fds[2];
    bool is_stdout_fd[2] = {false, false};
    nfds_t poll_count = 0;
    if (!out_closed) {
      poll_fds[poll_count].fd = out_pipe[0];
      poll_fds[poll_count].events = POLLIN | POLLHUP;
      poll_fds[poll_count].revents = 0;
      is_stdout_fd[poll_count] = true;
      ++poll_count;
    }
    if (!err_closed) {
      poll_fds[poll_count].fd = err_pipe[0];
      poll_fds[poll_count].events = POLLIN | POLLHUP;
      poll_fds[poll_count].revents = 0;
      is_stdout_fd[poll_count] = false;
      ++poll_count;
    }

    if (poll_count == 0) {
      break;
    }

    auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      command_timed_out = true;
      kill_child = true;
      break;
    }
    auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
    int wait_ms = static_cast<int>(
        std::min<std::chrono::milliseconds>(
            remaining,
            std::chrono::milliseconds(std::numeric_limits<int>::max()))
            .count());
    if (wait_ms < 0) {
      wait_ms = 0;
    }

    int ready = ::poll(poll_fds, poll_count, wait_ms);
    if (ready == -1) {
      if (errno == EINTR) {
        continue;
      }
      if (io_error.empty()) {
        io_error = errno_message("poll");
      }
      kill_child = true;
      break;
    }
    if (ready == 0) {
      continue;
    }

    for (nfds_t i = 0; i < poll_count; ++i) {
      short revents = poll_fds[i].revents;
      if ((revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) == 0) {
        continue;
      }
      if (is_stdout_fd[i]) {
        read_from_fd(out_pipe[0], output.stdout_data, out_closed, out_truncated,
                     io_error, kMaxCapturedStreamBytes);
      } else {
        read_from_fd(err_pipe[0], output.stderr_data, err_closed, err_truncated,
                     io_error, kMaxCapturedStreamBytes);
      }
      if (!io_error.empty()) {
        kill_child = true;
        break;
      }
    }
  }

  if (kill_child) {
    kill_process_tree(pid);
  }

  ::close(out_pipe[0]);
  ::close(err_pipe[0]);

  int status = 0;
  pid_t waited = 0;
  do {
    waited = ::waitpid(pid, &status, 0);
  } while (waited == -1 && errno == EINTR);

  if (waited == -1) {
    return std::unexpected(errno_message("waitpid"));
  }
  if (command_timed_out) {
    return std::unexpected("command timed out");
  }
  if (!io_error.empty()) {
    return std::unexpected(io_error);
  }

  if (WIFEXITED(status)) {
    output.exit_code = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    output.exit_code = 128 + WTERMSIG(status);
  } else {
    output.exit_code = status;
  }
  output.stdout_truncated = out_truncated;
  output.stderr_truncated = err_truncated;

  return output;
}

bool tool_exists(const std::string &tool) {
  bool secure_path = (::geteuid() == 0);
  return resolve_executable_path(tool, secure_path).has_value();
}

std::vector<std::string> walk_dir_bounded(const std::string &root,
                                          std::size_t max_entries,
                                          const DirVisitor &visitor,
                                          std::size_t max_depth) {
  std::vector<std::string> errors;
  std::deque<std::pair<std::string, std::size_t>> queue;
  queue.emplace_back(root, 0);
  std::size_t seen = 0;

  while (!queue.empty() && seen < max_entries) {
    std::string current = std::move(queue.front().first);
    std::size_t depth = queue.front().second;
    queue.pop_front();

    DIR *dir = ::opendir(current.c_str());
    if (!dir) {
      errors.push_back(errno_message("opendir " + current));
      continue;
    }

    while (seen < max_entries) {
      errno = 0;
      dirent *entry = ::readdir(dir);
      if (!entry) {
        if (errno != 0) {
          errors.push_back(errno_message("readdir " + current));
        }
        break;
      }
      std::string name(entry->d_name);
      if (name == "." || name == "..") {
        continue;
      }

      std::string path = current + "/" + name;
      struct stat st;
      if (::lstat(path.c_str(), &st) != 0) {
        errors.push_back(errno_message("lstat " + path));
        continue;
      }

      visitor(path, st);
      ++seen;

      if (S_ISDIR(st.st_mode) && depth < max_depth) {
        queue.emplace_back(path, depth + 1);
      }
    }

    ::closedir(dir);
  }

  if (!queue.empty() && seen >= max_entries) {
    errors.push_back("walk_dir_bounded truncated at " + root +
                     " (max_entries=" + std::to_string(max_entries) + ")");
  }

  return errors;
}

std::vector<std::string> split_lines(std::string_view text) {
  if (text.empty()) {
    return {};
  }
  std::vector<std::string> lines;
  std::size_t start = 0;
  while (start <= text.size()) {
    std::size_t end = text.find('\n', start);
    if (end == std::string_view::npos) {
      end = text.size();
    }
    lines.emplace_back(text.substr(start, end - start));
    if (end == text.size()) {
      break;
    }
    start = end + 1;
  }
  return lines;
}

std::string join(const std::vector<std::string> &parts,
                 std::string_view delim) {
  return join(std::span<const std::string>(parts.data(), parts.size()), delim);
}

std::string join(std::span<const std::string> parts, std::string_view delim) {
  if (parts.empty()) {
    return {};
  }
  std::string out = parts[0];
  for (std::size_t i = 1; i < parts.size(); ++i) {
    out.append(delim);
    out.append(parts[i]);
  }
  return out;
}

} // namespace klint::util
