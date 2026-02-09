#include "cli.hpp"

#include <charconv>
#include <sstream>

namespace klint::cli {

std::string usage(std::string_view program) {
  std::ostringstream out;
  out << "Usage: " << program << " [options]\n\n";
  out << "Options:\n";
  out << "  --json             Emit JSON output\n";
  out << "  --text             Emit colored text output (default)\n";
  out << "  --scanner <name>   Run only named scanner (repeatable)\n";
  out << "  --exclude <name>   Skip named scanner (repeatable)\n";
  out << "                     (applies even when --scanner is used)\n";
  out << "  --list             List scanners and exit\n";
  out << "  --timeout <sec>    Per-scanner timeout in seconds (default: 30)\n";
  out << "  --no-color         Disable ANSI color codes\n";
  out << "  -h, --help         Show this help and exit\n";
  return out.str();
}

std::expected<Options, std::string> parse_args(int argc, char **argv) {
  Options options;

  for (int i = 1; i < argc; ++i) {
    std::string_view arg(argv[i]);

    if (arg == "--json") {
      options.mode = OutputMode::Json;
      continue;
    }
    if (arg == "--text") {
      options.mode = OutputMode::Text;
      continue;
    }
    if (arg == "--list") {
      options.list = true;
      continue;
    }
    if (arg == "--no-color") {
      options.no_color = true;
      continue;
    }
    if (arg == "-h" || arg == "--help") {
      options.help = true;
      continue;
    }
    if (arg == "--scanner") {
      if (i + 1 >= argc) {
        return std::unexpected("Missing value for --scanner");
      }
      options.include_scanners.emplace_back(argv[++i]);
      continue;
    }
    if (arg == "--exclude") {
      if (i + 1 >= argc) {
        return std::unexpected("Missing value for --exclude");
      }
      options.exclude_scanners.emplace_back(argv[++i]);
      continue;
    }
    if (arg == "--timeout") {
      if (i + 1 >= argc) {
        return std::unexpected("Missing value for --timeout");
      }
      std::string_view value(argv[++i]);
      int timeout = 0;
      auto [ptr, ec] =
          std::from_chars(value.data(), value.data() + value.size(), timeout);
      if (ec != std::errc{} || ptr != value.data() + value.size()) {
        return std::unexpected("Invalid --timeout value: " +
                               std::string(value));
      }
      if (timeout <= 0) {
        return std::unexpected("--timeout must be positive");
      }
      options.timeout_seconds = timeout;
      continue;
    }

    if (!arg.empty() && arg[0] == '-') {
      return std::unexpected("Unknown option: " + std::string(arg));
    }

    return std::unexpected("Unexpected argument: " + std::string(arg));
  }

  return options;
}

} // namespace klint::cli
