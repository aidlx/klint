#pragma once

#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "result.hpp"
#include "util.hpp"

namespace klint {

enum class Category {
  Kernel,
  Network,
  Filesystem,
  Container,
  Persistence,
  Process,
};

inline std::string_view to_string(Category category) {
  switch (category) {
  case Category::Kernel:
    return "kernel";
  case Category::Network:
    return "network";
  case Category::Filesystem:
    return "filesystem";
  case Category::Container:
    return "container";
  case Category::Persistence:
    return "persistence";
  case Category::Process:
    return "process";
  }
  return "unknown";
}

struct Requirement {
  enum class Kind { ExternalTool };

  Kind kind;
  std::string tool;

  static Requirement external_tool(std::string tool_name) {
    return Requirement{Kind::ExternalTool, std::move(tool_name)};
  }

  bool check() const {
    switch (kind) {
    case Kind::ExternalTool:
      return util::tool_exists(tool);
    }
    return false;
  }

  std::string label() const {
    switch (kind) {
    case Kind::ExternalTool:
      return "tool:" + tool;
    }
    return "unknown";
  }
};

struct Scanner {
  std::string_view name;
  ScanResult (*func)();
  std::span<const Category> categories;
  std::span<const Requirement> requirements;

  std::vector<std::string> requirement_labels() const {
    std::vector<std::string> labels;
    labels.reserve(requirements.size());

    for (const auto &req : requirements) {
      labels.push_back(req.label());
    }

    return labels;
  }

  std::vector<std::string> unmet_requirements() const {
    std::vector<std::string> unmet;

    for (const auto &req : requirements) {
      if (!req.check()) {
        unmet.push_back(req.label());
      }
    }
    return unmet;
  }
};

inline std::vector<const Scanner *> &registry_storage() {
  static std::vector<const Scanner *> storage;
  return storage;
}

inline std::span<const Scanner *const> registry() {
  auto &storage = registry_storage();
  return std::span<const Scanner *const>(storage.data(), storage.size());
}

class Registrar {
public:
  explicit Registrar(Scanner scanner) : scanner_(std::move(scanner)) {
    registry_storage().push_back(&scanner_);
  }

private:
  Scanner scanner_;
};

} // namespace klint
