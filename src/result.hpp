#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace klint {

enum class Severity {
  Info = 0,
  Warning = 1,
  Critical = 2,
};

inline std::string_view to_string(Severity severity) {
  switch (severity) {
  case Severity::Info:
    return "info";
  case Severity::Warning:
    return "warning";
  case Severity::Critical:
    return "critical";
  }
  return "unknown";
}

struct Finding {
  std::string summary;
  Severity severity;
  std::optional<std::string> detail;
  std::vector<std::pair<std::string, std::string>> evidence;

  Finding(Severity severity_, std::string summary_)
      : summary(std::move(summary_)), severity(severity_) {}

  Finding &with_detail(std::string detail_) & {
    detail = std::move(detail_);
    return *this;
  }

  Finding &&with_detail(std::string detail_) && {
    detail = std::move(detail_);
    return std::move(*this);
  }

  Finding &with_evidence(std::string key, std::string value) & {
    evidence.emplace_back(std::move(key), std::move(value));
    return *this;
  }

  Finding &&with_evidence(std::string key, std::string value) && {
    evidence.emplace_back(std::move(key), std::move(value));
    return std::move(*this);
  }
};

struct ScanResult {
  std::vector<Finding> findings;
  std::vector<std::string> errors;

  void add_finding(Finding finding) { findings.push_back(std::move(finding)); }

  void add_error(std::string error) { errors.push_back(std::move(error)); }

  [[nodiscard]] bool has_findings() const { return !findings.empty(); }

  [[nodiscard]] bool has_errors() const { return !errors.empty(); }

  [[nodiscard]] std::optional<Severity> max_severity() const {
    if (findings.empty()) {
      return std::nullopt;
    }
    Severity max = findings.front().severity;
    for (const auto &finding : findings) {
      if (finding.severity > max) {
        max = finding.severity;
      }
    }
    return max;
  }

  static ScanResult clean() { return ScanResult{}; }
};

} // namespace klint
