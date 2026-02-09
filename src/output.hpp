#pragma once

#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "result.hpp"
#include "scanner.hpp"

namespace klint::output {

enum class ReportStatus {
  Clean,
  Findings,
  Error,
  Skipped,
  Timeout,
};

std::string_view to_string(ReportStatus status);

struct ScannerReport {
  std::string scanner;
  std::vector<std::string> categories;
  ReportStatus status = ReportStatus::Clean;
  std::optional<ScanResult> result;
  std::optional<std::string> skip_reason;
};

void print_text_report(const ScannerReport &report);

void print_scanner_list(std::span<const Scanner *const> scanners);

nlohmann::json reports_to_json(const std::vector<ScannerReport> &reports);

} // namespace klint::output
