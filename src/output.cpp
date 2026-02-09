#include "output.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>

#include "color.hpp"
#include "util.hpp"

namespace klint::output {

namespace {

std::string severity_label(Severity severity) {
  switch (severity) {
  case Severity::Info:
    return "INFO";
  case Severity::Warning:
    return "WARNING";
  case Severity::Critical:
    return "CRITICAL";
  }
  return "UNKNOWN";
}

std::string colorize_severity(Severity severity, std::string_view label) {
  switch (severity) {
  case Severity::Info:
    return color::dim(label);
  case Severity::Warning:
    return color::yellow(label);
  case Severity::Critical:
    return color::red(label);
  }
  return std::string(label);
}

std::string join_categories(const std::vector<std::string> &categories) {
  return util::join(categories, ", ");
}

} // namespace

std::string_view to_string(ReportStatus status) {
  switch (status) {
  case ReportStatus::Clean:
    return "clean";
  case ReportStatus::Findings:
    return "findings";
  case ReportStatus::Error:
    return "error";
  case ReportStatus::Skipped:
    return "skipped";
  case ReportStatus::Timeout:
    return "timeout";
  }
  return "unknown";
}

void print_text_report(const ScannerReport &report) {
  std::string name = color::bold(report.scanner);

  if (report.status == ReportStatus::Clean) {
    std::cout << "[" << name << "] " << color::green("OK") << "\n";
    return;
  }

  if (report.status == ReportStatus::Skipped) {
    std::cout << "[" << name << "] " << color::dim("SKIP");
    if (report.skip_reason && !report.skip_reason->empty()) {
      std::cout << " (" << color::dim(*report.skip_reason) << ")";
    }
    std::cout << "\n";
    return;
  }

  if (report.status == ReportStatus::Timeout) {
    std::cout << "[" << name << "] " << color::red("TIMEOUT") << "\n";
    return;
  }

  std::cout << "[" << name << "]";
  if (!report.categories.empty()) {
    std::cout << " (" << join_categories(report.categories) << ")";
  }
  std::cout << "\n";

  if (report.result) {
    for (const auto &finding : report.result->findings) {
      std::string label = severity_label(finding.severity);
      std::string colored = colorize_severity(finding.severity, label);
      std::cout << "  " << colored << " " << finding.summary << "\n";
      if (finding.detail && !finding.detail->empty()) {
        for (const auto &line : util::split_lines(*finding.detail)) {
          std::cout << "    " << color::dim(line) << "\n";
        }
      }
      for (const auto &evidence : finding.evidence) {
        std::cout << "    "
                  << color::dim(evidence.first + ": " + evidence.second)
                  << "\n";
      }
    }

    for (const auto &error : report.result->errors) {
      std::cout << "  " << color::red("ERROR") << " " << error << "\n";
    }
  }
}

void print_scanner_list(std::span<const Scanner *const> scanners) {
  struct Row {
    std::string name;
    std::string categories;
    std::string requirements;
  };

  std::vector<Row> rows;
  rows.reserve(scanners.size());

  std::size_t name_width = std::string("SCANNER").size();
  std::size_t category_width = std::string("CATEGORIES").size();
  std::size_t requires_width = std::string("REQUIRES").size();

  for (const auto *scanner : scanners) {
    Row row;
    row.name = std::string(scanner->name);

    std::vector<std::string> category_labels;
    category_labels.reserve(scanner->categories.size());
    for (auto category : scanner->categories) {
      category_labels.emplace_back(to_string(category));
    }
    row.categories = util::join(category_labels, ", ");

    std::vector<std::string> requirement_labels = scanner->requirement_labels();
    row.requirements =
        requirement_labels.empty() ? "-" : util::join(requirement_labels, ", ");

    name_width = std::max(name_width, row.name.size());
    category_width = std::max(category_width, row.categories.size());
    requires_width = std::max(requires_width, row.requirements.size());

    rows.push_back(std::move(row));
  }

  std::sort(rows.begin(), rows.end(),
            [](const Row &lhs, const Row &rhs) { return lhs.name < rhs.name; });

  const std::size_t padding = 2;
  std::size_t total_width =
      name_width + padding + category_width + padding + requires_width;

  std::cout << std::left << std::setw(static_cast<int>(name_width + padding))
            << "SCANNER"
            << std::setw(static_cast<int>(category_width + padding))
            << "CATEGORIES"
            << "REQUIRES" << "\n";
  std::cout << std::string(total_width, '-') << "\n";

  for (const auto &row : rows) {
    std::cout << std::left << std::setw(static_cast<int>(name_width + padding))
              << row.name
              << std::setw(static_cast<int>(category_width + padding))
              << row.categories << row.requirements << "\n";
  }
}

nlohmann::json reports_to_json(const std::vector<ScannerReport> &reports) {
  nlohmann::json root;
  nlohmann::json scanners_json = nlohmann::json::array();

  std::size_t clean = 0;
  std::size_t findings = 0;
  std::size_t errors = 0;
  std::size_t skipped = 0;
  std::size_t timed_out = 0;

  for (const auto &report : reports) {
    nlohmann::json item;
    item["scanner"] = report.scanner;
    item["categories"] = report.categories;
    item["status"] = std::string(to_string(report.status));

    if (report.result) {
      nlohmann::json result_json;
      nlohmann::json findings_json = nlohmann::json::array();
      for (const auto &finding : report.result->findings) {
        nlohmann::json finding_json;
        finding_json["severity"] = std::string(to_string(finding.severity));
        finding_json["summary"] = finding.summary;
        if (finding.detail && !finding.detail->empty()) {
          finding_json["detail"] = *finding.detail;
        }
        if (!finding.evidence.empty()) {
          nlohmann::json evidence_json = nlohmann::json::array();
          for (const auto &evidence : finding.evidence) {
            evidence_json.push_back(
                {{"key", evidence.first}, {"value", evidence.second}});
          }
          finding_json["evidence"] = std::move(evidence_json);
        }
        findings_json.push_back(std::move(finding_json));
      }
      result_json["findings"] = std::move(findings_json);

      nlohmann::json errors_json = nlohmann::json::array();
      for (const auto &error : report.result->errors) {
        errors_json.push_back(error);
      }
      result_json["errors"] = std::move(errors_json);

      item["result"] = std::move(result_json);
    }

    if (report.skip_reason && !report.skip_reason->empty()) {
      item["skip_reason"] = *report.skip_reason;
    }

    scanners_json.push_back(std::move(item));

    switch (report.status) {
    case ReportStatus::Clean:
      ++clean;
      break;
    case ReportStatus::Findings:
      ++findings;
      break;
    case ReportStatus::Error:
      ++errors;
      break;
    case ReportStatus::Skipped:
      ++skipped;
      break;
    case ReportStatus::Timeout:
      ++timed_out;
      break;
    }
  }

  root["scanners"] = std::move(scanners_json);
  root["summary"] = {
      {"total", reports.size()}, {"clean", clean},     {"findings", findings},
      {"errors", errors},        {"skipped", skipped}, {"timed_out", timed_out},
  };

  return root;
}

} // namespace klint::output
