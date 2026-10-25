#pragma once

#include "ghostdisk/analysis_types.hpp"
#include <cstdint>
#include <vector>
#include <string>

#if __has_include(<optional>)
#include <optional>
namespace ghostdisk {
    using std::optional;
    using std::nullopt;
}
#elif __has_include(<experimental/optional>)
#include <experimental/optional>
namespace ghostdisk {
    using std::experimental::optional;
    using std::experimental::nullopt;
}
#endif

namespace ghostdisk {

/**
 * @brief Turns measurements + a DiscrepancyReport into readable, evidence-backed Findings.
 *
 * Read-only: it never deletes files, never touches processes. Every recommendation
 * it produces is guidance text for the user, not an action.
 */
class FindingAnalyzer {
public:
    /**
     * @brief Full pipeline: runs DiscrepancyAnalyzer, then builds findings.
     * This is the one call Member 5's UI should make.
     */
    static AnalysisResult analyze(
        const FsSnapshot& fs,
        const DirectoryScanResult& scan,
        const ScanOptions& scan_options,
        const ProcScanResult& proc,
        const AnalyzerConfig& config = AnalyzerConfig{},
        optional<uint64_t> mount_device_id = nullopt
    );

    /**
     * @brief Builds findings from an existing report (useful for unit tests).
     */
    static std::vector<Finding> build_findings(
        const DiscrepancyReport& report,
        const FsSnapshot& fs,
        const AnalyzerConfig& config = AnalyzerConfig{}
    );

    /**
     * @brief Escapes a string for safe inclusion inside a JSON string literal.
     */
    static std::string json_escape(const std::string& s);
};

} // namespace ghostdisk
