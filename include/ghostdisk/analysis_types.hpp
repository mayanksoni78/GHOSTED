#pragma once

#include "ghostdisk/types.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace ghostdisk {

// ---------------------------------------------------------------------------
// Member 3 types. Kept in their own header so types.hpp (Member 1/2) is untouched.
// Members 4 (recovery) and 5 (UI + SQLite) consume these.
// ---------------------------------------------------------------------------

enum class FindingType {
    DeletedOpenFile,        // a deleted file still held open by a process
    UnresolvedDiscrepancy,  // filesystem used > scan total, and evidence does not explain it
    NoDiscrepancy,          // scan and filesystem agree within tolerance
    ScanExceedsFilesystem,  // scan total is larger than filesystem used (hard links, races, ...)
    ScopeNotComparable,     // scan scope cannot be compared with filesystem totals
    CoverageLimitation      // skipped paths / restricted PIDs / cancelled scan / proc scan failure
};

enum class Severity   { Info, Warning, Critical };
enum class Confidence { Low, Medium, High };

// Mirrors spec section 10.5:
//   Low    = supported   (only Member 4's allowlist may ever produce this for an action)
//   Medium = needs manual review
//   High   = unsupported (no automatic action, diagnostic guidance only)
enum class RiskLevel { Low, Medium, High };

// Where the scanned folder sits relative to the filesystem mount we measured.
enum class ScanScope {
    WholeMount,   // scan root == mount point
    PartOfMount,  // scan root is a sub-folder of the mount point
    OutsideMount, // scan root is not under the mount point at all
    Unknown       // missing information
};

inline const char* to_string(FindingType t) {
    switch (t) {
        case FindingType::DeletedOpenFile:       return "deleted_open_file";
        case FindingType::UnresolvedDiscrepancy: return "unresolved_discrepancy";
        case FindingType::NoDiscrepancy:         return "no_discrepancy";
        case FindingType::ScanExceedsFilesystem: return "scan_exceeds_filesystem";
        case FindingType::ScopeNotComparable:    return "scope_not_comparable";
        case FindingType::CoverageLimitation:    return "coverage_limitation";
    }
    return "unknown";
}

inline const char* to_string(Severity s) {
    switch (s) {
        case Severity::Info:     return "info";
        case Severity::Warning:  return "warning";
        case Severity::Critical: return "critical";
    }
    return "unknown";
}

inline const char* to_string(Confidence c) {
    switch (c) {
        case Confidence::Low:    return "low";
        case Confidence::Medium: return "medium";
        case Confidence::High:   return "high";
    }
    return "unknown";
}

inline const char* to_string(RiskLevel r) {
    switch (r) {
        case RiskLevel::Low:    return "low";
        case RiskLevel::Medium: return "medium";
        case RiskLevel::High:   return "high";
    }
    return "unknown";
}

inline const char* to_string(ScanScope s) {
    switch (s) {
        case ScanScope::WholeMount:   return "whole_mount";
        case ScanScope::PartOfMount:  return "part_of_mount";
        case ScanScope::OutsideMount: return "outside_mount";
        case ScanScope::Unknown:      return "unknown";
    }
    return "unknown";
}

/**
 * @brief Tunable thresholds. Defaults are sensible for a demo.
 */
struct AnalyzerConfig {
    // A gap smaller than max(tolerance_bytes, tolerance_fraction * fs_used) is treated
    // as normal noise (metadata, journal, rounding), not as a discrepancy.
    uint64_t tolerance_bytes{64ULL * 1024 * 1024};
    double   tolerance_fraction{0.01};

    // Severity thresholds for a single deleted-open file / unresolved gap.
    uint64_t warning_bytes{100ULL * 1024 * 1024};
    uint64_t critical_bytes{1024ULL * 1024 * 1024};

    // If available/total is below this, severity is bumped one level.
    double low_space_fraction{0.10};

    // 0 = use the current time. Tests set this for deterministic output.
    int64_t now_epoch_sec{0};
};

/**
 * @brief Result of comparing filesystem totals against a directory scan.
 *
 * All byte values are ALLOCATED bytes (st_blocks * 512), never apparent size.
 * The unresolved part is an investigation target, never "waste".
 */
struct DiscrepancyReport {
    bool valid{false};            // false when the filesystem snapshot itself failed
    std::string invalid_reason;

    std::string mount_point;
    std::string scan_root;
    ScanScope scope{ScanScope::Unknown};
    bool comparable{false};       // false => gap/unresolved below are NOT meaningful (left at 0)
    std::string scope_note;       // plain-language explanation of comparable / not comparable

    uint64_t fs_used_bytes{0};         // from statvfs: total - raw_free
    uint64_t scan_allocated_bytes{0};  // from DirectoryScanner
    int64_t  gap_bytes{0};             // fs_used - scan_allocated (negative = scan is larger)

    uint64_t deleted_open_bytes{0};    // deduplicated, only files on THIS filesystem
    uint64_t reserved_bytes{0};        // informational only; lives inside "free", NOT inside the gap
    uint64_t explained_bytes{0};       // min(max(gap,0), deleted_open_bytes)
    uint64_t unresolved_bytes{0};      // max(gap,0) - explained
    uint64_t tolerance_bytes{0};       // the tolerance actually applied
    bool unresolved_significant{false};   // unresolved_bytes > tolerance_bytes
    bool scan_exceeds_filesystem{false};  // gap < 0 beyond tolerance

    uint64_t skipped_count{0};
    uint64_t restricted_pid_count{0};
    bool scan_cancelled{false};
    bool scan_ok{false};
    bool proc_scan_ok{false};
    bool device_filter_applied{false};
    uint64_t deleted_open_other_mounts_count{0};

    std::vector<DeletedOpenFileFinding> deleted_open_on_mount;
    std::vector<std::string> caveats;

    int64_t fs_sampled_at_epoch_sec{0};
    int64_t analyzed_at_epoch_sec{0};
};

/**
 * @brief One explainable diagnosis. Confirmed facts and likely explanation are
 *        deliberately separate fields so the UI can show them separately.
 */
struct Finding {
    FindingType type{FindingType::CoverageLimitation};
    Severity severity{Severity::Info};
    Confidence confidence{Confidence::Low};
    RiskLevel risk{RiskLevel::High};

    std::string title;
    std::vector<std::string> confirmed_facts;   // things we directly measured
    std::string likely_explanation;             // interpretation, clearly NOT a measured fact
    std::vector<std::string> limitations;       // what we could not see / may be wrong
    std::string recommended_next_step;          // guidance only, never an automatic action

    uint64_t related_bytes{0};
    std::vector<ProcessRef> process_refs;       // for DeletedOpenFile findings
    std::string evidence_json;                  // ready for SQLite findings.evidence_json
    int64_t created_at_epoch_sec{0};
};

/**
 * @brief Everything the UI / database needs from one analysis run.
 */
struct AnalysisResult {
    DiscrepancyReport report;
    std::vector<Finding> findings;  // sorted: severity desc, then related_bytes desc
};

} // namespace ghostdisk