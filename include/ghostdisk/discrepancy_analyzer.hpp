#pragma once

#include "ghostdisk/analysis_types.hpp"
#include <cstdint>
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
 * @brief Compares filesystem totals with a directory scan and explains the gap.
 *
 * Pure logic: reads the structs produced by Member 1 and Member 2, touches no
 * files (except one optional stat() of the mount point to learn its device id),
 * and never deletes anything.
 */
class DiscrepancyAnalyzer {
public:
    /**
     * @param fs               Snapshot of ONE mount (FsScanner::scan_mount).
     * @param scan             Result of crawling a folder (DirectoryScanner::scan).
     * @param scan_options     Options used for that crawl (needed for the mount-boundary policy).
     * @param proc             Result of ProcInspector::scan.
     * @param config           Thresholds.
     * @param mount_device_id  st_dev of the mount. If omitted, the analyzer stat()s
     *                         fs.mount_point itself. If that also fails, deleted-open
     *                         files from all filesystems are counted and a caveat is added.
     */
    static DiscrepancyReport analyze(
        const FsSnapshot& fs,
        const DirectoryScanResult& scan,
        const ScanOptions& scan_options,
        const ProcScanResult& proc,
        const AnalyzerConfig& config = AnalyzerConfig{},
        optional<uint64_t> mount_device_id = nullopt
    );

    /**
     * @brief Purely textual comparison of two paths (no filesystem access).
     * Trailing slashes are ignored. Symlinks are NOT resolved.
     */
    static ScanScope classify_scope(const std::string& mount_point, const std::string& scan_root);
};

} // namespace ghostdisk
