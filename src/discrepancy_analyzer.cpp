#include "ghostdisk/discrepancy_analyzer.hpp"
#include "ghostdisk/fs_scanner.hpp"

#include <algorithm>
#include <ctime>
#include <limits>
#include <sys/stat.h>

using namespace std;

namespace ghostdisk {

using std::to_string;

namespace {

string normalize_path(string p) {
    while (p.size() > 1 && p.back() == '/') p.pop_back();
    return p;
}

bool starts_with(const string& s, const string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

// a - b as a signed value, clamped so it can never overflow.
int64_t signed_diff(uint64_t a, uint64_t b) {
    const uint64_t kMax = static_cast<uint64_t>(numeric_limits<int64_t>::max());
    if (a >= b) {
        const uint64_t d = a - b;
        return d > kMax ? numeric_limits<int64_t>::max() : static_cast<int64_t>(d);
    }
    const uint64_t d = b - a;
    return d > kMax ? numeric_limits<int64_t>::min() : -static_cast<int64_t>(d);
}

bool lookup_device_id(const string& path, uint64_t& out) {
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0) return false;
    out = static_cast<uint64_t>(st.st_dev);
    return true;
}

} // namespace

ScanScope DiscrepancyAnalyzer::classify_scope(const string& mount_point,
                                              const string& scan_root) {
    if (mount_point.empty() || scan_root.empty()) return ScanScope::Unknown;

    const string m = normalize_path(mount_point);
    const string r = normalize_path(scan_root);

    if (r == m) return ScanScope::WholeMount;

    if (m == "/") {
        return (r.front() == '/') ? ScanScope::PartOfMount : ScanScope::Unknown;
    }
    if (starts_with(r, m + "/")) return ScanScope::PartOfMount;
    return ScanScope::OutsideMount;
}

DiscrepancyReport DiscrepancyAnalyzer::analyze(
    const FsSnapshot& fs,
    const DirectoryScanResult& scan,
    const ScanOptions& scan_options,
    const ProcScanResult& proc,
    const AnalyzerConfig& config,
    optional<uint64_t> mount_device_id)
{
    DiscrepancyReport r;
    r.analyzed_at_epoch_sec = config.now_epoch_sec != 0
        ? config.now_epoch_sec
        : static_cast<int64_t>(time(nullptr));

    // ---- 1. Without a filesystem snapshot there is nothing to analyze -------------
    if (!fs.success) {
        r.valid = false;
        r.invalid_reason = "Filesystem measurement is unavailable: " +
                           (fs.error_message.empty() ? string("unknown error") : fs.error_message);
        return r;
    }

    r.valid = true;
    r.mount_point = fs.mount_point;
    r.scan_root = scan.root_path;
    r.fs_used_bytes = fs.used_bytes;
    r.reserved_bytes = fs.reserved_or_unavailable_bytes;
    r.fs_sampled_at_epoch_sec = fs.sampled_at_epoch_sec;
    r.scan_allocated_bytes = scan.total_allocated_bytes;
    r.scan_ok = scan.success;
    r.scan_cancelled = scan.is_cancelled;
    r.skipped_count = scan.skipped_entries.size();
    r.proc_scan_ok = proc.success;
    r.restricted_pid_count = proc.restricted_pids.size();

    // ---- 2. Keep only deleted-open files that live on THIS filesystem -------------
    uint64_t dev = 0;
    if (bool(mount_device_id)) {
        dev = *mount_device_id;
        r.device_filter_applied = true;
    } else if (lookup_device_id(fs.mount_point, dev)) {
        r.device_filter_applied = true;
    }

    for (const auto& f : proc.findings) {
        if (r.device_filter_applied && f.device_id != dev) {
            ++r.deleted_open_other_mounts_count;
            continue;
        }
        r.deleted_open_on_mount.push_back(f);
        // Each finding is already deduplicated by (device, inode) by ProcInspector,
        // so summing here does not double-count a file held by several processes.
        r.deleted_open_bytes += f.deduplicated_allocated_bytes;
    }

    // ---- 3. Is the scan comparable with the filesystem totals? --------------------
    r.scope = classify_scope(fs.mount_point, scan.root_path);

    if (!scan.success) {
        r.comparable = false;
        r.scope_note = "The directory scan did not complete successfully" +
                       (scan.error_message.empty() ? string(".") : ": " + scan.error_message);
    } else if (scan.is_cancelled) {
        r.comparable = false;
        r.scope_note = "The scan was cancelled, so its total is incomplete and cannot be compared with the filesystem.";
    } else if (r.scope == ScanScope::PartOfMount) {
        r.comparable = false;
        r.scope_note = "Only a sub-folder (" + scan.root_path + ") of the filesystem mounted at " +
                       fs.mount_point + " was scanned. Filesystem usage covers the whole mount, "
                       "so the difference is not meaningful.";
    } else if (r.scope == ScanScope::OutsideMount) {
        r.comparable = false;
        r.scope_note = "The scanned folder (" + scan.root_path + ") is not on the measured mount (" +
                       fs.mount_point + ").";
    } else if (r.scope == ScanScope::Unknown) {
        r.comparable = false;
        r.scope_note = "The scan root or mount point is missing, so the scope cannot be compared.";
    } else if (scan_options.cross_device_boundaries) {
        r.comparable = false;
        r.scope_note = "The scan was allowed to cross into other filesystems, so its total may include "
                       "storage that does not belong to " + fs.mount_point + ".";
    } else {
        r.comparable = true;
        r.scope_note = "The whole mount " + fs.mount_point +
                       " was scanned without crossing into other filesystems, so the totals are comparable.";
    }

    // ---- 4. Compute the gap (only when comparable) --------------------------------
    r.tolerance_bytes = max<uint64_t>(
        config.tolerance_bytes,
        static_cast<uint64_t>(static_cast<double>(r.fs_used_bytes) * config.tolerance_fraction));

    if (r.comparable) {
        r.gap_bytes = signed_diff(r.fs_used_bytes, r.scan_allocated_bytes);

        if (r.gap_bytes > 0) {
            const uint64_t gap = static_cast<uint64_t>(r.gap_bytes);
            r.explained_bytes = min(gap, r.deleted_open_bytes);
            r.unresolved_bytes = gap - r.explained_bytes;
            r.unresolved_significant = r.unresolved_bytes > r.tolerance_bytes;
        } else if (r.gap_bytes < 0) {
            // magnitude of a negative value without overflow
            const uint64_t over = r.scan_allocated_bytes - r.fs_used_bytes;
            r.scan_exceeds_filesystem = over > r.tolerance_bytes;
        }
    }

    // ---- 5. Caveats (always honest about limits) ----------------------------------
    r.caveats.push_back(
        "Reserved space (" + FsScanner::format_bytes(r.reserved_bytes) +
        ") is part of the filesystem's free space, not its used space, so it is not part of this difference.");
    r.caveats.push_back(
        "Sizes are allocated bytes (st_blocks * 512). Hard links, sparse files, filesystem metadata, "
        "journals, snapshots and files changed during the scan can all cause small differences.");

    if (r.skipped_count > 0) {
        r.caveats.push_back(to_string(r.skipped_count) +
                            " path(s) could not be read during the scan; their size is missing from the scan total.");
    }
    if (r.restricted_pid_count > 0) {
        r.caveats.push_back(to_string(r.restricted_pid_count) +
                            " process(es) could not be inspected (permission denied); more deleted-open files may exist.");
    }
    if (!proc.success) {
        r.caveats.push_back("Process inspection failed" +
                            (proc.error_message.empty() ? string(".") : ": " + proc.error_message) +
                            " Deleted-open files could not be checked, so none are used to explain the difference.");
    }
    if (!r.device_filter_applied) {
        r.caveats.push_back("The device id of " + fs.mount_point +
                            " could not be determined, so deleted-open files from every filesystem are counted.");
    }
    if (r.deleted_open_other_mounts_count > 0) {
        r.caveats.push_back(to_string(r.deleted_open_other_mounts_count) +
                            " deleted-open file(s) are on other filesystems and were ignored for this mount.");
    }
    if (r.scan_cancelled) {
        r.caveats.push_back("The scan was cancelled before it finished.");
    }

    return r;
}

} // namespace ghostdisk
