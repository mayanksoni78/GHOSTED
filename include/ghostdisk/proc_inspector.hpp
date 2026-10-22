#pragma once

#include "ghostdisk/types.hpp"
#include <string>
#include <vector>
#include <functional>
#include <atomic>

namespace ghostdisk {

/**
 * @brief Configuration options for process inspection.
 */
struct ProcScanOptions {
    std::string proc_root{"/proc"};  // Configurable procfs root (e.g., for mock tests)
    bool resolve_user_names{true};   // Look up usernames via system user database
};

/**
 * @brief Live progress metrics reported during process inspection.
 */
struct ProcScanProgress {
    uint64_t pids_scanned{0};
    uint64_t open_fds_inspected{0};
    uint64_t deleted_files_found{0};
    uint64_t restricted_pids_count{0};
    int64_t current_pid{0};
};

/**
 * @brief Linux Process Detective and Inode Inspector.
 * 
 * Inspects running processes under /proc to discover unlinked (deleted) files
 * that remain open via file descriptors, holding physical disk storage.
 * Deduplicates findings by (device_id, inode) so shared descriptors across
 * processes are not double-counted.
 */
class ProcInspector {
public:
    using ProgressCallback = std::function<void(const ProcScanProgress&)>;

    ProcInspector() = default;
    ~ProcInspector() = default;

    /**
     * @brief Performs a full scan of all numeric process directories in procfs.
     * 
     * @param options Scan configuration options (proc root path, username resolution).
     * @param cancel_token Optional pointer to atomic boolean for cooperative cancellation.
     * @param progress_cb Optional callback invoked periodically with progress metrics.
     * @return ProcScanResult Deduplicated findings, restricted PIDs, and reclaimable bytes.
     */
    ProcScanResult scan(
        const ProcScanOptions& options = ProcScanOptions{},
        const std::atomic<bool>* cancel_token = nullptr,
        ProgressCallback progress_cb = nullptr
    );

    /**
     * @brief Inspects open file descriptors for a specific PID.
     * 
     * @param pid Target process ID.
     * @param proc_root Root path to procfs (default: "/proc").
     * @param resolve_user_names Whether to look up the username.
     * @param out_is_restricted Output flag set to true if access to /proc/<pid>/fd was denied.
     * @return std::vector<ProcessRef> All deleted file descriptor references found for this process.
     */
    std::vector<ProcessRef> inspect_process(
        int64_t pid,
        const std::string& proc_root = "/proc",
        bool resolve_user_names = true,
        bool* out_is_restricted = nullptr
    );

    /**
     * @brief Deduplicates raw process references by (device_id, inode).
     * Multiple processes holding the same deleted file are grouped into a single
     * finding, counting its allocated storage only once.
     * 
     * @param raw_refs List of raw ProcessRef entries.
     * @param out_total_reclaimable_bytes Output sum of deduplicated allocated bytes.
     * @return std::vector<DeletedOpenFileFinding> Aggregated findings.
     */
    static std::vector<DeletedOpenFileFinding> deduplicate_findings(
        const std::vector<ProcessRef>& raw_refs,
        uint64_t& out_total_reclaimable_bytes
    );

    /**
     * @brief Checks if a symlink target string ends with the exact suffix " (deleted)".
     * If so, extracts the original unlinked filepath.
     * 
     * @param target Target string returned from readlink().
     * @param out_original_path Target string with " (deleted)" suffix removed.
     * @return true if target ended with " (deleted)", false otherwise.
     */
    static bool parse_deleted_target(const std::string& target, std::string& out_original_path);

    /**
     * @brief Checks if a string consists entirely of ASCII digits (a valid PID folder name).
     */
    static bool is_numeric_pid(const std::string& name);
};

} // namespace ghostdisk
