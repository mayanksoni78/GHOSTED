#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <chrono>

namespace ghostdisk {

/**
 * @brief Represents the filesystem object type.
 */
enum class EntryType {
    File,
    Directory,
    Symlink,
    Fifo,
    Socket,
    BlockDevice,
    CharDevice,
    Other
};

inline std::string entry_type_to_string(EntryType type) {
    switch (type) {
        case EntryType::File: return "File";
        case EntryType::Directory: return "Directory";
        case EntryType::Symlink: return "Symlink";
        case EntryType::Fifo: return "FIFO";
        case EntryType::Socket: return "Socket";
        case EntryType::BlockDevice: return "BlockDevice";
        case EntryType::CharDevice: return "CharDevice";
        default: return "Other";
    }
}

/**
 * @brief Recorded entry information for crawled files/directories.
 */
struct DirectoryEntry {
    std::string path;
    std::string name;
    EntryType entry_type{EntryType::Other};
    uint64_t apparent_bytes{0};    // st_size
    uint64_t allocated_bytes{0};   // st_blocks * 512
    uint64_t device_id{0};         // st_dev
    uint64_t inode{0};             // st_ino
    int64_t mtime_epoch_sec{0};    // st_mtime
};

/**
 * @brief Information about paths that could not be scanned (e.g. permission denied).
 */
struct SkippedPath {
    std::string path;
    std::string reason;
    int error_code{0};
};

/**
 * @brief Snapshot of filesystem-level storage capacity (statvfs telemetry).
 */
struct FsSnapshot {
    std::string mount_point;
    std::string device_name;
    std::string filesystem_type;
    uint64_t total_bytes{0};                      // f_blocks * f_frsize
    uint64_t raw_free_bytes{0};                  // f_bfree * f_frsize
    uint64_t available_bytes{0};                 // f_bavail * f_frsize (available to non-root)
    uint64_t used_bytes{0};                      // total_bytes - raw_free_bytes
    uint64_t reserved_or_unavailable_bytes{0};   // raw_free_bytes - available_bytes
    uint64_t block_size{0};                      // f_frsize
    int64_t sampled_at_epoch_sec{0};
    bool success{false};
    std::string error_message;
};

/**
 * @brief Mount point basic info discovered from system mounts.
 */
struct MountInfo {
    std::string mount_point;
    std::string device_name;
    std::string filesystem_type;
    std::string options;
};

/**
 * @brief Configuration options for directory crawling.
 */
struct ScanOptions {
    bool cross_device_boundaries{false}; // Prevent crossing into other mounts
    bool collect_all_entries{true};      // If false, only aggregates totals and top entries
    size_t top_entries_limit{100};       // Limit ranked large entries in memory
};

/**
 * @brief Progress metrics reported during scans.
 */
struct ScanProgress {
    uint64_t entries_scanned{0};
    uint64_t total_apparent_bytes{0};
    uint64_t total_allocated_bytes{0};
    uint64_t skipped_count{0};
    std::string current_path;
};

/**
 * @brief Cumulative results from crawling a directory subtree.
 */
struct DirectoryScanResult {
    std::string root_path;
    uint64_t total_apparent_bytes{0};
    uint64_t total_allocated_bytes{0};
    uint64_t files_count{0};
    uint64_t dirs_count{0};
    std::vector<DirectoryEntry> entries;
    std::vector<SkippedPath> skipped_entries;
    bool is_cancelled{false};
    int64_t scan_duration_ms{0};
    bool success{false};
    std::string error_message;
};

/**
 * @brief Reference to a process holding an open file descriptor.
 */
struct ProcessRef {
    int64_t pid{0};
    std::string process_name;
    std::string user_name;
    int fd{-1};
    std::string target_hint;
    uint64_t device_id{0};         // st_dev
    uint64_t inode{0};             // st_ino
    uint64_t apparent_bytes{0};    // st_size
    uint64_t allocated_bytes{0};   // st_blocks * 512
};

/**
 * @brief Aggregated finding for a deleted file held open by one or more processes.
 */
struct DeletedOpenFileFinding {
    uint64_t inode{0};
    uint64_t device_id{0};
    std::string original_path;
    uint64_t deduplicated_allocated_bytes{0};
    uint64_t apparent_bytes{0};
    std::vector<ProcessRef> holding_processes;
};

/**
 * @brief Cumulative results from scanning processes for deleted-but-open file descriptors.
 */
struct ProcScanResult {
    std::vector<DeletedOpenFileFinding> findings;
    std::vector<int64_t> restricted_pids;
    uint64_t total_reclaimable_bytes{0};
    int64_t scan_duration_ms{0};
    bool is_cancelled{false};
    bool success{false};
    std::string error_message;
};

} // namespace ghostdisk
