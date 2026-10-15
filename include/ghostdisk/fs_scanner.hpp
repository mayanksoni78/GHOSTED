#pragma once

#include "ghostdisk/types.hpp"
#include <string>
#include <vector>

namespace ghostdisk {

class FsScanner {
public:
    FsScanner() = default;
    ~FsScanner() = default;

    /**
     * @brief Reads filesystem storage metrics for the specified mount path or file path.
     * Uses statvfs() on Linux.
     * 
     * @param target_path Path on the filesystem (e.g., "/" or "/home").
     * @return FsSnapshot Populated filesystem storage snapshot.
     */
    FsSnapshot scan_mount(const std::string& target_path);

    /**
     * @brief Discovers currently mounted filesystems by inspecting /proc/mounts.
     * Filters out pseudofs (proc, sysfs, devpts, etc.) by default.
     * 
     * @param include_pseudo_fs If true, includes virtual/pseudo filesystems.
     * @return std::vector<MountInfo> List of detected mounts.
     */
    std::vector<MountInfo> discover_mounts(bool include_pseudo_fs = false);

    /**
     * @brief Formats raw bytes into human-readable strings (B, KB, MB, GB, TB).
     */
    static std::string format_bytes(uint64_t bytes);
};

} // namespace ghostdisk
