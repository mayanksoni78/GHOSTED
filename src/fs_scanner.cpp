#include "ghostdisk/fs_scanner.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <cerrno>

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
#include <sys/statvfs.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

namespace ghostdisk {

FsSnapshot FsScanner::scan_mount(const std::string& target_path) {
    FsSnapshot snapshot;
    snapshot.mount_point = target_path;
    snapshot.sampled_at_epoch_sec = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
    struct statvfs vfs;
    if (::statvfs(target_path.c_str(), &vfs) != 0) {
        snapshot.success = false;
        snapshot.error_message = std::string("statvfs failed: ") + std::strerror(errno);
        return snapshot;
    }

    uint64_t frsize = (vfs.f_frsize > 0) ? vfs.f_frsize : vfs.f_bsize;
    snapshot.block_size = frsize;
    snapshot.total_bytes = static_cast<uint64_t>(vfs.f_blocks) * frsize;
    snapshot.raw_free_bytes = static_cast<uint64_t>(vfs.f_bfree) * frsize;
    snapshot.available_bytes = static_cast<uint64_t>(vfs.f_bavail) * frsize;

    if (snapshot.total_bytes >= snapshot.raw_free_bytes) {
        snapshot.used_bytes = snapshot.total_bytes - snapshot.raw_free_bytes;
    } else {
        snapshot.used_bytes = 0;
    }

    if (snapshot.raw_free_bytes >= snapshot.available_bytes) {
        snapshot.reserved_or_unavailable_bytes = snapshot.raw_free_bytes - snapshot.available_bytes;
    } else {
        snapshot.reserved_or_unavailable_bytes = 0;
    }

    snapshot.success = true;

    // Resolve device_name and filesystem_type from system mount table
    auto mounts = discover_mounts(true);
    std::string best_mount;
    for (const auto& m : mounts) {
        if (m.mount_point == target_path) {
            snapshot.device_name = m.device_name;
            snapshot.filesystem_type = m.filesystem_type;
            best_mount = m.mount_point;
            break;
        }
        // Match longest matching prefix if not exact
        if (target_path.rfind(m.mount_point, 0) == 0 && m.mount_point.length() > best_mount.length()) {
            best_mount = m.mount_point;
            snapshot.device_name = m.device_name;
            snapshot.filesystem_type = m.filesystem_type;
        }
    }

    if (snapshot.device_name.empty()) {
        snapshot.device_name = "Root Storage";
    }
    if (snapshot.filesystem_type.empty()) {
        snapshot.filesystem_type = "ext4";
    }

#elif defined(_WIN32)
    ULARGE_INTEGER free_bytes_available, total_bytes, total_free_bytes;
    BOOL res = GetDiskFreeSpaceExA(
        target_path.c_str(),
        &free_bytes_available,
        &total_bytes,
        &total_free_bytes
    );

    if (!res) {
        snapshot.success = false;
        snapshot.error_message = "GetDiskFreeSpaceExA failed";
        return snapshot;
    }

    snapshot.block_size = 4096;
    snapshot.total_bytes = total_bytes.QuadPart;
    snapshot.raw_free_bytes = total_free_bytes.QuadPart;
    snapshot.available_bytes = free_bytes_available.QuadPart;
    snapshot.used_bytes = (snapshot.total_bytes >= snapshot.raw_free_bytes)
        ? (snapshot.total_bytes - snapshot.raw_free_bytes) : 0;
    snapshot.reserved_or_unavailable_bytes = (snapshot.raw_free_bytes >= snapshot.available_bytes)
        ? (snapshot.raw_free_bytes - snapshot.available_bytes) : 0;
    snapshot.success = true;
#endif

    return snapshot;
}

std::vector<MountInfo> FsScanner::discover_mounts(bool include_pseudo_fs) {
    std::vector<MountInfo> mounts;

#if defined(__linux__)
    std::ifstream file("/proc/mounts");
    if (!file.is_open()) {
        file.open("/etc/mtab");
    }

    if (!file.is_open()) {
        return mounts;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }

        std::istringstream iss(line);
        std::string dev, mount_pt, fs_type, opts;
        if (!(iss >> dev >> mount_pt >> fs_type >> opts)) {
            continue;
        }

        if (!include_pseudo_fs) {
            // Filter common pseudo and virtual filesystems
            if (fs_type == "sysfs" || fs_type == "proc" || fs_type == "devpts" ||
                fs_type == "devtmpfs" || fs_type == "cgroup" || fs_type == "cgroup2" ||
                fs_type == "pstore" || fs_type == "bpf" || fs_type == "autofs" ||
                fs_type == "tracefs" || fs_type == "hugetlbfs" || fs_type == "mqueue" ||
                fs_type == "debugfs" || fs_type == "securityfs" || fs_type == "fusectl" ||
                fs_type == "configfs" || fs_type == "ramfs" || fs_type == "binfmt_misc") {
                continue;
            }
        }

        MountInfo info;
        info.device_name = dev;
        info.mount_point = mount_pt;
        info.filesystem_type = fs_type;
        info.options = opts;
        mounts.push_back(info);
    }
#elif defined(_WIN32)
    // Fallback basic logical drive discovery on Windows
    DWORD drives = GetLogicalDrives();
    for (char c = 'A'; c <= 'Z'; ++c) {
        if (drives & (1 << (c - 'A'))) {
            std::string root = std::string(1, c) + ":\\";
            MountInfo info;
            info.device_name = root;
            info.mount_point = root;
            info.filesystem_type = "NTFS/FAT";
            info.options = "rw";
            mounts.push_back(info);
        }
    }
#endif

    return mounts;
}

std::string FsScanner::format_bytes(uint64_t bytes) {
    constexpr uint64_t KB = 1024ULL;
    constexpr uint64_t MB = KB * 1024ULL;
    constexpr uint64_t GB = MB * 1024ULL;
    constexpr uint64_t TB = GB * 1024ULL;

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);

    if (bytes >= TB) {
        oss << static_cast<double>(bytes) / TB << " TB";
    } else if (bytes >= GB) {
        oss << static_cast<double>(bytes) / GB << " GB";
    } else if (bytes >= MB) {
        oss << static_cast<double>(bytes) / MB << " MB";
    } else if (bytes >= KB) {
        oss << static_cast<double>(bytes) / KB << " KB";
    } else {
        oss << bytes << " B";
    }

    return oss.str();
}

} // namespace ghostdisk
