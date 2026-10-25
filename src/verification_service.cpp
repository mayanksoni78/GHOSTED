#include "ghostdisk/verification_service.hpp"
#include "ghostdisk/fs_scanner.hpp"
#include <chrono>
#include <sstream>
#include <algorithm>

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
#include <sys/stat.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

namespace ghostdisk {

namespace {

std::string normalize_slashes(const std::string& p) {
    std::string s = p;
    for (char& c : s) {
        if (c == '\\') c = '/';
    }
    while (s.size() > 1 && s.back() == '/') {
        s.pop_back();
    }
    return s;
}

} // namespace

std::string VerificationService::resolve_mount_point(const std::string& path) {
    std::string norm_path = normalize_slashes(path);
    FsScanner scanner;
    auto mounts = scanner.discover_mounts(true);
    
    std::string best_mount = "";
    size_t best_len = 0;

    for (const auto& m : mounts) {
        std::string m_pt = normalize_slashes(m.mount_point);
        if (m_pt == norm_path) {
            return m.mount_point;
        }

        if (m_pt == "/" || (norm_path.rfind(m_pt + "/", 0) == 0)) {
            if (m_pt.length() > best_len) {
                best_len = m_pt.length();
                best_mount = m.mount_point;
            }
        }
    }

    if (!best_mount.empty()) {
        return best_mount;
    }

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
    return "/";
#elif defined(_WIN32)
    if (norm_path.size() >= 2 && norm_path[1] == ':') {
        return norm_path.substr(0, 3);
    }
    return "C:\\";
#else
    return path;
#endif
}

FsSnapshot VerificationService::capture_snapshot_for_path(const std::string& path) {
    FsScanner scanner;
    std::string mount_pt = resolve_mount_point(path);
    FsSnapshot snapshot = scanner.scan_mount(mount_pt);
    if (!snapshot.success) {
        // Fallback: scan directly on the target path itself
        snapshot = scanner.scan_mount(path);
    }
    return snapshot;
}

VerificationResult VerificationService::verify(
    const std::string& target_path,
    const FsSnapshot& before_snapshot,
    uint64_t estimated_reclaimable_bytes,
    bool operation_succeeded,
    const std::string& operation_error
) {
    VerificationResult result;
    result.target_path = target_path;
    result.mount_point = before_snapshot.mount_point;
    result.available_bytes_before = before_snapshot.available_bytes;
    result.estimated_reclaimable_bytes = estimated_reclaimable_bytes;
    result.timestamp_epoch_sec = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    if (!operation_succeeded) {
        result.success = false;
        result.error_message = operation_error;
        result.available_bytes_after = before_snapshot.available_bytes;
        result.observed_delta_bytes = 0;
        result.audit_log_message = "Recovery failed for '" + target_path + "': " + operation_error;
        return result;
    }

    // Re-sample filesystem capacity after the unlink action
    FsSnapshot after_snapshot = capture_snapshot_for_path(target_path);
    if (!after_snapshot.success && !before_snapshot.mount_point.empty()) {
        FsScanner scanner;
        after_snapshot = scanner.scan_mount(before_snapshot.mount_point);
    }

    result.available_bytes_after = after_snapshot.success ? after_snapshot.available_bytes : before_snapshot.available_bytes;
    result.observed_delta_bytes = static_cast<int64_t>(result.available_bytes_after) - static_cast<int64_t>(result.available_bytes_before);
    result.success = true;

    std::ostringstream oss;
    oss << "Action: Unlinked '" << target_path << "'. "
        << "Estimated size: " << FsScanner::format_bytes(estimated_reclaimable_bytes) << ". "
        << "Observed available delta: " << result.observed_delta_bytes << " B ("
        << (result.observed_delta_bytes >= 0 ? "+" : "")
        << FsScanner::format_bytes(result.observed_delta_bytes >= 0 ? result.observed_delta_bytes : -result.observed_delta_bytes)
        << ").";

    if (result.observed_delta_bytes <= 0 && estimated_reclaimable_bytes > 0) {
        oss << " Note: Available space did not immediately increase; filesystem blocks may still be retained by open descriptors, delayed allocation, or concurrent writes.";
    }

    result.audit_log_message = oss.str();
    return result;
}

} // namespace ghostdisk
