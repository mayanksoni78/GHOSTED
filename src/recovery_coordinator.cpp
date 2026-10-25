#include "ghostdisk/recovery_coordinator.hpp"
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <iostream>
#include <algorithm>

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#elif defined(_WIN32)
#include <sys/types.h>
#include <sys/stat.h>
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

std::string expand_user_home(const std::string& path) {
    if (path.empty() || path[0] != '~') {
        return path;
    }
    const char* home = std::getenv("HOME");
#if defined(_WIN32)
    if (!home) home = std::getenv("USERPROFILE");
#endif
    if (!home) return path;

    if (path == "~") {
        return std::string(home);
    }
    if (path.length() >= 2 && (path[1] == '/' || path[1] == '\\')) {
        return std::string(home) + path.substr(1);
    }
    return path;
}

} // namespace

std::vector<std::string> RecoveryCoordinator::default_approved_roots() {
    std::vector<std::string> roots;

    std::string home_cache = expand_user_home("~/.cache/ghostdisk_test");
    roots.push_back(canonicalize_path(home_cache));

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
    roots.push_back(canonicalize_path("/tmp/ghostdisk_test"));
#elif defined(_WIN32)
    const char* temp_env = std::getenv("TEMP");
    if (!temp_env) temp_env = std::getenv("TMP");
    if (temp_env) {
        roots.push_back(canonicalize_path(std::string(temp_env) + "/ghostdisk_test"));
    } else {
        roots.push_back(canonicalize_path("C:/temp/ghostdisk_test"));
    }
#endif

    return roots;
}

RecoveryCoordinator::RecoveryCoordinator(std::vector<std::string> approved_roots) {
    if (approved_roots.empty()) {
        approved_roots_ = default_approved_roots();
    } else {
        for (const auto& r : approved_roots) {
            approved_roots_.push_back(canonicalize_path(r));
        }
    }
}

std::string RecoveryCoordinator::canonicalize_path(const std::string& path) {
    std::string expanded = expand_user_home(path);
    if (expanded.empty()) return "";

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
    char resolved[PATH_MAX];
    if (::realpath(expanded.c_str(), resolved) != nullptr) {
        return normalize_slashes(resolved);
    }
    // If path does not exist yet (e.g. prospective directory), normalize string
    return normalize_slashes(expanded);
#elif defined(_WIN32)
    char resolved[MAX_PATH];
    if (GetFullPathNameA(expanded.c_str(), MAX_PATH, resolved, nullptr) != 0) {
        return normalize_slashes(resolved);
    }
    return normalize_slashes(expanded);
#else
    return normalize_slashes(expanded);
#endif
}

bool RecoveryCoordinator::is_path_allowlisted(const std::string& path, std::string* out_canonical) const {
    std::string canon = canonicalize_path(path);
    if (out_canonical) {
        *out_canonical = canon;
    }

    if (canon.empty()) return false;

    for (const auto& root : approved_roots_) {
        std::string canon_root = normalize_slashes(root);
        if (canon_root.empty()) continue;

        // Ensure root prefix checking has trailing slash for exact directory containment
        std::string root_prefix = canon_root;
        if (root_prefix.back() != '/') {
            root_prefix += "/";
        }

        // Must be strictly INSIDE the directory, not the root directory itself
        if (canon.length() > root_prefix.length() && canon.rfind(root_prefix, 0) == 0) {
            return true;
        }
    }

    return false;
}

RecoveryPreview RecoveryCoordinator::create_preview(const std::string& target_path) const {
    RecoveryPreview preview;
    preview.target_path = target_path;
    preview.is_valid = false;

    // Check allowlist status first
    preview.is_allowlisted = is_path_allowlisted(target_path, &preview.canonical_path);

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
    struct stat st;
    if (::lstat(target_path.c_str(), &st) != 0) {
        preview.error_message = std::string("Target file stat failed: ") + std::strerror(errno);
        preview.risk_level = RiskLevel::High;
        return preview;
    }

    // Safety: Reject directory removal
    if (S_ISDIR(st.st_mode)) {
        preview.error_message = "Target is a directory. Directory deletion is rejected for safety.";
        preview.risk_level = RiskLevel::High;
        return preview;
    }

    // Safety: Reject symlinks to avoid symlink traversal / redirection attacks
    if (S_ISLNK(st.st_mode)) {
        preview.error_message = "Target is a symlink. Symlink deletion is rejected for safety.";
        preview.risk_level = RiskLevel::High;
        return preview;
    }

    preview.target_device_id = static_cast<uint64_t>(st.st_dev);
    preview.target_inode = static_cast<uint64_t>(st.st_ino);
    preview.target_mtime_epoch_sec = static_cast<int64_t>(st.st_mtime);
    preview.target_apparent_bytes = static_cast<uint64_t>(st.st_size);
    preview.estimated_reclaimable_bytes = static_cast<uint64_t>(st.st_blocks) * 512;

#elif defined(_WIN32)
    struct _stati64 st;
    if (_stati64(target_path.c_str(), &st) != 0) {
        preview.error_message = "Target file stat failed: file not found or inaccessible";
        preview.risk_level = RiskLevel::High;
        return preview;
    }

    if (st.st_mode & _S_IFDIR) {
        preview.error_message = "Target is a directory. Directory deletion is rejected for safety.";
        preview.risk_level = RiskLevel::High;
        return preview;
    }

    preview.target_device_id = static_cast<uint64_t>(st.st_dev);
    preview.target_inode = static_cast<uint64_t>(st.st_ino);
    preview.target_mtime_epoch_sec = static_cast<int64_t>(st.st_mtime);
    preview.target_apparent_bytes = static_cast<uint64_t>(st.st_size);
    preview.estimated_reclaimable_bytes = static_cast<uint64_t>(st.st_size);
#endif

    if (!preview.is_allowlisted) {
        preview.risk_level = RiskLevel::High;
        preview.warning = "Target path is OUTSIDE the approved safe recovery allowlist roots. Automated removal prohibited.";
        preview.action_description = "Unlink denied: target not allowlisted.";
        preview.is_valid = true;
        return preview;
    }

    preview.risk_level = RiskLevel::Low;
    preview.action_description = "Safe unlink of validated allowlisted regular file.";
    preview.is_valid = true;
    return preview;
}

VerificationResult RecoveryCoordinator::execute_recovery(
    const RecoveryPreview& preview,
    bool user_confirmed
) {
    // 1. Enforce explicit consent
    if (!user_confirmed) {
        return VerificationService::verify(
            preview.target_path,
            FsSnapshot{},
            preview.estimated_reclaimable_bytes,
            false,
            "Explicit user confirmation was not provided (user_confirmed == false)."
        );
    }

    // 2. Validate preview state
    if (!preview.is_valid) {
        return VerificationService::verify(
            preview.target_path,
            FsSnapshot{},
            preview.estimated_reclaimable_bytes,
            false,
            "Cannot execute recovery on an invalid preview: " + preview.error_message
        );
    }

    // 3. Enforce strict allowlist policy
    if (!preview.is_allowlisted || preview.risk_level != RiskLevel::Low) {
        return VerificationService::verify(
            preview.target_path,
            FsSnapshot{},
            preview.estimated_reclaimable_bytes,
            false,
            "Execution blocked: target path is not in the approved allowlist or has high risk level."
        );
    }

    // 4. Capture capacity snapshot immediately before unlinking
    FsSnapshot before_snapshot = VerificationService::capture_snapshot_for_path(preview.target_path);

    // 5. TOCTOU Defense: Immediate revalidation before action
#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
    struct stat st;
    if (::lstat(preview.target_path.c_str(), &st) != 0) {
        return VerificationService::verify(
            preview.target_path,
            before_snapshot,
            preview.estimated_reclaimable_bytes,
            false,
            "TOCTOU abort: target file disappeared or became inaccessible before execution."
        );
    }

    if (S_ISLNK(st.st_mode)) {
        return VerificationService::verify(
            preview.target_path,
            before_snapshot,
            preview.estimated_reclaimable_bytes,
            false,
            "TOCTOU abort: target was replaced by a symlink after preview generation."
        );
    }

    if (static_cast<uint64_t>(st.st_dev) != preview.target_device_id) {
        return VerificationService::verify(
            preview.target_path,
            before_snapshot,
            preview.estimated_reclaimable_bytes,
            false,
            "TOCTOU abort: target device ID changed unexpectedly."
        );
    }

    if (static_cast<uint64_t>(st.st_ino) != preview.target_inode) {
        return VerificationService::verify(
            preview.target_path,
            before_snapshot,
            preview.estimated_reclaimable_bytes,
            false,
            "TOCTOU abort: target inode changed (file was swapped or replaced)."
        );
    }

    if (static_cast<int64_t>(st.st_mtime) != preview.target_mtime_epoch_sec) {
        return VerificationService::verify(
            preview.target_path,
            before_snapshot,
            preview.estimated_reclaimable_bytes,
            false,
            "TOCTOU abort: target modification time changed (file modified after preview generation)."
        );
    }

    if (static_cast<uint64_t>(st.st_size) != preview.target_apparent_bytes) {
        return VerificationService::verify(
            preview.target_path,
            before_snapshot,
            preview.estimated_reclaimable_bytes,
            false,
            "TOCTOU abort: target size changed after preview generation."
        );
    }

    // 6. Direct POSIX safe unlink (zero shell execution)
    if (::unlink(preview.target_path.c_str()) != 0) {
        return VerificationService::verify(
            preview.target_path,
            before_snapshot,
            preview.estimated_reclaimable_bytes,
            false,
            std::string("Direct unlink failed: ") + std::strerror(errno)
        );
    }

#elif defined(_WIN32)
    struct _stati64 st;
    if (_stati64(preview.target_path.c_str(), &st) != 0) {
        return VerificationService::verify(
            preview.target_path,
            before_snapshot,
            preview.estimated_reclaimable_bytes,
            false,
            "TOCTOU abort: target file disappeared before execution."
        );
    }

    if (static_cast<uint64_t>(st.st_ino) != preview.target_inode ||
        static_cast<int64_t>(st.st_mtime) != preview.target_mtime_epoch_sec ||
        static_cast<uint64_t>(st.st_size) != preview.target_apparent_bytes) {
        return VerificationService::verify(
            preview.target_path,
            before_snapshot,
            preview.estimated_reclaimable_bytes,
            false,
            "TOCTOU abort: target file metadata changed after preview."
        );
    }

    if (DeleteFileA(preview.target_path.c_str()) == 0) {
        return VerificationService::verify(
            preview.target_path,
            before_snapshot,
            preview.estimated_reclaimable_bytes,
            false,
            "DeleteFileA failed."
        );
    }
#endif

    // 7. Post-action verification and audit logging
    return VerificationService::verify(
        preview.target_path,
        before_snapshot,
        preview.estimated_reclaimable_bytes,
        true
    );
}

} // namespace ghostdisk
