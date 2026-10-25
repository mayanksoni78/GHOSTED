#pragma once

#include "ghostdisk/analysis_types.hpp"
#include "ghostdisk/verification_service.hpp"
#include <string>
#include <vector>
#include <cstdint>

namespace ghostdisk {

/**
 * @brief Preview metadata generated prior to any filesystem modification.
 * Read-only generation: never modifies any file or process.
 */
struct RecoveryPreview {
    bool is_valid{false};
    std::string target_path;
    std::string canonical_path;
    std::string action_description;
    RiskLevel risk_level{RiskLevel::High};
    bool is_allowlisted{false};
    uint64_t estimated_reclaimable_bytes{0};  // st_blocks * 512 (or size)
    uint64_t target_apparent_bytes{0};        // st_size
    uint64_t target_device_id{0};             // st_dev
    uint64_t target_inode{0};                 // st_ino
    int64_t target_mtime_epoch_sec{0};        // st_mtime
    std::string warning;
    std::string error_message;
};

/**
 * @brief The only component in GhostDisk permitted to mutate the filesystem.
 *
 * Enforces:
 * 1. Read-only by default (preview generation does not alter data).
 * 2. Strict allowlist validation using canonical path resolution to prevent directory traversal.
 * 3. Explicit operator confirmation requirement (user_confirmed == true).
 * 4. TOCTOU defense: revalidates device, inode, size, mtime, and non-symlink status immediately before unlink.
 * 5. Direct POSIX unlink without shell invocation (zero system('rm ...')).
 * 6. Post-action verification via VerificationService.
 */
class RecoveryCoordinator {
public:
    explicit RecoveryCoordinator(std::vector<std::string> approved_roots = {});

    /**
     * @brief Stage 1: Inspects target, validates allowlist, records identity and size.
     * Never mutates data.
     */
    RecoveryPreview create_preview(const std::string& target_path) const;

    /**
     * @brief Stage 2: Requires explicit user_confirmed == true.
     * Revalidates target identity (device, inode, size, mtime, non-symlink) immediately
     * before unlinking. Aborts on any TOCTOU discrepancy.
     * Verifies space delta via VerificationService.
     */
    VerificationResult execute_recovery(
        const RecoveryPreview& preview,
        bool user_confirmed
    );

    /**
     * @brief Checks if a path resides within one of the approved roots.
     * Resolves both the root and target to canonical paths to prevent '..' or symlink escape.
     */
    bool is_path_allowlisted(const std::string& path, std::string* out_canonical = nullptr) const;

    /**
     * @brief Returns the configured approved roots.
     */
    const std::vector<std::string>& approved_roots() const { return approved_roots_; }

    /**
     * @brief Default approved roots (~/.cache/ghostdisk_test/, /tmp/ghostdisk_test/).
     */
    static std::vector<std::string> default_approved_roots();

    /**
     * @brief Path canonicalization helper resolving symlinks and dot-dots.
     */
    static std::string canonicalize_path(const std::string& path);

private:
    std::vector<std::string> approved_roots_;
    VerificationService verification_service_;
};

} // namespace ghostdisk
