#pragma once

#include "ghostdisk/types.hpp"
#include <string>
#include <cstdint>

namespace ghostdisk {

/**
 * @brief Observed results of an attempted recovery action and post-action capacity verification.
 *
 * Implements the core principle: never overclaim that 100% of a file's allocated size
 * was freed. Instead, measure available bytes before and after, compute the observed delta,
 * and record any concurrent filesystem factors in the audit log.
 */
struct VerificationResult {
    bool success{false};
    std::string target_path;
    std::string mount_point;
    uint64_t available_bytes_before{0};
    uint64_t available_bytes_after{0};
    int64_t observed_delta_bytes{0};      // available_bytes_after - available_bytes_before (signed)
    uint64_t estimated_reclaimable_bytes{0};
    std::string audit_log_message;
    std::string error_message;
    int64_t timestamp_epoch_sec{0};
};

class VerificationService {
public:
    /**
     * @brief Captures a filesystem capacity snapshot for the volume hosting the given target path.
     */
    static FsSnapshot capture_snapshot_for_path(const std::string& path);

    /**
     * @brief Performs post-unlink verification by sampling available capacity after the action,
     * computing the observed delta, and synthesizing an evidence-based audit log message.
     */
    static VerificationResult verify(
        const std::string& target_path,
        const FsSnapshot& before_snapshot,
        uint64_t estimated_reclaimable_bytes,
        bool operation_succeeded,
        const std::string& operation_error = ""
    );

    /**
     * @brief Resolves the canonical mount point containing the given target path.
     */
    static std::string resolve_mount_point(const std::string& path);
};

} // namespace ghostdisk
