#pragma once

#include "ghostdisk/types.hpp"
#include <string>
#include <vector>
#include <functional>
#include <atomic>

namespace ghostdisk {

class DirectoryScanner {
public:
    using ProgressCallback = std::function<void(const ScanProgress&)>;

    DirectoryScanner() = default;
    ~DirectoryScanner() = default;

    /**
     * @brief Performs an asynchronous-friendly crawl of a directory subtree.
     * Uses lstat() to guarantee symlinks are never followed recursively into directory trees.
     * Computes allocated blocks (st_blocks * 512) and apparent bytes (st_size).
     * 
     * @param root_path Directory path to crawl.
     * @param options Scanning options (mount boundaries, entry limits).
     * @param cancel_token Optional pointer to atomic boolean for early cancellation.
     * @param progress_cb Optional callback invoked periodically with progress metrics.
     * @return DirectoryScanResult Full summary of scan findings.
     */
    DirectoryScanResult scan(
        const std::string& root_path,
        const ScanOptions& options = ScanOptions{},
        const std::atomic<bool>* cancel_token = nullptr,
        ProgressCallback progress_cb = nullptr
    );

    /**
     * @brief Sorts entries by allocated bytes in descending order.
     */
    static void sort_entries_by_allocated_size(std::vector<DirectoryEntry>& entries);

    /**
     * @brief Sorts entries by apparent bytes in descending order.
     */
    static void sort_entries_by_apparent_size(std::vector<DirectoryEntry>& entries);

private:
    void crawl_recursive(
        const std::string& current_path,
        uint64_t root_device_id,
        const ScanOptions& options,
        const std::atomic<bool>* cancel_token,
        ProgressCallback& progress_cb,
        DirectoryScanResult& result,
        ScanProgress& progress
    );
};

} // namespace ghostdisk
