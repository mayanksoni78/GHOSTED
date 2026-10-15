#include "ghostdisk/directory_scanner.hpp"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <cerrno>

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <sys/types.h>
#include <sys/stat.h>
#include <windows.h>
#endif

namespace ghostdisk {

namespace {

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
EntryType determine_entry_type(const struct stat& st) {
    if (S_ISREG(st.st_mode)) return EntryType::File;
    if (S_ISDIR(st.st_mode)) return EntryType::Directory;
    if (S_ISLNK(st.st_mode)) return EntryType::Symlink;
    if (S_ISFIFO(st.st_mode)) return EntryType::Fifo;
    if (S_ISSOCK(st.st_mode)) return EntryType::Socket;
    if (S_ISBLK(st.st_mode)) return EntryType::BlockDevice;
    if (S_ISCHR(st.st_mode)) return EntryType::CharDevice;
    return EntryType::Other;
}
#elif defined(_WIN32)
EntryType determine_entry_type(const struct _stat64& st) {
    if (st.st_mode & _S_IFREG) return EntryType::File;
    if (st.st_mode & _S_IFDIR) return EntryType::Directory;
    return EntryType::Other;
}
#endif

std::string join_paths(const std::string& parent, const std::string& child) {
    if (parent.empty()) return child;
    char last = parent.back();
#if defined(_WIN32)
    if (last == '/' || last == '\\') {
        return parent + child;
    }
    return parent + "/" + child;
#else
    if (last == '/') {
        return parent + child;
    }
    return parent + "/" + child;
#endif
}

} // anonymous namespace

DirectoryScanResult DirectoryScanner::scan(
    const std::string& root_path,
    const ScanOptions& options,
    const std::atomic<bool>* cancel_token,
    ProgressCallback progress_cb
) {
    auto start_time = std::chrono::steady_clock::now();

    DirectoryScanResult result;
    result.root_path = root_path;
    result.is_cancelled = false;
    result.success = false;

    ScanProgress progress;
    progress.entries_scanned = 0;
    progress.total_apparent_bytes = 0;
    progress.total_allocated_bytes = 0;
    progress.skipped_count = 0;
    progress.current_path = root_path;

    uint64_t root_device_id = 0;

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
    struct stat root_st;
    if (::lstat(root_path.c_str(), &root_st) != 0) {
        result.error_message = std::string("Cannot inspect root path: ") + std::strerror(errno);
        SkippedPath skipped;
        skipped.path = root_path;
        skipped.reason = result.error_message;
        skipped.error_code = errno;
        result.skipped_entries.push_back(skipped);
        return result;
    }
    root_device_id = static_cast<uint64_t>(root_st.st_dev);
#elif defined(_WIN32)
    struct _stat64 root_st;
    if (_stat64(root_path.c_str(), &root_st) != 0) {
        result.error_message = "Cannot inspect root path: " + root_path;
        SkippedPath skipped;
        skipped.path = root_path;
        skipped.reason = result.error_message;
        skipped.error_code = errno;
        result.skipped_entries.push_back(skipped);
        return result;
    }
    root_device_id = static_cast<uint64_t>(root_st.st_dev);
#endif

    crawl_recursive(root_path, root_device_id, options, cancel_token, progress_cb, result, progress);

    auto end_time = std::chrono::steady_clock::now();
    result.scan_duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time
    ).count();

    result.total_apparent_bytes = progress.total_apparent_bytes;
    result.total_allocated_bytes = progress.total_allocated_bytes;
    result.success = !result.is_cancelled;

    if (progress_cb) {
        progress_cb(progress);
    }

    return result;
}

void DirectoryScanner::crawl_recursive(
    const std::string& current_path,
    uint64_t root_device_id,
    const ScanOptions& options,
    const std::atomic<bool>* cancel_token,
    ProgressCallback& progress_cb,
    DirectoryScanResult& result,
    ScanProgress& progress
) {
    if (cancel_token && cancel_token->load(std::memory_order_relaxed)) {
        result.is_cancelled = true;
        return;
    }

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
    DIR* dir = ::opendir(current_path.c_str());
    if (!dir) {
        SkippedPath skipped;
        skipped.path = current_path;
        skipped.error_code = errno;
        skipped.reason = std::string("Permission denied or unreadable directory: ") + std::strerror(errno);
        result.skipped_entries.push_back(skipped);
        progress.skipped_count++;
        return;
    }

    struct dirent* entry = nullptr;
    while ((entry = ::readdir(dir)) != nullptr) {
        if (cancel_token && cancel_token->load(std::memory_order_relaxed)) {
            result.is_cancelled = true;
            ::closedir(dir);
            return;
        }

        const char* name = entry->d_name;
        // Skip current and parent relative directory references
        if (std::strcmp(name, ".") == 0 || std::strcmp(name, "..") == 0) {
            continue;
        }

        std::string full_path = join_paths(current_path, name);

        // Always use lstat() to inspect the file without following symlinks
        struct stat st;
        if (::lstat(full_path.c_str(), &st) != 0) {
            SkippedPath skipped;
            skipped.path = full_path;
            skipped.error_code = errno;
            skipped.reason = std::string("lstat failed: ") + std::strerror(errno);
            result.skipped_entries.push_back(skipped);
            progress.skipped_count++;
            continue;
        }

        uint64_t entry_device = static_cast<uint64_t>(st.st_dev);
        if (!options.cross_device_boundaries && entry_device != root_device_id) {
            // Stop at device / mount boundaries
            SkippedPath skipped;
            skipped.path = full_path;
            skipped.error_code = 0;
            skipped.reason = "Crossed mount/device boundary (skipped by policy)";
            result.skipped_entries.push_back(skipped);
            progress.skipped_count++;
            continue;
        }

        DirectoryEntry item;
        item.path = full_path;
        item.name = name;
        item.entry_type = determine_entry_type(st);
        item.apparent_bytes = static_cast<uint64_t>(st.st_size);
        // On Linux/POSIX: st_blocks is counted in 512-byte blocks
        item.allocated_bytes = static_cast<uint64_t>(st.st_blocks) * 512ULL;
        item.device_id = entry_device;
        item.inode = static_cast<uint64_t>(st.st_ino);
        item.mtime_epoch_sec = static_cast<int64_t>(st.st_mtime);

        progress.entries_scanned++;
        progress.total_apparent_bytes += item.apparent_bytes;
        progress.total_allocated_bytes += item.allocated_bytes;
        progress.current_path = full_path;

        if (item.entry_type == EntryType::Directory) {
            result.dirs_count++;
        } else {
            result.files_count++;
        }

        if (options.collect_all_entries) {
            result.entries.push_back(item);
        }

        if (progress_cb && (progress.entries_scanned % 100 == 0)) {
            progress_cb(progress);
        }

        // Recurse into directories ONLY if it is not a symlink
        if (item.entry_type == EntryType::Directory) {
            crawl_recursive(full_path, root_device_id, options, cancel_token, progress_cb, result, progress);
        }
    }

    ::closedir(dir);

#elif defined(_WIN32)
    // Windows fallback crawler using FindFirstFile / FindNextFile
    std::string search_pattern = join_paths(current_path, "*");
    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(search_pattern.c_str(), &ffd);

    if (hFind == INVALID_HANDLE_VALUE) {
        SkippedPath skipped;
        skipped.path = current_path;
        skipped.error_code = static_cast<int>(GetLastError());
        skipped.reason = "Cannot open directory: Access denied";
        result.skipped_entries.push_back(skipped);
        progress.skipped_count++;
        return;
    }

    do {
        if (cancel_token && cancel_token->load(std::memory_order_relaxed)) {
            result.is_cancelled = true;
            FindClose(hFind);
            return;
        }

        const char* name = ffd.cFileName;
        if (std::strcmp(name, ".") == 0 || std::strcmp(name, "..") == 0) {
            continue;
        }

        std::string full_path = join_paths(current_path, name);

        // Check for reparse point (symlink / junction)
        bool is_reparse_point = (ffd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        bool is_directory = (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

        DirectoryEntry item;
        item.path = full_path;
        item.name = name;
        item.device_id = root_device_id;
        item.inode = 0;
        item.mtime_epoch_sec = 0;

        ULARGE_INTEGER file_size;
        file_size.LowPart = ffd.nFileSizeLow;
        file_size.HighPart = ffd.nFileSizeHigh;
        item.apparent_bytes = file_size.QuadPart;
        // Approximation for Windows cluster allocation (4KB aligned)
        item.allocated_bytes = ((item.apparent_bytes + 4095ULL) / 4096ULL) * 4096ULL;

        if (is_reparse_point) {
            item.entry_type = EntryType::Symlink;
        } else if (is_directory) {
            item.entry_type = EntryType::Directory;
        } else {
            item.entry_type = EntryType::File;
        }

        progress.entries_scanned++;
        progress.total_apparent_bytes += item.apparent_bytes;
        progress.total_allocated_bytes += item.allocated_bytes;
        progress.current_path = full_path;

        if (item.entry_type == EntryType::Directory) {
            result.dirs_count++;
        } else {
            result.files_count++;
        }

        if (options.collect_all_entries) {
            result.entries.push_back(item);
        }

        if (progress_cb && (progress.entries_scanned % 100 == 0)) {
            progress_cb(progress);
        }

        // Do not recurse into symlinks / reparse points
        if (is_directory && !is_reparse_point) {
            crawl_recursive(full_path, root_device_id, options, cancel_token, progress_cb, result, progress);
        }
    } while (FindNextFileA(hFind, &ffd) != 0);

    FindClose(hFind);
#endif
}

void DirectoryScanner::sort_entries_by_allocated_size(std::vector<DirectoryEntry>& entries) {
    std::sort(entries.begin(), entries.end(), [](const DirectoryEntry& a, const DirectoryEntry& b) {
        return a.allocated_bytes > b.allocated_bytes;
    });
}

void DirectoryScanner::sort_entries_by_apparent_size(std::vector<DirectoryEntry>& entries) {
    std::sort(entries.begin(), entries.end(), [](const DirectoryEntry& a, const DirectoryEntry& b) {
        return a.apparent_bytes > b.apparent_bytes;
    });
}

} // namespace ghostdisk
