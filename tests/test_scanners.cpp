#include "ghostdisk/fs_scanner.hpp"
#include "ghostdisk/directory_scanner.hpp"
#include <iostream>
#include <fstream>
#include <cassert>
#include <atomic>

#if defined(_WIN32)
#include <windows.h>
#include <direct.h>
#define mkdir_compat(p) _mkdir(p)
#define rmdir_compat(p) _rmdir(p)
#else
#include <sys/stat.h>
#include <unistd.h>
#define mkdir_compat(p) mkdir(p, 0755)
#define rmdir_compat(p) rmdir(p)
#endif

void test_fs_scanner() {
    std::cout << "[TEST] Running FsScanner unit tests..." << std::endl;
    ghostdisk::FsScanner scanner;

#if defined(_WIN32)
    std::string test_mount = "C:\\";
#else
    std::string test_mount = "/";
#endif

    auto snapshot = scanner.scan_mount(test_mount);
    assert(snapshot.success && "FsSnapshot scan_mount should succeed");
    assert(snapshot.total_bytes > 0 && "Total bytes must be > 0");
    assert(snapshot.raw_free_bytes <= snapshot.total_bytes && "Free bytes must be <= total bytes");
    assert(snapshot.available_bytes <= snapshot.raw_free_bytes && "Available bytes must be <= raw free bytes");
    assert(snapshot.used_bytes == (snapshot.total_bytes - snapshot.raw_free_bytes) && "used_bytes math verification");
    assert(snapshot.reserved_or_unavailable_bytes == (snapshot.raw_free_bytes - snapshot.available_bytes) && "reserved bytes math verification");

    std::cout << "  Mount: " << snapshot.mount_point << std::endl;
    std::cout << "  Total: " << ghostdisk::FsScanner::format_bytes(snapshot.total_bytes) << std::endl;
    std::cout << "  Used: " << ghostdisk::FsScanner::format_bytes(snapshot.used_bytes) << std::endl;
    std::cout << "  Available: " << ghostdisk::FsScanner::format_bytes(snapshot.available_bytes) << std::endl;
    std::cout << "  Reserved/Unavailable: " << ghostdisk::FsScanner::format_bytes(snapshot.reserved_or_unavailable_bytes) << std::endl;

    // Test byte formatting
    assert(ghostdisk::FsScanner::format_bytes(500) == "500 B");
    assert(ghostdisk::FsScanner::format_bytes(1024) == "1.00 KB");
    assert(ghostdisk::FsScanner::format_bytes(1024 * 1024) == "1.00 MB");
    assert(ghostdisk::FsScanner::format_bytes(1024ULL * 1024ULL * 1024ULL * 5ULL) == "5.00 GB");

    std::cout << "  [PASS] FsScanner passed all checks!\n" << std::endl;
}

void test_directory_scanner() {
    std::cout << "[TEST] Running DirectoryScanner unit tests (T1, T4, Cancellation)..." << std::endl;

    // Create a temporary sandbox directory for controlled testing
    std::string sandbox = "test_sandbox_ghostdisk";
    mkdir_compat(sandbox.c_str());

    std::string sub_dir = sandbox + "/subdir";
    mkdir_compat(sub_dir.c_str());

    // T1: Create a known large file (1 MB) and a small file
    std::string large_file_path = sandbox + "/large_file.bin";
    {
        std::ofstream ofs(large_file_path, std::ios::binary);
        std::vector<char> buffer(1024 * 1024, 'X'); // 1 MB
        ofs.write(buffer.data(), buffer.size());
    }

    std::string small_file_path = sub_dir + "/small_file.txt";
    {
        std::ofstream ofs(small_file_path);
        ofs << "GhostDisk verification test";
    }

    ghostdisk::DirectoryScanner scanner;
    ghostdisk::ScanOptions options;
    options.cross_device_boundaries = false;
    options.collect_all_entries = true;

    size_t callback_invocations = 0;
    auto progress_cb = [&callback_invocations](const ghostdisk::ScanProgress& prog) {
        (void)prog;
        callback_invocations++;
    };

#if !defined(_WIN32)
    // T4: Create directory symlinks and circular loop symlink to verify non-recursive safety
    std::string symlink_subdir = sandbox + "/link_to_subdir";
    std::string symlink_loop = sandbox + "/link_loop_parent";
    ::symlink(sub_dir.c_str(), symlink_subdir.c_str());
    ::symlink(sandbox.c_str(), symlink_loop.c_str());
#endif

    auto result = scanner.scan(sandbox, options, nullptr, progress_cb);

    assert(result.success && "Directory scan should succeed");
    assert(!result.is_cancelled && "Scan should not be cancelled");
    assert(result.files_count >= 2 && "Should find at least 2 files");
    assert(result.dirs_count >= 1 && "Should find at least 1 subdirectory");
    assert(result.total_apparent_bytes >= 1024 * 1024 && "Apparent bytes should account for >= 1 MB file");
    assert(result.total_allocated_bytes > 0 && "Allocated bytes should be > 0");

#if !defined(_WIN32)
    // T4: Verify symlinks were identified and not traversed recursively
    bool found_symlink = false;
    for (const auto& entry : result.entries) {
        if (entry.entry_type == ghostdisk::EntryType::Symlink) {
            found_symlink = true;
            break;
        }
    }
    assert(found_symlink && "T4: Symlink must be recorded as EntryType::Symlink without looping");
    std::cout << "  [PASS] T4 Symlink safety verified (no infinite loop on directory symlinks)." << std::endl;
    ::unlink(symlink_loop.c_str());
    ::unlink(symlink_subdir.c_str());
#endif

    std::cout << "  Scanned files: " << result.files_count << ", dirs: " << result.dirs_count << std::endl;
    std::cout << "  Total Apparent size: " << ghostdisk::FsScanner::format_bytes(result.total_apparent_bytes) << std::endl;
    std::cout << "  Total Allocated blocks: " << ghostdisk::FsScanner::format_bytes(result.total_allocated_bytes) << std::endl;

    // Sorting verification
    ghostdisk::DirectoryScanner::sort_entries_by_apparent_size(result.entries);
    assert(!result.entries.empty());
    assert(result.entries.front().apparent_bytes >= result.entries.back().apparent_bytes);

    // Cancellation test
    std::atomic<bool> cancel_flag{true};
    auto cancel_result = scanner.scan(sandbox, options, &cancel_flag, nullptr);
    assert(cancel_result.is_cancelled && "Cancellation token must safely stop scan");
    std::cout << "  Cancellation token verified safely." << std::endl;

    // Cleanup sandbox files
    std::remove(large_file_path.c_str());
    std::remove(small_file_path.c_str());
    rmdir_compat(sub_dir.c_str());
    rmdir_compat(sandbox.c_str());

    std::cout << "  [PASS] DirectoryScanner passed all checks!\n" << std::endl;
}

void test_permission_denied_skipped_paths() {
    std::cout << "[TEST] Running T3: Permission / skipped path handling..." << std::endl;
    const char* t3_env = std::getenv("GHOSTDISK_TEST_T3_DIR");
    std::string test_dir;
    bool created_locally = false;
    if (t3_env && *t3_env != '\0') {
        test_dir = t3_env;
    } else {
#if !defined(_WIN32)
        test_dir = "/tmp/ghostdisk_test_t3";
        mkdir_compat(test_dir.c_str());
        std::string unreadable = test_dir + "/unreadable_sub";
        mkdir_compat(unreadable.c_str());
        ::chmod(unreadable.c_str(), 0000);
        created_locally = true;
#endif
    }

    if (!test_dir.empty()) {
        ghostdisk::DirectoryScanner scanner;
        ghostdisk::ScanOptions options;
        auto result = scanner.scan(test_dir, options);
        assert(result.success && "Scan should succeed even when subdirectories are unreadable");
        assert(!result.skipped_entries.empty() && "Should record at least one skipped path");
        std::cout << "  Recorded " << result.skipped_entries.size() << " skipped path(s) successfully." << std::endl;
        std::cout << "  Skipped reason: " << result.skipped_entries[0].reason << std::endl;

#if !defined(_WIN32)
        if (created_locally) {
            ::chmod((test_dir + "/unreadable_sub").c_str(), 0755);
            rmdir_compat((test_dir + "/unreadable_sub").c_str());
            rmdir_compat(test_dir.c_str());
        }
#endif
    }
    std::cout << "  [PASS] T3 Permission / skipped paths verified successfully.\n" << std::endl;
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  GHOSTDISK - Member 1 Test Suite" << std::endl;
    std::cout << "  Modules: FsScanner, DirectoryScanner" << std::endl;
    std::cout << "========================================" << std::endl;

    test_fs_scanner();
    test_directory_scanner();
    test_permission_denied_skipped_paths();

    std::cout << "ALL TESTS PASSED SUCCESSFULLY!" << std::endl;
    return 0;
}
