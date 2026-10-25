#include "ghostdisk/recovery_coordinator.hpp"
#include "ghostdisk/verification_service.hpp"
#include "ghostdisk/fs_scanner.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdlib>
#include <cstring>

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
#include <sys/stat.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

using namespace std;
using namespace ghostdisk;

#define CHECK(cond)                                                                  \
    while (!(cond)) {                                                                \
        cerr << "  [FAIL] " << __FILE__ << ":" << __LINE__ << "  " #cond            \
             << endl;                                                                \
        exit(1);                                                                     \
    }

namespace {

constexpr uint64_t MiB = 1024ULL * 1024;

bool file_exists(const string& path) {
#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
    struct stat st;
    return (::lstat(path.c_str(), &st) == 0);
#elif defined(_WIN32)
    DWORD attr = GetFileAttributesA(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES);
#else
    ifstream f(path.c_str());
    return f.good();
#endif
}

void write_test_file(const string& path, size_t size_bytes) {
    ofstream ofs(path, ios::binary | ios::trunc);
    CHECK(ofs.is_open());
    string chunk(64 * 1024, 'X');
    size_t written = 0;
    while (written < size_bytes) {
        size_t to_write = min(chunk.size(), size_bytes - written);
        ofs.write(chunk.data(), to_write);
        written += to_write;
    }
    ofs.flush();
    ofs.close();
}

string get_test_temp_dir() {
#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
    string dir = "/tmp/ghostdisk_test";
    ::mkdir(dir.c_str(), 0755);
    return dir;
#elif defined(_WIN32)
    const char* temp = getenv("TEMP");
    string dir = (temp ? string(temp) : "C:/temp") + "/ghostdisk_test";
    CreateDirectoryA(dir.c_str(), NULL);
    return dir;
#else
    return "./ghostdisk_test";
#endif
}

void test_allowlist_containment() {
    cout << "[TEST] Allowlist path containment and traversal rejection..." << endl;
    string allowed_root = get_test_temp_dir();
    RecoveryCoordinator coordinator({allowed_root});

    // Valid file inside allowed root
    string inside_path = allowed_root + "/sample.txt";
    CHECK(coordinator.is_path_allowlisted(inside_path));

    // Outside path
    CHECK(!coordinator.is_path_allowlisted("/etc/shadow"));
    CHECK(!coordinator.is_path_allowlisted("C:/Windows/System32/drivers/etc/hosts"));

    // Directory traversal attempt using '..'
    string traversal_attempt = allowed_root + "/../../etc/passwd";
    CHECK(!coordinator.is_path_allowlisted(traversal_attempt));

    // The root directory itself is not a valid cleanup target
    CHECK(!coordinator.is_path_allowlisted(allowed_root));
    cout << "  [PASS]" << endl;
}

void test_preview_is_read_only() {
    cout << "[TEST] Preview generation is non-destructive (read-only)..." << endl;
    string allowed_root = get_test_temp_dir();
    string file_path = allowed_root + "/read_only_test.bin";
    write_test_file(file_path, 1024);

    RecoveryCoordinator coordinator({allowed_root});
    RecoveryPreview preview = coordinator.create_preview(file_path);

    CHECK(preview.is_valid);
    CHECK(preview.is_allowlisted);
    CHECK(preview.risk_level == RiskLevel::Low);
    CHECK(preview.target_apparent_bytes == 1024);

    // Verify file is completely unmodified and intact
    CHECK(file_exists(file_path));

    // Cleanup test file
    remove(file_path.c_str());
    cout << "  [PASS]" << endl;
}

void test_directory_rejection() {
    cout << "[TEST] Reject directory deletion for safety..." << endl;
    string allowed_root = get_test_temp_dir();
    string sub_dir = allowed_root + "/test_subdir";
#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
    ::mkdir(sub_dir.c_str(), 0755);
#elif defined(_WIN32)
    CreateDirectoryA(sub_dir.c_str(), NULL);
#endif

    RecoveryCoordinator coordinator({allowed_root});
    RecoveryPreview preview = coordinator.create_preview(sub_dir);

    // Directories must be rejected
    CHECK(!preview.is_valid);
    CHECK(preview.error_message.find("directory") != string::npos);

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
    ::rmdir(sub_dir.c_str());
#elif defined(_WIN32)
    RemoveDirectoryA(sub_dir.c_str());
#endif
    cout << "  [PASS]" << endl;
}

void test_unconfirmed_action_rejection() {
    cout << "[TEST] Reject mutation when user confirmation is false..." << endl;
    string allowed_root = get_test_temp_dir();
    string file_path = allowed_root + "/unconfirmed.bin";
    write_test_file(file_path, 2048);

    RecoveryCoordinator coordinator({allowed_root});
    RecoveryPreview preview = coordinator.create_preview(file_path);
    CHECK(preview.is_valid);

    // Attempt recovery with user_confirmed = false
    VerificationResult result = coordinator.execute_recovery(preview, /*user_confirmed=*/false);

    CHECK(!result.success);
    CHECK(result.error_message.find("user confirmation") != string::npos);
    // File must NOT be deleted
    CHECK(file_exists(file_path));

    remove(file_path.c_str());
    cout << "  [PASS]" << endl;
}

void test_non_allowlisted_execution_rejection() {
    cout << "[TEST] Reject execution on non-allowlisted targets..." << endl;
    string allowed_root = get_test_temp_dir();
    RecoveryCoordinator coordinator({allowed_root});

    RecoveryPreview preview;
    preview.is_valid = true;
    preview.target_path = "/non_allowlisted_secret.txt";
    preview.is_allowlisted = false;
    preview.risk_level = RiskLevel::High;

    VerificationResult result = coordinator.execute_recovery(preview, /*user_confirmed=*/true);
    CHECK(!result.success);
    CHECK(result.error_message.find("allowlist") != string::npos);
    cout << "  [PASS]" << endl;
}

void test_t6_controlled_cache_cleanup_20mb() {
    cout << "[TEST] T6: Controlled 20 MB Cache Cleanup and Space Verification..." << endl;
    string allowed_root = get_test_temp_dir();
    string target_file = allowed_root + "/ghostdisk_test_20mb.bin";

    // Create controlled 20 MB file
    write_test_file(target_file, 20 * MiB);
    CHECK(file_exists(target_file));

    RecoveryCoordinator coordinator({allowed_root});

    // Stage 1: Generate Preview
    RecoveryPreview preview = coordinator.create_preview(target_file);
    CHECK(preview.is_valid);
    CHECK(preview.is_allowlisted);
    CHECK(preview.risk_level == RiskLevel::Low);
    CHECK(preview.target_apparent_bytes == 20 * MiB);
    CHECK(preview.estimated_reclaimable_bytes >= 20 * MiB);

    // Stage 2: Confirmed Execution
    VerificationResult result = coordinator.execute_recovery(preview, /*user_confirmed=*/true);

    CHECK(result.success);
    CHECK(!file_exists(target_file)); // Target must be unlinked
    CHECK(!result.audit_log_message.empty());
    cout << "  Audit Record: " << result.audit_log_message << endl;
    cout << "  [PASS]" << endl;
}

void test_t7_toctou_modification_abort() {
    cout << "[TEST] T7: TOCTOU Race Condition Abort (Target modified before confirmation)..." << endl;
    string allowed_root = get_test_temp_dir();
    string target_file = allowed_root + "/toctou_target.txt";

    write_test_file(target_file, 512);

    RecoveryCoordinator coordinator({allowed_root});
    RecoveryPreview preview = coordinator.create_preview(target_file);
    CHECK(preview.is_valid);

    // Modify file between preview and confirmation (simulating concurrent race or swap)
    write_test_file(target_file, 4096);

    // Attempt confirmed execution
    VerificationResult result = coordinator.execute_recovery(preview, /*user_confirmed=*/true);

    // Coordinator must detect metadata change and safely abort without unlinking!
    CHECK(!result.success);
    CHECK(result.error_message.find("TOCTOU abort") != string::npos);
    CHECK(file_exists(target_file)); // File must NOT be deleted

    remove(target_file.c_str());
    cout << "  [PASS]" << endl;
}

void test_t7_toctou_vanished_abort() {
    cout << "[TEST] T7: TOCTOU Abort when target vanishes before confirmation..." << endl;
    string allowed_root = get_test_temp_dir();
    string target_file = allowed_root + "/toctou_vanish.txt";

    write_test_file(target_file, 1024);

    RecoveryCoordinator coordinator({allowed_root});
    RecoveryPreview preview = coordinator.create_preview(target_file);
    CHECK(preview.is_valid);

    // File removed by another process before user confirms
    remove(target_file.c_str());
    CHECK(!file_exists(target_file));

    VerificationResult result = coordinator.execute_recovery(preview, /*user_confirmed=*/true);
    CHECK(!result.success);
    CHECK(result.error_message.find("TOCTOU abort") != string::npos);
    cout << "  [PASS]" << endl;
}

void test_verification_service_delta_synthesis() {
    cout << "[TEST] VerificationService delta and audit message synthesis..." << endl;
    FsSnapshot before_snap;
    before_snap.mount_point = "/";
    before_snap.available_bytes = 100 * MiB;
    before_snap.total_bytes = 500 * MiB;
    before_snap.success = true;

    // Simulate failure
    VerificationResult fail_res = VerificationService::verify(
        "/tmp/ghostdisk_test/dummy.bin",
        before_snap,
        10 * MiB,
        false,
        "Simulated IO error"
    );
    CHECK(!fail_res.success);
    CHECK(fail_res.error_message == "Simulated IO error");
    cout << "  [PASS]" << endl;
}

} // namespace

int main() {
    cout << "==========================================" << endl;
    cout << "  GHOSTDISK - Member 4 Test Suite" << endl;
    cout << "  Modules: RecoveryCoordinator, VerificationService" << endl;
    cout << "==========================================" << endl;

    test_allowlist_containment();
    test_preview_is_read_only();
    test_directory_rejection();
    test_unconfirmed_action_rejection();
    test_non_allowlisted_execution_rejection();
    test_t6_controlled_cache_cleanup_20mb();
    test_t7_toctou_modification_abort();
    test_t7_toctou_vanished_abort();
    test_verification_service_delta_synthesis();

    cout << "\nALL RECOVERY & VERIFICATION TESTS PASSED SUCCESSFULLY!" << endl;
    return 0;
}
