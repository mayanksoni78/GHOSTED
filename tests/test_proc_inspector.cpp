#include "ghostdisk/proc_inspector.hpp"
#include "ghostdisk/fs_scanner.hpp"
#include <iostream>
#include <fstream>
#include <cassert>
#include <atomic>
#include <vector>

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

void test_deleted_target_parsing() {
    std::cout << "[TEST] Running parse_deleted_target tests..." << std::endl;

    std::string original;

    // Standard deleted file
    assert(ghostdisk::ProcInspector::parse_deleted_target("/var/log/nginx/access.log (deleted)", original));
    assert(original == "/var/log/nginx/access.log");

    // Path with spaces
    assert(ghostdisk::ProcInspector::parse_deleted_target("/home/user/my documents/temp.txt (deleted)", original));
    assert(original == "/home/user/my documents/temp.txt");

    // Negative tests: non-deleted targets
    assert(!ghostdisk::ProcInspector::parse_deleted_target("/usr/bin/python3", original));
    assert(!ghostdisk::ProcInspector::parse_deleted_target("/tmp/deleted.txt", original));
    assert(!ghostdisk::ProcInspector::parse_deleted_target(" (deleted", original));
    assert(!ghostdisk::ProcInspector::parse_deleted_target("", original));

    std::cout << "  [PASS] Target parsing verified successfully." << std::endl;
}

void test_numeric_pid_checking() {
    std::cout << "[TEST] Running numeric PID checking..." << std::endl;

    assert(ghostdisk::ProcInspector::is_numeric_pid("1"));
    assert(ghostdisk::ProcInspector::is_numeric_pid("12345"));
    assert(ghostdisk::ProcInspector::is_numeric_pid("0"));
    assert(!ghostdisk::ProcInspector::is_numeric_pid(""));
    assert(!ghostdisk::ProcInspector::is_numeric_pid("self"));
    assert(!ghostdisk::ProcInspector::is_numeric_pid("cpuinfo"));
    assert(!ghostdisk::ProcInspector::is_numeric_pid("123a"));
    assert(!ghostdisk::ProcInspector::is_numeric_pid("-10"));

    std::cout << "  [PASS] Numeric PID detection verified successfully." << std::endl;
}

void test_inode_deduplication() {
    std::cout << "[TEST] Running (device_id, inode) deduplication tests..." << std::endl;

    constexpr uint64_t SIZE_10MB = 10ULL * 1024ULL * 1024ULL;
    constexpr uint64_t SIZE_4MB  = 4ULL * 1024ULL * 1024ULL;
    constexpr uint64_t SIZE_2MB  = 2ULL * 1024ULL * 1024ULL;

    std::vector<ghostdisk::ProcessRef> raw_refs;

    // Ref 1: PID 101, FD 3 -> Dev 2050, Inode 55555 (10 MB allocated)
    ghostdisk::ProcessRef r1;
    r1.pid = 101;
    r1.process_name = "worker_a";
    r1.user_name = "appuser";
    r1.fd = 3;
    r1.target_hint = "/tmp/shared_leak.tmp (deleted)";
    r1.device_id = 2050;
    r1.inode = 55555;
    r1.apparent_bytes = SIZE_10MB;
    r1.allocated_bytes = SIZE_10MB;
    raw_refs.push_back(r1);

    // Ref 2: PID 102, FD 4 -> Dev 2050, Inode 55555 (Same file held open by PID 102!)
    ghostdisk::ProcessRef r2;
    r2.pid = 102;
    r2.process_name = "worker_b";
    r2.user_name = "appuser";
    r2.fd = 4;
    r2.target_hint = "/tmp/shared_leak.tmp (deleted)";
    r2.device_id = 2050;
    r2.inode = 55555;
    r2.apparent_bytes = SIZE_10MB;
    r2.allocated_bytes = SIZE_10MB;
    raw_refs.push_back(r2);

    // Ref 3: PID 103, FD 5 -> Dev 2051, Inode 55555 (Different device mount, same inode number!)
    ghostdisk::ProcessRef r3;
    r3.pid = 103;
    r3.process_name = "backup_daemon";
    r3.user_name = "root";
    r3.fd = 5;
    r3.target_hint = "/var/log/backup.log (deleted)";
    r3.device_id = 2051; // Different device!
    r3.inode = 55555;
    r3.apparent_bytes = SIZE_4MB;
    r3.allocated_bytes = SIZE_4MB;
    raw_refs.push_back(r3);

    // Ref 4: PID 101, FD 6 -> Dev 2050, Inode 77777 (Another distinct deleted file)
    ghostdisk::ProcessRef r4;
    r4.pid = 101;
    r4.process_name = "worker_a";
    r4.user_name = "appuser";
    r4.fd = 6;
    r4.target_hint = "/tmp/cache_extra.tmp (deleted)";
    r4.device_id = 2050;
    r4.inode = 77777;
    r4.apparent_bytes = SIZE_2MB;
    r4.allocated_bytes = SIZE_2MB;
    raw_refs.push_back(r4);

    uint64_t total_reclaimable = 0;
    auto findings = ghostdisk::ProcInspector::deduplicate_findings(raw_refs, total_reclaimable);

    // Exactly 3 unique findings: (2050, 55555), (2051, 55555), and (2050, 77777)
    assert(findings.size() == 3 && "Deduplication must yield exactly 3 findings");

    // Total reclaimable bytes must equal 10MB + 4MB + 2MB = 16MB (NOT 26MB)
    assert(total_reclaimable == (SIZE_10MB + SIZE_4MB + SIZE_2MB) && "Storage must be deduplicated across processes");

    // Finding with (2050, 55555) should have 2 holding processes
    bool found_shared = false;
    for (const auto& f : findings) {
        if (f.device_id == 2050 && f.inode == 55555) {
            found_shared = true;
            assert(f.holding_processes.size() == 2 && "Should record both holding processes");
            assert(f.deduplicated_allocated_bytes == SIZE_10MB);
        }
    }
    assert(found_shared && "Shared inode finding must exist");

    std::cout << "  Deduplicated findings count: " << findings.size() << std::endl;
    std::cout << "  Total Reclaimable Bytes: " << ghostdisk::FsScanner::format_bytes(total_reclaimable) << std::endl;
    std::cout << "  [PASS] Inode deduplication verified successfully." << std::endl;
}

void test_mock_proc_scan() {
    std::cout << "[TEST] Running Mock procfs directory scan..." << std::endl;

    std::string mock_root = "test_mock_proc_dir";
    mkdir_compat(mock_root.c_str());

    // Create process 4001
    std::string pid_4001 = mock_root + "/4001";
    mkdir_compat(pid_4001.c_str());
    {
        std::ofstream comm_file(pid_4001 + "/comm");
        comm_file << "mock_app\n";
    }
    {
        std::ofstream status_file(pid_4001 + "/status");
        status_file << "Name:\tmock_app\nUid:\t1000\t1000\t1000\t1000\n";
    }
    std::string fd_dir_4001 = pid_4001 + "/fd";
    mkdir_compat(fd_dir_4001.c_str());
    {
        std::ofstream fd_3(fd_dir_4001 + "/3");
        fd_3 << "/tmp/ghost_leak.bin (deleted)\n";
    }

    // Create process 4002 with normal non-deleted FD
    std::string pid_4002 = mock_root + "/4002";
    mkdir_compat(pid_4002.c_str());
    {
        std::ofstream comm_file(pid_4002 + "/comm");
        comm_file << "mock_regular\n";
    }
    std::string fd_dir_4002 = pid_4002 + "/fd";
    mkdir_compat(fd_dir_4002.c_str());
    {
        std::ofstream fd_4(fd_dir_4002 + "/4");
        fd_4 << "/var/log/active.log\n"; // Not deleted
    }

    // Non-PID directory (should be ignored by crawler)
    std::string non_pid = mock_root + "/sysinfo";
    mkdir_compat(non_pid.c_str());

    ghostdisk::ProcInspector inspector;
    ghostdisk::ProcScanOptions options;
    options.proc_root = mock_root;
    options.resolve_user_names = true;

    auto result = inspector.scan(options);
    assert(result.success && "Scan on mock proc must succeed");
    assert(!result.findings.empty() && "Should find deleted open file");
    assert(result.findings[0].original_path == "/tmp/ghost_leak.bin");

    std::cout << "  Discovered deleted files: " << result.findings.size() << std::endl;
    std::cout << "  Finding original path: " << result.findings[0].original_path << std::endl;

    // Cancellation test
    std::atomic<bool> cancel_flag{true};
    auto cancel_res = inspector.scan(options, &cancel_flag);
    assert(cancel_res.is_cancelled && "Cancellation token must safely stop scan");

    // Cleanup mock proc
    std::remove((fd_dir_4001 + "/3").c_str());
    rmdir_compat(fd_dir_4001.c_str());
    std::remove((pid_4001 + "/comm").c_str());
    std::remove((pid_4001 + "/status").c_str());
    rmdir_compat(pid_4001.c_str());

    std::remove((fd_dir_4002 + "/4").c_str());
    rmdir_compat(fd_dir_4002.c_str());
    std::remove((pid_4002 + "/comm").c_str());
    rmdir_compat(pid_4002.c_str());

    rmdir_compat(non_pid.c_str());
    rmdir_compat(mock_root.c_str());

    std::cout << "  [PASS] Mock procfs scan passed all checks!" << std::endl;
}

void test_live_workload_t2_and_t9() {
    std::cout << "[TEST] Running Live /proc and T2/T9 workload tests..." << std::endl;

    ghostdisk::ProcInspector inspector;

    // Check if a specific target PID was provided via GHOSTDISK_TEST_T2_PID (T2)
    const char* t2_pid_str = std::getenv("GHOSTDISK_TEST_T2_PID");
    if (t2_pid_str && *t2_pid_str != '\0') {
        int64_t target_pid = std::stoll(t2_pid_str);
        std::cout << "  Testing against live workload T2 process (PID " << target_pid << ")..." << std::endl;

        bool is_restricted = false;
        auto refs = inspector.inspect_process(target_pid, "/proc", true, &is_restricted);
        assert(!is_restricted && "Should have read permission for child workload process");
        assert(!refs.empty() && "Workload process must contain at least 1 deleted open file");

        const auto& target_ref = refs.front();
        std::cout << "  Discovered T2 file: " << target_ref.target_hint << std::endl;
        std::cout << "  Apparent size: " << ghostdisk::FsScanner::format_bytes(target_ref.apparent_bytes) << std::endl;
        std::cout << "  Allocated bytes: " << ghostdisk::FsScanner::format_bytes(target_ref.allocated_bytes) << std::endl;

        assert(target_ref.apparent_bytes >= 10ULL * 1024ULL * 1024ULL && "T2 file should be 10 MB apparent size");
        std::cout << "  [PASS] Controlled Workload T2 successfully verified!" << std::endl;
    }

    // T9: Live system scan resilience (verifies permission denied PIDs are handled gracefully)
#if defined(__linux__)
    std::cout << "  Running unprivileged system-wide /proc scan (T9 resilience)..." << std::endl;
    ghostdisk::ProcScanOptions live_opts;
    live_opts.proc_root = "/proc";
    auto live_result = inspector.scan(live_opts);
    assert(live_result.success && "Live /proc scan should succeed without crash or false assertions");
    std::cout << "  Live scan duration: " << live_result.scan_duration_ms << " ms" << std::endl;
    std::cout << "  Restricted PIDs recorded: " << live_result.restricted_pids.size() << std::endl;
    std::cout << "  [PASS] Unprivileged process scan (T9) handled gracefully!" << std::endl;
#endif
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  GHOSTDISK - Member 2 Test Suite" << std::endl;
    std::cout << "  Module: ProcInspector (/proc detective)" << std::endl;
    std::cout << "========================================" << std::endl;

    test_deleted_target_parsing();
    test_numeric_pid_checking();
    test_inode_deduplication();
    test_mock_proc_scan();
    test_live_workload_t2_and_t9();

    std::cout << "\nALL MEMBER 2 UNIT TESTS PASSED SUCCESSFULLY!" << std::endl;
    return 0;
}

