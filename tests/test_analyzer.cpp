#include "ghostdisk/analysis_types.hpp"
#include "ghostdisk/discrepancy_analyzer.hpp"
#include "ghostdisk/finding_analyzer.hpp"
#include "ghostdisk/proc_inspector.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

using namespace std;

// assert() disappears in Release builds (-DNDEBUG), so use our own check.
// exit() never returns, so this while body runs at most once. It behaves as one statement.
#define CHECK(cond)                                                                  \
    while (!(cond)) {                                                                \
        cerr << "  [FAIL] " << __FILE__ << ":" << __LINE__ << "  " #cond        \
                  << endl;                                                      \
        exit(1);                                                                \
    }

using namespace ghostdisk;

namespace {

constexpr uint64_t MiB = 1024ULL * 1024;
constexpr uint64_t GiB = 1024ULL * MiB;
constexpr uint64_t kMountDev = 42;

AnalyzerConfig test_config() {
    AnalyzerConfig c;
    c.now_epoch_sec = 1700000000;  // deterministic
    return c;
}

// 100 GiB filesystem, `used` bytes used, plenty free.
FsSnapshot make_fs(uint64_t used, const string& mount = "/") {
    FsSnapshot fs;
    fs.success = true;
    fs.mount_point = mount;
    fs.total_bytes = 100 * GiB;
    fs.used_bytes = used;
    fs.raw_free_bytes = fs.total_bytes - used;
    fs.reserved_or_unavailable_bytes = 5 * GiB;
    fs.available_bytes = fs.raw_free_bytes - fs.reserved_or_unavailable_bytes;
    fs.sampled_at_epoch_sec = 1700000000;
    return fs;
}

DirectoryScanResult make_scan(uint64_t allocated, const string& root = "/") {
    DirectoryScanResult s;
    s.success = true;
    s.root_path = root;
    s.total_allocated_bytes = allocated;
    s.total_apparent_bytes = allocated;
    return s;
}

ProcessRef make_ref(int64_t pid, const string& name, int fd, uint64_t dev, uint64_t inode, uint64_t bytes) {
    ProcessRef r;
    r.pid = pid;
    r.process_name = name;
    r.user_name = "tester";
    r.fd = fd;
    r.target_hint = "/var/log/big.log (deleted)";
    r.device_id = dev;
    r.inode = inode;
    r.apparent_bytes = bytes;
    r.allocated_bytes = bytes;
    return r;
}

ProcScanResult make_proc(const vector<ProcessRef>& refs) {
    ProcScanResult p;
    p.success = true;
    p.findings = ProcInspector::deduplicate_findings(refs, p.total_reclaimable_bytes);
    for (auto& f : p.findings) f.original_path = "/var/log/big.log";
    return p;
}

const Finding* find_type(const vector<Finding>& v, FindingType t) {
    for (const auto& f : v) if (f.type == t) return &f;
    return nullptr;
}

size_t count_type(const vector<Finding>& v, FindingType t) {
    size_t n = 0;
    for (const auto& f : v) if (f.type == t) ++n;
    return n;
}

AnalysisResult run(const FsSnapshot& fs, const DirectoryScanResult& scan,
                   const ProcScanResult& proc, bool cross_device = false) {
    ScanOptions opts;
    opts.cross_device_boundaries = cross_device;
    return FindingAnalyzer::analyze(fs, scan, opts, proc, test_config(), kMountDev);
}

// ---------------------------------------------------------------------------

void test_scope_classification() {
    cout << "[TEST] classify_scope..." << endl;
    CHECK(DiscrepancyAnalyzer::classify_scope("/", "/") == ScanScope::WholeMount);
    CHECK(DiscrepancyAnalyzer::classify_scope("/home", "/home/") == ScanScope::WholeMount);
    CHECK(DiscrepancyAnalyzer::classify_scope("/", "/home/dhir") == ScanScope::PartOfMount);
    CHECK(DiscrepancyAnalyzer::classify_scope("/home", "/home/dhir") == ScanScope::PartOfMount);
    CHECK(DiscrepancyAnalyzer::classify_scope("/home", "/homework") == ScanScope::OutsideMount);  // prefix trap
    CHECK(DiscrepancyAnalyzer::classify_scope("/mnt/usb", "/home") == ScanScope::OutsideMount);
    CHECK(DiscrepancyAnalyzer::classify_scope("", "/home") == ScanScope::Unknown);
    cout << "  [PASS]" << endl;
}

void test_fully_explained_by_deleted_open() {
    cout << "[TEST] Gap fully explained by a deleted-open file..." << endl;
    auto proc = make_proc({make_ref(4123, "nginx", 7, kMountDev, 900, 3 * GiB)});
    auto res = run(make_fs(10 * GiB), make_scan(7 * GiB), proc);

    CHECK(res.report.valid);
    CHECK(res.report.comparable);
    CHECK(res.report.gap_bytes == static_cast<int64_t>(3 * GiB));
    CHECK(res.report.deleted_open_bytes == 3 * GiB);
    CHECK(res.report.explained_bytes == 3 * GiB);
    CHECK(res.report.unresolved_bytes == 0);
    CHECK(!res.report.unresolved_significant);

    CHECK(count_type(res.findings, FindingType::DeletedOpenFile) == 1);
    CHECK(count_type(res.findings, FindingType::UnresolvedDiscrepancy) == 0);
    CHECK(count_type(res.findings, FindingType::NoDiscrepancy) == 1);

    const Finding* f = find_type(res.findings, FindingType::DeletedOpenFile);
    CHECK(f->related_bytes == 3 * GiB);
    CHECK(f->severity == Severity::Critical);   // >= 1 GiB
    CHECK(f->confidence == Confidence::High);
    CHECK(f->risk == RiskLevel::High);          // guidance only
    CHECK(f->process_refs.size() == 1 && f->process_refs[0].pid == 4123);
    CHECK(!f->confirmed_facts.empty());
    CHECK(!f->likely_explanation.empty());
    CHECK(!f->limitations.empty());
    CHECK(f->recommended_next_step.find("never stops or restarts") != string::npos);
    CHECK(f->evidence_json.find("\"pid\":4123") != string::npos);
    CHECK(res.findings[0].type == FindingType::DeletedOpenFile);  // most important first
    cout << "  [PASS]" << endl;
}

void test_partially_explained_leaves_unresolved() {
    cout << "[TEST] Partly explained gap keeps an unresolved remainder..." << endl;
    auto proc = make_proc({make_ref(10, "app", 3, kMountDev, 1, 1 * GiB)});
    auto res = run(make_fs(10 * GiB), make_scan(6 * GiB), proc);

    CHECK(res.report.gap_bytes == static_cast<int64_t>(4 * GiB));
    CHECK(res.report.explained_bytes == 1 * GiB);
    CHECK(res.report.unresolved_bytes == 3 * GiB);
    CHECK(res.report.unresolved_significant);

    const Finding* u = find_type(res.findings, FindingType::UnresolvedDiscrepancy);
    CHECK(u != nullptr);
    CHECK(u->related_bytes == 3 * GiB);
    CHECK(u->confidence == Confidence::Low);
    CHECK(u->risk == RiskLevel::High);
    CHECK(u->recommended_next_step.find("not something to delete") != string::npos);
    CHECK(u->likely_explanation.find("none of them confirmed") != string::npos);
    CHECK(count_type(res.findings, FindingType::NoDiscrepancy) == 0);
    cout << "  [PASS]" << endl;
}

void test_no_evidence_gap_stays_unresolved() {
    cout << "[TEST] Big gap with no evidence is NOT explained away..." << endl;
    auto res = run(make_fs(10 * GiB), make_scan(4 * GiB), make_proc({}));
    CHECK(res.report.explained_bytes == 0);
    CHECK(res.report.unresolved_bytes == 6 * GiB);
    CHECK(count_type(res.findings, FindingType::DeletedOpenFile) == 0);
    CHECK(count_type(res.findings, FindingType::UnresolvedDiscrepancy) == 1);
    cout << "  [PASS]" << endl;
}

void test_no_double_counting() {
    cout << "[TEST] Same inode held by two processes counts once..." << endl;
    auto proc = make_proc({
        make_ref(100, "worker-a", 5, kMountDev, 777, 2 * GiB),
        make_ref(101, "worker-b", 9, kMountDev, 777, 2 * GiB),  // same file
    });
    CHECK(proc.findings.size() == 1);

    auto res = run(make_fs(10 * GiB), make_scan(8 * GiB), proc);
    CHECK(res.report.deleted_open_bytes == 2 * GiB);   // not 4 GiB
    CHECK(res.report.unresolved_bytes == 0);
    const Finding* f = find_type(res.findings, FindingType::DeletedOpenFile);
    CHECK(f != nullptr && f->process_refs.size() == 2);
    CHECK(f->related_bytes == 2 * GiB);
    cout << "  [PASS]" << endl;
}

void test_deleted_open_never_exceeds_gap() {
    cout << "[TEST] Evidence larger than the gap cannot create negative remainder..." << endl;
    auto proc = make_proc({make_ref(1, "big", 3, kMountDev, 5, 5 * GiB)});
    auto res = run(make_fs(10 * GiB), make_scan(9 * GiB), proc);  // gap is only 1 GiB
    CHECK(res.report.explained_bytes == 1 * GiB);
    CHECK(res.report.unresolved_bytes == 0);
    cout << "  [PASS]" << endl;
}

void test_other_mount_ignored() {
    cout << "[TEST] Deleted-open files on other filesystems are ignored..." << endl;
    auto proc = make_proc({
        make_ref(1, "here", 3, kMountDev, 1, 1 * GiB),
        make_ref(2, "elsewhere", 4, /*dev*/ 99, 2, 2 * GiB),
    });
    auto res = run(make_fs(10 * GiB), make_scan(9 * GiB), proc);
    CHECK(res.report.deleted_open_bytes == 1 * GiB);
    CHECK(res.report.deleted_open_other_mounts_count == 1);
    CHECK(count_type(res.findings, FindingType::DeletedOpenFile) == 1);
    cout << "  [PASS]" << endl;
}

void test_partial_scope_not_comparable() {
    cout << "[TEST] Sub-folder scan is not compared with the whole filesystem..." << endl;
    auto res = run(make_fs(10 * GiB), make_scan(1 * GiB, "/home/dhir"), make_proc({}));
    CHECK(res.report.scope == ScanScope::PartOfMount);
    CHECK(!res.report.comparable);
    CHECK(res.report.unresolved_bytes == 0);
    CHECK(res.report.gap_bytes == 0);
    CHECK(count_type(res.findings, FindingType::UnresolvedDiscrepancy) == 0);
    CHECK(count_type(res.findings, FindingType::ScopeNotComparable) == 1);
    cout << "  [PASS]" << endl;
}

void test_cross_device_not_comparable() {
    cout << "[TEST] Scan allowed to cross mounts is not comparable..." << endl;
    auto res = run(make_fs(10 * GiB), make_scan(12 * GiB), make_proc({}), /*cross_device=*/true);
    CHECK(!res.report.comparable);
    CHECK(count_type(res.findings, FindingType::ScopeNotComparable) == 1);
    cout << "  [PASS]" << endl;
}

void test_cancelled_scan_not_comparable() {
    cout << "[TEST] Cancelled scan is not comparable and is reported..." << endl;
    auto scan = make_scan(1 * GiB);
    scan.is_cancelled = true;
    auto res = run(make_fs(10 * GiB), scan, make_proc({}));
    CHECK(!res.report.comparable);
    const Finding* c = find_type(res.findings, FindingType::CoverageLimitation);
    CHECK(c != nullptr && c->severity == Severity::Warning);
    cout << "  [PASS]" << endl;
}

void test_scan_exceeds_filesystem() {
    cout << "[TEST] Scan larger than filesystem usage..." << endl;
    auto res = run(make_fs(10 * GiB), make_scan(12 * GiB), make_proc({}));
    CHECK(res.report.comparable);
    CHECK(res.report.gap_bytes == -static_cast<int64_t>(2 * GiB));
    CHECK(res.report.scan_exceeds_filesystem);
    CHECK(res.report.unresolved_bytes == 0);
    CHECK(count_type(res.findings, FindingType::ScanExceedsFilesystem) == 1);
    CHECK(count_type(res.findings, FindingType::UnresolvedDiscrepancy) == 0);
    cout << "  [PASS]" << endl;
}

void test_within_tolerance() {
    cout << "[TEST] Tiny gap is treated as noise..." << endl;
    auto res = run(make_fs(10 * GiB), make_scan(10 * GiB - 10 * MiB), make_proc({}));
    CHECK(res.report.unresolved_bytes == 10 * MiB);
    CHECK(!res.report.unresolved_significant);
    CHECK(count_type(res.findings, FindingType::UnresolvedDiscrepancy) == 0);
    CHECK(count_type(res.findings, FindingType::NoDiscrepancy) == 1);
    cout << "  [PASS]" << endl;
}

void test_restricted_and_skipped_reported() {
    cout << "[TEST] Restricted PIDs and skipped paths produce limitations (T3/T9)..." << endl;
    auto proc = make_proc({});
    proc.restricted_pids = {1, 2, 3};
    auto scan = make_scan(4 * GiB);
    scan.skipped_entries.push_back({"/root/secret", "Permission denied", 13});

    auto res = run(make_fs(10 * GiB), scan, proc);
    CHECK(res.report.restricted_pid_count == 3);
    CHECK(res.report.skipped_count == 1);

    const Finding* u = find_type(res.findings, FindingType::UnresolvedDiscrepancy);
    CHECK(u != nullptr);
    bool mentions_restricted = false, mentions_skipped = false;
    for (const auto& l : u->limitations) {
        if (l.find("could not be inspected") != string::npos) mentions_restricted = true;
        if (l.find("could not be read") != string::npos) mentions_skipped = true;
    }
    CHECK(mentions_restricted && mentions_skipped);
    CHECK(u->confidence == Confidence::Low);
    CHECK(count_type(res.findings, FindingType::CoverageLimitation) == 1);
    cout << "  [PASS]" << endl;
}

void test_proc_failure_reported() {
    cout << "[TEST] Failed process scan is reported, not hidden..." << endl;
    ProcScanResult proc;
    proc.success = false;
    proc.error_message = "cannot open /proc";
    auto res = run(make_fs(10 * GiB), make_scan(9 * GiB), proc);
    CHECK(!res.report.proc_scan_ok);
    const Finding* c = find_type(res.findings, FindingType::CoverageLimitation);
    CHECK(c != nullptr && c->severity == Severity::Warning);
    cout << "  [PASS]" << endl;
}

void test_invalid_filesystem_snapshot() {
    cout << "[TEST] Failed filesystem snapshot gives a single clear finding..." << endl;
    FsSnapshot fs;
    fs.success = false;
    fs.error_message = "statvfs failed";
    auto res = run(fs, make_scan(1 * GiB), make_proc({}));
    CHECK(!res.report.valid);
    CHECK(res.findings.size() == 1);
    CHECK(res.findings[0].type == FindingType::CoverageLimitation);
    cout << "  [PASS]" << endl;
}

void test_low_space_bumps_severity() {
    cout << "[TEST] Nearly full disk raises severity..." << endl;
    FsSnapshot fs = make_fs(95 * GiB);
    fs.available_bytes = 2 * GiB;  // 2% available
    auto proc = make_proc({make_ref(1, "app", 3, kMountDev, 1, 200 * MiB)});  // normally Warning
    auto res = run(fs, make_scan(94 * GiB + 800 * MiB), proc);
    const Finding* f = find_type(res.findings, FindingType::DeletedOpenFile);
    CHECK(f != nullptr && f->severity == Severity::Critical);
    cout << "  [PASS]" << endl;
}

void test_json_escape_and_evidence() {
    cout << "[TEST] JSON escaping keeps evidence_json valid..." << endl;
    CHECK(FindingAnalyzer::json_escape("a\"b") == "a\\\"b");
    CHECK(FindingAnalyzer::json_escape("a\\b") == "a\\\\b");
    CHECK(FindingAnalyzer::json_escape("a\nb") == "a\\nb");
    CHECK(FindingAnalyzer::json_escape(string("a\x01" "b")) == "a\\u0001b");

    auto proc = make_proc({make_ref(1, "we\"ird", 3, kMountDev, 1, 1 * GiB)});
    auto res = run(make_fs(10 * GiB), make_scan(9 * GiB), proc);
    const Finding* f = find_type(res.findings, FindingType::DeletedOpenFile);
    CHECK(f->evidence_json.find("we\\\"ird") != string::npos);
    cout << "  [PASS]" << endl;
}

void test_reserved_not_in_gap() {
    cout << "[TEST] Reserved space is shown but never mixed into the gap..." << endl;
    auto res = run(make_fs(10 * GiB), make_scan(10 * GiB), make_proc({}));
    CHECK(res.report.reserved_bytes == 5 * GiB);
    CHECK(res.report.gap_bytes == 0);
    CHECK(res.report.unresolved_bytes == 0);
    cout << "  [PASS]" << endl;
}

} // namespace

int main() {
    cout << "  GHOSTDISK - Member 3 Test Suite" << endl;
    cout << "  Modules: DiscrepancyAnalyzer, FindingAnalyzer" << endl;

    test_scope_classification();
    test_fully_explained_by_deleted_open();
    test_partially_explained_leaves_unresolved();
    test_no_evidence_gap_stays_unresolved();
    test_no_double_counting();
    test_deleted_open_never_exceeds_gap();
    test_other_mount_ignored();
    test_partial_scope_not_comparable();
    test_cross_device_not_comparable();
    test_cancelled_scan_not_comparable();
    test_scan_exceeds_filesystem();
    test_within_tolerance();
    test_restricted_and_skipped_reported();
    test_proc_failure_reported();
    test_invalid_filesystem_snapshot();
    test_low_space_bumps_severity();
    test_json_escape_and_evidence();
    test_reserved_not_in_gap();

    cout << "\nALL ANALYZER TESTS PASSED SUCCESSFULLY!" << endl;
    return 0;
}