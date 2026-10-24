#include "ghostdisk/finding_analyzer.hpp"
#include "ghostdisk/discrepancy_analyzer.hpp"
#include "ghostdisk/fs_scanner.hpp"

#include <algorithm>
#include <cstdio>
#include <ctime>

using namespace std;

namespace ghostdisk {

using std::to_string;

namespace {

string bytes_text(uint64_t b) {
    return FsScanner::format_bytes(b);
}

string signed_bytes_text(int64_t v) {
    if (v >= 0) return bytes_text(static_cast<uint64_t>(v));
    return "-" + bytes_text(static_cast<uint64_t>(-(v + 1)) + 1);
}

string basename_of(const string& path) {
    const auto pos = path.find_last_of('/');
    if (pos == string::npos || pos + 1 >= path.size()) return path;
    return path.substr(pos + 1);
}

Severity bump(Severity s) {
    if (s == Severity::Info) return Severity::Warning;
    return Severity::Critical;
}

Severity severity_for_bytes(uint64_t bytes, bool low_space, const AnalyzerConfig& cfg) {
    Severity s = Severity::Info;
    if (bytes >= cfg.critical_bytes)     s = Severity::Critical;
    else if (bytes >= cfg.warning_bytes) s = Severity::Warning;
    if (low_space) s = bump(s);
    return s;
}

string describe_ref(const ProcessRef& p) {
    string s = "PID " + to_string(p.pid) + " (" +
                    (p.process_name.empty() ? "unknown" : p.process_name);
    if (!p.user_name.empty()) s += ", user " + p.user_name;
    s += ") holds it open on fd " + to_string(p.fd);
    return s;
}

string num(uint64_t v) { return to_string(v); }

string report_json(const DiscrepancyReport& r) {
    string j = "{";
    j += "\"mount_point\":\"" + FindingAnalyzer::json_escape(r.mount_point) + "\",";
    j += "\"scan_root\":\"" + FindingAnalyzer::json_escape(r.scan_root) + "\",";
    j += string("\"scope\":\"") + to_string(r.scope) + "\",";
    j += string("\"comparable\":") + (r.comparable ? "true" : "false") + ",";
    j += "\"fs_used_bytes\":" + num(r.fs_used_bytes) + ",";
    j += "\"scan_allocated_bytes\":" + num(r.scan_allocated_bytes) + ",";
    j += "\"gap_bytes\":" + to_string(r.gap_bytes) + ",";
    j += "\"deleted_open_bytes\":" + num(r.deleted_open_bytes) + ",";
    j += "\"explained_bytes\":" + num(r.explained_bytes) + ",";
    j += "\"unresolved_bytes\":" + num(r.unresolved_bytes) + ",";
    j += "\"reserved_bytes\":" + num(r.reserved_bytes) + ",";
    j += "\"skipped_count\":" + num(r.skipped_count) + ",";
    j += "\"restricted_pid_count\":" + num(r.restricted_pid_count);
    j += "}";
    return j;
}

void add_common_limitations(Finding& f, const DiscrepancyReport& r) {
    if (r.restricted_pid_count > 0) {
        f.limitations.push_back(
            num(r.restricted_pid_count) + " process(es) could not be inspected (permission denied), "
            "so other deleted-open files may exist.");
    }
    if (r.skipped_count > 0) {
        f.limitations.push_back(
            num(r.skipped_count) + " path(s) could not be read during the scan.");
    }
}

// ----- individual finding builders ---------------------------------------------------

Finding make_deleted_open(const DeletedOpenFileFinding& d, const DiscrepancyReport& r,
                          bool low_space, const AnalyzerConfig& cfg, int64_t now) {
    Finding f;
    f.type = FindingType::DeletedOpenFile;
    f.severity = severity_for_bytes(d.deduplicated_allocated_bytes, low_space, cfg);
    f.risk = RiskLevel::High;  // active file held by a process: guidance only, no automation
    f.related_bytes = d.deduplicated_allocated_bytes;
    f.process_refs = d.holding_processes;
    f.created_at_epoch_sec = now;

    const string name = d.original_path.empty() ? string("(unknown path)")
                                                     : basename_of(d.original_path);
    f.title = "Deleted file still held open: " + name + " (" + bytes_text(d.deduplicated_allocated_bytes) + ")";

    f.confirmed_facts.push_back("Path before deletion: " +
                                (d.original_path.empty() ? string("unknown") : d.original_path));
    f.confirmed_facts.push_back("Allocated on disk: " + bytes_text(d.deduplicated_allocated_bytes) +
                                " (apparent size " + bytes_text(d.apparent_bytes) + ")");
    f.confirmed_facts.push_back("Held by " + to_string(d.holding_processes.size()) + " process reference(s)");

    const size_t kMaxListed = 5;
    for (size_t i = 0; i < d.holding_processes.size() && i < kMaxListed; ++i) {
        f.confirmed_facts.push_back(describe_ref(d.holding_processes[i]));
    }
    if (d.holding_processes.size() > kMaxListed) {
        f.confirmed_facts.push_back("... and " + to_string(d.holding_processes.size() - kMaxListed) +
                                    " more reference(s)");
    }
    f.confirmed_facts.push_back("File identity: device " + num(d.device_id) + ", inode " + num(d.inode));

    f.likely_explanation =
        "The file's name was removed while a running process kept it open, so the filesystem cannot "
        "release its blocks until every process holding it closes it.";

    f.limitations.push_back(
        "Detected from the \"(deleted)\" marker on /proc/<pid>/fd links. File contents are never inspected.");
    f.limitations.push_back(
        "The process may have closed the file since the scan; re-scan to confirm before acting.");
    if (d.deduplicated_allocated_bytes == 0) {
        f.limitations.push_back("The allocated size could not be read, so the amount of space held is unknown.");
    }
    add_common_limitations(f, r);

    f.confidence = (d.deduplicated_allocated_bytes == 0) ? Confidence::Medium : Confidence::High;

    f.recommended_next_step =
        "Decide whether the holding application or service can be safely restarted, or asked to reopen "
        "its log file (for example through log rotation or a service reload). Do that yourself, then "
        "re-scan to confirm the space was released. GhostDisk never stops or restarts processes.";

    string j = "{\"kind\":\"deleted_open_file\",";
    j += "\"device_id\":" + num(d.device_id) + ",\"inode\":" + num(d.inode) + ",";
    j += "\"original_path\":\"" + FindingAnalyzer::json_escape(d.original_path) + "\",";
    j += "\"allocated_bytes\":" + num(d.deduplicated_allocated_bytes) + ",";
    j += "\"apparent_bytes\":" + num(d.apparent_bytes) + ",\"processes\":[";
    for (size_t i = 0; i < d.holding_processes.size(); ++i) {
        const auto& p = d.holding_processes[i];
        if (i) j += ",";
        j += "{\"pid\":" + to_string(p.pid) +
             ",\"name\":\"" + FindingAnalyzer::json_escape(p.process_name) + "\"" +
             ",\"user\":\"" + FindingAnalyzer::json_escape(p.user_name) + "\"" +
             ",\"fd\":" + to_string(p.fd) + "}";
    }
    j += "]}";
    f.evidence_json = j;
    return f;
}

Finding make_unresolved(const DiscrepancyReport& r, bool low_space,
                        const AnalyzerConfig& cfg, int64_t now) {
    Finding f;
    f.type = FindingType::UnresolvedDiscrepancy;
    f.severity = severity_for_bytes(r.unresolved_bytes, low_space, cfg);
    f.confidence = Confidence::Low;
    f.risk = RiskLevel::High;  // unknown target: never offer deletion
    f.related_bytes = r.unresolved_bytes;
    f.created_at_epoch_sec = now;

    f.title = "Unexplained storage difference: " + bytes_text(r.unresolved_bytes);

    f.confirmed_facts.push_back("Filesystem reports " + bytes_text(r.fs_used_bytes) + " used on " + r.mount_point);
    f.confirmed_facts.push_back("The scan of " + r.scan_root + " found " + bytes_text(r.scan_allocated_bytes) +
                                " allocated");
    f.confirmed_facts.push_back("Difference: " + signed_bytes_text(r.gap_bytes));
    f.confirmed_facts.push_back("Explained by deleted-open files: " + bytes_text(r.explained_bytes));
    f.confirmed_facts.push_back("Still unresolved: " + bytes_text(r.unresolved_bytes) +
                                " (tolerance applied: " + bytes_text(r.tolerance_bytes) + ")");

    f.likely_explanation =
        "Cause not determined. Possible causes, none of them confirmed: files in paths the scan could not read, "
        "deleted-open files held by processes that could not be inspected, snapshots, filesystem metadata or "
        "journal, hard-linked files, or data changing while the scan ran.";

    for (const auto& c : r.caveats) f.limitations.push_back(c);

    f.recommended_next_step =
        "Treat this as something to investigate, not something to delete. Check the largest folders in the "
        "scan results, review the skipped paths and restricted processes, and look for snapshots on this "
        "filesystem. Do not remove anything based on this number alone.";

    f.evidence_json = "{\"kind\":\"unresolved_discrepancy\",\"report\":" + report_json(r) + "}";
    return f;
}

Finding make_simple(FindingType type, Severity sev, Confidence conf, RiskLevel risk,
                    const string& title, const string& explanation,
                    const string& next_step, const DiscrepancyReport& r, int64_t now) {
    Finding f;
    f.type = type;
    f.severity = sev;
    f.confidence = conf;
    f.risk = risk;
    f.title = title;
    f.likely_explanation = explanation;
    f.recommended_next_step = next_step;
    f.created_at_epoch_sec = now;
    f.evidence_json = string("{\"kind\":\"") + to_string(type) + "\",\"report\":" + report_json(r) + "}";
    return f;
}

} // namespace

string FindingAnalyzer::json_escape(const string& s) {
    string out;
    out.reserve(s.size() + 8);
    for (const char ch : s) {
        const unsigned char c = static_cast<unsigned char>(ch);
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += ch;
                }
        }
    }
    return out;
}

vector<Finding> FindingAnalyzer::build_findings(
    const DiscrepancyReport& r, const FsSnapshot& fs, const AnalyzerConfig& cfg)
{
    vector<Finding> out;
    const int64_t now = r.analyzed_at_epoch_sec != 0
        ? r.analyzed_at_epoch_sec : static_cast<int64_t>(time(nullptr));

    // No usable filesystem measurement: say so and stop.
    if (!r.valid) {
        out.push_back(make_simple(
            FindingType::CoverageLimitation, Severity::Warning, Confidence::High, RiskLevel::Low,
            "Filesystem measurement unavailable",
            r.invalid_reason,
            "Check that the selected path exists and is readable, then run the analysis again.",
            r, now));
        out.back().evidence_json = "{\"kind\":\"coverage_limitation\",\"reason\":\"" +
                                   json_escape(r.invalid_reason) + "\"}";
        return out;
    }

    const bool low_space = fs.total_bytes > 0 &&
        (static_cast<double>(fs.available_bytes) / static_cast<double>(fs.total_bytes)) < cfg.low_space_fraction;

    // 1. One finding per deleted-open file (already deduplicated by inode).
    for (const auto& d : r.deleted_open_on_mount) {
        out.push_back(make_deleted_open(d, r, low_space, cfg, now));
    }

    // 2. What does the comparison say?
    if (!r.comparable) {
        Finding f = make_simple(
            FindingType::ScopeNotComparable, Severity::Info, Confidence::High, RiskLevel::Low,
            "Scan cannot be compared with filesystem usage",
            r.scope_note,
            "To see how much of the filesystem is unexplained, scan the whole mount point (" +
                r.mount_point + ") to completion without crossing into other filesystems.",
            r, now);
        f.confirmed_facts.push_back("Scan root: " + (r.scan_root.empty() ? string("none") : r.scan_root));
        f.confirmed_facts.push_back("Measured mount: " + r.mount_point);
        f.confirmed_facts.push_back(string("Scope: ") + to_string(r.scope));
        out.push_back(move(f));
    } else if (r.unresolved_significant) {
        out.push_back(make_unresolved(r, low_space, cfg, now));
    } else if (r.scan_exceeds_filesystem) {
        Finding f = make_simple(
            FindingType::ScanExceedsFilesystem, Severity::Info, Confidence::Medium, RiskLevel::Low,
            "Scan total is larger than filesystem usage",
            "This usually means some files were counted more than once (hard links), were removed while the "
            "scan ran, or the filesystem reports usage differently (for example compression or shared extents).",
            "No action needed. Compare allocated and apparent sizes in the scan results if you want to dig further.",
            r, now);
        f.confirmed_facts.push_back("Filesystem used: " + bytes_text(r.fs_used_bytes));
        f.confirmed_facts.push_back("Scan allocated: " + bytes_text(r.scan_allocated_bytes));
        f.confirmed_facts.push_back("Difference: " + signed_bytes_text(r.gap_bytes));
        out.push_back(move(f));
    } else {
        Finding f = make_simple(
            FindingType::NoDiscrepancy, Severity::Info, Confidence::Medium, RiskLevel::Low,
            "Scan matches filesystem usage",
            "The scan and the filesystem agree within the tolerance, so there is no significant hidden usage "
            "in the scanned scope.",
            "No action needed.",
            r, now);
        f.confirmed_facts.push_back("Filesystem used: " + bytes_text(r.fs_used_bytes));
        f.confirmed_facts.push_back("Scan allocated: " + bytes_text(r.scan_allocated_bytes));
        f.confirmed_facts.push_back("Tolerance applied: " + bytes_text(r.tolerance_bytes));
        out.push_back(move(f));
    }

    // 3. Coverage limitations (skipped paths, restricted PIDs, cancelled scan, proc failure).
    if (r.skipped_count > 0 || r.restricted_pid_count > 0 || r.scan_cancelled || !r.proc_scan_ok) {
        const bool serious = r.scan_cancelled || !r.proc_scan_ok;
        Finding f = make_simple(
            FindingType::CoverageLimitation,
            serious ? Severity::Warning : Severity::Info,
            Confidence::Medium, RiskLevel::Low,
            "Some storage could not be inspected",
            "Results may be incomplete because GhostDisk runs without elevated permissions and does not "
            "force access to protected paths or processes.",
            "Treat the results as a lower bound. Review the skipped paths list; run GhostDisk as a user "
            "that owns the data you care about if you need fuller coverage.",
            r, now);
        f.confirmed_facts.push_back("Skipped paths: " + num(r.skipped_count));
        f.confirmed_facts.push_back("Restricted processes: " + num(r.restricted_pid_count));
        if (r.scan_cancelled) f.confirmed_facts.push_back("The directory scan was cancelled.");
        if (!r.proc_scan_ok) f.confirmed_facts.push_back("Process inspection did not complete.");
        out.push_back(move(f));
    }

    // Most important first: severity desc, then bytes desc. Stable keeps ties in build order.
    stable_sort(out.begin(), out.end(), [](const Finding& a, const Finding& b) {
        if (a.severity != b.severity) return a.severity > b.severity;
        return a.related_bytes > b.related_bytes;
    });
    return out;
}

AnalysisResult FindingAnalyzer::analyze(
    const FsSnapshot& fs,
    const DirectoryScanResult& scan,
    const ScanOptions& scan_options,
    const ProcScanResult& proc,
    const AnalyzerConfig& config,
    optional<uint64_t> mount_device_id)
{
    AnalysisResult result;
    result.report = DiscrepancyAnalyzer::analyze(fs, scan, scan_options, proc, config, mount_device_id);
    result.findings = build_findings(result.report, fs, config);
    return result;
}

} // namespace ghostdisk