#include "ghostdisk/fs_scanner.hpp"
#include "ghostdisk/directory_scanner.hpp"
#include "ghostdisk/proc_inspector.hpp"
#include "ghostdisk/discrepancy_analyzer.hpp"
#include "ghostdisk/finding_analyzer.hpp"

#include <iostream>
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>
#include <chrono>
#include <ctime>
#include <sstream>

using namespace ghostdisk;

void print_help(const char* prog) {
    std::cout << "GhostDisk - Linux Disk Diagnostics & Discrepancy Analyzer\n\n"
              << "Usage: " << prog << " [mount_point_or_path] [options]\n\n"
              << "Options:\n"
              << "  -w, --export-web      Export results directly to web_ui/live_data.json\n"
              << "  -o, --export-json <f> Export results to a custom JSON file\n"
              << "  -h, --help            Show this help message\n\n"
              << "Examples:\n"
              << "  sudo " << prog << " / --export-web\n"
              << "  sudo " << prog << " /home -o report.json\n";
}

std::string format_bytes(uint64_t bytes) {
    return FsScanner::format_bytes(bytes);
}

std::string escape_json(const std::string& s) {
    return FindingAnalyzer::json_escape(s);
}

int main(int argc, char* argv[]) {
    std::string target_path = "/";
    bool export_web = false;
    std::string export_json_path;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_help(argv[0]);
            return 0;
        } else if (arg == "-w" || arg == "--export-web") {
            export_web = true;
        } else if ((arg == "-o" || arg == "--export-json") && i + 1 < argc) {
            export_json_path = argv[++i];
        } else if (!arg.empty() && arg[0] != '-') {
            target_path = arg;
        }
    }

    if (export_web && export_json_path.empty()) {
        export_json_path = "web_ui/live_data.json";
    }

    std::cout << "\033[1;36m====================================================================\033[0m\n";
    std::cout << "\033[1;36m   GHOSTDISK - Evidence-Based Linux Disk Diagnostics\033[0m\n";
    std::cout << "\033[1;36m====================================================================\033[0m\n";
    std::cout << "[*] Target Path: " << target_path << "\n";

    // 1. Filesystem Telemetry
    std::cout << "[*] Phase 1: Measuring filesystem capacity via statvfs()...\n";
    FsScanner fs_scanner;
    FsSnapshot fs = fs_scanner.scan_mount(target_path);
    if (!fs.success) {
        std::cerr << "\033[1;31m[!] Error reading filesystem metrics: " << fs.error_message << "\033[0m\n";
        return 1;
    }

    std::cout << "    Mount Point:   " << fs.mount_point << "\n"
              << "    Device Name:   " << fs.device_name << " (" << fs.filesystem_type << ")\n"
              << "    Total Space:   " << format_bytes(fs.total_bytes) << "\n"
              << "    Reported Used: " << format_bytes(fs.used_bytes) << " (" 
              << std::fixed << std::setprecision(1) 
              << (fs.total_bytes > 0 ? (100.0 * fs.used_bytes / fs.total_bytes) : 0.0) << "%)\n"
              << "    Available:     " << format_bytes(fs.available_bytes) << "\n"
              << "    Superuser Res: " << format_bytes(fs.reserved_or_unavailable_bytes) << "\n\n";

    // 2. Directory Crawl
    std::cout << "[*] Phase 2: Crawling directory subtree (safe lstat, mount-boundary protected)...\n";
    DirectoryScanner dir_scanner;
    ScanOptions scan_opts;
    scan_opts.cross_device_boundaries = false;
    scan_opts.collect_all_entries = true;
    scan_opts.top_entries_limit = 50;

    auto scan_start = std::chrono::steady_clock::now();
    DirectoryScanResult scan_res = dir_scanner.scan(target_path, scan_opts, nullptr, [](const ScanProgress& p) {
        if (p.entries_scanned % 10000 == 0 && p.entries_scanned > 0) {
            std::cout << "\r    Crawling: " << p.entries_scanned << " entries (" 
                      << format_bytes(p.total_allocated_bytes) << " allocated)..." << std::flush;
        }
    });
    auto scan_end = std::chrono::steady_clock::now();
    int64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(scan_end - scan_start).count();

    std::cout << "\r    Crawl Complete: " << scan_res.entries.size() << " entries in " << dur_ms << "ms.     \n"
              << "    Files Found:    " << scan_res.files_count << " files, " << scan_res.dirs_count << " dirs\n"
              << "    Apparent Total: " << format_bytes(scan_res.total_apparent_bytes) << "\n"
              << "    Allocated Total:" << format_bytes(scan_res.total_allocated_bytes) << "\n"
              << "    Skipped Paths:  " << scan_res.skipped_entries.size() << " (permission denied / restricted)\n\n";

    // 3. Process & Deleted File Detection
    std::cout << "[*] Phase 3: Inspecting /proc for unlinked (deleted) open descriptors...\n";
    ProcInspector proc_inspector;
    ProcScanOptions proc_opts;
    proc_opts.proc_root = "/proc";
    proc_opts.resolve_user_names = true;

    ProcScanResult proc_res = proc_inspector.scan(proc_opts);
    std::cout << "    Scan Duration:  " << proc_res.scan_duration_ms << "ms\n"
              << "    Restricted PIDs:" << proc_res.restricted_pids.size() << " (insufficient permissions)\n"
              << "    Deleted Leaks:  " << proc_res.findings.size() << " unique files holding "
              << format_bytes(proc_res.total_reclaimable_bytes) << "\n\n";

    // 4. Discrepancy & 4-Pillar Analysis
    std::cout << "[*] Phase 4: Correlating discrepancy & generating evidence-backed findings...\n";
    AnalyzerConfig analyzer_cfg;
    AnalysisResult analysis = FindingAnalyzer::analyze(fs, scan_res, scan_opts, proc_res, analyzer_cfg);

    const auto& rep = analysis.report;
    std::cout << "\033[1;32m--------------------------------------------------------------------\033[0m\n";
    std::cout << "\033[1;32m   DISCREPANCY ANALYSIS SUMMARY\033[0m\n";
    std::cout << "\033[1;32m--------------------------------------------------------------------\033[0m\n";
    std::cout << "  Filesystem Reported Used: " << format_bytes(rep.fs_used_bytes) << "\n"
              << "  Directory Crawl Total:    " << format_bytes(rep.scan_allocated_bytes) << "\n"
              << "  Storage Discrepancy Gap:  " << (rep.gap_bytes >= 0 ? "+" : "-") 
              << format_bytes(rep.gap_bytes >= 0 ? rep.gap_bytes : -rep.gap_bytes) << "\n"
              << "  -> Explained by Open Del: " << format_bytes(rep.explained_bytes) << "\n"
              << "  -> Unresolved Remainder:  " << format_bytes(rep.unresolved_bytes) << "\n"
              << "  -> Applied Noise Margin:  " << format_bytes(rep.tolerance_bytes) << "\n\n";

    std::cout << "\033[1;33m[*] Evidence-Backed Findings (" << analysis.findings.size() << "):\033[0m\n";
    for (size_t i = 0; i < analysis.findings.size(); ++i) {
        const auto& f = analysis.findings[i];
        std::cout << "  [" << (i + 1) << "] [" << to_string(f.severity) << "] " << f.title << "\n";
        for (const auto& fact : f.confirmed_facts) {
            std::cout << "      * Fact: " << fact << "\n";
        }
        std::cout << "      * Guidance: " << f.recommended_next_step << "\n\n";
    }

    // 5. Export JSON if requested
    if (!export_json_path.empty()) {
        std::ofstream out(export_json_path);
        if (!out) {
            // Try saving in current directory if web_ui not writable
            export_json_path = "ghostdisk_live_data.json";
            out.open(export_json_path);
        }

        if (out) {
            out << "{\n"
                << "  \"is_live\": true,\n"
                << "  \"timestamp\": \"" << std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()) << "\",\n"
                << "  \"mount_point\": \"" << escape_json(fs.mount_point) << "\",\n"
                << "  \"device_name\": \"" << escape_json(fs.device_name) << "\",\n"
                << "  \"filesystem_type\": \"" << escape_json(fs.filesystem_type) << "\",\n"
                << "  \"total_bytes\": " << fs.total_bytes << ",\n"
                << "  \"used_bytes\": " << fs.used_bytes << ",\n"
                << "  \"available_bytes\": " << fs.available_bytes << ",\n"
                << "  \"reserved_bytes\": " << fs.reserved_or_unavailable_bytes << ",\n"
                << "  \"crawled_bytes\": " << scan_res.total_allocated_bytes << ",\n"
                << "  \"apparent_bytes\": " << scan_res.total_apparent_bytes << ",\n"
                << "  \"files_count\": " << scan_res.files_count << ",\n"
                << "  \"dirs_count\": " << scan_res.dirs_count << ",\n"
                << "  \"deleted_open_bytes\": " << rep.deleted_open_bytes << ",\n"
                << "  \"unresolved_bytes\": " << rep.unresolved_bytes << ",\n"
                << "  \"skipped_count\": " << scan_res.skipped_entries.size() << ",\n"
                << "  \"restricted_pids_count\": " << proc_res.restricted_pids.size() << ",\n";

            // Findings array formatted for UI
            out << "  \"findings\": [\n";
            for (size_t i = 0; i < analysis.findings.size(); ++i) {
                const auto& f = analysis.findings[i];
                std::string sev = to_string(f.severity);
                std::string badge_cls = (sev == "critical") ? "badge-critical" : (sev == "warning" ? "badge-warning" : "badge-info");
                std::string proc_str = "None (System accounting)";
                int fd_val = -1;
                uint64_t ino_val = 0;
                uint64_t dev_val = 0;
                if (!f.process_refs.empty()) {
                    const auto& p = f.process_refs[0];
                    proc_str = p.process_name + " (PID " + std::to_string(p.pid) + ", user " + p.user_name + ")";
                    fd_val = p.fd;
                    ino_val = p.inode;
                    dev_val = p.device_id;
                }

                out << "    {\n"
                    << "      \"id\": " << i << ",\n"
                    << "      \"title\": \"" << escape_json(f.title) << "\",\n"
                    << "      \"severity\": \"" << (sev == "critical" ? "Critical" : (sev == "warning" ? "Warning" : "Info")) << "\",\n"
                    << "      \"severityClass\": \"" << badge_cls << "\",\n"
                    << "      \"relatedBytes\": \"" << format_bytes(f.related_bytes) << "\",\n"
                    << "      \"process\": \"" << escape_json(proc_str) << "\",\n"
                    << "      \"fd\": " << fd_val << ",\n"
                    << "      \"inode\": " << ino_val << ",\n"
                    << "      \"device\": " << dev_val << ",\n"
                    << "      \"summary\": \"" << escape_json(f.title) << "\",\n"
                    << "      \"guidance\": \"Guidance: Safe Inspection\",\n"
                    << "      \"confirmedFacts\": [\n";
                for (size_t j = 0; j < f.confirmed_facts.size(); ++j) {
                    out << "        \"" << escape_json(f.confirmed_facts[j]) << "\"" 
                        << (j + 1 < f.confirmed_facts.size() ? "," : "") << "\n";
                }
                out << "      ],\n"
                    << "      \"explanation\": \"" << escape_json(f.likely_explanation) << "\",\n"
                    << "      \"limitations\": [\n";
                for (size_t j = 0; j < f.limitations.size(); ++j) {
                    out << "        \"" << escape_json(f.limitations[j]) << "\""
                        << (j + 1 < f.limitations.size() ? "," : "") << "\n";
                }
                out << "      ],\n"
                    << "      \"recommendation\": \"" << escape_json(f.recommended_next_step) << "\"\n"
                    << "    }" << (i + 1 < analysis.findings.size() ? "," : "") << "\n";
            }
            out << "  ],\n";

            // Tree samples: top 10 largest entries
            DirectoryScanner::sort_entries_by_allocated_size(scan_res.entries);
            out << "  \"tree\": [\n";
            size_t max_tree = std::min<size_t>(scan_res.entries.size(), 15);
            for (size_t i = 0; i < max_tree; ++i) {
                const auto& e = scan_res.entries[i];
                out << "    {\n"
                    << "      \"path\": \"" << escape_json(e.path) << "\",\n"
                    << "      \"allocated\": \"" << format_bytes(e.allocated_bytes) << "\",\n"
                    << "      \"apparent\": \"" << format_bytes(e.apparent_bytes) << "\",\n"
                    << "      \"type\": \"" << entry_type_to_string(e.entry_type) << "\",\n"
                    << "      \"dev\": \"" << e.device_id << "\",\n"
                    << "      \"ino\": \"" << e.inode << "\"\n"
                    << "    }" << (i + 1 < max_tree ? "," : "") << "\n";
            }
            out << "  ]\n"
                << "}\n";

            std::cout << "\033[1;32m[+] Successfully exported live diagnostic data to: " << export_json_path << "\033[0m\n";
        }
    }

    std::cout << "\n[*] Done. To view in browser, start: python3 -m http.server 8080 --directory web_ui\n";
    return 0;
}
