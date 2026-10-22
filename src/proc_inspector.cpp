#include "ghostdisk/proc_inspector.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <cerrno>
#include <map>

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#elif defined(_WIN32)
#include <windows.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif

namespace ghostdisk {

namespace {

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)

std::string read_first_line(const std::string& path) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        return "";
    }
    std::string line;
    if (std::getline(ifs, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
            line.pop_back();
        }
        return line;
    }
    return "";
}

std::string resolve_uid_to_username(uid_t uid) {
    struct passwd pwd;
    struct passwd* result = nullptr;
    char buf[1024];
    if (::getpwuid_r(uid, &pwd, buf, sizeof(buf), &result) == 0 && result != nullptr) {
        return std::string(pwd.pw_name);
    }
    return "uid:" + std::to_string(uid);
}

std::string extract_proc_username(const std::string& status_path) {
    std::ifstream ifs(status_path);
    if (!ifs.is_open()) {
        return "unknown";
    }
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.rfind("Uid:", 0) == 0) {
            std::istringstream iss(line.substr(4));
            uid_t ruid = 0;
            if (iss >> ruid) {
                return resolve_uid_to_username(ruid);
            }
            break;
        }
    }
    return "unknown";
}

#elif defined(_WIN32)

std::string read_first_line(const std::string& path) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        return "";
    }
    std::string line;
    if (std::getline(ifs, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
            line.pop_back();
        }
        return line;
    }
    return "";
}

#endif

} // anonymous namespace

bool ProcInspector::is_numeric_pid(const std::string& name) {
    if (name.empty()) {
        return false;
    }
    for (char c : name) {
        if (c < '0' || c > '9') {
            return false;
        }
    }
    return true;
}

bool ProcInspector::parse_deleted_target(const std::string& target, std::string& out_original_path) {
    static const std::string suffix = " (deleted)";
    if (target.size() >= suffix.size() &&
        target.compare(target.size() - suffix.size(), suffix.size(), suffix) == 0) {
        out_original_path = target.substr(0, target.size() - suffix.size());
        return true;
    }
    return false;
}

std::vector<DeletedOpenFileFinding> ProcInspector::deduplicate_findings(
    const std::vector<ProcessRef>& raw_refs,
    uint64_t& out_total_reclaimable_bytes
) {
    out_total_reclaimable_bytes = 0;

    // Deduplication key: pair of (device_id, inode)
    // Note: device_id is critical because inodes are not globally unique across different mounts
    std::map<std::pair<uint64_t, uint64_t>, DeletedOpenFileFinding> deduplicated_map;
    // Fallback list for items where device/inode could not be statted (dev==0 && ino==0)
    std::vector<DeletedOpenFileFinding> unallocated_findings;

    for (const auto& pref : raw_refs) {
        std::string original_path;
        parse_deleted_target(pref.target_hint, original_path);
        if (original_path.empty()) {
            original_path = pref.target_hint;
        }

        if (pref.device_id == 0 && pref.inode == 0) {
            // Cannot deduplicate by device/inode; add as separate or unindexed finding
            DeletedOpenFileFinding finding;
            finding.device_id = 0;
            finding.inode = 0;
            finding.original_path = original_path;
            finding.deduplicated_allocated_bytes = pref.allocated_bytes;
            finding.apparent_bytes = pref.apparent_bytes;
            finding.holding_processes.push_back(pref);
            out_total_reclaimable_bytes += pref.allocated_bytes;
            unallocated_findings.push_back(finding);
            continue;
        }

        auto key = std::make_pair(pref.device_id, pref.inode);
        auto it = deduplicated_map.find(key);
        if (it == deduplicated_map.end()) {
            DeletedOpenFileFinding finding;
            finding.device_id = pref.device_id;
            finding.inode = pref.inode;
            finding.original_path = original_path;
            finding.deduplicated_allocated_bytes = pref.allocated_bytes;
            finding.apparent_bytes = pref.apparent_bytes;
            finding.holding_processes.push_back(pref);
            deduplicated_map[key] = std::move(finding);
            out_total_reclaimable_bytes += pref.allocated_bytes;
        } else {
            // Inode already present: append process reference without recounting storage
            it->second.holding_processes.push_back(pref);
            if (pref.allocated_bytes > it->second.deduplicated_allocated_bytes) {
                out_total_reclaimable_bytes -= it->second.deduplicated_allocated_bytes;
                it->second.deduplicated_allocated_bytes = pref.allocated_bytes;
                out_total_reclaimable_bytes += pref.allocated_bytes;
            }
            if (pref.apparent_bytes > it->second.apparent_bytes) {
                it->second.apparent_bytes = pref.apparent_bytes;
            }
        }
    }

    std::vector<DeletedOpenFileFinding> result;
    result.reserve(deduplicated_map.size() + unallocated_findings.size());
    for (auto& kv : deduplicated_map) {
        result.push_back(std::move(kv.second));
    }
    for (auto& item : unallocated_findings) {
        result.push_back(std::move(item));
    }

    // Sort findings descending by deduplicated allocated bytes
    std::sort(result.begin(), result.end(), [](const DeletedOpenFileFinding& a, const DeletedOpenFileFinding& b) {
        return a.deduplicated_allocated_bytes > b.deduplicated_allocated_bytes;
    });

    return result;
}

std::vector<ProcessRef> ProcInspector::inspect_process(
    int64_t pid,
    const std::string& proc_root,
    bool resolve_user_names,
    bool* out_is_restricted
) {
    if (out_is_restricted) {
        *out_is_restricted = false;
    }

    std::vector<ProcessRef> refs;
    std::string pid_str = std::to_string(pid);
    std::string pid_dir = proc_root + "/" + pid_str;

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
    std::string comm_path = pid_dir + "/comm";
    std::string proc_name = read_first_line(comm_path);
    if (proc_name.empty()) {
        proc_name = "pid:" + pid_str;
    }

    std::string user_name = "unknown";
    if (resolve_user_names) {
        user_name = extract_proc_username(pid_dir + "/status");
    }

    std::string fd_dir_path = pid_dir + "/fd";
    DIR* fd_dir = ::opendir(fd_dir_path.c_str());
    if (!fd_dir) {
        if (errno == EACCES || errno == EPERM) {
            if (out_is_restricted) {
                *out_is_restricted = true;
            }
        }
        // ENOENT / ESRCH means process exited (normal scan race)
        return refs;
    }

    struct dirent* entry = nullptr;
    while ((entry = ::readdir(fd_dir)) != nullptr) {
        const char* name = entry->d_name;
        if (!is_numeric_pid(name)) {
            continue;
        }

        int fd_num = -1;
        try {
            fd_num = std::stoi(name);
        } catch (...) {
            continue;
        }

        std::string fd_link = fd_dir_path + "/" + name;
        char link_target[4096];
        ssize_t len = ::readlink(fd_link.c_str(), link_target, sizeof(link_target) - 1);
        if (len <= 0) {
            // Race: FD closed while inspecting
            continue;
        }
        link_target[len] = '\0';
        std::string target_str(link_target, len);

        std::string orig_path;
        if (!parse_deleted_target(target_str, orig_path)) {
            continue;
        }

        // Query descriptor metadata
        uint64_t dev = 0;
        uint64_t ino = 0;
        uint64_t apparent = 0;
        uint64_t allocated = 0;
        bool stat_ok = false;

        // Try opening descriptor and using fstat() for robustness
        int opened_fd = ::open(fd_link.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        struct stat st;
        if (opened_fd >= 0) {
            if (::fstat(opened_fd, &st) == 0) {
                stat_ok = true;
            }
            ::close(opened_fd);
        }

        // Fallback to stat() directly on procfs fd link
        if (!stat_ok) {
            if (::stat(fd_link.c_str(), &st) == 0) {
                stat_ok = true;
            }
        }

        if (stat_ok) {
            dev = static_cast<uint64_t>(st.st_dev);
            ino = static_cast<uint64_t>(st.st_ino);
            apparent = static_cast<uint64_t>(st.st_size);
            allocated = static_cast<uint64_t>(st.st_blocks) * 512ULL;
        }

        ProcessRef pref;
        pref.pid = pid;
        pref.process_name = proc_name;
        pref.user_name = user_name;
        pref.fd = fd_num;
        pref.target_hint = target_str;
        pref.device_id = dev;
        pref.inode = ino;
        pref.apparent_bytes = apparent;
        pref.allocated_bytes = allocated;

        refs.push_back(std::move(pref));
    }

    ::closedir(fd_dir);

#elif defined(_WIN32)
    // Windows/Mock inspection support
    (void)resolve_user_names;
    std::string comm_path = pid_dir + "/comm";
    std::string proc_name = read_first_line(comm_path);
    if (proc_name.empty()) {
        proc_name = "pid:" + pid_str;
    }
    std::string user_name = "user";

    std::string fd_dir_path = pid_dir + "/fd";
    std::string search_pattern = fd_dir_path + "/*";
    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(search_pattern.c_str(), &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED && out_is_restricted) {
            *out_is_restricted = true;
        }
        return refs;
    }

    do {
        const char* name = ffd.cFileName;
        if (!is_numeric_pid(name)) {
            continue;
        }
        int fd_num = std::stoi(name);
        std::string fd_link = fd_dir_path + "/" + name;

        // In mock testing, the file in fd/ contains the simulated target hint
        std::string target_str = read_first_line(fd_link);
        std::string orig_path;
        if (parse_deleted_target(target_str, orig_path)) {
            ProcessRef pref;
            pref.pid = pid;
            pref.process_name = proc_name;
            pref.user_name = user_name;
            pref.fd = fd_num;
            pref.target_hint = target_str;
            pref.device_id = 1;
            pref.inode = static_cast<uint64_t>(pid * 1000 + fd_num);
            pref.apparent_bytes = 10485760; // 10 MB default mock size
            pref.allocated_bytes = 10485760;
            refs.push_back(std::move(pref));
        }
    } while (FindNextFileA(hFind, &ffd) != 0);

    FindClose(hFind);
#endif

    return refs;
}

ProcScanResult ProcInspector::scan(
    const ProcScanOptions& options,
    const std::atomic<bool>* cancel_token,
    ProgressCallback progress_cb
) {
    auto start_time = std::chrono::steady_clock::now();

    ProcScanResult result;
    result.is_cancelled = false;
    result.success = false;

    ProcScanProgress progress;
    progress.pids_scanned = 0;
    progress.open_fds_inspected = 0;
    progress.deleted_files_found = 0;
    progress.restricted_pids_count = 0;
    progress.current_pid = 0;

    std::vector<ProcessRef> raw_refs;

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
    DIR* proc_dir = ::opendir(options.proc_root.c_str());
    if (!proc_dir) {
        result.error_message = "Failed to open proc root: " + options.proc_root +
                               " (" + std::strerror(errno) + ")";
        result.success = false;
        return result;
    }

    struct dirent* entry = nullptr;
    while ((entry = ::readdir(proc_dir)) != nullptr) {
        if (cancel_token && cancel_token->load(std::memory_order_relaxed)) {
            result.is_cancelled = true;
            break;
        }

        const char* name = entry->d_name;
        if (!is_numeric_pid(name)) {
            continue;
        }

        int64_t pid = 0;
        try {
            pid = std::stoll(name);
        } catch (...) {
            continue;
        }

        progress.pids_scanned++;
        progress.current_pid = pid;

        bool is_restricted = false;
        std::vector<ProcessRef> proc_refs = inspect_process(
            pid,
            options.proc_root,
            options.resolve_user_names,
            &is_restricted
        );

        if (is_restricted) {
            result.restricted_pids.push_back(pid);
            progress.restricted_pids_count++;
        }

        for (auto& r : proc_refs) {
            raw_refs.push_back(std::move(r));
            progress.deleted_files_found++;
        }

        if (progress_cb && (progress.pids_scanned % 20 == 0)) {
            progress_cb(progress);
        }
    }

    ::closedir(proc_dir);

#elif defined(_WIN32)
    // Windows/Mock procfs scanning
    std::string search_pattern = options.proc_root + "/*";
    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(search_pattern.c_str(), &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        result.error_message = "Cannot open proc directory: " + options.proc_root;
        result.success = false;
        return result;
    }

    do {
        if (cancel_token && cancel_token->load(std::memory_order_relaxed)) {
            result.is_cancelled = true;
            break;
        }

        const char* name = ffd.cFileName;
        if (!is_numeric_pid(name)) {
            continue;
        }

        int64_t pid = std::stoll(name);
        progress.pids_scanned++;
        progress.current_pid = pid;

        bool is_restricted = false;
        std::vector<ProcessRef> proc_refs = inspect_process(
            pid,
            options.proc_root,
            options.resolve_user_names,
            &is_restricted
        );

        if (is_restricted) {
            result.restricted_pids.push_back(pid);
            progress.restricted_pids_count++;
        }

        for (auto& r : proc_refs) {
            raw_refs.push_back(std::move(r));
            progress.deleted_files_found++;
        }

        if (progress_cb && (progress.pids_scanned % 20 == 0)) {
            progress_cb(progress);
        }
    } while (FindNextFileA(hFind, &ffd) != 0);

    FindClose(hFind);
#endif

    // Deduplicate discovered references by (device_id, inode)
    result.findings = deduplicate_findings(raw_refs, result.total_reclaimable_bytes);

    auto end_time = std::chrono::steady_clock::now();
    result.scan_duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time
    ).count();
    result.success = !result.is_cancelled;

    if (progress_cb) {
        progress_cb(progress);
    }

    return result;
}

} // namespace ghostdisk
