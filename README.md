# GhostDisk: Evidence-Based Storage Diagnosis & Safe Recovery

> A Linux-first desktop utility to investigate filesystem storage discrepancies, detect deleted-but-open files, recommend safe recovery, and verify reclaimed storage.

---

## Team Division & Roles

| Member | Role | Key Modules | Status |
| :--- | :--- | :--- | :--- |
| **Member 1** | **OS Telemetry & Directory Crawler Engineer** | `FsScanner`, `DirectoryScanner`, `types.hpp` | Completed |
| **Member 2** | **Linux Process & `/proc` Detective Engineer** | `ProcInspector`, Open-FD detection, T2/T9 | Completed |
| Member 3 | Discrepancy & Finding Analysis Engine | `FindingAnalyzer`, `DiscrepancyAnalyzer` | Planned |
| Member 4 | Safe Recovery Coordinator & Verification Service | `RecoveryCoordinator`, `VerificationService` | Planned |
| Member 5 | UI, Persistence & Architecture Lead | `MainWindow` (Qt Widgets), `SQLiteRepository` | Planned |

---

## Member 1 Deliverables

### 1. `FsScanner` (`include/ghostdisk/fs_scanner.hpp`, `src/fs_scanner.cpp`)
- Reads filesystem capacity via Linux `statvfs()`:
  - `total_bytes = f_blocks * f_frsize`
  - `raw_free_bytes = f_bfree * f_frsize`
  - `available_bytes = f_bavail * f_frsize` (unprivileged user space)
  - `used_bytes = total_bytes - raw_free_bytes`
  - `reserved_or_unavailable_bytes = raw_free_bytes - available_bytes`
- Discovers mounted filesystems dynamically by parsing `/proc/mounts` and filtering pseudo-filesystems (`proc`, `sysfs`, `cgroup`, etc.).
- Formats bytes into human-readable notation (`B`, `KB`, `MB`, `GB`, `TB`).

### 2. `DirectoryScanner` (`include/ghostdisk/directory_scanner.hpp`, `src/directory_scanner.cpp`)
- **Symlink Safety**: Traverses directory subtrees using `lstat()` to ensure symlinks are never followed recursively into directory loops.
- **Size Distinction**:
  - `apparent_bytes` (`st_size`)
  - `allocated_bytes` (`st_blocks * 512`)
- **Mount Boundary Detection**: Checks `st_dev` against the scan root and stops when `cross_device_boundaries == false`.
- **Skipped Path Tracking**: Records unreadable or permission-denied directories without crashing.
- **Asynchronous Ready**: Supports cooperative cancellation tokens (`std::atomic<bool>`) and periodic progress callbacks (`ScanProgress`).

---

## Member 2 Deliverables

### 1. `ProcInspector` (`include/ghostdisk/proc_inspector.hpp`, `src/proc_inspector.cpp`)
- **Process Enumeration**: Traverses `/proc` accepting only valid numeric PID directories.
- **FD Inspection**: Examines `/proc/<pid>/fd/` descriptors and uses `readlink()` to identify targets ending in the exact suffix `' (deleted)'`.
- **Metadata Extraction**: Opens `/proc/<pid>/fd/<fd>` and runs `fstat()` (with `stat()` link fallback) to collect `st_dev`, `st_ino`, `st_size`, and `st_blocks * 512`.
- **Inode Deduplication**: Deduplicates findings by `(device_id, inode)` pairs so multiple processes/FDs holding the same unlinked file count its allocated storage only once.
- **Race & Permission Resilience**: Non-fatally handles `ENOENT`/`ESRCH` process races and logs permission-denied processes in `restricted_pids` without crashing.
- **Process & User Resolution**: Extracts process names from `/proc/<pid>/comm` and resolves usernames from UID lines in `/proc/<pid>/status`.

### 2. Controlled Test Workload T2 (`scripts/workload_t2_deleted_open.py`)
- Python test workload creating a 10 MB temporary file, opening a file descriptor, unlinking it from the filesystem, and outputting JSON metadata for automated test verification.

---

## Controlled Tests Matrix

| Test ID | Scenario | Module | Verified Behavior |
| :--- | :--- | :--- | :--- |
| **T1** | Large file size accounting | `DirectoryScanner` | Reports apparent size vs allocated disk blocks. |
| **T2** | Controlled deleted-open file | `ProcInspector` + Workload | Detects unlinked 10 MB file with PID and deduplicated bytes. |
| **T3** | Inaccessible directory handling | `DirectoryScanner` | Gracefully skips `000` permission subtrees into `skipped_entries`. |
| **T4** | Symlink safety & non-traversal | `DirectoryScanner` | Symlinks marked as `EntryType::Symlink` and not followed into loops. |
| **T9** | Unprivileged process inspection | `ProcInspector` | Permission-denied PIDs cleanly logged into `restricted_pids`. |

---

## Build & Test Instructions

### Linux (Ubuntu 20.04/22.04+)
```bash
# Using CMake and CTest
mkdir build && cd build
cmake ..
cmake --build .
ctest --output-on-failure

# Or using the automated test suite runner (runs T1, T2, T3, T4, T9)
chmod +x scripts/run_linux_tests.sh
./scripts/run_linux_tests.sh
```

### Direct Compilation with g++
```bash
# Member 1 Tests
g++ -std=c++17 -Iinclude src/fs_scanner.cpp src/directory_scanner.cpp tests/test_scanners.cpp -o test_scanners
./test_scanners

# Member 2 Tests
g++ -std=c++17 -Iinclude src/fs_scanner.cpp src/directory_scanner.cpp src/proc_inspector.cpp tests/test_proc_inspector.cpp -o test_proc_inspector
./test_proc_inspector
```
