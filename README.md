# GhostDisk: Evidence-Based Storage Diagnosis & Safe Recovery

> A Linux-first desktop utility to investigate filesystem storage discrepancies, detect deleted-but-open files, recommend safe recovery, and verify reclaimed storage.

---

## Team Division & Roles

| Member | Role | Key Modules |
| :--- | :--- | :--- |
| **Member 1 (Current)** | **OS Telemetry & Directory Crawler Engineer** | `FsScanner`, `DirectoryScanner`, `types.hpp` |
| Member 2 | Linux Process & `/proc` Detective Engineer | `ProcInspector`, Open-FD detection |
| Member 3 | Discrepancy & Finding Analysis Engine | `FindingAnalyzer`, `DiscrepancyAnalyzer` |
| Member 4 | Safe Recovery Coordinator & Verification Service | `RecoveryCoordinator`, `VerificationService` |
| Member 5 | UI, Persistence & Architecture Lead | `MainWindow` (Qt Widgets), `SQLiteRepository` |

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

## Controlled Tests Owned

- **T1 (Large File Allocation)**: Tests apparent size vs allocated disk block count on known sample files.
- **T3 (Permission Denied)**: Verifies that inaccessible subtrees are gracefully skipped and recorded in `skipped_entries`.
- **T4 (Symlink & Boundary Handling)**: Confirms symlinks are recorded as `EntryType::Symlink` and not traversed.

---

## Build & Test Instructions

### Linux (Ubuntu 20.04/22.04+)
```bash
# Using CMake
mkdir build && cd build
cmake ..
cmake --build .
ctest --output-on-failure

# Or using the automated test script
chmod +x scripts/run_linux_tests.sh
./scripts/run_linux_tests.sh
```

### Direct Compilation with g++
```bash
g++ -std=c++17 -Iinclude src/fs_scanner.cpp src/directory_scanner.cpp tests/test_scanners.cpp -o test_scanners
./test_scanners
```
