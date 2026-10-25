# GhostDisk: Evidence-Based Storage Diagnosis & Safe Recovery

> A Linux-first desktop utility to investigate filesystem storage discrepancies, detect deleted-but-open files, recommend safe recovery, and verify reclaimed storage.

---

## Team Division & Roles

| Member | Role | Key Modules | Status |
| :--- | :--- | :--- | :--- |
| **Member 1** | **OS Telemetry & Directory Crawler Engineer** | `FsScanner`, `DirectoryScanner`, `types.hpp` | Completed |
| **Member 2** | **Linux Process & `/proc` Detective Engineer** | `ProcInspector`, Open-FD detection, T2/T9 | Completed |
| **Member 3** | **Discrepancy & Finding Analysis Engine** | `DiscrepancyAnalyzer`, `FindingAnalyzer`, `analysis_types.hpp` | Completed |
| **Member 4** | **Safe Recovery Coordinator & Verification Service** | `RecoveryCoordinator`, `VerificationService` | Completed |
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

## Member 3 Deliverables

### 1. `DiscrepancyAnalyzer` (`include/ghostdisk/discrepancy_analyzer.hpp`, `src/discrepancy_analyzer.cpp`)
- **Scope Classification & Boundary Verification**:
  - Distinguishes scan coverage: `WholeMount`, `PartOfMount`, `OutsideMount`, and `Unknown`.
  - Normalizes root paths and guards against prefix collision traps (e.g., `/home` vs `/homework`).
  - Sets `comparable = false` when scope is partial, when cross-device boundaries are enabled, or when scans are cancelled.
- **Signed Discrepancy Arithmetic**:
  - Computes `gap_bytes = (int64_t)fs_used_bytes - (int64_t)scan_allocated_bytes`.
  - Distinguishes negative gaps (`ScanExceedsFilesystem`) triggered by concurrent writes, hard links, or sparse/uncommitted blocks.
- **Device-Scoped Evidence Attribution**:
  - Filters deleted-open findings strictly by device ID (`st_dev`) so unlinked files on different filesystems do not skew calculations.
  - Formulates attribution: `explained_bytes = min(max(gap, 0), deleted_open_bytes)`.
  - Formulates remainder: `unresolved_bytes = max(gap, 0) - explained_bytes`.
- **Noise Tolerance & Accounting Caveats**:
  - Applies configurable noise floor (`tolerance_bytes`, `tolerance_fraction`) to ignore normal filesystem metadata/journal fluctuations.
  - Keeps superuser reserve (`reserved_or_unavailable_bytes`) isolated from user-space discrepancy gaps.
  - Captures coverage limitations (skipped directories, restricted PIDs) as explicit caveats.

### 2. `FindingAnalyzer` (`include/ghostdisk/finding_analyzer.hpp`, `src/finding_analyzer.cpp`, `analysis_types.hpp`)
- **Four-Pillar Finding Architecture**:
  - `confirmed_facts`: Strictly direct measurements (exact byte counts, PIDs, file descriptors, inodes).
  - `likely_explanation`: Plausible OS-level interpretation, clearly designated as an interpretation.
  - `limitations`: Inaccessible paths, uninspected processes, scan races, and mount scope boundaries.
  - `recommended_next_step`: Safe, non-destructive operator guidance (e.g. reload or restart daemon); never instructs automated deletion.
- **Strict Safety Invariant**: Never classifies unexplained space as "junk" or "safe to delete". Unresolved gaps remain flagged as investigation targets.
- **Risk & Severity Classification**:
  - Assigns severity (`Info`, `Warning`, `Critical`) based on byte scale and remaining filesystem headroom (escalates to `Critical` if user-available space < 10%).
  - Assigns `RiskLevel` (`Low`, `Medium`, `High`) ensuring user-actionable clarity.
- **JSON Evidence Serialization**:
  - Built-in `json_escape` utility producing RFC 8259-compliant JSON snippets (`evidence_json`) ready for Member 5 SQLite persistence.

---

## Member 4 Deliverables

### 1. `RecoveryCoordinator` (`include/ghostdisk/recovery_coordinator.hpp`, `src/recovery_coordinator.cpp`)
- **Two-Stage Safe Recovery Workflow**:
  - **Stage 1 (Read-Only Preview)**: Inspects target via `lstat()`, verifies allowlist eligibility, captures device/inode/mtime/size, estimates reclaimable bytes, and returns `RecoveryPreview` without modifying data.
  - **Stage 2 (Confirmed Execution)**: Requires explicit `user_confirmed == true`. Rejects directories, symlinks, and paths outside allowlisted roots.
- **Strict Allowlist Enforcement**:
  - Resolves canonical paths to prevent directory traversal (`..`) or symlink redirects escaping approved roots (`~/.cache/ghostdisk_test/`, `/tmp/ghostdisk_test/`).
- **TOCTOU Defense (Time-Of-Check to Time-Of-Use)**:
  - Immediately before unlinking, re-validates identity: device ID (`st_dev`), inode (`st_ino`), size (`st_size`), modification timestamp (`st_mtime`), and non-symlink status. Aborts immediately if the file was modified, swapped, or replaced.
- **Zero Shell Invocation**:
  - Executes deletions strictly via the direct POSIX `unlink()` system call. Never invokes `system('rm ...')` or shell interpreters.
- **No Automatic Process Killing**:
  - Protects running processes; active open-file locks are provided with operator restart instructions rather than process termination signals.

### 2. `VerificationService` (`include/ghostdisk/verification_service.hpp`, `src/verification_service.cpp`)
- **Dynamic Mount Point Resolution**:
  - Resolves the filesystem volume hosting any target path by matching against active mounts.
- **Before-and-After Telemetry**:
  - Samples available space (`available_bytes`) immediately prior to and directly following the unlink operation.
- **Honest Observed Delta Accounting**:
  - Computes `observed_delta_bytes = available_bytes_after - available_bytes_before`.
  - Explains discrepancies in the audit log when observed space change differs from estimated file size (due to concurrent writes, delayed allocation, or other held descriptors).

---

## Controlled Tests Matrix

| Test ID | Scenario | Module | Verified Behavior |
| :--- | :--- | :--- | :--- |
| **T1** | Large file size accounting | `DirectoryScanner` | Reports apparent size vs allocated disk blocks. |
| **T2** | Controlled deleted-open file | `ProcInspector` + Workload | Detects unlinked 10 MB file with PID and deduplicated bytes. |
| **T3** | Inaccessible directory handling | `DirectoryScanner` | Gracefully skips `000` permission subtrees into `skipped_entries`. |
| **T4** | Symlink safety & non-traversal | `DirectoryScanner` | Symlinks marked as `EntryType::Symlink` and not followed into loops. |
| **T6** | Allowlisted cache cleanup & verification | `RecoveryCoordinator`, `VerificationService` | Creates 20 MB file in allowlist, generates preview, unlinks with confirmation, and verifies observed capacity delta. |
| **T7** | TOCTOU race condition abort | `RecoveryCoordinator` | Aborts safely when target is modified, deleted, or swapped between preview and execution. |
| **T8** | Scope, Discrepancy & Finding verification | `DiscrepancyAnalyzer`, `FindingAnalyzer` | Validates signed math, attribution deduplication, tolerance, and caveats across 17 scenarios. |
| **T9** | Unprivileged process inspection | `ProcInspector` | Permission-denied PIDs cleanly logged into `restricted_pids`. |

---

## Build & Test Instructions

### Linux (Ubuntu 20.04/22.04+)
```bash
# Using CMake and CTest (Runs all tests T1 through T9)
mkdir build && cd build
cmake ..
cmake --build .
ctest --output-on-failure

# Or using the automated test suite runner
chmod +x scripts/run_linux_tests.sh
./scripts/run_linux_tests.sh
```

### Direct Compilation with g++
```bash
# Member 1 Tests (Scanners)
g++ -std=c++17 -Iinclude src/fs_scanner.cpp src/directory_scanner.cpp tests/test_scanners.cpp -o test_scanners
./test_scanners

# Member 2 Tests (Proc Inspector)
g++ -std=c++17 -Iinclude src/fs_scanner.cpp src/directory_scanner.cpp src/proc_inspector.cpp tests/test_proc_inspector.cpp -o test_proc_inspector
./test_proc_inspector

# Member 3 Tests (Discrepancy & Finding Analyzer)
g++ -std=c++17 -Iinclude src/fs_scanner.cpp src/directory_scanner.cpp src/proc_inspector.cpp src/discrepancy_analyzer.cpp src/finding_analyzer.cpp tests/test_analyzer.cpp -o test_analyzer
./test_analyzer

# Member 4 Tests (Recovery Coordinator & Verification Service)
g++ -std=c++17 -Iinclude src/fs_scanner.cpp src/directory_scanner.cpp src/proc_inspector.cpp src/discrepancy_analyzer.cpp src/finding_analyzer.cpp src/verification_service.cpp src/recovery_coordinator.cpp tests/test_recovery.cpp -o test_recovery
./test_recovery
```
