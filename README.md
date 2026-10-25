# GhostDisk: Evidence-Based Storage Diagnosis & Safe Recovery

> A Linux-first desktop utility to investigate filesystem storage discrepancies, detect deleted-but-open files, recommend safe recovery, and verify reclaimed storage.

---

## Executive Summary & Principles

GhostDisk explains the discrepancy between filesystem-reported storage usage and apparent directory tree totals. It combines Linux filesystem capacity telemetry, directory metadata analysis, deleted-but-open file discovery via `/proc`, signed discrepancy analysis, safe allowlisted cleanup, post-action capacity verification, a local audit database, and a Qt desktop interface.

### Safety Boundaries & Non-Goals
* **Read-only by default**: Scans and recovery preview generation never mutate data or processes.
* **Never label unexplained space as junk**: Unresolved discrepancies are treated strictly as investigation targets (unscanned subtrees, metadata, snapshots, journal overhead).
* **Zero shell interpolation**: Cleanup occurs exclusively via direct POSIX `unlink()`, never `system('rm ...')` or shell scripts.
* **No automatic process killing**: Processes holding deleted files are identified with operator restart/reload guidance, never terminated automatically.
* **Strict allowlist & TOCTOU defense**: Recovery is strictly confined to approved cache directories (`~/.cache/ghostdisk_test/`, `/tmp/ghostdisk_test/`), requires explicit operator confirmation, and re-validates file identity (device, inode, size, mtime, non-symlink) immediately before unlink.

---

## Team Division & Roles

| Member | Role | Key Modules | Status |
| :--- | :--- | :--- | :--- |
| **Member 1** | **OS Telemetry & Directory Crawler Engineer** | `FsScanner`, `DirectoryScanner`, `types.hpp` | **Completed & Verified** |
| **Member 2** | **Linux Process & `/proc` Detective Engineer** | `ProcInspector`, Open-FD detection, T2/T9 | **Completed & Verified** |
| **Member 3** | **Discrepancy & Finding Analysis Engine** | `DiscrepancyAnalyzer`, `FindingAnalyzer`, `analysis_types.hpp` | **Completed & Verified** |
| **Member 4** | **Safe Recovery Coordinator & Verification Service** | `RecoveryCoordinator`, `VerificationService` | **Completed & Verified** |
| Member 5 | UI, Persistence & Architecture Lead | `MainWindow` (Qt Widgets), `SQLiteRepository` | Planned (Phase 5) |

---

## Controlled Tests Matrix

| Test ID | Scenario | Module | Verified Behavior | Status |
| :--- | :--- | :--- | :--- | :--- |
| **T1** | Large file size accounting | `DirectoryScanner` | Reports apparent size (`st_size`) vs allocated disk blocks (`st_blocks * 512`). | **PASS** |
| **T2** | Controlled deleted-open file | `ProcInspector` + Python Workload | Detects unlinked 10 MB file with PID and deduplicated bytes. | **PASS** |
| **T3** | Inaccessible directory handling | `DirectoryScanner` | Gracefully skips `000` permission subtrees into `skipped_entries`. | **PASS** |
| **T4** | Symlink safety & non-traversal | `DirectoryScanner` | Symlinks marked as `EntryType::Symlink` and not followed into loops. | **PASS** |
| **T6** | Allowlisted cache cleanup & verification | `RecoveryCoordinator`, `VerificationService` | Creates 20 MB file in allowlist, generates preview, unlinks with confirmation, and verifies observed capacity delta. | **PASS** |
| **T7** | TOCTOU race condition abort | `RecoveryCoordinator` | Aborts safely when target is modified, deleted, or swapped between preview and execution. | **PASS** |
| **T8** | Scope, Discrepancy & Finding verification | `DiscrepancyAnalyzer`, `FindingAnalyzer` | Validates signed math, attribution deduplication, tolerance, and caveats across 18 scenarios (including transient growth). | **PASS** |
| **T9** | Unprivileged process inspection | `ProcInspector` | Permission-denied PIDs cleanly logged into `restricted_pids` without crashes. | **PASS** |

---

## How to Run

### Prerequisites
On Linux (Ubuntu 20.04/22.04/24.04) or Windows WSL2:
```bash
sudo apt update && sudo apt install -y build-essential cmake python3
```

---

### 1. Automated Full Test Suite Runner (Recommended)
Run the all-in-one test runner script covering unit tests, CTest, controlled workloads (T2, T3), and safe recovery (T6, T7):

```bash
chmod +x scripts/run_linux_tests.sh
./scripts/run_linux_tests.sh
```

*(From Windows PowerShell via WSL:)*
```powershell
wsl -e bash -c "cd /mnt/c/Project/GHOSTED && ./scripts/run_linux_tests.sh"
```

---

### 2. Standard CMake & CTest Workflow
```bash
# Configure and build
mkdir -p build && cd build
cmake ..
cmake --build .

# Run all automated tests via CTest
ctest --output-on-failure
```

---

### 3. Running Individual Test Executables

After building with CMake (inside the `build/` directory):

```bash
# Member 1 Tests: Filesystem Telemetry & Directory Crawler (T1, T3, T4, Cancellation)
./test_scanners

# Member 2 Tests: Process & Inode Inspector (Deduplication, Mock /proc, T9 Unprivileged Scan)
./test_proc_inspector

# Member 3 Tests: Discrepancy & Finding Analyzer (Scope, Signed Math, Caveats, T8 Bursty Activity)
./test_analyzer

# Member 4 Tests: Safe Recovery Coordinator & Verification Service (Allowlist, TOCTOU Abort T7, T6 Cleanup)
./test_recovery
```

---

### 4. Running the Live Controlled Workload T2 (Deleted-Open File)
To run the automated T2 test against a live background Python workload:

```bash
# In the repository root:
python3 scripts/workload_t2_deleted_open.py &
WORKLOAD_PID=$!

# Run ProcInspector against the workload PID:
GHOSTDISK_TEST_T2_PID="$WORKLOAD_PID" ./build/test_proc_inspector

# Stop the workload after testing:
kill -TERM "$WORKLOAD_PID" 2>/dev/null || true
```

---

### 5. Direct Compilation with `g++` (Without CMake)

If you prefer compiling directly using `g++ -std=c++17`:

```bash
# 1. Member 1: Scanners Test
g++ -std=c++17 -Iinclude src/fs_scanner.cpp src/directory_scanner.cpp tests/test_scanners.cpp -o test_scanners
./test_scanners

# 2. Member 2: Proc Inspector Test
g++ -std=c++17 -Iinclude src/fs_scanner.cpp src/directory_scanner.cpp src/proc_inspector.cpp tests/test_proc_inspector.cpp -o test_proc_inspector
./test_proc_inspector

# 3. Member 3: Discrepancy & Finding Analyzer Test
g++ -std=c++17 -Iinclude src/fs_scanner.cpp src/directory_scanner.cpp src/proc_inspector.cpp src/discrepancy_analyzer.cpp src/finding_analyzer.cpp tests/test_analyzer.cpp -o test_analyzer
./test_analyzer

# 4. Member 4: Recovery Coordinator & Verification Service Test
g++ -std=c++17 -Iinclude src/fs_scanner.cpp src/directory_scanner.cpp src/proc_inspector.cpp src/discrepancy_analyzer.cpp src/finding_analyzer.cpp src/verification_service.cpp src/recovery_coordinator.cpp tests/test_recovery.cpp -o test_recovery
./test_recovery
```

---

## Module Deliverables Overview

### Member 1 — Telemetry & Directory Crawler
* **`FsScanner`** (`include/ghostdisk/fs_scanner.hpp`, `src/fs_scanner.cpp`):
  * Reads `statvfs()` capacity metrics: total, used, raw-free, user-available, and reserved/unavailable bytes.
  * Discovers mounted filesystems dynamically from `/proc/mounts`, filtering pseudo-filesystems (`proc`, `sysfs`, `cgroup`).
  * Byte notation formatting (`B`, `KB`, `MB`, `GB`, `TB`).
* **`DirectoryScanner`** (`include/ghostdisk/directory_scanner.hpp`, `src/directory_scanner.cpp`):
  * Traverses directories with `lstat()`, avoiding recursive symlink loops.
  * Tracks both apparent size (`st_size`) and physical allocated size (`st_blocks * 512`).
  * Enforces device boundaries via `st_dev`.
  * Records unreadable paths non-fatally into `skipped_entries`.
  * Cancellation (`std::atomic<bool>`) and progress callbacks (`ScanProgress`).

### Member 2 — Process & Inode Detective
* **`ProcInspector`** (`include/ghostdisk/proc_inspector.hpp`, `src/proc_inspector.cpp`):
  * Scans numeric PIDs in `/proc`.
  * Inspects `/proc/<pid>/fd/` descriptors via `readlink()` looking for `' (deleted)'`.
  * Inspects descriptor metadata (`st_dev`, `st_ino`, `st_size`, `st_blocks * 512`).
  * Deduplicates findings by `(device_id, inode)` pairs to prevent double-counting storage across multiple references.
  * Captures permission-restricted PIDs gracefully into `restricted_pids`.
* **Controlled Workload T2** (`scripts/workload_t2_deleted_open.py`):
  * Creates a 10 MB temporary file, holds an open descriptor, unlinks it, outputs metadata as JSON, and sleeps for verification.

### Member 3 — Discrepancy & Finding Analysis
* **`DiscrepancyAnalyzer`** (`include/ghostdisk/discrepancy_analyzer.hpp`, `src/discrepancy_analyzer.cpp`):
  * Scope classification (`WholeMount`, `PartOfMount`, `OutsideMount`, `Unknown`).
  * Signed arithmetic: `gap = fs_used - scan_allocated`.
  * Filters deleted-open findings to the target device ID and bounds explained storage.
  * Applies configurable noise floor (`tolerance_bytes`, `tolerance_fraction`).
* **`FindingAnalyzer`** (`include/ghostdisk/finding_analyzer.hpp`, `src/finding_analyzer.cpp`, `analysis_types.hpp`):
  * Four-pillar finding structure: `confirmed_facts`, `likely_explanation`, `limitations`, `recommended_next_step`.
  * Golden safety invariant: Unresolved space is never labeled as "junk" or "safe to delete".
  * Assigns severity (`Info`, `Warning`, `Critical`) and `RiskLevel` (`Low`, `Medium`, `High`).
  * RFC 8259-compliant JSON serialization (`evidence_json`) ready for persistence.

### Member 4 — Safe Recovery & Verification
* **`RecoveryCoordinator`** (`include/ghostdisk/recovery_coordinator.hpp`, `src/recovery_coordinator.cpp`):
  * Stage 1 preview: Read-only `lstat()`, canonical path allowlist validation (`~/.cache/ghostdisk_test/`, `/tmp/ghostdisk_test/`), estimate reclaimable bytes.
  * Stage 2 execution: Requires explicit `user_confirmed == true`.
  * Revalidates device, inode, size, mtime, and non-symlink status immediately before unlink (TOCTOU defense).
  * Direct POSIX `unlink()`, zero shell invocation.
* **`VerificationService`** (`include/ghostdisk/verification_service.hpp`, `src/verification_service.cpp`):
  * Samples capacity before and after recovery actions.
  * Measures observed delta (`available_after - available_before`) and logs an honest audit trail.
