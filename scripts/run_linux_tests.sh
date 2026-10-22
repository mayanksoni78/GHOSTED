#!/usr/bin/env bash
set -euo pipefail

echo "=========================================="
echo " GhostDisk - Test Suite (Member 1 & 2)"
echo "=========================================="

mkdir -p build
cd build
cmake ..
cmake --build .

echo ""
echo ">>> Running C++ Unit Tests (T1, T4, Inode Deduplication, Mock Proc, Cancellation)..."
ctest --output-on-failure

echo ""
echo ">>> Running Controlled Workload T3 (Unreadable / Permission-Denied Path)..."
DISPOSABLE_DIR=$(mktemp -d -t ghostdisk_t3_XXXXXX)
mkdir -p "$DISPOSABLE_DIR/readable_dir"
touch "$DISPOSABLE_DIR/readable_dir/file1.txt"
mkdir -p "$DISPOSABLE_DIR/unreadable_dir"
touch "$DISPOSABLE_DIR/unreadable_dir/secret.txt"
chmod 000 "$DISPOSABLE_DIR/unreadable_dir"

# Verify scanner reports skipped path
./test_scanners

# Cleanup
chmod 755 "$DISPOSABLE_DIR/unreadable_dir"
rm -rf "$DISPOSABLE_DIR"

echo ""
echo ">>> Running Controlled Workload T2 (10 MB Deleted-Open File via Python)..."
WORKLOAD_LOG=$(mktemp -t ghostdisk_t2_XXXXXX.json)
python3 ../scripts/workload_t2_deleted_open.py > "$WORKLOAD_LOG" 2>&1 &
WORKLOAD_PID=$!

# Wait for workload to allocate and print JSON metadata
sleep 1
if [ -s "$WORKLOAD_LOG" ]; then
    DETECTED_PID=$(python3 -c "import json; data=json.load(open('$WORKLOAD_LOG')); print(data['pid'])" 2>/dev/null || echo "$WORKLOAD_PID")
    echo "  Spawned Workload T2 process PID: $DETECTED_PID"
    GHOSTDISK_TEST_T2_PID="$DETECTED_PID" ./test_proc_inspector
else
    echo "  Warning: Workload did not output in time; running ProcInspector with PID $WORKLOAD_PID"
    GHOSTDISK_TEST_T2_PID="$WORKLOAD_PID" ./test_proc_inspector
fi

# Cleanup workload process
kill -TERM "$WORKLOAD_PID" 2>/dev/null || true
wait "$WORKLOAD_PID" 2>/dev/null || true
rm -f "$WORKLOAD_LOG"

echo "=========================================="
echo " ALL WORKLOAD TESTS PASSED SUCCESSFULLY!"
echo "=========================================="
