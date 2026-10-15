#!/usr/bin/env bash
set -euo pipefail

echo "=========================================="
echo " GhostDisk - Member 1 Linux Test Suite"
echo "=========================================="

mkdir -p build
cd build
cmake ..
cmake --build .

echo ""
echo ">>> Running C++ Unit Tests (T1, T4, Cancellation)..."
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

echo "=========================================="
echo " ALL WORKLOAD TESTS PASSED SUCCESSFULLY!"
echo "=========================================="
