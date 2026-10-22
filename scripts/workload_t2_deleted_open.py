#!/usr/bin/env python3
"""
GhostDisk Controlled Test Workload T2: Deleted-But-Open File
------------------------------------------------------------
Creates a 10 MB temporary file, holds an open file descriptor,
unlinks the file from the filesystem, outputs PID and path metadata
as JSON to stdout, and sleeps waiting for test inspection.
"""

import os
import sys
import time
import signal
import tempfile
import json

running = True

def handle_signal(sig, frame):
    global running
    running = False

def main():
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # 10 Megabytes allocation
    FILE_SIZE_BYTES = 10 * 1024 * 1024

    # Create temporary file
    temp_dir = tempfile.gettempdir()
    test_filepath = os.path.join(temp_dir, f"ghostdisk_t2_workload_{os.getpid()}.tmp")

    # Write 10 MB
    with open(test_filepath, "wb") as f_prep:
        chunk = b"GHOSTDISK_TEST_DATA_" * 512  # 10240 bytes
        written = 0
        while written < FILE_SIZE_BYTES:
            to_write = min(len(chunk), FILE_SIZE_BYTES - written)
            f_prep.write(chunk[:to_write])
            written += to_write
        f_prep.flush()
        os.fsync(f_prep.fileno())

    # Open file descriptor to retain after unlinking
    open_fd = open(test_filepath, "rb")

    # Unlink file from directory tree while descriptor remains open
    try:
        os.unlink(test_filepath)
    except Exception as e:
        sys.stderr.write(f"Failed to unlink {test_filepath}: {e}\n")
        sys.stderr.flush()

    # Output metadata for test assertions
    metadata = {
        "pid": os.getpid(),
        "original_path": test_filepath,
        "target_hint": f"{test_filepath} (deleted)",
        "fd": open_fd.fileno(),
        "size_bytes": FILE_SIZE_BYTES,
        "status": "ready"
    }

    # Print JSON line for automated parsing
    sys.stdout.write(json.dumps(metadata) + "\n")
    sys.stdout.flush()

    # Keep descriptor open while test runner inspects
    max_sleep = int(os.environ.get("GHOSTDISK_WORKLOAD_TIMEOUT", "60"))
    start_time = time.time()

    while running and (time.time() - start_time < max_sleep):
        time.sleep(0.2)

    # Close descriptor to release storage
    open_fd.close()
    sys.exit(0)

if __name__ == "__main__":
    main()
