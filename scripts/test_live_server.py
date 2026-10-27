#!/usr/bin/env python3
import time
import subprocess
import urllib.request
import json
import sys

def test():
    print("[*] Starting web_server.py on port 8085...")
    proc = subprocess.Popen([sys.executable, "web_server.py", "8085"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.5)

    try:
        # Test 1: GET /api/status
        print("[*] Testing GET /api/status...")
        req = urllib.request.urlopen("http://127.0.0.1:8085/api/status", timeout=5)
        status_data = json.loads(req.read().decode('utf-8'))
        print("    -> Response:", status_data)
        assert status_data["status"] == "ready"
        assert status_data["binary_found"] == True

        # Test 2: GET /api/mounts
        print("[*] Testing GET /api/mounts...")
        req_mounts = urllib.request.urlopen("http://127.0.0.1:8085/api/mounts", timeout=5)
        mounts_data = json.loads(req_mounts.read().decode('utf-8'))
        print(f"    -> Found {len(mounts_data)} Linux system mounts")
        assert len(mounts_data) > 0

        # Test 3: POST /api/scan (Trigger real Linux disk scan from browser API)
        print("[*] Testing POST /api/scan (Trigger live Linux disk scan)...")
        post_data = json.dumps({"mount": "/"}).encode('utf-8')
        scan_req = urllib.request.Request("http://127.0.0.1:8085/api/scan", data=post_data, headers={"Content-Type": "application/json"})
        scan_res = urllib.request.urlopen(scan_req, timeout=30)
        scan_json = json.loads(scan_res.read().decode('utf-8'))
        print("    -> Scan Success:", scan_json.get("success"))
        print("    -> Scanned Mount:", scan_json.get("data", {}).get("mount_point"))
        print("    -> Device Name:", scan_json.get("data", {}).get("device_name"))
        print("    -> Filesystem Type:", scan_json.get("data", {}).get("filesystem_type"))
        print("    -> Total Bytes:", scan_json.get("data", {}).get("total_bytes"))
        print("    -> Used Bytes:", scan_json.get("data", {}).get("used_bytes"))
        print("    -> Findings:", len(scan_json.get("data", {}).get("findings", [])))
        assert scan_json.get("success") == True

        print("\n\033[1;32m[✓] ALL LINUX LIVE SERVER & DIAGNOSTICS TESTS PASSED!\033[0m")
    finally:
        proc.terminate()
        proc.wait()

if __name__ == "__main__":
    test()
