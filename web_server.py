#!/usr/bin/env python3
"""
GHOSTED - Live Diagnostic Dashboard Web Server
Provides a zero-dependency local HTTP server with real-time Linux scan execution.
"""

import os
import sys
import json
import subprocess
import mimetypes
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

ROOT_DIR = Path(__file__).resolve().parent
WEB_UI_DIR = ROOT_DIR / "web_ui"
BUILD_DIR = ROOT_DIR / "build"

def find_cli_binary():
    candidates = [
        BUILD_DIR / "ghostdisk_cli",
        ROOT_DIR / "ghostdisk_cli",
        BUILD_DIR / "Debug" / "ghostdisk_cli.exe",
        BUILD_DIR / "Release" / "ghostdisk_cli.exe",
    ]
    for c in candidates:
        if c.exists() and (os.access(c, os.X_OK) or sys.platform == "win32"):
            return c
    return None

def get_system_mounts():
    mounts = []
    proc_mounts = Path("/proc/mounts")
    if proc_mounts.exists():
        try:
            with open(proc_mounts, "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        dev, mount_pt, fs_type = parts[0], parts[1], parts[2]
                        if fs_type not in ["proc", "sysfs", "devpts", "cgroup", "cgroup2", "autofs", "tracefs", "debugfs", "securityfs", "pstore", "bpf"]:
                            mounts.append({
                                "mount_point": mount_pt,
                                "device_name": dev,
                                "filesystem_type": fs_type
                            })
        except Exception:
            pass
    if not mounts:
        mounts = [
            {"mount_point": "/", "device_name": "/dev/root", "filesystem_type": "ext4"},
            {"mount_point": "/home", "device_name": "/dev/sda2", "filesystem_type": "ext4"},
            {"mount_point": "/tmp", "device_name": "tmpfs", "filesystem_type": "tmpfs"}
        ]
    return mounts

class GhostDiskHandler(BaseHTTPRequestHandler):
    def end_headers(self):
        # Disable browser caching completely to ensure live telemetry displays immediately
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/status":
            cli = find_cli_binary()
            is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
            data = {
                "status": "ready",
                "binary_found": cli is not None,
                "binary_path": str(cli) if cli else None,
                "is_root": is_root,
                "platform": sys.platform
            }
            self.send_json(data)
            return

        if path == "/api/mounts":
            self.send_json(get_system_mounts())
            return

        if path == "/api/live":
            live_json_path = WEB_UI_DIR / "live_data.json"
            if live_json_path.exists():
                try:
                    with open(live_json_path, "r", encoding="utf-8") as f:
                        content = json.load(f)
                    self.send_json(content)
                    return
                except Exception as e:
                    self.send_json({"error": str(e)}, status=500)
                    return
            self.send_json({"error": "No live_data.json found"}, status=404)
            return

        # Serve static web_ui assets
        if path == "/" or path == "":
            path = "/index.html"

        rel_path = path.lstrip("/")
        target_file = (WEB_UI_DIR / rel_path).resolve()

        # Prevent directory traversal
        if not str(target_file).startswith(str(WEB_UI_DIR.resolve())):
            self.send_error(403, "Access Denied")
            return

        if target_file.is_file():
            mime_type, _ = mimetypes.guess_type(target_file)
            if not mime_type:
                if str(target_file).endswith(".js"):
                    mime_type = "application/javascript"
                elif str(target_file).endswith(".json"):
                    mime_type = "application/json"
                elif str(target_file).endswith(".css"):
                    mime_type = "text/css"
                else:
                    mime_type = "application/octet-stream"

            self.send_response(200)
            self.send_header("Content-Type", mime_type)
            with open(target_file, "rb") as f:
                content = f.read()
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_error(404, "File Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/scan":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length > 0 else b"{}"
            try:
                payload = json.loads(body.decode("utf-8")) if body else {}
            except Exception:
                payload = {}

            target_mount = payload.get("mount", "/")
            cli = find_cli_binary()

            if not cli:
                # Try auto-building if cmake build exists
                try:
                    subprocess.run(["cmake", "--build", str(BUILD_DIR)], check=True, cwd=str(ROOT_DIR))
                    cli = find_cli_binary()
                except Exception:
                    pass

            if not cli:
                self.send_json({
                    "success": False,
                    "error": "ghostdisk_cli binary not found. Please compile: cmake -B build && cmake --build build"
                }, status=500)
                return

            try:
                # Run real Linux storage scan
                env = os.environ.copy()
                env["GHOSTDISK_WEB_UI"] = str(WEB_UI_DIR)
                cmd = [str(cli), target_mount, "--export-web"]

                result = subprocess.run(
                    cmd,
                    cwd=str(ROOT_DIR),
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=30
                )

                live_json_path = WEB_UI_DIR / "live_data.json"
                if live_json_path.exists():
                    with open(live_json_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    self.send_json({
                        "success": True,
                        "cli_stdout": result.stdout,
                        "data": data
                    })
                else:
                    self.send_json({
                        "success": False,
                        "error": "Scan finished but live_data.json was not created",
                        "cli_stdout": result.stdout,
                        "cli_stderr": result.stderr
                    }, status=500)

            except subprocess.TimeoutExpired:
                self.send_json({"success": False, "error": "Disk scan timed out (>30s)"}, status=504)
            except Exception as e:
                self.send_json({"success": False, "error": str(e)}, status=500)
            return

        self.send_error(404, "Unknown API route")

    def send_json(self, data, status=200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Clean terminal logging
        sys.stderr.write(f"[{self.log_date_time_string()}] {format % args}\n")

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server_address = ("0.0.0.0", port)
    httpd = HTTPServer(server_address, GhostDiskHandler)
    
    cli = find_cli_binary()
    is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
    
    print("\033[1;36m====================================================================\033[0m")
    print("\033[1;36m   GHOSTED — Haunted Telemetry & Linux Storage Server               \033[0m")
    print("\033[1;36m====================================================================\033[0m")
    print(f"[*] Dashboard URL:     \033[1;32mhttp://localhost:{port}\033[0m")
    print(f"[*] C++ Engine Binary: {'Found (' + str(cli) + ')' if cli else 'Not built yet (run cmake -B build)'}")
    print(f"[*] Privilege Level:   {'Superuser (root)' if is_root else 'Unprivileged (run with sudo for full /proc coverage)'}")
    print(f"[*] Serving web_ui at: {WEB_UI_DIR}")
    print("\nPress Ctrl+C to stop the dashboard server.\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard server...")
        httpd.server_close()

if __name__ == "__main__":
    main()
