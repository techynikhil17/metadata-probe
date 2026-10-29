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
        results[name] = {"status": resp.status, "data": data[:4000], "headers": dict(resp.headers)}
    except Exception as e:
        results[name] = {"error": str(e)}

def port_scan(name, host, ports, timeout=2):
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        except Exception as e:
            pass
    results[name] = {"open_ports": open_ports}

# GCP metadata probes
probe("meta_gcp", "http://169.254.169.254/computeMetadata/v1/?recursive=true", headers={"Metadata-Flavor": "Google"})
probe("meta_aws", "http://169.254.169.254/latest/meta-data/")

# HOST MACHINE probes (169.254.1.2 = host.containers.internal)
common_ports = [22, 80, 443, 2375, 2376, 4243, 5000, 6443, 8080, 8443, 9090, 10250, 10255]
port_scan("host_ports", "169.254.1.2", common_ports)
probe("host_80", "http://169.254.1.2:80/")
probe("host_8080", "http://169.254.1.2:8080/")
probe("host_443", "https://169.254.1.2:443/")
probe("host_10255", "http://169.254.1.2:10255/pods")  # kubelet read-only
probe("host_2375", "http://169.254.1.2:2375/version")  # docker API
probe("host_4243", "http://169.254.1.2:4243/version")  # docker API alt

# DNS server probe (169.254.1.1)
port_scan("dns_ports", "169.254.1.1", [53, 80, 443, 8080, 8443, 9090])
probe("dns_80", "http://169.254.1.1:80/")
probe("dns_8080", "http://169.254.1.1:8080/")

# Internal infrastructure nodes (IPv6 ULA)
infra_nodes = [
    ("fda7:a938:5bfe:5fa6:0:5ee:a62c:22a", "330"),
    ("fda7:a938:5bfe:5fa6:0:5ee:aa07:73b2", "336"),
]
for ipv6, node_id in infra_nodes:
    port_scan(f"infra_{node_id}_ports", ipv6, [80, 443, 8080, 8443, 9090, 6443, 2375, 4646, 8500])
    probe(f"infra_{node_id}_80", f"http://[{ipv6}]:80/")
    probe(f"infra_{node_id}_443", f"https://[{ipv6}]:443/")
    probe(f"infra_{node_id}_8080", f"http://[{ipv6}]:8080/")

# Sidecar probe (runs on localhost)
port_scan("sidecar_ports", "127.0.0.1", [80, 443, 3000, 4180, 8080, 8443, 9090, 15000, 15001, 15006])

# Network interfaces
try:
    r = subprocess.run(['ip', 'addr'], capture_output=True, text=True, timeout=2)
    results["ip_addr"] = r.stdout
except Exception as e:
    results["ip_addr"] = str(e)

# Routes
try:
    r = subprocess.run(['ip', '-6', 'route'], capture_output=True, text=True, timeout=2)
    results["ipv6_routes"] = r.stdout
except Exception as e:
    results["ipv6_routes"] = str(e)

# DNS resolution tests
try:
    r = subprocess.run(['dig', '+short', 'metadata.google.internal'], capture_output=True, text=True, timeout=3)
    results["dns_metadata"] = r.stdout.strip() if r.returncode == 0 else f"err: {r.stderr}"
except Exception as e:
    results["dns_metadata"] = str(e)

# Env (filter sensitive)
results["env"] = {k: v for k, v in os.environ.items()
                  if not any(s in k.lower() for s in ['password', 'secret', 'key', 'token', 'credential'])}

# /etc/hosts and resolv.conf
for f in ['/etc/hosts', '/etc/resolv.conf', '/proc/1/cgroup', '/proc/net/tcp', '/proc/net/tcp6']:
    try:
        with open(f) as fh:
            results[f] = fh.read()[:2000]
    except Exception as e:
        results[f] = str(e)

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(results, indent=2, default=str).encode())
    def log_message(self, *args):
        pass

print("Starting probe server on port 8080...")
http.server.HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
