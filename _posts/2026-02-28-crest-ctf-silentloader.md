---
title: CREST CTF - silent_loader
date: 2026-02-28 19:00:00 +0530
categories:
  - CTF
  - Crest CTF
tags:
  - rev
---


This was a small reversing challenge, but it does one useful thing to waste time:
it embeds a string that looks like the answer even though that string is only used
when the flag is printed. The actual solve is recovering the environment variable
that passes the checks.

Flag:

```text
CREST{$il3nt_$tAg3_v3rifi3d}
```

## Solve plan

I approached it like this:

1. do quick triage with `file`, `strings`, and a baseline run
2. reconstruct `main`
3. understand the three helper checks
4. recover the required `GM_STAGE` value
5. run the binary once with the correct environment variable

## 1. Quick triage

I started with the usual first pass from the challenge root.

```bash
$ file rev/silent_loader
rev/silent_loader: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=5990dda4fe02e878d457e07ec3a3ccea33b5f090, for GNU/Linux 3.2.0, stripped

$ strings -n 6 rev/silent_loader | head -n 20
/lib64/ld-linux-x86-64.so.2
strlen
__libc_start_main
__cxa_finalize
getenv
stpcpy
libc.so.6
GLIBC_2.34
GLIBC_2.2.5
D$	CRES
D$SST{$
D$@fi3d
GM_STAGE
No stage configured.
il3nt_$tAg3_v3ri
```

That already gives three useful hints:

- the program reads an environment variable named `GM_STAGE`
- it complains if the variable is missing
- the string `il3nt_$tAg3_v3ri` is probably related to the final flag

Running the binary without any environment variable confirms the first part.

```bash
$ ./rev/silent_loader
No stage configured.
```

So the natural next step is to reconstruct the control flow around `getenv()`.

## 2. Main control flow

Because the binary is tiny and stripped, `objdump` is enough.

```bash
$ objdump -d rev/silent_loader | sed -n '40,95p'
0000000000001080 <.text>:
    1080:	53                   	push   %rbx
    1081:	48 8d 3d 7c 0f 00 00 	lea    0xf7c(%rip),%rdi
    1088:	e8 a3 ff ff ff       	call   1030 <getenv@plt>
    108d:	48 85 c0             	test   %rax,%rax
    1090:	74 37                	je     10c9
    1092:	48 89 c7             	mov    %rax,%rdi
    1095:	48 89 c3             	mov    %rax,%rbx
    1098:	e8 83 01 00 00       	call   1220
    109d:	85 c0                	test   %eax,%eax
    109f:	74 0c                	je     10ad
    10a1:	48 89 df             	mov    %rbx,%rdi
    10a4:	e8 f7 01 00 00       	call   12a0
    10a9:	85 c0                	test   %eax,%eax
    10ab:	75 07                	jne    10b4
    10ad:	b8 01 00 00 00       	mov    $0x1,%eax
    10b2:	5b                   	pop    %rbx
    10b3:	c3                   	ret
    10b4:	48 89 df             	mov    %rbx,%rdi
    10b7:	e8 34 02 00 00       	call   12f0
    10bc:	85 c0                	test   %eax,%eax
    10be:	74 ed                	je     10ad
    10c0:	e8 6b 02 00 00       	call   1330
```

That simplifies to:

```c
char *s = getenv("GM_STAGE");
if (!s) {
    puts("No stage configured.");
    return 1;
}

if (!check1(s)) return 1;
if (!check2(s)) return 1;
if (!check3(s)) return 1;

print_flag();
```

So the whole challenge is really just three small helpers.

## 3. Check 1: length must be 16

The first helper calls `strlen` immediately.

```bash
$ objdump -d rev/silent_loader | sed -n '140,190p'
0000000000001220 <...>:
    1220:	53                   	push   %rbx
    1221:	48 89 fb             	mov    %rdi,%rbx
    1224:	e8 37 fe ff ff       	call   1060 <strlen@plt>
    1229:	48 83 f8 10          	cmp    $0x10,%rax
    122d:	75 61                	jne    1290
```

So the first hard requirement is:

```text
len(GM_STAGE) == 16
```

The rest of the function mixes the bytes into a 32-bit state and stores it in a
global. It does not reject on that state. So I treated `check1` as a length gate
plus setup code for the later routines.

## 4. Check 3: alternating parity

The third helper is much easier to read than the second one, so I looked at it next.

```bash
$ objdump -d rev/silent_loader | sed -n '190,235p'
00000000000012f0 <...>:
    12f0:	0f b6 0f             	movzbl (%rdi),%ecx
    12f3:	48 8d 57 01          	lea    0x1(%rdi),%rdx
    12f7:	48 83 c7 10          	add    $0x10,%rdi
    1300:	89 c8                	mov    %ecx,%eax
    1302:	0f b6 0a             	movzbl (%rdx),%ecx
    1305:	31 c8                	xor    %ecx,%eax
    1307:	a8 01                	test   $0x1,%al
    1309:	74 1d                	je     1328
```

That means adjacent bytes must have different low bits.

In plain English:

- byte 0 and byte 1 must have opposite parity
- byte 1 and byte 2 must have opposite parity
- byte 2 and byte 3 must have opposite parity
- and so on

So the whole 16-byte string must alternate:

```text
even, odd, even, odd, ...
```

or:

```text
odd, even, odd, even, ...
```

That is a very useful reduction in search space.

## 5. Check 2: the real validation

The second helper is where the actual condition lives.

```bash
$ objdump -d rev/silent_loader | sed -n '165,210p'
00000000000012a0 <...>:
    12a0:	be 0b 00 00 00       	mov    $0xb,%esi
    12a5:	4c 8d 47 10          	lea    0x10(%rdi),%r8
    12a9:	ba de c0 37 13       	mov    $0x1337c0de,%edx
    ...
    12cd:	31 d0                	xor    %edx,%eax
    12cf:	c1 c0 05             	rol    $0x5,%eax
    12d2:	8d 90 b9 79 37 9e    	lea    -0x61c88647(%rax),%edx
    ...
    12e5:	81 fa b1 3b ff 46    	cmp    $0x46ff3bb1,%edx
    12eb:	0f 94 c0             	sete   %al
```

After simplifying the loop, the logic is:

```c
state = 0x1337c0de;
for (i = 0; i < 16; i++) {
    tmp = (i + 11) * (signed char)s[i];
    tmp ^= state;
    tmp = rol(tmp, 5);
    state = tmp - 0x61c88647;
}
return state == 0x46ff3bb1;
```

This is the only real obstacle in the binary.

## 6. The string from `strings` is a decoy

The suspicious string from the initial triage is:

```text
il3nt_$tAg3_v3ri
```

At first glance it looks like the answer, but it is not the value of
`GM_STAGE`. It only shows up later when the flag-printing routine builds the
final output.

That was the only trick in the challenge:

- one embedded string belongs to the final flag
- the required input is something else entirely

Once that was clear, the job became: find a 16-byte printable string that
satisfies both the rolling-state check and the alternating-parity rule.

## 7. Recovering `GM_STAGE`

A full brute force over 16 printable bytes is too large, but the state update in
`check2` is reversible. That makes meet-in-the-middle the cleanest practical
solve.

My approach was:

1. generate many valid 8-byte prefixes and store the state after byte 7
2. generate many valid 8-byte suffixes backward from the target state
3. match on the middle state
4. bake the parity rule into candidate generation so every hit already satisfies `check3`

This is the script I used:

```python
import random

MASK = 0xffffffff
C = 0x61c88647
INIT = 0x1337c0de
TARGET = 0x46ff3bb1

PRINT = [c for c in range(0x21, 0x7f)]
BY_PARITY = {
    0: [c for c in PRINT if c % 2 == 0],
    1: [c for c in PRINT if c % 2 == 1],
}

def rol(x, r):
    return ((x << r) & MASK) | (x >> (32 - r))

def ror(x, r):
    return (x >> r) | ((x << (32 - r)) & MASK)

def step_fwd(state, i, b):
    sc = b if b < 0x80 else b - 0x100
    tmp = ((i + 11) * sc) & MASK
    tmp ^= state
    tmp = rol(tmp, 5)
    return (tmp - C) & MASK

def step_back(next_state, i, b):
    sc = b if b < 0x80 else b - 0x100
    tmp = (next_state + C) & MASK
    tmp = ror(tmp, 5)
    return tmp ^ (((i + 11) * sc) & MASK)

def gen_half(start_parity, start_idx, n=8):
    out = []
    for j in range(n):
        parity = start_parity ^ ((start_idx + j) & 1)
        out.append(random.choice(BY_PARITY[parity]))
    return bytes(out)

random.seed(0)

for start_parity in [0, 1]:
    fwd = {}
    for _ in range(300000):
        left = gen_half(start_parity, 0, 8)
        state = INIT
        for i, b in enumerate(left):
            state = step_fwd(state, i, b)
        fwd.setdefault(state, left)

    for _ in range(2000000):
        right = gen_half(start_parity, 8, 8)
        state = TARGET
        for i in range(15, 7, -1):
            state = step_back(state, i, right[i - 8])
        if state in fwd:
            print((fwd[state] + right).decode())
            raise SystemExit
```

It produced:

```text
@%^+TGxSTORG(1&m
```

## 8. Final run

Once I had the stage value, the binary printed the flag immediately.

```bash
$ GM_STAGE='@%^+TGxSTORG(1&m' ./rev/silent_loader
CREST{$il3nt_$tAg3_v3rifi3d}
```

## Final flag

```text
CREST{$il3nt_$tAg3_v3rifi3d}
```

## Takeaway

The challenge was easy once the decoy string was recognized for what it was.
The important workflow was:

- use `strings` to find the input surface
- recover the helper checks from `objdump`
- reduce the search space with the parity rule
- solve the rolling-state check with a small script instead of trying to reason it out by hand
