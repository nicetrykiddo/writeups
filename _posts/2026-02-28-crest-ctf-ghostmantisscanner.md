---
title: CREST CTF - ghost_mantis_scanner
date: 2026-02-28 19:00:00 +0530
categories:
  - CTF
  - Crest CTF
tags:
  - rev
---

## Overview

This binary spends a lot of time pretending to be a multi-stage interactive
challenge, but the shortest solve path is much more direct: reverse the final
unlock path, understand how the stage results build the decryption key, and
recover the embedded flag offline.

Flag:

```text
CREST{4dv4nc3d_r3v3rs3_m4nt1s_pwn3d!}
```

## What I noticed first

The first pass with `strings` already explains the structure of the challenge.

```bash
$ strings -n 6 rev/ghost_mantis_scanner | grep -E 'MANTIS|ghost|GHOST|Stage|prime|manifest|unlock|dispatch|Protocol|flag'
[!] WARNING: This is a decoy. Real flag requires all stages.
[*] Stage 1: Command validation
[*] Stage 2: Environment analysis
[*] Stage 3: File system integrity check
[*] Stage 4: Mathematical verification
[*] Calculating dispatch index...
[*] Dispatching to unlock module at index: 0x%02X
GHOST_PROTOCOL_2026
.ghost_manifest
MANTIS_AUTH_TOKEN
MANTIS_PRIME_SEQUENCE
```

That is enough to predict the general shape:

- four stage checks
- one global stage counter or key
- a dispatch table that picks the final routine
- one visible decoy path

So instead of trying to satisfy everything dynamically, I started from the stage
handlers and the dispatcher.

## The startup checks are just noise

Early in `main`, the binary runs anti-debug and VM-detection code:

- `ptrace` anti-debugging
- reads `/sys/class/dmi/id/product_name`
- checks for virtualization markers

That is useful context because it tells me dynamic interaction will be noisier
than static analysis. It is not useful solve logic.

So I treated those functions as environment checks and moved on to the stage
logic.

## Decompiler-style view of the stage flow

Once the banner code is stripped away, the main challenge loop is basically:

```c
int run_stages(int argc, char **argv) {
    int passed = 0;

    if (stage1_check(argc > 1 ? argv[1] : NULL))
        passed++;

    if (stage2_check(getenv("MANTIS_AUTH_TOKEN")))
        passed++;

    if (stage3_check())
        passed++;

    if (stage4_check(getenv("MANTIS_PRIME_SEQUENCE")))
        passed++;

    if (passed != 4) {
        run_decoy_path();
        return 0;
    }

    int idx = compute_dispatch_index();
    dispatch_table[idx]();
    return 1;
}
```

That means there are really only two questions:

1. what program state does each stage contribute?
2. what condition causes the dispatcher to call the real unlock routine?

## Stage 1: command-line gate

The first stage is hostile on purpose. In pseudocode it is:

```c
bool stage1_check(char *arg) {
    if (!arg || strlen(arg) != 19)
        return false;

    for (int i = 0; i < 19; i++) {
        if ((arg[i] ^ 0x42) != "GHOST_PROTOCOL_2026"[i])
            return false;
    }

    key |= 0x1000;
    stage1_ok = 1;
    return true;
}
```

I verified the required raw argument with a quick script:

```bash
$ python3 - <<'PY'
from pathlib import Path

blob = Path('rev/ghost_mantis_scanner').read_bytes()
stored = blob[0x3cc5:0x3cc5+0x13]
want = bytes(b ^ 0x42 for b in stored)

print('stored:', stored)
print('required argv[1]:', want)
print('escaped:', ''.join(f'\\x{b:02x}' for b in want))
PY
stored: b'GHOST_PROTOCOL_2026'
required argv[1]: b'\x05\n\r\x11\x16\x1d\x12\x10\r\x16\r\x01\r\x0e\x1dprpt'
escaped: \x05\x0a\x0d\x11\x16\x1d\x12\x10\x0d\x16\x0d\x01\x0d\x0e\x1d\x70\x72\x70\x74
```

That is the point where the intended route became obvious. A stage that wants a
mostly non-printable command-line argument is telling me not to solve the
challenge by hand-feeding the program.

The important part is not the exact input. The important part is:

```text
stage 1 sets bit 0x1000 in the global key
```

## Stage 2: environment token hash

Stage 2 hashes `MANTIS_AUTH_TOKEN` with a custom rolling function and compares
the result against a constant.

```c
uint32_t hash_token(char *s) {
    uint32_t h = 0x811c9dc5;

    while (*s) {
        h ^= (uint8_t)*s++;
        h *= 0x1000193;
        h = rol32(h, 13);
    }

    return h;
}

bool stage2_check(char *token) {
    if (!token)
        return false;

    if (hash_token(token) != 0xc2ce40ec)
        return false;

    key |= 0x2000;
    stage2_ok = 1;
    return true;
}
```

Again, I did not need the preimage. I only needed to understand what a passing
stage contributes.

```text
stage 2 sets bit 0x2000
```

## Stage 3: manifest magic

The third stage is much simpler:

```c
bool stage3_check(void) {
    int fd = open(".ghost_manifest", O_RDONLY);
    uint32_t magic;

    if (fd < 0)
        return false;

    read(fd, &magic, 4);
    close(fd);

    if (magic != 0xdeadc0de)
        return false;

    key |= 0x4000;
    stage3_ok = 1;
    return true;
}
```

So:

```text
stage 3 sets bit 0x4000
```

## Stage 4: "prime sequence" is just 127

Despite the dramatic name, the last stage is just:

```c
bool stage4_check(char *s) {
    if (!s)
        return false;

    if (atoi(s) != 127)
        return false;

    key |= 0x8000;
    stage4_ok = 1;
    return true;
}
```

So:

```text
stage 4 sets bit 0x8000
```

## The important observation: all stages only build one key

Now the whole challenge is much simpler.

Each successful stage only contributes one bit-pattern to the same global value:

- stage 1 -> `0x1000`
- stage 2 -> `0x2000`
- stage 3 -> `0x4000`
- stage 4 -> `0x8000`

So the only fully valid combined key is:

```text
0xf000
```

That is exactly what the real unlock routine checks.

```c
void real_unlock(void) {
    if (!stage1_ok || !stage2_ok || !stage3_ok || !stage4_ok)
        return;

    if (key != 0xf000)
        return;

    ...
}
```

At this point the challenge stops being four separate puzzles. It becomes:

```text
find the relationship between key == 0xf000 and the dispatcher
```

## The dispatcher gives the real index away

The helper that computes the dispatch index is very small:

```c
int compute_dispatch_index(void) {
    if (key != 0xf000)
        return 0xff;

    return ((key >> 8) & 0xff) + 5;
}
```

For `key = 0xf000`:

```text
AH = 0xf0
dispatch index = 0xf0 + 5 = 0xf5
```

That gives the only index I actually care about:

```text
real unlock index = 0xf5
```

The dispatch table builder fills the table mostly with repeated decoy handlers,
then writes the real decryptor into slot `0xf5`.

So the solve path reduces to one sentence:

```text
all four stage bits -> key 0xf000 -> dispatch index 0xf5 -> real decrypt routine
```

## What the real decryptor does

Once I followed the dispatch table to the real target, the rest was straightforward.

The real unlock code:

1. generates a 16-byte keystream from the global key
2. copies four encrypted chunks from `.data`
3. XOR-decrypts each chunk with the keystream
4. concatenates the plaintext chunks into the final flag

In pseudocode it looks like this:

```c
void build_keystream(uint8_t *out, size_t n) {
    uint64_t k = key;

    for (size_t i = 0; i < n; i++) {
        uint8_t part = (i < 8) ? ((k >> (8 * i)) & 0xff) : 0;
        out[i] = part ^ (uint8_t)(i - 0x56);
    }
}

void xor_in_place(uint8_t *buf, size_t len, uint8_t *stream, size_t slen) {
    for (size_t i = 0; i < len; i++)
        buf[i] ^= stream[i % slen];
}

void real_unlock(void) {
    uint8_t ks[16];
    build_keystream(ks, 16);

    xor_in_place(chunk1,  6, ks, 16);   // 0x6034
    xor_in_place(chunk2, 12, ks, 16);   // 0x6028
    xor_in_place(chunk3, 11, ks, 16);   // 0x6018
    xor_in_place(chunk4,  8, ks, 16);   // 0x6010
}
```

The encrypted data in `.data` is:

```bash
$ objdump -s --start-address=0x6010 --stop-address=0x6040 -j .data rev/ghost_mantis_scanner

Contents of section .data:
 6010 f52bdbc3 9dcb91cc 9929df9e f1c284df  .+.......)......
 6020 c682c700 00000000 9e3fda99 c0cc83d5  .........?......
 6030 edc187c3 e909e9fe fad40000 00000000  ................
```

And the four copied chunks are:

- `0x6034`, length `6`
- `0x6028`, length `12`
- `0x6018`, length `11`
- `0x6010`, length `8`

## Reproducing the decrypt offline

After that, I did not need to run the binary at all. I just reimplemented the
decryptor directly against the file contents.

```bash
$ python3 - <<'PY'
from pathlib import Path

blob = Path('rev/ghost_mantis_scanner').read_bytes()

# .data is VA 0x6000 at file offset 0x5000
chunks = [(0x6034, 6), (0x6028, 12), (0x6018, 11), (0x6010, 8)]
key = 0xf000

stream = bytes(
    ((((key >> (8 * i)) if i < 8 else 0) ^ ((i - 0x56) & 0xff)) & 0xff)
    for i in range(16)
)

print("stream", stream.hex(), stream)

parts = []
for va, n in chunks:
    off = 0x5000 + (va - 0x6000)
    pt = bytearray(blob[off:off + n])
    for i in range(n):
        pt[i] ^= stream[i % len(stream)]
    parts.append(bytes(pt))
    print(hex(va), bytes(pt))

print(b"".join(parts).decode())
PY
stream aa5bacadaeafb0b1b2b3b4b5b6b7b8b9 b'\xaa[\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9'
0x6034 b'CREST{'
0x6028 b'4dv4nc3d_r3v'
0x6018 b'3rs3_m4nt1s'
0x6010 b'_pwn3d!}'
CREST{4dv4nc3d_r3v3rs3_m4nt1s_pwn3d!}
```

That is the flag in the exact order the binary would assemble it.

## Final flag

```text
CREST{4dv4nc3d_r3v3rs3_m4nt1s_pwn3d!}
```

## Takeaway

The most useful habit in this challenge was separating "things the binary makes
loud" from "things the binary actually needs."

The real methodology was:

1. ignore anti-analysis noise
2. understand what state each stage contributes
3. notice that every stage only feeds the same key
4. derive the real dispatch index
5. reimplement the decryptor offline
