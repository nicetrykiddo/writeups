---
title: CREST CTF - transmission.log
date: 2026-02-28 19:00:00 +0530
categories:
  - CTF
  - Crest CTF
tags:
  - crypto
  - rsa
  - reuse
---

**Challenge:** transmission.log \[Handshake Reuse / Shadow Protocol]
**Category:** Crypto
**Difficulty:** Easy (once you notice the reuse)
**Flag:** `CREST{mantis_reused_the_channel@ghost!}`

---

## Overview

This log is trying *really hard* to look like “hybrid quantum-resistant handshake” noise, but the actual bug is classic: a **session-unique element is reused**.

In RSA terms, the key tell is:

> Two different sessions encrypt the **same plaintext** using the **same modulus `n`** but **different public exponents** (`e1`, `e2`).
> If `gcd(e1, e2) = 1`, you can recover the plaintext directly via the **Common Modulus Attack**.

The decoys are there to waste time (and one of them is hilariously obvious once you spot it).

---

## 1) File triage (what am I looking at?)

```bash
$ cd /mnt/data

$ file transmissions.log
transmissions.log: ASCII text, with very long lines (820)

$ wc -l transmissions.log
63 transmissions.log
```

Find session boundaries:

```bash
$ grep -n '^--- session:' transmissions.log
1:--- session:alpha ---
6:--- session:delta ---
19:--- session:gamma ---
33:--- session:zeta ---
46:--- session:beta ---
59:--- session:epsilon ---
```

Quick peek at the structure (trimmed so we don't dump walls of digits):

```bash
$ sed -n '1,8p' transmissions.log | cut -c1-120
--- session:alpha ---
modulus: 0x9f88422369ba94a97497db67fd78a8c88b229821d762a3db4b4593b5a0f69845a995a57e4c5813b7a0c635a7feab6dce74c790afbbb90
exp: 65537
payload: 108753052270017272133204317269909450886819537303210325671970888170802680916046601040015666968618702768811228581

--- session:delta ---
modulus:
20139081987659790741884202382451204551095902301026932836217521825584386107257125
```

So each session gives me:

- `modulus` (sometimes hex, sometimes decimal split across lines)
- `exp` (public exponent)
- `payload` (ciphertext; sometimes looks decimal, sometimes base64)

---

## 2) Find “deja vu”: what's reused across sessions?

The fastest way here is to normalize each session's modulus and check duplicates.

```bash
$ python3 - <<'PY'
import re
from pathlib import Path
from collections import defaultdict

text=Path('transmissions.log').read_text()
blocks=re.split(r'\n(?=--- session:)', text.strip())

def parse_mod(block):
    m=re.search(r'modulus:\s*0x([0-9a-fA-F]+)', block)
    if m:
        return int(m.group(1),16)
    m=re.search(r'modulus:\s*\n([0-9\n]+)\nexp:', block)
    if m:
        return int(m.group(1).replace('\n',''))
    return None

def parse_exp(block):
    m=re.search(r'^exp:\s*(\d+)', block, re.M)
    return int(m.group(1)) if m else None

rows=[]
for b in blocks:
    name=re.search(r'^--- session:([a-z]+) ---', b, re.M).group(1)
    rows.append((name, parse_mod(b), parse_exp(b)))

seen=defaultdict(list)
for name,mod,_ in rows:
    seen[mod].append(name)

print('[*] Modulus reuse check:')
for mod,names in sorted(seen.items(), key=lambda x: (-len(x[1]), x[1])):
    if len(names)>1:
        print(f'  - n reused in {names}  (bitlen={mod.bit_length()})')

print('\n[*] n tail comparison (helps spot decoys):')
for name,mod,exp in rows:
    print(f'  {name:8} e={exp:<6} n_tail=...{str(mod)[-12:]}')
PY
[*] Modulus reuse check:
  - n reused in ['alpha', 'gamma']  (bitlen=2048)

[*] n tail comparison (helps spot decoys):
  alpha    e=65537  n_tail=...445039660817
  delta    e=17     n_tail=...441234567890
  gamma    e=31337  n_tail=...445039660817
  zeta     e=65537  n_tail=...767699616799
  beta     e=65537  n_tail=...272574421793
  epsilon  e=65537  n_tail=...228586415009
```

Key observations:

- **`alpha` and `gamma` share the exact same modulus `n`** (2048-bit).
- `delta` looks *almost* the same but ends in `...1234567890` — that's **bait**. I ignore it.

So the “reuse” is: **same modulus across two sessions**, plus they use **different exponents** (`65537` vs `31337`).

That's the common modulus attack setup.

---

## 3) Extract the two ciphertexts (c1, c2)

### Alpha ciphertext (decimal already)

`alpha` payload is directly a decimal integer (ciphertext).

### Gamma ciphertext (base64 → decimal string)

`gamma` payload is base64, and base64-decoding it gives a **decimal string** (still ciphertext, just wrapped).

Here's a quick sanity check:

```bash
$ echo '[*] gamma payload base64 -> decoded decimal preview:' \
  && sed -n '31p' transmissions.log | base64 -d | head -c 120 && echo
[*] gamma payload base64 -> decoded decimal preview:
462847587701490964843532040277313819703711107349332439881550896693759432433474864777381023141269412886469300241983212189
```

So we have:

- same `n`
- `c1 = alpha.payload`
- `c2 = int(base64_decode(gamma.payload))`
- `e1 = 65537`, `e2 = 31337`

---

## 4) Exploit: RSA Common Modulus Attack (why this works)

If:

- `c1 = m^e1 mod n`
- `c2 = m^e2 mod n`
- and `gcd(e1, e2) = 1`

Then there exist integers `a, b` such that:

`a*e1 + b*e2 = 1`

and you can recover:

`m = (c1^a * c2^b) mod n`

If `a` or `b` is negative, you use modular inverses.

---

## 5) Solve script + run

I wrote a small script to parse both sessions, compute Bézout coefficients, recover `m`, then decode the final layers.

```bash
$ ./solve.py
[+] n bits  : 2048
[+] exponents: e1=65537, e2=31337, gcd=1
[+] bezout  : a=3415, b=-7142  (a*e1 + b*e2 = 1)
[+] recovered (ascii preview):
H4sICE3am2kAA2ZsYWcudHh0AHMOcg0Oqc5NzCvJLI4vSi0tTk2JL8lIjU/OSMzLS81xSM/ILy5R
rAUA/OGj+ycAAAA=

[+] flag:
CREST{mantis_reused_the_channel@ghost!}
```

That “ascii preview” blob (`H4sI...`) is a recognizable pattern: it's **base64 of a gzip stream** (classic `H4sI`).

The script base64-decodes it, gunzips it, and the decompressed content is the flag.

---

## Flag

✅ `CREST{mantis_reused_the_channel@ghost!}`

---

## Silent Load (veteran short version)

- Enumerated sessions and normalized RSA moduli.
- Found **modulus reuse** between `alpha` and `gamma`; ignored `delta` since it's a near-copy ending in `...1234567890` (obvious decoy).
- Observed different exponents (`65537`, `31337`) and extracted both ciphertexts (`alpha` decimal payload, `gamma` base64→decimal payload).
- Used **RSA Common Modulus Attack** since `gcd(e1,e2)=1` → Bézout coefficients recover `m = c1^a * c2^b (mod n)`.
- Resulting plaintext was `base64(gzip(flag.txt))` → decoded + decompressed to flag.

---
