---
title: CREST CTF - Read Between The Lines
date: 2026-02-28 19:00:00 +0530
categories:
  - CTF
  - Crest CTF
tags:
  - misc
---

## Challenge

We are given a memo file:

```text
misc/challenge_memo.txt
```

Prompt summary:

- The memo looks normal.
- No malicious links or attachments.
- Ghost Mantis is known for hiding signals in plain sight.
- We need to recover the hidden communication.
- Flag format: `CREST{}`

---

## Initial thought process

Since the challenge title is **Read Between The Lines**, I immediately assumed this was not going to be a normal visible-text challenge. The most likely possibilities were:

1. Zero-width Unicode characters
2. Homoglyphs / mixed scripts
3. Whitespace stego
4. Line/word positional encoding
5. A decoy visible layer plus a second real layer

So I started by checking the file type and printing the contents in a way that would expose invisible characters.

---

## Step 1: Basic inspection

I first checked the file size and type:

```bash
$ wc -c misc/challenge_memo.txt
1654 misc/challenge_memo.txt

$ file misc/challenge_memo.txt
misc/challenge_memo.txt: Unicode text, UTF-8 text
```

That already matters because if the file is UTF-8 text, weird Unicode tricks are very possible.

Then I printed the file normally:

```bash
$ sed -n '1,220p' misc/challenge_memo.txt
S‌u​b‌j‌e‌c‌t​:​ F‌a​c‌u​l‌t‌y​ R‌e‌s​е‌a‌r‌c​h‌ c​o‌o​r‌d​i‌n‌a​t​i‌o​n‌

G​e‌n​e‌r‌a‌l​l​y​ s​p‌e​a​k‌i​n​g‌,‌ a​s​ w‌e‌ p‌r​е​p‌а​r‌e‌ f‌o​r​ t‌h​e‌ u​p​c‌o​m​i‌n​g​ i‌n​t‌е​r‌d​i​s​с​i​p‌l​i​n​а‌r​y‌ r‌е‌v​i​e​w‌,‌
a​l‌l‌ d‌o​c​u‌m​е‌n‌t‌a‌t​i‌o‌n‌ m‌u​s‌t​ b​е‌ f​i​n‌а‌l‌i​z‌e​d​ a​n​d​ а‌r​c​h‌i​v​е​d‌ b‌e‌f​o​r‌е‌ t‌h‌e‌ d​e​а​d‌l​i‌n‌e‌.​
с​о‌о‌r‌d‌i‌n‌a‌t​i​o‌n‌ w‌i​t‌h​ d​e‌p​а​r​t‌m‌e​n​t‌ h‌e​а​d​s‌ i​s​ e​x​p​е‌c​tеd withоut еxcеptiоn.

Rеsearсh summaries are tо be submitted bеfоrе thе end оf the month.
all tеams must cоnfirm participatiоn and еnsure аccurасy of reсоrds.
Revisions aftеr submission will not bе асceptеd undеr nоrmal cirсumstanсеs.

In light оf reсеnt schedule сhanges, pleasе accоunt for аdditiоnal review timе.
соntaсt your depаrtmеnt сoordinаtоr if any issues аrise during preparatiоn.
careful аttentiоn tо formatting guidelinеs will be apprеciаted аnd nоtеd.

Many оf you have alrеady completed initial drаfts — thаnk yоu fоr your еffort.
additionаl rеsources are available on the shared faculty portal if needed.
No extensions will be granted except in cases of documented emergencies.

Regards,
Office of Academic Affairs
```

Even from the raw view, two things looked suspicious:

1. There were clearly invisible separators between letters in the first few lines.
2. Some letters looked normal visually but were probably different Unicode code points later in the file.

---

## Step 2: Make invisible characters visible

I used `cat -A` to force weird bytes to show up:

```bash
$ sed -n '1,220p' misc/challenge_memo.txt | cat -A
SM-bM-^@M-^LuM-bM-^@M-^KbM-bM-^@M-^LjM-bM-^@M-^LeM-bM-^@M-^LcM-bM-^@M-^LtM-bM-^@M-^K:M-bM-^@M-^K FM-bM-^@M-^LaM-bM-^@M-^KcM-bM-^@M-^LuM-bM-^@M-^KlM-bM-^@M-^LtM-bM-^@M-^LyM-bM-^@M-^K RM-bM-^@M-^LeM-bM-^@M-^LsM-bM-^@M-^KM-PM-5M-bM-^@M-^LaM-bM-^@M-^LrM-bM-^@M-^LcM-bM-^@M-^KhM-bM-^@M-^L cM-bM-^@M-^KoM-bM-^@M-^LoM-bM-^@M-^KrM-bM-^@M-^LdM-bM-^@M-^KiM-bM-^@M-^LnM-bM-^@M-^LaM-bM-^@M-^KtM-bM-^@M-^KiM-bM-^@M-^LoM-bM-^@M-^KnM-bM-^@M-^L$
...
```

This confirmed that hidden Unicode bytes were all over the text.

At that point I wanted exact code points, not mangled terminal escapes.

---

## Step 3: Count the non-ASCII characters

I ran a short Python script to count non-ASCII characters:

```bash
$ python3 - <<'PY'
from pathlib import Path
from collections import Counter
text = Path('misc/challenge_memo.txt').read_text('utf-8')
nonascii = Counter(ch for ch in text if ord(ch) > 127)
for ch, n in nonascii.most_common():
    print(f'U+{ord(ch):04X} {ch!r} {n}')
PY
U+200B '\\u200b' 101
U+200C '\\u200c' 99
U+0435 'е' 33
U+043E 'о' 23
U+0430 'а' 20
U+0441 'с' 13
U+2014 '—' 1
```

This was the big turning point.

The file contains:

- `U+200B` ZERO WIDTH SPACE
- `U+200C` ZERO WIDTH NON-JOINER
- Cyrillic `е о а с`

That means the file has **two different hidden channels**:

1. Zero-width binary-looking data
2. Mixed-script homoglyph data

That screamed **decoy + real payload**.

---

## Step 4: Confirm where the weird characters are

I printed each line with non-ASCII characters annotated:

```bash
$ python3 - <<'PY'
from pathlib import Path
text = Path('misc/challenge_memo.txt').read_text('utf-8')
for i, line in enumerate(text.splitlines(), 1):
    if any(ord(ch) > 127 for ch in line):
        print('LINE', i)
        print(''.join(f'{ch}(U+{ord(ch):04X}) ' if ord(ch) > 127 else ch for ch in line))
        print()
PY
```

Important observations:

- Lines `1`, `3`, `4`, `5` are full of `U+200B` and `U+200C`.
- Lines `7` onward are full of Cyrillic homoglyphs like:
  - `е` instead of Latin `e`
  - `о` instead of Latin `o`
  - `а` instead of Latin `a`
  - `с` instead of Latin `c`

So the memo absolutely had layered hiding.

---

## Step 5: Decode the zero-width layer first

The zero-width characters are the easiest thing to try first.

I mapped:

- `U+200B` -> `1`
- `U+200C` -> `0`

Actually I tested both directions because either mapping could be correct.

This script was enough:

```bash
$ python3 - <<'PY'
from pathlib import Path
text = Path('misc/challenge_memo.txt').read_text('utf-8')
seq = ''.join('0' if ch == '\u200b' else '1' for ch in text if ch in '\u200b\u200c')
print('len bits', len(seq))

for name, bits in [
    ('200b=0,200c=1', seq),
    ('200b=1,200c=0', ''.join('1' if b == '0' else '0' for b in seq)),
]:
    print('\\n', name)
    for off in range(8):
        s = bits[off:]
        n = len(s) // 8 * 8
        by = bytes(int(s[i:i+8], 2) for i in range(0, n, 8))
        printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in by)
        print('offset', off, printable)
PY
len bits 200

 200b=0,200c=1
offset 0 .........................
offset 1 y[uYW.3.)5A....'A#../.#1
...

 200b=1,200c=0
offset 0 CREST{f4ke_tr41l_n0th1ng}
...
```

So the zero-width channel decodes perfectly to:

```text
CREST{f4ke_tr41l_n0th1ng}
```

At first glance that looks like a flag, but it literally says:

```text
fake_trail_n0th1ng
```

So this is obviously a trap.

That matches the challenge story too: Ghost Mantis is subtle, and this is exactly the kind of bait I would expect in a layered challenge.

So I discarded that as the final answer and moved on.

---

## Step 6: Focus only on the homoglyph layer

Now I needed to inspect the second hidden channel.

I normalized the text by replacing the Cyrillic lookalikes with visible tags:

```bash
$ python3 - <<'PY'
from pathlib import Path
text = Path('misc/challenge_memo.txt').read_text('utf-8')
mapc = {'а':'[a]','е':'[e]','о':'[o]','с':'[c]'}
for i, line in enumerate(text.splitlines(), 1):
    cleaned = ''.join(ch for ch in line if ch not in '\u200b\u200c')
    marked = ''.join(mapc.get(ch, ch) for ch in cleaned)
    print(f'{i:02}: {marked}')
PY
01: Subject: Faculty Res[e]arch coordination
02: 
03: Generally speaking, as we pr[e]p[a]re for the upcoming int[e]rdis[c]iplin[a]ry r[e]view,
04: all docum[e]ntation must b[e] fin[a]lized and [a]rchiv[e]d befor[e] the de[a]dline.
05: [c][o][o]rdination with dep[a]rtment he[a]ds is exp[e]ct[e]d with[o]ut [e]xc[e]pti[o]n.
06: 
07: R[e]sear[c]h summaries are t[o] be submitted b[e]f[o]r[e] th[e] end [o]f the month.
08: all t[e]ams must c[o]nfirm participati[o]n and [e]nsure [a]ccur[a][c]y of re[c][o]rds.
09: Revisions aft[e]r submission will not b[e] [a][c]cept[e]d und[e]r n[o]rmal cir[c]umstan[c][e]s.
10: 
11: In light [o]f re[c][e]nt schedule [c]hanges, pleas[e] acc[o]unt for [a]dditi[o]nal review tim[e].
12: [c][o]nta[c]t your dep[a]rtm[e]nt [c]oordin[a]t[o]r if any issues [a]rise during preparati[o]n.
13: careful [a]ttenti[o]n t[o] formatting guidelin[e]s will be appr[e]ci[a]ted [a]nd n[o]t[e]d.
14: 
15: Many [o]f you have alr[e]ady completed initial dr[a]fts — th[a]nk y[o]u f[o]r your [e]ffort.
16: addition[a]l r[e]sources are available on the shared faculty portal if needed.
17: No extensions will be granted except in cases of documented emergencies.
18: 
19: Regards,
20: Office of Academic Affairs
```

So the second layer is not random at all. It is systematically replacing letters in `a/c/e/o`.

The obvious interpretation is:

- normal Latin letter = `0`
- Cyrillic lookalike = `1`

But the question is: **which characters are carriers?**

That part matters a lot.

---

## Step 7: The wrong way that almost works

My first attempt was to only look at the altered letters themselves and flatten them into bits.

That gave structured data, but not a clean decode.

I also tested:

- byte grouping
- 7-bit ASCII
- Baconian / 5-bit grouping
- line-wise grouping
- grouping only the later paragraph
- grouping only altered words
- symbol-identity encodings using `a/c/e/o`

All of those produced either noise or misleading almost-readable garbage.

That told me the real carrier selection was broader than “only the visibly modified letters”.

---

## Step 8: The actual carrier set

The thing that finally worked was this:

> Use **every ambiguous `a/c/e/o` in the whole memo** as a carrier, not just the Cyrillic ones.

Meaning:

- For every occurrence of `a`, `c`, `e`, `o` (or their Cyrillic lookalikes),
- write `0` if the character is the normal Latin version,
- write `1` if the character is the Cyrillic homoglyph.

That gives one long bitstream.

This exact script extracts it:

```bash
$ python3 - <<'PY'
from pathlib import Path
text = Path('misc/challenge_memo.txt').read_text('utf-8')
trans = {'а':'a','с':'c','е':'e','о':'o','А':'A','С':'C','Е':'E','О':'O'}

bits = []
for ch in text:
    base = trans.get(ch, ch)
    if base.lower() in 'aceo':
        bits.append('1' if ch != base else '0')

bitseq = ''.join(bits)
print('bitlen', len(bitseq))
print(bitseq[:64])
PY
bitlen 276
0000010000000000000011000001111000010011001010010010111000100101
```

Then I grouped those bits into bytes:

```bash
$ python3 - <<'PY'
from pathlib import Path
text = Path('misc/challenge_memo.txt').read_text('utf-8')
trans = {'а':'a','с':'c','е':'e','о':'o','А':'A','С':'C','Е':'E','О':'O'}

bits = []
for ch in text:
    base = trans.get(ch, ch)
    if base.lower() in 'aceo':
        bits.append('1' if ch != base else '0')

bitseq = ''.join(bits)
by = bytes(int(bitseq[i:i+8], 2) for i in range(0, len(bitseq)//8*8, 8))
print(by)
PY
b\"\\x04\\x00\\x0c\\x1e\\x13).%w!=\\x12*f'9v!\\x16:s!\\x16%t z0\\x00\\x00\\x00\\x00\\x00\\x00\"
```

This is not printable, but it is very structured:

- sensible byte length
- clear padding zeros at the end
- not random garbage

So I knew I was close.

---

## Step 9: Recover the XOR key using the known flag prefix

Since the flag format is known, I used the classic known-plaintext trick:

The decoded text should start with:

```text
CREST{
```

So I XORed the first few ciphertext bytes against that prefix.

```bash
$ python3 - <<'PY'
from pathlib import Path
import re

text = Path('misc/challenge_memo.txt').read_text('utf-8')
trans = {'а':'a','с':'c','е':'e','о':'o','А':'A','С':'C','Е':'E','О':'O'}

bits = ''.join(
    '1' if ch != trans.get(ch, ch) else '0'
    for ch in text
    if trans.get(ch, ch).lower() in 'aceo'
)

by = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits)//8*8, 8))
crib = b'CREST{'

for klen in range(1, 9):
    key = [None] * klen
    ok = True
    for i, ch in enumerate(crib):
        kval = by[i] ^ ch
        idx = i % klen
        if key[idx] is None:
            key[idx] = kval
        elif key[idx] != kval:
            ok = False
            break
    print('klen', klen, 'ok', ok, 'key', key)
    if ok:
        keybytes = bytes(k if k is not None else 0 for k in key)
        dec = bytes(by[i] ^ keybytes[i % klen] for i in range(len(by)))
        print('dec', dec[:40])
PY
klen 1 ok False key [71]
klen 2 ok False key [71, 82]
klen 3 ok False key [71, 82, 73]
klen 4 ok True key [71, 82, 73, 77]
dec b'CREST{gh0st_m4nt1s_w4s_h3r3}GRIMGR'
...
```

The key bytes `[71, 82, 73, 77]` are ASCII:

```text
GRIM
```

So the hidden byte stream is XORed with repeating key:

```text
GRIM
```

At that point the plaintext becomes:

```text
CREST{gh0st_m4nt1s_w4s_h3r3}GRIMGR
```

The extra `GRIMGR` at the end is just leftover trailing noise because the bitstream length is not a perfect multiple of the full plaintext structure and the file has padded carriers.

The actual flag is the proper flag-shaped substring:

```text
CREST{gh0st_m4nt1s_w4s_h3r3}
```

---

## Step 10: Final confirmation

I extracted the flag cleanly with one final script:

```bash
$ python3 - <<'PY'
import re
from pathlib import Path

text = Path('misc/challenge_memo.txt').read_text('utf-8')
trans = {'а':'a','с':'c','е':'e','о':'o','А':'A','С':'C','Е':'E','О':'O'}

bits = ''.join(
    '1' if ch != trans.get(ch, ch) else '0'
    for ch in text
    if trans.get(ch, ch).lower() in 'aceo'
)

by = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits)//8*8, 8))
key = b'GRIM'
dec = bytes(b ^ key[i % len(key)] for i, b in enumerate(by))

print(dec)
print(re.search(rb'CREST\\{[^}]+\\}', dec).group(0).decode())
PY
b'CREST{gh0st_m4nt1s_w4s_h3r3}GRIMGR'
CREST{gh0st_m4nt1s_w4s_h3r3}
```

---

## Why the challenge is nice

What makes this challenge good is that it is layered on purpose:

1. The first hidden channel is easy to find.
2. That first channel gives a believable-looking but obviously fake flag:

```text
CREST{f4ke_tr41l_n0th1ng}
```

3. The second hidden channel is harder because it uses:
   - Unicode homoglyphs
   - a wider carrier set than the obvious modified letters
   - XOR after the bit extraction

So the solve is not just “spot invisible chars and decode”.

It is:

1. detect the bait
2. refuse to stop at the bait
3. identify the second Unicode channel
4. choose the correct carrier set
5. extract bits
6. recover XOR key from known flag prefix

That is why the fake flag is actually a clue, not just trolling.

---

## Final flag

```text
CREST{gh0st_m4nt1s_w4s_h3r3}
```
