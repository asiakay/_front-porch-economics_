// Front Porch Economics — Cloudflare Worker API
// Passkey (WebAuthn) auth, JWT sessions

const SESSION_TTL = 60 * 60 * 24 * 7; // 7 days
const CHALLENGE_TTL = 600; // 10 minutes

const ALLOWED_ORIGINS = new Set([
  'https://frontporcheconomics.com',
  'https://www.frontporcheconomics.com',
  'https://front-porch-economics.pages.dev',
  'http://localhost:8787',
]);

// ─── NORMALIZATION ─────────────────────────────────────────────────────────────

function normalizeEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function normalizePhone(value) {
  if (typeof value !== 'string') return null;
  const raw = value.trim();
  if (!raw) return null;
  const digits = raw.replace(/\D/g, '');
  let normalized;
  if (digits.length === 10) normalized = `+1${digits}`;
  else if (digits.length === 11 && digits.startsWith('1')) normalized = `+${digits}`;
  else if (raw.startsWith('+') && digits.length >= 8 && digits.length <= 15) normalized = `+${digits}`;
  else return null;
  return /^\+[1-9]\d{7,14}$/.test(normalized) ? normalized : null;
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ─── CORS ─────────────────────────────────────────────────────────────────────

function corsHeaders(origin, withCredentials = false) {
  const allowed = ALLOWED_ORIGINS.has(origin) ? origin : 'https://frontporcheconomics.com';
  const h = {
    'Access-Control-Allow-Origin': withCredentials ? allowed : '*',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
  if (withCredentials) h['Access-Control-Allow-Credentials'] = 'true';
  return h;
}

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extra },
  });
}

// ─── JWT (HS256 via Web Crypto) ────────────────────────────────────────────────

function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function fromB64url(str) {
  const padded = str + '=='.slice(0, (4 - (str.length % 4)) % 4);
  return atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
}

function b64urlToBytes(str) {
  return Uint8Array.from(fromB64url(str), c => c.charCodeAt(0));
}

async function signJWT(payload, secret) {
  const enc = s => b64url(new TextEncoder().encode(JSON.stringify(s)));
  const data = `${enc({ alg: 'HS256', typ: 'JWT' })}.${enc(payload)}`;
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return `${data}.${b64url(sig)}`;
}

async function verifyJWT(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [header, body, sig] = parts;
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
  );
  const sigBytes = Uint8Array.from(fromB64url(sig), c => c.charCodeAt(0));
  const valid = await crypto.subtle.verify(
    'HMAC', key, sigBytes, new TextEncoder().encode(`${header}.${body}`)
  );
  if (!valid) return null;
  const payload = JSON.parse(fromB64url(body));
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}

// ─── WEBAUTHN HELPERS ─────────────────────────────────────────────────────────

// Minimal CBOR decoder — handles unsigned ints, negative ints, bytes, text, and maps
function decodeCbor(bytes) {
  if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
  let offset = 0;

  function readLen(info) {
    if (info < 24) return info;
    if (info === 24) return bytes[offset++];
    if (info === 25) { const v = (bytes[offset] << 8) | bytes[offset + 1]; offset += 2; return v; }
    if (info === 26) {
      const v = ((bytes[offset] << 24) | (bytes[offset+1] << 16) | (bytes[offset+2] << 8) | bytes[offset+3]) >>> 0;
      offset += 4; return v;
    }
    throw new Error(`CBOR: unsupported info ${info}`);
  }

  function readItem() {
    const b = bytes[offset++];
    const major = b >> 5;
    const info = b & 0x1f;
    const len = readLen(info);
    switch (major) {
      case 0: return len;
      case 1: return -1 - len;
      case 2: { const s = bytes.slice(offset, offset + len); offset += len; return s; }
      case 3: { const s = new TextDecoder().decode(bytes.slice(offset, offset + len)); offset += len; return s; }
      case 5: {
        const map = {};
        for (let i = 0; i < len; i++) { const k = readItem(); map[k] = readItem(); }
        return map;
      }
      default: throw new Error(`CBOR: unsupported major type ${major}`);
    }
  }

  return readItem();
}

// Parse COSE ES256 key → uncompressed P-256 point (04 || x || y, 65 bytes)
function parseCoseKey(coseBytes) {
  const map = decodeCbor(coseBytes);
  const x = map[-2];
  const y = map[-3];
  if (!x || !y || x.length !== 32 || y.length !== 32) throw new Error('Invalid COSE ES256 key');
  const out = new Uint8Array(65);
  out[0] = 0x04;
  out.set(x, 1);
  out.set(y, 33);
  return out;
}

// Convert DER-encoded ECDSA signature to IEEE P1363 format (r||s, 64 bytes)
function derToRaw(der) {
  let offset = 2; // skip 0x30 <len>
  if (der[1] & 0x80) offset += (der[1] & 0x7f); // long-form length (rare)
  offset++; // skip 0x02
  const rLen = der[offset++];
  const r = der.slice(offset, offset + rLen);
  offset += rLen;
  offset++; // skip 0x02
  const sLen = der[offset++];
  const s = der.slice(offset, offset + sLen);
  const raw = new Uint8Array(64);
  const rTrim = r[0] === 0 ? r.slice(1) : r;
  const sTrim = s[0] === 0 ? s.slice(1) : s;
  raw.set(rTrim, 32 - rTrim.length);
  raw.set(sTrim, 64 - sTrim.length);
  return raw;
}

function getRpId(origin) {
  if (!origin) return 'front-porch-economics.pages.dev';
  try { return new URL(origin).hostname; } catch { return 'front-porch-economics.pages.dev'; }
}

// ─── DB HELPERS ───────────────────────────────────────────────────────────────

const getUserByEmail = (db, email) =>
  db.prepare('SELECT * FROM signups WHERE lower(email) = lower(?)').bind(email).first();

const setUserPhone = (db, email, phone) =>
  db.prepare('UPDATE signups SET phone = ? WHERE lower(email) = lower(?)').bind(phone, email).run();

async function createSession(db, email) {
  const id = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);
  await db.prepare(
    'INSERT INTO sessions (id, email, created_at, expires_at) VALUES (?, ?, ?, ?)'
  ).bind(id, email, now, now + SESSION_TTL).run();
  return id;
}

const getSession = (db, sessionId) => {
  const now = Math.floor(Date.now() / 1000);
  return db.prepare('SELECT * FROM sessions WHERE id = ? AND expires_at > ?')
    .bind(sessionId, now).first();
};

const deleteSession = (db, sessionId) =>
  db.prepare('DELETE FROM sessions WHERE id = ?').bind(sessionId).run();

// ─── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────

export async function requireAuth(request, env) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/(?:^|;\s*)fpe_session=([^;]+)/);
  if (!match) return null;
  const payload = await verifyJWT(match[1], env.JWT_SECRET).catch(() => null);
  if (!payload?.sid || !payload?.sub) return null;
  const session = await getSession(env.DB, payload.sid);
  if (!session) return null;
  if (normalizeEmail(session.email) !== normalizeEmail(payload.sub)) return null;
  return { email: normalizeEmail(session.email), sessionId: payload.sid };
}

// ─── ROUTE HANDLERS ───────────────────────────────────────────────────────────

async function handleSignup(request, env, cors) {
  const body = await request.json();
  const email = normalizeEmail(body.email);
  const phone = normalizePhone(body.phone);
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  const neighborhood = typeof body.neighborhood === 'string' ? body.neighborhood.trim() : '';
  const building = typeof body.building === 'string' ? body.building.trim() : '';

  if (!isValidEmail(email)) return json({ success: false, error: 'Valid email required' }, 400, cors);
  if (!phone) return json({ success: false, error: 'Valid phone number required' }, 400, cors);

  const existing = await getUserByEmail(env.DB, email);
  if (existing) return json({ success: false, error: 'Already on the list.' }, 409, cors);

  try {
    await env.DB.prepare(
      'INSERT INTO signups (email, name, neighborhood, building, phone) VALUES (?, ?, ?, ?, ?)'
    ).bind(email, name || null, neighborhood || null, building || null, phone).run();
    return json({ success: true, message: 'Welcome to the porch.' }, 200, cors);
  } catch (err) {
    if (err.message?.includes('UNIQUE')) return json({ success: false, error: 'Already on the list.' }, 409, cors);
    throw err;
  }
}

async function handlePasskeyRegisterOptions(request, env, cors) {
  const { email } = await request.json();
  const normalEmail = normalizeEmail(email);
  if (!isValidEmail(normalEmail)) return json({ error: 'Valid email required' }, 400, cors);

  const user = await getUserByEmail(env.DB, normalEmail);
  if (!user) return json({ error: 'Email not found. Sign up first.' }, 404, cors);

  const challengeBytes = crypto.getRandomValues(new Uint8Array(32));
  const challenge = b64url(challengeBytes);
  const now = Math.floor(Date.now() / 1000);

  await env.DB.prepare(
    'UPDATE signups SET webauthn_challenge = ?, webauthn_challenge_exp = ? WHERE lower(email) = lower(?)'
  ).bind(challenge, now + CHALLENGE_TTL, normalEmail).run();

  const rpId = getRpId(request.headers.get('Origin') || '');
  const userId = b64url(new TextEncoder().encode(normalEmail));

  return json({
    challenge,
    rp: { id: rpId, name: 'Front Porch Economics' },
    user: { id: userId, name: normalEmail, displayName: user.name || normalEmail },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    timeout: 60000,
    attestation: 'none',
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
  }, 200, cors);
}

async function handlePasskeyRegisterFinish(request, env, cors) {
  const body = await request.json();
  const normalEmail = normalizeEmail(body.email);
  if (!isValidEmail(normalEmail)) return json({ error: 'Valid email required' }, 400, cors);

  const user = await getUserByEmail(env.DB, normalEmail);
  if (!user?.webauthn_challenge) return json({ error: 'No registration in progress.' }, 400, cors);

  const now = Math.floor(Date.now() / 1000);
  if (user.webauthn_challenge_exp < now) return json({ error: 'Registration expired. Try again.' }, 400, cors);

  const clientDataBytes = b64urlToBytes(body.response.clientDataJSON);
  const clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));

  if (clientData.type !== 'webauthn.create') return json({ error: 'Invalid ceremony type.' }, 400, cors);
  if (clientData.challenge !== user.webauthn_challenge) return json({ error: 'Challenge mismatch.' }, 400, cors);

  const origin = request.headers.get('Origin') || '';
  if (!ALLOWED_ORIGINS.has(clientData.origin) && clientData.origin !== origin) {
    return json({ error: 'Origin mismatch.' }, 400, cors);
  }

  const attObjBytes = b64urlToBytes(body.response.attestationObject);
  const attObj = decodeCbor(attObjBytes);
  const authData = attObj['authData'];
  if (!(authData instanceof Uint8Array)) return json({ error: 'Missing authData.' }, 400, cors);

  const rpId = getRpId(origin);
  const rpIdHash = authData.slice(0, 32);
  const expectedRpIdHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId))
  );
  if (!rpIdHash.every((b, i) => b === expectedRpIdHash[i])) {
    return json({ error: 'rpId hash mismatch.' }, 400, cors);
  }

  const flags = authData[32];
  if (!(flags & 0x40)) return json({ error: 'No credential data in authData.' }, 400, cors);

  // attestedCredentialData starts at byte 37: aaguid(16) + credIdLen(2) + credId + coseKey
  const aaguidEnd = 37 + 16;
  const credIdLen = (authData[aaguidEnd] << 8) | authData[aaguidEnd + 1];
  const credIdStart = aaguidEnd + 2;
  const credentialId = authData.slice(credIdStart, credIdStart + credIdLen);
  const credentialIdB64 = b64url(credentialId);

  const coseKeyBytes = authData.slice(credIdStart + credIdLen);
  const pubKeyBytes = parseCoseKey(coseKeyBytes);
  const pubKeyB64 = b64url(pubKeyBytes);

  const transports = Array.isArray(body.response.transports) ? JSON.stringify(body.response.transports) : null;

  await env.DB.prepare(
    'INSERT OR REPLACE INTO passkey_credentials (credential_id, email, public_key, sign_count, transports, created_at) VALUES (?, ?, ?, 0, ?, ?)'
  ).bind(credentialIdB64, normalEmail, pubKeyB64, transports, now).run();

  await env.DB.prepare(
    'UPDATE signups SET webauthn_challenge = NULL, webauthn_challenge_exp = NULL WHERE lower(email) = lower(?)'
  ).bind(normalEmail).run();

  return json({ success: true }, 200, cors);
}

async function handlePasskeyLoginOptions(request, env, cors) {
  const { email } = await request.json();
  const normalEmail = normalizeEmail(email);
  if (!isValidEmail(normalEmail)) return json({ error: 'Valid email required' }, 400, cors);

  const creds = await env.DB.prepare(
    'SELECT credential_id, transports FROM passkey_credentials WHERE lower(email) = lower(?)'
  ).bind(normalEmail).all();

  if (!creds.results?.length) return json({ error: 'No passkey registered for this email. Sign in after registering a passkey.' }, 404, cors);

  const challengeBytes = crypto.getRandomValues(new Uint8Array(32));
  const challenge = b64url(challengeBytes);
  const now = Math.floor(Date.now() / 1000);

  await env.DB.prepare(
    'UPDATE signups SET webauthn_challenge = ?, webauthn_challenge_exp = ? WHERE lower(email) = lower(?)'
  ).bind(challenge, now + CHALLENGE_TTL, normalEmail).run();

  const rpId = getRpId(request.headers.get('Origin') || '');

  return json({
    challenge,
    rpId,
    timeout: 60000,
    allowCredentials: creds.results.map(c => ({
      id: c.credential_id,
      type: 'public-key',
      transports: c.transports ? JSON.parse(c.transports) : [],
    })),
    userVerification: 'preferred',
  }, 200, cors);
}

async function handlePasskeyLoginFinish(request, env, cors) {
  const body = await request.json();
  const normalEmail = normalizeEmail(body.email);
  if (!isValidEmail(normalEmail)) return json({ error: 'Valid email required' }, 400, cors);

  const user = await getUserByEmail(env.DB, normalEmail);
  if (!user?.webauthn_challenge) return json({ error: 'No login in progress.' }, 400, cors);

  const now = Math.floor(Date.now() / 1000);
  if (user.webauthn_challenge_exp < now) return json({ error: 'Challenge expired. Try again.' }, 400, cors);

  const credentialId = body.response.id;
  const cred = await env.DB.prepare(
    'SELECT * FROM passkey_credentials WHERE credential_id = ? AND lower(email) = lower(?)'
  ).bind(credentialId, normalEmail).first();
  if (!cred) return json({ error: 'Credential not found.' }, 404, cors);

  const clientDataBytes = b64urlToBytes(body.response.clientDataJSON);
  const clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));
  if (clientData.type !== 'webauthn.get') return json({ error: 'Invalid ceremony type.' }, 400, cors);
  if (clientData.challenge !== user.webauthn_challenge) return json({ error: 'Challenge mismatch.' }, 400, cors);

  const origin = request.headers.get('Origin') || '';
  if (!ALLOWED_ORIGINS.has(clientData.origin) && clientData.origin !== origin) {
    return json({ error: 'Origin mismatch.' }, 400, cors);
  }

  // signed data = authData || SHA-256(clientDataJSON)
  const authData = b64urlToBytes(body.response.authenticatorData);
  const clientDataHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', clientDataBytes)
  );
  const signedData = new Uint8Array(authData.length + clientDataHash.length);
  signedData.set(authData);
  signedData.set(clientDataHash, authData.length);

  const pubKeyBytes = b64urlToBytes(cred.public_key);
  const cryptoKey = await crypto.subtle.importKey(
    'raw', pubKeyBytes,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, ['verify']
  );
  const sigBytes = b64urlToBytes(body.response.signature);
  const rawSig = derToRaw(sigBytes);
  const valid = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    cryptoKey, rawSig, signedData
  );
  if (!valid) return json({ error: 'Signature verification failed.' }, 401, cors);

  const newSignCount = Number(cred.sign_count || 0) + 1;
  await env.DB.prepare(
    'UPDATE passkey_credentials SET sign_count = ? WHERE credential_id = ?'
  ).bind(newSignCount, credentialId).run();

  await env.DB.prepare(
    'UPDATE signups SET webauthn_challenge = NULL, webauthn_challenge_exp = NULL WHERE lower(email) = lower(?)'
  ).bind(normalEmail).run();

  const canonicalEmail = normalizeEmail(user.email);
  const sessionId = await createSession(env.DB, canonicalEmail);
  const token = await signJWT(
    { sub: canonicalEmail, sid: sessionId, exp: now + SESSION_TTL },
    env.JWT_SECRET
  );

  return json(
    { success: true, email: canonicalEmail, name: user.name },
    200,
    {
      ...cors,
      'Set-Cookie': `fpe_session=${token}; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL}; Path=/`,
    }
  );
}

async function handleLogout(request, env, cors) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/(?:^|;\s*)fpe_session=([^;]+)/);
  if (match) {
    const payload = await verifyJWT(match[1], env.JWT_SECRET).catch(() => null);
    if (payload?.sid) await deleteSession(env.DB, payload.sid);
  }
  return json(
    { success: true },
    200,
    { ...cors, 'Set-Cookie': 'fpe_session=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/' }
  );
}

async function handleMe(request, env, cors) {
  const auth = await requireAuth(request, env);
  if (!auth) return json({ success: false, error: 'Not authenticated' }, 401, cors);

  const user = await getUserByEmail(env.DB, auth.email);
  if (!user) {
    await deleteSession(env.DB, auth.sessionId);
    return json(
      { success: false, error: 'Session is no longer valid' },
      401,
      { ...cors, 'Set-Cookie': 'fpe_session=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/' }
    );
  }

  return json(
    { success: true, email: normalizeEmail(user.email), name: user.name, neighborhood: user.neighborhood, building: user.building },
    200,
    cors
  );
}

// ─── ROUTER ───────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const isAuthRoute = url.pathname.startsWith('/auth/');
    const cors = corsHeaders(origin, isAuthRoute);

    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });

    try {
      if (request.method === 'POST' && url.pathname === '/signup') return await handleSignup(request, env, cors);
      if (request.method === 'POST' && url.pathname === '/auth/passkey/register-options') return await handlePasskeyRegisterOptions(request, env, cors);
      if (request.method === 'POST' && url.pathname === '/auth/passkey/register-finish') return await handlePasskeyRegisterFinish(request, env, cors);
      if (request.method === 'POST' && url.pathname === '/auth/passkey/login-options') return await handlePasskeyLoginOptions(request, env, cors);
      if (request.method === 'POST' && url.pathname === '/auth/passkey/login-finish') return await handlePasskeyLoginFinish(request, env, cors);
      if (request.method === 'POST' && url.pathname === '/auth/logout') return await handleLogout(request, env, cors);
      if (request.method === 'GET' && url.pathname === '/auth/me') return await handleMe(request, env, cors);
      return new Response('Front Porch Economics API', { status: 200 });
    } catch (err) {
      console.error(err);
      return json({ success: false, error: 'Internal server error' }, 500, cors);
    }
  },
};
