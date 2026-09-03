// Front Porch Economics — Cloudflare Worker API
// Shared auth + data layer: JWT sessions, SMS PIN via Twilio, protected route middleware

const SESSION_TTL = 60 * 60 * 24 * 7; // 7 days
const PIN_TTL = 60 * 10;               // 10 minutes
const PIN_MAX_ATTEMPTS = 6;
const PIN_REQUEST_COOLDOWN = 60;        // 60 seconds per account

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

const ALLOWED_ORIGINS = new Set([
  'https://frontporcheconomics.com',
  'https://www.frontporcheconomics.com',
  'https://front-porch-economics.pages.dev',
  'http://localhost:8787',
]);

// ─── CORS ─────────────────────────────────────────────────────────────────────

function corsHeaders(origin, withCredentials = false) {
  const allowed = ALLOWED_ORIGINS.has(origin)
    ? origin
    : 'https://frontporcheconomics.com';
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

// ─── PIN ──────────────────────────────────────────────────────────────────────

function generatePin() {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return String(100000 + (buf[0] % 900000));
}

async function hashPin(pin) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pin));
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// ─── TWILIO ───────────────────────────────────────────────────────────────────

async function sendSMS(to, body, env) {
  if (!env.TWILIO_ACCOUNT_SID || !env.TWILIO_AUTH_TOKEN || !env.TWILIO_FROM_NUMBER) {
    console.error('Twilio secrets not configured');
    return false;
  }
  const url = `https://api.twilio.com/2010-04-01/Accounts/${env.TWILIO_ACCOUNT_SID}/Messages.json`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${btoa(`${env.TWILIO_ACCOUNT_SID}:${env.TWILIO_AUTH_TOKEN}`)}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ To: to, From: env.TWILIO_FROM_NUMBER, Body: body }),
  });
  if (!res.ok) console.error('Twilio error:', await res.text());
  return res.ok;
}

// ─── DB HELPERS ───────────────────────────────────────────────────────────────

const getUserByEmail = (db, email) =>
  db.prepare('SELECT * FROM signups WHERE lower(email) = lower(?)').bind(email).first();

const setUserPin = (db, email, pinHash, expiresAt, attempts = 0, requestedAt = null) =>
  db.prepare('UPDATE signups SET pin = ?, pin_expires_at = ?, pin_attempts = ?, pin_requested_at = ? WHERE lower(email) = lower(?)')
    .bind(pinHash, expiresAt, attempts, requestedAt, email).run();

const incrementPinAttempts = (db, email) =>
  db.prepare('UPDATE signups SET pin_attempts = COALESCE(pin_attempts, 0) + 1 WHERE lower(email) = lower(?)')
    .bind(email).run();

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

  if (!isValidEmail(email)) {
    return json({ success: false, error: 'Valid email required' }, 400, cors);
  }
  if (!phone) {
    return json({ success: false, error: 'Valid phone number required' }, 400, cors);
  }

  const existing = await getUserByEmail(env.DB, email);
  if (existing) {
    return json({ success: false, error: 'Already on the list.' }, 409, cors);
  }

  try {
    await env.DB.prepare(
      'INSERT INTO signups (email, name, neighborhood, building, phone) VALUES (?, ?, ?, ?, ?)'
    ).bind(email, name || null, neighborhood || null, building || null, phone).run();

    return json({ success: true, message: 'Welcome to the porch.' }, 200, cors);
  } catch (err) {
    if (err.message?.includes('UNIQUE')) {
      return json({ success: false, error: 'Already on the list.' }, 409, cors);
    }
    throw err;
  }
}

async function handleRequestPin(request, env, cors) {
  const body = await request.json();
  const email = normalizeEmail(body.email);

  if (!isValidEmail(email)) {
    return json({ success: false, error: 'Valid email required' }, 400, cors);
  }

  const user = await getUserByEmail(env.DB, email);
  if (!user) {
    return json({ success: false, error: 'Email not found. Sign up first.' }, 404, cors);
  }

  const requestedPhone = body.phone ? normalizePhone(body.phone) : null;
  if (body.phone && !requestedPhone) {
    return json({ success: false, error: 'Valid phone number required' }, 400, cors);
  }

  const phoneToUse = requestedPhone || normalizePhone(user.phone);
  if (!phoneToUse) {
    return json({ success: false, error: 'Phone number required to receive a PIN.' }, 400, cors);
  }

  const now = Math.floor(Date.now() / 1000);
  const lastRequestedAt = Number(user.pin_requested_at || 0);
  if (lastRequestedAt && now - lastRequestedAt < PIN_REQUEST_COOLDOWN) {
    const retryAfter = PIN_REQUEST_COOLDOWN - (now - lastRequestedAt);
    return json(
      { success: false, error: `Please wait ${retryAfter} seconds before requesting another code.` },
      429,
      { ...cors, 'Retry-After': String(retryAfter) }
    );
  }

  if (requestedPhone && requestedPhone !== normalizePhone(user.phone)) {
    await setUserPhone(env.DB, email, requestedPhone);
  }

  const pin = generatePin();
  const expiresAt = now + PIN_TTL;
  await setUserPin(env.DB, email, await hashPin(pin), expiresAt, 0, now);

  const sent = await sendSMS(
    phoneToUse,
    `Your Front Porch Economics code: ${pin}. Valid for 10 minutes.`,
    env
  );

  if (!sent) {
    await setUserPin(env.DB, email, null, null, 0, null);
    return json({ success: false, error: 'Could not send PIN. Try again.' }, 500, cors);
  }

  return json({ success: true, message: 'PIN sent. Check your phone.' }, 200, cors);
}

async function handleVerifyPin(request, env, cors) {
  const body = await request.json();
  const email = normalizeEmail(body.email);
  const pin = typeof body.pin === 'string' ? body.pin.trim() : '';

  if (!isValidEmail(email) || !/^\d{6}$/.test(pin)) {
    return json({ success: false, error: 'Valid email and 6-digit PIN required' }, 400, cors);
  }

  const user = await getUserByEmail(env.DB, email);
  if (!user?.pin || !user.pin_expires_at) {
    return json({ success: false, error: 'No PIN found. Request a new one.' }, 400, cors);
  }

  const now = Math.floor(Date.now() / 1000);
  if (user.pin_expires_at < now) {
    await setUserPin(env.DB, email, null, null, 0, null);
    return json({ success: false, error: 'PIN expired. Request a new one.' }, 400, cors);
  }

  const attempts = Number(user.pin_attempts || 0);
  if (attempts >= PIN_MAX_ATTEMPTS) {
    await setUserPin(env.DB, email, null, null, 0, null);
    return json({ success: false, error: 'Too many incorrect attempts. Request a new code.' }, 429, cors);
  }

  if ((await hashPin(pin)) !== user.pin) {
    const nextAttempts = attempts + 1;
    await incrementPinAttempts(env.DB, email);

    if (nextAttempts >= PIN_MAX_ATTEMPTS) {
      await setUserPin(env.DB, email, null, null, 0, null);
      return json({ success: false, error: 'Too many incorrect attempts. Request a new code.' }, 429, cors);
    }

    return json({ success: false, error: 'Incorrect PIN.' }, 401, cors);
  }

  // Consume the PIN immediately so it can't be reused.
  await setUserPin(env.DB, email, null, null, 0, null);

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
  if (!auth) {
    return json({ success: false, error: 'Not authenticated' }, 401, cors);
  }

  const user = await getUserByEmail(env.DB, auth.email);
  if (!user) {
    await deleteSession(env.DB, auth.sessionId);
    return json(
      { success: false, error: 'Session is no longer valid' },
      401,
      {
        ...cors,
        'Set-Cookie': 'fpe_session=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/',
      }
    );
  }

  return json(
    {
      success: true,
      email: normalizeEmail(user.email),
      name: user.name,
      neighborhood: user.neighborhood,
      building: user.building,
    },
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

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: cors });
    }

    try {
      if (request.method === 'POST' && url.pathname === '/signup') {
        return await handleSignup(request, env, cors);
      }
      if (request.method === 'POST' && url.pathname === '/auth/request-pin') {
        return await handleRequestPin(request, env, cors);
      }
      if (request.method === 'POST' && url.pathname === '/auth/verify-pin') {
        return await handleVerifyPin(request, env, cors);
      }
      if (request.method === 'POST' && url.pathname === '/auth/logout') {
        return await handleLogout(request, env, cors);
      }
      if (request.method === 'GET' && url.pathname === '/auth/me') {
        return await handleMe(request, env, cors);
      }

      return new Response('Front Porch Economics API', { status: 200 });
    } catch (err) {
      console.error(err);
      return json({ success: false, error: 'Internal server error' }, 500, cors);
    }
  },
};
