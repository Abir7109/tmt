import { createHmac, randomBytes, timingSafeEqual } from 'crypto';

const ADMIN_PASS = process.env.ADMIN_PASSWORD || '';
const TOKEN_SECRET = process.env.TOKEN_SECRET || randomBytes(32).toString('hex');

const attempts = new Map();

function createToken(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = createHmac('sha256', TOKEN_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function constantTimeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

function getRateLimitKey(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown';
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const key = getRateLimitKey(req);
  const now = Date.now();
  const record = attempts.get(key);

  if (record && record.count >= 5 && now - record.last < 15 * 60 * 1000) {
    const retryAfter = Math.ceil((15 * 60 * 1000 - (now - record.last)) / 1000);
    return res.status(429).json({ error: `Too many attempts. Try again in ${retryAfter}s.` });
  }

  const { password } = req.body || {};

  if (!password) {
    return res.status(400).json({ error: 'Password required' });
  }

  if (!ADMIN_PASS) {
    return res.status(500).json({ error: 'Server not configured' });
  }

  await new Promise(r => setTimeout(r, 500));

  if (!constantTimeCompare(password, ADMIN_PASS)) {
    const rec = attempts.get(key) || { count: 0, last: 0 };
    rec.count = (now - rec.last > 15 * 60 * 1000) ? 1 : rec.count + 1;
    rec.last = now;
    attempts.set(key, rec);
    return res.status(401).json({ error: 'Invalid password' });
  }

  attempts.delete(key);

  const token = createToken({
    admin: true,
    exp: Date.now() + 4 * 60 * 60 * 1000,
  });

  res.setHeader('Set-Cookie', `admin_token=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=14400`);

  return res.status(200).json({ success: true, token });
}
