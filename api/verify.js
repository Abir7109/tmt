import { createHmac } from 'crypto';

const TOKEN_SECRET = process.env.TOKEN_SECRET || '';

function verifyToken(token) {
  try {
    const [data, sig] = token.split('.');
    const expected = createHmac('sha256', TOKEN_SECRET).update(data).digest('base64url');
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString());
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { token } = req.body || {};
  if (!token) {
    return res.status(401).json({ valid: false });
  }

  const payload = verifyToken(token);
  if (!payload || !payload.admin) {
    return res.status(401).json({ valid: false });
  }

  return res.status(200).json({ valid: true });
}
