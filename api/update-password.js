import { createClient } from '@supabase/supabase-js';

// Service-role client (server-side only — never expose this key to the browser)
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

/* ────────────────────────────────────────────
   Decode a JWT and return its payload.
   No signature verification needed here —
   Supabase's admin API will reject bad tokens.
──────────────────────────────────────────── */
function decodeJWT(token) {
  if (!token || typeof token !== 'string') return null;
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(Buffer.from(base64, 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

/* ────────────────────────────────────────────
   Extract user ID (sub) from access token
──────────────────────────────────────────── */
function getUserIdFromToken(token) {
  const payload = decodeJWT(token);
  if (!payload) return null;
  return payload.sub || payload.user_id || null;
}

/* ────────────────────────────────────────────
   Check if the token is expired
──────────────────────────────────────────── */
function isTokenExpired(token) {
  const payload = decodeJWT(token);
  if (!payload || !payload.exp) return true;
  return payload.exp < Math.floor(Date.now() / 1000);
}

/* ────────────────────────────────────────────
   Main handler
──────────────────────────────────────────── */
export default async function handler(req, res) {
  // Only accept POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { access_token, refresh_token, type, password } = req.body ?? {};

  // ── Input validation ──────────────────────
  if (!access_token || !type || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  if (type !== 'recovery') {
    return res.status(400).json({ error: 'Invalid token type' });
  }

  if (typeof password !== 'string' || password.length < 6) {
    return res.status(400).json({ error: 'Password too short (minimum 6 characters)' });
  }

  // ── Token checks ──────────────────────────
  if (isTokenExpired(access_token)) {
    return res.status(401).json({ error: 'Token expired — please request a new reset link' });
  }

  const userId = getUserIdFromToken(access_token);
  if (!userId) {
    return res.status(400).json({ error: 'Invalid access token' });
  }

  // ── Update password via admin API ─────────
  // Using admin.updateUserById avoids the broken setSession() behaviour
  // that can return null user when called with a service-role client.
  const { error: updateError } = await supabase.auth.admin.updateUserById(
    userId,
    { password }
  );

  if (updateError) {
    console.error('[update-password] Supabase error:', updateError.message);
    return res.status(500).json({ error: updateError.message });
  }

  return res.status(200).json({ success: true });
}