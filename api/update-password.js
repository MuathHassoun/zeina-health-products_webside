import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { access_token, refresh_token, type, password } = req.body;

  if (!access_token || !type || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  if (type !== 'recovery') {
    return res.status(400).json({ error: 'Invalid token type' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password too short' });
  }

  // set the session using the tokens from the URL
  const { data: sessionData, error: sessionError } = await supabase.auth.setSession({
    access_token,
    refresh_token,
  });

  if (sessionError || !sessionData.user) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  // update the password
  const { error: updateError } = await supabase.auth.admin.updateUserById(
    sessionData.user.id,
    { password }
  );

  if (updateError) {
    return res.status(500).json({ error: updateError.message });
  }

  return res.status(200).json({ success: true });
}