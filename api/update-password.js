import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY  // service role — never expose on frontend
);

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { token_hash, type, password } = req.body;

  if (!token_hash || !type || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password too short' });
  }

  // verify the token and get the user
  const { data: verifyData, error: verifyError } = await supabase.auth.verifyOtp({
    token_hash,
    type,
  });

  if (verifyError || !verifyData.user) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  // update the password using the user's id
  const { error: updateError } = await supabase.auth.admin.updateUserById(
    verifyData.user.id,
    { password }
  );

  if (updateError) {
    return res.status(500).json({ error: updateError.message });
  }

  return res.status(200).json({ success: true });
}