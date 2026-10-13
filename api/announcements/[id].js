import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createLoginVerifier } from '../../src/verify-login.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

try {
  process.loadEnvFile?.(resolve(process.cwd(), '.env'));
} catch {}

let loginVerifier = null;

async function getVerifier() {
  if (loginVerifier) return loginVerifier;
  const root = resolve(process.cwd());
  const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
  if (process.env.SUPABASE_URL) {
    const origin = process.env.SUPABASE_URL.replace(/\/+$/, '');
    config.identityProvider = {
      issuer: `${origin}/auth/v1`,
      jwksUrl: `${origin}/auth/v1/.well-known/jwks.json`,
      audience: config.identityProvider?.audience || 'authenticated',
    };
  }
  loginVerifier = createLoginVerifier({ config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY });
  return loginVerifier;
}

function serverHeaders(key, extra = {}) {
  return {
    apikey: key,
    Authorization: `Bearer ${key}`,
    'Content-Type': 'application/json',
    ...extra,
  };
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SECRET_KEY;
  if (!supabaseUrl || !supabaseKey) {
    return res.status(503).json({ error: 'SERVER_CONFIG_MISSING' });
  }

  let verified;
  try {
    verified = await (await getVerifier())(req.headers.authorization);
  } catch {
    return res.status(500).json({ error: 'VERIFIER_ERROR' });
  }
  if (!verified?.userId) return res.status(401).json({ error: 'UNAUTHORIZED' });

  const { id } = req.query;
  if (typeof id !== 'string' || !UUID.test(id)) {
    return res.status(400).json({ error: 'INVALID_RESOURCE_ID' });
  }

  const announcementUrl = `${supabaseUrl}/rest/v1/instructor_announcements?id=eq.${id}`;
  if (req.method === 'GET') {
    try {
      const response = await fetch(`${announcementUrl}&select=id,title,content`, {
        headers: serverHeaders(supabaseKey),
      });
      if (!response.ok) return res.status(502).json({ error: 'DB_FETCH_FAILED' });
      const [announcement] = await response.json();
      if (!announcement) return res.status(404).json({ error: 'NOT_FOUND' });
      return res.status(200).json({ id: announcement.id, title: announcement.title, body: announcement.content });
    } catch {
      return res.status(502).json({ error: 'DB_NETWORK_ERROR' });
    }
  }

  if (req.method !== 'PUT') return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });

  const { title, body } = req.body || {};
  if (title === undefined && body === undefined) {
    return res.status(400).json({ error: 'BAD_REQUEST' });
  }
  if ((title !== undefined && typeof title !== 'string') || (body !== undefined && typeof body !== 'string')) {
    return res.status(400).json({ error: 'BAD_REQUEST' });
  }

  try {
    const roleResponse = await fetch(
      `${supabaseUrl}/rest/v1/instructor_roles?user_id=eq.${verified.userId}&select=user_id&limit=1`,
      { headers: serverHeaders(supabaseKey) }
    );
    if (!roleResponse.ok) return res.status(502).json({ error: 'ROLE_CHECK_FAILED' });
    const roles = await roleResponse.json();
    const isInstructor = Array.isArray(roles) && roles.some((role) =>
      typeof role?.user_id === 'string'
      && role.user_id.toLowerCase() === verified.userId.toLowerCase());
    if (!isInstructor) return res.status(403).json({ error: 'INSTRUCTOR_REQUIRED' });

    const updates = {};
    if (title !== undefined) updates.title = title;
    if (body !== undefined) updates.content = body;
    const response = await fetch(announcementUrl, {
      method: 'PATCH',
      headers: serverHeaders(supabaseKey, { Prefer: 'return=representation' }),
      body: JSON.stringify(updates),
    });
    if (!response.ok) return res.status(502).json({ error: 'DB_UPDATE_FAILED' });
    const [announcement] = await response.json();
    if (!announcement) return res.status(404).json({ error: 'NOT_FOUND' });
    return res.status(200).json({ id: announcement.id, title: announcement.title, body: announcement.content });
  } catch {
    return res.status(502).json({ error: 'DB_NETWORK_ERROR' });
  }
}
