import { isIP } from 'node:net';
import { createClient } from '@supabase/supabase-js';
import { createRemoteJWKSet, decodeJwt, jwtVerify } from 'jose';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const BEARER = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/u;

function httpsUrl(value, path) {
  if (typeof value !== 'string' || value !== value.trim()) throw new TypeError('invalid_login_issuer');
  let url;
  try { url = new URL(value); } catch { throw new TypeError('invalid_login_issuer'); }
  const host = url.hostname.toLowerCase();
  if (url.protocol !== 'https:' || url.username || url.password || url.port
      || url.pathname !== path || url.search || url.hash || !host.includes('.')
      || host === 'localhost' || isIP(host)
      || host.endsWith('.local') || host.endsWith('.internal')
      || host.endsWith('.invalid') || host.endsWith('.test') || host.endsWith('.example')) {
    throw new TypeError('invalid_login_issuer');
  }
  return url;
}

function verifiedConfig(config) {
  const judge = httpsUrl(config?.judgeIssuer, '/defense/judge');
  const app = httpsUrl(config?.publicAppUrl, '/');
  if (!app.hostname.endsWith('.vercel.app')) throw new TypeError('invalid_login_app_origin');
  const student = httpsUrl(config?.identityProvider?.issuer, '/auth/v1');
  if (student.origin === judge.origin || student.origin === app.origin
      || config.identityProvider.jwksUrl !== `${student.href}/.well-known/jwks.json`
      || typeof config.identityProvider.audience !== 'string'
      || !/^[a-zA-Z0-9._:-]{1,120}$/u.test(config.identityProvider.audience)) {
    throw new TypeError('invalid_student_identity_provider');
  }
  return { judgeIssuer: judge.href, judgeJwksUrl: `${judge.href}/.well-known/jwks.json`,
    audience: app.hostname, studentIssuer: student.href,
    studentAudience: config.identityProvider.audience, studentUrl: student.origin };
}

// Create once in the server runtime. The judge intake separately compares the
// checked-in judgeIssuer to its registered operator issuer before any attack.
export function createLoginVerifier({ config, supabaseSecretKey, judgeKeySet,
  supabaseClient } = {}) {
  const bound = verifiedConfig(config);
  if (!supabaseClient && (typeof supabaseSecretKey !== 'string'
      || !supabaseSecretKey.trim() || supabaseSecretKey !== supabaseSecretKey.trim())) {
    throw new TypeError('missing_supabase_secret_key');
  }
  const keys = judgeKeySet ?? createRemoteJWKSet(new URL(bound.judgeJwksUrl),
    { timeoutDuration: 5000, cacheMaxAge: 5 * 60 * 1000 });
  const supabase = supabaseClient ?? createClient(bound.studentUrl, supabaseSecretKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  });
  if (typeof keys !== 'function' || typeof supabase?.auth?.getClaims !== 'function') {
    throw new TypeError('invalid_login_verifier_configuration');
  }

  return async function verifyLoginAuthorization(authorization) {
    if (typeof authorization !== 'string' || authorization.length > 8192) return null;
    const match = BEARER.exec(authorization);
    if (!match) return null;
    const token = match[1];
    let issuer;
    try { issuer = decodeJwt(token).iss; } catch { return null; }
    if (issuer === bound.judgeIssuer) {
      try {
        const { payload, protectedHeader } = await jwtVerify(token, keys, {
          issuer: bound.judgeIssuer, audience: bound.audience, algorithms: ['ES256'],
          maxTokenAge: '15 minutes', clockTolerance: 5,
        });
        if (protectedHeader.alg !== 'ES256' || payload.aud !== bound.audience
            || !UUID_V4.test(payload.sub ?? '') || !UUID_V4.test(payload.aleph_run ?? '')
            || payload.aleph_role !== 'judge'
            || !['a', 'b'].includes(payload.aleph_identity)
            || !Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp)
            || payload.exp <= payload.iat || payload.exp - payload.iat > 900) return null;
        // 심판 토큰은 최대 15분짜리이며 발급 시각(iat)을 로그인 시각으로 봅니다.
        return Object.freeze({ kind: 'judge', userId: payload.sub,
          runId: payload.aleph_run, identity: payload.aleph_identity, authTime: payload.iat });
      } catch { return null; }
    }
    if (issuer === bound.studentIssuer) {
      try {
        // Supabase verifies asymmetric keys locally through JWKS and shared-secret
        // tokens through its Auth server. Never decode and trust a student claim here.
        const { data, error } = await supabase.auth.getClaims(token);
        const claims = data?.claims;
        if (error || !claims || claims.iss !== bound.studentIssuer
            || claims.aud !== bound.studentAudience
            || claims.role !== 'authenticated' || !UUID.test(claims.sub ?? '')
            || !Number.isSafeInteger(claims.exp)
            || claims.exp <= Math.floor(Date.now() / 1000)) return null;
        // 11단계 기기 승인용: 실제로 비밀번호 등으로 로그인한 시각(amr). 토큰을 새로 고쳐도 바뀌지 않습니다.
        const authTimes = Array.isArray(claims.amr)
          ? claims.amr.map((entry) => entry?.timestamp).filter(Number.isSafeInteger) : [];
        return Object.freeze({ kind: 'student', userId: claims.sub,
          authTime: authTimes.length ? Math.max(...authTimes) : null });
      } catch { return null; }
    }
    return null;
  };
}
