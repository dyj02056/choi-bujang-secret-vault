// Student self-check: retain the stage 5 API-access checks in stage 6.
export async function runAttackChecks(config) {
  if (config.step !== 6) throw new Error('Current step requires updating src/attack-check.mjs.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json must contain a valid public app URL.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json must contain a valid public app URL.');
  }

  let anonObserved = '';
  try {
    const response = await fetch(new URL('/api/notes', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    let data;
    try { data = await response.json(); } catch {}
    if (response.status === 401 || response.status === 403) {
      anonObserved = `Anonymous request correctly rejected (HTTP ${response.status}: ${data?.error || 'UNAUTHORIZED'})`;
    } else {
      anonObserved = `Anonymous request needs review (HTTP ${response.status})`;
    }
  } catch (err) {
    anonObserved = `Anonymous request could not be checked (${err.message})`;
  }

  const crossObserved = 'Not run: manually verify that the original API rejects an anon-key request.';

  return [
    {
      attackId: 'anonymous_api_read',
      expected: 'Anonymous request is rejected with HTTP 401 or 403',
      observed: anonObserved,
    },
    {
      attackId: 'original_direct_blocked',
      expected: 'The original API rejects a direct anon-key request',
      observed: crossObserved,
    },
  ];
}
