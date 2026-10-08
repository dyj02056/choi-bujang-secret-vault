import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, '..', 'fixtures', 'web-injection.json');

export async function readAlerts() {
  const content = await readFile(fixturePath, 'utf8');
  const parsed = JSON.parse(content);
  const alerts = parsed.alerts || [];

  return alerts.map((alert) => ({
    timestamp: alert.timestamp ?? '',
    srcip: alert.data?.srcip ?? '',
    srcuser: alert.data?.srcuser ?? '',
    level: alert.rule?.level ?? 0,
    description: alert.rule?.description ?? '',
  }));
}

const isMain = process.argv[1] && process.argv[1].endsWith('read-alerts.mjs');
if (isMain) {
  const extracted = await readAlerts();
  for (const item of extracted) {
    console.log(`[${item.timestamp}] IP:${item.srcip} USER:${item.srcuser || '-'} LEVEL:${item.level} DESC:${item.description}`);
  }
  console.log(`총 경보 건수: ${extracted.length}`);
}
