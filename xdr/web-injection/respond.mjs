import { appendFile, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, '..', 'fixtures', 'web-injection.json');
const alertLogPath = join(__dirname, '..', 'alerts.log');

/**
 * decide 결과 중 block 대상만 ZTNA 거부 규칙 목록으로 변환
 * 규칙에는 만료 시각(현재 시각 + 1시간)과 근거 경보 ID가 포함됩니다.
 * 정상 사용자(srcuser가 있거나 정상 이벤트)는 차단 규칙에 포함하지 않습니다.
 */
export async function generateDenyRules(alerts) {
  const denyRules = [];

  for (const alert of alerts) {
    const decision = await decide(alert);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 60 * 60 * 1000).toISOString();

    if (decision.action === 'block') {
      const srcip = alert.data?.srcip;
      if (srcip) {
        denyRules.push({
          ruleId: `xdr.block.web_inj.${srcip.replace(/[^a-zA-Z0-9]/g, '_')}`,
          targetIp: srcip,
          targetUser: alert.data?.srcuser ?? null,
          reason: decision.reason,
          confidence: decision.confidence,
          alertId: alert.id,
          createdAt: now.toISOString(),
          expiresAt,
        });
      }
    }

    // 알림(alert 또는 block) 발생 시 xdr/alerts.log 에 한 줄씩 기록
    if (decision.action === 'alert' || decision.action === 'block') {
      const logLine = `[${now.toISOString()}] [${decision.action.toUpperCase()}] alertId=${alert.id} ip=${alert.data?.srcip ?? 'unknown'} user=${alert.data?.srcuser ?? 'none'} reason=${decision.reason} confidence=${decision.confidence}\n`;
      await appendFile(alertLogPath, logLine, 'utf8');
    }
  }

  return denyRules;
}

const isMain = process.argv[1] && process.argv[1].endsWith('respond.mjs');
if (isMain) {
  const content = await readFile(fixturePath, 'utf8');
  const fixture = JSON.parse(content);
  const denyRules = await generateDenyRules(fixture.alerts || []);
  console.log(`생성된 ZTNA 거부 규칙 수: ${denyRules.length}`);
  for (const rule of denyRules) {
    console.log(`- 규칙 ID: ${rule.ruleId} (근거 경보: ${rule.alertId}, 대상 IP: ${rule.targetIp}, 만료: ${rule.expiresAt})`);
  }
}

