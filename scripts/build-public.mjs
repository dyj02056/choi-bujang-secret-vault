import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');

// 로컬 .env 파일이 있으면 자동 로드 (Node.js 내장)
try {
  process.loadEnvFile?.(resolve(root, '.env'));
} catch {}

const source = resolve(root, 'data.json');
const output = resolve(root, 'public', 'data.json');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));

if (!Number.isInteger(config.step) || config.step < 1) {
  throw new Error('aleph.config.json의 step을 확인해 주세요.');
}

const data = JSON.parse(await readFile(source, 'utf8'));
if (!Array.isArray(data.notes)) {
  throw new Error('실습용 공개 자료 형식을 확인하세요. 실제 학생 자료를 넣으면 안 됩니다.');
}

await mkdir(resolve(root, 'public'), { recursive: true });
await copyFile(source, output);
console.log('실습용 공개 자료를 public/data.json에 복사했습니다.');

if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
