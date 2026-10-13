import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { HEADERS, bodySha256, deviceIdOf, signingString } from './device-signature.mjs';

// 11단계 자기 점검·테스트용 가상 기기. 접속 앱(public/index.html)과 같은 방식으로 서명합니다.
// 키는 이 프로세스의 메모리에만 있고 파일·로그·제출 묶음에 쓰지 않습니다.
export function createVirtualDevice() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const publicJwk = { crv: 'P-256', kty: 'EC', x: jwk.x, y: jwk.y };
  const id = deviceIdOf(publicJwk);

  // body 는 보낼 값(객체) 그대로 받습니다. 서명할 본문 문자열은 JSON.stringify(body) 입니다.
  function signHeaders({ method = 'GET', path, body, timestamp = String(Date.now()), nonce = randomUUID() }) {
    const text = signingString({
      method, path, bodyHash: bodySha256(body === undefined ? '' : JSON.stringify(body)), timestamp, nonce, deviceId: id,
    });
    const signature = sign('sha256', Buffer.from(text, 'utf8'), { key: privateKey, dsaEncoding: 'ieee-p1363' })
      .toString('base64url');
    return {
      [HEADERS.device]: id, [HEADERS.timestamp]: timestamp, [HEADERS.nonce]: nonce, [HEADERS.signature]: signature,
    };
  }
  return { id, publicJwk, signHeaders };
}
