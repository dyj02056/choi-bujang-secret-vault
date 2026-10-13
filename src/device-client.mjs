import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { HEADERS, bodySha256, challengeOf, deviceIdOfCredential, signingString } from './device-signature.mjs';

// 11단계 자기 점검·테스트용 가상 인증기. 브라우저의 패스키(WebAuthn)와 같은 바이트 형식으로 서명합니다.
// 키는 이 프로세스의 메모리에서만 만들어지고 사라지며, 파일·로그·제출 묶음에 쓰지 않습니다.
// origin 은 앱 주소(예: https://<배포 호스트>)입니다. 패스키는 그 호스트에만 묶입니다.
export function createVirtualDevice({ origin }) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const credentialId = randomBytes(32).toString('base64url');
  const id = deviceIdOfCredential(credentialId);
  const rpId = new URL(origin).hostname;
  const sha256 = (data) => createHash('sha256').update(data).digest();
  let counter = 0;

  // 등록 요청 본문: 공개키(SPKI)와 자격 ID. 개인키는 담지 않습니다.
  const registration = () => ({
    credentialId, publicKey: publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
  });

  // body 는 보낼 값(객체) 그대로 받습니다. 서명할 본문 문자열은 JSON.stringify(body) 입니다.
  function signHeaders({ method = 'GET', path, body, timestamp = String(Date.now()), nonce = randomUUID() }) {
    const text = signingString({ method, path, bodyHash: bodySha256(body === undefined ? '' : JSON.stringify(body)), timestamp, nonce });
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: challengeOf(text), origin, crossOrigin: false }), 'utf8');
    counter += 1;
    const authenticatorData = Buffer.concat([sha256(Buffer.from(rpId, 'utf8')), Buffer.from([0x05]), Buffer.from([0, 0, 0, counter])]);
    const signature = sign('sha256', Buffer.concat([authenticatorData, sha256(clientDataJSON)]), privateKey);
    return {
      [HEADERS.device]: id,
      [HEADERS.timestamp]: timestamp,
      [HEADERS.nonce]: nonce,
      [HEADERS.signature]: signature.toString('base64url'),
      [HEADERS.authenticatorData]: authenticatorData.toString('base64url'),
      [HEADERS.clientData]: clientDataJSON.toString('base64url'),
    };
  }
  return { id, registration, signHeaders };
}
