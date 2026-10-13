# 접속 앱 기기 서명 계약 v2 (11단계)

11단계부터 자료실의 보호 API는 **로그인 토큰**과 **승인된 기기의 서명**을 모두 확인합니다.
설치(홈 화면 추가)는 기기 확인이 아닙니다. 기기 승인 상태는 서버 표 `device_keys`에만 있고,
브라우저가 보낸 "승인됨" 같은 값은 믿지 않습니다.

## 기기 키는 어디에 있나

- 기기 = 이 기기의 운영체제 인증기(Windows Hello, Touch ID, 휴대폰 화면 잠금 등)에 만든 **패스키(WebAuthn, ES256)**.
- 개인키는 인증기 밖으로 나오지 않습니다. 화면 코드(`public/`)는 키를 만들거나 내보내거나 저장하지 않고,
  인증기가 돌려준 서명 결과만 요청에 붙입니다. 브라우저 저장소(localStorage, sessionStorage, IndexedDB,
  Cache Storage)에도 키를 넣지 않습니다.
- 서버는 등록 때 받은 **공개키**만 `device_keys`에 둡니다. 키 값은 Git·로그·제출 묶음에 없습니다.
- 기기 ID: 패스키 자격 ID(credential ID) 바이트의 SHA-256 앞 16자리(소문자 16진수). 키가 아니며 화면에 표시하지 않습니다.

## 보호 API

| 경로 | 메서드 |
|---|---|
| `/api/notes` | GET, POST |
| `/api/notes/:id` | GET, PUT, DELETE |
| `/api/announcements/:id` | GET, PUT 등 |
| `/api/restore/notes` | POST |

로그인이 없으면 이전처럼 401 `UNAUTHORIZED`입니다. 로그인이 있으면 그다음에 서명을 확인합니다.

## 서명 방법

줄바꿈(`\n`)으로 이은 6줄의 SHA-256을 패스키 도전값(`challenge`)으로 넣고 `navigator.credentials.get`으로 서명받습니다.

```
aleph.device.v2
<메서드, 대문자>
<경로와 쿼리, 예: /api/notes/<id>>
<본문 SHA-256 16진수: 본문이 없으면 빈 문자열의 해시, JSON 본문이면 JSON.stringify(값)의 해시>
<시각: 밀리초 13자리>
<일회용 번호: UUID v4 소문자>
```

| 머리글 | 값 |
|---|---|
| `x-aleph-device` | 기기 ID |
| `x-aleph-timestamp` | 시각(ms) |
| `x-aleph-nonce` | 일회용 번호 |
| `x-aleph-signature` | 인증기 서명(DER, base64url) |
| `x-aleph-authenticator-data` | 인증기 데이터(base64url) |
| `x-aleph-client-data` | clientDataJSON(base64url) |

## 서버 판단 (`src/device-signature.mjs`)

서버는 **실제로 받은** 메서드·경로·본문으로 도전값을 다시 만들고 다음을 모두 확인합니다:
clientData 의 `type`이 `webauthn.get`, `challenge`가 다시 만든 값, `origin`이 요청을 받은 앱 주소,
인증기 데이터의 호스트 해시가 그 호스트, 사용자 존재 표시, 저장된 공개키로 ES256 서명 검증.

| 경우 | 결과 |
|---|---|
| 서명 머리글이 하나도 없음 | 401 `DEVICE_SIGNATURE_REQUIRED` |
| 머리글 형식이 틀림 | 401 `DEVICE_SIGNATURE_INVALID` |
| 시각이 60초 넘게 차이 남 | 401 `DEVICE_SIGNATURE_EXPIRED` |
| 등록 안 됨, 승인 대기, 다른 계정의 기기 | 403 `DEVICE_NOT_APPROVED` |
| 서명 뒤 경로·쿼리·메서드·본문이 바뀜, 다른 사이트에서 받은 서명 | 403 `DEVICE_SIGNATURE_MISMATCH` |
| 같은 서명(일회용 번호)을 다시 보냄 | 403 `DEVICE_SIGNATURE_REPLAYED` |
| 기기 표를 읽을 수 없음 | 502 `DEVICE_CHECK_UNAVAILABLE` (허용하지 않음) |

맞지 않는 서명은 일회용 번호를 쓰지 않습니다. 통과한 서명만 `device_nonces`에 기록됩니다.

## 기기 승인 (`POST /api/devices`, `src/device-approval.mjs`)

- 앱이 `navigator.credentials.create`로 이 기기에 패스키를 만들고, 본문
  `{ "credentialId": <base64url>, "publicKey": <SPKI 공개키 base64url>, "label"?: 문자열 }`을 보냅니다.
  P-256 공개키가 아니면 400.
- 이 등록 요청 자체를 **그 패스키로** 위 방식대로 서명해야 합니다. 다른 패스키의 서명이면 403 `DEVICE_SIGNATURE_MISMATCH`.
- 서버는 로그인 토큰의 실제 로그인 시각이 **최근 10분 안**일 때만 `approved`로 정합니다
  (Supabase 토큰은 `amr`의 로그인 시각, 심판 토큰은 발급 시각 `iat`).
  아니면 `pending`으로 남기고 403 `REAUTH_REQUIRED`를 돌려줍니다. 다시 로그인한 뒤 같은 요청을 보내면 승인됩니다.
- 이미 다른 계정에 등록된 패스키는 409, 회수된 기기는 403입니다. 등록 뒤 공개키와 소유자는 바꿀 수 없습니다(DB 트리거).
- `GET /api/devices`: 로그인한 계정의 기기 ID, 상태, 시각만 돌려줍니다(공개키 없음).

## 하지 않는 것

- `npm run test:device`와 `npm run bundle`의 기기 점검은 같은 바이트 형식으로 서명하는 가상 인증기(`src/device-client.mjs`)를
  씁니다. 그 키는 실행 중인 프로세스 메모리에서만 만들어지고 사라집니다. 로컬 연습이며 심판 판정이 아닙니다.
- 반 엔진(ALEPH SDP)의 기기 등록과 이 앱의 기기 승인은 별개입니다. 판정기(`src/decider.mjs`)는 엔진이 넘긴
  `deviceRegistered`만 보며, 이 계약 때문에 바뀌지 않았습니다.
