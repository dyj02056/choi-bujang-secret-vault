# 접속 앱 기기 서명 계약 v1 (11단계)

11단계부터 자료실의 보호 API는 **로그인 토큰**과 **승인된 기기의 서명**을 모두 확인합니다.
설치(홈 화면 추가)는 기기 확인이 아닙니다. 기기 승인 상태는 서버 표 `device_keys`에만 있고,
브라우저가 보낸 "승인됨" 같은 값은 믿지 않습니다.

## 보호 API

| 경로 | 메서드 |
|---|---|
| `/api/notes` | GET, POST |
| `/api/notes/:id` | GET, PUT, DELETE |
| `/api/announcements/:id` | GET, PUT 등 |
| `/api/restore/notes` | POST |

로그인이 없으면 이전처럼 401 `UNAUTHORIZED`입니다. 로그인이 있으면 그다음에 서명을 확인합니다.

## 기기 키와 기기 ID

- 키: ECDSA P-256. 접속 앱은 WebCrypto로 **내보낼 수 없는** 개인키를 만들고, 화면이 열려 있는 동안 메모리에만 둡니다.
  브라우저 저장소(localStorage, IndexedDB 등)에 넣지 않으므로 새로고침하면 새 키로 다시 승인받습니다.
- 기기 ID: 공개키 JWK `{"crv":"P-256","kty":"EC","x":…,"y":…}`(이 순서의 JSON)의 SHA-256 앞 16자리(소문자 16진수).
  반 엔진 계약의 `deviceId` 형식과 같습니다.

## 서명할 문자열

줄바꿈(`\n`)으로 이은 7줄입니다.

```
aleph.device.v1
<메서드, 대문자>
<경로와 쿼리, 예: /api/notes/<id>>
<본문 SHA-256 16진수: 본문이 없으면 빈 문자열의 해시, JSON 본문이면 JSON.stringify(값)의 해시>
<시각: 밀리초 13자리>
<일회용 번호: UUID v4 소문자>
<기기 ID>
```

서명: ECDSA P-256 + SHA-256, 결과는 64바이트(r‖s)를 base64url(86자)로.

## 머리글

| 머리글 | 값 |
|---|---|
| `x-aleph-device` | 기기 ID |
| `x-aleph-timestamp` | 서명한 시각(ms) |
| `x-aleph-nonce` | 일회용 번호 |
| `x-aleph-signature` | 서명 |

## 서버 판단 (`src/device-signature.mjs`)

서버는 **실제로 받은** 메서드·경로·본문으로 같은 문자열을 다시 만들어 저장된 공개키로 검증합니다.

| 경우 | 결과 |
|---|---|
| 서명 머리글이 하나도 없음 | 401 `DEVICE_SIGNATURE_REQUIRED` |
| 머리글 형식이 틀림 | 401 `DEVICE_SIGNATURE_INVALID` |
| 시각이 60초 넘게 차이 남 | 401 `DEVICE_SIGNATURE_EXPIRED` |
| 등록 안 됨, 승인 대기, 다른 계정의 기기 | 403 `DEVICE_NOT_APPROVED` |
| 서명 뒤 경로·쿼리·메서드·본문이 바뀜 | 403 `DEVICE_SIGNATURE_MISMATCH` |
| 같은 서명(일회용 번호)을 다시 보냄 | 403 `DEVICE_SIGNATURE_REPLAYED` |
| 기기 표를 읽을 수 없음 | 502 `DEVICE_CHECK_UNAVAILABLE` (허용하지 않음) |

맞지 않는 서명은 일회용 번호를 쓰지 않습니다. 통과한 서명만 `device_nonces`에 기록됩니다.

## 기기 승인 (`POST /api/devices`, `src/device-approval.mjs`)

- 본문: `{ "publicKey": <P-256 공개키 JWK>, "label"?: 문자열(40자 이하) }`. 개인키 값 `d`가 있으면 400.
- 이 요청 자체를 **등록하려는 키로** 위 방식대로 서명해야 합니다. 다른 키의 서명이면 403 `DEVICE_SIGNATURE_MISMATCH`.
- 서버는 로그인 토큰의 실제 로그인 시각이 **최근 10분 안**일 때만 `approved`로 정합니다
  (Supabase 토큰은 `amr`의 로그인 시각, 심판 토큰은 발급 시각 `iat`).
  아니면 `pending`으로 남기고 403 `REAUTH_REQUIRED`를 돌려줍니다. 다시 로그인한 뒤 같은 요청을 보내면 승인됩니다.
- 이미 다른 계정에 등록된 키는 409, 회수된 기기는 403입니다. 등록 뒤 공개키와 소유자는 바꿀 수 없습니다(DB 트리거).
- `GET /api/devices`: 로그인한 계정의 기기 ID, 상태, 시각만 돌려줍니다(공개키 없음).

## 하지 않는 것

- 개인키를 서버로 보내거나 저장하지 않습니다. 저장소·로그·제출 묶음에도 넣지 않습니다.
- `npm run test:device`는 가짜 DB로 하는 로컬 연습이며 심판 판정이 아닙니다.
- 반 엔진(ALEPH SDP)의 기기 등록과 이 앱의 기기 승인은 별개입니다. 판정기(`src/decider.mjs`)는 엔진이 넘긴
  `deviceRegistered`만 보며, 이 계약 때문에 바뀌지 않았습니다.
