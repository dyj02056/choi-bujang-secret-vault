// 알려진 취약점(CVE-2021-44228, MITRE ATT&CK T1190) 악용 판단 모듈.
// 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert) 를 부릅니다. 그래서 import 문을 두지 않고,
// 파일을 읽거나 쓰지 않고, 바깥에 묻지 않습니다. 패턴은 xdr/known-cve/patterns.json 을 아래 상수로 옮겨 적었습니다.
// 알림 기록(xdr/alerts.log)과 판정기 연결은 respond.mjs 가 맡고, 이 파일은 판단 결과만 돌려줍니다.

const LOOKUP_REGEX = '\\$\\{jndi:(?:ldap|ldaps|rmi|dns|iiop|corba|nds|nis|http|https)://[^}\\s]+\\}';

const PATTERNS = Object.freeze([
  {
    name: 'jndi-lookup-in-header',
    condition: '요청 머리글(useragent)에 완전한 원격 조회 구문 ${jndi:<프로토콜>://…} 이 있음',
    match: { fields: ['useragent'], regex: LOOKUP_REGEX, flags: 'i' },
    confidence: { base: 0.9 },
    rationale: 'CVE-2021-44228: 로그에 남는 머리글 값 안의 ${jndi:…} 조회 구문이 원격 클래스 불러오기로 이어지는 취약점입니다 (MITRE ATT&CK T1190).',
  },
  {
    name: 'jndi-lookup-in-url',
    condition: '요청 주소·인자(url)에 완전한 원격 조회 구문 ${jndi:<프로토콜>://…} 이 있음',
    match: { fields: ['url'], regex: LOOKUP_REGEX, flags: 'i' },
    confidence: { base: 0.9 },
    rationale: 'CVE-2021-44228: 로그에 남는 요청 인자 안의 ${jndi:…} 조회 구문도 머리글과 같은 원격 조회를 일으킵니다 (MITRE ATT&CK T1190).',
  },
  {
    name: 'repeated-jndi-lookup',
    condition: '위 조회 구문이 있고, 같은 경보의 반복 횟수(count)가 2 이상이거나 머리글과 인자 두 곳에 함께 있음',
    match: { requires: ['jndi-lookup-in-header', 'jndi-lookup-in-url'], countAtLeast: 2, orBothFields: true },
    confidence: { add: 0.05 },
    rationale: 'MITRE ATT&CK T1190: 공개 앱의 알려진 취약점(CVE-2021-44228)을 노린 악용은 같은 구문을 여러 번·여러 위치에 보내는 자동 시도로 나타납니다.',
  },
  {
    name: 'cve-scanner-trace',
    condition: '위 조회 구문이 있고, 경보 설명에 알려진 취약점 점검 흔적이 있거나 인자 이름이 점검용(probe)임',
    match: { requires: ['jndi-lookup-in-header', 'jndi-lookup-in-url'], descriptionIncludes: ['점검 흔적'], urlParamNames: ['probe'] },
    confidence: { add: 0.03 },
    rationale: 'MITRE ATT&CK T1190: 공개 앱을 대상으로 CVE-2021-44228 같은 알려진 취약점을 찾는 점검 도구가 악용 구문을 함께 보냅니다.',
  },
  {
    name: 'cve-keyword-probe',
    condition: '경보에 MITRE T1190 표시가 있고 규칙 수준이 5 이상이지만, 완전한 원격 조회 구문은 없음(취약점 이름 검색, jndi 단어, 잘린 조회 조각, 점검 도구와 비슷한 이름 등)',
    match: { mitre: 'T1190', levelAtLeast: 5, withoutPatterns: ['jndi-lookup-in-header', 'jndi-lookup-in-url'] },
    confidence: { base: 0.6 },
    rationale: 'CVE-2021-44228 은 완전한 ${jndi:…} 구문이 있어야 악용되므로, T1190 표시만 있고 구문이 없는 요청은 막지 않고 알림으로만 남깁니다.',
  },
]);

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const MAX_CONFIDENCE = 0.99;
const byName = Object.fromEntries(PATTERNS.map((pattern) => [pattern.name, pattern]));

const text = (value) => (typeof value === 'string' ? value : '');
const round = (value) => Math.round(value * 100) / 100;
const actionFor = (confidence) => (confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');

function fieldMatches(pattern, data) {
  const regex = new RegExp(pattern.match.regex, pattern.match.flags);
  return pattern.match.fields.some((field) => regex.test(text(data[field])));
}

function urlHasParam(url, names) {
  const query = url.includes('?') ? url.slice(url.indexOf('?') + 1) : '';
  const params = query.split('&').map((part) => part.split('=')[0].toLowerCase());
  return names.some((name) => params.includes(name));
}

export function decide(alert) {
  const data = alert && typeof alert.data === 'object' && alert.data !== null ? alert.data : {};
  const rule = alert && typeof alert.rule === 'object' && alert.rule !== null ? alert.rule : {};
  const level = Number(rule.level) || 0;
  const mitre = Array.isArray(rule.mitre) ? rule.mitre : [];
  const description = text(rule.description);
  const count = Number(data.count) || 1;

  // 1) 완전한 원격 조회 구문: 머리글·인자에서 찾습니다. 하나라도 있으면 뚜렷한 악용 형태입니다.
  const inHeader = fieldMatches(byName['jndi-lookup-in-header'], data);
  const inUrl = fieldMatches(byName['jndi-lookup-in-url'], data);
  if (inHeader || inUrl) {
    const matched = [];
    if (inHeader) matched.push('jndi-lookup-in-header');
    if (inUrl) matched.push('jndi-lookup-in-url');
    let confidence = byName[matched[0]].confidence.base;

    const repeated = byName['repeated-jndi-lookup'];
    if (count >= repeated.match.countAtLeast || (repeated.match.orBothFields && inHeader && inUrl)) {
      matched.push(repeated.name);
      confidence += repeated.confidence.add;
    }
    const scanner = byName['cve-scanner-trace'];
    if (scanner.match.descriptionIncludes.some((word) => description.includes(word))
        || urlHasParam(text(data.url), scanner.match.urlParamNames)) {
      matched.push(scanner.name);
      confidence += scanner.confidence.add;
    }
    confidence = round(Math.min(confidence, MAX_CONFIDENCE));
    return { action: actionFor(confidence), confidence, reason: matched.join(', ') };
  }

  // 2) 구문 없이 T1190 표시와 수준만 있는 시도: 정상 사용자와 겹칠 수 있어 알림까지만 갑니다.
  const probe = byName['cve-keyword-probe'];
  if (mitre.includes(probe.match.mitre) && level >= probe.match.levelAtLeast) {
    const confidence = probe.confidence.base;
    return { action: actionFor(confidence), confidence, reason: probe.name };
  }

  // 3) 어느 패턴에도 맞지 않는 경보는 기록만 남깁니다.
  return { action: 'record', confidence: 0, reason: '맞는 패턴 없음' };
}
