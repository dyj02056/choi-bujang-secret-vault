// BYTE BACK 접속 앱 서비스 워커. 앱 껍데기(오프라인 안내, 아이콘, 앱 정보)만 저장합니다.
// /api/ 요청과 자료(메모·공지)는 가로채지도 저장하지도 않습니다. 기기 키도 다루지 않습니다.
const CACHE = 'byteback-shell-v1';
const SHELL = ['/offline.html', '/manifest.webmanifest', '/icon.svg'];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(caches.keys()
    .then((keys) => Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key))))
    .then(() => self.clients.claim()));
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin || url.pathname.startsWith('/api/')) return;
  if (event.request.mode === 'navigate') {
    // 화면은 항상 네트워크에서 받고, 연결이 없을 때만 오프라인 안내를 보여 줍니다.
    event.respondWith(fetch(event.request).catch(() => caches.match('/offline.html')));
    return;
  }
  if (SHELL.includes(url.pathname)) {
    event.respondWith(caches.match(event.request).then((hit) => hit || fetch(event.request)));
  }
});
