// GENBU PWA service worker — S3 (CF-H3)
// 戦略:
//   - document(HTML)        = network-first  : online ⇒ 常に最新 crypto / offline ⇒ cache fallback
//   - その他 shell(manifest, icon) = cache-first : offline 安全・背景で更新
//   - versioned cache + activate purge + skipWaiting/clients.claim : 旧 SW を即時退役
// ∴ stale-SW 回避は "構造"（online で古い shell を返す経路が存在しない）。

const CACHE = 'genbu-shell-v1'; // ★ shell を変えたら v2.. に bump → activate が旧 cache を purge

const SHELL = [
  '/',                          // index.html（"/" のルート解決）
  '/index.html',
  '/genbu_mock.html',
  '/genbu_entitlement.html',
  '/manifest.webmanifest',
  '/icon.svg',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE)
      .then((c) => c.addAll(SHELL))
      .then(() => self.skipWaiting()) // 新 SW を waiting で留めない（即時取得へ）
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)) // 旧 version cache を消す
      ))
      .then(() => self.clients.claim()) // 既存タブも新 SW の管理下へ
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return; // GET 以外は素通し

  const accept = req.headers.get('accept') || '';
  const isDocument = req.mode === 'navigate' || accept.includes('text/html');

  if (isDocument) {
    // network-first: online ⇒ 最新を取り cache 更新 / offline ⇒ cache → 最後は "/" に fallback
    event.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
          return res;
        })
        .catch(() => caches.match(req).then((hit) => hit || caches.match('/index.html')))
    );
    return;
  }

  // cache-first: shell 静的物（manifest/icon）。なければ network → cache へ充填。
  event.respondWith(
    caches.match(req).then((hit) =>
      hit || fetch(req).then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(req, copy));
        return res;
      })
    )
  );
});
