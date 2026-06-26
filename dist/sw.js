// retired: GENBU reskin no longer uses a service worker (PWA本番化は M2 へ defer).
// This minimal SW unregisters any previously-installed GENBU SW and clears its caches,
// so existing clients drop the old (PoC) shell deterministically. — see S3 stale-SW invariant.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.map((k) => caches.delete(k)));
    await self.registration.unregister();
    const clients = await self.clients.matchAll();
    clients.forEach((c) => c.navigate(c.url)); // 古 shell を捨てて取り直す
  })());
});
