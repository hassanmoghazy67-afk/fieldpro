// FieldPro service worker.
//
// Two jobs:
//   1. Network-first caching of the app shell (offline fallback only).
//   2. Handling clicks on notifications the page asks it to display.
//
// The page now displays notifications through THIS worker rather than
// `new Notification()`, because a backgrounded page can't reliably raise one
// itself — some browsers refuse it, and mobile Chrome doesn't support it at
// all. Without the click handler below, tapping the banner would dismiss it
// and do nothing.

const CACHE = 'fieldpro-v3';
const SHELL = ['/', '/index.html', '/manifest.json', '/icons/icon-192.png', '/icons/icon-512.png'];

self.addEventListener('install', (e) => {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL).catch(() => {})));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  // API responses are NEVER cached — stale dispatch data is worse than none.
  if (url.pathname.startsWith('/api/')) return;

  e.respondWith(
    fetch(req)
      .then(res => {
        if (res && res.status === 200 && res.type === 'basic') {
          const copy = res.clone();
          caches.open(CACHE).then(c => c.put(req, copy)).catch(() => {});
        }
        return res;
      })
      .catch(() => caches.match(req).then(hit => hit || caches.match('/index.html')))
  );
});

// Clicking a notification focuses an already-open CRM tab rather than opening a
// duplicate — dispatchers keep one tab open all day.
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const target = (e.notification.data && e.notification.data.url) || '/';
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      for (const client of list) {
        if (client.url.includes(self.location.origin) && 'focus' in client) {
          if ('navigate' in client && target !== '/') client.navigate(target).catch(() => {});
          return client.focus();
        }
      }
      if (self.clients.openWindow) return self.clients.openWindow(target);
    })
  );
});
