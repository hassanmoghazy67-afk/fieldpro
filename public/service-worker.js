// FieldPro CRM service worker
// Scope: enables "Add to Home Screen" / standalone app behavior on iOS and Android.
// Deliberately conservative caching — this is a live business CRM, not static
// content. We cache only the app shell (HTML/CSS/JS/icons) for fast reloads and
// basic offline tolerance. We NEVER cache anything under /api/ — job data,
// messages, invoices, etc. must always come from the network, fresh. Caching
// API responses would risk showing a tech or dispatcher stale, wrong data
// (e.g. an old job status), which is worse than no offline support at all.

const CACHE_NAME = 'fieldpro-shell-v3';
const SHELL_ASSETS = [
  '/',
  '/manifest.json',
  '/icons/icon-192.png',
  '/icons/icon-512.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Never touch API calls or webhooks — always go straight to the network so
  // the CRM never shows stale job/customer/message data.
  if (url.pathname.startsWith('/api/')) return;

  // Only handle our own origin's GET requests for the shell.
  if (event.request.method !== 'GET' || url.origin !== location.origin) return;

  // Network-first, not cache-first: always try to fetch the latest version of
  // the app shell. Only fall back to the cached copy if the network request
  // genuinely fails (offline, server unreachable) — this is what offline
  // tolerance actually means. Serving the cache FIRST (the previous approach)
  // meant anyone with this installed as a home-screen app could keep seeing an
  // old version of the CRM indefinitely after a deploy, since the stale cached
  // copy would load instantly and the real update only happened silently in
  // the background, never replacing what was already on screen.
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        if (response && response.status === 200) {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
        }
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});
