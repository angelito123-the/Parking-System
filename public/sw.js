const CACHE_PREFIX = 'naap-parking-';
const CACHE_NAME = `${CACHE_PREFIX}v28`;
const OFFLINE_URL = '/offline.html';
const ASSETS_TO_CACHE = [
  OFFLINE_URL,
  '/styles.css?v=20260828-ops1',
  '/design-system.css?v=20260829-directory-search',
  '/manifest.json',
  '/icons/favicon-32.png',
  '/icons/apple-touch-icon.png',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/icons/icon-maskable-512.png',
  '/offline-sync.js?v=20260828-ops1',
  '/js/qr-behavior-classifier.js',
  '/js/ui-states.js?v=20260826-ui1',
  '/js/qr-token-parser.js?v=20260826-accuracy1',
  '/js/scan-readiness-model.js?v=20260828-ops1',
  '/js/ml-qr-detector.js?v=20260828-ops1',
  '/js/scanner-guidance.js?v=20260827-ml1',
  '/js/scanner-device-check.js?v=20260828-ops1'
];
const OPTIONAL_ASSETS_TO_CACHE = [
  'https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js',
  'https://unpkg.com/html5-qrcode@2.3.8/html5-qrcode.min.js',
  'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Manrope:wght@400;500;600;700;800&family=Plus+Jakarta+Sans:wght@500;600;700;800&family=Sora:wght@600;700;800&display=swap'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll(ASSETS_TO_CACHE).then(() => Promise.allSettled(
        OPTIONAL_ASSETS_TO_CACHE.map(asset => cache.add(asset))
      ));
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames
          .filter(name => name.startsWith(CACHE_PREFIX) && name !== CACHE_NAME)
          .map(name => caches.delete(name))
      );
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;

  const requestUrl = new URL(event.request.url);

  // Rendered pages are network-only because they can contain authenticated
  // information. When the network is unavailable, serve the static fallback.
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).catch(() => caches.match(OFFLINE_URL))
    );
    return;
  }

  if (requestUrl.origin === self.location.origin && requestUrl.pathname.startsWith('/api/')) return;

  const unavailableResponse = () => new Response('Offline and resource not cached.', {
    status: 503,
    statusText: 'Service Unavailable',
    headers: new Headers({ 'Content-Type': 'text/plain' })
  });

  if (requestUrl.origin === self.location.origin) {
    const networkResponse = fetch(event.request);
    const cacheUpdate = networkResponse.then(response => {
      if (response && response.status === 200 && response.type === 'basic') {
        const responseToCache = response.clone();
        return caches.open(CACHE_NAME).then(cache => cache.put(event.request, responseToCache));
      }
    });
    event.waitUntil(cacheUpdate.catch(() => undefined));
    event.respondWith(
      caches.match(event.request).then(cachedResponse => (
        cachedResponse || networkResponse
      )).catch(unavailableResponse)
    );
    return;
  }

  event.respondWith(
    fetch(event.request)
      .catch(() => caches.match(event.request).then(cachedResponse => cachedResponse || unavailableResponse()))
  );
});
