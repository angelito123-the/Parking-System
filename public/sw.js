const CACHE_NAME = 'naap-parking-v1';
const ASSETS_TO_CACHE = [
  '/',
  '/login',
  '/scanner',
  '/styles.css',
  '/manifest.json',
  '/offline-sync.js',
  'https://unpkg.com/html5-qrcode@2.3.8/html5-qrcode.min.js',
  'https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=Outfit:wght@500;600;700&display=swap'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      console.log('Opened cache, caching assets');
      return cache.addAll(ASSETS_TO_CACHE);
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.filter(name => name !== CACHE_NAME).map(name => caches.delete(name))
      );
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', event => {
  // Only cache GET requests
  if (event.request.method !== 'GET') return;

  // Skip API calls from being served from the SW Cache entirely
  // We handle them in the client-side offline DB logic instead
  if (event.request.url.includes('/api/')) return;

  event.respondWith(
    caches.match(event.request).then(response => {
      // Return cached version if found
      if (response) {
        // Fetch new version in the background to update cache for next time (Stale-while-revalidate)
        fetch(event.request).then(res => {
          if (res && res.status === 200) {
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, res));
          }
        }).catch(() => {});
        return response;
      }

      // If not in cache, fetch from network
      return fetch(event.request).then(response => {
        // Don't cache cross-origin or non-success unless it's the font API
        if (!response || response.status !== 200 || response.type !== 'basic') {
          return response;
        }
        
        // Cache the new resource
        const responseToCache = response.clone();
        caches.open(CACHE_NAME).then(cache => {
          cache.put(event.request, responseToCache);
        });
        
        return response;
      }).catch(err => {
        console.error('Fetch failed (offline) and not in cache:', event.request.url);
        // Fallbacks like an offline.html could go here if implemented
      });
    })
  );
});
