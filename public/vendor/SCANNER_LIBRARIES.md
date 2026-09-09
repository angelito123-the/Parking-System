# Scanner libraries

These pinned browser bundles are served from the application so camera startup
does not depend on a third-party CDN. Both projects use the Apache 2.0 license;
their license files are included beside the bundles.

| Library | Version | Upstream | Bundle source |
| --- | --- | --- | --- |
| jsQR | 1.4.0 | https://github.com/cozmo/jsQR | https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js |
| html5-qrcode | 2.3.8 | https://github.com/mebjas/html5-qrcode | https://cdn.jsdelivr.net/npm/html5-qrcode@2.3.8/html5-qrcode.min.js |

When upgrading, update the versioned URLs in both scanner templates and
`public/sw.js`, bump the service-worker cache version, and run `npm run test:camera`.
