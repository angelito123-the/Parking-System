# System review - 9 September 2026

The reviewed workflows passed in an isolated MariaDB database and local application. This review found and fixed failures beyond the initial camera problem; it does not certify every device, production record, or external service.

## Confirmed defects and fixes

| Area | Reproduced failure | Change |
| --- | --- | --- |
| Manual scanner | Missing offline support caused an uncaught error and permanent searching state, even online. Camera startup errors were difficult to retry. | Online lookup works independently of IndexedDB; unavailable offline storage shows a retry message; camera errors allow another attempt. |
| Movement history | The history panel was queried before its markup existed. Button clicks also recorded success before the server response. | Resolve the panel when rendering and add history only after a successful save or durable queue operation. |
| Reports | Blocking the external chart CDN caused `Chart is not defined`. | Bundle the existing pinned Chart.js version locally, include its license, and show a readable fallback if the asset fails. |
| Account access | Demoting or deleting a user left an existing privileged session usable. Session revocation examined only the first 500 records. | Revoke sessions on role changes and deletion, and remove the incomplete session scan limit. |
| Private image cache | A QR image fetched while signed in was served by the service worker after logout. | Restrict caching to an explicit public asset list and upgrade the cache to v35, removing old caches. |
| Timestamps | SQL `NOW()` was parsed eight hours ahead of JavaScript time when the database server used Asia/Singapore. | Initialize database sessions in UTC; keep daily counts and sticker expiry aligned with Philippine calendar dates. |
| Offline movements | A repeated or conflicting requested action could silently become the opposite action. Old events could override newer movement state. Cached stickers were not rechecked for expiry. | Reject conflicting/older events, retain audit details, show a sync warning, preserve idempotency, and recheck cached expiry. |
| Database failures | Several transaction routes acquired their connection outside their error handler. | Catch connection failures for registration, visitor decisions, CSV import, remote entry decisions, offline sync and metric batches. Handle session-revocation errors and malformed offline batches. |

## Verification

- 93 Node tests: authentication, authorization, password policy, data validation, backups, QR handling, operational behavior, database failure responses, private cache rules, and offline expiry.
- 26 Chromium browser tests across desktop and Pixel 7 profiles: fake camera startup/restart, permission denial/retry, unavailable decoder fallback, pending permission, missing offline support, failed IndexedDB access, lookup and accurate movement history.
- 12 integration workflow groups against an isolated local MariaDB instance: registration, QR issuance/rotation, manual entry/exit, duplicate prevention, remote scan confirmation with snapshot, offline retry/conflict/stale-event handling, account demotion/deletion session revocation, visitor approval and movements, CSV preview/import/tamper rejection, encrypted backup preview/restore/replay rejection, private QR access after logout, and timestamp consistency.
- 19 authenticated administrator/guard pages loaded without uncaught JavaScript errors while external page resources were blocked. Reports rendered using the local chart bundle and displayed their fallback when that bundle was deliberately blocked.
- Operational schema verification passed. `npm audit --omit=dev` reported zero known production dependency vulnerabilities at review time.

## Repeat the checks

Run `npm test` and `npm run test:camera` for checks that do not require a real database.

`scripts/review-system.js` exercises and changes records. Run it only with a dedicated local application and a disposable database whose name ends in `_review`. Configure `.env` for that database and the dedicated admin/guard accounts. In PowerShell:

```powershell
$env:REVIEW_BASE_URL = 'http://127.0.0.1:3018'
$env:REVIEW_ALLOW_WRITES = '1'
node scripts/review-system.js
npm run verify:schema
```

The script refuses remote application URLs and requires explicit write opt-in. Confirm that the running application uses the same isolated database as the script. It creates uniquely named fixtures and performs a backup restore against that database.

## Limits

Physical phone camera hardware, iOS Safari, actual QR scanning under gate lighting, and real SMTP delivery were not tested. Browser camera checks use a simulated video source; mobile checks use Chromium device emulation. Email tests use mocks and no review emails were sent. Production data was not modified for testing. Existing historical timestamps were not rewritten; the UTC connection change governs future operations and timestamp interpretation. Offline devices cannot learn about server-side revocations until they reconnect.
