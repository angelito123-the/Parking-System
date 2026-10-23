# Live Updates presentation

`/admin/updates` keeps the existing Express/EJS page and its manual refresh and
20-second `GET /api/dashboard-stats` polling. No backend, database, authentication,
permissions, or API contract changes are part of this update.

## Files

| File | Responsibility |
| --- | --- |
| `views/admin_updates.ejs` | Responsive summary markup, feed controls, and presentation hooks around the existing refresh. |
| `public/live-updates-ui.css` | Page-scoped light/dark colors, responsive cards, sticky day headings, focus states, skeletons, and hover effects. |
| `public/js/live-updates-ui.js` | Local filters, keyed row reconciliation, scroll anchoring, relative dates, refresh feedback, and limited animations. |
| `views/partials/header.ejs` | Loads this stylesheet only on Live Updates. |
| `public/sw.js` | Versions and caches the new public assets for the installed app. |
| `e2e/live-updates-ui.spec.js`, `playwright.updates.config.js` | Browser coverage for layout, accessibility, filters, refresh, escaping, and row stability. |
| `tests/theme.test.js`, `tests/web-security-hardening.test.js` | Updated cache version and stored-text escaping checks. |

The organized local checkout uses `views/admin/live-activity.ejs` and
`views/layouts/header.ejs`; its existing API wrapper is retained.

## Interaction and animation

- Stats use four columns on desktop, two on tablet, and stacked rows on phones.
  Existing count-up motion runs on load. Changed values receive a short tint
  highlight. A positive overstay count has red styling and a soft pulse.
- Entry and exit have different arrow icons, text labels, and left accents.
  Unknown students have a warning icon and tint; non-valid scan results remain
  visible, so an attempted entry is not represented as a successful validation.
- Days and event timestamps use Philippine time. Exact timestamps are available
  through native tooltips and accessible labels. Missing values are labeled.
- Filters search all currently loaded records and display the first 14 matches.
  All preserves the existing first-14 view. Filtering makes no network requests
  and does not affect the stat calculations.
- Existing row nodes are reused. New rows enter above them; a scrolled feed keeps
  its visible row in place where that record is still in the loaded window.
- Entrance, movement, highlight, and feedback effects use transform/opacity for
  150–400 ms. New-row highlights wait briefly before fading. Motion is limited to
  visible rows and disabled for reduced motion, data saving, low CPU concurrency,
  or a hidden tab. Skeleton shimmer and refresh rotation run only while loading.
- The codebase is EJS/vanilla JavaScript, not React. Native Web Animations and the
  existing `NaapMotion` helper implement these effects without adding React or
  Framer Motion dependencies.

## Meaning of Live and Last updated

The initial timestamp is when the server rendered the displayed snapshot. After
a successful refresh it is when the browser received and displayed that response.
It ticks without extra API requests. It is **not** the latest vehicle-event time
or a database synchronization watermark. A failed refresh retains the timestamp
and previous feed, and presents an error. Offline and stale states are explicit.
Live means the existing polling is operating; it does not imply a streaming feed.

## Data limitations left unchanged

- The API returns at most 80 movement records, and this page calculates today's
  entry/exit counts from those rows using UTC dates. It also counts matching
  actions regardless of their validation result. These are the existing rules.
  Day headings use Philippine time, so near midnight the headings and counters
  can refer to different calendar days.
- The initial inside/overstay lists are capped at 30; the refresh endpoint uses
  20. Counters remain list lengths, even though aggregate metrics also exist in
  the response. They can undercount or change at the first refresh. Correcting
  this requires an approved data/logic change.
- The current movement query does not return `scan_source` or a stable log ID.
  The interface says “Method unavailable” rather than inferring manual versus
  scanned. When explicit source data is supplied, its method and icon are shown.
- Row identity uses a composite of existing fields and duplicate occurrence
  order. Truly identical duplicate records cannot be distinguished reliably
  until the API exposes the log ID.
- Polling timing and response ordering are unchanged. Overlapping requests can
  complete out of order. Malformed timestamps can still fail the existing stats
  calculation; this presentation change does not rewrite that calculation.

## Verification

Use a local scratch database and configured Admin credentials:

```sh
node --test
npx playwright test --config=playwright.updates.config.js
```

The browser suite mocks dashboard responses and does not create parking records.
It covers desktop, tablet, phone, dark mode, and reduced motion. Check the actual
page with both empty and populated data; refresh, filter, scroll down the feed,
and confirm a refresh preserves the visible row. The local organized checkout
also supports `npm run lint` and `npm run build`.

Validated on 2026-10-23: 169 code tests passed; all 25 browser scenarios passed
against the release preview and the local checkout (including the corrected
contrast recheck). WCAG AA checks passed in all five display modes. Local lint
passed and the build checked 50 JavaScript files and 26 templates. No new package
dependencies were added. All database-backed review runs used local scratch data.
