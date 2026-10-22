# Alerts presentation update

The actual frontend in this checkout is Express/EJS with plain JavaScript. This update reuses its CSS tokens, `NaapMotion`, `NaapPages` and browser animation helpers. It adds no React runtime, Framer Motion, or other dependencies. Backend routes, database operations, permissions, alert classification, request methods, payloads and existing refresh triggers are unchanged.

## Presentation

- Cards have severity accents and icon/text badges: red High/Critical, amber Medium, blue Low. Type names are readable, with an icon from the existing local icon font.
- Unread active cards have a tinted surface, bold title and NEW badge. Read cards use normal weight. Resolved cards take visual priority, with a muted surface, green check and recorded resolution time. Read/resolved cards do not show a Mark as read action. Active cards retain Resolve.
- Metadata uses labeled gate, zone and source chips. Dates explicitly use Philippine time. QR identifiers are shortened visually; the full value remains available in a tooltip and clipboard action, with the existing manual-copy fallback pattern. User-provided text remains escaped.
- The new summary counts displayed rows, excluding resolved cards from its Unread count and including Critical in High severity. The original operational totals remain intact.
- Filters collapse with an accessible disclosure. Applied-filter chips describe the last successful request and can be removed. Mark all read retains its existing global scope, which is now stated beside the button. Request results drive success/error toasts; failed writes never produce a success message.
- Refresh has a busy spinner and skeletons. Empty and failed states provide readable feedback. Keyboard focus returns to a remaining action, card heading or log heading after a refreshed row disappears.

## Motion and accessibility

Card entrance, movement and removal use transform/opacity for 240ms; disclosure and tint transitions use the same short effects. Only up to six visible cards animate at once. A newly arriving high-severity unread card has a finite, subtle icon pulse. Summary counters reuse the existing 360ms accessible count-up helper. Skeletons and refresh indicators run only while pending.

Reduced motion, hidden tabs, data-saving settings and low-core devices suppress decorative animation. Interactive controls retain visible focus and 44px touch targets. Color is paired with text and icons; light/dark themes use existing semantic tokens. No data update waits for an animation.

## Existing data and logic left unchanged

1. **Resolved is independent of read.** Automatic resolution does not necessarily create a per-user read record. The header's global unread count can therefore include resolved alerts, while this page's Unread summary excludes them. The page prioritizes resolved styling without writing a read record. Changing global counts requires an explicit backend decision.
2. **Initial snapshot and default filters differ.** The server initially supplies up to 30 alerts across all statuses; the form defaults to Active and subsequent requests use a limit of 60. A note explains the initial snapshot. Changing the default query was outside this presentation task.
3. **Summary counts are not system-wide totals.** The existing API does not supply aggregate high/resolved counts. The summary is explicitly labeled as covering displayed alerts. No additional query or request was introduced to calculate totals.
4. **Mark all read ignores page filters.** It marks every accessible alert for the current user/audience, including resolved or hidden alerts. The button's description makes this existing scope explicit.
5. **Overlapping refreshes can be skipped.** The existing `isFetching` guard drops a request while another is in progress. Applied chips show the filters used by the successful request; reapply filters if selections changed during loading. Request scheduling was not changed.
6. **Missing resolution dates remain missing.** Such cards say “time not recorded.” No timestamp is inferred from creation or update dates.

## Files

| File | Responsibility |
| --- | --- |
| `views/admin_alerts.ejs` | Card markup, summary, toolbar, filter chips and presentation hooks around existing requests |
| `public/alerts-ui.css` | Scoped severity, states, responsive layout and CSS effects |
| `public/js/alerts-ui.js` | Counts, animations, disclosure, clipboard feedback and focus preservation; no data requests |
| `public/js/ui-motion.js` | Exposes the existing count-up helper for reuse |
| `views/partials/header.ejs` | Loads Alerts styles only on this route and versions the shared helper |
| `public/sw.js` | Versions and caches the new public assets; private-response caching rules unchanged |
| `tests/theme.test.js` | Checks the updated installed-app cache version |
| `e2e/alerts-ui.spec.js`, `playwright.alerts.config.js` | Interaction, request-contract, escaping, accessibility and motion tests |
| `docs/ALERTS_UI.md` | Behavior notes, unchanged issues and verification |

The same scoped changes are mirrored to the organized development checkout, using `views/admin/alerts.ejs` and `views/layouts/header.ejs`. Its existing API wrapper, includes and filter options are preserved.

## Verification

Run `node --test` in the release checkout. Run `npm run lint` and `npm run build` in the organized development checkout. For browser coverage use `npx playwright test --config=playwright.alerts.config.js` with a dedicated local database, `E2E_BASE_URL`, `ADMIN_USERNAME` and `ADMIN_PASSWORD`. The Alerts tests mock notification reads/writes; only authentication touches the local test service. Never point regression tests that perform writes at production.

Verified on October 23, 2026: 169 code tests, 20 Alerts browser checks across desktop, phone, dark phone and reduced motion, six existing Admin/Guard notification-menu regression checks, five checks against the local development preview, lint, the production asset/template build (49 JavaScript files and 26 templates), and installed-app cache/offline behavior. Automated WCAG AA checks and visual review cover the new cards, toolbar and filters. Physical phone camera behavior was outside this Alerts-only change.
