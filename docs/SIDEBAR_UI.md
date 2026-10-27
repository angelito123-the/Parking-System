# Sidebar hover rail and Live Updates indicator

The sidebar uses the existing Express/EJS templates and locally hosted Phosphor
icons. Navigation remains ordinary page loads. Routes, role visibility,
authentication, database queries, API calls, and business rules are unchanged.
No dependencies were added.

## Layout and interaction

- Desktop devices with hover and a fine pointer start with a 72px icon rail.
  Pointer entry waits 80 ms before expanding to 280px; pointer exit waits 200 ms
  before collapsing. Keyboard focus expands immediately and prevents collapse
  until focus leaves. Focus is never discarded to force a collapse.
- The sidebar is a fixed overlay. Unpinned content always has a 72px gutter, so
  hovering does not reflow the page. Pinning reserves 280px and stays expanded.
  The pin at the bottom persists using `naap-sidebar-pinned`, with storage access
  guarded by try/catch. The earlier manual-collapse preference is not used.
- Width transitions take 240 ms with ease-out. Labels fade without wrapping;
  icon positions and section heights stay stable. Existing section preferences
  remain available; navigating to a page reveals its section.
- The account card, pin, version, and logout remain outside the scrolling menu.
  The shared navy active highlight, visible focus states, icon tooltips, and
  role-specific links are retained.
- Small screens and devices without hover or with a coarse pointer use the
  off-canvas drawer, including large touch tablets. The drawer supports a
  backdrop, tap outside, Escape, a deliberate left swipe, and focus trapping.
  Vertical scrolling and changes in browser chrome height do not close it.
- Reduced motion removes transitions and hover delays. Low-power devices skip
  decorative animation. Only sidebar width animates layout; page content never
  animates width or margin during hover.

## Red indicator: cause and correction

Previously both Alerts and Live Updates had `data-sidebar-unread`. The sidebar
copied `summary.unread_total` from the notification API into both badges. That
value counts unread alerts, including resolved alerts with no read record. It
is not an unseen movement count, and visiting Live Updates does not mark alerts
as read. This caused the persistent, unrelated red badge.

Alerts still uses its original summary. Live Updates now has its own
`data-sidebar-live` indicator, listening to the already-connected
`naap:notifications-updated` browser event. It counts only confirmed movement
messages: recorded entry/exit, confirmed pending entry, visitor entry/exit, and
the accepted count from a completed offline sync. Denials, pending requests,
notification reads/resolutions, and summary polling do not increment it.

The count is browser-local and scoped to the authenticated user's ID and role.
It persists across reloads. Opening or returning to the visible Live Updates
page acknowledges received updates, including across tabs for that account.
Messages received while that page is visible are treated as being viewed.
The page's existing 20-second feed refresh remains unchanged.

The badge is a dot at the icon corner in the rail and a count pill when expanded.
The link has an accessible label such as "Live Updates, 3 new updates". Unchanged
counts do not replace badge nodes or replay animations, avoiding poll flicker.
Event fingerprints suppress duplicates; the last 512 fingerprints are retained.
Only SHA-256 fingerprints and counters/timestamps are stored, never QR tokens,
plate numbers, or other event details. Secure-context Web Crypto is required for
fingerprinting; if unavailable, the indicator stays inactive. Blocked storage
falls back to memory for the current page.

## Limits intentionally left untouched

The existing stream has no stable event IDs, replay cursor, or server-side
per-user seen marker. It cannot reliably reconstruct movements missed while
closed/disconnected, or synchronize read state across devices. This update
therefore counts received movement notifications, not an authoritative historical
unread total. Storage clearing also clears that local count.

A complete cross-device solution would add a stable movement-event sequence,
a per-user last-seen sequence, and replay/unseen-count support on the backend.
Those API/database changes are outside this task and were not made. Existing
alert read/resolved rules and overstay indicators are also unchanged.

## Files and verification

- `views/partials/header.ejs`: pin, separate badges, account identifier, preference
  bootstrap, and versioned assets.
- `views/partials/footer.ejs`: touch-capable drawer breakpoint and focus handoff.
- `public/sidebar-polish.css`: fixed hover rail, pin layout, badge geometry, touch
  drawer, responsive styling, and motion preferences.
- `public/js/sidebar-polish.js`: hover/focus delays, pin persistence, original
  navigation controls, and Alerts-only summary updates.
- `public/js/sidebar-live-updates.js`: received movement count and seen state.
- `public/sw.js`, `tests/theme.test.js`: cache version and asset checks.
- `e2e/sidebar-polish.spec.js`: role links, keyboard/pin/hover/drawer behavior,
  layout stability, event deduplication, persistence, cross-tab clearing, and
  WCAG AA audits.

The organized local checkout uses `views/layouts/header.ejs` and
`views/layouts/footer.ejs`. Existing local API-client wrappers are retained.

```sh
node --test
npx playwright test --config=playwright.sidebar.config.js
npx playwright test --config=playwright.header.config.js
```

Use local test accounts and a disposable database. The sidebar suite mocks
notification updates; it does not change parking data. The local checkout also
supports `npm run lint` and `npm run build`. Manual checks should include tabbing
into and out of the rail, pinning/reloading/unpinning, and reaching Reports and
User Accounts with the menu scrollbar on a short screen.
