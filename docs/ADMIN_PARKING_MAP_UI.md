# Responsive admin parking map

The `/admin/slots` zone view fills the available width up to 760px with two
fractional bay columns and a separate 56–72px drive lane. Bays use a 3:2 aspect
ratio, centered labels, muted 1px borders, and status-tinted backgrounds. A blue
ring identifies the selected bay; keyboard focus retains a visible outline. The lane
has its own darker surface, dashed centerline, and occasional arrows. Column gaps
are 8–10px, row gaps are 10px, and 12px planter/curb bars separate bay groups.
One zone is visible at a time. The page owns vertical
scrolling; the map has no nested vertical scroll box. The existing table remains
available, with its own horizontal scrolling on small screens.

## Files

| File | Responsibility |
| --- | --- |
| `views/admin_slots.ejs` | Loads the map assets and connects existing render, selection, and refresh flows to the presentation helper. |
| `public/admin-parking-map.css` | Admin-only bay geometry, surface, status colors, controls, responsive sizing, and motion preferences. |
| `public/js/admin-parking-map.js` | Zone summaries, highlight legend, safe tooltips, keyboard focus, find-available selection, conditional zoom, and brief animations. |
| `public/sw.js` | Versions and precaches the new assets for the installed app. |
| `tests/theme.test.js` | Verifies the template and service worker reference the same assets. |
| `e2e/admin-parking-map.spec.js` | Exercises responsive layout, accessibility, keyboard/table selection, refresh/failure states, zoom, and empty zones. |
| `playwright.parking-map.config.js` | Runs the map checks on desktop, phone, tablet, dark themes, and reduced motion. |
| `e2e/page-polish.spec.js` | Retains the status-color regression with muted 1px bay borders and explicit status labels. |

The local organized checkout uses `views/admin/parking-spaces.ejs` for the template.
Its backend does not supply separate zone settings, so its selector uses zone
names from the existing initial inventory. Release-only threshold forms are not
added to that checkout. Both backends and their existing fetch wrappers stay intact.

## Interaction

- The zone selector includes existing configured zones and shows their available
  count. It changes only which zone is displayed.
- The legend highlights a status without removing slots, changing the existing
  search/filter controls, or requesting additional data. Click the same status
  again to clear the highlight.
- Arrow keys move focus between adjacent bays; Enter selects using the original
  button handler. Home and End focus the first and last bay in the visible zone.
- **Find available slot** selects a green available bay nearest to the selected
  bay's position in the drawing. With no selection in the zone, it uses the first
  bay by the existing ordering. This is visual proximity, not measured physical
  distance. It does not assign a vehicle, change eligibility, or include reserved
  bays in its suggestions. Existing search and status filters remain in force.
- Plates, owner names, reservations, and maintenance reasons come only from the
  existing overview data. Missing values are omitted. Hover or keyboard focus
  shows details; Escape dismisses the tooltip. Stored text is inserted as text,
  never interpreted as HTML.
- Fit, plus, and minus controls appear only when a drawing is wider than its
  container. The normal responsive two-column drawing needs no zoom controls.

## Preserved behavior and limits

No routes, API calls, polling intervals, database records, authentication, roles,
assignment rules, or backend queries changed. The helper decorates the existing
buttons and uses their original selection/history flow. Refresh errors retain the
previous data and the existing error feedback.

Basketball retains 20 spaces, the existing ordering, and dividers between groups.
Hangar retains the previously requested left-side-only arrangement. Its 20 rows
still require page scrolling; turning it into two occupied columns would misstate
the physical arrangement. Guard and scanner maps keep their existing layouts.

Zone counts are four distinct visual categories: available, occupied, reserved,
and maintenance. An unused reserved space is counted under reserved. Occupied
reserved spaces count as occupied. Disabled spaces count as maintenance, even if
a vehicle remains parked; its available plate and car icon remain visible.
Existing overall totals and API filters still follow their original definitions
(the backend's available count can include unused reserved spaces). Empty or
legacy zones already in the data are shown, not deleted or renamed.

This repository renders Express/EJS pages with vanilla JavaScript, rather than
React. The map therefore reuses the existing motion helpers, native Web Animations
API, and CSS transitions instead of adding a React/Framer Motion runtime. No new
dependencies were added. Movement uses transform and opacity, with 240 ms
ease-out entrances and at most eight staggered bays per zone. Existing selection,
inspector, status cross-fade, and lane effects are reused. Reduced motion, hidden
tabs, data-saving mode, and low-power devices suppress decorative movement.

## Verification

The map suite covers 1920px, 1280px, 768px, and 390px widths, dark themes, reduced
motion, and a narrow 320px low-power case. Geometry checks cover road clearance,
proportions, centered labels, full-width drawing, and curb size. Taller bays use
more page height; no extra scrolling container is introduced.

Run with a disposable local database and existing test accounts. Never point
browser tests at production data.

```sh
node --test
npx playwright test --config=playwright.parking-map.config.js
npx playwright test --config=playwright.pages.config.js --grep "parking status|contrast"
npx playwright test e2e/parking-layout.spec.js
```

Set `E2E_BASE_URL`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `GUARD_USERNAME`, and
`GUARD_PASSWORD` for the local test server. The new map suite mocks overview and
history responses, including missing data, a live arrival, and a failed refresh.
It does not modify parking records. Existing parking-layout tests cover the real
local inventory, guard selection, and intercepted bulk-action confirmation forms.

In the organized local checkout, `npm run lint` validates JavaScript and
`npm run build` validates the EJS templates. The release checkout serves these
assets directly and has no frontend bundle/build step.
