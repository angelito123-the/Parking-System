# Header and Notifications UI

The shared header now keeps its section name in the top bar and leaves the page
title in the main heading. Student registration/directory tabs fit their labels,
stay aligned left, and keep their existing keyboard, hash, and form behavior.

## Notifications presentation

- The desktop panel opens from the bell with a 240 ms scale/fade; on phones it
  becomes a full-width bottom sheet. A soft backdrop dims and blurs the page.
  Escape, outside clicks, and the close button dismiss it and restore focus.
- Tab/Shift+Tab and programmatic focus stay inside the open panel. Header pointer
  actions dismiss it before opening the account menu or mobile navigation. A
  failed refresh that removes a focused row returns focus to the close button.
- Active unread rows have bold titles, tinted backgrounds, an Unread label, and
  severity icons. Different shapes and accessible names accompany the high/red,
  medium/amber, and low/blue colors. Read titles use normal weight. Resolved rows
  are muted and use green checks, without warning dots.
- Resolved records live in a collapsed, keyboard-accessible Resolved section.
  Its open state survives refreshes while that section remains in the results.
  Resolved-but-unread records retain their existing Mark read action in history.
- The server summary remains authoritative. “All caught up” requires zero active
  alerts, a successfully loaded list, and no active rows in that snapshot. It
  explicitly identifies unread history. A temporary contradiction between the
  summary and list is labeled “Alert status is updating…” until they agree.
- Times describe creation time, use Philippine calendar days for Yesterday, and
  tick while the panel is open. Exact creation timestamps appear in tooltips and
  accessible labels. Missing or invalid times are labeled rather than invented.
- Filter pills slide using measured transforms; list updates fade, and up to
  five displayed rows enter in a short stagger. Read changes use a settling fade.
  The Admin footer stays visible while the list scrolls.
- Mark all read displays a dismissible success or failure toast inside the focus
  trap. Success requires both a successful HTTP response and `ok: true`; a failed
  response never receives a success toast. The existing refreshes still run.

Only transform and opacity are animated (150–240 ms). Reduced motion, data
saving, two-core devices, and hidden tabs suppress scripted motion; low-power
mode also disables backdrop blur. No React/Framer Motion dependency was added:
this repository uses EJS and native JavaScript, so existing UI conventions and
the Web Animations API implement the effects.

## Files

| File | Change |
| --- | --- |
| `views/partials/header.ejs` | Section labels, dialog markup, presentation hooks, confirmed read-all feedback. |
| `public/header-polish.css` | Responsive panel, backdrop, states, focus styling, content-width Students tabs. |
| `public/js/header-polish.js` | Dialog motion/focus, grouped rendering, relative time, slide indicators, toasts. Contains no fetch calls. |
| `public/sw.js` | Cache the new public assets and advance the installed-app cache version. |
| `tests/theme.test.js` | Match the updated cache version. |
| `e2e/header-polish.spec.js`, `playwright.header.config.js` | Header, filters, focus, accessibility, errors, low-power mode, and tab checks. |
| `e2e/ui-usability.spec.js` | Update existing notification regressions for grouped history and focus trapping. |
| `docs/HEADER_NOTIFICATIONS_UI.md` | This handoff. |

The local organized checkout mirrors these changes; its shared header is
`views/layouts/header.ejs`. Its API wrapper and EventSource wrapper are preserved.

## Existing data and behavior left untouched

- Read state and resolved state are independent. The unread badge includes
  resolved-but-unread alerts, even with zero active alerts. No records are marked
  read or resolved merely by displaying or collapsing them.
- The dropdown requests up to 20 matching records; summary counts cover all
  alerts visible to the current role. The history section counts loaded rows,
  not the full historical total.
- High priority still requests `severity=high`, which excludes `critical` alerts
  if that severity exists. Changing this requires a filter/API decision.
- Query strings, endpoints, POST payloads, credentials, the EventSource stream,
  and the 15-second summary polling remain unchanged. Existing overlapping
  requests may still arrive out of order. The UI does not introduce sequencing
  or additional requests to repair this.
- Individual Mark read/Resolve actions retain their previous refetch-only error
  behavior. Explicit success/failure feedback was added only for Mark all read.
- View all alerts remains Admin-only. Guards keep their existing dropdown and
  permissions. No backend, database, authentication, or RBAC files were edited.

## Verification

Run against a local review database with the existing E2E credentials configured:

```sh
node --test
npx playwright test --config=playwright.header.config.js
npx playwright test --config=playwright.ui.config.js --grep "notification and account panels"
```

The browser checks mock notification reads/writes and exercise both roles without
changing real notification or parking records. Display modes include desktop,
tablet, phone, dark mode, and reduced motion. The narrow-device check uses 320 px
and a two-core profile. The local checkout also supports `npm run lint` and
`npm run build`.

Validation completed on 2026-10-25: 169 code tests passed; all 30 header scenarios
passed in both the release preview and local checkout, including targeted final
rechecks. Six existing Admin/Guard notification regressions also passed. WCAG AA
audits passed in all five display modes. Local lint and build passed (51
JavaScript files, 26 templates). No new dependencies were added.
