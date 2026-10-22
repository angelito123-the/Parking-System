# Parking, student and sticker presentation

These changes enhance the existing Express/EJS frontend. This checkout does not use React, so no React runtime or Framer Motion dependency was added. CSS, the existing `NaapMotion` helpers, and native browser animations provide the requested effects. Routes, form field names, HTTP methods, validation rules, eligibility, database operations and role checks remain unchanged.

## Parking spaces

- Green means available, amber occupied, blue reserved, and gray blocked/maintenance. Every state has text and an icon. Reservation is a **space type**, not a new occupancy state: an empty reserved bay has a blue outline and an Available badge; occupied or blocked reservations use amber or gray and retain a Reserved label. This preserves assignment rules and existing summary counts.
- The map retains the basketball dividers and the hangar's left-side layout. It has a taller viewport, a static asphalt texture, thin scrollbars, hover depth and a selection ring. The desktop inspector stays in view while scrolling.
- Changed states cross-fade through a short overlay; the border color itself is never animated. The dashed lane moves for 400ms on pointer hover, with no background animation loop on phones.
- All available chips are horizontally scrollable, including reserved spaces with an explicit reservation marker. Selecting a chip opens the map, applies the existing slot search, focuses the bay and scrolls it into view. Map and table retain shared filters and selection.

## Students

- Registration has equal-width columns on larger screens and one column on phones. Existing validation messages animate into view; touched valid fields receive a small confirmation. Optional vehicle fields retain their existing inclusion/exclusion rules.
- Vehicle sections fade and slide in or out. Closing sections immediately become inert, and rapid toggles cancel the previous animation safely.
- Tabs have a sliding underline and a cross-fade. The directory retains its existing details/Edit/overflow actions, with a filled Edit button, rotating disclosure chevron and nested vehicle cards. Keyboard Escape and arrow navigation complement the existing overflow menus.
- Skeleton rows appear during native directory filter/page-size submissions. No requests, delays, or simulated loading states were added. Existing server success messages generate the shared success toast, now with an animated checkmark.

## Stickers

- View QR is the primary action. Download, Print card, Copy link and Replace QR are compact 44px icon controls with accessible names and native tooltips. Revoke remains a separate destructive action with the existing confirmation.
- The QR preview is a native modal dialog with focus containment, Escape, return focus, loading/error messages and an original-link fallback. The original image route and downloadable links are preserved.
- Successful clipboard writes show a temporary checkmark and toast. Clipboard failure preserves the existing manual-copy prompt. Active, expired and revoked badges retain server-calculated states, with icons and a finite Active pulse.
- Sticker issuance uses the existing form validation and native submit/loading behavior. Success is shown only after the server confirms it.

## Motion and accessibility

Effects animate transform and opacity for 200–400ms. Skeleton shimmer runs only during pending navigation. Same-document View Transitions cross-fade tabs and map/table views where supported; other browsers use a short fade. The existing light/dark palette, visible focus rings and mobile layouts are retained. Reduced-motion preferences, hidden tabs, data-saving mode and low-core devices suppress decorative effects. No business state waits for an animation to finish.

## Verification

Run `node --test` and, in the organized development checkout, `npm run lint` and `npm run build`. Browser coverage is in `e2e/page-polish.spec.js` with `playwright.pages.config.js` (desktop, phone, dark phone and reduced motion), alongside the existing `playwright.ui.config.js` suite. Use a dedicated local test database; do not enable browser write tests against production.

The service-worker cache and asset query versions were bumped so installed apps receive the updated presentation. Existing data, authentication and private-response caching rules were not changed.

Verified on October 22, 2026: 169 code tests; lint and production build (48 JavaScript files, 26 templates); 16 page-specific browser checks; 78 existing UI checks after rerunning the corrected directory interaction (six viewport-specific skips); four checks against the local development preview; and the installed-app cache/offline check. Browser checks cover desktop, phone, dark mode, reduced motion, keyboard operation and automated WCAG AA audits. Visual review also checked the registration, directory, parking and sticker screens. Physical phone performance still depends on the device and browser.

## Changed files (release checkout)

| Files | Purpose |
| --- | --- |
| `public/page-polish.css`, `public/js/page-polish.js` | Shared controls, page effects, accessible disclosures, QR dialog and feedback |
| `public/parking-layout.css`, `public/js/parking-layout.js` | Semantic bay colors, icons, texture, selection and lane effects |
| `views/admin_slots.ejs` | Legend, chips, selection and map/table presentation hooks |
| `views/students.ejs` | Registration disclosure, tab transitions and accessible details chevron |
| `views/stickers.ejs` | Compact QR controls, preview, badges and copy feedback |
| `views/partials/header.ejs`, `views/verify.ejs`, `public/sw.js` | Asset loading and installed-app cache version |
| `e2e/page-polish.spec.js`, `playwright.pages.config.js` | New page interaction and accessibility coverage |
| `e2e/ui-usability.spec.js` | Check QR replacement in its new compact-control location |
| `tests/design-consistency.test.js`, `tests/phosphor-icons.test.js`, `tests/theme.test.js` | Current style/cache versions, additional control classes and existing SVG metric charts |
| `docs/PAGE_POLISH.md` | Implementation notes, file list and validation |

Equivalent template edits were mirrored to the organized development checkout (`views/admin/parking-spaces.ejs`, `students-and-vehicles.ejs`, `parking-stickers.ejs`, `views/layouts/header.ejs` and `views/verification/qr-verification.ejs`). Its existing includes and API fetch wrapper were preserved.
