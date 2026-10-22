# Student directory refinements

This update is limited to the existing EJS frontend. It adds no dependencies and preserves all routes, request fields, native form submissions, database operations and permission checks.

- The Details label stays unchanged and occupies a fixed width. Its existing chevron rotates with the expanded state.
- Editing a vehicle hides its Edit trigger instead of relabeling it Close. Save changes and Cancel remain at the bottom. Cancel closes the form and restores keyboard focus to Edit. As before, reopening a cancelled form retains the unsaved draft; Cancel does not reset or submit it.
- Directory vehicle panels and edit forms use an opt-in 240ms height/opacity disclosure. An inner spacing container lets the outer panel collapse to zero without animating borders or padding. Rapid reversals cancel the previous animation safely. Reduced motion and the existing low-power/hidden-tab handling suppress the effect.
- The edit form is a tinted part of the vehicle card, without its own border or shadow. Inputs have associated labels and a focus glow. Mobile Save/Cancel controls have consistent widths.
- Plates use a monospace font stack, uppercase presentation, and slashed-zero/tabular-number features to distinguish `0` from `O`. Typing or pasting into directory plate inputs uppercases the value while preserving selection and respecting composition input. Existing stored records are not rewritten by viewing the page.
- Inline errors use the browser's existing validity rules and messages. No plate format, length or optional-field requirement was added. Space is reserved for errors so validation does not move Save while it is being clicked.
- Save uses the existing loading indicator and POST/redirect flow. The existing server success flash produces a toast with a checkmark; error redirects produce error feedback. No optimistic save or extra API call was introduced.

## Files

| File | Change |
| --- | --- |
| `views/students.ejs` | Stable Details control, edit visibility/focus, labels and height-animation hooks |
| `public/page-polish.css` | Borderless form, plate typography, focus glow, stable error spacing and mobile actions |
| `public/js/page-polish.js` | Optional height mode, plate input casing and native validation presentation |
| `views/partials/header.ejs`, `public/sw.js` | Updated asset versions and installed-app cache |
| `tests/theme.test.js` | Updated cache-version expectation |
| `e2e/student-directory-ui.spec.js`, `playwright.directory.config.js` | Interaction, request-contract and accessibility checks |
| `docs/STUDENT_DIRECTORY_UI.md` | Behavior and verification notes |

Equivalent edits are mirrored to the organized development checkout, where the templates are `views/admin/students-and-vehicles.ejs` and `views/layouts/header.ejs`.

## Verification

Run `node --test`; use `npm run lint` and `npm run build` in the organized development checkout. Browser tests run with `npx playwright test --config=playwright.directory.config.js`, using a dedicated local service and `E2E_BASE_URL`, `ADMIN_USERNAME` and `ADMIN_PASSWORD`. Vehicle writes are intercepted; tests verify the original POST and redirect contracts without changing vehicle records.

Coverage includes rapid reversals, focus restoration, unchanged Cancel draft behavior, uppercase typing and cursor position, optional fields, native required validation, pending saves, success/error redirects, WCAG AA audits, mobile fit, dark mode and reduced motion. Existing page-polish tests also exercise parking, registration, directory menus and QR controls.

Verified on October 23, 2026: 169 code tests, 12 directory browser checks in the release preview, 12 checks in the local development preview, 16 existing page-polish checks, lint, production build (49 JavaScript files and 26 templates), and installed-app asset caching/offline fallback. Desktop and phone screenshots were visually reviewed.
