# Interface improvements — 11 September 2026

The dashboard and student directory now put common tasks and working information closer to the top of the page. This follows the mobile navigation and camera usability work in [the previous review](UI_REVIEW_2026-09-10.md).

- **Dashboards:** clear page headings, readable summary figures, and compact shortcuts replace the large instructional cards. The admin vehicle roster appears before secondary summaries. The guard scanner remains a prominent action, with separate shortcuts for manual lookup, visitors, and a remote camera.
- **Student directory:** compact tabs, a visible search field, and optional filters reduce scrolling. Advanced filters open when they are applied, and Reset clears search, filters, and sorting. CSV template download is grouped with the import controls.
- **Student records:** desktop values and actions align with their headings. Narrow screens use cards with compact information fields, including at tablet widths where the previous table could become cramped.
- **Sign-in:** fewer notices, a simple Sign in button, account help, 16-pixel phone inputs, and a larger password visibility button. Username entry avoids automatic capitalization. The page no longer automatically focuses an input, and reduced-motion settings remove entrance delays.
- **Caching:** updated stylesheet references and service worker v37 deliver the new interface to returning users.

## Screenshots

These screenshots contain isolated test records, not production activity.

| Screen | Updated interface |
| --- | --- |
| Admin dashboard | [Desktop](interface-refresh/admin-desktop.png) |
| Student directory | [Desktop](interface-refresh/directory-desktop.png), [phone](interface-refresh/directory-phone.png) |
| Guard dashboard | [Phone](interface-refresh/guard-phone.png) |
| Sign-in | [Small phone, 320 × 568](interface-refresh/login-phone.png) |

On a 390 × 844 phone viewport, the student search field begins at 352 pixels and the first student record at 567 pixels. Both are visible on the initial screen with the test data. The admin vehicle roster section begins at 529 pixels on a 1440-pixel desktop viewport.

## Verification

- `npm test`: 93 checks passed.
- `npm run test:ui`: 17 browser tests passed. Four cases are intentionally skipped because they apply only to desktop columns or phone navigation.
- The UI suite checks real sign-in, password visibility, search results, filter persistence and reset, keyboard-operated disclosures, CSV controls, student details, column alignment, tabs, navigation focus, and camera startup.
- The full review script checked 39 page/profile combinations without browser errors, panel overflow, or detected accessibility violations. Final focused checks covered the changed dashboards and directory in desktop, phone, dark mode, and 320-pixel layouts; all 12 passed. Expanded directory filters also fit those screen widths.
- Sign-in accessibility checks passed at 320, 390, 768, and 1440 pixels. At 320 × 568, the Sign in button ends at 451 pixels and remains visible without scrolling.

Checks used Chromium, axe-core, and an isolated local database. Physical phones, Safari, and assistive technology were not tested in this pass.
