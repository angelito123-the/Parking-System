# Form usability and code review — 12 September 2026

This pass improves completing forms and recovering from mistakes, following the dashboard and directory changes in the previous interface review.

## User-facing changes

- Student registration, account creation, password changes, and visitor registration show specific inline errors, an error summary with field links, and focus the first field that needs correction. Client-side errors keep entered values on the page.
- Password forms offer Show/Hide buttons and a checklist that updates while typing. The browser and server use the same password rules, including the previously unexplained restriction on predictable starting words. Confirmation fields detect mismatches before submission.
- New-account roles include plain-language guidance and default to Guard. An administrator can still select Admin.
- Removing the optional vehicle section disables its fields, so a removed vehicle is not accidentally submitted. Reopening the section restores the values and focuses the plate field.
- Visitor forms explain when the end time must be later than the start. Contact fields use the phone-friendly telephone input.
- Backup downloads no longer activate the page-navigation loading state indefinitely. Download completion does not cause a normal page navigation, so the form remains usable for another action.
- Offline queues are uploaded in batches matching the server's 100-record limit. Only explicitly acknowledged records are deleted; failed or partially accepted batches retain the remaining records.

Screenshots use test data: [registration errors](form-usability/registration-errors.png), [password guidance](form-usability/password-guidance.png).

## Code organization

New form behavior lives in `public/js/form-feedback.js`, with opt-in annotations on the relevant forms. Password policy is shared through `public/js/password-policy.js`, imported by `lib/security.js`. Offline movement and scanner-metric uploads share one batching helper instead of separate request/acknowledgement implementations.

The system still has substantial maintenance debt. `server.js` is approximately 9,300 lines and combines routing, SQL, background workers, reporting, and streaming. Several EJS files combine large templates, styles, and scripts; the student view alone is over 2,000 lines. A staged cleanup should extract services and route groups with behavior tests first, then move page scripts and styles into dedicated assets. This pass does not claim to have untangled the entire application.

Two areas identified by inspection deserve a separate follow-up: the live-event streams register disconnect handlers after awaiting their initial database snapshot, and their lifecycle is not explicitly tied to later session revocation. These paths need dedicated disconnect/revocation integration tests and lifecycle cleanup. They were not changed in this UI-focused pass.

## Verification

- `npm test`: 97 passed, including new large-queue, partial-acknowledgement, failed-batch and retry tests.
- `npm run test:ui`: 29 passed; four platform-specific cases skipped. Covers retained form values, error focus, optional-vehicle payloads, password matching and visibility, visitor dates, repeat downloads, navigation, search, filters, and scanner startup.
- Camera regression suite: 26 passed across desktop and emulated phone profiles.
- Full page review: 39 page/profile checks without detected accessibility violations, page errors, or panel overflow.
- Focused form checks: nine page/size combinations, including 320-pixel dark mode, with no detected accessibility violations or overflowing controls.
- `npm audit --omit=dev`: zero reported production dependency vulnerabilities at review time.

Tests used an isolated local database, Chromium, axe-core, simulated camera input, and mocked form submissions/downloads where appropriate. They did not send email or modify production records. Physical phones, Safari, and assistive technology were not tested. Server-side errors can still navigate to an error page; the field-preservation improvement applies to mistakes caught before submission.
