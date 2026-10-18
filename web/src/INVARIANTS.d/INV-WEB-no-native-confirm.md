- **INV-WEB-no-native-confirm** No non-test file under `web/src` calls or references the
  browser's native `confirm()` (bare `confirm(`, or `window`/`globalThis`/`self`/`top`/`parent`
  `.confirm` / `['confirm']`). Destructive or access-removing actions ask through the shared
  in-app dialog, `components/ui/useConfirm` (`requestConfirm` + the `confirmDialog` element,
  built on `ui/Dialog`), whose wording is the old `confirm()` message verbatim. Why: #3153 and
  DEMO-WALK-4 — a native dialog is unthemed, blocks the event loop and cannot be driven or
  asserted from the page. Guard:
  `__tests__/structure/noNativeConfirm.test.ts` (TypeScript-AST sweep over every non-test
  `.ts`/`.tsx`; calibrated red on eight shapes and green on five, and red in-tree when a site
  is reverted to `window.confirm`). **Not covered**: indirection through another binding
  (`const w = window; w.confirm()`), string-eval code, native dialogs outside `src/` (e2e
  helpers, `index.html`), and `alert()`/`prompt()`. The Playwright real-backend specs
  (`secrets-crud.spec.ts`) fail on any native `page.on('dialog')` event.
