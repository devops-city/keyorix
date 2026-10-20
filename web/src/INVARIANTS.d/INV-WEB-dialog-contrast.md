- **INV-WEB-dialog-contrast** The title and message of every modal/dialog surface in `web/src`
  reach WCAG AA (4.5:1) on the surface they sit on, in both the light and the dark theme. Why:
  #3153 — the revoke dialog drew a dark title on the dark dialog surface, and the shared
  `Dialog` fix was the only thing pinned. Guard: `__tests__/structure/dialogContrast.test.tsx`
  (resolver: `test/contrast.ts`, reads inline `var(--token)` styles and class names through
  `index.css`): (1) an inventory of every dialog surface (Radix `Dialog` import, `aria-modal` /
  `<dialog>` / `role="dialog"`, `fixed inset-0 z-40|50` overlay) that must be registered, audited
  or exempt with a reason; every `<Modal>` must carry a `title` or be registered with the files
  that draw its heading; (2) rendered audits of `Modal`, `Dialog` (4 types), the Sharing revoke
  dialog, `useConfirm`, `SessionTimeoutWarning` and `CmdKSearch`, plus a static class/style audit
  of every heading inside a `<Modal>`/`<Dialog>` and of the untitled-modal bodies
  (`SecretDetailView`, the drift and rotation-plan panels); (3) calibration: a title equal to its
  background, the #3153 fixed-dark title, an unknown palette class and a non-literal className
  each fail the same audit. Fail closed: a colour it cannot resolve is a violation, not a skip.
  **Not covered**: text other than titles, messages and the palette input (button labels, the
  session countdown colour, icon badges), hover/focus states, the sr-only Sidebar drawer title
  and the NotificationBell click-catcher (exempt in the registry), colours a page applies to a
  dialog from outside its components, non-modal banners (`AbsoluteSessionExpiryWarning`), and
  real pixel rendering (jsdom has no CSS engine; the Playwright theme check in
  `e2e/real/sharing-page-names.spec.ts` is the browser-level cover, pending e2e VM here).
