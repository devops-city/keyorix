### Fixed
- **A secret you just deleted now shows up in the project's recycle bin without a page reload.**
  Deleting a secret (single or bulk) did not refresh the project settings "Recycle bin" list, which
  could stay stale for up to five minutes after in-app navigation; both delete actions now invalidate it.
