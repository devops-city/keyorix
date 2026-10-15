- **INV-SW-fence-resolves-no-names** Nothing the fence functions or the guard's own sessions run
  resolves a name through a writer's `search_path`: the functions are created with
  `SET search_path = pg_catalog, pg_temp` and qualify every catalog relation and function; the
  guard's sessions pin the same search_path after reading their schema (`pinSessionSchema`) and
  qualify every Keyorix object with it. A temp table named like a catalog, or a function or operator
  of the same name in a schema the writer lists first, changes nothing the fence checks or counts.
  Why: REVIEW-SINGLE-WRITER-2 N1. Guard: `TestFence_NameResolutionCannotBeHijacked` (red on every
  shadow without the fix; the operator shadow red with qualification but without the pinned
  search_path), `TestFenceSQL_QualifiesEveryFunction`.
