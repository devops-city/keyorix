- **INV-SW-fence-refuses-foreign-writes** While a holder lives, every write to a fenced table from a
  session without the holder's tag is refused: every statement kind (TRUNCATE included), under
  `session_replication_role = replica`, and from a session on another `search_path` writing
  schema-qualified names (the holder is looked up for the fired table's schema, every object the
  functions touch is qualified with `TG_TABLE_SCHEMA`). An UPDATE that changes only a listed
  bookkeeping column (`last_used_at`) is neither fenced nor counted. Guard:
  `TestFence_RefusesEveryForeignWriteWhileHolderLives` (red with the triggers left non-ALWAYS, and
  with the lock looked up by the session's schema).
