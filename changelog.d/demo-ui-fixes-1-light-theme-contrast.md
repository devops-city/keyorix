### Fixed
- **Light-theme secondary text is readable.** `--text-muted` (gray-400 on white, about 2.5:1) and the light `--danger`, `--error`, `--success` and `--warning` tokens now reach 4.5:1 as text on every light surface; the dark theme is unchanged. A unit test computes the ratio of every token pair so it cannot regress (DEMO-WALK-4 finding 5).
