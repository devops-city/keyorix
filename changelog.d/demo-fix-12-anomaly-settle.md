### Fixed
- **A fresh demo no longer grows a red Alerts tile a few minutes after start (#3152).** The detector's first pass reports the seed's own first reads and writes as low-severity "first observed access" alerts (no baseline exists yet; detection and thresholds are unchanged). `scripts/demo/up.sh` now waits for that first pass and acknowledges exactly those alerts (new_user / new_ip / off_hours, low or medium, accessor one of the seeded demo principals); anything else stays open.

### Testing
- `scripts/demo/check.sh` gains a step that waits until the demo server has been up 6 minutes and fails if any anomaly alert is still open.
