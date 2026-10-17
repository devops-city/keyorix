### Testing
- **Test reliability (TEST-RELIABILITY-2).** The gRPC interceptor tests no longer share the per-IP failed-auth limiter across tests and `-count` repeats (#2945); `fuzzutil.Guard` reuses a runner goroutine and timer per call instead of spawning a goroutine and a 3s timer (#2431); the web `openapiDrift` exemptions are keyed by finding kind, so one written for optionality cannot hide a type change at the same path (#2868).

### Fixed
- **Audit full-verification job status.** `GET /api/v1/audit/verify/jobs/{id}` could report a job that had just finished as `interrupted`: the dead-process check ran after the job cleared its local id but against the state read before it saved its result. The status is now re-read before a job is declared interrupted.
