### Documentation
- **ADR-115 (local audit journal) parked.** The prototype was measured; the journal only improved median latency over the existing audit group commit while adding complexity and an undetectable-loss tail, so the ADR is marked Parked with an Outcome section. Revisit only if group commit becomes the bottleneck.
