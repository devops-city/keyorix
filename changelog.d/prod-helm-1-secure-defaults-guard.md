### Changed
- Helm chart: the pod-hardening guard now also covers init containers and the `helm test` pod (drop ALL capabilities, no privilege escalation, read-only root filesystem, non-root, RuntimeDefault seccomp), not just the Deployment containers.
