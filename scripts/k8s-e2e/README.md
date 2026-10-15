# scripts/k8s-e2e

Real-cluster end-to-end journeys for the Kubernetes delivery paths (`run.sh`,
`make k8s-e2e`; needs Docker, kind, helm, kubectl, openssl, go). Manual target,
not run in CI. Flow and journey list: the header of `run.sh`.

| Journey | Covers |
|---|---|
| J1 | helm install (bundled Postgres), bootstrap, MFA enrol, CLI secret round-trip |
| J2 | helm lint / template / kubeconform on all three charts, NetworkPolicies exist |
| J3 | operator: `KeyorixSecret` reaches Ready, target Secret value |
| J4 | k8s-sync agent: sync and prune-on-mapping-removal |
| J5 | External Secrets Operator webhook provider |
| J6 | `secureBaseline.existingSecret` (see below) |

## J6: secureBaseline.existingSecret

Pre-creates the TLS/metrics Secret, installs the chart pointing at it, then:

- no chart-generated `<fullname>-secure-baseline` Secret exists, and the server,
  web and Postgres workloads mount the pre-created one;
- two `helm upgrade` runs with the same values leave the Secret (resourceVersion
  and a hash of its data), the server certificate, pod UIDs, restart counts,
  workload generations and the `checksum/secure-baseline` annotation identical
  (nothing rolls);
- an upgrade pointed at a Secret missing `server.key` fails with
  `missing required key(s): server.key`, the error contains no PEM and no
  metrics token, and the running release is untouched.

Secret contents are never printed: only hashes and the sanitized error line.

J6 needs only the server and web images and no CLI login, so it runs first and
can run alone, which skips building the operator/k8s-sync images and J1-J5:

```sh
KEYORIX_K8S_E2E_ONLY=j6 KEYORIX_K8S_E2E_CLUSTER=my-cluster ./scripts/k8s-e2e/run.sh
```

Other knobs: `KEYORIX_K8S_E2E_CLUSTER` (kind cluster name),
`KEYORIX_K8S_E2E_KEEP_CLUSTER=0` (delete the cluster on exit),
`KEYORIX_K8S_E2E_IMAGE_TAG`.
