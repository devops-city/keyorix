- **INV-GRPC-rest-walk-parity** Every REST route family in the committed route inventory
  (`scripts/e2e/routes.json`, regenerated and drift-checked by `server/http`
  `TestRouteInventoryIsCurrent`) either has at least one gRPC method mapped into it (and is then
  walked by the low-privilege and dead-credential walks automatically, which enumerate
  `GetServiceInfo`) or is listed in `restOnlyFamilies` with a reason; every registered gRPC method
  maps to a real REST route or carries a `grpcOnlyReason`; a family leaves `restOnlyFamilies` the
  moment a method maps into it. Why: the REST walks cover every route family, the gRPC walks cover
  the registered methods, and nothing tied the two together, so a new REST family (or a new RPC) could
  slip past one set of walks unclassified. The join is a hand-written table because
  `keyorix.proto` has no `google.api.http` annotations (ADR-106 withdrawn, INV-GRPC-06); both sides
  of it are derived and checked. Guard:
  `authz_walk_rest_parity_test.go:TestGRPCMethodsHaveRESTCounterpartOrReason`. Not covered: route
  parity inside a covered family (ADR-105: gRPC is deliberately partial) and decision parity for
  the same principal (INV-GRPC-02 for secret reads).
<!-- section: Cross-transport parity -->
