package interceptors

import (
	"go/constant"
	"go/types"
	"testing"

	"golang.org/x/tools/go/packages"
)

// TestRateLimitSweepParity_GRPCMatchesHTTP keeps the gRPC limiters' idle-eviction
// sweep on the HTTP limiters' schedule (#3429: the gRPC failure limiter had
// drifted to sweeping on every call). The HTTP constants are unexported in
// server/middleware, so their values are read by type-checking that package
// from source (export data omits unexported constants) rather than duplicated
// here: changing either side without the other fails this test.
func TestRateLimitSweepParity_GRPCMatchesHTTP(t *testing.T) {
	pkgs, err := packages.Load(&packages.Config{Mode: packages.NeedName | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo, Dir: "."}, "../../middleware")
	if err != nil {
		t.Fatalf("packages.Load: %v", err)
	}
	if packages.PrintErrors(pkgs) > 0 || len(pkgs) != 1 {
		t.Fatalf("server/middleware failed to load")
	}
	httpConst := func(name string) int64 {
		c, ok := pkgs[0].Types.Scope().Lookup(name).(*types.Const)
		if !ok {
			t.Fatalf("server/middleware has no constant %s — update this parity test", name)
		}
		v, exact := constant.Int64Val(c.Val())
		if !exact {
			t.Fatalf("%s is not an integer constant", name)
		}
		return v
	}
	for _, p := range []struct {
		http string
		grpc int64
	}{
		{"principalLimiterSweepEvery", grpcPrincipalLimiterSweepEvery},
		{"principalLimiterIdleTTL", int64(grpcPrincipalLimiterIdleTTL)},
	} {
		if got := httpConst(p.http); got != p.grpc {
			t.Errorf("middleware.%s = %d, gRPC counterpart = %d — the two transports' limiters must sweep alike", p.http, got, p.grpc)
		}
	}
}
