package store

import "testing"

func TestRetryJitterN_Bounds(t *testing.T) {
	if got := retryJitterN(0); got != 0 {
		t.Fatalf("n=0: got %d", got)
	}
	if got := retryJitterN(-5); got != 0 {
		t.Fatalf("n<0: got %d", got)
	}
	for range 200 {
		if got := retryJitterN(10); got < 0 || got >= 10 {
			t.Fatalf("out of [0,10): %d", got)
		}
	}
}
