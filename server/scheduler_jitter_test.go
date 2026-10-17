package main

import (
	"testing"
	"time"
)

func TestDefaultRandN_Bounds(t *testing.T) {
	if got := defaultRandN(0); got != 0 {
		t.Fatalf("n=0: got %v", got)
	}
	for range 200 {
		if got := defaultRandN(time.Second); got < 0 || got >= time.Second {
			t.Fatalf("out of range: %v", got)
		}
	}
}
