package main

import (
	"bytes"
	"testing"
)

// TestGenerate_IsDeterministic runs the generator twice in-process over the
// real storage package and requires identical output. The freshness test in
// the parent package (generated_fresh_test.go) is only sound if this holds: a
// generator whose output depended on map iteration or directory order would
// make that test flake instead of reporting real drift. It does not cover
// cross-toolchain go/format differences. Validated red by taking method order
// from map iteration instead of sort.Slice; dropping the import-name sort does
// NOT turn it red, because go/format re-sorts a single import block anyway.
func TestGenerate_IsDeterministic(t *testing.T) {
	root, err := findModuleRoot(".")
	if err != nil {
		t.Fatalf("findModuleRoot from the gen package dir: %v", err)
	}
	first, _, n, _, err := generate(root)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if n == 0 {
		t.Fatal("generate emitted zero methods; the fixture is not exercising the generator")
	}
	for i := range 5 {
		again, _, _, _, err := generate(root)
		if err != nil {
			t.Fatalf("generate (run %d): %v", i+2, err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("generator output differs between run 1 and run %d: output is non-deterministic", i+2)
		}
	}
}
