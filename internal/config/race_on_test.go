//go:build race

package config

// raceEnabled mirrors internal/fuzzutil's guard_race.go/guard_norace.go pair.
const raceEnabled = true
