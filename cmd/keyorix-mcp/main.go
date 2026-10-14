/*
Keyorix MCP server — exposes read-only Keyorix secret access to an AI agent over the
Model Context Protocol (stdio JSON-RPC 2.0). It is a thin, audited proxy in front of the
Keyorix API: every read carries a least-privilege machine-identity token and is subject
to Keyorix's scoped permission, max_reads, suspension, and audit. Secret values are
never logged.

Configure it in your agent client (e.g. Claude Desktop/Code) as a stdio MCP server with
KEYORIX_URL and a scoped KEYORIX_TOKEN in the environment.

Copyright (C) 2025 Keyorix Contributors. Licensed under the AGPL-3.0-or-later.
*/
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/mcp"
)

// version is overridden at build time via -ldflags.
var version = "dev"

// defaultMaxReads is the per-process keyorix_get_secret ceiling applied when
// KEYORIX_MCP_MAX_READS is left unset. The documented minimal setup is KEYORIX_URL +
// KEYORIX_TOKEN only, which previously left the cap at 0 ("unlimited") — a
// prompt-injected agent with a broadly-scoped token got zero backstop against sweeping
// every secret the token can read. 100 is chosen as generous-but-bounded: comfortably
// above what a normal single-task agent session needs, while still giving a hard,
// non-infinite ceiling by default. Not safety-critical as an exact number — operators
// with legitimate high-volume needs raise it via KEYORIX_MCP_MAX_READS.
const defaultMaxReads = 100

// defaultMaxListCalls is the per-process keyorix_list_secrets ceiling applied when
// KEYORIX_MCP_MAX_LIST_CALLS is left unset — the same reasoning as defaultMaxReads
// (#G44): a listing call does no per-item value disclosure, but a manipulated agent
// can still be driven to repeat it an unbounded number of times in one session.
const defaultMaxListCalls = 100

// resolveMaxReads parses KEYORIX_MCP_MAX_READS. An empty raw value (the variable unset
// or blank) applies defaultMaxReads rather than "unlimited". A non-empty value that
// isn't a positive integer is a fatal misconfiguration, not a silent fallback —
// usedDefault reports whether the default was applied, for logging.
func resolveMaxReads(raw string) (n int, usedDefault bool, err error) {
	if raw == "" {
		return defaultMaxReads, true, nil
	}
	n, perr := strconv.Atoi(raw)
	if perr != nil || n <= 0 {
		return 0, false, fmt.Errorf("KEYORIX_MCP_MAX_READS must be a positive integer, got %q", raw)
	}
	return n, false, nil
}

// resolveMaxListCalls parses KEYORIX_MCP_MAX_LIST_CALLS, mirroring resolveMaxReads.
func resolveMaxListCalls(raw string) (n int, usedDefault bool, err error) {
	if raw == "" {
		return defaultMaxListCalls, true, nil
	}
	n, perr := strconv.Atoi(raw)
	if perr != nil || n <= 0 {
		return 0, false, fmt.Errorf("KEYORIX_MCP_MAX_LIST_CALLS must be a positive integer, got %q", raw)
	}
	return n, false, nil
}

// resolveAllowedRefs parses KEYORIX_MCP_ALLOWED_REFS. An empty raw value means "not
// configured" (nil patterns, no error) — unchanged, no restriction. A non-empty raw
// value that parses to zero usable patterns (e.g. a bare "," or all-whitespace/empty
// segments, such as from templating an empty list) is a misconfiguration: passing that
// nil/empty slice through to Server.SetAllowedRefs would be silently treated as "no
// restriction" — identical to never setting the variable — while a log line claiming
// "ref allowlist active: 0 pattern(s)" reads as confirmation the restriction IS in
// effect. Fail closed instead: refuse to start rather than run unrestricted while
// claiming otherwise.
func resolveAllowedRefs(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	var patterns []string
	for p := range strings.SplitSeq(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			patterns = append(patterns, p)
		}
	}
	if len(patterns) == 0 {
		return nil, fmt.Errorf("KEYORIX_MCP_ALLOWED_REFS is set but contains no usable patterns after parsing %q — refusing to start unrestricted; unset the variable entirely if no restriction is intended", raw)
	}
	return patterns, nil
}

func main() {
	// Logs go to stderr so they never corrupt the JSON-RPC stream on stdout.
	log.SetOutput(os.Stderr)
	log.SetPrefix("keyorix-mcp: ")

	baseURL := strings.TrimSpace(os.Getenv("KEYORIX_URL"))
	if baseURL == "" {
		log.Fatal("KEYORIX_URL is required (the Keyorix server base URL)")
	}
	token := strings.TrimSpace(os.Getenv("KEYORIX_TOKEN"))
	if token == "" {
		log.Fatal("KEYORIX_TOKEN is required (a least-privilege Keyorix machine-identity token)")
	}

	client, err := mcp.NewKeyorixClient(baseURL, token)
	if err != nil {
		log.Fatal(err)
	}
	server := mcp.NewServer(client, version)

	// Defense-in-depth (#122) — neither replaces the token's own server-side RBAC
	// scope: KEYORIX_MCP_ALLOWED_REFS (opt-in, off by default) further restricts which
	// refs this process will touch, and KEYORIX_MCP_MAX_READS (on by default —
	// defaultMaxReads applies when unset) bounds how many secret VALUES it will serve
	// in its lifetime, so a manipulated agent (steered by an injected instruction
	// inside some OTHER secret's returned value) has a hard ceiling on how much it can
	// sweep even if it tries.
	if raw := strings.TrimSpace(os.Getenv("KEYORIX_MCP_ALLOWED_REFS")); raw != "" {
		patterns, rerr := resolveAllowedRefs(raw)
		if rerr != nil {
			log.Fatal(rerr)
		}
		server.SetAllowedRefs(patterns)
		log.Printf("ref allowlist active: %d pattern(s)", len(patterns))
	}
	maxReads, usedDefault, merr := resolveMaxReads(strings.TrimSpace(os.Getenv("KEYORIX_MCP_MAX_READS")))
	if merr != nil {
		log.Fatal(merr)
	}
	server.SetMaxReads(maxReads)
	if usedDefault {
		log.Printf("KEYORIX_MCP_MAX_READS not set — applying default per-process read cap of %d (override via KEYORIX_MCP_MAX_READS)", maxReads)
	} else {
		log.Printf("per-process read cap active: %d", maxReads)
	}

	maxListCalls, usedListDefault, lerr := resolveMaxListCalls(strings.TrimSpace(os.Getenv("KEYORIX_MCP_MAX_LIST_CALLS")))
	if lerr != nil {
		log.Fatal(lerr)
	}
	server.SetMaxListCalls(maxListCalls)
	if usedListDefault {
		log.Printf("KEYORIX_MCP_MAX_LIST_CALLS not set — applying default per-process list-call cap of %d (override via KEYORIX_MCP_MAX_LIST_CALLS)", maxListCalls)
	} else {
		log.Printf("per-process list-call cap active: %d", maxListCalls)
	}

	log.Printf("ready (server %s) — read-only Keyorix tools over stdio", version)
	if err := server.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
