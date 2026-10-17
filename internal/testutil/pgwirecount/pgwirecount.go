// Package pgwirecount is a test-only PostgreSQL wire-protocol proxy that counts
// the statements and round trips every client connection sends through it.
//
// It sits between the code under test and the real server, so it sees every
// pool the process opens (the GORM pool, the native pgx read pool, the audit
// flusher, lock pools) with no hook in production code. What it counts, per
// frontend message:
//
//   - a statement is an Execute ('E') or a simple Query ('Q'): one statement
//     the server runs. A pgx batch of N statements is N statements.
//   - a round trip is a Sync ('S') or a simple Query ('Q'): one point where
//     the client waits for the server. A pgx batch of N statements is one
//     round trip.
//
// The SQL of each statement is recovered from the Parse ('P') and Bind ('B')
// messages of the same connection, so a test can print what ran.
//
// What it does NOT see: anything sent over TLS. The proxied DSN is forced to
// sslmode=disable, and an SSLRequest from a client is refused with 'N', so a
// client that insists on TLS fails to connect rather than going uncounted.
//
// Nothing outside *_test.go files may import this package.
package pgwirecount

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Statement is one counted statement: its SQL as the client prepared or sent it.
type Statement struct {
	SQL string
}

// Proxy forwards connections to one upstream PostgreSQL server and counts what
// the clients send while counting is on.
type Proxy struct {
	ln       net.Listener
	upstream string

	mu         sync.Mutex
	counting   bool
	statements []Statement
	roundTrips int
}

// Start starts a proxy in front of the server dsn names and returns it with a
// DSN that reaches the same database through it. The proxy stops at test end.
func Start(t testing.TB, dsn string) (*Proxy, string) {
	t.Helper()
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("pgwirecount: parse dsn: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pgwirecount: listen: %v", err)
	}
	p := &Proxy{ln: ln, upstream: net.JoinHostPort(cc.Host, fmt.Sprint(cc.Port))}
	go p.accept()
	t.Cleanup(func() { _ = ln.Close() })
	proxied, err := rewriteDSN(dsn, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("pgwirecount: %v", err)
	}
	return p, proxied
}

// rewriteDSN points dsn (URL or keyword/value form) at addr with TLS off.
func rewriteDSN(dsn string, addr *net.TCPAddr) (string, error) {
	if strings.Contains(dsn, "://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "", err
		}
		u.Host = addr.String()
		q := u.Query()
		q.Set("sslmode", "disable")
		u.RawQuery = q.Encode()
		return u.String(), nil
	}
	// Keyword/value: a later key overrides an earlier one.
	return fmt.Sprintf("%s host=%s port=%d sslmode=disable", dsn, addr.IP, addr.Port), nil
}

// Count runs fn with counting on and returns the statements and round trips
// every connection sent meanwhile. Statements are in arrival order per
// connection; their order across connections is the order the proxy read them.
func (p *Proxy) Count(fn func()) ([]Statement, int) {
	p.mu.Lock()
	p.counting, p.statements, p.roundTrips = true, nil, 0
	p.mu.Unlock()
	fn()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.counting = false
	return append([]Statement(nil), p.statements...), p.roundTrips
}

func (p *Proxy) accept() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.serve(c)
	}
}

func (p *Proxy) serve(client net.Conn) {
	defer func() { _ = client.Close() }()
	server, err := net.Dial("tcp", p.upstream)
	if err != nil {
		return
	}
	defer func() { _ = server.Close() }()
	go func() {
		_, _ = io.Copy(client, server)
		_ = client.Close()
	}()
	if err := p.startup(client, server); err != nil {
		return
	}
	p.frontend(client, server)
}

const (
	sslRequestCode    = 80877103
	gssEncRequestCode = 80877104
)

// startup forwards the untyped startup message, refusing SSL/GSS encryption
// requests itself so the rest of the session stays readable.
func (p *Proxy) startup(client, server net.Conn) error {
	for {
		var hdr [8]byte
		if _, err := io.ReadFull(client, hdr[:]); err != nil {
			return err
		}
		n := binary.BigEndian.Uint32(hdr[:4])
		code := binary.BigEndian.Uint32(hdr[4:])
		if code == sslRequestCode || code == gssEncRequestCode {
			if _, err := client.Write([]byte{'N'}); err != nil {
				return err
			}
			continue
		}
		if n < 8 {
			return errors.New("pgwirecount: short startup message")
		}
		body := make([]byte, n-8)
		if _, err := io.ReadFull(client, body); err != nil {
			return err
		}
		if _, err := server.Write(append(hdr[:], body...)); err != nil {
			return err
		}
		return nil
	}
}

// frontend forwards typed frontend messages and counts them.
func (p *Proxy) frontend(client, server net.Conn) {
	prepared := map[string]string{} // statement name -> SQL
	portals := map[string]string{}  // portal name -> SQL
	for {
		var hdr [5]byte
		if _, err := io.ReadFull(client, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[1:])
		if n < 4 {
			return
		}
		body := make([]byte, n-4)
		if _, err := io.ReadFull(client, body); err != nil {
			return
		}
		switch hdr[0] {
		case 'P': // Parse: name, query, ...
			name, rest := cstring(body)
			query, _ := cstring(rest)
			prepared[name] = query
		case 'B': // Bind: portal, statement, ...
			portal, rest := cstring(body)
			stmt, _ := cstring(rest)
			portals[portal] = prepared[stmt]
		case 'C': // Close: 'S'|'P', name
			if len(body) > 0 {
				name, _ := cstring(body[1:])
				if body[0] == 'S' {
					delete(prepared, name)
				} else {
					delete(portals, name)
				}
			}
		case 'E': // Execute: portal, ...
			portal, _ := cstring(body)
			p.record(portals[portal], false)
		case 'Q': // simple Query
			query, _ := cstring(body)
			p.record(query, true)
		case 'S': // Sync
			p.mu.Lock()
			if p.counting {
				p.roundTrips++
			}
			p.mu.Unlock()
		}
		if _, err := server.Write(append(hdr[:], body...)); err != nil {
			return
		}
	}
}

func (p *Proxy) record(sql string, roundTrip bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.counting {
		return
	}
	p.statements = append(p.statements, Statement{SQL: sql})
	if roundTrip {
		p.roundTrips++
	}
}

func cstring(b []byte) (string, []byte) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), b[i+1:]
		}
	}
	return string(b), nil
}
