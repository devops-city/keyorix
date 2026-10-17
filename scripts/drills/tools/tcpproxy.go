//go:build ignore

// tcpproxy is a minimal TCP forwarder for the disaster drill: it stands between the
// server and PostgreSQL so the drill can reproduce what a PostgreSQL restart looks like
// from the server's side (established connections reset, new connections refused while
// it is down, accepted again when it is back) without owning the database process.
//
// Usage: go run tcpproxy.go <listen-addr> <target-addr>
// Signals: SIGUSR1 = go down (close the listener and every open connection);
//
//	SIGUSR2 = come back (listen again on the same address); SIGTERM = exit.
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: tcpproxy <listen-addr> <target-addr>")
		os.Exit(2)
	}
	listenAddr, target := os.Args[1], os.Args[2]

	var (
		mu    sync.Mutex
		ln    net.Listener
		conns = map[net.Conn]struct{}{}
	)
	up := func() {
		mu.Lock()
		defer mu.Unlock()
		if ln != nil {
			return
		}
		l, err := net.Listen("tcp", listenAddr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "listen:", err)
			os.Exit(1)
		}
		ln = l
		go func(l net.Listener) {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go handle(c, target, &mu, conns)
			}
		}(l)
	}
	down := func() {
		mu.Lock()
		defer mu.Unlock()
		if ln != nil {
			_ = ln.Close()
			ln = nil
		}
		for c := range conns {
			_ = c.Close()
			delete(conns, c)
		}
	}

	up()
	fmt.Println("tcpproxy ready")
	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGTERM, syscall.SIGINT)
	for s := range sig {
		switch s {
		case syscall.SIGUSR1:
			down()
		case syscall.SIGUSR2:
			up()
		default:
			down()
			return
		}
	}
}

func handle(c net.Conn, target string, mu *sync.Mutex, conns map[net.Conn]struct{}) {
	t, err := net.Dial("tcp", target)
	if err != nil {
		_ = c.Close()
		return
	}
	mu.Lock()
	conns[c], conns[t] = struct{}{}, struct{}{}
	mu.Unlock()
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(t, c)
	go cp(c, t)
	<-done
	_ = c.Close()
	_ = t.Close()
	mu.Lock()
	delete(conns, c)
	delete(conns, t)
	mu.Unlock()
}
