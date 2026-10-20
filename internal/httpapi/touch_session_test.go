package httpapi

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"auth-server-go/internal/config"
	"auth-server-go/internal/redis"
)

// fakeRedis answers only the handful of commands touchSession issues. It is
// deliberately a real RESP endpoint so the test exercises go-redis, including
// the HELLO fallback, instead of mocking our own wrapper.
type fakeRedis struct {
	ln       net.Listener
	remember string

	mu       sync.Mutex
	expires  [][]string
	lastSeen string
}

func newFakeRedis(t *testing.T, remember string) *fakeRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeRedis{ln: ln, remember: remember}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *fakeRedis) addr() (string, int) {
	host, port, _ := net.SplitHostPort(f.ln.Addr().String())
	n, _ := strconv.Atoi(port)
	return host, n
}

func (f *fakeRedis) serve(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		args, err := readRESPCommand(br)
		if err != nil {
			return
		}
		switch strings.ToUpper(args[0]) {
		case "HELLO":
			// Force the RESP2 fallback; the test only needs simple replies.
			_, _ = io.WriteString(conn, "-ERR unknown command 'HELLO'\r\n")
		case "PING":
			_, _ = io.WriteString(conn, "+PONG\r\n")
		case "HGET":
			if len(args) >= 3 && args[2] == "remember" && f.remember != "" {
				_, _ = io.WriteString(conn, "$1\r\n"+f.remember+"\r\n")
			} else {
				_, _ = io.WriteString(conn, "$-1\r\n")
			}
		case "EXISTS":
			_, _ = io.WriteString(conn, ":1\r\n")
		case "HSET":
			if len(args) >= 4 {
				f.mu.Lock()
				f.lastSeen = args[len(args)-1]
				f.mu.Unlock()
			}
			_, _ = io.WriteString(conn, ":1\r\n")
		case "EXPIRE":
			f.mu.Lock()
			f.expires = append(f.expires, append([]string(nil), args...))
			f.mu.Unlock()
			_, _ = io.WriteString(conn, ":1\r\n")
		default:
			_, _ = io.WriteString(conn, "+OK\r\n")
		}
	}
}

func (f *fakeRedis) expireCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.expires)
}

func readRESPCommand(br *bufio.Reader) ([]string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	if len(line) == 0 || line[0] != '*' {
		return nil, io.ErrUnexpectedEOF
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		hdr, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		hdr = strings.TrimSuffix(strings.TrimSuffix(hdr, "\n"), "\r")
		if len(hdr) == 0 || hdr[0] != '$' {
			return nil, io.ErrUnexpectedEOF
		}
		size, err := strconv.Atoi(hdr[1:])
		if err != nil {
			return nil, err
		}
		buf := make([]byte, size+2)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:size]))
	}
	return args, nil
}

// TestTouchSessionRenewsOnlyRemembered is the regression guard for absolute
// short sessions: touchSession may update lastSeenAt, but it must never issue
// EXPIRE for remember=0.
func TestTouchSessionRenewsOnlyRemembered(t *testing.T) {
	for _, tc := range []struct {
		name     string
		remember string
		want     int
	}{
		{"short session never renews", "0", 0},
		{"remembered session slides", "1", 2},
		{"legacy session without field slides", "", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeRedis(t, tc.remember)
			host, port := fake.addr()
			store := redis.New(host, port, 0)
			t.Cleanup(func() { _ = store.Close() })
			s := &Server{
				cfg:   &config.Config{SessionDays: 7, SessionTTL: 7 * 86400, SessionShortTTL: 900},
				store: store,
			}
			// The throttle is process-wide; clear it so every subtest runs.
			lastSeenWrites.mu.Lock()
			lastSeenWrites.seen = map[string]int64{}
			lastSeenWrites.mu.Unlock()

			r := httptest.NewRequest("GET", "/api/verify", nil)
			s.touchSession(context.Background(), strings.Repeat("a", 64), r)
			time.Sleep(20 * time.Millisecond)

			if got := fake.expireCount(); got != tc.want {
				t.Fatalf("EXPIRE count = %d, want %d", got, tc.want)
			}
		})
	}
}
