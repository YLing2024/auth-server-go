package oidc

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"auth-server-go/internal/redis"
)

// readOnlyRedis is a tiny RESP endpoint that answers the read commands
// ReadCookieSession issues and records every command name, so the test can
// prove the path never writes.
type readOnlyRedis struct {
	ln   net.Listener
	mu   sync.Mutex
	seen map[string]int
}

func newReadOnlyRedis(t *testing.T, get map[string]string, hashes map[string]map[string]string, ttl map[string]int) *readOnlyRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &readOnlyRedis{ln: ln, seen: map[string]int{}}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn, get, hashes, ttl)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *readOnlyRedis) record(cmd string) {
	f.mu.Lock()
	f.seen[cmd]++
	f.mu.Unlock()
}

func (f *readOnlyRedis) counts() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]int{}
	for k, v := range f.seen {
		out[k] = v
	}
	return out
}

func (f *readOnlyRedis) serve(conn net.Conn, get map[string]string, hashes map[string]map[string]string, ttl map[string]int) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		args, err := readTestCommand(br)
		if err != nil {
			return
		}
		cmd := strings.ToUpper(args[0])
		f.record(cmd)
		switch cmd {
		case "HELLO":
			_, _ = io.WriteString(conn, "-ERR unknown command 'HELLO'\r\n")
		case "PING":
			_, _ = io.WriteString(conn, "+PONG\r\n")
		case "GET":
			if v, ok := get[args[1]]; ok {
				_, _ = io.WriteString(conn, "$"+strconv.Itoa(len(v))+"\r\n"+v+"\r\n")
			} else {
				_, _ = io.WriteString(conn, "$-1\r\n")
			}
		case "HGETALL":
			fields := hashes[args[1]]
			_, _ = io.WriteString(conn, "*"+strconv.Itoa(len(fields)*2)+"\r\n")
			for k, v := range fields {
				_, _ = io.WriteString(conn, "$"+strconv.Itoa(len(k))+"\r\n"+k+"\r\n")
				_, _ = io.WriteString(conn, "$"+strconv.Itoa(len(v))+"\r\n"+v+"\r\n")
			}
		case "TTL":
			n, ok := ttl[args[1]]
			if !ok {
				n = -2
			}
			_, _ = io.WriteString(conn, ":"+strconv.Itoa(n)+"\r\n")
		default:
			_, _ = io.WriteString(conn, "-ERR unsupported command "+cmd+"\r\n")
		}
	}
}

func readTestCommand(br *bufio.Reader) ([]string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	if len(line) == 0 || line[0] != '*' {
		return nil, io.ErrUnexpectedEOF
	}
	count, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
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

func newTestProvider(t *testing.T, fake *readOnlyRedis) *Provider {
	t.Helper()
	host, port, _ := net.SplitHostPort(fake.ln.Addr().String())
	n, _ := strconv.Atoi(port)
	store := redis.New(host, n, 0)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = store.Close()
	})
	store.Start(ctx)
	deadline := time.Now().Add(time.Second)
	for !store.Available() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &Provider{
		store:           store,
		cookieName:      "HomeAuth",
		subject:         "linden",
		legacy:          map[string]bool{"HomeAuth": true},
		sessionTTL:      7 * 86400,
		shortSessionTTL: 900,
		logger:          logger,
	}
}

func cookieRequest(token string) *http.Request {
	r := httptest.NewRequest("GET", "/api/me", nil)
	r.AddCookie(&http.Cookie{Name: "HomeAuth", Value: token})
	return r
}

// TestReadCookieSessionLegacy pins the read-only legacy path: subject
// normalisation, createdAt from the metadata hash (ms → s) and expiresAt from
// the Redis TTL, with no renewal writes.
func TestReadCookieSessionLegacy(t *testing.T) {
	token := strings.Repeat("a", 64)
	fake := newReadOnlyRedis(t,
		map[string]string{token: "HomeAuth"},
		map[string]map[string]string{"auth:session:" + token: {"createdAt": "1792498323000", "remember": "0"}},
		map[string]int{token: 120},
	)
	p := newTestProvider(t, fake)

	got, err := p.ReadCookieSession(context.Background(), cookieRequest(token))
	if err != nil {
		t.Fatalf("ReadCookieSession: %v", err)
	}
	if got == nil {
		t.Fatal("session = nil, want a snapshot")
	}
	if got.Subject != "linden" {
		t.Errorf("Subject = %q, want linden", got.Subject)
	}
	if got.CreatedAt != 1792498323 {
		t.Errorf("CreatedAt = %d, want 1792498323", got.CreatedAt)
	}
	if got.Remember {
		t.Error("Remember = true, want false")
	}
	if delta := got.ExpiresAt - (time.Now().Unix() + 120); delta < -2 || delta > 2 {
		t.Errorf("ExpiresAt differs from now+TTL by %ds, want <=2", delta)
	}
	if n := fake.counts()["EXPIRE"]; n != 0 {
		t.Errorf("EXPIRE issued %d times, want 0 (read-only)", n)
	}
}

// TestReadCookieSessionSSO covers the shared cookie record, including the
// missing-remember default and auth_time as the login time.
func TestReadCookieSessionSSO(t *testing.T) {
	token := "sso-token-value"
	fake := newReadOnlyRedis(t,
		map[string]string{ssoPrefix + SHA256Hex(token): `{"sub":"linden","auth_time":1792498323,"remember":false}`},
		nil,
		map[string]int{ssoPrefix + SHA256Hex(token): 300},
	)
	p := newTestProvider(t, fake)

	got, err := p.ReadCookieSession(context.Background(), cookieRequest(token))
	if err != nil {
		t.Fatalf("ReadCookieSession: %v", err)
	}
	if got == nil || got.Subject != "linden" || got.CreatedAt != 1792498323 || got.Remember {
		t.Fatalf("session = %+v, want linden/1792498323/remember=false", got)
	}
	if delta := got.ExpiresAt - (time.Now().Unix() + 300); delta < -2 || delta > 2 {
		t.Errorf("ExpiresAt differs from now+TTL by %ds, want <=2", delta)
	}
	if n := fake.counts()["EXPIRE"]; n != 0 {
		t.Errorf("EXPIRE issued %d times, want 0 (read-only)", n)
	}
}

// TestReadCookieSessionMissing checks that an unknown cookie is simply
// unauthenticated rather than an error.
func TestReadCookieSessionMissing(t *testing.T) {
	fake := newReadOnlyRedis(t, nil, nil, nil)
	p := newTestProvider(t, fake)

	got, err := p.ReadCookieSession(context.Background(), cookieRequest("unknown"))
	if err != nil || got != nil {
		t.Fatalf("ReadCookieSession = (%+v, %v), want (nil, nil)", got, err)
	}
}

// TestReadCookieSessionRedisDown makes sure an unreachable store becomes an
// error the handler can turn into authenticated:false, not a 500.
func TestReadCookieSessionRedisDown(t *testing.T) {
	store := redis.New("127.0.0.1", 1, 0)
	t.Cleanup(func() { _ = store.Close() })
	p := &Provider{store: store, cookieName: "HomeAuth", subject: "linden", logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	if got, err := p.ReadCookieSession(context.Background(), cookieRequest("token")); err == nil || got != nil {
		t.Fatalf("ReadCookieSession = (%+v, %v), want error when store is unavailable", got, err)
	}
}
