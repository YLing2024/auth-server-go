// Package redis wraps the go-redis client with the readiness semantics the
// legacy service exposed: handlers report 503 while the store is unreachable,
// but the process still starts so a cold Redis does not crash the auth centre.
package redis

import (
	"context"
	"sync/atomic"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// Store is the session/code/SSO backing store.
type Store struct {
	client *goredis.Client
	ready  atomic.Bool
}

// New builds a client. enableOfflineQueue=false mirrors the legacy client: calls
// fail fast when Redis is down instead of queueing.
func New(host string, port, db int) *Store {
	return &Store{
		client: goredis.NewClient(&goredis.Options{
			Addr:            host + ":" + itoa(port),
			DB:              db,
			MaxRetries:      2,
			DisableIdentity: true,
		}),
	}
}

// Client exposes the underlying client for the packages that need raw commands.
func (s *Store) Client() *goredis.Client { return s.client }

// Available reports whether the last health probe succeeded.
func (s *Store) Available() bool { return s.ready.Load() }

// Start runs an initial probe (bounded) and then a background health loop until
// ctx is cancelled. It never blocks startup on a down Redis.
func (s *Store) Start(ctx context.Context) {
	s.ready.Store(s.probe(ctx))
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				s.ready.Store(s.probe(probeCtx))
				cancel()
			}
		}
	}()
}

func (s *Store) probe(ctx context.Context) bool {
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return s.client.Ping(probeCtx).Err() == nil
}

// Close releases the connection pool.
func (s *Store) Close() error { return s.client.Close() }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
