// Package ratelimit provides a stdlib-only token bucket used to enforce
// per-key request rate and bandwidth limits.
package ratelimit

import (
	"sync"
	"time"
)

// Bucket is a token bucket refilled at a fixed rate. A zero rate means the
// bucket never limits: Take always succeeds and Wait returns immediately.
type Bucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

// New returns a bucket that refills at rate tokens per second, holding at most
// burst tokens. A rate of zero returns an unlimited bucket.
func New(rate, burst float64) *Bucket {
	return &Bucket{rate: rate, burst: burst, tokens: burst, last: time.Now()}
}

// Take consumes n tokens if available without blocking, reporting success.
func (b *Bucket) Take(n float64) bool {
	if b.rate <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill()
	if b.tokens >= n {
		b.tokens -= n
		return true
	}
	return false
}

// Wait blocks until n tokens are available, then consumes them. Unlike Take,
// the refill is not capped at the burst, so requests larger than the burst
// still complete.
func (b *Bucket) Wait(n float64) {
	if b.rate <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		now := time.Now()
		b.tokens += now.Sub(b.last).Seconds() * b.rate
		b.last = now
		if b.tokens >= n {
			b.tokens -= n
			return
		}
		need := n - b.tokens
		sleep := time.Duration(need / b.rate * float64(time.Second))
		b.mu.Unlock()
		time.Sleep(sleep)
		b.mu.Lock()
	}
}

func (b *Bucket) refill() {
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = now
}
