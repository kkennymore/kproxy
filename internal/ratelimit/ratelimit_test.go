package ratelimit

import (
	"testing"
	"time"
)

func TestBucketTakeLimits(t *testing.T) {
	b := New(2, 2)
	if !b.Take(1) || !b.Take(1) {
		t.Fatal("expected two tokens to be available")
	}
	if b.Take(1) {
		t.Fatal("expected bucket to be empty")
	}
}

func TestBucketRefills(t *testing.T) {
	b := New(10, 10)
	b.Take(10)
	if b.Take(1) {
		t.Fatal("expected bucket to be empty")
	}
	time.Sleep(150 * time.Millisecond)
	if !b.Take(1) {
		t.Fatal("expected bucket to have refilled after 100ms")
	}
}

func TestBucketWaitPaces(t *testing.T) {
	b := New(1000, 1000)
	start := time.Now()
	b.Wait(2000)
	elapsed := time.Since(start)
	if elapsed < 900*time.Millisecond {
		t.Fatalf("Wait(2000) at 1000/s returned after %v", elapsed)
	}
}

func TestBucketUnlimited(t *testing.T) {
	b := New(0, 0)
	if !b.Take(1) {
		t.Fatal("unlimited bucket must always grant")
	}
	done := make(chan struct{})
	go func() {
		b.Wait(1)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("unlimited Wait must return immediately")
	}
}
