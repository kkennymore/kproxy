package metrics

import (
	"bytes"
	"strings"
	"testing"
)

func TestCounterAndGaugeRender(t *testing.T) {
	r := NewRegistry()
	reqs := r.Counter("kproxy_requests_total", "Total requests.", "tunnel", "proto")
	up := r.Gauge("kproxy_uptime_seconds", "Uptime.")

	reqs.Inc("app.example.com", "http")
	reqs.Inc("app.example.com", "http")
	reqs.Add(5, "tcp:20000", "tcp")
	up.Set(42)

	var buf bytes.Buffer
	if err := r.Render(&buf); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := buf.String()

	for _, want := range []string{
		"# HELP kproxy_requests_total Total requests.",
		"# TYPE kproxy_requests_total counter",
		`kproxy_requests_total{tunnel="app.example.com",proto="http"} 2`,
		`kproxy_requests_total{tunnel="tcp:20000",proto="tcp"} 5`,
		"# TYPE kproxy_uptime_seconds gauge",
		"kproxy_uptime_seconds 42",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\n---\n%s", want, got)
		}
	}
}

func TestLabelEscaping(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("kproxy_test", "help.", "name")
	c.Inc(`we"ird\nname`)

	var buf bytes.Buffer
	if err := r.Render(&buf); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !strings.Contains(buf.String(), `kproxy_test{name="we\"ird\\nname"} 1`) {
		t.Fatalf("escaped label not rendered:\n%s", buf.String())
	}
}

func TestDuplicateRegistrationIsIdempotent(t *testing.T) {
	r := NewRegistry()
	a := r.Counter("x", "one.")
	b := r.Counter("x", "two.")
	if a != b {
		t.Fatal("duplicate registration returned a different metric")
	}
}

func TestLabelCountMismatchPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on wrong label count")
		}
	}()
	r := NewRegistry()
	c := r.Counter("y", "help.", "a", "b")
	c.Inc("only-one")
}

func TestGaugeLabelsAndEmptyFamilies(t *testing.T) {
	r := NewRegistry()
	g := r.Gauge("kproxy_tunnels", "Tunnels.", "proto")
	g.Set(3, "http")
	g.Set(2, "tcp")

	var buf bytes.Buffer
	if err := r.Render(&buf); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, want := range []string{
		`kproxy_tunnels{proto="http"} 3`,
		`kproxy_tunnels{proto="tcp"} 2`,
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("output missing %q\n---\n%s", want, buf.String())
		}
	}
}