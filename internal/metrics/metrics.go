// Package metrics implements a tiny Prometheus-compatible registry with no
// external dependencies. It supports counters and gauges with a fixed label
// set per family and renders the Prometheus text exposition format.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Kind distinguishes counters from gauges.
type Kind int

const (
	Counter Kind = iota
	Gauge
)

// Metric is a single series family (one name with a fixed label set). It is
// safe for concurrent use.
type Metric struct {
	name, help string
	kind       Kind
	labels     []string

	mu     sync.Mutex
	series map[string]*series
}

type series struct {
	labels []string
	value  float64
}

func seriesKey(labels []string) string { return strings.Join(labels, "\x00") }

// Registry owns a set of named metric families.
type Registry struct {
	mu       sync.Mutex
	families map[string]*Metric
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{families: make(map[string]*Metric)}
}

// Counter registers a counter family, returning the existing one if already
// registered under the same name.
func (r *Registry) Counter(name, help string, labels ...string) *Metric {
	return r.family(name, help, Counter, labels...)
}

// Gauge registers a gauge family, returning the existing one if already
// registered under the same name.
func (r *Registry) Gauge(name, help string, labels ...string) *Metric {
	return r.family(name, help, Gauge, labels...)
}

func (r *Registry) family(name, help string, kind Kind, labels ...string) *Metric {
	r.mu.Lock()
	defer r.mu.Unlock()
	if m, ok := r.families[name]; ok {
		return m
	}
	m := &Metric{name: name, help: help, kind: kind, labels: labels, series: make(map[string]*series)}
	r.families[name] = m
	return m
}

// Labels returns the metric's declared label names.
func (m *Metric) Labels() []string { return m.labels }

func (m *Metric) seriesFor(labels []string) *series {
	if len(labels) != len(m.labels) {
		panic(fmt.Sprintf("metrics: %s expects %d label values, got %d", m.name, len(m.labels), len(labels)))
	}
	k := seriesKey(labels)
	s, ok := m.series[k]
	if !ok {
		s = &series{labels: append([]string(nil), labels...)}
		m.series[k] = s
	}
	return s
}

// Inc increments the series identified by the label values by one.
func (m *Metric) Inc(labels ...string) {
	m.Add(1, labels...)
}

// Add increments the series identified by the label values by delta.
func (m *Metric) Add(delta int64, labels ...string) {
	if delta == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seriesFor(labels).value += float64(delta)
}

// Set overwrites the series value (used for gauges).
func (m *Metric) Set(value int64, labels ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seriesFor(labels).value = float64(value)
}

// WriteTo renders the whole registry in the Prometheus text exposition format.
func (r *Registry) Render(w io.Writer) error {
	r.mu.Lock()
	names := make([]string, 0, len(r.families))
	for name := range r.families {
		names = append(names, name)
	}
	sort.Strings(names)
	families := make([]*Metric, 0, len(names))
	for _, name := range names {
		families = append(families, r.families[name])
	}
	r.mu.Unlock()

	for _, m := range families {
		if _, err := fmt.Fprintf(w, "# HELP %s %s\n", m.name, m.help); err != nil {
			return err
		}
		typ := "counter"
		if m.kind == Gauge {
			typ = "gauge"
		}
		if _, err := fmt.Fprintf(w, "# TYPE %s %s\n", m.name, typ); err != nil {
			return err
		}

		m.mu.Lock()
		keys := make([]string, 0, len(m.series))
		for k := range m.series {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		items := make([]*series, 0, len(keys))
		for _, k := range keys {
			items = append(items, m.series[k])
		}
		m.mu.Unlock()

		for _, s := range items {
			if _, err := fmt.Fprintf(w, "%s%s %s\n", m.name, formatLabels(m.labels, s.labels), formatValue(s.value)); err != nil {
				return err
			}
		}
	}
	return nil
}

func formatLabels(names, values []string) string {
	if len(names) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(n)
		b.WriteString(`="`)
		b.WriteString(escapeLabel(values[i]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

func escapeLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	return v
}

// formatValue renders integers without a decimal point.
func formatValue(v float64) string {
	if v == float64(int64(v)) {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}
