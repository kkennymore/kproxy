// Package units parses human-readable size and duration values shared by the
// CLI, the admin API and the relay (e.g. "1mb", "512kb", "30s", "7d").
package units

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseTTL parses a duration string. It accepts Go durations plus the "d"
// (days) and "w" (weeks) suffixes. An empty, "0" or "none" value means no
// expiry.
func ParseTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" || s == "none" {
		return 0, nil
	}
	for _, suf := range []struct {
		s string
		d time.Duration
	}{{"w", 7 * 24 * time.Hour}, {"d", 24 * time.Hour}} {
		if strings.HasSuffix(s, suf.s) {
			n, err := strconv.Atoi(strings.TrimSuffix(s, suf.s))
			if err != nil || n <= 0 {
				return 0, fmt.Errorf("invalid duration %q", s)
			}
			return time.Duration(n) * suf.d, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return d, nil
}

// ParseSize parses a byte size such as "512kb", "1mb" or "2.5gb" (binary
// units). An empty value means zero. A bare number is treated as bytes.
func ParseSize(s string) (int64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "0" || s == "none" {
		return 0, nil
	}
	mult := int64(1)
	for _, suf := range []struct {
		s string
		m int64
	}{{"kb", 1 << 10}, {"mb", 1 << 20}, {"gb", 1 << 30}, {"b", 1}} {
		if strings.HasSuffix(s, suf.s) {
			mult = suf.m
			s = strings.TrimSuffix(s, suf.s)
			break
		}
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return int64(n * float64(mult)), nil
}
