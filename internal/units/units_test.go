package units

import "testing"

func TestParseSize(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		err  bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{"none", 0, false},
		{"512", 512, false},
		{"1kb", 1024, false},
		{"512kb", 512 * 1024, false},
		{"1mb", 1 << 20, false},
		{"2.5gb", int64(2.5 * (1 << 30)), false},
		{"2.5GB", int64(2.5 * (1 << 30)), false},
		{"12b", 12, false},
		{"-1", 0, true},
		{"abc", 0, true},
	}
	for _, c := range cases {
		got, err := ParseSize(c.in)
		if c.err {
			if err == nil {
				t.Errorf("ParseSize(%q) = %d, want error", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", c.in, got, err, c.want)
		}
	}
}

func TestParseTTL(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		err  bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{"none", 0, false},
		{"24h", 24 * 3600, false},
		{"7d", 7 * 24 * 3600, false},
		{"2w", 14 * 24 * 3600, false},
		{"90m", 90 * 60, false},
		{"-1h", 0, true},
		{"abc", 0, true},
	}
	for _, c := range cases {
		got, err := ParseTTL(c.in)
		if c.err {
			if err == nil {
				t.Errorf("ParseTTL(%q) = %v, want error", c.in, got)
			}
			continue
		}
		if err != nil || int64(got.Seconds()) != c.want {
			t.Errorf("ParseTTL(%q) = %v, %v; want %d seconds", c.in, got, err, c.want)
		}
	}
}
