package protocol

import (
	"bytes"
	"testing"
)

// FuzzReadFrame ensures the frame parser never panics on arbitrary input and
// never accepts a payload larger than the configured cap.
func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'x'})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		typ, id, payload, err := readFrame(bytes.NewReader(data))
		if err != nil {
			return
		}
		if len(payload) > int(maxFrameSize) {
			t.Fatalf("readFrame accepted %d-byte payload (max %d)", len(payload), maxFrameSize)
		}
		if id != 0 && payload != nil {
			// no-op: keep typ/id live so the optimizer can't drop the call
			_ = typ
		}
	})
}

// FuzzControlRoundTrip checks that control messages round-trip through the
// JSON codec stably: encoding a decoded message yields identical bytes.
func FuzzControlRoundTrip(f *testing.F) {
	f.Add("hello", "1.2.3", "secret", "http", "8080", "myapp", "app.example.com")
	f.Add("welcome", "", "", "tcp", "127.0.0.1:3306", "", "")
	f.Fuzz(func(t *testing.T, typ, version, apiKey, proto, local, subdomain, domain string) {
		h := Hello{
			Type:    typ,
			Version: version,
			APIKey:  apiKey,
			Tunnels: []TunnelSpec{{
				ID: "t1", Proto: proto, Local: local, Subdomain: subdomain, Domain: domain,
			}},
		}
		b, err := MarshalControl(h)
		if err != nil {
			return
		}
		var h2 Hello
		if err := UnmarshalControl(b, &h2); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		b2, err := MarshalControl(h2)
		if err != nil {
			t.Fatalf("remarshal: %v", err)
		}
		var h3 Hello
		if err := UnmarshalControl(b2, &h3); err != nil {
			t.Fatalf("unmarshal b2: %v", err)
		}
		b3, err := MarshalControl(h3)
		if err != nil {
			t.Fatalf("remarshal b3: %v", err)
		}
		if !bytes.Equal(b2, b3) {
			t.Fatalf("round-trip not stable:\n%q\n%q", b2, b3)
		}
	})
}

// FuzzUnmarshalControl throws arbitrary bytes at the JSON decoders to ensure
// malformed control traffic is rejected without panics.
func FuzzUnmarshalControl(f *testing.F) {
	f.Add([]byte(`{"type":"hello","version":"1","api_key":"k","tunnels":[]}`))
	f.Add([]byte(`{"type":"welcome","tunnels":[{"id":"x","public_url":"u"}]}`))
	f.Add([]byte(`not json`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var v any
		_ = UnmarshalControl(data, &v)
		_ = UnmarshalError(data)
	})
}
