package protocol

import (
	"bytes"
	"reflect"
	"testing"
)

func TestTunnelSpecRoundTrip(t *testing.T) {
	orig := TunnelSpec{
		ID:             "t1",
		Proto:          "http",
		Local:          "127.0.0.1:8080",
		Subdomain:      "api",
		Domain:         "app.example.com",
		Port:           2200,
		BasicAuth:      "user:pass",
		IPAllow:        []string{"10.0.0.0/8", "192.168.1.1"},
		IPDeny:         []string{"10.0.0.5"},
		MaxRequestSize: "1mb",
		RequestTimeout: "30s",
	}
	b, err := MarshalControl(orig)
	if err != nil {
		t.Fatal(err)
	}
	var got TunnelSpec
	if err := UnmarshalControl(b, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, orig) {
		t.Fatalf("round trip = %+v, want %+v", got, orig)
	}
}

func TestTunnelSpecOmitEmpty(t *testing.T) {
	b, err := MarshalControl(TunnelSpec{ID: "t1", Proto: "http", Local: "x:1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"basic_auth", "ip_allow", "ip_deny", "max_request_size", "request_timeout"} {
		if hasJSONField(b, f) {
			t.Fatalf("%q should be omitted when empty", f)
		}
	}
}

func hasJSONField(b []byte, field string) bool {
	return bytes.Contains(b, []byte(`"`+field+`":`))
}
