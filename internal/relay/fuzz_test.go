package relay

import (
	"strings"
	"testing"

	"kproxy/internal/protocol"
)

// FuzzApplySpecOptions ensures server-side tunnel option parsing never panics
// on hostile specs from an agent.
func FuzzApplySpecOptions(f *testing.F) {
	f.Add("user:pass", "10.0.0.0/8,1.2.3.4", "", "1mb", "30s")
	f.Add("nocolon", "badcidr!!", "deny-me", "-5", "forever")
	f.Add("", "", "", "", "")
	f.Fuzz(func(t *testing.T, basicAuth, ipAllow, ipDeny, maxReq, timeout string) {
		for _, proto := range []string{protocol.ProtoHTTP, protocol.ProtoTCP} {
			tun := &tunnel{proto: proto}
			spec := protocol.TunnelSpec{
				BasicAuth:      basicAuth,
				IPAllow:        splitList(ipAllow),
				IPDeny:         splitList(ipDeny),
				MaxRequestSize: maxReq,
				RequestTimeout: timeout,
			}
			_ = applySpecOptions(tun, spec)
		}
	})
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
