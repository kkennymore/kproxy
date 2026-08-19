package protocol

import (
	"encoding/json"
	"errors"
)

// Control message types. The Type field on each JSON payload disambiguates
// the frame.
const (
	TypeHello    = "hello"
	TypeWelcome  = "welcome"
	TypeClose    = "close"
	TypeAdd      = "add"
	TypeAssigned = "assigned"
	TypeError    = "error"
)

var ErrProtocol = errors.New("protocol: control error")

// TunnelProto identifies how a tunnel is exposed on the public side.
const (
	ProtoHTTP = "http"
	ProtoTCP  = "tcp"
)

// TunnelSpec describes a tunnel the agent wants to open. The ID is
// agent-assigned and must be unique within one connection.
type TunnelSpec struct {
	ID        string `json:"id"`
	Proto     string `json:"proto"`
	Local     string `json:"local"`
	Subdomain string `json:"subdomain,omitempty"`
	Domain    string `json:"domain,omitempty"`
	// Port requests a specific public TCP port for ProtoTCP tunnels. Zero
	// means the server allocates one from its range.
	Port int `json:"port,omitempty"`
	// BasicAuth protects an HTTP tunnel with HTTP Basic auth ("user:pass").
	BasicAuth string `json:"basic_auth,omitempty"`
	// IPAllow and IPDeny are comma-separated IP/CIDR allow and deny lists
	// applied to public client connections. Deny wins over allow; an empty
	// allow list admits everyone not denied.
	IPAllow []string `json:"ip_allow,omitempty"`
	IPDeny  []string `json:"ip_deny,omitempty"`
	// MaxRequestSize caps an HTTP request body, e.g. "1mb". Empty is
	// unlimited.
	MaxRequestSize string `json:"max_request_size,omitempty"`
	// RequestTimeout bounds how long an HTTP request may take, e.g. "30s".
	// Empty means no timeout.
	RequestTimeout string `json:"request_timeout,omitempty"`
}

// Hello is the first control message an agent sends when it connects.
type Hello struct {
	Type    string       `json:"type"`
	Version string       `json:"version"`
	APIKey  string       `json:"api_key"`
	Tunnels []TunnelSpec `json:"tunnels"`
}

// TunnelAssign is the public assignment for one tunnel in a Welcome.
type TunnelAssign struct {
	ID        string `json:"id"`
	PublicURL string `json:"public_url"`
}

// Welcome is the server's reply to a Hello.
type Welcome struct {
	Type    string         `json:"type"`
	Version string         `json:"version"`
	Server  string         `json:"server"`
	Tunnels []TunnelAssign `json:"tunnels"`
}

// ErrorMsg reports a fatal control-channel error.
type ErrorMsg struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// CloseMsg requests the server to unregister tunnels by ID. Unknown IDs are
// ignored. Sent by the agent on exit and when a local target fails.
type CloseMsg struct {
	Type    string   `json:"type"`
	Tunnels []string `json:"tunnels"`
}

// AddMsg requests the server to open additional tunnels on an already
// registered connection, e.g. after a local target recovers. Tunnel IDs must
// not collide with already-registered ones.
type AddMsg struct {
	Type    string       `json:"type"`
	Tunnels []TunnelSpec `json:"tunnels"`
}

// AssignedMsg is the server's reply to an AddMsg.
type AssignedMsg struct {
	Type    string         `json:"type"`
	Tunnels []TunnelAssign `json:"tunnels"`
}

// MarshalControl encodes a control message payload.
func MarshalControl(v any) ([]byte, error) {
	return json.Marshal(v)
}

// UnmarshalControl decodes a control message payload.
func UnmarshalControl(b []byte, v any) error {
	return json.Unmarshal(b, v)
}

// UnmarshalError decodes an ErrorMsg and returns its message, or an empty
// string if b is not an error message.
func UnmarshalError(b []byte) string {
	var e ErrorMsg
	if err := json.Unmarshal(b, &e); err != nil {
		return ""
	}
	return e.Message
}
