package protocol

import (
	"encoding/json"
	"errors"
)

// Control message types. The Type field on each JSON payload disambiguates
// the frame.
const (
	TypeHello   = "hello"
	TypeWelcome = "welcome"
	TypeError   = "error"
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
