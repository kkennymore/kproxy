//go:build !windows

package keyring

// On macOS and Linux a pure-Go keychain or secret-service client would need
// cgo or third-party bindings, which kproxy avoids; secrets are stored in an
// owner-only (0600) JSON file instead.

// encryptValue stores plain bytes unchanged; the file permissions protect it.
func encryptValue(plain []byte) (string, error) {
	return string(plain), nil
}

// decryptValue reverses encryptValue.
func decryptValue(stored string) ([]byte, error) {
	return []byte(stored), nil
}
