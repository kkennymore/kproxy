//go:build windows

package keyring

import (
	"encoding/base64"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	cryptProtectLocalMachine = 0x10
	cryptProtectUiForbidden  = 0x1
)

var (
	crypt32     = syscall.NewLazyDLL("crypt32.dll")
	kernel32    = syscall.NewLazyDLL("kernel32.dll")
	dpProtect   = crypt32.NewProc("CryptProtectData")
	dpUnprotect = crypt32.NewProc("CryptUnprotectData")
	localFree   = kernel32.NewProc("LocalFree")
)

// dataBlob mirrors the Windows DATA_BLOB structure. The pointer field keeps
// natural 8-byte alignment on 64-bit Windows, matching the native layout.
type dataBlob struct {
	cbData uint32
	pbData *byte
}

// encryptValue protects plain bytes with DPAPI (local-machine scope so it
// also works for service accounts) and returns the value stored on disk.
func encryptValue(plain []byte) (string, error) {
	in := &dataBlob{}
	if len(plain) > 0 {
		in.cbData = uint32(len(plain))
		in.pbData = &plain[0]
	}
	var out dataBlob
	r, _, err := dpProtect.Call(
		uintptr(unsafe.Pointer(in)),
		0, // optional description
		0, // optional entropy
		0, // reserved
		0, // prompt struct
		uintptr(cryptProtectLocalMachine|cryptProtectUiForbidden),
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return "", fmt.Errorf("CryptProtectData failed: %w", err)
	}
	defer localFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	// Copy out before the deferred LocalFree returns the buffer to the heap.
	enc := make([]byte, int(out.cbData))
	copy(enc, unsafe.Slice(out.pbData, int(out.cbData)))
	return base64.StdEncoding.EncodeToString(enc), nil
}

// decryptValue reverses encryptValue.
func decryptValue(stored string) ([]byte, error) {
	enc, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		return nil, err
	}
	in := &dataBlob{}
	if len(enc) > 0 {
		in.cbData = uint32(len(enc))
		in.pbData = &enc[0]
	}
	var out dataBlob
	r, _, err := dpUnprotect.Call(
		uintptr(unsafe.Pointer(in)),
		0, // description
		0, // entropy
		0, // reserved
		0, // prompt
		uintptr(cryptProtectUiForbidden),
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %w", err)
	}
	defer localFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	// Copy out before the deferred LocalFree returns the buffer to the heap.
	plain := make([]byte, int(out.cbData))
	copy(plain, unsafe.Slice(out.pbData, int(out.cbData)))
	return plain, nil
}
