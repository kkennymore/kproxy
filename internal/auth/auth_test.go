package auth

import (
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	h, err := HashSecret("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$") {
		t.Fatalf("hash = %q, want $argon2id$ prefix", h)
	}
	if !VerifySecret("s3cret", h) {
		t.Fatal("verify of correct secret failed")
	}
	if VerifySecret("wrong", h) {
		t.Fatal("verify of wrong secret succeeded")
	}
	if VerifySecret("", h) {
		t.Fatal("verify of empty secret succeeded")
	}
}

func TestHashesAreSalted(t *testing.T) {
	h1, _ := HashSecret("same")
	h2, _ := HashSecret("same")
	if h1 == h2 {
		t.Fatal("two hashes of the same secret should differ (random salt)")
	}
}

func TestVerifySecretRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "not-a-hash", "$argon2id$v=19$m=x$aa$bb", "$argon2id$v=19$m=65536,t=1,p=4$!$!"} {
		if VerifySecret("s3cret", bad) {
			t.Fatalf("VerifySecret accepted malformed hash %q", bad)
		}
	}
}

func TestNewSecret(t *testing.T) {
	s1, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s2, _ := NewSecret()
	if !strings.HasPrefix(s1, "kproxy_") || len(s1) != len("kproxy_")+64 {
		t.Fatalf("secret %q has wrong shape", s1)
	}
	if s1 == s2 {
		t.Fatal("two secrets should differ")
	}
}
