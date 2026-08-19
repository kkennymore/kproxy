package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopyDir(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"index.html": "<html/>", "assets/app.js": "js"}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(src, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	dst := filepath.Join(t.TempDir(), "dashboard")
	if err := copyDir(src, dst); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		b, err := os.ReadFile(filepath.Join(dst, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(b) != content {
			t.Fatalf("%s = %q, want %q", name, b, content)
		}
	}
}
