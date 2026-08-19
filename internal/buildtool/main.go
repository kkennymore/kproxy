// Command buildtool performs the file operations the Makefile needs in a way
// that works with any shell (cmd.exe on Windows, sh on Unix). The Makefile
// uses it to stage the built dashboard into the go:embed directory and to
// clean build artifacts.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func main() {
	fs := flag.NewFlagSet("buildtool", flag.ExitOnError)
	clean := fs.Bool("clean", false, "delete dst before copying")
	var rmPaths multiFlag
	fs.Var(&rmPaths, "rm", "path to remove (repeatable)")
	fs.Parse(os.Args[1:])

	for _, p := range rmPaths {
		if err := os.RemoveAll(p); err != nil {
			fatal(err)
		}
	}

	args := fs.Args()
	if len(args) != 2 {
		if len(rmPaths) > 0 {
			return
		}
		fmt.Fprintln(os.Stderr, "usage: buildtool [-clean] <src-dir> <dst-dir> | -rm PATH...")
		os.Exit(2)
	}
	src, dst := args[0], args[1]
	if *clean {
		if err := os.RemoveAll(dst); err != nil {
			fatal(err)
		}
	}
	if err := copyDir(src, dst); err != nil {
		fatal(err)
	}
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "buildtool:", err)
	os.Exit(1)
}
