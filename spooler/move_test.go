package spooler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMoveFileToDir_EmptyDstDirErrors(t *testing.T) {
	if _, err := MoveFileToDir("x", ""); err == nil {
		t.Fatalf("expected error for empty dstDir")
	}
}

func TestMoveFileToDir_AvoidsNameCollision(t *testing.T) {
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "src")
	dstDir := filepath.Join(tmp, "dst")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Prepare an existing file in dst with the same base name.
	base := "a.warn"
	if err := os.WriteFile(filepath.Join(dstDir, base), []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Move a different source file with the same base name.
	srcPath := filepath.Join(srcDir, base)
	if err := os.WriteFile(srcPath, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	dstPath, err := MoveFileToDir(srcPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(dstPath) == base {
		t.Fatalf("expected collision-avoiding filename, got %q", dstPath)
	}
	if !strings.HasPrefix(filepath.Base(dstPath), strings.TrimSuffix(base, filepath.Ext(base))+"-") {
		t.Fatalf("expected collision-avoiding suffix, got %q", dstPath)
	}

	if _, err := os.Stat(srcPath); err == nil {
		t.Fatalf("expected source removed: %s", srcPath)
	}
	b, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "payload" {
		t.Fatalf("unexpected content: %q", string(b))
	}
}
