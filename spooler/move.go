package spooler

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func MoveFileToDir(srcPath string, dstDir string) (string, error) {
	if strings.TrimSpace(dstDir) == "" {
		return "", fmt.Errorf("dstDir is empty")
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return "", err
	}
	base := filepath.Base(srcPath)
	dstPath := filepath.Join(dstDir, base)
	if _, err := os.Stat(dstPath); err == nil {
		ext := filepath.Ext(base)
		name := strings.TrimSuffix(base, ext)
		dstPath = filepath.Join(dstDir, fmt.Sprintf("%s-%d%s", name, time.Now().UnixNano(), ext))
	}

	// Try fast rename first.
	if err := os.Rename(srcPath, dstPath); err == nil {
		return dstPath, nil
	}

	// Fallback: copy + remove (handles cross-device moves).
	in, err := os.Open(srcPath)
	if err != nil {
		return "", err
	}
	defer in.Close()

	out, err := os.Create(dstPath)
	if err != nil {
		return "", err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(dstPath)
		return "", copyErr
	}
	if closeErr != nil {
		_ = os.Remove(dstPath)
		return "", closeErr
	}
	if err := os.Remove(srcPath); err != nil {
		return "", err
	}
	return dstPath, nil
}
