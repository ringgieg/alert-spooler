package spooler

import (
	"fmt"
	"path/filepath"
	"strings"
)

// NormalizeAlertLevel aligns with notifier's level2Severity mapping:
// - warn/warning/1 -> warning
// - error/critical/2..5 -> critical
// - else -> unknown
func NormalizeAlertLevel(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case "error", "critical", "2", "3", "4", "5":
		return "critical"
	case "warn", "warning", "1":
		return "warning"
	default:
		return "unknown"
	}
}

func ExtractAlertLevel(item any, sourcePath string) string {
	if m, ok := item.(map[string]any); ok {
		for _, key := range []string{"status", "level", "severity"} {
			if v, ok := m[key]; ok {
				return NormalizeAlertLevel(fmt.Sprint(v))
			}
		}
	}

	ext := strings.ToLower(filepath.Ext(sourcePath))
	switch ext {
	case ".warn":
		return "warning"
	case ".alarm":
		return "critical"
	default:
		return "unknown"
	}
}
