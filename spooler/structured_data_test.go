package spooler

import (
	"strings"
	"testing"
)

func TestBuildStructuredData_DefaultSDIDWhenEmpty(t *testing.T) {
	sd := buildStructuredData("", map[string]string{"job": "mhdbs"})
	if !strings.HasPrefix(sd, "[cndp ") {
		t.Fatalf("expected default sdID=cndp, got: %q", sd)
	}
}

func TestBuildStructuredData_SkipsEmptyAndSortsExtraKeys(t *testing.T) {
	sd := buildStructuredData("cndp", map[string]string{
		"job":         "mhdbs",
		"service":     "alerts",
		"env":         "", // should be skipped
		"filename":    "f.warn",
		"alert_type":  "general",
		"alert_level": "warning",
		"hash":        "h",
		"cccc":        "none",
		// extra keys should be appended in sorted order
		"zzz": "3",
		"aaa": "1",
	})

	if strings.Contains(sd, " env=") {
		t.Fatalf("expected empty env skipped, got: %q", sd)
	}

	ia := strings.Index(sd, ` aaa="1"`)
	iz := strings.Index(sd, ` zzz="3"`)
	if ia == -1 || iz == -1 {
		t.Fatalf("expected extra keys present, got: %q", sd)
	}
	if ia > iz {
		t.Fatalf("expected extra keys sorted (aaa before zzz), got: %q", sd)
	}
}
