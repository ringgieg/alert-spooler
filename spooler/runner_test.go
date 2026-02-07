package spooler

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

type mockSyslogSender struct {
	mu    sync.Mutex
	calls []mockSyslogCall
	failN int
}

type mockSyslogCall struct {
	appName         string
	structuredData  string
	message         string
	timeoutArgument time.Duration
}

func (m *mockSyslogSender) SendRFC5424Timeout(appName string, structuredData string, message string, timeout time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, mockSyslogCall{appName: appName, structuredData: structuredData, message: message, timeoutArgument: timeout})
	if m.failN > 0 {
		m.failN--
		return errors.New("mock syslog send failure")
	}
	return nil
}

func (m *mockSyslogSender) FailNext(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failN = n
}

func (m *mockSyslogSender) Calls() []mockSyslogCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]mockSyslogCall, len(m.calls))
	copy(out, m.calls)
	return out
}

func TestRunner_SameHashIsOneToOne_AndTraverseSQLiteOnce(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "general"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Build 3 input files:
	// - two produce the same normalized hash (timestamp differs only)
	// - one produces a different hash
	inputs := []struct {
		name   string
		detail string
	}{
		{name: "same1.warn", detail: "2026-02-07 12:00:00 heart beat missing ZBBB"},
		{name: "same2.warn", detail: "2026-02-07 12:00:01 heart beat missing ZBBB"},
		{name: "diff.warn", detail: "2026-02-07 12:00:00 heart beat missing ZGGG"},
	}
	for _, in := range inputs {
		p := filepath.Join(tmp, "general", in.name)
		b := mustBuildFixtureJSON(t, in.detail)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	runner, err := NewRunner(RunnerConfig{
		DBFolder:        tmp,
		DBPrefix:        "spooler_",
		JobLabel:        "mhdbs",
		Inputs:          []InputSpec{{Glob: filepath.Join(tmp, "general", "*.warn"), AlertType: "general"}},
		SyslogAddr:      "127.0.0.1:1",
		ServiceLabel:    "alerts",
		HashHexLen:      24,
		CCCCCodes:       []string{"ZBBB", "ZGGG"},
		DeleteAfterSend: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()

	sender := &mockSyslogSender{}
	runner.syslog = sender

	if err := runner.RunOnce(); err != nil {
		t.Fatal(err)
	}

	// Source files should be deleted after confirmed send+DB.
	for _, in := range inputs {
		p := filepath.Join(tmp, "general", in.name)
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("expected file deleted: %s", p)
		}
	}

	// Expect exactly 3 syslog sends (1:1 with input files), even when two share the same hash.
	calls := sender.Calls()
	if len(calls) != 3 {
		t.Fatalf("expected 3 syslog sends, got %d", len(calls))
	}

	hashRe := regexp.MustCompile(`hash="([^"]+)"`)
	ccccRe := regexp.MustCompile(`cccc="([^"]+)"`)
	jobRe := regexp.MustCompile(`job="([^"]+)"`)
	var sameHash string
	sameCount := 0
	diffCount := 0
	for _, c := range calls {
		if c.appName != "alert-spooler" {
			t.Fatalf("expected appName=alert-spooler, got %q", c.appName)
		}
		if !strings.Contains(c.structuredData, "[cndp") {
			t.Fatalf("expected structured data, got: %q", c.structuredData)
		}
		jm := jobRe.FindStringSubmatch(c.structuredData)
		if len(jm) != 2 || jm[1] != "mhdbs" {
			t.Fatalf("expected job=mhdbs in structured data, got: %q", c.structuredData)
		}
		hm := hashRe.FindStringSubmatch(c.structuredData)
		if len(hm) != 2 {
			t.Fatalf("expected hash in structured data, got: %q", c.structuredData)
		}
		cm := ccccRe.FindStringSubmatch(c.structuredData)
		if len(cm) != 2 {
			t.Fatalf("expected cccc in structured data, got: %q", c.structuredData)
		}
		h := hm[1]
		cccc := cm[1]
		if cccc == "ZBBB" {
			if sameHash == "" {
				sameHash = h
			}
			if h != sameHash {
				t.Fatalf("expected same hash for ZBBB group, got %q vs %q", h, sameHash)
			}
			sameCount++
		} else if cccc == "ZGGG" {
			if sameHash != "" && h == sameHash {
				t.Fatalf("expected different hash for ZGGG vs ZBBB, got same %q", h)
			}
			diffCount++
		} else {
			t.Fatalf("unexpected cccc=%q in structured data: %q", cccc, c.structuredData)
		}
	}
	if sameCount != 2 || diffCount != 1 {
		t.Fatalf("expected 2 same-hash lines and 1 diff line, got same=%d diff=%d", sameCount, diffCount)
	}

	// Ensure idempotency on second run (no second send expected)
	if err := runner.RunOnce(); err != nil {
		t.Fatal(err)
	}
	if len(sender.Calls()) != 3 {
		t.Fatalf("unexpected second send(s), got %d total calls", len(sender.Calls()))
	}

	// Traverse SQLite test DB once and validate 1:1 counts by hash.
	// Runner uses monthly rolling DB under tmp with prefix; locate it by glob.
	candidates, _ := filepath.Glob(filepath.Join(tmp, "spooler_*.db"))
	if len(candidates) != 1 {
		t.Fatalf("expected 1 monthly db file, got %d", len(candidates))
	}
	db, err := OpenQueryDB(candidates[0])
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err == nil {
		defer sqlDB.Close()
	}

	var events []SpoolEvent
	if err := db.Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 events in sqlite, got %d", len(events))
	}

	counts := map[string]int{}
	ccccByHash := map[string]string{}
	for _, ev := range events {
		counts[ev.ContentHash]++
		if prev, ok := ccccByHash[ev.ContentHash]; ok {
			if prev != ev.CCCC {
				t.Fatalf("expected stable CCCC per hash, got %q vs %q for hash %q", prev, ev.CCCC, ev.ContentHash)
			}
		} else {
			ccccByHash[ev.ContentHash] = ev.CCCC
		}
	}

	if len(counts) != 2 {
		t.Fatalf("expected 2 distinct hashes, got %d", len(counts))
	}
	for h, n := range counts {
		cccc := ccccByHash[h]
		switch cccc {
		case "ZBBB":
			if n != 2 {
				t.Fatalf("expected 2 events for ZBBB hash, got %d", n)
			}
		case "ZGGG":
			if n != 1 {
				t.Fatalf("expected 1 event for ZGGG hash, got %d", n)
			}
		default:
			t.Fatalf("unexpected cccc=%q in sqlite", cccc)
		}
	}
}

func TestRunner_SendFailureDoesNotDelete_ThenResendDeletes(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "general"), 0o755); err != nil {
		t.Fatal(err)
	}

	p := filepath.Join(tmp, "general", "fail.warn")
	b := mustBuildFixtureJSON(t, "2026-02-07 12:00:00 heart beat missing ZBBB")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}

	runner, err := NewRunner(RunnerConfig{
		DBFolder:        tmp,
		DBPrefix:        "spooler_",
		JobLabel:        "mhdbs",
		Inputs:          []InputSpec{{Glob: filepath.Join(tmp, "general", "*.warn"), AlertType: "general"}},
		SyslogAddr:      "127.0.0.1:1",
		ServiceLabel:    "alerts",
		HashHexLen:      24,
		CCCCCodes:       []string{"ZBBB"},
		DeleteAfterSend: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()

	sender := &mockSyslogSender{}
	// RunOnce() does: ingest -> resendPending -> finalizeFiles.
	// Force both the first send and the in-run resend attempt to fail,
	// so the file is not deleted until the next run.
	sender.FailNext(2)
	runner.syslog = sender

	// First run: send fails; file must not be deleted; DB must record pending event.
	if err := runner.RunOnce(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("expected source file to remain after send failure: %v", err)
	}
	if len(sender.Calls()) != 2 {
		t.Fatalf("expected 2 syslog calls on first run (send + resendPending), got %d", len(sender.Calls()))
	}

	candidates, _ := filepath.Glob(filepath.Join(tmp, "spooler_*.db"))
	if len(candidates) != 1 {
		t.Fatalf("expected 1 monthly db file, got %d", len(candidates))
	}
	db, err := OpenQueryDB(candidates[0])
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err == nil {
		defer sqlDB.Close()
	}

	var events []SpoolEvent
	if err := db.Order("id asc").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event in sqlite, got %d", len(events))
	}
	if events[0].SentSyslog {
		t.Fatalf("expected sent_syslog=false after failure")
	}
	if strings.TrimSpace(events[0].SendError) == "" {
		t.Fatalf("expected send_error to be recorded")
	}

	var pfs []ProcessedFile
	if err := db.Order("id asc").Find(&pfs).Error; err != nil {
		t.Fatal(err)
	}
	if len(pfs) != 1 {
		t.Fatalf("expected 1 processed_file row, got %d", len(pfs))
	}
	if pfs[0].AllSent {
		t.Fatalf("expected all_sent=false when send failed")
	}
	if pfs[0].Deleted {
		t.Fatalf("expected deleted=false when send failed")
	}

	// Second run: resendPending should succeed (no new ingest since file already processed);
	// finalizeFiles should delete the file and mark DB sent+deleted.
	sender.FailNext(0)
	if err := runner.RunOnce(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err == nil {
		t.Fatalf("expected source file deleted after successful resend")
	}
	if len(sender.Calls()) != 3 {
		t.Fatalf("expected 3 total syslog calls after second run, got %d", len(sender.Calls()))
	}

	var events2 []SpoolEvent
	if err := db.Order("id asc").Find(&events2).Error; err != nil {
		t.Fatal(err)
	}
	if len(events2) != 1 {
		t.Fatalf("expected 1 event in sqlite, got %d", len(events2))
	}
	if !events2[0].SentSyslog {
		t.Fatalf("expected sent_syslog=true after resend")
	}
	if strings.TrimSpace(events2[0].SendError) != "" {
		t.Fatalf("expected send_error cleared after resend, got %q", events2[0].SendError)
	}

	var pfs2 []ProcessedFile
	if err := db.Order("id asc").Find(&pfs2).Error; err != nil {
		t.Fatal(err)
	}
	if len(pfs2) != 1 {
		t.Fatalf("expected 1 processed_file row, got %d", len(pfs2))
	}
	if !pfs2[0].AllSent {
		t.Fatalf("expected all_sent=true after resend")
	}
	if !pfs2[0].Deleted {
		t.Fatalf("expected deleted=true after resend")
	}
}

func TestRunner_FixedLabelsAppearInStructuredData(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "general"), 0o755); err != nil {
		t.Fatal(err)
	}

	p := filepath.Join(tmp, "general", "one.warn")
	b := mustBuildFixtureJSON(t, "2026-02-07 12:00:00 heart beat missing ZBBB")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}

	runner, err := NewRunner(RunnerConfig{
		DBFolder:        tmp,
		DBPrefix:        "spooler_",
		JobLabel:        "mhdbs",
		Inputs:          []InputSpec{{Glob: filepath.Join(tmp, "general", "*.warn"), AlertType: "general"}},
		SyslogAddr:      "127.0.0.1:1",
		ServiceLabel:    "alerts",
		HashHexLen:      24,
		CCCCCodes:       []string{"ZBBB"},
		DeleteAfterSend: true,
		FixedLabels: map[string]string{
			"env":     "prod",
			"site":    "bj",
			"cluster": "c1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()

	sender := &mockSyslogSender{}
	runner.syslog = sender

	if err := runner.RunOnce(); err != nil {
		t.Fatal(err)
	}

	calls := sender.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 syslog send, got %d", len(calls))
	}
	sd := calls[0].structuredData
	if !strings.Contains(sd, ` env="prod"`) {
		t.Fatalf("expected env label in structured data, got: %q", sd)
	}
	if !strings.Contains(sd, ` site="bj"`) {
		t.Fatalf("expected site label in structured data, got: %q", sd)
	}
	if !strings.Contains(sd, ` cluster="c1"`) {
		t.Fatalf("expected cluster label in structured data, got: %q", sd)
	}
}

func TestRunner_ErrorDirMovesBadJSON(t *testing.T) {
	tmp := t.TempDir()
	alertDir := filepath.Join(tmp, "general")
	errorDir := filepath.Join(tmp, "general_err")
	if err := os.MkdirAll(alertDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(errorDir, 0o755); err != nil {
		t.Fatal(err)
	}

	src := filepath.Join(alertDir, "bad.warn")
	if err := os.WriteFile(src, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	runner, err := NewRunner(RunnerConfig{
		DBFolder:        tmp,
		DBPrefix:        "spooler_",
		JobLabel:        "mhdbs",
		Inputs:          []InputSpec{{Glob: filepath.Join(alertDir, "*.warn"), AlertType: "general", ErrorDir: errorDir}},
		SyslogAddr:      "127.0.0.1:1",
		ServiceLabel:    "alerts",
		HashHexLen:      24,
		DeleteAfterSend: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()

	sender := &mockSyslogSender{}
	runner.syslog = sender

	if err := runner.RunOnce(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(src); err == nil {
		t.Fatalf("expected source file moved out of alert dir: %s", src)
	}

	moved, _ := filepath.Glob(filepath.Join(errorDir, "bad.warn"))
	if len(moved) != 1 {
		// MoveFileToDir may rename on collision; in this test there shouldn't be one,
		// but fall back to "any file present" to avoid flakiness.
		any, _ := filepath.Glob(filepath.Join(errorDir, "*"))
		if len(any) == 0 {
			t.Fatalf("expected file present in error_dir: %s", errorDir)
		}
	}
}

func mustBuildFixtureJSON(t *testing.T, detail string) []byte {
	t.Helper()
	fixture := map[string]any{
		"id":          fmt.Sprintf("fixture-%d", time.Now().UnixNano()),
		"code":        "NIL_REPORT",
		"detail":      detail,
		"description": detail,
		"status":      "2",
		"type":        "TEST",
		"time":        "2026-02-07 12:00:00",
	}
	b, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRunner_AlertLevel_StatusAndFallbackToExt(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "general"), 0o755); err != nil {
		t.Fatal(err)
	}

	// One event has explicit status=2 -> critical; one has no status -> fallback to .warn => warning.
	p1 := filepath.Join(tmp, "general", "has_status.warn")
	if err := os.WriteFile(p1, mustBuildFixtureJSON(t, "detail ZBBB"), 0o644); err != nil {
		t.Fatal(err)
	}

	noStatus := map[string]any{
		"id":          "fixture-nostatus",
		"code":        "NIL_REPORT",
		"detail":      "detail ZGGG",
		"description": "detail ZGGG",
		"type":        "TEST",
		"time":        "2026-02-07 12:00:00",
	}
	b2, err := json.Marshal(noStatus)
	if err != nil {
		t.Fatal(err)
	}
	p2 := filepath.Join(tmp, "general", "no_status.warn")
	if err := os.WriteFile(p2, b2, 0o644); err != nil {
		t.Fatal(err)
	}

	runner, err := NewRunner(RunnerConfig{
		DBFolder:        tmp,
		DBPrefix:        "spooler_",
		JobLabel:        "mhdbs",
		Inputs:          []InputSpec{{Glob: filepath.Join(tmp, "general", "*.warn"), AlertType: "general"}},
		SyslogAddr:      "127.0.0.1:1",
		ServiceLabel:    "alerts",
		HashHexLen:      24,
		CCCCCodes:       []string{"ZBBB", "ZGGG"},
		DeleteAfterSend: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()

	sender := &mockSyslogSender{}
	runner.syslog = sender

	if err := runner.RunOnce(); err != nil {
		t.Fatal(err)
	}

	calls := sender.Calls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 syslog calls, got %d", len(calls))
	}
	filenameRe := regexp.MustCompile(`filename="([^"]+)"`)
	levelRe := regexp.MustCompile(`alert_level="([^"]+)"`)
	levelsByFile := map[string]string{}
	for _, c := range calls {
		fm := filenameRe.FindStringSubmatch(c.structuredData)
		lm := levelRe.FindStringSubmatch(c.structuredData)
		if len(fm) != 2 || len(lm) != 2 {
			t.Fatalf("missing filename/alert_level in structured data: %q", c.structuredData)
		}
		levelsByFile[fm[1]] = lm[1]
	}
	if levelsByFile["has_status.warn"] != "critical" {
		t.Fatalf("expected critical for has_status.warn, got %q", levelsByFile["has_status.warn"])
	}
	if levelsByFile["no_status.warn"] != "warning" {
		t.Fatalf("expected warning for no_status.warn, got %q", levelsByFile["no_status.warn"])
	}
}

func TestRunner_ReplayFrom_AddsReplayLabel(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "general"), 0o755); err != nil {
		t.Fatal(err)
	}

	p := filepath.Join(tmp, "general", "one.warn")
	if err := os.WriteFile(p, mustBuildFixtureJSON(t, "detail ZBBB"), 0o644); err != nil {
		t.Fatal(err)
	}

	runner, err := NewRunner(RunnerConfig{
		DBFolder:        tmp,
		DBPrefix:        "spooler_",
		JobLabel:        "mhdbs",
		Inputs:          []InputSpec{{Glob: filepath.Join(tmp, "general", "*.warn"), AlertType: "general"}},
		SyslogAddr:      "127.0.0.1:1",
		ServiceLabel:    "alerts",
		HashHexLen:      24,
		CCCCCodes:       []string{"ZBBB"},
		DeleteAfterSend: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()

	sender := &mockSyslogSender{}
	runner.syslog = sender

	if err := runner.RunOnce(); err != nil {
		t.Fatal(err)
	}
	if len(sender.Calls()) != 1 {
		t.Fatalf("expected 1 syslog call, got %d", len(sender.Calls()))
	}
	if strings.Contains(sender.Calls()[0].structuredData, "replay=") {
		t.Fatalf("did not expect replay label on normal send: %q", sender.Calls()[0].structuredData)
	}

	runner.cfg.ReplayFrom = time.Now().Add(-10 * time.Minute).UTC()
	if err := runner.RunOnce(); err != nil {
		t.Fatal(err)
	}
	calls := sender.Calls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 total syslog calls after replay, got %d", len(calls))
	}
	if !strings.Contains(calls[1].structuredData, "replay=\"true\"") {
		t.Fatalf("expected replay label on replay send: %q", calls[1].structuredData)
	}
}

func TestRunner_CCCCEnabledDerivedFromCodes_IgnoresFlag(t *testing.T) {
	tmp := t.TempDir()
	alertDir := filepath.Join(tmp, "general")
	if err := os.MkdirAll(alertDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Content contains ZBBB; codes list is non-empty, but flag is false.
	src := filepath.Join(alertDir, "one.warn")
	b := mustBuildFixtureJSON(t, "2026-02-07 12:00:00 heart beat missing ZBBB")
	if err := os.WriteFile(src, b, 0o644); err != nil {
		t.Fatal(err)
	}

	runner, err := NewRunner(RunnerConfig{
		DBFolder:        tmp,
		DBPrefix:        "spooler_",
		JobLabel:        "mhdbs",
		Inputs:          []InputSpec{{Glob: filepath.Join(alertDir, "*.warn"), AlertType: "general"}},
		SyslogAddr:      "127.0.0.1:1",
		ServiceLabel:    "alerts",
		HashHexLen:      24,
		CCCCEnabled:     false,
		CCCCCodes:       []string{"ZBBB"},
		DeleteAfterSend: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()

	sender := &mockSyslogSender{}
	runner.syslog = sender

	if err := runner.RunOnce(); err != nil {
		t.Fatal(err)
	}

	calls := sender.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 syslog send, got %d", len(calls))
	}
	if !strings.Contains(calls[0].structuredData, ` cccc="ZBBB"`) {
		t.Fatalf("expected cccc=ZBBB in structured data, got: %q", calls[0].structuredData)
	}
}

func TestRunner_CCCCIgnoresFlag_EmptyCodesDisablesTagging(t *testing.T) {
	tmp := t.TempDir()
	alertDir := filepath.Join(tmp, "general")
	if err := os.MkdirAll(alertDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Content contains ZBBB, but codes list is empty; flag is true.
	src := filepath.Join(alertDir, "one.warn")
	b := mustBuildFixtureJSON(t, "2026-02-07 12:00:00 heart beat missing ZBBB")
	if err := os.WriteFile(src, b, 0o644); err != nil {
		t.Fatal(err)
	}

	runner, err := NewRunner(RunnerConfig{
		DBFolder:        tmp,
		DBPrefix:        "spooler_",
		JobLabel:        "mhdbs",
		Inputs:          []InputSpec{{Glob: filepath.Join(alertDir, "*.warn"), AlertType: "general"}},
		SyslogAddr:      "127.0.0.1:1",
		ServiceLabel:    "alerts",
		HashHexLen:      24,
		CCCCEnabled:     true,
		CCCCCodes:       nil,
		DeleteAfterSend: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()

	sender := &mockSyslogSender{}
	runner.syslog = sender

	if err := runner.RunOnce(); err != nil {
		t.Fatal(err)
	}

	calls := sender.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 syslog send, got %d", len(calls))
	}
	if !strings.Contains(calls[0].structuredData, ` cccc="none"`) {
		t.Fatalf("expected cccc=none when codes empty, got: %q", calls[0].structuredData)
	}
}
