package spooler

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestFixtureFromNotifierDBOrFallback(t *testing.T) {
	raw := loadRawContentFixture(t)
	if raw == "" {
		t.Fatal("expected non-empty fixture")
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("fixture should be valid json: %v", err)
	}
}

func loadRawContentFixture(t *testing.T) string {
	t.Helper()

	// Prefer existing notifier databases in workspace.
	candidates, _ := filepath.Glob(filepath.Join("..", "notifier", "database", "alerts_*.db"))
	if len(candidates) == 0 {
		candidates, _ = filepath.Glob(filepath.Join("..", "notifier", "alert_notifier", "run", "database", "alerts_*.db"))
	}

	for _, dbPath := range candidates {
		raw, ok := tryLoadRawContentFromDB(dbPath)
		if ok {
			return raw
		}
	}

	// Fallback sample compatible with notifier handlers.
	return `{"id":"fixture","code":"NIL_REPORT","detail":"2025-06-01 15:30:00 heart beat missing","status":"2","type":"TEST","time":"2024-01-01 00:00:00"}`
}

func tryLoadRawContentFromDB(dbPath string) (string, bool) {
	db, err := OpenQueryDB(dbPath)
	if err != nil {
		return "", false
	}
	sqlDB, err := db.DB()
	if err == nil {
		defer sqlDB.Close()
	}

	queries := []string{
		"SELECT raw_content AS raw_content FROM dev_alert_events WHERE raw_content IS NOT NULL AND raw_content != '' LIMIT 1",
		"SELECT raw_content AS raw_content FROM iec_alert_events WHERE raw_content IS NOT NULL AND raw_content != '' LIMIT 1",
		"SELECT raw_content AS raw_content FROM business_alert_events WHERE raw_content IS NOT NULL AND raw_content != '' LIMIT 1",
		"SELECT raw_content AS raw_content FROM general_alert_events WHERE raw_content IS NOT NULL AND raw_content != '' LIMIT 1",
	}

	type row struct {
		RawContent string `gorm:"column:raw_content"`
	}
	for _, q := range queries {
		var r row
		if err := db.Raw(q).Scan(&r).Error; err == nil {
			if r.RawContent != "" {
				return r.RawContent, true
			}
		}
	}
	return "", false
}
