package spooler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"log"

	"gorm.io/gorm"
)

type RunnerConfig struct {
	// Legacy single DB path. If DBFolder is set, DBPath is ignored.
	DBPath string
	// Monthly rolling DB settings (recommended).
	DBFolder string
	DBPrefix string
	JobLabel string
	Debug    bool
	// Legacy globs. Prefer Inputs.
	InputGlobs []string
	// Notifier-style inputs: each input has its own alert type.
	Inputs       []InputSpec
	SyslogAddr   string
	ServiceLabel string
	HashHexLen   int
	// Deprecated: CCCCEnabled is ignored. CCCC tagging is enabled when CCCCCodes is non-empty.
	CCCCEnabled     bool
	CCCCCodes       []string
	DeleteAfterSend bool
	Timeout         time.Duration
	DeadmanToken    string
	ReplayFrom      time.Time
	// FixedLabels are constant labels added to structured-data.
	// Currently supported keys: env, site, cluster.
	FixedLabels map[string]string
}

type InputSpec struct {
	Glob      string
	AlertType string
	ErrorDir  string
}

type Runner struct {
	cfg    RunnerConfig
	db     *gorm.DB
	dbKey  string
	syslog SyslogSender
}

func (r *Runner) debugf(format string, args ...any) {
	if r == nil || !r.cfg.Debug {
		return
	}
	log.Printf(format, args...)
}

type runStats struct {
	FilesIngested   int
	EventsNew       int
	EventsSentOK    int
	EventsSentErr   int
	EventsReplayOK  int
	EventsReplayErr int
	FilesDeleted    int
	MaxLag          time.Duration
}

func (r *Runner) replayFrom(from time.Time, deadline time.Time, stats *runStats) error {
	if strings.TrimSpace(r.cfg.DBFolder) == "" {
		return fmt.Errorf("replay requires DBFolder (monthly rolling DB)")
	}
	if strings.TrimSpace(r.cfg.DBPrefix) == "" {
		return fmt.Errorf("replay requires DBPrefix (monthly rolling DB)")
	}
	to := time.Now().UTC()
	dbPaths, err := listMonthlyDBs(r.cfg.DBFolder, r.cfg.DBPrefix, from.UTC(), to)
	if err != nil {
		return err
	}
	if len(dbPaths) == 0 {
		r.debugf("replay: no db files matched folder=%q prefix=%q", r.cfg.DBFolder, r.cfg.DBPrefix)
		return nil
	}

	for _, dbPath := range dbPaths {
		if isDeadlineExceeded(deadline) {
			return fmt.Errorf("timeout exceeded")
		}
		r.debugf("replay: open db=%q", dbPath)
		db, err := OpenQueryDB(dbPath)
		if err != nil {
			return err
		}
		sqlDB, err := db.DB()
		if err != nil {
			return err
		}

		var events []SpoolEvent
		if err := db.Where("archived_at >= ?", from.UTC()).Order("id asc").Find(&events).Error; err != nil {
			_ = sqlDB.Close()
			return err
		}

		for _, ev := range events {
			if isDeadlineExceeded(deadline) {
				_ = sqlDB.Close()
				return fmt.Errorf("timeout exceeded")
			}
			if stats != nil {
				if lag, ok := computeLag(time.Now().UTC(), jsonAnyFromString(ev.EventJSON)); ok {
					if lag > stats.MaxLag {
						stats.MaxLag = lag
					}
				}
			}
			structured := buildStructuredData("cndp", map[string]string{
				"job":        r.cfg.JobLabel,
				"service":    r.cfg.ServiceLabel,
				"env":        r.cfg.FixedLabels["env"],
				"site":       r.cfg.FixedLabels["site"],
				"cluster":    r.cfg.FixedLabels["cluster"],
				"filename":   filepath.Base(ev.SourcePath),
				"alert_type": ev.AlertType,
				"alert_level": func() string {
					if strings.TrimSpace(ev.AlertLevel) == "" {
						return "unknown"
					}
					return ev.AlertLevel
				}(),
				"hash":   ev.ContentHash,
				"cccc":   ev.CCCC,
				"replay": "true",
			})

			payload := map[string]any{
				"source":      ev.SourcePath,
				"event_index": ev.EventIndex,
				"event":       json.RawMessage(ev.EventJSON),
				"flat":        json.RawMessage(ev.FlatJSON),
			}
			payloadBytes, _ := json.Marshal(payload)
			err := r.syslog.SendRFC5424Timeout("alert-spooler", structured, string(payloadBytes), remainingTimeout(deadline, 3*time.Second))
			if err != nil {
				r.debugf("replay send failed path=%q id=%d err=%v", ev.SourcePath, ev.ID, err)
				if stats != nil {
					stats.EventsReplayErr++
				}
				continue
			}
			r.debugf("replay send ok path=%q id=%d", ev.SourcePath, ev.ID)
			if stats != nil {
				stats.EventsReplayOK++
			}
		}
		_ = sqlDB.Close()
	}
	return nil
}

func listMonthlyDBs(folder string, prefix string, from time.Time, to time.Time) ([]string, error) {
	pattern := filepath.Join(folder, prefix+"*.db")
	candidates, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	// Parse month from filename: <prefix><YYYYMM>.db
	fromKey := from.Year()*100 + int(from.Month())
	toKey := to.Year()*100 + int(to.Month())

	filtered := make([]string, 0, len(candidates))
	for _, p := range candidates {
		base := filepath.Base(p)
		if !strings.HasPrefix(base, prefix) || !strings.HasSuffix(base, ".db") {
			continue
		}
		yyyymm := strings.TrimSuffix(strings.TrimPrefix(base, prefix), ".db")
		if len(yyyymm) != 6 {
			continue
		}
		tm, err := time.Parse("200601", yyyymm)
		if err != nil {
			continue
		}
		key := tm.Year()*100 + int(tm.Month())
		if key < fromKey || key > toKey {
			continue
		}
		filtered = append(filtered, p)
	}
	sort.Strings(filtered)
	return filtered, nil
}

func NewRunner(cfg RunnerConfig) (*Runner, error) {
	if strings.TrimSpace(cfg.DBFolder) == "" && strings.TrimSpace(cfg.DBPath) == "" {
		return nil, fmt.Errorf("DBPath or DBFolder is required")
	}
	if strings.TrimSpace(cfg.JobLabel) == "" {
		return nil, fmt.Errorf("JobLabel is required")
	}
	if len(cfg.InputGlobs) == 0 && len(cfg.Inputs) == 0 {
		return nil, fmt.Errorf("Inputs or InputGlobs is required")
	}
	if cfg.SyslogAddr == "" {
		return nil, fmt.Errorf("SyslogAddr is required")
	}
	if cfg.ServiceLabel == "" {
		cfg.ServiceLabel = "alerts"
	}
	if cfg.HashHexLen <= 0 {
		cfg.HashHexLen = 24
	}
	// Required by user: delete after confirmed send+DB by default.
	if !cfg.DeleteAfterSend {
		cfg.DeleteAfterSend = true
	}

	r := &Runner{
		cfg:    cfg,
		syslog: NewSyslogClient(cfg.SyslogAddr),
	}
	if err := r.ensureDBForNow(); err != nil {
		_ = r.Close()
		return nil, err
	}
	return r, nil
}

func (r *Runner) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	sqlDB, err := r.db.DB()
	if err != nil {
		return err
	}
	err = sqlDB.Close()
	r.db = nil
	r.dbKey = ""
	return err
}

func (r *Runner) RunOnce() error {
	start := time.Now()
	stats := &runStats{}
	var runErr error
	deadline := time.Time{}
	if r.cfg.Timeout > 0 {
		deadline = time.Now().Add(r.cfg.Timeout)
	}
	defer func() {
		if strings.TrimSpace(r.cfg.DeadmanToken) == "" {
			return
		}
		// Best-effort: deadman should still be sent even on failures.
		_ = r.sendDeadman(deadline, start, time.Now(), stats, runErr)
	}()

	if err := r.ensureDBForNow(); err != nil {
		runErr = err
		return err
	}
	r.debugf("run_once start: dbFolder=%q dbPrefix=%q inputs=%d globs=%d deleteAfterSend=%v timeout=%s", r.cfg.DBFolder, r.cfg.DBPrefix, len(r.cfg.Inputs), len(r.cfg.InputGlobs), r.cfg.DeleteAfterSend, r.cfg.Timeout)

	if !r.cfg.ReplayFrom.IsZero() {
		r.debugf("replay mode: from=%s", r.cfg.ReplayFrom.UTC().Format(time.RFC3339Nano))
		err := r.replayFrom(r.cfg.ReplayFrom, deadline, stats)
		if err != nil {
			runErr = err
			return err
		}
		return nil
	}

	paths, err := r.expandGlobs(r.cfg.InputGlobs)
	if err != nil {
		runErr = err
		return err
	}
	for _, p := range paths {
		if isDeadlineExceeded(deadline) {
			runErr = fmt.Errorf("timeout exceeded")
			return runErr
		}
		r.debugf("ingest legacy glob path=%q", p)
		_ = r.ingestFile(p, "", "", deadline, stats)
	}

	items, err := r.expandInputs(r.cfg.Inputs)
	if err != nil {
		runErr = err
		return err
	}
	for _, it := range items {
		if isDeadlineExceeded(deadline) {
			runErr = fmt.Errorf("timeout exceeded")
			return runErr
		}
		r.debugf("ingest path=%q alertType=%q", it.Path, it.AlertType)
		_ = r.ingestFile(it.Path, it.AlertType, it.ErrorDir, deadline, stats)
	}

	if isDeadlineExceeded(deadline) {
		runErr = fmt.Errorf("timeout exceeded")
		return runErr
	}
	if err := r.resendPending(deadline, stats); err != nil {
		runErr = err
		return err
	}
	if isDeadlineExceeded(deadline) {
		runErr = fmt.Errorf("timeout exceeded")
		return runErr
	}
	if err := r.finalizeFiles(stats); err != nil {
		runErr = err
		return err
	}
	r.debugf("run_once done: filesIngested=%d eventsNew=%d sentOK=%d sentErr=%d filesDeleted=%d maxLag=%s elapsed=%s", stats.FilesIngested, stats.EventsNew, stats.EventsSentOK, stats.EventsSentErr, stats.FilesDeleted, stats.MaxLag, time.Since(start))
	return nil
}

func isDeadlineExceeded(deadline time.Time) bool {
	return !deadline.IsZero() && time.Now().After(deadline)
}

func remainingTimeout(deadline time.Time, fallback time.Duration) time.Duration {
	if deadline.IsZero() {
		return fallback
	}
	rem := time.Until(deadline)
	if rem <= 0 {
		return 1 * time.Millisecond
	}
	if fallback <= 0 || rem < fallback {
		return rem
	}
	return fallback
}

func (r *Runner) ensureDBForNow() error {
	if strings.TrimSpace(r.cfg.DBFolder) == "" {
		if r.db != nil {
			return nil
		}
		db, err := OpenDB(r.cfg.DBPath)
		if err != nil {
			return err
		}
		r.db = db
		r.dbKey = "static"
		return nil
	}

	now := time.Now()
	key := fmt.Sprintf("%04d%02d", now.Year(), int(now.Month()))
	if r.db != nil && r.dbKey == key {
		return nil
	}
	// switch DB per natural month
	_ = r.Close()
	if strings.TrimSpace(r.cfg.DBPrefix) == "" {
		r.cfg.DBPrefix = "alerts_"
	}
	if err := os.MkdirAll(r.cfg.DBFolder, 0o755); err != nil {
		return err
	}
	dbPath := filepath.Join(r.cfg.DBFolder, r.cfg.DBPrefix+key+".db")
	db, err := OpenDB(dbPath)
	if err != nil {
		return err
	}
	r.db = db
	r.dbKey = key
	return nil
}

func (r *Runner) expandGlobs(globs []string) ([]string, error) {
	seen := make(map[string]struct{})
	var out []string
	for _, g := range globs {
		matches, err := expandGlobWithDoubleStar(g)
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			if _, ok := seen[m]; ok {
				continue
			}
			seen[m] = struct{}{}
			out = append(out, m)
		}
	}
	return out, nil
}

type inputItem struct {
	Path      string
	AlertType string
	ErrorDir  string
}

func (r *Runner) expandInputs(inputs []InputSpec) ([]inputItem, error) {
	seen := make(map[string]struct{})
	var out []inputItem
	for _, in := range inputs {
		if strings.TrimSpace(in.Glob) == "" {
			continue
		}
		matches, err := expandGlobWithDoubleStar(in.Glob)
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			if _, ok := seen[m]; ok {
				continue
			}
			seen[m] = struct{}{}
			out = append(out, inputItem{Path: m, AlertType: in.AlertType, ErrorDir: in.ErrorDir})
		}
	}
	return out, nil
}

func expandGlobWithDoubleStar(pattern string) ([]string, error) {
	// Go's filepath.Glob doesn't support **; implement a minimal recursive matcher.
	if !strings.Contains(pattern, "**") {
		return filepath.Glob(pattern)
	}

	// Split at the first ** occurrence.
	idx := strings.Index(pattern, "**")
	basePart := strings.TrimRight(pattern[:idx], string(filepath.Separator)+"/")
	if basePart == "" {
		basePart = "."
	}
	basePart = filepath.Clean(basePart)

	suffix := pattern[idx+2:]
	suffix = strings.TrimLeft(suffix, string(filepath.Separator)+"/")
	if suffix == "" {
		suffix = "*"
	}

	baseSlash := filepath.ToSlash(basePart)
	suffixSlash := filepath.ToSlash(suffix)
	matchBasenameOnly := !strings.Contains(suffixSlash, "/")

	var matches []string
	err := filepath.WalkDir(basePart, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		pSlash := filepath.ToSlash(p)
		rel := strings.TrimPrefix(pSlash, baseSlash)
		rel = strings.TrimLeft(rel, "/")
		candidate := rel
		if matchBasenameOnly {
			candidate = path.Base(rel)
		}
		ok, matchErr := path.Match(suffixSlash, candidate)
		if matchErr != nil {
			return matchErr
		}
		if ok {
			matches = append(matches, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return matches, nil
}

func (r *Runner) ingestFile(path string, forcedAlertType string, errorDir string, deadline time.Time, stats *runStats) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return nil
	}
	if info.Size() <= 0 {
		return nil
	}

	content, err := os.ReadFile(path)
	if err != nil {
		// Best-effort: move unreadable files out of the input directory.
		if strings.TrimSpace(errorDir) != "" {
			_, _ = MoveFileToDir(path, errorDir)
		}
		return err
	}

	fileSHA := sha256.Sum256(content)
	fileSHAHex := hex.EncodeToString(fileSHA[:])

	already, err := r.isAlreadyProcessed(path, fileSHAHex, info)
	if err != nil {
		return err
	}
	if already {
		r.debugf("skip already processed path=%q sha=%s", path, fileSHAHex)
		return nil
	}

	alertType := strings.TrimSpace(forcedAlertType)
	if alertType == "" {
		alertType = inferAlertType(path)
	}
	sourceType := inferSourceType(path)
	raw := string(content)

	var decoded any
	if err := json.Unmarshal(content, &decoded); err != nil {
		// archive decode error as a single event
		r.debugf("decode error path=%q err=%v", path, err)
		return r.archiveAndMarkFile(path, fileSHAHex, info, []SpoolEvent{newErrorEvent(path, sourceType, alertType, fileSHAHex, raw, err)}, deadline, stats, errorDir, true)
	}

	events, err := r.toEvents(decoded, raw, path, sourceType, alertType, fileSHAHex)
	if err != nil {
		r.debugf("toEvents error path=%q err=%v", path, err)
		return r.archiveAndMarkFile(path, fileSHAHex, info, []SpoolEvent{newErrorEvent(path, sourceType, alertType, fileSHAHex, raw, err)}, deadline, stats, errorDir, true)
	}

	return r.archiveAndMarkFile(path, fileSHAHex, info, events, deadline, stats, "", false)
}

func (r *Runner) toEvents(decoded any, raw string, sourcePath string, sourceType string, alertType string, fileSHA string) ([]SpoolEvent, error) {
	now := time.Now().UTC()
	switch v := decoded.(type) {
	case []any:
		out := make([]SpoolEvent, 0, len(v))
		for i, item := range v {
			ev, err := r.buildEvent(item, raw, sourcePath, sourceType, alertType, fileSHA, i, now, nil)
			if err != nil {
				out = append(out, newErrorEvent(sourcePath, sourceType, alertType, fileSHA, raw, err))
				continue
			}
			out = append(out, ev)
		}
		return out, nil
	default:
		ev, err := r.buildEvent(v, raw, sourcePath, sourceType, alertType, fileSHA, 0, now, nil)
		if err != nil {
			return nil, err
		}
		return []SpoolEvent{ev}, nil
	}
}

func (r *Runner) buildEvent(item any, raw string, sourcePath string, sourceType string, alertType string, fileSHA string, idx int, now time.Time, stats *runStats) (SpoolEvent, error) {
	eventBytes, err := json.Marshal(item)
	if err != nil {
		return SpoolEvent{}, err
	}
	eventJSON := string(eventBytes)

	flat := FlattenJSON(item, FlattenOptions{})
	flatBytes, err := json.Marshal(flat)
	if err != nil {
		return SpoolEvent{}, err
	}
	flatJSON := string(flatBytes)

	keyText := extractKeyText(item)
	normalized := NormalizeText(keyText)
	hash := HashNormalized(normalized, r.cfg.HashHexLen)
	cccc := "none"
	if len(r.cfg.CCCCCodes) > 0 {
		cccc = ExtractCCCC(keyText, r.cfg.CCCCCodes)
	}
	alertLevel := ExtractAlertLevel(item, sourcePath)
	if stats != nil {
		if lag, ok := computeLag(now, item); ok {
			if lag > stats.MaxLag {
				stats.MaxLag = lag
			}
		}
	}

	ev := SpoolEvent{
		IngestedAt:       now,
		SourcePath:       sourcePath,
		SourceType:       sourceType,
		AlertType:        alertType,
		AlertLevel:       alertLevel,
		CCCC:             cccc,
		EventIndex:       idx,
		FileDigestSHA256: fileSHA,
		RawContent:       raw,
		EventJSON:        eventJSON,
		FlatJSON:         flatJSON,
		Normalized:       normalized,
		ContentHash:      hash,
		ArchivedAt:       now,
	}

	return ev, nil
}

func computeLag(now time.Time, item any) (time.Duration, bool) {
	ts, ok := extractEventTime(item)
	if !ok {
		return 0, false
	}
	if ts.IsZero() {
		return 0, false
	}
	lag := now.Sub(ts)
	if lag < 0 {
		return 0, false
	}
	return lag, true
}

func extractEventTime(item any) (time.Time, bool) {
	m, ok := item.(map[string]any)
	if !ok {
		return time.Time{}, false
	}
	keys := []string{"time", "timestamp", "ts", "occur_time", "occurTime", "created_at", "createdAt", "alert_time", "alertTime"}
	for _, k := range keys {
		v, ok := m[k]
		if !ok {
			continue
		}
		if ts, ok := parseAnyTime(v); ok {
			return ts, true
		}
	}
	return time.Time{}, false
}

func parseAnyTime(v any) (time.Time, bool) {
	switch t := v.(type) {
	case string:
		return parseTimeString(t)
	case float64:
		// could be unix seconds
		sec := int64(t)
		if sec <= 0 {
			return time.Time{}, false
		}
		return time.Unix(sec, 0).UTC(), true
	case int64:
		if t <= 0 {
			return time.Time{}, false
		}
		return time.Unix(t, 0).UTC(), true
	case int:
		if t <= 0 {
			return time.Time{}, false
		}
		return time.Unix(int64(t), 0).UTC(), true
	default:
		return time.Time{}, false
	}
}

func parseTimeString(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts.UTC(), true
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts.UTC(), true
	}
	// Try common notifier formats; interpret as Asia/Shanghai when possible.
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		loc = time.Local
	}
	layouts := []string{
		"2006-01-02 15:04:05.000",
		"2006-01-02 15:04:05",
		"2006/01/02 15:04:05",
		"2006/01/02 15:04:05.000",
	}
	for _, layout := range layouts {
		if ts, err := time.ParseInLocation(layout, s, loc); err == nil {
			return ts.UTC(), true
		}
	}
	return time.Time{}, false
}

func extractKeyText(item any) string {
	m, ok := item.(map[string]any)
	if ok {
		if v, ok := m["detail"]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		if v, ok := m["description"]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	b, _ := json.Marshal(item)
	return string(b)
}

func inferSourceType(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".warn":
		return "warn"
	case ".alarm":
		return "alarm"
	default:
		return strings.TrimPrefix(ext, ".")
	}
}

func inferAlertType(path string) string {
	p := strings.ToLower(filepath.ToSlash(path))
	switch {
	case strings.Contains(p, "/dev/"):
		return "dev"
	case strings.Contains(p, "/iec/"):
		return "iec"
	case strings.Contains(p, "/business/"):
		return "business"
	case strings.Contains(p, "/general/"):
		return "general"
	default:
		// best-effort by extension
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".alarm" {
			return "dev"
		}
		return "unknown"
	}
}

func (r *Runner) isAlreadyProcessed(path string, sha string, info fs.FileInfo) (bool, error) {
	var pf ProcessedFile
	err := r.db.Where("path = ? AND sha256 = ?", path, sha).First(&pf).Error
	if err == nil {
		return true, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	return false, err
}

func (r *Runner) archiveAndMarkFile(path string, sha string, info fs.FileInfo, events []SpoolEvent, deadline time.Time, stats *runStats, errorDir string, moveToErrorDir bool) error {
	// send syslog + persist
	allSent := true
	for i := range events {
		if stats != nil {
			stats.EventsNew++
			if lag, ok := computeLag(time.Now().UTC(), jsonAnyFromString(events[i].EventJSON)); ok {
				if lag > stats.MaxLag {
					stats.MaxLag = lag
				}
			}
		}
		structured := buildStructuredData("cndp", map[string]string{
			"job":        r.cfg.JobLabel,
			"service":    r.cfg.ServiceLabel,
			"env":        r.cfg.FixedLabels["env"],
			"site":       r.cfg.FixedLabels["site"],
			"cluster":    r.cfg.FixedLabels["cluster"],
			"filename":   filepath.Base(path),
			"alert_type": events[i].AlertType,
			"alert_level": func() string {
				if strings.TrimSpace(events[i].AlertLevel) == "" {
					return "unknown"
				}
				return events[i].AlertLevel
			}(),
			"hash": events[i].ContentHash,
			"cccc": events[i].CCCC,
		})

		payload := map[string]any{
			"source":      events[i].SourcePath,
			"event_index": events[i].EventIndex,
			"event":       json.RawMessage(events[i].EventJSON),
			"flat":        json.RawMessage(events[i].FlatJSON),
		}
		payloadBytes, _ := json.Marshal(payload)
		err := r.syslog.SendRFC5424Timeout("alert-spooler", structured, string(payloadBytes), remainingTimeout(deadline, 3*time.Second))
		if err != nil {
			r.debugf("syslog send failed path=%q idx=%d err=%v", path, events[i].EventIndex, err)
			events[i].SentSyslog = false
			events[i].SendError = err.Error()
			allSent = false
			if stats != nil {
				stats.EventsSentErr++
			}
		} else {
			r.debugf("syslog send ok path=%q idx=%d", path, events[i].EventIndex)
			t := time.Now().UTC()
			events[i].SentSyslog = true
			events[i].SentAt = &t
			if stats != nil {
				stats.EventsSentOK++
			}
		}
	}

	err := r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&events).Error; err != nil {
			return err
		}
		pf := ProcessedFile{
			Path:        path,
			SHA256:      sha,
			SizeBytes:   info.Size(),
			ModUnixNano: info.ModTime().UnixNano(),
			ProcessedAt: time.Now().UTC(),
			AllSent:     allSent,
			Deleted:     false,
		}
		if err := tx.Create(&pf).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		r.debugf("db transaction failed path=%q err=%v", path, err)
		// Best-effort: move files that failed DB archive out of the input directory.
		if moveToErrorDir && strings.TrimSpace(errorDir) != "" {
			_, _ = MoveFileToDir(path, errorDir)
		}
		return err
	}
	if stats != nil {
		stats.FilesIngested++
	}

	// For broken/unparseable inputs: move to error_dir after DB insert (independent of syslog send success).
	if moveToErrorDir && strings.TrimSpace(errorDir) != "" {
		dst, mvErr := MoveFileToDir(path, errorDir)
		now := time.Now().UTC()
		if mvErr != nil {
			_ = r.db.Model(&ProcessedFile{}).
				Where("path = ? AND sha256 = ?", path, sha).
				Updates(map[string]any{"last_error": fmt.Sprintf("move to error_dir failed: %v", mvErr)}).Error
			return mvErr
		}
		_ = r.db.Model(&ProcessedFile{}).
			Where("path = ? AND sha256 = ?", path, sha).
			Updates(map[string]any{"deleted": true, "deleted_at": &now, "last_error": fmt.Sprintf("moved to error_dir: %s", dst)}).Error
		if stats != nil {
			stats.FilesDeleted++
		}
		return nil
	}

	// Delete source file only after allSent + DB insert succeeded.
	if r.cfg.DeleteAfterSend && allSent {
		if remErr := r.tryDeleteProcessedFile(path, sha); remErr != nil {
			r.debugf("delete failed path=%q err=%v", path, remErr)
			return remErr
		}
		r.debugf("deleted source file path=%q", path)
		if stats != nil {
			stats.FilesDeleted++
		}
	}
	return nil
}

func jsonAnyFromString(s string) any {
	var v any
	_ = json.Unmarshal([]byte(s), &v)
	return v
}

func (r *Runner) tryDeleteProcessedFile(path string, sha string) error {
	removeErr := os.Remove(path)
	now := time.Now().UTC()
	if removeErr != nil {
		_ = r.db.Model(&ProcessedFile{}).
			Where("path = ? AND sha256 = ?", path, sha).
			Updates(map[string]any{"last_error": fmt.Sprintf("delete failed: %v", removeErr)}).Error
		return removeErr
	}
	return r.db.Model(&ProcessedFile{}).
		Where("path = ? AND sha256 = ?", path, sha).
		Updates(map[string]any{"deleted": true, "deleted_at": &now, "last_error": ""}).Error
}

func (r *Runner) resendPending(deadline time.Time, stats *runStats) error {
	var pending []SpoolEvent
	if err := r.db.Where("sent_syslog = ?", false).Find(&pending).Error; err != nil {
		return err
	}
	for _, ev := range pending {
		if isDeadlineExceeded(deadline) {
			return fmt.Errorf("timeout exceeded")
		}
		if stats != nil {
			if lag, ok := computeLag(time.Now().UTC(), jsonAnyFromString(ev.EventJSON)); ok {
				if lag > stats.MaxLag {
					stats.MaxLag = lag
				}
			}
		}
		structured := buildStructuredData("cndp", map[string]string{
			"job":        r.cfg.JobLabel,
			"service":    r.cfg.ServiceLabel,
			"env":        r.cfg.FixedLabels["env"],
			"site":       r.cfg.FixedLabels["site"],
			"cluster":    r.cfg.FixedLabels["cluster"],
			"filename":   filepath.Base(ev.SourcePath),
			"alert_type": ev.AlertType,
			"alert_level": func() string {
				if strings.TrimSpace(ev.AlertLevel) == "" {
					return "unknown"
				}
				return ev.AlertLevel
			}(),
			"hash": ev.ContentHash,
			"cccc": ev.CCCC,
		})
		payload := map[string]any{
			"source":      ev.SourcePath,
			"event_index": ev.EventIndex,
			"event":       json.RawMessage(ev.EventJSON),
			"flat":        json.RawMessage(ev.FlatJSON),
		}
		payloadBytes, _ := json.Marshal(payload)
		err := r.syslog.SendRFC5424Timeout("alert-spooler", structured, string(payloadBytes), remainingTimeout(deadline, 3*time.Second))
		if err != nil {
			r.debugf("resend failed id=%d path=%q err=%v", ev.ID, ev.SourcePath, err)
			_ = r.db.Model(&SpoolEvent{}).
				Where("id = ?", ev.ID).
				Updates(map[string]any{"send_error": err.Error()}).Error
			if stats != nil {
				stats.EventsSentErr++
			}
			continue
		}
		r.debugf("resend ok id=%d path=%q", ev.ID, ev.SourcePath)
		now := time.Now().UTC()
		_ = r.db.Model(&SpoolEvent{}).
			Where("id = ?", ev.ID).
			Updates(map[string]any{"sent_syslog": true, "send_error": "", "sent_at": &now}).Error
		if stats != nil {
			stats.EventsSentOK++
		}
	}
	return nil
}

func (r *Runner) finalizeFiles(stats *runStats) error {
	var pfs []ProcessedFile
	if err := r.db.Where("all_sent = ? OR deleted = ?", false, false).Find(&pfs).Error; err != nil {
		return err
	}
	for _, pf := range pfs {
		var total int64
		var sent int64
		if err := r.db.Model(&SpoolEvent{}).
			Where("source_path = ? AND file_sha256 = ?", pf.Path, pf.SHA256).
			Count(&total).Error; err != nil {
			continue
		}
		if total == 0 {
			continue
		}
		if err := r.db.Model(&SpoolEvent{}).
			Where("source_path = ? AND file_sha256 = ? AND sent_syslog = ?", pf.Path, pf.SHA256, true).
			Count(&sent).Error; err != nil {
			continue
		}
		allSent := sent == total
		if allSent && !pf.AllSent {
			_ = r.db.Model(&ProcessedFile{}).
				Where("id = ?", pf.ID).
				Updates(map[string]any{"all_sent": true, "last_error": ""}).Error
		}
		if r.cfg.DeleteAfterSend && allSent && !pf.Deleted {
			// If file already missing, mark deleted to stop retry loop.
			if _, statErr := os.Stat(pf.Path); statErr != nil {
				now := time.Now().UTC()
				_ = r.db.Model(&ProcessedFile{}).
					Where("id = ?", pf.ID).
					Updates(map[string]any{"deleted": true, "deleted_at": &now, "last_error": "file missing"}).Error
				continue
			}
			if err := r.tryDeleteProcessedFile(pf.Path, pf.SHA256); err == nil {
				r.debugf("finalize deleted path=%q", pf.Path)
				if stats != nil {
					stats.FilesDeleted++
				}
			}
		}
	}
	return nil
}

func (r *Runner) sendDeadman(deadline time.Time, start time.Time, end time.Time, stats *runStats, runErr error) error {
	status := "ok"
	errMsg := ""
	if runErr != nil {
		status = "error"
		errMsg = runErr.Error()
	}
	maxLagMs := int64(0)
	if stats != nil {
		maxLagMs = stats.MaxLag.Milliseconds()
	}
	msg := map[string]any{
		"deadman":           r.cfg.DeadmanToken,
		"status":            status,
		"error":             errMsg,
		"started_at":        start.UTC().Format(time.RFC3339Nano),
		"ended_at":          end.UTC().Format(time.RFC3339Nano),
		"duration_ms":       end.Sub(start).Milliseconds(),
		"events_new":        stats.EventsNew,
		"events_sent_ok":    stats.EventsSentOK,
		"events_sent_err":   stats.EventsSentErr,
		"events_replay_ok":  stats.EventsReplayOK,
		"events_replay_err": stats.EventsReplayErr,
		"files_ingested":    stats.FilesIngested,
		"files_deleted":     stats.FilesDeleted,
		"max_lag_ms":        maxLagMs,
	}
	b, _ := json.Marshal(msg)

	structured := buildStructuredData("cndp", map[string]string{
		"job":         r.cfg.JobLabel,
		"service":     r.cfg.ServiceLabel,
		"env":         r.cfg.FixedLabels["env"],
		"site":        r.cfg.FixedLabels["site"],
		"cluster":     r.cfg.FixedLabels["cluster"],
		"filename":    "-",
		"alert_type":  "deadman",
		"alert_level": "unknown",
		"hash":        "deadman",
		"cccc":        "none",
		"deadman":     r.cfg.DeadmanToken,
	})
	return r.syslog.SendRFC5424Timeout("alert-spooler", structured, string(b), remainingTimeout(deadline, 3*time.Second))
}

func newErrorEvent(sourcePath string, sourceType string, alertType string, fileSHA string, raw string, err error) SpoolEvent {
	now := time.Now().UTC()
	return SpoolEvent{
		IngestedAt:       now,
		SourcePath:       sourcePath,
		SourceType:       sourceType,
		AlertType:        alertType,
		AlertLevel:       "unknown",
		EventIndex:       0,
		FileDigestSHA256: fileSHA,
		RawContent:       raw,
		EventJSON:        "{}",
		FlatJSON:         "{}",
		Normalized:       "",
		ContentHash:      "",
		SentSyslog:       false,
		SendError:        fmt.Sprintf("decode/build error: %v", err),
		ArchivedAt:       now,
	}
}

func buildStructuredData(sdID string, kv map[string]string) string {
	if sdID == "" {
		sdID = "cndp"
	}
	var b strings.Builder
	b.WriteString("[")
	b.WriteString(sdID)
	preferredOrder := []string{"job", "service", "env", "site", "cluster", "filename", "alert_type", "alert_level", "hash", "cccc", "replay", "deadman"}
	seen := make(map[string]struct{}, len(kv))
	for _, k := range preferredOrder {
		v, ok := kv[k]
		if !ok {
			continue
		}
		if strings.TrimSpace(v) == "" {
			continue
		}
		seen[k] = struct{}{}
		b.WriteString(" ")
		b.WriteString(k)
		b.WriteString("=\"")
		b.WriteString(escapeSDParam(v))
		b.WriteString("\"")
	}
	extraKeys := make([]string, 0, len(kv))
	for k, v := range kv {
		if _, ok := seen[k]; ok {
			continue
		}
		if strings.TrimSpace(v) == "" {
			continue
		}
		extraKeys = append(extraKeys, k)
	}
	sort.Strings(extraKeys)
	for _, k := range extraKeys {
		v := kv[k]
		b.WriteString(" ")
		b.WriteString(k)
		b.WriteString("=\"")
		b.WriteString(escapeSDParam(v))
		b.WriteString("\"")
	}
	b.WriteString("]")
	return b.String()
}

func escapeSDParam(v string) string {
	v = strings.ReplaceAll(v, "\\", "\\\\")
	v = strings.ReplaceAll(v, "\"", "\\\"")
	v = strings.ReplaceAll(v, "]", "\\]")
	v = strings.ReplaceAll(v, "\n", " ")
	v = strings.ReplaceAll(v, "\r", " ")
	return v
}
