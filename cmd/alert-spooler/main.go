package main

import (
	"alert-spooler/spooler"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var configPath string
	var inputGlobs multiFlag
	var dbPath string
	var dbFolder string
	var dbPrefix string
	var debug bool
	var jobLabel string
	var syslogAddr string
	var serviceLabel string
	var hashHexLen int
	var ccccCodesCSV string
	var deleteAfterSend bool
	var timeout time.Duration
	var deadman string
	var once bool
	var pollInterval time.Duration
	var replayFrom string

	flag.StringVar(&configPath, "config", "", "YAML config file path.")
	flag.Var(&inputGlobs, "input-glob", "Input glob(s) for alert files. Can be repeated.")
	flag.StringVar(&dbPath, "db", "spooler.db", "SQLite database path.")
	flag.StringVar(&dbFolder, "db-folder", "", "Monthly rolling DB folder (overrides config.database.folder).")
	flag.StringVar(&dbPrefix, "db-prefix", "", "Monthly rolling DB prefix (overrides config.database.prefix).")
	flag.BoolVar(&debug, "debug", false, "Enable debug logs.")
	flag.StringVar(&jobLabel, "job", "", "Loki label 'job' (sent via syslog structured-data). Prefer config file.")
	flag.StringVar(&syslogAddr, "syslog-addr", "127.0.0.1:1514", "Alloy syslog receiver address (tcp).")
	flag.StringVar(&serviceLabel, "service", "alerts", "Syslog structured-data service label.")
	flag.IntVar(&hashHexLen, "hash-hex-len", 24, "Normalized content hash hex length.")
	flag.StringVar(&ccccCodesCSV, "cccc", "", "Comma-separated CCCC codes list (e.g. ZBBB,ZGGG). Overrides config.")
	flag.BoolVar(&deleteAfterSend, "delete-after-send", true, "Delete source files only after syslog send + DB insert succeed.")
	flag.DurationVar(&timeout, "timeout", 0, "Overall timeout for one run (e.g. 30s, 2m).")
	flag.StringVar(&deadman, "deadman", "", "Deadman token/message. Required each run.")
	flag.StringVar(&replayFrom, "replay-from", "", "Replay mode: resend archived events from this time (adds replay label). Formats: RFC3339 or '2006-01-02 15:04:05'.")
	flag.BoolVar(&once, "once", true, "Run once and exit (default true for crontab).")
	flag.DurationVar(&pollInterval, "poll-interval", 5*time.Second, "Polling interval when not running with --once=false.")
	flag.Parse()

	visited := map[string]bool{}
	flag.CommandLine.Visit(func(f *flag.Flag) {
		visited[f.Name] = true
	})

	// Base config from file (optional)
	fileCfg := &spooler.FileConfig{}
	if configPath != "" {
		cfg, err := spooler.LoadConfig(configPath)
		if err != nil {
			log.Fatalf("load config: %v", err)
		}
		fileCfg = cfg
	}

	// Merge config + CLI overrides
	finalDBFolder := fileCfg.Database.Folder
	finalDBPrefix := fileCfg.Database.Prefix
	if visited["db-folder"] {
		finalDBFolder = dbFolder
	}
	if visited["db-prefix"] {
		finalDBPrefix = dbPrefix
	}
	// Legacy single DB file
	finalDB := fileCfg.DB
	if visited["db"] {
		finalDB = dbPath
	}

	finalJob := fileCfg.Job
	if visited["job"] {
		finalJob = jobLabel
	}
	finalDebug := fileCfg.Debug
	if visited["debug"] {
		finalDebug = debug
	}
	finalDeleteAfterSend := true
	if fileCfg.DeleteAfterSend != nil {
		finalDeleteAfterSend = *fileCfg.DeleteAfterSend
	}
	if visited["delete-after-send"] {
		finalDeleteAfterSend = deleteAfterSend
	}

	finalSyslog := fileCfg.SyslogAddr
	if finalSyslog == "" {
		finalSyslog = "127.0.0.1:1514"
	}
	if visited["syslog-addr"] {
		finalSyslog = syslogAddr
	}

	finalService := fileCfg.Service
	if finalService == "" {
		finalService = "alerts"
	}
	if visited["service"] {
		finalService = serviceLabel
	}

	finalHashLen := fileCfg.HashHexLen
	if finalHashLen == 0 {
		finalHashLen = 24
	}
	if visited["hash-hex-len"] {
		finalHashLen = hashHexLen
	}

	finalGlobs := fileCfg.InputGlobs
	if visited["input-glob"] {
		finalGlobs = inputGlobs
	}

	finalInputs := make([]spooler.InputSpec, 0, len(fileCfg.Files.Items))
	for _, f := range fileCfg.Files.Items {
		finalInputs = append(finalInputs, spooler.InputSpec{Glob: f.AlertDir, AlertType: f.AlertType})
	}

	// CCCC codes
	finalCCCCCodes := fileCfg.CCCC.Codes
	if strings.TrimSpace(ccccCodesCSV) != "" {
		parts := strings.Split(ccccCodesCSV, ",")
		finalCCCCCodes = make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				finalCCCCCodes = append(finalCCCCCodes, p)
			}
		}
	}
	// CCCC tagging is enabled iff codes is non-empty.
	finalCCCCEnabled := len(finalCCCCCodes) > 0

	if len(finalGlobs) == 0 && len(finalInputs) == 0 {
		fmt.Fprintln(os.Stderr, "missing inputs (use config.yaml files[] or --input-glob / input_globs)")
		os.Exit(2)
	}
	if strings.TrimSpace(finalJob) == "" {
		fmt.Fprintln(os.Stderr, "missing job label (use --job or config.yaml job)")
		os.Exit(2)
	}
	if strings.TrimSpace(deadman) == "" {
		fmt.Fprintln(os.Stderr, "missing deadman token (use --deadman=...)")
		os.Exit(2)
	}

	var finalReplayFrom time.Time
	if strings.TrimSpace(replayFrom) != "" {
		tm, err := parseReplayFrom(replayFrom)
		if err != nil {
			log.Fatalf("parse --replay-from: %v", err)
		}
		finalReplayFrom = tm
	}

	runner, err := spooler.NewRunner(spooler.RunnerConfig{
		DBPath:          finalDB,
		DBFolder:        finalDBFolder,
		DBPrefix:        finalDBPrefix,
		JobLabel:        finalJob,
		Debug:           finalDebug,
		InputGlobs:      finalGlobs,
		Inputs:          finalInputs,
		SyslogAddr:      finalSyslog,
		ServiceLabel:    finalService,
		HashHexLen:      finalHashLen,
		CCCCEnabled:     finalCCCCEnabled,
		CCCCCodes:       finalCCCCCodes,
		DeleteAfterSend: finalDeleteAfterSend,
		Timeout:         timeout,
		DeadmanToken:    deadman,
		ReplayFrom:      finalReplayFrom,
	})
	if err != nil {
		log.Fatalf("init runner: %v", err)
	}
	defer runner.Close()

	if once {
		if err := runner.RunOnce(); err != nil {
			log.Fatalf("run once: %v", err)
		}
		return
	}

	for {
		if err := runner.RunOnce(); err != nil {
			log.Printf("run once error: %v", err)
		}
		time.Sleep(pollInterval)
	}
}

func parseReplayFrom(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty time")
	}
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		loc = time.Local
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.000",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05.000",
		"2006-01-02T15:04:05",
	}
	var lastErr error
	for _, layout := range layouts {
		var tm time.Time
		if strings.Contains(layout, "Z07") {
			tm, lastErr = time.Parse(layout, s)
		} else {
			tm, lastErr = time.ParseInLocation(layout, s, loc)
		}
		if lastErr == nil {
			return tm.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported time format: %q", s)
}
