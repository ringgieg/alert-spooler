package spooler

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// CCCCConfig configures 4-char code tagging (e.g. ZBBB, ZGGG).
type CCCCConfig struct {
	// Deprecated: Enabled is ignored. Tagging is enabled when Codes is non-empty.
	Enabled bool     `yaml:"enabled"`
	Codes   []string `yaml:"codes"`
}

// InputFileConfig represents one input glob with an explicit alert type.
type InputFileConfig struct {
	AlertDir  string `yaml:"alert_dir"`
	AlertType string `yaml:"alert_type"`
	ErrorDir  string `yaml:"error_dir"`
}

// FilesConfig accepts either:
//  1. mapping form (preferred):
//     files:
//     business: C:\\...\\*.warn
//     dev:      C:\\...\\*.alarm
//  2. legacy list form:
//     files:
//     - alert_dir: ...
//     alert_type: business
type FilesConfig struct {
	Items []InputFileConfig
}

func (f *FilesConfig) UnmarshalYAML(value *yaml.Node) error {
	if value == nil {
		return nil
	}
	switch value.Kind {
	case yaml.MappingNode:
		items := make([]InputFileConfig, 0, len(value.Content)/2)
		for i := 0; i+1 < len(value.Content); i += 2 {
			k := value.Content[i]
			v := value.Content[i+1]
			alertType := strings.TrimSpace(k.Value)
			if alertType == "" {
				continue
			}

			// Allow mapping values to be either:
			// - scalar string: <alert_dir>
			// - mapping object: {alert_dir: ..., error_dir: ...}
			switch v.Kind {
			case yaml.ScalarNode:
				alertDir := strings.TrimSpace(v.Value)
				if alertDir == "" {
					continue
				}
				items = append(items, InputFileConfig{AlertDir: alertDir, AlertType: alertType})
			case yaml.MappingNode:
				var tmp struct {
					AlertDir string `yaml:"alert_dir"`
					ErrorDir string `yaml:"error_dir"`
				}
				if err := v.Decode(&tmp); err != nil {
					return err
				}
				if strings.TrimSpace(tmp.AlertDir) == "" {
					continue
				}
				items = append(items, InputFileConfig{AlertDir: strings.TrimSpace(tmp.AlertDir), AlertType: alertType, ErrorDir: strings.TrimSpace(tmp.ErrorDir)})
			default:
				continue
			}
		}
		f.Items = items
		return nil
	case yaml.SequenceNode:
		var items []InputFileConfig
		if err := value.Decode(&items); err != nil {
			return err
		}
		f.Items = items
		return nil
	default:
		// ignore other kinds
		return nil
	}
}

type DatabaseConfig struct {
	Folder string `yaml:"folder"`
	Prefix string `yaml:"prefix"`
}

type FileConfig struct {
	// Legacy single DB path (kept for compatibility). Prefer Database for monthly rolling.
	DB string `yaml:"db"`

	// Database config (recommended).
	Database DatabaseConfig `yaml:"database"`

	Job   string `yaml:"job"`
	Debug bool   `yaml:"debug"`

	// When true, source files are deleted only after (1) syslog send success for all events and
	// (2) DB insert success.
	DeleteAfterSend *bool `yaml:"delete_after_send"`

	// Legacy globs (kept for compatibility). Prefer Files.
	InputGlobs []string `yaml:"input_globs"`

	// Input specs. Prefer mapping form: files: {type: path}
	Files FilesConfig `yaml:"files"`

	// Fixed labels emitted to syslog structured-data (for Loki labels).
	// Note: Alloy must be configured to extract these keys.
	FixedLabels map[string]string `yaml:"fixed_labels"`

	SyslogAddr string     `yaml:"syslog_addr"`
	Service    string     `yaml:"service"`
	HashHexLen int        `yaml:"hash_hex_len"`
	CCCC       CCCCConfig `yaml:"cccc"`
}

func LoadConfig(path string) (*FileConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg FileConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
