package spooler

import "time"

type ProcessedFile struct {
	ID          uint   `gorm:"primaryKey"`
	Path        string `gorm:"uniqueIndex:uniq_path_sha;size:1024"`
	SHA256      string `gorm:"uniqueIndex:uniq_path_sha;size:64"`
	SizeBytes   int64
	ModUnixNano int64
	ProcessedAt time.Time `gorm:"index"`
	AllSent     bool      `gorm:"index"`
	Deleted     bool      `gorm:"index"`
	DeletedAt   *time.Time
	LastError   string `gorm:"type:text"`
}

type SpoolEvent struct {
	ID         uint      `gorm:"primaryKey"`
	IngestedAt time.Time `gorm:"index"`
	SourcePath string    `gorm:"index;size:1024"`
	SourceType string    `gorm:"index;size:32"` // warn, alarm, other
	AlertType  string    `gorm:"index;size:32"` // dev, iec, business, general, unknown
	AlertLevel string    `gorm:"index;size:16"` // warning, critical, unknown
	CCCC       string    `gorm:"index;size:16"` // 4-char code tag (e.g. ZBBB)
	EventIndex int       `gorm:"index"`
	// FileDigestSHA256 is the SHA-256 digest of the whole file content.
	// It is used to associate events with their source file record (ProcessedFile) and to ensure idempotency.
	// For ZYC-like de-duplication, use ContentHash (normalized key-text hash) instead.
	FileDigestSHA256 string `gorm:"column:file_sha256;index;size:64"`
	RawContent       string `gorm:"type:text"`
	EventJSON        string `gorm:"type:text"`
	FlatJSON         string `gorm:"type:text"`
	Normalized       string `gorm:"type:text"`
	// ContentHash is the ZYC-like hash: hash(normalize(extractKeyText(detail/description/...))).
	ContentHash string `gorm:"index;size:64"`
	SentSyslog  bool   `gorm:"index"`
	SendError   string `gorm:"type:text"`
	SentAt      *time.Time
	ArchivedAt  time.Time `gorm:"index"`
}
