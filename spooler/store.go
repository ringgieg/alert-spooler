package spooler

import (
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func OpenDB(path string) (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	if err := db.AutoMigrate(&ProcessedFile{}, &SpoolEvent{}); err != nil {
		return nil, err
	}
	return db, nil
}

// OpenQueryDB opens an existing SQLite DB for querying without mutating schema.
// This is important when reading fixtures from notifier's historical DBs.
func OpenQueryDB(path string) (*gorm.DB, error) {
	return gorm.Open(sqlite.Open(path), &gorm.Config{})
}
