package spooler

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var timestampPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}`),
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`),
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}`),
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3,6}`),
	regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3,6}`),
	regexp.MustCompile(`\d{4}\.\d{2}\.\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3,6})?`),
	regexp.MustCompile(`\d{4}/\d{2}/\d{2} \d{2}:\d{2}`),
	regexp.MustCompile(`\d{4}-\d{1,2}-\d{1,2} \d{1,2}:\d{1,2}:\d{1,2}`),
}

func NormalizeText(input string) string {
	s := input
	for _, re := range timestampPatterns {
		s = re.ReplaceAllString(s, "")
	}
	s = strings.TrimSpace(s)
	s = strings.Join(strings.Fields(s), " ")
	return s
}

func HashNormalized(normalized string, hexLen int) string {
	sum := sha256.Sum256([]byte(normalized))
	full := hex.EncodeToString(sum[:])
	if hexLen <= 0 || hexLen >= len(full) {
		return full
	}
	return full[:hexLen]
}
