package spooler

import "strings"

func ExtractCCCC(text string, codes []string) string {
	if len(codes) == 0 {
		return "none"
	}
	// Use original (not normalized) text to maximize hit rate.
	upper := strings.ToUpper(text)
	for _, c := range codes {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		if strings.Contains(upper, c) {
			return c
		}
	}
	return "none"
}
