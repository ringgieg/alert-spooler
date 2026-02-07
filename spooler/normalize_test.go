package spooler

import "testing"

func TestNormalizeHash(t *testing.T) {
	text1 := "2025-06-01 15:30:00 foo error"
	text2 := "2025-06-02 11:22:33 foo error"
	n1 := NormalizeText(text1)
	n2 := NormalizeText(text2)
	if n1 != "foo error" || n2 != "foo error" {
		t.Fatalf("unexpected normalize: %q %q", n1, n2)
	}
	if HashNormalized(n1, 24) != HashNormalized(n2, 24) {
		t.Fatalf("hash should match for normalized equivalent")
	}
}
