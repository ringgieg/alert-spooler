package spooler

import "testing"

func TestExtractCCCC(t *testing.T) {
	codes := []string{"ZBBB", "ZGGG"}
	if got := ExtractCCCC("hello ZGGGZHHHZSSS world", codes); got != "ZGGG" {
		t.Fatalf("expected ZGGG, got %q", got)
	}
	if got := ExtractCCCC("no match", codes); got != "none" {
		t.Fatalf("expected none, got %q", got)
	}
}
