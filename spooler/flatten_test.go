package spooler

import "testing"

func TestFlattenJSON(t *testing.T) {
	input := map[string]any{
		"a": map[string]any{
			"b": 1,
			"c": []any{"x", map[string]any{"y": true}},
		},
	}
	flat := FlattenJSON(input, FlattenOptions{MaxDepth: 8, MaxKeys: 100})
	if flat["a.b"] != 1 {
		t.Fatalf("expected a.b=1, got %v", flat["a.b"])
	}
	if flat["a.c[0]"] != "x" {
		t.Fatalf("expected a.c[0]=x, got %v", flat["a.c[0]"])
	}
	if flat["a.c[1].y"] != true {
		t.Fatalf("expected a.c[1].y=true, got %v", flat["a.c[1].y"])
	}
}
