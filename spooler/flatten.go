package spooler

import (
	"fmt"
	"strconv"
)

type FlattenOptions struct {
	MaxDepth int
	MaxKeys  int
}

func FlattenJSON(value any, opts FlattenOptions) map[string]any {
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 16
	}
	if opts.MaxKeys <= 0 {
		opts.MaxKeys = 5000
	}

	out := make(map[string]any)
	flattenInto(out, "", value, 0, opts)
	return out
}

func flattenInto(out map[string]any, prefix string, value any, depth int, opts FlattenOptions) {
	if len(out) >= opts.MaxKeys {
		return
	}
	if depth > opts.MaxDepth {
		if prefix != "" {
			out[prefix] = fmt.Sprintf("<max_depth:%d>", opts.MaxDepth)
		}
		return
	}

	switch v := value.(type) {
	case map[string]any:
		for k, child := range v {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			flattenInto(out, key, child, depth+1, opts)
			if len(out) >= opts.MaxKeys {
				return
			}
		}
	case []any:
		for i, child := range v {
			idx := strconv.Itoa(i)
			key := idx
			if prefix != "" {
				key = prefix + "[" + idx + "]"
			}
			flattenInto(out, key, child, depth+1, opts)
			if len(out) >= opts.MaxKeys {
				return
			}
		}
	default:
		if prefix == "" {
			out["value"] = v
			return
		}
		out[prefix] = v
	}
}
