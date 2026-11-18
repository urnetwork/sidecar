//go:build !js

// No MCP code reaches the drop calls (EVS2-M10-21; D-MCP-32, §16.6's refused list): an agent may preview a drop, never
// sign one or cancel one. It reads the source tree, so it runs on the host, never in the js Worker.

package sidecar

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// No MCP code calls DropHistory or CancelDrop (D-MCP-32; §16.6's refused list): an agent never drops history.
func TestEvsDropHistoryNoMcpRoute(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("mcp", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no mcp sources: %v", err)
	}
	for _, file := range files {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, call := range []string{".DropHistory(", ".CancelDrop("} {
			if bytes.Contains(source, []byte(call)) {
				t.Fatalf("%s calls %s", file, call)
			}
		}
	}
}
