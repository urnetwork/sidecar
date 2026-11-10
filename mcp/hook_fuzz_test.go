//go:build !js && !ios && !android && !sdk_mobile_bind

// §22.6's `ur hook` payloads: every adapter reads any bytes without a panic, and refuses with a field's name alone,
// never echoing what the payload held (I-7). Seeds are testdata/harness's payloads, each harness's own shape.

package mcp

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// The fields a refusal may name.
var hookPayloadErrorFields = []string{"json", "session_id", "hook_event_name", "conversation_id"}

func FuzzHookPayload(f *testing.F) {
	directory := filepath.Join("..", "testdata", "harness")
	entries, err := os.ReadDir(directory)
	if err != nil {
		f.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			payload, err := os.ReadFile(filepath.Join(directory, entry.Name()))
			if err != nil {
				f.Fatal(err)
			}
			f.Add(payload)
		}
	}
	// a secret-shaped value where a refusal could be tempted to quote it
	f.Add([]byte(`{"session_id":"ur-authkey-synthetic-0000","tool_name":"Bash"}`))
	f.Add([]byte(`{"conversation_id":"","hook_event_name":"ur_sk_synthetic"}`))
	ingest := sidecar.DefaultSidecarSettings().Ingest
	f.Fuzz(func(t *testing.T, payload []byte) {
		for _, harness := range HookHarnesses() {
			adapter, _ := HookAdapterFor(harness)
			event, err := adapter.Parse(payload, ingest)
			if err != nil {
				field, named := strings.CutPrefix(err.Error(), ErrHookPayload.Error()+": ")
				if !errors.Is(err, ErrHookPayload) || !named || !slices.Contains(hookPayloadErrorFields, field) {
					t.Fatalf("%s refused with %q, which names more than a field", harness, err)
				}
				continue
			}
			if event.Harness != harness || event.SessionId == "" || event.AdapterVersion != adapter.Version() {
				t.Fatalf("%s read %+v", harness, event)
			}
			CursorHookAnswer(event)
		}
	})
}
