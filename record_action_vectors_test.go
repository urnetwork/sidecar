//go:build !js

// MCP-M3-02's vectors: each buildable kind's stored bytes in testdata/record/canonical_action.json, byte for byte, and
// FuzzCanonicalActionBuild. The js leg opens no files, so these stay off it.

package sidecar

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
)

var updateCanonicalActionVectors = flag.Bool("update-canonical-action-vectors", false,
	"rewrite testdata/record/canonical_action.json")

const testCanonicalActionVectorsPath = "testdata/record/canonical_action.json"

// testdata/record/canonical_action.json: each kind's action as stored and its payload_sha256, in lowercase hex.
type testCanonicalActionVectors struct {
	Comment string `json:"comment"`
	Actions []struct {
		Name          string `json:"name"`
		Stored        string `json:"stored"`
		PayloadSha256 string `json:"payload_sha256"`
	} `json:"actions"`
}

// The vectors as testBuildableActions builds them, by name.
func testComputeCanonicalActionVectors(t *testing.T) *testCanonicalActionVectors {
	vectors := &testCanonicalActionVectors{
		Comment: "MCP-M3-02's vectors: one action of each kind NewCanonicalAction builds, as stored, with its " +
			"payload_sha256. A build of the same inputs must give these bytes on every leg. go test -run " +
			"TestCanonicalActionVectors -update-canonical-action-vectors rewrites this file.",
	}
	actions := testBuildableActions()
	names := []string{}
	for name := range actions {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		stored := buildTestAction(t, actions[name])
		payloadSha256 := stored.PayloadSha256()
		vectors.Actions = append(vectors.Actions, struct {
			Name          string `json:"name"`
			Stored        string `json:"stored"`
			PayloadSha256 string `json:"payload_sha256"`
		}{Name: name, Stored: hex.EncodeToString(stored.Bytes), PayloadSha256: hex.EncodeToString(payloadSha256[:])})
	}
	return vectors
}

// The file's bytes are what the builder makes of the same inputs today, and each stored action parses and hashes to
// its payload_sha256.
func TestCanonicalActionVectors(t *testing.T) {
	if *updateCanonicalActionVectors {
		encoded, err := json.MarshalIndent(testComputeCanonicalActionVectors(t), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(testCanonicalActionVectorsPath, append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := os.ReadFile(testCanonicalActionVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	vectors := &testCanonicalActionVectors{}
	if err := json.Unmarshal(encoded, vectors); err != nil {
		t.Fatal(err)
	}
	computed := testComputeCanonicalActionVectors(t)
	if len(vectors.Actions) != len(computed.Actions) {
		t.Fatalf("%d vectors, %d kinds built", len(vectors.Actions), len(computed.Actions))
	}
	for i, vector := range vectors.Actions {
		if vector != computed.Actions[i] {
			t.Errorf("%s: the builder now makes %s", vector.Name, computed.Actions[i].Stored)
		}
		stored, err := ParseStoredCanonicalAction(testRecordHex(t, vector.Stored))
		if err != nil {
			t.Errorf("%s: %v", vector.Name, err)
			continue
		}
		if payloadSha256 := stored.PayloadSha256(); hex.EncodeToString(payloadSha256[:]) != vector.PayloadSha256 {
			t.Errorf("%s: payload_sha256 %x", vector.Name, payloadSha256)
		}
	}
}

// Any bytes as a CanonicalAction: the builder never panics, and an action it answers sets no field outside its kind's
// row and parses as the verifiers take it.
func FuzzCanonicalActionBuild(f *testing.F) {
	for _, action := range testBuildableActions() {
		encoded, err := proto.Marshal(action)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(encoded)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		action := &protocol.CanonicalAction{}
		if proto.Unmarshal(encoded, action) != nil {
			return
		}
		stored, err := NewCanonicalAction(action)
		if err != nil {
			return
		}
		row, ok := CanonicalActionFields(SidecarActionKind(stored.Action.GetKind()))
		if !ok {
			t.Fatalf("built kind %d", stored.Action.GetKind())
		}
		for _, dst := range stored.Action.GetGrantDst() {
			if !canonicalActionGrantDstClear(dst) {
				t.Errorf("built a clear grant_dst naming a prefix or a port on kind %d", stored.Action.GetKind())
			}
		}
		stored.Action.ProtoReflect().Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
			if !row.allows(field.Number(), stored.Action.GetVersion()) {
				t.Errorf("built field %d on kind %d", field.Number(), stored.Action.GetKind())
			}
			return true
		})
		if _, err := ParseStoredCanonicalAction(stored.Bytes); err != nil {
			t.Errorf("built bytes do not parse: %v", err)
		}
	})
}
