// The compiler's golden states at the device role (bridge_compile_test.go writes them): every state the compile gives
// in testdata/bridge/compile/ is one device.ParseBridgeRules takes whole, since a row it refuses refuses the state, and
// whose digest is its bytes'. An external test, so the root links no device/ (§4.4) while the two are checked against
// each other.

package sidecar_test

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

//go:embed testdata/bridge/compile
var bridgeCompileGoldenFiles embed.FS

func TestCompiledGoldenStatesParseAtTheDeviceRole(t *testing.T) {
	data, err := bridgeCompileGoldenFiles.ReadFile("testdata/bridge/compile/states.json")
	if err != nil {
		t.Fatal(err)
	}
	vectors := map[string]struct {
		Digest string `json:"digest"`
		State  string `json:"state"`
	}{}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no golden state")
	}
	for name, vector := range vectors {
		stateBytes, err := hex.DecodeString(vector.State)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if digest := sha256.Sum256(stateBytes); hex.EncodeToString(digest[:]) != vector.Digest {
			t.Errorf("%s: the digest is not the state's bytes'", name)
		}
		state := &bridge.BridgeState{}
		if err := proto.Unmarshal(stateBytes, state); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		rules, err := device.ParseBridgeRules(state.GetRules(), nil)
		if err != nil {
			t.Errorf("%s: the device role refuses the compiled rules: %v", name, err)
			continue
		}
		if rules.GetBlock() == nil || len(rules.GetEntries()) == 0 || len(rules.GetSubjects()) == 0 {
			t.Errorf("%s: rules with no block, entry or subject: %v", name, rules)
		}
	}
}
