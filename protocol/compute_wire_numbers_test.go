// DESIGN-COMPUTE's wire numbers, reserved once (CARCH-M11-05, CONTRACTS C-25): the four MessageType values and the
// three SignedType values compute's areas planned in these two shared protos, so none of their tasks edits either file.
// Each owner builds its bodies and statements in its own .proto; until then a reader refuses the value as any it does
// not know, so reserving them early changes no behavior.

package protocol

import (
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The seven, as DESIGN-COMPUTE.md and the plan number them: Appendix D's §6.11 MessageType 0x19 row for the live ask
// (§26.8, LSTN), the enclave plan's reading beside SEARCH for the indexer enclave's evidence (§11.6, §11.10, ENC;
// compute-plan-enc-readings), and Appendix D's three SignedType values (§7.10 HARN, §2.8 CTRUST, §11.7 ENC).
var testComputeWireNumbers = []struct {
	enum   string
	name   string
	number int32
}{
	{enum: "urnetwork.sidecar.MessageType", name: "EVIDENCE", number: 0x1406},
	{enum: "urnetwork.sidecar.MessageType", name: "EVIDENCE_RESULT", number: 0x1407},
	{enum: "urnetwork.sidecar.MessageType", name: "LISTENERS", number: 0x1901},
	{enum: "urnetwork.sidecar.MessageType", name: "LISTENERS_RESULT", number: 0x1902},
	{enum: "urnetwork.sidecar.SignedType", name: "SIGNED_ATTACH_ORIGIN", number: 0x1808},
	{enum: "urnetwork.sidecar.SignedType", name: "SIGNED_DISCLOSURE_ACK", number: 0x1809},
	{enum: "urnetwork.sidecar.SignedType", name: "SIGNED_ENCLAVE_SETUP", number: 0x180A},
}

// The seven values as listed, each its number's only name, an RPC's result its request's value + 1, 0x1807 left
// untouched, and wire_lock.json holding each.
func TestComputeWireNumbers(t *testing.T) {
	names := map[string]map[int32]string{
		"urnetwork.sidecar.MessageType": MessageType_name,
		"urnetwork.sidecar.SignedType":  bridge.SignedType_name,
	}
	values := map[string]map[string]int32{
		"urnetwork.sidecar.MessageType": MessageType_value,
		"urnetwork.sidecar.SignedType":  bridge.SignedType_value,
	}
	for _, c := range testComputeWireNumbers {
		if number, ok := values[c.enum][c.name]; !ok || number != c.number {
			t.Errorf("%s.%s is %#x, declared %t, want %#x", c.enum, c.name, number, ok, c.number)
		}
		// a number protoc would let two names share only under allow_alias, which no registry here sets
		if name := names[c.enum][c.number]; name != c.name {
			t.Errorf("%#x in %s is %q, want %s", c.number, c.enum, name, c.name)
		}
	}
	if MessageType_EVIDENCE+1 != MessageType_EVIDENCE_RESULT || MessageType_LISTENERS+1 != MessageType_LISTENERS_RESULT {
		t.Error("an RPC's result is not its request's value + 1 (§6.11)")
	}
	if name, declared := bridge.SignedType_name[0x1807]; declared {
		t.Errorf("0x1807 is %s, which Appendix D leaves untouched", name)
	}

	locked := map[string]map[int32]string{}
	for _, enum := range testReadWireLock(t).Enums {
		locked[enum.Name] = map[int32]string{}
		for _, value := range enum.Values {
			locked[enum.Name][value.Number] = value.Name
		}
	}
	for _, c := range testComputeWireNumbers {
		if name := locked[c.enum][c.number]; name != c.name {
			t.Errorf("wire_lock.json holds %#x in %s as %q, want %s", c.number, c.enum, name, c.name)
		}
	}
}
