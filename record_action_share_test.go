//go:build !ios_extension

// CanonicalAction.share_network_id, field 40 (the owner's answer to acl-m6-03-share-grant-subject, QD-820), as every
// builder and parser holds it: a dial or route grant alone names it, a forward's at version 4, as one network's id;
// it follows the sealed detail on the wire and is bound into the detail's seal as every clear field is; a server path
// takes it; and an approver's render says which half of the share the action is. Synthetic values only.

package sidecar

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The other network a test's share names.
func testShareNetworkId() []byte {
	return bytes.Repeat([]byte{0x53}, 16)
}

// The test's forward as a share's inbound half, its clear fields alone.
func testShareForwardClear() *protocol.CanonicalAction {
	clear := proto.Clone(testBuildableActions()["bridge_forward"]).(*protocol.CanonicalAction)
	clear.SealedDetail = nil
	clear.ShareNetworkId = testShareNetworkId()
	return clear
}

// A share's forward builds, its network the last record on the wire, after the sealed detail, in the bytes field 40
// takes, and it parses, passes a server path, and opens its detail beside its own clear fields alone.
func TestCanonicalActionShareNetworkBuilds(t *testing.T) {
	stored, err := NewSealedCanonicalAction(testShareForwardClear(), testForwardDetail(), testConfigSealKey(testActionDetailGeneration),
		testActionDetailNetworkId(), testActionDetailRandom())
	if err != nil {
		t.Fatal(err)
	}
	// field 40, a length-delimited record of 16 bytes: tag 0xc2 0x02, length 0x10
	suffix := append([]byte{0xc2, 0x02, 0x10}, testShareNetworkId()...)
	if !bytes.HasSuffix(stored.Bytes, suffix) {
		t.Fatalf("the stored action does not end with field 40's record: %x", stored.Bytes[max(0, len(stored.Bytes)-24):])
	}
	numbers := testWireFieldNumbers(t, stored.Bytes)
	if count := len(numbers); count < 2 || numbers[count-1] != canonicalActionFieldShareNetworkId || numbers[count-2] != canonicalActionFieldSealedDetail {
		t.Errorf("the wire's fields %v", numbers)
	}
	if stored.Action.GetVersion() != canonicalActionVersionSealedGrant || !bytes.Equal(stored.Action.GetShareNetworkId(), testShareNetworkId()) {
		t.Errorf("the share as built: %+v", stored.Action)
	}
	parsed, err := ParseStoredCanonicalAction(stored.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckCanonicalActionForServer(parsed); err != nil {
		t.Errorf("a share on a server path: %v", err)
	}
	opener := newTestActionDetailOpener(testActionDetailGeneration)
	if detail, err := opener.OpenActionDetail(parsed); err != nil || !proto.Equal(detail, testForwardDetail()) {
		t.Errorf("the share's detail opened to %+v: %v", detail, err)
	}

	// the seal binds the network: the same detail beside another network, or beside none, opens nowhere
	for name, edit := range map[string]func(action *protocol.CanonicalAction){
		"another network": func(action *protocol.CanonicalAction) { action.ShareNetworkId = bytes.Repeat([]byte{0x54}, 16) },
		"no network":      func(action *protocol.CanonicalAction) { action.ShareNetworkId = nil },
	} {
		moved := proto.Clone(stored.Action).(*protocol.CanonicalAction)
		edit(moved)
		movedBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(moved)
		if err != nil {
			t.Fatal(err)
		}
		movedStored, err := ParseStoredCanonicalAction(movedBytes)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := opener.OpenActionDetail(movedStored); !errors.Is(err, ErrConfigSealInvalid) {
			t.Errorf("a detail beside %s: %v", name, err)
		}
	}

	// a forward with no network builds as it did, with no field 40 on its wire
	plain := testSealedForward(t)
	if numbers := testWireFieldNumbers(t, plain.Bytes); len(numbers) == 0 || numbers[len(numbers)-1] != protowire.Number(canonicalActionFieldSealedDetail) {
		t.Errorf("a forward that is no share: %v", numbers)
	}
}

// Only a dial or route grant names a share's network, and only as a network's id: the builder and every parser
// refuse it on another kind or version, at another size, and as zeros.
func TestCanonicalActionShareNetworkRefusals(t *testing.T) {
	seal := func(action *protocol.CanonicalAction) *protocol.CanonicalAction {
		return testWithSealedDetail(action, testForwardDetail())
	}
	short := testShareForwardClear()
	short.ShareNetworkId = short.ShareNetworkId[:15]
	zeros := testShareForwardClear()
	zeros.ShareNetworkId = make([]byte, 16)
	listen := proto.Clone(testBuildableActions()["socket_listen"]).(*protocol.CanonicalAction)
	listen.ShareNetworkId = testShareNetworkId()
	egress := proto.Clone(testBuildableActions()["egress_change"]).(*protocol.CanonicalAction)
	egress.ShareNetworkId = testShareNetworkId()
	cases := map[string]*protocol.CanonicalAction{
		"15 bytes":         seal(short),
		"zeros":            seal(zeros),
		"a listen":         listen,
		"an egress change": egress,
	}
	for name, action := range cases {
		if _, err := NewCanonicalAction(action); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("the builder, %s: %v", name, err)
		}
		// as no builder would write it
		if action.GetVersion() == 0 {
			action.Version = 1
			if SidecarActionKind(action.GetKind()) == SidecarActionForward {
				action.Version = canonicalActionVersionSealedGrant
			}
		}
		stored, err := proto.MarshalOptions{Deterministic: true}.Marshal(action)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseStoredCanonicalAction(stored); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("a parser, %s: %v", name, err)
		}
	}
	// a version-3 access request names none either
	request := proto.Clone(testRecordAccessRequestAction()).(*protocol.CanonicalAction)
	request.ShareNetworkId = testShareNetworkId()
	stored, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseStoredCanonicalAction(stored, testRecordVersionsKnown(1, 3, 4)); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("an access request naming a share's network: %v", err)
	}
}

// An approver reads which half of a share an action is, and the other network by id, before the fields themselves.
func TestApprovalRenderSaysAShare(t *testing.T) {
	network := strings.Repeat("53", 16)
	inbound := testShareForwardClear()
	if meaning := approvalRenderMeaning(inbound); !strings.Contains(meaning, "let network "+network+" reach "+testActionTargetDst) {
		t.Errorf("the inbound half: %q", meaning)
	}
	outbound := testShareForwardClear()
	outbound.GrantDst = []string{"network:" + network}
	if meaning := approvalRenderMeaning(outbound); !strings.Contains(meaning, "let sidecar "+strings.Repeat("47", 16)+" reach network "+network) {
		t.Errorf("the outbound half: %q", meaning)
	}
	plain := proto.Clone(testBuildableActions()["bridge_forward"]).(*protocol.CanonicalAction)
	if meaning := approvalRenderMeaning(plain); meaning != "" {
		t.Errorf("a forward that is no share: %q", meaning)
	}
}
