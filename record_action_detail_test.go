//go:build !ios_extension

// QD-740's sealed form (record_action_detail.go): each kind's clear bytes hold no port or prefix; a detail round-trips
// under its seal and is held to its action; and a version-3 access request's port rides sealed. How a request binds
// its local port, weight and ALPNs, and how an approver and a spender treat a sealed grant, are
// record_approval_detail_test.go's. Synthetic values only.

package sidecar

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// An approver's device that holds the test key's generations.
type testActionDetailOpener struct {
	generations []uint64
	context     *ConfigSealContext
}

func newTestActionDetailOpener(generations ...uint64) *testActionDetailOpener {
	return &testActionDetailOpener{generations: generations, context: testActionDetailContext()}
}

func (self *testActionDetailOpener) OpenActionDetail(action *StoredCanonicalAction) (*protocol.CanonicalActionDetail, error) {
	return OpenCanonicalActionDetail(action, self.context, func(generation uint64) *EvsRepoKey {
		if !slices.Contains(self.generations, generation) {
			return nil
		}
		return testConfigSealKey(generation)
	})
}

// The test's forward, built as a daemon builds it: its clear fields and its detail, sealed.
func testSealedForward(t *testing.T) *StoredCanonicalAction {
	t.Helper()
	return testSealedForwardExpiring(t, testBuildableActions()["bridge_forward"].GetExpiresMillis())
}

// testSealedForward, its grant expiring at expiresMs.
func testSealedForwardExpiring(t *testing.T, expiresMs int64) *StoredCanonicalAction {
	t.Helper()
	clear := proto.Clone(testBuildableActions()["bridge_forward"]).(*protocol.CanonicalAction)
	clear.SealedDetail = nil
	clear.ExpiresMillis = expiresMs
	stored, err := NewSealedCanonicalAction(clear, testForwardDetail(), testConfigSealKey(testActionDetailGeneration),
		testActionDetailContext(), bytes.NewReader(bytes.Repeat([]byte{0x24}, 24)))
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// The field numbers on stored's wire, top level, in the order written.
func testWireFieldNumbers(t *testing.T, stored []byte) []protowire.Number {
	t.Helper()
	numbers := []protowire.Number{}
	for 0 < len(stored) {
		number, wireType, tagByteCount := protowire.ConsumeTag(stored)
		if tagByteCount < 0 {
			t.Fatal(protowire.ParseError(tagByteCount))
		}
		valueByteCount := protowire.ConsumeFieldValue(number, wireType, stored[tagByteCount:])
		if valueByteCount < 0 {
			t.Fatal(protowire.ParseError(valueByteCount))
		}
		numbers = append(numbers, number)
		stored = stored[tagByteCount+valueByteCount:]
	}
	return numbers
}

// Each kind's clear bytes hold no port or prefix: no action carries local_port's, weight's or alpn's old numbers; an
// action a server may see carries no cidrs and no target_port, and its grant_dst names subjects alone; a sealed
// action's bytes hold its detail nowhere in the clear; and the builder refuses a grant_dst naming a port or a prefix
// on every kind that takes one.
func TestEveryKindsClearBytesHoldNoPortOrPrefix(t *testing.T) {
	known := testRecordVersionsKnown(1, 3, 4)
	actions := testBuildableActions()
	actions["access_request"] = testRecordAccessRequestAction()
	for name, action := range actions {
		stored, err := newCanonicalAction(action, known)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		numbers := testWireFieldNumbers(t, stored.Bytes)
		for _, left := range []protowire.Number{24, 25, 34} {
			if slices.Contains(numbers, left) {
				t.Errorf("%s carries field %d, which left CanonicalAction", name, left)
			}
		}
		row, _ := CanonicalActionFields(SidecarActionKind(stored.Action.GetKind()))
		if len(row.Server) == 0 {
			// no server path takes it: CheckCanonicalActionForServer refuses the kind whole
			if err := CheckCanonicalActionForServer(stored); !errors.Is(err, ErrCanonicalActionInvalid) {
				t.Errorf("%s on a server path: %v", name, err)
			}
			continue
		}
		for _, clear := range []protowire.Number{9, 27} {
			if slices.Contains(numbers, clear) {
				t.Errorf("%s shows a server field %d", name, clear)
			}
		}
		for _, dst := range stored.Action.GetGrantDst() {
			if !canonicalActionGrantDstClear(dst) {
				t.Errorf("%s: a clear grant_dst names a prefix or a port", name)
			}
		}
		for _, text := range []string{":tcp:", ":udp:", "ip:", "/24"} {
			if bytes.Contains(stored.Bytes, []byte(text)) {
				t.Errorf("%s: the stored bytes hold %q", name, text)
			}
		}
		if row.allows(canonicalActionFieldGrantDst, stored.Action.GetVersion()) {
			for _, dst := range []string{testActionTargetDst + ":tcp:8443", testActionTargetDst + ":udp:53", "ip:192.0.2.0/24", "ip:2001:db8::/32"} {
				widened := proto.Clone(action).(*protocol.CanonicalAction)
				widened.GrantDst = append(widened.GrantDst, dst)
				if _, err := newCanonicalAction(widened, known); !errors.Is(err, ErrCanonicalActionInvalid) {
					t.Errorf("%s with a clear grant_dst of a port or a prefix answered %v", name, err)
				}
			}
		}
	}
	// what the forward and the access request seal shows nowhere in their bytes
	for name, detail := range map[string]*protocol.CanonicalActionDetail{
		"bridge_forward": testForwardDetail(), "access_request": testRecordAccessRequestDetail(),
	} {
		stored, err := newCanonicalAction(actions[name], known)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(stored.Bytes, testRecordStored(t, detail)) {
			t.Errorf("%s: the detail shows in the clear", name)
		}
		if stored.Action.GetTargetPort() != 0 || len(stored.Action.GetCidrs()) != 0 {
			t.Errorf("%s: a clear port or prefix", name)
		}
	}
	// a publish or a listen an older builder made, a prefix or a target's port beside its grant, parses and reaches no
	// server
	for _, name := range []string{"tls_publish", "socket_listen"} {
		for _, widen := range []func(action *protocol.CanonicalAction){
			func(action *protocol.CanonicalAction) { action.Cidrs = []string{"192.0.2.0/24"} },
			func(action *protocol.CanonicalAction) { action.TargetPort = 8443 },
		} {
			action := proto.Clone(actions[name]).(*protocol.CanonicalAction)
			action.Version = 1
			widen(action)
			parsed, err := ParseStoredCanonicalAction(testRecordStored(t, action))
			if err != nil {
				t.Fatal(err)
			}
			if err := CheckCanonicalActionForServer(parsed); !errors.Is(err, ErrCanonicalActionInvalid) {
				t.Errorf("%s with a prefix or a port on a server path: %v", name, err)
			}
		}
	}
}

// A detail opens to what was sealed, under the generation it names and what it was sealed to, and to nothing else.
func TestCanonicalActionDetailRoundTrip(t *testing.T) {
	stored := testSealedForward(t)
	if !bytes.Equal(stored.Bytes, buildTestAction(t, testBuildableActions()["bridge_forward"]).Bytes) {
		t.Error("the sealed builder and the plain one differ on one action")
	}
	if generation, err := ConfigSealedGeneration(stored.Action.GetSealedDetail()); err != nil || generation != testActionDetailGeneration {
		t.Errorf("generation %d: %v", generation, err)
	}
	detail, err := newTestActionDetailOpener(testActionDetailGeneration).OpenActionDetail(stored)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(detail, testForwardDetail()) {
		t.Errorf("opened %+v", detail)
	}
	if _, err := newTestActionDetailOpener(1, 2).OpenActionDetail(stored); !errors.Is(err, ErrConfigSealGenerationMissing) {
		t.Errorf("a device without the generation: %v", err)
	}
	elsewhere := newTestActionDetailOpener(testActionDetailGeneration)
	elsewhere.context.NetworkId = testConfigId("another network").Bytes()
	if _, err := elsewhere.OpenActionDetail(stored); !errors.Is(err, ErrConfigSealInvalid) {
		t.Errorf("another network's context: %v", err)
	}
	otherType := newTestActionDetailOpener(testActionDetailGeneration)
	otherType.context.SignedType = bridge.SignedType_SIGNED_INDEXER_SET
	if _, err := otherType.OpenActionDetail(stored); !errors.Is(err, ErrConfigSealInvalid) {
		t.Errorf("another signed type's context: %v", err)
	}
	// an action with no detail opens to none
	plain := buildTestAction(t, testBuildableActions()["dns_set"])
	if detail, err := newTestActionDetailOpener(testActionDetailGeneration).OpenActionDetail(plain); err != nil || detail != nil {
		t.Errorf("an action with no detail: %+v, %v", detail, err)
	}
	// two seals of one detail differ, each naming its own nonce
	clear := proto.Clone(testBuildableActions()["bridge_forward"]).(*protocol.CanonicalAction)
	clear.SealedDetail = nil
	fresh, err := NewSealedCanonicalAction(clear, testForwardDetail(), testConfigSealKey(testActionDetailGeneration), testActionDetailContext(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(fresh.Bytes, stored.Bytes) {
		t.Error("a random nonce gave the fixed one's bytes")
	}
	if _, err := NewSealedCanonicalAction(fresh.Action, testForwardDetail(), testConfigSealKey(testActionDetailGeneration), testActionDetailContext(), nil); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("sealing a sealed action: %v", err)
	}
}

// A detail is held to its action: it holds something, its port is one, its prefixes read in one form, its
// destinations each name a port or a prefix, and a sidecar it names a port of is one the clear grant_dst names; a
// detail sealed for one action and carried by another is refused where it is opened.
func TestCanonicalActionDetailHeldToItsAction(t *testing.T) {
	action := testBuildableActions()["bridge_forward"]
	other := "sidecar:6162636465666768696a6b6c6d6e6f70"
	good := []*protocol.CanonicalActionDetail{
		testForwardDetail(),
		{TargetPort: 65535},
		{Cidrs: []string{"192.0.2.0/24", "2001:db8::/32"}},
		{GrantDst: []string{"ip:198.51.100.0/24", testActionTargetDst + ":udp:53"}},
	}
	for i, detail := range good {
		if err := CheckCanonicalActionDetail(action, detail); err != nil {
			t.Errorf("detail %d: %v", i, err)
		}
	}
	unknown := testForwardDetail()
	unknown.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 9, protowire.VarintType), 1))
	bad := map[string]*protocol.CanonicalActionDetail{
		"none":                    nil,
		"empty":                   {},
		"a port past 65535":       {TargetPort: 65536},
		"host bits":               {Cidrs: []string{"192.0.2.1/24"}},
		"an address":              {Cidrs: []string{"192.0.2.1"}},
		"a second form":           {Cidrs: []string{"192.000.2.0/24"}},
		"a subject alone":         {GrantDst: []string{testActionTargetDst}},
		"a name":                  {GrantDst: []string{"dns:blog.example"}},
		"a prefix that is none":   {GrantDst: []string{"ip:not-a-prefix"}},
		"a port that is none":     {GrantDst: []string{testActionTargetDst + ":tcp:0"}},
		"a protocol that is none": {GrantDst: []string{testActionTargetDst + ":sctp:22"}},
		"another sidecar's port":  {GrantDst: []string{other + ":tcp:22"}},
		"an unknown field":        unknown,
	}
	for name, detail := range bad {
		if err := CheckCanonicalActionDetail(action, detail); !errors.Is(err, ErrCanonicalActionDetailInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// the refusal names no prefix or port, since a log may carry it (I-13)
	err := CheckCanonicalActionDetail(action, &protocol.CanonicalActionDetail{Cidrs: []string{"203.0.113.77/24"}})
	if err == nil || strings.Contains(err.Error(), "203.0.113") {
		t.Errorf("the refusal: %v", err)
	}
	// the builder refuses a detail that is not its action's, before it seals
	clear := proto.Clone(action).(*protocol.CanonicalAction)
	clear.SealedDetail = nil
	stray := &protocol.CanonicalActionDetail{GrantDst: []string{other + ":tcp:22"}}
	if _, err := NewSealedCanonicalAction(clear, stray, testConfigSealKey(testActionDetailGeneration), testActionDetailContext(), nil); !errors.Is(err, ErrCanonicalActionDetailInvalid) {
		t.Errorf("another sidecar's port: %v", err)
	}
	// and one sealed well for another action, then carried by this one, is refused where it is opened
	moved := proto.Clone(action).(*protocol.CanonicalAction)
	moved.SealedDetail = testSealActionDetail(stray)
	carried, err := NewCanonicalAction(moved)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newTestActionDetailOpener(testActionDetailGeneration).OpenActionDetail(carried); !errors.Is(err, ErrCanonicalActionDetailInvalid) {
		t.Errorf("a detail carried by another action: %v", err)
	}
	// a sealed body that holds no detail at all
	empty := proto.Clone(action).(*protocol.CanonicalAction)
	empty.SealedDetail = testSealActionDetail(&protocol.CanonicalActionDetail{})
	hollow, err := NewCanonicalAction(empty)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newTestActionDetailOpener(testActionDetailGeneration).OpenActionDetail(hollow); !errors.Is(err, ErrCanonicalActionDetailInvalid) {
		t.Errorf("an empty detail: %v", err)
	}
}

// A version-3 access request to a worker's port carries the port and its sidecar:<id>:tcp:<port> text in
// sealed_detail: its clear bytes name the worker alone, a server path takes them, and the port opens on a device that
// holds the key. Version 3 itself stays unknown until MCP-M6-01, so the production builder still refuses it.
func TestAccessRequestPortRidesSealed(t *testing.T) {
	known := testRecordVersionsKnown(1, 3, 4)
	clear := testRecordAccessRequestAction()
	clear.SealedDetail = nil
	random := func() *bytes.Reader {
		return bytes.NewReader(bytes.Repeat([]byte{0x24}, 24))
	}
	stored, err := newSealedCanonicalAction(clear, testRecordAccessRequestDetail(), testConfigSealKey(testActionDetailGeneration),
		testActionDetailContext(), random(), known)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Action.GetVersion() != 3 || stored.Action.GetTargetPort() != 0 || len(stored.Action.GetSealedDetail()) == 0 ||
		!slices.Equal(stored.Action.GetGrantDst(), []string{testRecordWorkerDst}) {
		t.Errorf("the stored access request: %+v", stored.Action)
	}
	if slices.Contains(testWireFieldNumbers(t, stored.Bytes), 27) || bytes.Contains(stored.Bytes, []byte(":tcp:")) {
		t.Error("the port shows in the clear")
	}
	if err := CheckCanonicalActionForServer(stored); err != nil {
		t.Errorf("a server path: %v", err)
	}
	detail, err := newTestActionDetailOpener(testActionDetailGeneration).OpenActionDetail(stored)
	if err != nil {
		t.Fatal(err)
	}
	if detail.GetTargetPort() != 22 || !slices.Equal(detail.GetGrantDst(), []string{testRecordWorkerDst + ":tcp:22"}) {
		t.Errorf("opened %+v", detail)
	}
	// the port in the clear, as a number or as text, is refused by the builder and by every parser
	numbered := proto.Clone(clear).(*protocol.CanonicalAction)
	numbered.TargetPort = 22
	if _, err := newSealedCanonicalAction(numbered, testRecordAccessRequestDetail(), testConfigSealKey(testActionDetailGeneration),
		testActionDetailContext(), random(), known); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a clear target_port: %v", err)
	}
	texted := proto.Clone(clear).(*protocol.CanonicalAction)
	texted.GrantDst = []string{testRecordWorkerDst + ":tcp:22"}
	if _, err := newSealedCanonicalAction(texted, testRecordAccessRequestDetail(), testConfigSealKey(testActionDetailGeneration),
		testActionDetailContext(), random(), known); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("clear port text: %v", err)
	}
	numbered.Version, numbered.SealedDetail = 3, stored.Action.GetSealedDetail()
	if _, err := parseStoredCanonicalAction(testRecordStored(t, numbered), known); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a stored clear target_port: %v", err)
	}
	// this build's approvers do not know version 3 yet
	if _, err := NewSealedCanonicalAction(clear, testRecordAccessRequestDetail(), testConfigSealKey(testActionDetailGeneration),
		testActionDetailContext(), random()); !errors.Is(err, ErrCanonicalActionVersionUnknown) {
		t.Errorf("version 3 in production: %v", err)
	}
	if _, err := ParseStoredCanonicalAction(stored.Bytes); !errors.Is(err, ErrCanonicalActionVersionUnknown) {
		t.Errorf("version 3 parsed in production: %v", err)
	}
}
