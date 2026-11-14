//go:build !ios_extension

// QD-740's sealed form (record_action_detail.go): each kind's clear bytes hold no port or prefix; a detail round-trips
// under its seal and is held to its action; and a version-3 access request's port rides sealed. QD-771's binding: a
// detail is sealed beside its action's own clear fields, its context derived from the stored bytes alone, so it opens
// beside those fields and in that network and beside no other. How a request binds its local port, weight and ALPNs,
// and how an approver and a spender treat a sealed grant, are record_approval_detail_test.go's; section 20's detail
// vectors are record_hash_test.go's and record_action_detail_vectors_test.go's. Synthetic values only.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// An approver's device in a network that holds the test key's generations.
type testActionDetailOpener struct {
	generations []uint64
	networkId   Id
}

func newTestActionDetailOpener(generations ...uint64) *testActionDetailOpener {
	return &testActionDetailOpener{generations: generations, networkId: testActionDetailNetworkId()}
}

func (self *testActionDetailOpener) OpenActionDetail(action *StoredCanonicalAction) (*protocol.CanonicalActionDetail, error) {
	return OpenCanonicalActionDetail(action, self.networkId, func(generation uint64) *EvsRepoKey {
		if !slices.Contains(self.generations, generation) {
			return nil
		}
		return testConfigSealKey(generation)
	})
}

// A daemon's device that seals a grant's detail as Sidecar.SealActionDetail does: under the test key's generation, in
// the test's network.
type testActionDetailSealer struct{}

func (self testActionDetailSealer) SealActionDetail(ctx context.Context, clear *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail) (*StoredCanonicalAction, error) {
	return NewSealedCanonicalAction(clear, detail, testConfigSealKey(testActionDetailGeneration), testActionDetailNetworkId(), nil)
}

// The test's forward, built as a daemon builds it: its clear fields, then its detail sealed beside them.
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
		testActionDetailNetworkId(), testActionDetailRandom())
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// The test's version-3 access request as stored, its detail sealed beside its clear fields, parsed as a build that
// knows version 3 parses it.
func testSealedAccessRequest(t *testing.T) *StoredCanonicalAction {
	t.Helper()
	stored, err := parseStoredCanonicalAction(testRecordStored(t, testRecordAccessRequestAction()), testRecordVersionsKnown(1, 3, 4))
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// stored's tag-and-value records, top level, in the order written. Here rather than record_hash_test.go's
// testRecordFields, which the js legs leave out with the file.
func testWireRecords(t *testing.T, stored []byte) [][]byte {
	t.Helper()
	records := [][]byte{}
	for 0 < len(stored) {
		number, wireType, tagByteCount := protowire.ConsumeTag(stored)
		if tagByteCount < 0 {
			t.Fatal(protowire.ParseError(tagByteCount))
		}
		valueByteCount := protowire.ConsumeFieldValue(number, wireType, stored[tagByteCount:])
		if valueByteCount < 0 {
			t.Fatal(protowire.ParseError(valueByteCount))
		}
		records = append(records, stored[:tagByteCount+valueByteCount])
		stored = stored[tagByteCount+valueByteCount:]
	}
	return records
}

// The field numbers on stored's wire, top level, in the order written.
func testWireFieldNumbers(t *testing.T, stored []byte) []protowire.Number {
	t.Helper()
	numbers := []protowire.Number{}
	for _, record := range testWireRecords(t, stored) {
		number, _, _ := protowire.ConsumeTag(record)
		numbers = append(numbers, number)
	}
	return numbers
}

// stored's tag-and-value records cut in two: every one but field 38's, in the order written, and field 38's.
func testCutDetailRecords(t *testing.T, stored []byte) ([]byte, [][]byte) {
	t.Helper()
	clear := []byte{}
	detailRecords := [][]byte{}
	for _, record := range testWireRecords(t, stored) {
		if number, _, _ := protowire.ConsumeTag(record); number == canonicalActionFieldSealedDetail {
			detailRecords = append(detailRecords, record)
			continue
		}
		clear = append(clear, record...)
	}
	return clear, detailRecords
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

// A detail opens to what was sealed, under the generation it names, in its network and under SIGNED_GRANT_ACTIVATE,
// and to nothing else.
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
	if _, err := OpenCanonicalActionDetail(stored, testActionDetailNetworkId(), nil); !errors.Is(err, ErrConfigSealGenerationMissing) {
		t.Errorf("a device holding no generation: %v", err)
	}
	elsewhere := newTestActionDetailOpener(testActionDetailGeneration)
	elsewhere.networkId = testConfigId("another network")
	if _, err := elsewhere.OpenActionDetail(stored); !errors.Is(err, ErrConfigSealInvalid) {
		t.Errorf("another network: %v", err)
	}
	// sealed under another signed type, with this action's own nonce and network, it opens under none
	otherTypeContext, err := CanonicalActionDetailSealContext(testActionDetailNetworkId(), stored.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if otherTypeContext.SignedType != bridge.SignedType_SIGNED_GRANT_ACTIVATE {
		t.Errorf("the derived context's type is %s", otherTypeContext.SignedType)
	}
	otherTypeContext.SignedType = bridge.SignedType_SIGNED_INDEXER_SET
	otherType := proto.Clone(stored.Action).(*protocol.CanonicalAction)
	if otherType.SealedDetail, err = SealConfigBody(testConfigSealKey(testActionDetailGeneration), otherTypeContext, testForwardDetail(), nil); err != nil {
		t.Fatal(err)
	}
	carried, err := NewCanonicalAction(otherType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newTestActionDetailOpener(testActionDetailGeneration).OpenActionDetail(carried); !errors.Is(err, ErrConfigSealInvalid) {
		t.Errorf("another signed type: %v", err)
	}
	// an action with no detail opens to none
	plain := buildTestAction(t, testBuildableActions()["dns_set"])
	if detail, err := newTestActionDetailOpener(testActionDetailGeneration).OpenActionDetail(plain); err != nil || detail != nil {
		t.Errorf("an action with no detail: %+v, %v", detail, err)
	}
	// two seals of one detail differ, each naming its own nonce
	clear := proto.Clone(testBuildableActions()["bridge_forward"]).(*protocol.CanonicalAction)
	clear.SealedDetail = nil
	fresh, err := NewSealedCanonicalAction(clear, testForwardDetail(), testConfigSealKey(testActionDetailGeneration), testActionDetailNetworkId(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(fresh.Bytes, stored.Bytes) {
		t.Error("a random nonce gave the fixed one's bytes")
	}
	if _, err := NewSealedCanonicalAction(fresh.Action, testForwardDetail(), testConfigSealKey(testActionDetailGeneration), testActionDetailNetworkId(), nil); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("sealing a sealed action: %v", err)
	}
	if _, err := NewSealedCanonicalAction(clear, testForwardDetail(), testConfigSealKey(testActionDetailGeneration), Id{}, nil); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("sealing in no network: %v", err)
	}
}

// The context is the action's own (QD-771): SIGNED_GRANT_ACTIVATE, the network, and the first 16 bytes of SHA-256 over
// the stored bytes with the field-38 record cut out, every other byte as stored, which for the builder's bytes is the
// clear fields' deterministic encoding. With or without its detail, and wherever the detail's record stands, an action
// derives one context; its clear fields reordered derive another, since nothing is re-encoded; and bytes that are not
// the wire format, a detail stored twice and a zero network derive none.
func TestCanonicalActionDetailSealContextIsTheClearFieldsAsStored(t *testing.T) {
	networkId := testActionDetailNetworkId()
	for name, stored := range map[string]*StoredCanonicalAction{
		"version 4": testSealedForward(t), "version 3": testSealedAccessRequest(t),
	} {
		clear, detailRecords := testCutDetailRecords(t, stored.Bytes)
		if len(detailRecords) != 1 {
			t.Fatalf("%s: %d detail records", name, len(detailRecords))
		}
		clearSha256 := sha256.Sum256(clear)
		derived, err := CanonicalActionDetailSealContext(networkId, stored.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if derived.SignedType != bridge.SignedType_SIGNED_GRANT_ACTIVATE || !bytes.Equal(derived.NetworkId, networkId.Bytes()) ||
			!bytes.Equal(derived.Nonce, clearSha256[:16]) {
			t.Errorf("%s: the derived context %+v", name, derived)
		}
		// the builder writes the clear fields in number order and the detail after them
		clearAction := proto.Clone(stored.Action).(*protocol.CanonicalAction)
		clearAction.SealedDetail = nil
		if !bytes.Equal(clear, testRecordStored(t, clearAction)) || !bytes.HasSuffix(stored.Bytes, detailRecords[0]) {
			t.Errorf("%s: the stored bytes are not the clear fields' encoding and the detail after them", name)
		}
		// a daemon derives from the clear bytes alone before it seals; a detail written first derives the same
		for what, bytesOf := range map[string][]byte{
			"the clear bytes":          clear,
			"the detail written first": slices.Concat(detailRecords[0], clear),
		} {
			again, err := CanonicalActionDetailSealContext(networkId, bytesOf)
			if err != nil || !bytes.Equal(again.Nonce, derived.Nonce) {
				t.Errorf("%s, %s: %+v, %v", name, what, again, err)
			}
		}
		// the same clear fields reordered, the first two swapped: protobuf reads them alike, and they derive another
		// nonce
		records := testWireRecords(t, stored.Bytes)
		records[0], records[1] = records[1], records[0]
		if reordered, err := CanonicalActionDetailSealContext(networkId, bytes.Join(records, nil)); err != nil || bytes.Equal(reordered.Nonce, derived.Nonce) {
			t.Errorf("%s: the clear fields reordered derive %+v, %v", name, reordered, err)
		}
		for what, bytesOf := range map[string][]byte{
			"a detail stored twice": slices.Concat(stored.Bytes, detailRecords[0]),
			"bytes cut short":       stored.Bytes[:len(stored.Bytes)-1],
			"a tag of field 0":      slices.Concat(stored.Bytes, []byte{0x00}),
		} {
			if _, err := CanonicalActionDetailSealContext(networkId, bytesOf); !errors.Is(err, ErrCanonicalActionInvalid) {
				t.Errorf("%s, %s: %v", name, what, err)
			}
		}
		if _, err := CanonicalActionDetailSealContext(Id{}, stored.Bytes); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("%s in no network: %v", name, err)
		}
	}
}

// A detail opens beside the clear fields it was sealed with, and beside no action that differs in one bound field:
// subject, rule, destination, expiry, allow, scope, kind and version, and for version 3 its repo and target, nor in
// another network. Each altered action a parser takes is refused by the AEAD before the detail's own check, which a
// destination added beside the detail's would pass; one at another kind or version, which no parser takes beside the
// detail's version, is refused by the AEAD as well, so the binding does not rest on the parsers alone.
func TestCanonicalActionDetailOpensBesideItsOwnClearFieldsAlone(t *testing.T) {
	known := testRecordVersionsKnown(1, 3, 4)
	opener := newTestActionDetailOpener(testActionDetailGeneration)
	other := "sidecar:6162636465666768696a6b6c6d6e6f70"
	elsewhere := newTestActionDetailOpener(testActionDetailGeneration)
	elsewhere.networkId = testConfigId("another network")
	cases := map[string]struct {
		stored  *StoredCanonicalAction
		detail  *protocol.CanonicalActionDetail
		changes map[string]func(action *protocol.CanonicalAction)
		// a kind and a version no parser takes beside this one's detail
		otherKind    SidecarActionKind
		otherVersion uint32
	}{
		"version 4": {
			stored: testSealedForward(t), detail: testForwardDetail(),
			changes: map[string]func(action *protocol.CanonicalAction){
				"subject":            func(action *protocol.CanonicalAction) { action.Subject = bytes.Repeat([]byte{0x57}, 16) },
				"rule":               func(action *protocol.CanonicalAction) { action.RuleId = bytes.Repeat([]byte{0x56}, 16) },
				"destination":        func(action *protocol.CanonicalAction) { action.GrantDst = []string{other} },
				"destination beside": func(action *protocol.CanonicalAction) { action.GrantDst = append(action.GrantDst, other) },
				"expiry":             func(action *protocol.CanonicalAction) { action.ExpiresMillis += 1 },
				"allow":              func(action *protocol.CanonicalAction) { action.GrantAllow = []string{"route"} },
				"scope":              func(action *protocol.CanonicalAction) { action.Scope = true },
			},
			otherKind: SidecarActionAccessRequest, otherVersion: canonicalActionVersionAccessRequest,
		},
		"version 3": {
			stored: testSealedAccessRequest(t), detail: testRecordAccessRequestDetail(),
			changes: map[string]func(action *protocol.CanonicalAction){
				"subject":            func(action *protocol.CanonicalAction) { action.Subject = bytes.Repeat([]byte{0x57}, 16) },
				"repo":               func(action *protocol.CanonicalAction) { action.RepoId = bytes.Repeat([]byte{0x56}, 16) },
				"target":             func(action *protocol.CanonicalAction) { action.TargetSidecarId = bytes.Repeat([]byte{0x55}, 16) },
				"destination":        func(action *protocol.CanonicalAction) { action.GrantDst = []string{other} },
				"destination beside": func(action *protocol.CanonicalAction) { action.GrantDst = append(action.GrantDst, other) },
				"expiry":             func(action *protocol.CanonicalAction) { action.ExpiresMillis += 1 },
				"allow":              func(action *protocol.CanonicalAction) { action.GrantAllow = []string{"read"} },
				"scope":              func(action *protocol.CanonicalAction) { action.Scope = true },
			},
			otherKind: SidecarActionForward, otherVersion: canonicalActionVersionSealedGrant,
		},
	}
	for name, c := range cases {
		opened, err := opener.OpenActionDetail(c.stored)
		if err != nil || !proto.Equal(opened, c.detail) {
			t.Errorf("%s beside its own clear fields: %+v, %v", name, opened, err)
		}
		if _, err := elsewhere.OpenActionDetail(c.stored); !errors.Is(err, ErrConfigSealInvalid) {
			t.Errorf("%s in another network: %v", name, err)
		}
		for field, change := range c.changes {
			altered := proto.Clone(c.stored.Action).(*protocol.CanonicalAction)
			change(altered)
			parsed, err := parseStoredCanonicalAction(testRecordStored(t, altered), known)
			if err != nil {
				t.Fatalf("%s, another %s: the parse refused it, %v", name, field, err)
			}
			if _, err := opener.OpenActionDetail(parsed); !errors.Is(err, ErrConfigSealInvalid) {
				t.Errorf("%s beside another %s: %v", name, field, err)
			}
		}
		for field, change := range map[string]func(action *protocol.CanonicalAction){
			"kind":    func(action *protocol.CanonicalAction) { action.Kind = uint32(c.otherKind) },
			"version": func(action *protocol.CanonicalAction) { action.Version = c.otherVersion },
		} {
			altered := proto.Clone(c.stored.Action).(*protocol.CanonicalAction)
			change(altered)
			alteredBytes := testRecordStored(t, altered)
			if _, err := parseStoredCanonicalAction(alteredBytes, known); err == nil {
				t.Errorf("%s at another %s: a parser took it", name, field)
			}
			unparsed := &StoredCanonicalAction{Action: altered, Bytes: alteredBytes}
			if _, err := opener.OpenActionDetail(unparsed); !errors.Is(err, ErrConfigSealInvalid) {
				t.Errorf("%s beside another %s: %v", name, field, err)
			}
		}
	}
}

// A detail is held to its action: it holds something, its port is one, its prefixes read in one form, its
// destinations each name a port or a prefix, and a sidecar it names a port of is one the clear grant_dst names; a
// detail sealed beside an action it is not held to is refused where it is opened, after its AEAD passes.
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
	if _, err := NewSealedCanonicalAction(clear, stray, testConfigSealKey(testActionDetailGeneration), testActionDetailNetworkId(), nil); !errors.Is(err, ErrCanonicalActionDetailInvalid) {
		t.Errorf("another sidecar's port: %v", err)
	}
	// and one a device sealed beside this action's own fields though it names another sidecar's port opens, and is
	// refused there
	strayed, err := NewCanonicalAction(testWithSealedDetail(proto.Clone(clear).(*protocol.CanonicalAction), stray))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newTestActionDetailOpener(testActionDetailGeneration).OpenActionDetail(strayed); !errors.Is(err, ErrCanonicalActionDetailInvalid) {
		t.Errorf("a detail not held to the action it is sealed beside: %v", err)
	}
	// a sealed body that holds no detail at all
	hollow, err := NewCanonicalAction(testWithSealedDetail(proto.Clone(clear).(*protocol.CanonicalAction), &protocol.CanonicalActionDetail{}))
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
	stored, err := newSealedCanonicalAction(clear, testRecordAccessRequestDetail(), testConfigSealKey(testActionDetailGeneration),
		testActionDetailNetworkId(), testActionDetailRandom(), known)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Action.GetVersion() != 3 || stored.Action.GetTargetPort() != 0 || len(stored.Action.GetSealedDetail()) == 0 ||
		!slices.Equal(stored.Action.GetGrantDst(), []string{testRecordWorkerDst}) {
		t.Errorf("the stored access request: %+v", stored.Action)
	}
	if !bytes.Equal(stored.Bytes, testSealedAccessRequest(t).Bytes) {
		t.Error("the sealed builder and the test's fixture differ on one access request")
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
		testActionDetailNetworkId(), testActionDetailRandom(), known); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a clear target_port: %v", err)
	}
	texted := proto.Clone(clear).(*protocol.CanonicalAction)
	texted.GrantDst = []string{testRecordWorkerDst + ":tcp:22"}
	if _, err := newSealedCanonicalAction(texted, testRecordAccessRequestDetail(), testConfigSealKey(testActionDetailGeneration),
		testActionDetailNetworkId(), testActionDetailRandom(), known); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("clear port text: %v", err)
	}
	numbered.Version, numbered.SealedDetail = 3, stored.Action.GetSealedDetail()
	if _, err := parseStoredCanonicalAction(testRecordStored(t, numbered), known); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a stored clear target_port: %v", err)
	}
	// this build's approvers do not know version 3 yet
	if _, err := NewSealedCanonicalAction(clear, testRecordAccessRequestDetail(), testConfigSealKey(testActionDetailGeneration),
		testActionDetailNetworkId(), testActionDetailRandom()); !errors.Is(err, ErrCanonicalActionVersionUnknown) {
		t.Errorf("version 3 in production: %v", err)
	}
	if _, err := ParseStoredCanonicalAction(stored.Bytes); !errors.Is(err, ErrCanonicalActionVersionUnknown) {
		t.Errorf("version 3 parsed in production: %v", err)
	}
}
