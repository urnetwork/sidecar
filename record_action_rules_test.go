// record_action_rules.go's rules: an approver refuses a CanonicalAction version it does not know (§22.5's §16 row),
// each version sets only what it may, and a push's entries order alike everywhere (§16.8's order row).

package sidecar

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// An action's stored bytes, as a daemon writes them.
func testRecordStored(t *testing.T, message proto.Message) []byte {
	t.Helper()
	stored, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// A dns_set action at version 1, the shape §12.8's gate takes.
func testRecordDnsAction() *protocol.CanonicalAction {
	return &protocol.CanonicalAction{
		Kind:          uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_DNS_SET),
		ExpiresMillis: 1762387200000,
		Version:       1,
		DnsName:       "www",
		DnsType:       "A",
		DnsValue:      "192.0.2.10",
		DnsTtl:        300,
	}
}

// A version-3 access_request, using only its fields.
func testRecordAccessRequestAction() *protocol.CanonicalAction {
	return &protocol.CanonicalAction{
		Kind:            uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_ACCESS_REQUEST),
		ExpiresMillis:   1762387200000,
		GrantDst:        []string{"sidecar:" + "0102030405060708090a0b0c0d0e0f10" + ":tcp:22"},
		GrantAllow:      []string{"dial"},
		Version:         3,
		RepoId:          bytes.Repeat([]byte{0x31}, 16),
		TargetSidecarId: bytes.Repeat([]byte{0x32}, 16),
		TargetPort:      22,
		Subject:         bytes.Repeat([]byte{0x33}, 16),
	}
}

// A known set for a test of a later version's rules.
func testRecordVersionsKnown(versions ...uint32) func(version uint32) bool {
	return func(version uint32) bool {
		return slices.Contains(versions, version)
	}
}

// §22.5's §16 row at M3: versions 0, 2, 3 and 4 are refused, and 1 parses.
func TestApproverRefusesUnknownVersion(t *testing.T) {
	for _, version := range []uint32{0, 2, 3, 4} {
		action := testRecordDnsAction()
		action.Version = version
		_, err := ParseStoredCanonicalAction(testRecordStored(t, action))
		if !errors.Is(err, ErrCanonicalActionVersionUnknown) {
			t.Errorf("version %d: %v", version, err)
		}
	}
	stored := testRecordStored(t, testRecordDnsAction())
	parsed, err := ParseStoredCanonicalAction(stored)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.Bytes, stored) || !proto.Equal(parsed.Action, testRecordDnsAction()) {
		t.Error("the parse did not keep the action or its bytes")
	}
	// The M3 set is a set: neither later version is known, whichever comes first.
	if CanonicalActionVersionKnown(2) || CanonicalActionVersionKnown(3) || !CanonicalActionVersionKnown(1) {
		t.Error("M3's set is not {1}")
	}
}

// Version 3 is access_request alone, with only its fields, and access_request is version 3 alone.
func TestCanonicalActionVersionThreeTakesOnlyItsFields(t *testing.T) {
	known := testRecordVersionsKnown(1, 3)
	if err := canonicalActionCheck(testRecordAccessRequestAction(), known); err != nil {
		t.Fatalf("a version-3 access_request: %v", err)
	}
	scoped := testRecordAccessRequestAction()
	scoped.Scope = true
	if err := canonicalActionCheck(scoped, known); err != nil {
		t.Errorf("scope on a version-3 action: %v", err)
	}
	extras := map[string]func(action *protocol.CanonicalAction){
		"host":         func(action *protocol.CanonicalAction) { action.Host = "www.example" },
		"port":         func(action *protocol.CanonicalAction) { action.Port = 443 },
		"cidrs":        func(action *protocol.CanonicalAction) { action.Cidrs = []string{"192.0.2.0/24"} },
		"dns_name":     func(action *protocol.CanonicalAction) { action.DnsName = "www" },
		"preview":      func(action *protocol.CanonicalAction) { action.Preview = "ssh" },
		"recipients":   func(action *protocol.CanonicalAction) { action.Recipients = []string{"a@example.com"} },
		"rule_id":      func(action *protocol.CanonicalAction) { action.RuleId = bytes.Repeat([]byte{0x34}, 16) },
		"socket_name":  func(action *protocol.CanonicalAction) { action.SocketName = "app" },
		"versioning":   func(action *protocol.CanonicalAction) { action.Versioning = 1 },
		"content_hash": func(action *protocol.CanonicalAction) { action.ContentSha256 = bytes.Repeat([]byte{0x35}, 32) },
	}
	for name, extra := range extras {
		action := testRecordAccessRequestAction()
		extra(action)
		if err := canonicalActionCheck(action, known); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("a version-3 action setting %s: %v", name, err)
		}
	}

	otherKind := testRecordAccessRequestAction()
	otherKind.Kind = uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_FORWARD)
	if err := canonicalActionCheck(otherKind, known); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a forward at version 3: %v", err)
	}
	earlier := testRecordAccessRequestAction()
	earlier.Version = 1
	if err := canonicalActionCheck(earlier, known); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("an access_request at version 1: %v", err)
	}
}

// Field 37 is version 2's, and a version-2 action with versioning on carries none.
func TestCanonicalActionFieldThirtySevenOnlyAtVersionTwo(t *testing.T) {
	known := testRecordVersionsKnown(1, 2)
	write := func(version uint32, versioning uint32) *protocol.CanonicalAction {
		return &protocol.CanonicalAction{
			Kind:          uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_AGENT_CONFIG_WRITE),
			Version:       version,
			RepoId:        bytes.Repeat([]byte{0x41}, 16),
			Path:          "AGENTS.md",
			ContentSha256: bytes.Repeat([]byte{0x42}, 32),
			BaseVersion:   3,
			Versioning:    versioning,
		}
	}
	if err := canonicalActionCheck(write(1, 1), known); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("versioning off at version 1: %v", err)
	}
	if err := canonicalActionCheck(write(2, 1), known); err != nil {
		t.Errorf("versioning off at version 2: %v", err)
	}
	// versioning 0, on, is absent on the wire, so its absence says nothing of the version.
	if err := canonicalActionCheck(write(2, 0), known); err != nil {
		t.Errorf("versioning on at version 2: %v", err)
	}
	if err := canonicalActionCheck(write(1, 0), known); err != nil {
		t.Errorf("version 1 with no field 37: %v", err)
	}
}

// Every version: a kind record.proto names and not 0, no field this build cannot name, the preview cap, and the
// enumerations a set audience or mode must hold.
func TestCanonicalActionRefusesWhatNoVersionHolds(t *testing.T) {
	cases := map[string]func(action *protocol.CanonicalAction){
		"kind 0":     func(action *protocol.CanonicalAction) { action.Kind = 0 },
		"kind 18":    func(action *protocol.CanonicalAction) { action.Kind = 18 },
		"kind 2^31":  func(action *protocol.CanonicalAction) { action.Kind = 1 << 31 },
		"preview":    func(action *protocol.CanonicalAction) { action.Preview = string(bytes.Repeat([]byte("p"), 2*1024+1)) },
		"audience 9": func(action *protocol.CanonicalAction) { action.Audience = 9 },
		"app_mode 9": func(action *protocol.CanonicalAction) { action.AppMode = 9 },
		"unknown field": func(action *protocol.CanonicalAction) {
			action.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
		},
	}
	for name, change := range cases {
		action := testRecordDnsAction()
		change(action)
		if _, err := ParseStoredCanonicalAction(testRecordStored(t, action)); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	atCap := testRecordDnsAction()
	atCap.Preview = string(bytes.Repeat([]byte("p"), 2*1024))
	atCap.Audience = uint32(protocol.AclAudience_ACL_AUDIENCE_MEMBERS)
	if _, err := ParseStoredCanonicalAction(testRecordStored(t, atCap)); err != nil {
		t.Errorf("a preview at the cap with a known audience: %v", err)
	}
	if _, err := ParseStoredCanonicalAction([]byte{0xff}); !errors.Is(err, ErrRecordStoredInvalid) {
		t.Errorf("bytes that do not parse: %v", err)
	}
}

// A header for an order test: a writer, a seq, and a body byte that tells two forked entries apart.
func testRecordOrderHeader(t *testing.T, writer byte, seq uint64, fork byte) *StoredRecordHeader {
	header := &protocol.RecordHeader{
		EntryId:         bytes.Repeat([]byte{fork}, 16),
		LogId:           bytes.Repeat([]byte{0x02}, 16),
		WriterSidecarId: bytes.Repeat([]byte{writer}, 16),
		Seq:             seq,
		PrevSha256:      bytes.Repeat([]byte{0x04}, 32),
		Kind:            uint32(RecordKindNote),
		BodyCommitment:  bytes.Repeat([]byte{0x05}, 32),
	}
	stored, err := ParseStoredRecordHeader(testRecordStored(t, header))
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// Two writers' entries in one push order by writer, then seq, from any order the statement held them in, and a fork
// inside the push orders by leaf the same way every time.
func TestRecordOrderInPushIsDeterministic(t *testing.T) {
	want := []*StoredRecordHeader{
		testRecordOrderHeader(t, 0x0a, 1, 0x01),
		testRecordOrderHeader(t, 0x0a, 2, 0x01),
		testRecordOrderHeader(t, 0x0a, 3, 0x01),
		testRecordOrderHeader(t, 0x0b, 1, 0x01),
		testRecordOrderHeader(t, 0x0b, 7, 0x01),
	}
	// a fork: two entries of writer 0x0b at seq 7, kept in leaf order
	fork := testRecordOrderHeader(t, 0x0b, 7, 0x02)
	forkLeaf := fork.LeafHash()
	wantLeaf := want[4].LeafHash()
	if bytes.Compare(forkLeaf[:], wantLeaf[:]) < 0 {
		want = slices.Insert(want, 4, fork)
	} else {
		want = append(want, fork)
	}
	if !RecordInPushOrder(want) {
		t.Fatal("the expected order is not in order")
	}
	random := rand.New(rand.NewPCG(1, 2))
	for round := 0; round < 64; round += 1 {
		shuffled := slices.Clone(want)
		random.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		RecordOrderInPush(shuffled)
		for i := range want {
			if shuffled[i] != want[i] {
				t.Fatalf("round %d: position %d holds writer %x seq %d", round, i, shuffled[i].Header.GetWriterSidecarId()[0], shuffled[i].Header.GetSeq())
			}
		}
	}
	reversed := slices.Clone(want)
	slices.Reverse(reversed)
	if RecordInPushOrder(reversed) {
		t.Error("a reversed push reads as in order")
	}
}
