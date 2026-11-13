// record_action_rules.go's rules: an approver refuses a CanonicalAction version it does not know (§22.5's §16 row),
// each version sets only what it may, versions 3 and 4 show no prefix or port in the clear (QD-740), and a push's
// entries order alike everywhere (§16.8's order row).

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

// The worker a test's access request asks for, as grant_dst names it.
const testRecordWorkerDst = "sidecar:0102030405060708090a0b0c0d0e0f10"

// What a test's access request seals: its worker's port, and the port's text.
func testRecordAccessRequestDetail() *protocol.CanonicalActionDetail {
	return &protocol.CanonicalActionDetail{TargetPort: 22, GrantDst: []string{testRecordWorkerDst + ":tcp:22"}}
}

// A version-3 access_request, using only its fields: its worker's port rides sealed_detail.
func testRecordAccessRequestAction() *protocol.CanonicalAction {
	return &protocol.CanonicalAction{
		Kind:            uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_ACCESS_REQUEST),
		ExpiresMillis:   1762387200000,
		GrantDst:        []string{testRecordWorkerDst},
		GrantAllow:      []string{"dial"},
		Version:         3,
		RepoId:          bytes.Repeat([]byte{0x31}, 16),
		TargetSidecarId: bytes.Repeat([]byte{0x32}, 16),
		Subject:         bytes.Repeat([]byte{0x33}, 16),
		SealedDetail:    testSealActionDetail(testRecordAccessRequestDetail()),
	}
}

// A version-4 dial grant, kind bridge_forward's, using only its fields.
func testRecordSealedGrantAction() *protocol.CanonicalAction {
	return &protocol.CanonicalAction{
		Kind:          uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_FORWARD),
		ExpiresMillis: 1762387200000,
		GrantDst:      []string{testActionTargetDst},
		GrantAllow:    []string{"dial"},
		Version:       4,
		RuleId:        bytes.Repeat([]byte{0x36}, 16),
		Subject:       bytes.Repeat([]byte{0x37}, 16),
		SealedDetail:  testSealActionDetail(testForwardDetail()),
	}
}

// A known set for a test of a later version's rules.
func testRecordVersionsKnown(versions ...uint32) func(version uint32) bool {
	return func(version uint32) bool {
		return slices.Contains(versions, version)
	}
}

// §22.5's §16 row at M3: versions 0, 2, 3 and 5 are refused, and 1 parses. Version 4, a dial or route grant's, is
// known (QD-740), and is no dns action's.
func TestApproverRefusesUnknownVersion(t *testing.T) {
	for _, version := range []uint32{0, 2, 3, 5} {
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
	// The set is a set: 2 and 3 are not known, whichever comes first, though 4 is.
	if CanonicalActionVersionKnown(2) || CanonicalActionVersionKnown(3) || CanonicalActionVersionKnown(5) ||
		!CanonicalActionVersionKnown(1) || !CanonicalActionVersionKnown(4) {
		t.Error("the known set is not {1, 4}")
	}
	misplaced := testRecordDnsAction()
	misplaced.Version = 4
	if _, err := ParseStoredCanonicalAction(testRecordStored(t, misplaced)); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a dns action at version 4: %v", err)
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
		// QD-740: a worker's port leaves version 3's clear set, as a number and as text
		"target_port": func(action *protocol.CanonicalAction) { action.TargetPort = 22 },
		"port text": func(action *protocol.CanonicalAction) {
			action.GrantDst = []string{testRecordWorkerDst + ":tcp:22"}
		},
		"a prefix":       func(action *protocol.CanonicalAction) { action.GrantDst = []string{"ip:192.0.2.0/24"} },
		"a short detail": func(action *protocol.CanonicalAction) { action.SealedDetail = []byte{0x01, 0x02, 0x03} },
		"a plain detail": func(action *protocol.CanonicalAction) {
			action.SealedDetail = testRecordStored(t, testRecordAccessRequestDetail())
		},
		"local_port's old": func(action *protocol.CanonicalAction) { testRecordSetUnknownVarint(action, 24, 8022) },
	}
	for name, extra := range extras {
		action := testRecordAccessRequestAction()
		extra(action)
		if err := canonicalActionCheck(action, known); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("a version-3 action setting %s: %v", name, err)
		}
	}
	// an access request for no port carries no detail
	portless := testRecordAccessRequestAction()
	portless.SealedDetail = nil
	if err := canonicalActionCheck(portless, known); err != nil {
		t.Errorf("a version-3 access_request with no detail: %v", err)
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

// Sets a field this build's CanonicalAction does not declare, as another build's bytes would carry it.
func testRecordSetUnknownVarint(action *protocol.CanonicalAction, number protowire.Number, value uint64) {
	action.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, number, protowire.VarintType), value))
}

// Version 4 is a dial or route grant, kind bridge_forward alone, with only its fields: its clear grant_dst names
// subjects, its grant_allow dial or route, and its prefixes and ports ride sealed_detail, which no other version but
// 3 sets.
func TestCanonicalActionVersionFourTakesOnlyItsFields(t *testing.T) {
	stored, err := ParseStoredCanonicalAction(testRecordStored(t, testRecordSealedGrantAction()))
	if err != nil {
		t.Fatalf("a version-4 grant: %v", err)
	}
	if err := CheckCanonicalActionForServer(stored); err != nil {
		t.Errorf("a version-4 grant on a server path: %v", err)
	}
	route := testRecordSealedGrantAction()
	route.GrantAllow = []string{"dial", "route"}
	route.GrantDst = []string{testActionTargetDst, "network:0102030405060708090a0b0c0d0e0f10"}
	if _, err := ParseStoredCanonicalAction(testRecordStored(t, route)); err != nil {
		t.Errorf("a version-4 route grant: %v", err)
	}
	extras := map[string]func(action *protocol.CanonicalAction){
		"host":              func(action *protocol.CanonicalAction) { action.Host = "www.example" },
		"port":              func(action *protocol.CanonicalAction) { action.Port = 443 },
		"cidrs":             func(action *protocol.CanonicalAction) { action.Cidrs = []string{"192.0.2.0/24"} },
		"target_port":       func(action *protocol.CanonicalAction) { action.TargetPort = 8443 },
		"target_sidecar_id": func(action *protocol.CanonicalAction) { action.TargetSidecarId = bytes.Repeat([]byte{0x32}, 16) },
		"repo_id":           func(action *protocol.CanonicalAction) { action.RepoId = bytes.Repeat([]byte{0x31}, 16) },
		"preview":           func(action *protocol.CanonicalAction) { action.Preview = "a forward" },
		"socket_name":       func(action *protocol.CanonicalAction) { action.SocketName = "app" },
		"versioning":        func(action *protocol.CanonicalAction) { action.Versioning = 1 },
		"port text": func(action *protocol.CanonicalAction) {
			action.GrantDst = []string{testActionTargetDst + ":tcp:8443"}
		},
		"a prefix":       func(action *protocol.CanonicalAction) { action.GrantDst = append(action.GrantDst, "ip:192.0.2.0/24") },
		"publish":        func(action *protocol.CanonicalAction) { action.GrantAllow = []string{"dial", "publish"} },
		"a short detail": func(action *protocol.CanonicalAction) { action.SealedDetail = bytes.Repeat([]byte{0x01}, 47) },
		"a plain detail": func(action *protocol.CanonicalAction) { action.SealedDetail = testRecordStored(t, testForwardDetail()) },
		"a cut detail": func(action *protocol.CanonicalAction) {
			action.SealedDetail = action.SealedDetail[:len(action.SealedDetail)-1]
		},
		"no detail": func(action *protocol.CanonicalAction) { action.SealedDetail = nil },
		"a template with no detail": func(action *protocol.CanonicalAction) {
			action.Scope, action.SealedDetail = true, nil
		},
		"local_port's old number": func(action *protocol.CanonicalAction) { testRecordSetUnknownVarint(action, 24, 18443) },
		"weight's old number":     func(action *protocol.CanonicalAction) { testRecordSetUnknownVarint(action, 25, 10) },
		"an unknown field":        func(action *protocol.CanonicalAction) { testRecordSetUnknownVarint(action, 99, 1) },
	}
	for name, extra := range extras {
		action := testRecordSealedGrantAction()
		extra(action)
		if _, err := ParseStoredCanonicalAction(testRecordStored(t, action)); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("a version-4 action setting %s: %v", name, err)
		}
	}
	for _, kind := range []protocol.SidecarActionKind{
		protocol.SidecarActionKind_SIDECAR_ACTION_KIND_PUBLISH, protocol.SidecarActionKind_SIDECAR_ACTION_KIND_LISTEN,
		protocol.SidecarActionKind_SIDECAR_ACTION_KIND_EXPOSE, protocol.SidecarActionKind_SIDECAR_ACTION_KIND_DNS_SET,
		protocol.SidecarActionKind_SIDECAR_ACTION_KIND_ACCESS_REQUEST,
	} {
		otherKind := testRecordSealedGrantAction()
		otherKind.Kind = uint32(kind)
		if _, err := ParseStoredCanonicalAction(testRecordStored(t, otherKind)); !errors.Is(err, ErrCanonicalActionInvalid) &&
			!errors.Is(err, ErrCanonicalActionVersionUnknown) {
			t.Errorf("%s at version 4: %v", kind, err)
		}
	}
	// field 38 is versions 3 and 4's: a version-1 action that carries it is refused, a grant's included
	earlier := testRecordSealedGrantAction()
	earlier.Version = 1
	if _, err := ParseStoredCanonicalAction(testRecordStored(t, earlier)); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a sealed_detail at version 1: %v", err)
	}
	dns := testRecordDnsAction()
	dns.SealedDetail = testSealActionDetail(testForwardDetail())
	if _, err := ParseStoredCanonicalAction(testRecordStored(t, dns)); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a dns action with a sealed_detail: %v", err)
	}
}

// A bridge_forward takes version 4 alone (QD-740): the shape before it, a forward at version 1, is refused by every
// parser and by the builder, with its port in the clear, with none, and as a template, and so is one at version 2 or
// 3. And at every version a clear grant_dst names its destination alone, so another kind's version-1 action naming a
// port or a prefix is refused as a forward's would be.
func TestForwardTakesVersionFourAloneAndNoVersionShowsAPort(t *testing.T) {
	known := testRecordVersionsKnown(1, 2, 3, 4)
	forwards := map[string]func(action *protocol.CanonicalAction){
		"version 1":            func(action *protocol.CanonicalAction) { action.Version = 1 },
		"version 1, no detail": func(action *protocol.CanonicalAction) { action.Version, action.SealedDetail = 1, nil },
		"version 1, a clear port": func(action *protocol.CanonicalAction) {
			action.Version, action.SealedDetail, action.GrantDst = 1, nil, []string{testActionTargetDst + ":tcp:8443"}
		},
		"version 1, a template": func(action *protocol.CanonicalAction) {
			action.Version, action.SealedDetail, action.Scope = 1, nil, true
		},
		"version 2": func(action *protocol.CanonicalAction) { action.Version, action.SealedDetail = 2, nil },
		"version 3": func(action *protocol.CanonicalAction) { action.Version = 3 },
	}
	for name, change := range forwards {
		action := testRecordSealedGrantAction()
		change(action)
		if err := canonicalActionCheck(action, known); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("a forward at %s: %v", name, err)
		}
		if _, err := newCanonicalAction(action, known); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("a forward built at %s: %v", name, err)
		}
	}
	bare := &protocol.CanonicalAction{Kind: uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_FORWARD), Version: 1}
	if _, err := ParseStoredCanonicalAction(testRecordStored(t, bare)); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a forward at version 1 with no field: %v", err)
	}

	listen := func(dst string) *protocol.CanonicalAction {
		return &protocol.CanonicalAction{
			Kind:       uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_LISTEN),
			Version:    1,
			GrantDst:   []string{"sock:tls/443/blog", dst},
			GrantAllow: []string{"listen"},
			RuleId:     bytes.Repeat([]byte{0x36}, 16),
			Subject:    bytes.Repeat([]byte{0x37}, 16),
		}
	}
	for _, dst := range []string{testActionTargetDst + ":tcp:8443", testActionTargetDst + ":udp:53", "ip:192.0.2.0/24", "ip:2001:db8::/32"} {
		if _, err := ParseStoredCanonicalAction(testRecordStored(t, listen(dst))); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("a version-1 action whose grant_dst names a port or a prefix: %v", err)
		}
	}
	for _, dst := range []string{testActionTargetDst, "dns:blog.example", "network:0102030405060708090a0b0c0d0e0f10", "mail:*"} {
		if _, err := ParseStoredCanonicalAction(testRecordStored(t, listen(dst))); err != nil {
			t.Errorf("a version-1 action whose grant_dst names a destination alone: %v", err)
		}
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
		"kind 19":    func(action *protocol.CanonicalAction) { action.Kind = 19 },
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
