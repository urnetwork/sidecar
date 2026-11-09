//go:build !js

// §22.6's config-delta target as a native fuzz target, whose seeds in testdata/fuzz/FuzzConfigDelta run as ordinary
// tests under go test. Not on js: testing.F reads its corpus directory before it runs a seed, and js has none.
//
// The input is a run of entries for the test network's log at base 1. Each starts with a mode byte and a 16-bit
// length: the mode's low bits pick the entry's kind, raw; its high bit asks the harness to sign the body as the type
// the next two bytes name, by the owner's device, so the rules see signed statements, and bit 6 to give that body a
// fresh header at the tip first, so they see statements that pass the replay row. Whatever arrives, the reader applies,
// refuses or stops at a fork, never panics; two readers fed the same bytes reach the same verdicts and the same state;
// and what a reader keeps grows with the entries it applied and no faster.

package sidecar

import (
	"encoding/binary"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The most input one run takes, and the most entries.
const (
	testConfigDeltaMaxByteCount  = 64 * 1024
	testConfigDeltaMaxEntryCount = 48
)

// A mode byte's bits.
const (
	testConfigDeltaSign   = 0x80
	testConfigDeltaHeader = 0x40
)

// One chunk of fuzz input: a mode, then a body, framed.
func testConfigDeltaChunk(mode byte, body []byte) []byte {
	chunk := []byte{mode, 0, 0}
	binary.BigEndian.PutUint16(chunk[1:], uint16(len(body)))
	return append(chunk, body...)
}

// A signed chunk: the type, then its body, signed by the owner's device and given a fresh header.
func testConfigDeltaSigned(t testing.TB, signedType bridge.SignedType, body proto.Message) []byte {
	typed := binary.BigEndian.AppendUint16(nil, uint16(signedType))
	return testConfigDeltaChunk(testConfigDeltaSign|testConfigDeltaHeader|byte(bridge.AuthEntryKindStatement), append(typed, testConfigMarshal(t, body)...))
}

// The seeds: an admission run, a proposal at k = 1, revocations, a tick that reaps, and each kind's raw form.
func testConfigDeltaSeeds(t testing.TB) map[string][]byte {
	member := testConfigId("fuzz member").Bytes()
	device := testConfigDevice{sidecarId: testConfigId("fuzz device"), memberId: testConfigId("fuzz member"), key: testConfigDeviceKey("fuzz device")}
	admit := &protocol.SidecarAdmit{
		NetworkId: testConfigId("network").Bytes(), SidecarId: device.sidecarId.Bytes(), IdentityPublicKey: device.publicKey(),
		IdentityAlg: configIdentityAlgEd25519, MemberId: member,
	}
	ephemeral := &protocol.SidecarAdmit{
		NetworkId: testConfigId("network").Bytes(), SidecarId: testConfigId("fuzz worker").Bytes(), IdentityPublicKey: device.publicKey(),
		IdentityAlg: configIdentityAlgEd25519, MemberId: member, Ephemeral: true, NotAfter: testConfigStartMs + 24*60*60*1000,
	}
	proposal := &protocol.AuthorityProposal{
		StatementType: uint32(bridge.SignedType_SIGNED_MEMBER_ADMIT),
		Statement:     testConfigMarshal(t, &protocol.MemberAdmit{MemberId: testConfigId("proposed").Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER}),
	}
	join := func(chunks ...[]byte) []byte {
		joined := []byte{}
		for _, chunk := range chunks {
			joined = append(joined, chunk...)
		}
		return joined
	}
	memberAdmit := testConfigDeltaSigned(t, bridge.SignedType_SIGNED_MEMBER_ADMIT, &protocol.MemberAdmit{MemberId: member, Role: bridge.MemberRole_MEMBER_ROLE_MEMBER})
	return map[string][]byte{
		"admission_run": join(
			memberAdmit,
			testConfigDeltaSigned(t, bridge.SignedType_SIGNED_SIDECAR_ADMIT, admit),
			testConfigDeltaSigned(t, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, &protocol.AdmissionConfirm{SidecarId: device.sidecarId.Bytes()}),
			testConfigDeltaSigned(t, bridge.SignedType_SIGNED_SIDECAR_REVOKE, &bridge.SidecarRevoke{
				SidecarId: device.sidecarId.Bytes(), Reason: bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST,
			}),
			testConfigDeltaSigned(t, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{MemberId: member}),
		),
		"proposal_at_one": join(testConfigDeltaSigned(t, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, proposal)),
		"admin_set":       join(memberAdmit, testConfigDeltaSigned(t, bridge.SignedType_SIGNED_ADMIN_SET, &protocol.AdminSet{Owners: [][]byte{testConfigId("owner member").Bytes()}, Admins: [][]byte{member}})),
		"reap": join(
			memberAdmit,
			testConfigDeltaSigned(t, bridge.SignedType_SIGNED_SIDECAR_ADMIT, ephemeral),
			testConfigDeltaChunk(byte(bridge.AuthEntryKindTick), testConfigMarshal(t, &bridge.ApiTick{ReapedSidecarIds: [][]byte{ephemeral.SidecarId}})),
		),
		"raw_kinds": join(
			testConfigDeltaChunk(byte(bridge.AuthEntryKindStatement), []byte{0x0A, 0x02, 0x08, 0x01}),
			testConfigDeltaChunk(byte(bridge.AuthEntryKindTick), nil),
			testConfigDeltaChunk(byte(bridge.AuthEntryKindBase), []byte{0x0A, 0x00}),
		),
		"unknown_kind":            join(testConfigDeltaChunk(0, nil)),
		"unsigned_header_rewrite": join(testConfigDeltaChunk(testConfigDeltaHeader|byte(bridge.AuthEntryKindStatement), []byte{0x12, 0x01})),
	}
}

// A signed chunk's body as the owner's device signs it, its header made fresh at the tip when asked, or nil when
// the type is no config statement or the body does not parse as one.
func (self *testConfigNet) fuzzSignedBody(signedType bridge.SignedType, body []byte, freshHeader bool) []byte {
	purpose, ok := ConfigStatementPurpose(signedType)
	if !ok {
		return nil
	}
	message, err := ParseConfigStatement(purpose, signedType, body)
	if err != nil {
		return nil
	}
	if freshHeader {
		field := message.ProtoReflect().Descriptor().Fields().ByName("header")
		if field != nil && field.Kind() == protoreflect.MessageKind {
			message.ProtoReflect().Set(field, protoreflect.ValueOfMessage(self.header().ProtoReflect()))
		}
	}
	return self.sign(self.owner, signedType, message)
}

func FuzzConfigDelta(f *testing.F) {
	for _, seed := range testConfigDeltaSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if testConfigDeltaMaxByteCount < len(data) {
			return
		}
		net := newTestConfigNet(t)
		other := net.newReader()
		entryCount := 0
		for 3 <= len(data) && entryCount < testConfigDeltaMaxEntryCount {
			mode := data[0]
			length := min(int(binary.BigEndian.Uint16(data[1:3])), len(data)-3)
			body := data[3 : 3+length]
			data = data[3+length:]
			kind := uint32(mode & 0x03)
			if mode&testConfigDeltaSign != 0 && 2 <= len(body) {
				body = net.fuzzSignedBody(bridge.SignedType(binary.BigEndian.Uint16(body)), body[2:], mode&testConfigDeltaHeader != 0)
				kind = bridge.AuthEntryKindStatement
			}
			entryBytes := net.makeEntry(kind, body)
			entryCount += 1

			verdict, err := net.log.Apply(entryBytes, net.source)
			otherVerdict, otherErr := other.Apply(entryBytes, net.source)
			if (err == nil) != (otherErr == nil) {
				t.Fatalf("entry %d: one reader got %v and the other %v", entryCount, err, otherErr)
			}
			if err != nil {
				if !errors.Is(err, ErrConfigFork) && !errors.Is(err, ErrConfigEntryMalformed) {
					t.Fatalf("entry %d: %v", entryCount, err)
				}
				break
			}
			if verdict.Accepted() != otherVerdict.Accepted() || verdict.StatementId != otherVerdict.StatementId {
				t.Fatalf("entry %d: verdicts %v and %v", entryCount, verdict.Refusal, otherVerdict.Refusal)
			}
			if !verdict.Accepted() && !errors.Is(verdict.Refusal, ErrConfigRefused) {
				t.Fatalf("entry %d: a refusal outside ErrConfigRefused: %v", entryCount, verdict.Refusal)
			}
			entry := &bridge.AuthEntry{}
			if err := proto.Unmarshal(entryBytes, entry); err != nil {
				t.Fatal(err)
			}
			net.n, net.timeMs = entry.GetN(), entry.GetTimeMs()
			net.chain = testConfigEntryChainTB(t, entryBytes)
			net.entries = append(net.entries, entryBytes)

			if len(net.log.kept) > entryCount+1 || len(net.log.ringOrder) > configStatementWindow {
				t.Fatalf("kept %d entries and %d ids after %d entries", len(net.log.kept), len(net.log.ringOrder), entryCount)
			}
		}
		if net.log.Fork() == nil {
			testConfigStatesEqual(t, net.log.State(), other.State())
		}
	})
}

// The chain digest an entry carries, for any testing.TB.
func testConfigEntryChainTB(t testing.TB, entryBytes []byte) [32]byte {
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(entryBytes, entry); err != nil {
		t.Fatal(err)
	}
	chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
	if err != nil {
		t.Fatal(err)
	}
	return chain
}
