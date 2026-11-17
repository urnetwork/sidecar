// DESIGN-DETAILS 4.4's rows fixture, rerun (BRIDGE-M8-03; 4.2.4's table, QD-620): the rows a team of n devices folds
// into, in 4.2.4's mix (n devices in n/3 members, two devices in three with a forwarding row in 4.2.2's form, three
// repos a member, a 1,024-entry ring), decoded and loaded as a compile's judge loads a base's rows (configLoadRows), and
// the heap that holds measured against the rows' bytes. The Forwarder's admission rule counts a compile's rows at
// CompileEstimateRowsFactor times their bytes, with CompileEstimateOverheadByteCount beside them: a change to
// MemberRow, SidecarRow, DelegationRow or AclRows that makes a loaded row cost more than the rule counts fails here, in
// every make check, rather than as a tunnel killed on a phone. The figures are logged in 4.2.4's shape; they are this
// host's, no surrogate's or device's. Until the review phase's storage-backed compile retires the factor (4.2.4, QD-641)
// this is what holds it to the code. sidecartest/forwardcell builds the same rows with a copy of this generator, since
// the root's tests import no sidecartest package (§4.4), and compiles a network on them with a real Forwarder for T4's
// cells; both copies are held to one digest of their six-device rows.

package sidecar

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"runtime"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A fixture id from a label and a number, the same on every run.
func testRowsFixtureId(label string, i int) []byte {
	seed := sha256.Sum256(binary.BigEndian.AppendUint64([]byte("rows fixture "+label), uint64(i)))
	return seed[:len(Id{})]
}

// A fixture digest, 32 bytes.
func testRowsFixtureDigest(label string, i int) []byte {
	seed := sha256.Sum256(binary.BigEndian.AppendUint64([]byte("rows fixture digest "+label), uint64(i)))
	return seed[:]
}

// The genesis the fixture's rows name: its owner is the fixture's member 0, and its first device the fixture's device 0.
func testRowsFixtureGenesis() *bridge.Genesis {
	return &bridge.Genesis{OwnerSidecarId: testRowsFixtureId("device", 0), OwnerMemberId: testRowsFixtureId("member", 0)}
}

// 4.2.4's mix at deviceCount devices, as a base's ProjectionRows: every device admitted by the owner's first device
// under its member, with an identity key, an admission confirmed and its live_since; two in three with a forwarding
// Delegation's row, its key and its reader key's digest, and its host client where its network is its device's; three
// repos a member, each consented by the member's devices; and a ring of 1,024 statements.
func testRowsFixture(t testing.TB, deviceCount int) *bridge.ProjectionRows {
	t.Helper()
	memberCount := max(1, deviceCount/3)
	rows := &bridge.ProjectionRows{Settings: &bridge.ProjectionSettings{}}
	for i := range memberCount {
		role := bridge.MemberRole_MEMBER_ROLE_MEMBER
		if i == 0 {
			role = bridge.MemberRole_MEMBER_ROLE_OWNER
		}
		rows.Members = append(rows.Members, &bridge.MemberRow{MemberId: testRowsFixtureId("member", i), Role: role})
	}
	owner := testRowsFixtureId("device", 0)
	acl := &protocol.AclRows{}
	memberDevices := make([][][]byte, memberCount)
	for i := range deviceCount {
		sidecarId := testRowsFixtureId("device", i)
		memberIndex := i % memberCount
		memberDevices[memberIndex] = append(memberDevices[memberIndex], sidecarId)
		identityKey := ed25519.NewKeyFromSeed(testRowsFixtureDigest("identity", i)).Public().(ed25519.PublicKey)
		at := uint64(2 + i)
		row := &bridge.SidecarRow{
			SidecarId:         sidecarId,
			AdmissionSha256:   testRowsFixtureDigest("admission", i),
			AdmissionSigners:  [][]byte{owner},
			AdmittedAt:        at,
			ConfirmSigner:     owner,
			ConfirmedAt:       at,
			LiveSince:         at,
			IdentityPublicKey: identityKey,
			IdentityAlg:       "ed25519",
			MemberId:          testRowsFixtureId("member", memberIndex),
			AdmittedTimeMs:    int64(1_800_000_000_000 + i),
			Confirmations:     []*bridge.ConfirmationRow{{Signer: owner, At: at}},
		}
		if i == 0 {
			// the Genesis's device, which no entry admitted
			row.AdmissionSigners, row.AdmittedAt, row.AdmittedTimeMs = nil, 0, 0
		}
		rows.Sidecars = append(rows.Sidecars, row)
		if i%3 == 2 {
			continue
		}
		// a forwarding Delegation's row in 4.2.2's form: the reader key a digest, the key gkm's object
		forwardKey := ed25519.NewKeyFromSeed(testRowsFixtureDigest("forward", i)).Public().(ed25519.PublicKey)
		hostKey := ed25519.NewKeyFromSeed(testRowsFixtureDigest("host client", i)).Public().(ed25519.PublicKey)
		rows.Delegations = append(rows.Delegations, &bridge.DelegationRow{
			DelegationId:        testRowsFixtureDigest("delegation", i),
			Signer:              sidecarId,
			At:                  uint64(deviceCount + 2 + i),
			Pubkey:              forwardKey,
			ForwardSidecarId:    sidecarId,
			HostClientId:        testRowsFixtureId("host client", i),
			HostClientPublicKey: hostKey,
			ReaderKeySha256:     testRowsFixtureDigest("reader key", i),
		})
	}
	for memberIndex := range memberCount {
		for repo := range 3 {
			acl.Repos = append(acl.Repos, &protocol.AclRepo{
				RepoId:              testRowsFixtureId("repo", 3*memberIndex+repo),
				Kind:                protocol.RepoKind_REPO_KIND_GENERAL,
				OwnerMemberId:       testRowsFixtureId("member", memberIndex),
				ConsentedSidecarIds: memberDevices[memberIndex],
			})
		}
	}
	aclBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(acl)
	if err != nil {
		t.Fatal(err)
	}
	rows.Acl = aclBytes
	ringStart := uint64(3 * deviceCount)
	for i := range 1024 {
		rows.Ring = append(rows.Ring, &bridge.RingRow{StatementId: testRowsFixtureId("ring", i), N: ringStart + uint64(i)})
	}
	return rows
}

// What a compile holds once a base's rows are decoded and loaded, in bytes of live heap: the rows decoded, the state's
// indexes over them and the AclState a compile builds over them (stateFromBase builds one to refuse rows whose acl
// part does not, and the compile's view builds its own), measured between two collections with all of it kept alive.
func testRowsFixtureLoaded(t testing.TB, rowsBytes []byte) int64 {
	t.Helper()
	runtime.GC()
	runtime.GC()
	before := &runtime.MemStats{}
	runtime.ReadMemStats(before)
	rows := &bridge.ProjectionRows{}
	if err := proto.Unmarshal(rowsBytes, rows); err != nil {
		t.Fatal(err)
	}
	state := &ConfigState{genesis: testRowsFixtureGenesis()}
	if err := configLoadRows(state, rows); err != nil {
		t.Fatal(err)
	}
	acl, err := NewAclState(state.aclRows, state)
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	after := &runtime.MemStats{}
	runtime.ReadMemStats(after)
	runtime.KeepAlive(rows)
	runtime.KeepAlive(state)
	runtime.KeepAlive(acl)
	return int64(after.HeapAlloc) - int64(before.HeapAlloc)
}

// The rows of deviceCount devices in the fixture's mix: their bytes, what loading them holds, and what the admission
// rule under settings counts for them.
func testRowsFixtureMeasure(t testing.TB, settings *ForwarderSettings, deviceCount int) (int64, int64, int64) {
	t.Helper()
	rowsBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(testRowsFixture(t, deviceCount))
	if err != nil {
		t.Fatal(err)
	}
	loaded := testRowsFixtureLoaded(t, rowsBytes)
	rowsByteCount := int64(len(rowsBytes))
	return rowsByteCount, loaded, settings.CompileEstimate(ForwarderCompileSize{RowsByteCount: rowsByteCount})
}

// The admission rule's rows and overhead terms cover what loading the rows holds, at every size in 4.2.4's table up
// to the 4 MiB of rows §8.8 allows: 6, 100, 1,000 and 5,000 devices. Each figure is logged beside the ratio 4.2.4
// measured (12.6, 6.5, 5.1, 4.8), which a move far past it would make worth a new row in that table. The check is not
// vacuous: with a rows factor of 3 the 5,000-device rows' load passes what the rule would count.
func TestTheCompileEstimateCoversTheLoadedRows(t *testing.T) {
	settings := DefaultForwarderSettings(ForwarderHostApple)
	for _, deviceCount := range []int{6, 100, 1_000, 5_000} {
		rowsByteCount, loaded, counted := testRowsFixtureMeasure(t, settings, deviceCount)
		t.Logf("%6d devices: rows %10d B, decoded and loaded %11d B, ratio %5.1f; the rule counts %11d B",
			deviceCount, rowsByteCount, loaded, float64(loaded)/float64(rowsByteCount), counted)
		if counted < loaded {
			t.Errorf("at %d devices loading %d B of rows holds %d B, past the %d B the admission rule counts for them",
				deviceCount, rowsByteCount, loaded, counted)
		}
	}
	undercounting := DefaultForwarderSettings(ForwarderHostApple)
	undercounting.CompileEstimateRowsFactor = 3
	if rowsByteCount, loaded, counted := testRowsFixtureMeasure(t, undercounting, 5_000); loaded <= counted {
		t.Errorf("a rows factor of 3 counts %d B for %d B of rows holding %d B: the check could not fail", counted, rowsByteCount, loaded)
	}
}

// The six-device rows' SHA-256, which sidecartest/forwardcell holds its copy of the generator to as well
// (forward_cell_test.go), so the two copies of 4.2.4's mix cannot drift apart.
const testRowsFixtureSixSha256 = "032b2dbcd53a97393e0f3bac4c4c1efe174a65e9e57243d5c35790c749fa3ba2"

// The rows are forwardcell's mix, byte for byte.
func TestTheRowsFixtureIsForwardcellsMix(t *testing.T) {
	rowsBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(testRowsFixture(t, 6))
	if err != nil {
		t.Fatal(err)
	}
	if digest := sha256.Sum256(rowsBytes); hex.EncodeToString(digest[:]) != testRowsFixtureSixSha256 {
		t.Fatalf("the six-device rows hash to %x, forwardcell's copy to %s", digest, testRowsFixtureSixSha256)
	}
}
