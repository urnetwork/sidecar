//go:build !sidecar_http && !js

// The admission a network's first device's row names (QD-825): base 1's compile gives the Genesis's owner's row
// A_0 = SHA-256(Signed Genesis), the hash §10.4 has that device's credential carry, so a member's check of its leaf is
// the byte comparison it is for every other device, whose row names its SidecarAdmit's id. On config_writer_test.go's
// world: BootstrapNetwork on T2's fake api, read by a full reader that checks base 1's compile for real.

package sidecar_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A credential of device naming admissionSha256, signed by its identity key.
func (self *testWriterWorld) credential(device testWriterDevice, admissionSha256 []byte) *protocol.UrMlsCredential {
	self.t.Helper()
	signer := &sidecartest.FakeGkmSigner{SidecarId: device.sidecarId, PrivateKey: device.key}
	encoded, err := sidecar.SignUrMlsCredential(&sidecar.UrMlsCredentialArgs{
		SidecarId:             device.sidecarId,
		IdentityPublicKey:     signer.PublicKey(),
		MlsSignaturePublicKey: signer.PublicKey(),
		NotAfter:              self.clock.Now().Add(90 * 24 * time.Hour),
		AdmissionSha256:       admissionSha256,
	}, signer.Sign)
	if err != nil {
		self.t.Fatal(err)
	}
	credential, err := sidecar.CheckUrMlsCredential(encoded)
	if err != nil {
		self.t.Fatal(err)
	}
	return credential
}

// The owner's device admits device to its member with a SidecarAdmit; the statement's id.
func (self *testWriterWorld) admitDevice(device testWriterDevice) [sha256.Size]byte {
	self.t.Helper()
	signedBytes := self.statement(self.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, &protocol.SidecarAdmit{
		Header:            self.header(),
		NetworkId:         self.networkId.Bytes(),
		SidecarId:         device.sidecarId.Bytes(),
		IdentityPublicKey: device.key.Public().(ed25519.PublicKey),
		IdentityAlg:       "ed25519",
		MemberId:          device.memberId.Bytes(),
	})
	if _, err := self.api.AppendStatement(self.ctx, self.networkId, signedBytes); err != nil {
		self.t.Fatalf("the SidecarAdmit: %v", err)
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		self.t.Fatal(err)
	}
	purpose, _ := sidecar.ConfigStatementPurpose(bridge.SignedType_SIGNED_SIDECAR_ADMIT)
	return bridge.SignedBytesSha256(purpose, bridge.SignedType_SIGNED_SIDECAR_ADMIT, signed.GetBody())
}

// Base 1's compiled row of the Genesis's owner's device names SHA-256(Signed Genesis), the A_0 the bootstrap answers
// and an anchor records, and a full reader, which compiles base 1 itself, takes the base and holds the same row.
func TestBaseOnesOwnerRowNamesTheSignedGenesis(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	genesisSha256 := sha256.Sum256(world.genesis.SignedGenesis)
	if world.genesis.GenesisChain != genesisSha256 {
		t.Fatalf("the bootstrap's A_0 %x is not SHA-256(Signed Genesis) %x", world.genesis.GenesisChain, genesisSha256)
	}

	client := world.client()
	state := world.caughtUp(client)
	if state.Pin().GetVersion() != 1 {
		t.Fatalf("the reader stands at %d, not base 1", state.Pin().GetVersion())
	}
	row := state.SidecarRow(world.owner.sidecarId)
	if row == nil {
		t.Fatal("base 1 holds no row of the first device")
	}
	if !bytes.Equal(row.GetAdmissionSha256(), genesisSha256[:]) {
		t.Errorf("the first device's row names admission %x, want SHA-256(Signed Genesis) %x", row.GetAdmissionSha256(), genesisSha256)
	}
	if signers := row.GetAdmissionSigners(); len(signers) != 1 || !bytes.Equal(signers[0], world.owner.sidecarId.Bytes()) ||
		!bytes.Equal(row.GetIdentityPublicKey(), world.owner.key.Public().(ed25519.PublicKey)) ||
		!bytes.Equal(row.GetMemberId(), world.owner.memberId.Bytes()) {
		t.Errorf("the first device's row: %v", row)
	}

	// the rows api holds for base 1 are the bytes that row is in
	base := state.Base()
	if base == nil {
		t.Fatal("the reader holds no base")
	}
	projection, err := world.reader().ReadConfigProjection(world.ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(projection.Rows) != 1 {
		t.Fatalf("api holds %d rows for base 1", len(projection.Rows))
	}
	if rowsSha256 := sha256.Sum256(projection.Rows[0]); !bytes.Equal(rowsSha256[:], base.GetRowsSha256()) {
		t.Fatalf("the rows hash to %x, base 1 names %x", rowsSha256, base.GetRowsSha256())
	}
	rows := &bridge.ProjectionRows{}
	if err := proto.Unmarshal(projection.Rows[0], rows); err != nil {
		t.Fatal(err)
	}
	if len(rows.GetSidecars()) != 1 || !bytes.Equal(rows.GetSidecars()[0].GetAdmissionSha256(), genesisSha256[:]) {
		t.Errorf("base 1's rows: sidecars %v", rows.GetSidecars())
	}
}

// A member's check of the first device's leaf (§10.4): its credential signed under A_0 is admitted at the state base 1
// gives, and one naming another hash, the all-zero one and the hash of the Genesis's body among them, is refused,
// since the check compares the row's bytes and reads nothing else for this device.
func TestAMemberAdmitsTheFirstDevicesCredentialUnderTheGenesis(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	member := testWriterDeviceOf("member device", world.owner.memberId)
	world.admitDevice(member)

	// the member device's own reader
	client := world.client()
	state := world.caughtUp(client)
	if state.SidecarRow(member.sidecarId) == nil {
		t.Fatal("the member device is not admitted")
	}

	genesisSha256 := world.genesis.GenesisChain
	if err := sidecar.GkmCredentialAdmitted(state, world.credential(world.owner, genesisSha256[:])); err != nil {
		t.Errorf("the first device's credential under A_0: %v", err)
	}
	if err := sidecar.GkmCredentialStanding(state, world.credential(world.owner, genesisSha256[:])); err != nil {
		t.Errorf("the first device's credential under A_0, standing: %v", err)
	}
	check := sidecar.NewGkmCredentialCheck(func() sidecar.GkmAuthView { return state })
	if err := check(world.credential(world.owner, genesisSha256[:])); err != nil {
		t.Errorf("the first device's credential under A_0 at the engine's check: %v", err)
	}

	signedGenesis := &bridge.Signed{}
	if err := proto.Unmarshal(world.genesis.SignedGenesis, signedGenesis); err != nil {
		t.Fatal(err)
	}
	bodySha256 := sha256.Sum256(signedGenesis.GetBody())
	otherSha256 := sha256.Sum256([]byte("an admission the log never held"))
	flipped := bytes.Clone(genesisSha256[:])
	flipped[len(flipped)-1] ^= 1
	for label, admissionSha256 := range map[string][]byte{
		"another hash":              otherSha256[:],
		"the all-zero hash":         make([]byte, sha256.Size),
		"the Genesis's body's hash": bodySha256[:],
		"A_0 with one bit changed":  flipped,
	} {
		credential := world.credential(world.owner, admissionSha256)
		if err := sidecar.GkmCredentialAdmitted(state, credential); !errors.Is(err, sidecar.ErrGkmNotAdmitted) {
			t.Errorf("the first device's credential under %s: %v", label, err)
		}
		if err := check(credential); !errors.Is(err, sidecar.ErrGkmNotAdmitted) {
			t.Errorf("the first device's credential under %s at the engine's check: %v", label, err)
		}
	}

	// another device's credential under A_0 is not the first device's
	if err := sidecar.GkmCredentialAdmitted(state, world.credential(member, genesisSha256[:])); !errors.Is(err, sidecar.ErrGkmNotAdmitted) {
		t.Errorf("a member device's credential under A_0: %v", err)
	}
}

// A device a SidecarAdmit admits still names the statement's id, at the log's tail and in the rows a later base
// folds, where the first device's row keeps the Genesis's hash.
func TestADeviceASidecarAdmitAdmitsNamesTheStatementsId(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	member := testWriterDeviceOf("member device", world.owner.memberId)
	admitId := world.admitDevice(member)
	genesisSha256 := world.genesis.GenesisChain
	if admitId == genesisSha256 {
		t.Fatal("the SidecarAdmit's id is the Genesis's hash")
	}

	client := world.client()
	expect := func(label string, state *sidecar.ConfigState) {
		t.Helper()
		row := state.SidecarRow(member.sidecarId)
		if row == nil || !bytes.Equal(row.GetAdmissionSha256(), admitId[:]) {
			t.Errorf("%s: the admitted device's row names admission %x, want its SidecarAdmit's id %x", label, row.GetAdmissionSha256(), admitId)
		}
		if row := state.SidecarRow(world.owner.sidecarId); row == nil || !bytes.Equal(row.GetAdmissionSha256(), genesisSha256[:]) {
			t.Errorf("%s: the first device's row names admission %x, want A_0 %x", label, row.GetAdmissionSha256(), genesisSha256)
		}
		if err := sidecar.GkmCredentialAdmitted(state, world.credential(member, admitId[:])); err != nil {
			t.Errorf("%s: the admitted device's credential under its SidecarAdmit: %v", label, err)
		}
		if err := sidecar.GkmCredentialAdmitted(state, world.credential(world.owner, admitId[:])); !errors.Is(err, sidecar.ErrGkmNotAdmitted) {
			t.Errorf("%s: the first device's credential under another device's SidecarAdmit: %v", label, err)
		}
	}
	expect("at the tail", world.caughtUp(client))

	// a second base folds the admission into its rows, compiled from base 1's
	writer := world.writer(world.owner, client, nil, 0, sidecartest.NewFakeClock(world.clock.Now()))
	pin, err := writer.PublishBase(world.ctx, true)
	if err != nil {
		t.Fatalf("the fold: %v", err)
	}
	folded := world.caughtUp(client)
	if folded.Pin().GetVersion() != pin.GetVersion() || folded.Base() == nil || folded.Base().GetVersion() != pin.GetVersion() {
		t.Fatalf("the reader stands at %d with base %v, not at the new base %d", folded.Pin().GetVersion(), folded.Base(), pin.GetVersion())
	}
	expect("after a fold", folded)
}
