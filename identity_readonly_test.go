package sidecar

// CORE-M4-01: a read_only sidecar's Sign refuses at once what every verifier refuses from it (§7.9's read_only row), and
// signs what D-TEAM-24 leaves it: its own sign-out, ReaderKeys and KeyPackage credentials, `read` entries and their
// receipt deposits.

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Admits the act sidecar in its authority with capabilities.
func admitTestActSidecar(t *testing.T, sidecar *Sidecar, authority *testActAuthority, capabilities uint32) Id {
	t.Helper()
	identity := sidecar.currentIdentity()
	if identity == nil {
		t.Fatal("no identity")
	}
	authority.stateLock.Lock()
	defer authority.stateLock.Unlock()
	authority.sidecars[identity.SidecarId] = &AclSidecar{
		Row: &bridge.SidecarRow{
			SidecarId:    identity.SidecarId.Bytes(),
			AdmittedAt:   1,
			Capabilities: capabilities,
			MemberId:     NewId().Bytes(),
		},
	}
	return identity.SidecarId
}

// A body of message, marshalled.
func testReadOnlyBody(t *testing.T, message proto.Message) []byte {
	t.Helper()
	body, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// One statement Sign is asked for, and whether a read_only device may sign it.
type testReadOnlySign struct {
	name       string
	signedType bridge.SignedType
	body       []byte
	allowed    bool
}

// What a read_only device signs and what it is refused, for sidecarId.
func testReadOnlySigns(t *testing.T, sidecarId Id) []testReadOnlySign {
	other := NewId()
	return []testReadOnlySign{
		{name: "its own sign-out", signedType: bridge.SignedType_SIGNED_SIDECAR_REVOKE, body: testReadOnlyBody(t, &bridge.SidecarRevoke{SidecarId: sidecarId.Bytes()}), allowed: true},
		{name: "its ReaderKey", signedType: bridge.SignedType_SIGNED_READER_KEY, body: []byte("reader-key"), allowed: true},
		{name: "a KeyPackage's credential", signedType: bridge.SignedType_SIGNED_UR_MLS_CREDENTIAL, body: []byte("credential"), allowed: true},
		{name: "a read entry", signedType: bridge.SignedType_SIGNED_RECORD_HEADER, body: testReadOnlyBody(t, &protocol.RecordHeader{
			Kind: uint32(RecordKindRead), WriterSidecarId: sidecarId.Bytes()}), allowed: true},
		{name: "a receipt deposit", signedType: bridge.SignedType_SIGNED_EVS_PUSH, body: testReadOnlyBody(t, &protocol.EvsPush{
			RefKind: uint32(protocol.EvsRefKind_EVS_REF_DEPOSIT), OwnerSidecarId: sidecarId.Bytes(), SignerSidecarId: sidecarId.Bytes()}), allowed: true},
		{name: "another's revocation", signedType: bridge.SignedType_SIGNED_SIDECAR_REVOKE, body: testReadOnlyBody(t, &bridge.SidecarRevoke{SidecarId: other.Bytes()}), allowed: false},
		{name: "an admission", signedType: bridge.SignedType_SIGNED_SIDECAR_ADMIT, body: testReadOnlyBody(t, &protocol.SidecarAdmit{SidecarId: other.Bytes()}), allowed: false},
		{name: "an OwnerConfirm", signedType: bridge.SignedType_SIGNED_OWNER_CONFIRM, body: testReadOnlyBody(t, &protocol.OwnerConfirm{SidecarId: other.Bytes()}), allowed: false},
		{name: "an EvsShare", signedType: bridge.SignedType_SIGNED_EVS_SHARE, body: []byte("share"), allowed: false},
		{name: "a KeyRegister", signedType: bridge.SignedType_SIGNED_KEY_REGISTER, body: []byte("key"), allowed: false},
		{name: "a RecoveryBind", signedType: bridge.SignedType_SIGNED_RECOVERY_BIND, body: []byte("bind"), allowed: false},
		{name: "an IndexerSet", signedType: bridge.SignedType_SIGNED_INDEXER_SET, body: []byte("indexer"), allowed: false},
		{name: "a grant", signedType: bridge.SignedType_SIGNED_GRANT_ACTIVATE, body: []byte("grant"), allowed: false},
		{name: "a bridge route", signedType: bridge.SignedType_SIGNED_BRIDGE_ROUTE, body: []byte("route"), allowed: false},
		{name: "a ReaderWrap", signedType: bridge.SignedType_SIGNED_READER_WRAP, body: []byte("wrap"), allowed: false},
		{name: "a DelegationWrap", signedType: bridge.SignedType_SIGNED_DELEGATION_WRAP, body: []byte("wrap"), allowed: false},
		{name: "a GenRotate", signedType: bridge.SignedType_SIGNED_GEN_ROTATE, body: []byte("rotate"), allowed: false},
		{name: "a GroupForm", signedType: bridge.SignedType_SIGNED_GROUP_FORM, body: []byte("form"), allowed: false},
		{name: "an approval", signedType: bridge.SignedType_SIGNED_APPROVAL_DECISION, body: []byte("decision"), allowed: false},
		{name: "a head on a shared ref", signedType: bridge.SignedType_SIGNED_EVS_PUSH, body: testReadOnlyBody(t, &protocol.EvsPush{
			RefKind: uint32(protocol.EvsRefKind_EVS_REF_SHARED), SignerSidecarId: sidecarId.Bytes()}), allowed: false},
		{name: "a deposit to another's ref", signedType: bridge.SignedType_SIGNED_EVS_PUSH, body: testReadOnlyBody(t, &protocol.EvsPush{
			RefKind: uint32(protocol.EvsRefKind_EVS_REF_DEPOSIT), OwnerSidecarId: other.Bytes(), SignerSidecarId: sidecarId.Bytes()}), allowed: false},
		{name: "another kind of record entry", signedType: bridge.SignedType_SIGNED_RECORD_HEADER, body: testReadOnlyBody(t, &protocol.RecordHeader{
			Kind: uint32(RecordKindClaim), WriterSidecarId: sidecarId.Bytes()}), allowed: false},
		{name: "a socket registration", signedType: bridge.SignedType_SIGNED_SOCKET_REGISTRATION, body: []byte("registration"), allowed: false},
		{name: "a TLS key attestation", signedType: bridge.SignedType_SIGNED_TLS_KEY_ATTESTATION, body: []byte("attestation"), allowed: false},
		{name: "a directory card", signedType: bridge.SignedType_SIGNED_DIRECTORY_CARD, body: []byte("card"), allowed: false},
	}
}

// §7.9's read_only row: a device admitted read_only is refused locally, with ErrSidecarSignReadOnly and before any key
// is read, what verifiers refuse from it, and signs what they accept; an act of a refused statement signs and posts
// nothing.
func TestReadOnlyRefusedLocally(t *testing.T) {
	sidecar, authority, deltaApi := newActTestSidecar(t)
	sidecarId := admitTestActSidecar(t, sidecar, authority, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY))

	for _, sign := range testReadOnlySigns(t, sidecarId) {
		purpose, ok := sidecarIdentitySignedPurpose(sign.signedType)
		if !ok {
			t.Fatalf("%s: the identity key signs no type %#x", sign.name, int32(sign.signedType))
		}
		signed, err := sidecar.Sign(purpose, sign.signedType, sign.body, nil)
		switch {
		case sign.allowed && err != nil:
			t.Errorf("%s: refused: %v", sign.name, err)
		case !sign.allowed && !errors.Is(err, ErrSidecarSignReadOnly):
			t.Errorf("%s: err %v, want a read_only refusal", sign.name, err)
		case !sign.allowed && !errors.Is(err, ErrSidecarSignRefused):
			t.Errorf("%s: a read_only refusal is not a sign refusal", sign.name)
		case !sign.allowed && signed != nil:
			t.Errorf("%s: signed anyway", sign.name)
		}
	}

	act, err := sidecar.newAct(SidecarActConfirmed)
	if err != nil {
		t.Fatal(err)
	}
	if err := act.Add(bridge.SignedType_SIGNED_OWNER_CONFIRM, &protocol.OwnerConfirm{SidecarId: NewId().Bytes()}); err != nil {
		t.Fatal(err)
	}
	if _, err := act.Run(context.Background(), nil); !errors.Is(err, ErrSidecarSignReadOnly) {
		t.Errorf("the act ran: %v", err)
	}
	if posts := deltaApi.postsSoFar(); len(posts) != 0 {
		t.Errorf("%d posts from a read_only device's act", len(posts))
	}
	if pendings, err := sidecar.pendingStatements(); err != nil || len(pendings) != 0 {
		t.Errorf("%d kept, %v", len(pendings), err)
	}
}

// The refusal is a read_only device's only: one admitted without read_only signs every statement, which verifiers judge
// by their own rules.
func TestNotReadOnlySignsStatements(t *testing.T) {
	sidecar, authority, _ := newActTestSidecar(t)
	sidecarId := admitTestActSidecar(t, sidecar, authority, 0)
	for _, sign := range testReadOnlySigns(t, sidecarId) {
		purpose, _ := sidecarIdentitySignedPurpose(sign.signedType)
		if _, err := sidecar.Sign(purpose, sign.signedType, sign.body, nil); err != nil {
			t.Errorf("%s: %v", sign.name, err)
		}
	}
}
