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
		{"its own sign-out", bridge.SignedType_SIGNED_SIDECAR_REVOKE, testReadOnlyBody(t, &bridge.SidecarRevoke{SidecarId: sidecarId.Bytes()}), true},
		{"its ReaderKey", bridge.SignedType_SIGNED_READER_KEY, []byte("reader-key"), true},
		{"a KeyPackage's credential", bridge.SignedType_SIGNED_UR_MLS_CREDENTIAL, []byte("credential"), true},
		{"a read entry", bridge.SignedType_SIGNED_RECORD_HEADER, testReadOnlyBody(t, &protocol.RecordHeader{
			Kind: uint32(RecordKindRead), WriterSidecarId: sidecarId.Bytes()}), true},
		{"a receipt deposit", bridge.SignedType_SIGNED_EVS_PUSH, testReadOnlyBody(t, &protocol.EvsPush{
			RefKind: uint32(protocol.EvsRefKind_EVS_REF_DEPOSIT), OwnerSidecarId: sidecarId.Bytes(), SignerSidecarId: sidecarId.Bytes()}), true},

		{"another's revocation", bridge.SignedType_SIGNED_SIDECAR_REVOKE, testReadOnlyBody(t, &bridge.SidecarRevoke{SidecarId: other.Bytes()}), false},
		{"an admission", bridge.SignedType_SIGNED_SIDECAR_ADMIT, testReadOnlyBody(t, &protocol.SidecarAdmit{SidecarId: other.Bytes()}), false},
		{"an OwnerConfirm", bridge.SignedType_SIGNED_OWNER_CONFIRM, testReadOnlyBody(t, &protocol.OwnerConfirm{SidecarId: other.Bytes()}), false},
		{"an EvsShare", bridge.SignedType_SIGNED_EVS_SHARE, []byte("share"), false},
		{"a KeyRegister", bridge.SignedType_SIGNED_KEY_REGISTER, []byte("key"), false},
		{"a RecoveryBind", bridge.SignedType_SIGNED_RECOVERY_BIND, []byte("bind"), false},
		{"an IndexerSet", bridge.SignedType_SIGNED_INDEXER_SET, []byte("indexer"), false},
		{"a grant", bridge.SignedType_SIGNED_GRANT_ACTIVATE, []byte("grant"), false},
		{"a bridge route", bridge.SignedType_SIGNED_BRIDGE_ROUTE, []byte("route"), false},
		{"a ReaderWrap", bridge.SignedType_SIGNED_READER_WRAP, []byte("wrap"), false},
		{"a DelegationWrap", bridge.SignedType_SIGNED_DELEGATION_WRAP, []byte("wrap"), false},
		{"a GenRotate", bridge.SignedType_SIGNED_GEN_ROTATE, []byte("rotate"), false},
		{"a GroupForm", bridge.SignedType_SIGNED_GROUP_FORM, []byte("form"), false},
		{"an approval", bridge.SignedType_SIGNED_APPROVAL_DECISION, []byte("decision"), false},
		{"a head on a shared ref", bridge.SignedType_SIGNED_EVS_PUSH, testReadOnlyBody(t, &protocol.EvsPush{
			RefKind: uint32(protocol.EvsRefKind_EVS_REF_SHARED), SignerSidecarId: sidecarId.Bytes()}), false},
		{"a deposit to another's ref", bridge.SignedType_SIGNED_EVS_PUSH, testReadOnlyBody(t, &protocol.EvsPush{
			RefKind: uint32(protocol.EvsRefKind_EVS_REF_DEPOSIT), OwnerSidecarId: other.Bytes(), SignerSidecarId: sidecarId.Bytes()}), false},
		{"another kind of record entry", bridge.SignedType_SIGNED_RECORD_HEADER, testReadOnlyBody(t, &protocol.RecordHeader{
			Kind: uint32(RecordKindClaim), WriterSidecarId: sidecarId.Bytes()}), false},
		{"a socket registration", bridge.SignedType_SIGNED_SOCKET_REGISTRATION, []byte("registration"), false},
		{"a TLS key attestation", bridge.SignedType_SIGNED_TLS_KEY_ATTESTATION, []byte("attestation"), false},
		{"a directory card", bridge.SignedType_SIGNED_DIRECTORY_CARD, []byte("card"), false},
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
