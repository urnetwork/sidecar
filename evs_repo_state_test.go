//go:build !sidecar_http

package sidecar

import (
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A repo/ object in a state, with the deletion fields that state carries.
func evsTestRepoObject(state protocol.EvsRepoState, deletionLabel string) *protocol.EvsRepoObject {
	object := &protocol.EvsRepoObject{
		RepoId:    evsTestId("repo").Bytes(),
		Kind:      protocol.RepoKind_REPO_KIND_GENERAL,
		State:     state,
		StateMs:   1,
		Format:    EvsRepoFormat1,
		NetworkId: evsTestId("network").Bytes(),
	}
	if deletionLabel != "" {
		object.DeletionId = evsTestId(deletionLabel).Bytes()
		object.StateMs = 2
	}
	if state == protocol.EvsRepoState_EVS_REPO_DELETED {
		object.StateSigner = evsTestId("signer").Bytes()
	}
	return object
}

// §11.12's state machine: the edges it takes, each state's deletion fields, and nothing else.
func TestEvsRepoTransitionsTakeOnlyTheMachinesEdges(t *testing.T) {
	keying := evsTestRepoObject(protocol.EvsRepoState_EVS_REPO_KEYING, "")
	active := evsTestRepoObject(protocol.EvsRepoState_EVS_REPO_ACTIVE, "")
	deleted := evsTestRepoObject(protocol.EvsRepoState_EVS_REPO_DELETED, "deletion 1")
	shredding := evsTestRepoObject(protocol.EvsRepoState_EVS_REPO_SHREDDING, "deletion 1")
	shreddingOther := evsTestRepoObject(protocol.EvsRepoState_EVS_REPO_SHREDDING, "deletion 2")
	shredded := evsTestRepoObject(protocol.EvsRepoState_EVS_REPO_SHREDDED, "deletion 1")
	shreddedOther := evsTestRepoObject(protocol.EvsRepoState_EVS_REPO_SHREDDED, "deletion 2")
	cases := []struct {
		name  string
		prior *protocol.EvsRepoObject
		next  *protocol.EvsRepoObject
		ok    bool
	}{
		{name: "activate", prior: keying, next: active, ok: true},
		{name: "delete", prior: active, next: deleted, ok: true},
		{name: "delete now", prior: active, next: shredding, ok: true},
		{name: "restore", prior: deleted, next: active, ok: true},
		{name: "start", prior: deleted, next: shredding, ok: true},
		{name: "a newer now", prior: deleted, next: shreddingOther, ok: true},
		{name: "tombstone", prior: shredding, next: shredded, ok: true},
		{name: "another deletion's tombstone", prior: shredding, next: shreddedOther},
		{name: "keying to deleted", prior: keying, next: deleted},
		{name: "back to keying", prior: active, next: keying},
		{name: "a shred restored", prior: shredding, next: active},
		{name: "a tombstone restored", prior: shredded, next: active},
		{name: "active straight to a tombstone", prior: active, next: shredded},
	}
	for _, c := range cases {
		err := CheckEvsRepoTransition(c.prior, c.next)
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrEvsRepoTransition)) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	unsigned := evsTestRepoObject(protocol.EvsRepoState_EVS_REPO_DELETED, "deletion 1")
	unsigned.StateSigner = nil
	if err := CheckEvsRepoTransition(active, unsigned); !errors.Is(err, ErrEvsRepoTransition) {
		t.Errorf("deleted with no signer: %v", err)
	}
	activeNamingDeletion := evsTestRepoObject(protocol.EvsRepoState_EVS_REPO_ACTIVE, "deletion 1")
	if err := CheckEvsRepoTransition(deleted, activeNamingDeletion); !errors.Is(err, ErrEvsRepoTransition) {
		t.Errorf("active naming a deletion: %v", err)
	}
	otherKind := evsTestRepoObject(protocol.EvsRepoState_EVS_REPO_ACTIVE, "")
	otherKind.Kind = protocol.RepoKind_REPO_KIND_RECORD
	if err := CheckEvsRepoTransition(keying, otherKind); !errors.Is(err, ErrEvsRepoTransition) {
		t.Errorf("a kind changed: %v", err)
	}
	format2 := evsTestRepoObject(protocol.EvsRepoState_EVS_REPO_ACTIVE, "")
	format2.Format = EvsRepoFormat2
	if err := CheckEvsRepoTransition(active, format2); err != nil {
		t.Errorf("the format rising: %v", err)
	}
	if err := CheckEvsRepoTransition(format2, active); !errors.Is(err, ErrEvsRepoTransition) {
		t.Errorf("the format falling: %v", err)
	}
}

// repo/'s codec: what it writes it reads back, and ids of any width but 16 or 0 are refused.
func TestEvsRepoObjectCodecHoldsItsShape(t *testing.T) {
	object := evsTestRepoObject(protocol.EvsRepoState_EVS_REPO_DELETED, "deletion 1")
	objectBytes, err := MarshalEvsRepoObject(object)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseEvsRepoObject(evsTestId("repo"), objectBytes)
	if err != nil || Id(parsed.GetDeletionId()) != evsTestId("deletion 1") {
		t.Fatalf("%v %v", parsed, err)
	}
	if _, err := ParseEvsRepoObject(evsTestId("other repo"), objectBytes); !errors.Is(err, ErrEvsRepoInvalid) {
		t.Errorf("another repo's: %v", err)
	}
	object.StateSigner = []byte("short")
	if _, err := MarshalEvsRepoObject(object); !errors.Is(err, ErrEvsRepoInvalid) {
		t.Errorf("a signer of 5 bytes: %v", err)
	}
	unknownKind := evsTestRepoObject(protocol.EvsRepoState_EVS_REPO_ACTIVE, "")
	unknownKind.Kind = protocol.RepoKind(99)
	if _, err := MarshalEvsRepoObject(unknownKind); !errors.Is(err, ErrEvsRepoInvalid) {
		t.Errorf("an unknown kind: %v", err)
	}
	if !EvsRepoKindKnown(protocol.RepoKind_REPO_KIND_DIRECTORY) || EvsRepoKindKnown(protocol.RepoKind_REPO_KIND_UNSPECIFIED) ||
		!EvsRepoKindOwnerBound(protocol.RepoKind_REPO_KIND_SECRET) || EvsRepoKindOwnerBound(protocol.RepoKind_REPO_KIND_DIRECTORY) {
		t.Error("the kinds table")
	}
}
