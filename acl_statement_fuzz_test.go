//go:build !js

// §22.6's acl statement target as a native fuzz target, whose seeds in testdata/fuzz/FuzzAclStatement run as ordinary
// tests under go test. Not on js: testing.F reads its corpus directory before it runs a seed, and js has none.
//
// The input picks one of the 0x11xx types, bytes merged over a well-formed body of that type about the fuzz cast, and a
// position. Decoding is total: whatever the bytes, each signer's statement, alone and as k of n, is refused with a
// refusal of the log's classes or folds into rows that build. Tampering is refused: a statement the log takes stops
// verifying once the position's byte of its signed body changes.

package sidecar

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The most body one input takes.
const aclFuzzMaxByteCount = 16 * 1024

// Lets every decision spend, so a fuzzed GrantActivate's quorum and fold run.
type aclFuzzSpendCheck struct{}

func (self aclFuzzSpendCheck) Spendable(state *AclState, decision *StoredApprovalDecision, action *StoredCanonicalAction, spender Id, pin *bridge.AuthPin, now time.Time) error {
	return nil
}

// A well-formed body of each type about the cast, which the fuzz bytes are merged over.
func aclFuzzBody(cast *aclStatementCast, signedType bridge.SignedType) proto.Message {
	var repoId, vaultId []byte
	for _, repo := range cast.fixture.rows.GetRepos() {
		switch repo.GetKind() {
		case protocol.RepoKind_REPO_KIND_GENERAL:
			repoId = repo.GetRepoId()
		case protocol.RepoKind_REPO_KIND_VAULT:
			vaultId = repo.GetRepoId()
		}
	}
	grantId := cast.fixture.rows.GetSpentGrants()[0].GetGrantId()
	suspendId := aclTestSuspendId("fuzz")
	switch signedType {
	case bridge.SignedType_SIGNED_GRANT_ACTIVATE:
		return &protocol.GrantActivate{GrantId: grantId}
	case bridge.SignedType_SIGNED_GRANT_REVOKE:
		return &bridge.GrantRevoke{GrantId: grantId}
	case bridge.SignedType_SIGNED_SUSPEND:
		return &bridge.Suspend{Subject: cast.phone.Bytes(), SuspendId: suspendId}
	case bridge.SignedType_SIGNED_UNSUSPEND:
		return &bridge.Unsuspend{Subject: cast.phone.Bytes(), SuspendId: suspendId}
	case bridge.SignedType_SIGNED_EVS_SHARE:
		return &protocol.EvsShare{RepoId: vaultId, Subject: cast.stranger.Bytes()}
	case bridge.SignedType_SIGNED_OWNER_CONFIRM:
		return &protocol.OwnerConfirm{SidecarId: cast.phone.Bytes()}
	case bridge.SignedType_SIGNED_REPO_CREATE:
		return &protocol.RepoCreate{RepoId: testConfigId("fuzz repo").Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}
	case bridge.SignedType_SIGNED_REPO_ADMIN:
		return &protocol.RepoAdmin{RepoId: repoId, SidecarId: cast.phone.Bytes(), Change: protocol.RepoAdminChange_REPO_ADMIN_CHANGE_ADD}
	case bridge.SignedType_SIGNED_REPO_GRANT:
		return &protocol.RepoGrant{RepoId: repoId, Subject: cast.stranger.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER}
	case bridge.SignedType_SIGNED_REPO_REVOKE:
		return &protocol.RepoRevoke{RepoId: repoId, Subject: cast.stranger.Bytes()}
	case bridge.SignedType_SIGNED_REPO_DELETE:
		return &protocol.RepoDelete{RepoId: repoId, DeletionId: testConfigId("fuzz deletion").Bytes()}
	case bridge.SignedType_SIGNED_REPO_RESTORE:
		return &protocol.RepoRestore{RepoId: repoId, DeletionId: testConfigId("fuzz deletion").Bytes()}
	case bridge.SignedType_SIGNED_REPO_VERSIONING:
		return &protocol.RepoVersioning{RepoId: repoId, Lock: protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED}
	case bridge.SignedType_SIGNED_AUDIT_OPT_IN:
		return &protocol.AuditOptIn{}
	}
	return &protocol.AuditOptOut{}
}

func FuzzAclStatement(f *testing.F) {
	for i := range aclFuzzStatementTypes {
		f.Add(uint8(i), []byte{}, uint16(i))
	}
	// a short subject, a stray field, a lock out of range, a truncated tag
	f.Add(uint8(2), []byte{0x12, 0x01, 0x01}, uint16(3))
	f.Add(uint8(8), []byte{0xF8, 0x07, 0x01}, uint16(7))
	f.Add(uint8(12), []byte{0x18, 0x09}, uint16(1))
	f.Add(uint8(0), []byte{0x22}, uint16(0))
	f.Fuzz(func(t *testing.T, typeIndex uint8, body []byte, flip uint16) {
		if aclFuzzMaxByteCount < len(body) {
			return
		}
		signedType := aclFuzzStatementTypes[int(typeIndex)%len(aclFuzzStatementTypes)]
		cast, state, signers := aclFuzzState(t)
		message := aclFuzzBody(cast, signedType)
		if err := (proto.UnmarshalOptions{Merge: true}).Unmarshal(body, message); err == nil {
			for _, signer := range signers {
				for _, authority := range []bool{false, true} {
					statement := &AclStatement{
						Type: signedType, Body: message, Authority: authority, N: cast.fixture.next(), TimeMs: aclTestNow.UnixMilli(),
						Signers: []ConfigSigner{{Kind: ConfigSignerSidecar, SidecarId: signer}, {Kind: ConfigSignerSidecar, SidecarId: cast.ownerDevice}},
					}
					if !authority {
						statement.Signers = statement.Signers[:1]
					}
					verdict, err := state.CheckStatement(statement, aclFuzzSpendCheck{})
					if err != nil {
						if !errors.Is(err, ErrConfigRefused) {
							t.Fatalf("%s: a refusal outside the log's classes: %v", signedType, err)
						}
						continue
					}
					rows, _, err := state.ApplyStatement(statement, verdict)
					if err != nil {
						t.Fatalf("%s: a statement its check took does not fold: %v", signedType, err)
					}
					if _, err := NewAclState(rows, cast.fixture.view); err != nil {
						t.Fatalf("%s: its rows do not build: %v", signedType, err)
					}
				}
			}
		}

		// a statement the log takes stops verifying once its signed body changes
		net := newTestConfigNet(t)
		valid := net.sign(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
			Header: net.header(), RepoId: testConfigId("tampered repo").Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
		})
		if verdict := net.log.Check(valid, net.timeMs+1000); !verdict.Accepted() {
			t.Fatalf("the untouched statement: %v", verdict.Refusal)
		}
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(valid, signed); err != nil {
			t.Fatal(err)
		}
		signed.Body[int(flip)%len(signed.Body)] ^= byte(flip>>8) | 1
		if verdict := net.log.Check(testConfigMarshal(t, signed), net.timeMs+1000); verdict.Accepted() {
			t.Fatal("a tampered statement took effect")
		}
	})
}
