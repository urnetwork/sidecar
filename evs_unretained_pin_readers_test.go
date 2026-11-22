//go:build !ios_extension

// QD-1178 for the readers the network extensions' leg links none of (evs_unretained_pin_test.go has the head reader's
// own): a format-2 versionless version whose statement is pinned before two bases reads where it sits, the repo's kind
// its creation's and its lock at the pin unjudged, and the two rows that turn on the lock take a version either way
// while it is unjudged; a push's provenance, its git committer's key and its signed import check under the key the
// oldest retained rows give its signer, an import's admin rule not judged; and a DROP's signer is not judged beyond
// what the repo's kind forbids.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A versionless version written before two bases reads on a format-2 reader that read it then and on a new format-2
// device started at the newest base, neither ignored nor refused, with no alarm.
func TestEvsFormat2VersionlessVersionWrittenBeforeTwoBasesReads(t *testing.T) {
	retained := newEvsTestRetainedWorld(t)
	written := retained.net.log.Pin()
	retained.push(&evsTestChange{path: "big.bin", content: []byte("one"), segment: true,
		format2: evsTestVersionless(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, "one")})
	device := retained.follower(t, "format 2 device")
	device.client.EnableFormat2Reader()
	if _, err := evsTestVerifiedPath(t, device, retained.world, nil, "big.bin", 0); err != nil {
		t.Fatal(err)
	}

	retained.foldPast(t, written)
	newDevice, _ := retained.started(t, "new format 2 device")
	newDevice.client.EnableFormat2Reader()
	for label, reader := range map[string]*evsTestClient{"the device that read it": device, "the new device": newDevice} {
		verified, err := evsTestVerifiedPath(t, reader, retained.world, nil, "big.bin", 0)
		if err != nil {
			t.Errorf("%s: %v", label, err)
			continue
		}
		if verified.Entry.GetVersioning() != uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS) || verified.Ignored || verified.Absent {
			t.Errorf("%s: verified %+v", label, verified)
		}
		evsTestRequireNoAlarm(t, label, reader)
	}
}

// A lock unjudged at a push's pin takes the version under both rows that turn on it: a versionless version, which a
// lock standing at the pin refuses, and a kept object on ur/lfs, which only a locked repo's store writes.
func TestEvsCheckVersioningTakesAVersionWhereTheLockIsUnjudged(t *testing.T) {
	general := func(reserved EvsReservedRef, locked bool, unjudged bool) *EvsVersioningContext {
		return &EvsVersioningContext{
			RepoKind: protocol.RepoKind_REPO_KIND_GENERAL, RefKind: protocol.EvsRefKind_EVS_REF_SHARED,
			RefMode: protocol.EvsRefMode_EVS_REF_FILE, Reserved: reserved, Locked: locked, LockUnjudged: unjudged,
		}
	}
	versionless := &protocol.EvsEntryVersion{Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), Versioning: uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)}
	kept := &protocol.EvsEntryVersion{Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE)}
	object := [][]byte{[]byte("objects"), []byte("ab"), []byte("cdef")}
	cases := []struct {
		label   string
		context *EvsVersioningContext
		names   [][]byte
		entry   *protocol.EvsEntryVersion
		want    error
	}{
		{label: "versionless under a standing lock", context: general(EvsReservedRefNone, true, false), names: [][]byte{[]byte("big.bin")}, entry: versionless, want: ErrEvsVersioningRefused},
		{label: "versionless, the lock unjudged", context: general(EvsReservedRefNone, false, true), names: [][]byte{[]byte("big.bin")}, entry: versionless},
		{label: "a kept lfs object, unlocked", context: general(EvsReservedRefLfs, false, false), names: object, entry: kept, want: ErrEvsVersionIgnored},
		{label: "a kept lfs object, locked", context: general(EvsReservedRefLfs, true, false), names: object, entry: kept},
		{label: "a kept lfs object, the lock unjudged", context: general(EvsReservedRefLfs, false, true), names: object, entry: kept},
	}
	for _, c := range cases {
		err := EvsCheckVersioning(c.context, c.names, c.entry)
		if (c.want == nil && err != nil) || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%s: %v, want %v", c.label, err, c.want)
		}
	}
}

// A push made for an agent before two bases reads its provenance verified on a device that never read it then, the
// agent's certificate checked under the key the oldest retained rows give the writer.
func TestEvsProvenanceOfAPushPinnedBeforeTwoBasesVerifies(t *testing.T) {
	retained := newEvsTestRetainedWorld(t)
	writer := retained.writerOf(t, retained.writer)
	signer := &evsTestSigner{sidecarId: retained.writer.sidecarId, privateKey: retained.writer.key}
	agent := newEvsTestAgent(t, signer, "before the bases", writer.test.clock.Now().Add(24*time.Hour))
	writer.test.client.args.SignProvenance = agent.signer(false)
	writer.server.know("notes.md")
	written := retained.net.log.Pin()
	ctx := context.Background()
	if _, err := writer.repo.WritePaths(ctx, &EvsWritePathsArgs{AgentId: &agent.agentId, Writes: []*EvsPathWrite{
		{Path: "notes.md", Content: bytes.NewReader([]byte("an agent's notes"))},
	}}); err != nil {
		t.Fatal(err)
	}

	retained.foldPast(t, written)
	reader := retained.follower(t, "provenance reader")
	reader.client.args.Gkm = writer.gkm
	reader.client.args.Transport = &evsTestTransport{handler: writer.server}
	reader.client.http.transport = wrapSidecarApiTransport(reader.client.args.Transport)
	read, err := reader.client.Repo(retained.repoId).Provenance(ctx, &EvsReadArgs{Path: "notes.md"})
	if err != nil || read.State != EvsProvenanceVerified || read.AgentId == nil || *read.AgentId != agent.agentId || read.Refused {
		t.Fatalf("the agent's push: %+v %v", read, err)
	}
	evsTestRequireNoAlarm(t, "the provenance reader", reader)
}

// A statement on the world's repo pinned at pin, by signer, for the repo repoId names.
func evsTestRetainedStatement(t *testing.T, retained *evsTestRetainedWorld, label string, repoId Id, pin *bridge.AuthPin, signer *evsTestSigner) *EvsStatement {
	t.Helper()
	plan := evsTestPlan(t, signer, label, 1)
	plan.RepoId, plan.RefId, plan.Auth = repoId, retained.world.refId, pin
	built, err := NewEvsStatementBuilder(signer.sign).Build(plan)
	if err != nil {
		t.Fatal(err)
	}
	return built.Statement
}

// A push pinned before two bases gives its git committer check the key the oldest retained rows give its signer, and
// one by a signer they never admitted is refused; its signed import is taken on its signature under that key, though
// its signer is no repo admin, which the state at a retained pin refuses and the one at this pin can no longer judge,
// and a forged import is refused.
func TestEvsGitKeysOfAPushPinnedBeforeTwoBases(t *testing.T) {
	retained := newEvsTestRetainedWorld(t)
	written := retained.net.log.Pin()
	writerSigner := &evsTestSigner{sidecarId: retained.writer.sidecarId, privateKey: retained.writer.key}
	push := evsTestRetainedStatement(t, retained, "git push", retained.repoId, written, writerSigner).Push
	importOf := func(signer *evsTestSigner) []byte {
		body, err := proto.Marshal(&protocol.EvsImport{RepoId: retained.repoId.Bytes(), RefId: retained.world.refId.Bytes(), Count: 1})
		if err != nil {
			t.Fatal(err)
		}
		signed, err := proto.Marshal(&bridge.Signed{
			Body: body, SignerId: signer.sidecarId.Bytes(), Type: uint32(bridge.SignedType_SIGNED_EVS_IMPORT),
			Signature: ed25519.Sign(signer.privateKey, bridge.SignedBytes(evsImportPurpose, bridge.SignedType_SIGNED_EVS_IMPORT, body)),
		})
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	reader := retained.follower(t, "git reader")
	verifier := reader.client.verifier
	if _, err := verifier.verifyImport(importOf(writerSigner), retained.repoId, push); !errors.Is(err, ErrEvsStatementRefused) {
		t.Errorf("an import by no repo admin at a retained pin: %v", err)
	}

	retained.foldPast(t, written)
	if key, err := verifier.signerIdentityKey(push); err != nil || !bytes.Equal(key, retained.writer.publicKey()) {
		t.Errorf("the committer's key: %x %v", key, err)
	}
	stranger := newEvsTestSigner("stranger")
	strangers := evsTestRetainedStatement(t, retained, "a stranger's push", retained.repoId, written, stranger).Push
	if _, err := verifier.signerIdentityKey(strangers); !errors.Is(err, ErrConfigSignerNotAdmitted) {
		t.Errorf("a stranger's committer key: %v", err)
	}
	if _, err := verifier.verifyImport(importOf(writerSigner), retained.repoId, push); err != nil {
		t.Errorf("an import pinned before the window: %v", err)
	}
	forged := &evsTestSigner{sidecarId: retained.writer.sidecarId, privateKey: stranger.privateKey}
	if _, err := verifier.verifyImport(importOf(forged), retained.repoId, push); !errors.Is(err, ErrEvsStatementRefused) {
		t.Errorf("a forged import pinned before the window: %v", err)
	}
}

// A DROP pinned before two bases is not judged on its signer, no repo admin, whom the state at a retained pin refuses;
// one in the config repo is still refused, a config repo's kind being its creation's.
func TestEvsDropSignerOfADropPinnedBeforeTwoBases(t *testing.T) {
	retained := newEvsTestRetainedWorld(t)
	written := retained.net.log.Pin()
	writerSigner := &evsTestSigner{sidecarId: retained.writer.sidecarId, privateKey: retained.writer.key}
	drop := evsTestRetainedStatement(t, retained, "drop", retained.repoId, written, writerSigner)
	configRepoId := retained.net.configRepoId()
	configDrop := evsTestRetainedStatement(t, retained, "config drop", configRepoId, written, writerSigner)
	if repo := retained.net.log.State().Repo(configRepoId); repo.GetKind() != protocol.RepoKind_REPO_KIND_CONFIG {
		t.Fatalf("the config repo's row: %v", repo)
	}
	reader := retained.follower(t, "drop reader")
	if err := evsDropSignedBy(reader.client.verifier, drop, retained.repoId, false); !errors.Is(err, ErrEvsStatementRefused) {
		t.Errorf("a DROP by no repo admin at a retained pin: %v", err)
	}

	retained.foldPast(t, written)
	if err := evsDropSignedBy(reader.client.verifier, drop, retained.repoId, false); err != nil {
		t.Errorf("a DROP pinned before the window: %v", err)
	}
	if err := evsDropSignedBy(reader.client.verifier, configDrop, configRepoId, false); !errors.Is(err, ErrEvsStatementRefused) {
		t.Errorf("a DROP in the config repo pinned before the window: %v", err)
	}
}
