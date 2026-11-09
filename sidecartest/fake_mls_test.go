// FakeMls refuses what the subset refuses, an Update proposal and a commit by a removed leaf among them, derives each
// epoch's KEK only for that epoch's leaves, and frames a member's commit so ParseMlsHeader reads it as gkm will a
// real one's. mlssuite runs the rest of the seam's behavior on it.

package sidecartest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The repo every fake group here keys.
var fakeMlsTestRepoId = sidecar.Id{0x46, 0x4d}

// A group of count engines, all leaves at epoch 1 by one Add-only commit.
func fakeMlsTestGroup(t *testing.T, count int) ([]*FakeMls, []sidecar.MlsGroup) {
	t.Helper()
	world := NewFakeMlsWorld()
	engines := []*FakeMls{}
	for index := 0; index < count; index += 1 {
		engines = append(engines, world.Engine(sidecar.NewId(), []byte{byte(index)}))
	}
	creator, err := engines[0].CreateGroup(sidecar.NewId(), &sidecar.MlsUrGroup{RepoId: fakeMlsTestRepoId, Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	if err != nil {
		t.Fatal(err)
	}
	adds := [][]byte{}
	for _, engine := range engines[1:] {
		keyPackage, err := engine.CreateKeyPackage(false)
		if err != nil {
			t.Fatal(err)
		}
		adds = append(adds, keyPackage.Encoded)
	}
	staged, err := creator.Commit(&sidecar.MlsCommitArgs{Adds: adds, AuthenticatedData: []byte("add")})
	if err != nil {
		t.Fatal(err)
	}
	groupInfo, err := staged.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := staged.Adopt()
	if err != nil {
		t.Fatal(err)
	}
	groups := []sidecar.MlsGroup{adopted}
	for _, engine := range engines[1:] {
		pending, err := engine.JoinWelcome(staged.Welcome())
		if err != nil {
			t.Fatal(err)
		}
		joined, err := pending.Complete(groupInfo)
		if err != nil {
			t.Fatal(err)
		}
		groups = append(groups, joined)
	}
	return engines, groups
}

// A PrivateMessage of contentType at the group's epoch, framed as RFC 9420 §6.3 fixes it.
func fakeMlsTestPrivateMessage(group sidecar.MlsGroup, contentType uint8) []byte {
	message := fakeMlsAppendHeader(nil, fakeMlsWireFormatPrivate)
	message = fakeMlsAppendVector(message, group.GroupId().Bytes())
	message = binary.BigEndian.AppendUint64(message, group.Epoch())
	message = append(message, contentType)
	message = fakeMlsAppendVector(message, nil)
	message = fakeMlsAppendVector(message, make([]byte, 16))
	return fakeMlsAppendVector(message, make([]byte, 32))
}

// Standalone proposals are refused when processed (§10.4), so an Update's framing, at the right group and epoch,
// stages nothing, and neither does application data.
func TestFakeMlsRefusesAnUpdateProposal(t *testing.T) {
	_, groups := fakeMlsTestGroup(t, 2)
	for name, contentType := range map[string]uint8{"a proposal": 2, "application data": 1} {
		if _, err := groups[1].Process(fakeMlsTestPrivateMessage(groups[0], contentType)); !errors.Is(err, errFakeMlsRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if groups[1].Epoch() != 1 {
		t.Error("a refused message moved the group")
	}
}

// A leaf a commit removed commits nothing after: its own engine refuses once it holds the removal, and a commit it
// sends from its old epoch is refused by every member past it, as is one framed as a member's but made by no leaf of
// its epoch.
func TestFakeMlsRefusesACommitByARemovedLeaf(t *testing.T) {
	engines, groups := fakeMlsTestGroup(t, 3)
	removed := groups[2].Self()
	remove, err := groups[0].Commit(&sidecar.MlsCommitArgs{Removes: []uint32{removed.LeafIndex}, Path: true, AuthenticatedData: []byte("remove")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remove.Adopt(); err != nil {
		t.Fatal(err)
	}
	processed, err := groups[1].Process(remove.Message())
	if err != nil {
		t.Fatal(err)
	}
	member, err := processed.Adopt()
	if err != nil {
		t.Fatal(err)
	}

	// Still at epoch 1, the removed leaf commits there: a member at epoch 2 refuses it.
	stale, err := groups[2].Commit(&sidecar.MlsCommitArgs{Path: true, AuthenticatedData: []byte("stale")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Process(stale.Message()); !errors.Is(err, errFakeMlsRefused) {
		t.Errorf("a removed leaf's stale commit: %v", err)
	}

	// Once it processes its removal it holds nothing, and commits nothing.
	removal, err := groups[2].Process(remove.Message())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := removal.Adopt(); !errors.Is(err, sidecar.ErrMlsNotMember) {
		t.Errorf("adopting its removal: %v", err)
	}
	if _, err := groups[2].Commit(&sidecar.MlsCommitArgs{Path: true, AuthenticatedData: []byte("after")}); !errors.Is(err, sidecar.ErrMlsGroupUnknown) {
		t.Errorf("committing after its removal: %v", err)
	}
	if _, err := engines[2].LoadGroup(groups[0].GroupId()); !errors.Is(err, sidecar.ErrMlsGroupUnknown) {
		t.Errorf("loading after its removal: %v", err)
	}

	// An external commit relabeled a member's commit, by a sender epoch 2 does not hold, is refused.
	adoptedGroupInfo, err := member.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	external, err := engines[2].JoinExternal(adoptedGroupInfo, &sidecar.MlsCommitArgs{Path: true, AuthenticatedData: []byte("rejoin")})
	if err != nil {
		t.Fatal(err)
	}
	reader := &fakeMlsReader{remaining: external.Message()}
	reader.uint16()
	reader.uint16()
	reader.vector()
	reader.uint64()
	reader.uint8()
	reader.vector()
	reader.uint8()
	handle := reader.vector()
	relabeled := fakeMlsAppendHeader(nil, fakeMlsWireFormatPrivate)
	relabeled = fakeMlsAppendVector(relabeled, member.GroupId().Bytes())
	relabeled = binary.BigEndian.AppendUint64(relabeled, member.Epoch())
	relabeled = append(relabeled, fakeMlsContentTypeCommit)
	relabeled = fakeMlsAppendVector(relabeled, []byte("rejoin"))
	relabeled = fakeMlsAppendVector(relabeled, make([]byte, 16))
	relabeled = fakeMlsAppendVector(relabeled, handle)
	if _, err := member.Process(relabeled); !errors.Is(err, errFakeMlsRefused) {
		t.Errorf("an external commit framed as a member's: %v", err)
	}
	// Framed as what it is, the same commit is an external join a member may judge.
	if _, err := member.Process(external.Message()); err != nil {
		t.Errorf("the external commit as framed: %v", err)
	}
}

// KEK_e reaches exactly the epoch's leaves: a removed leaf derives the new epoch's from neither the staged commit nor
// anything else, and a leaf added at epoch 1 derives epoch 1's alike with the others.
func TestFakeMlsDerivesKeksOnlyForMembers(t *testing.T) {
	_, groups := fakeMlsTestGroup(t, 3)
	first, err := sidecar.MlsKek(groups[0], fakeMlsTestRepoId)
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range groups[1:] {
		kek, err := sidecar.MlsKek(group, fakeMlsTestRepoId)
		if err != nil || !bytes.Equal(kek, first) {
			t.Errorf("a leaf's KEK differs: %v", err)
		}
	}
	other, _ := sidecar.MlsKek(groups[0], sidecar.Id{0x99})
	if bytes.Equal(other, first) {
		t.Error("two repos share a KEK")
	}

	remove, err := groups[0].Commit(&sidecar.MlsCommitArgs{Removes: []uint32{groups[2].Self().LeafIndex}, Path: true, AuthenticatedData: []byte("remove")})
	if err != nil {
		t.Fatal(err)
	}
	next, err := sidecar.MlsKek(remove, fakeMlsTestRepoId)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(next, first) {
		t.Error("the new epoch keeps the old KEK")
	}
	removal, err := groups[2].Process(remove.Message())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sidecar.MlsKek(removal, fakeMlsTestRepoId); !errors.Is(err, sidecar.ErrMlsNotMember) {
		t.Errorf("a removed leaf's KEK of the new epoch: %v", err)
	}
	if removal.EpochAuthenticator() != nil {
		t.Error("a removed leaf reads the new epoch_authenticator")
	}
	if _, err := removal.GroupInfo(); !errors.Is(err, sidecar.ErrMlsNotMember) {
		t.Errorf("a removed leaf writes the new GroupInfo: %v", err)
	}
}

// A member's commit carries RFC 9420's PrivateMessage clear header, which ParseMlsHeader reads with no key, and an
// external commit is a PublicMessage, which it refuses: FakeMls's carries no Commit, where a real one's does.
func TestFakeMlsFramesCommitsAsParseMlsHeaderReads(t *testing.T) {
	engines, groups := fakeMlsTestGroup(t, 2)
	staged, err := groups[0].Commit(&sidecar.MlsCommitArgs{Path: true, AuthenticatedData: []byte("a GkmCommitHeader")})
	if err != nil {
		t.Fatal(err)
	}
	header, err := sidecar.ParseMlsHeader(staged.Message())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(header.GroupId, groups[0].GroupId().Bytes()) || header.Epoch != 1 || header.ContentType != 3 ||
		!bytes.Equal(header.AuthenticatedData, []byte("a GkmCommitHeader")) {
		t.Errorf("header %+v", header)
	}
	groupInfo, err := groups[0].GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	external, err := engines[1].JoinExternal(groupInfo, &sidecar.MlsCommitArgs{Removes: []uint32{groups[1].Self().LeafIndex}, Path: true, AuthenticatedData: []byte("resync")})
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(external.Message()[2:4]) != fakeMlsWireFormatPublicMessage {
		t.Error("an external commit is not a PublicMessage")
	}
	if _, err := sidecar.ParseMlsHeader(external.Message()); err == nil {
		t.Error("ParseMlsHeader read an external commit that carries no Commit")
	}
	welcomeHeader := binary.BigEndian.Uint16(fakeMlsAppendHeader(nil, fakeMlsWireFormatWelcome)[2:4])
	if welcomeHeader != 3 {
		t.Error("a Welcome's wire format")
	}
}

// An Add of a sidecar already a leaf, or of bytes no engine made, is refused, and so is a GroupInfo whose MAC fails.
func TestFakeMlsRefusesWhatNoEngineMade(t *testing.T) {
	engines, groups := fakeMlsTestGroup(t, 2)
	again, err := engines[1].CreateKeyPackage(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := groups[0].Commit(&sidecar.MlsCommitArgs{Adds: [][]byte{again.Encoded}, AuthenticatedData: []byte("add")}); !errors.Is(err, errFakeMlsRefused) {
		t.Errorf("an Add of a leaf: %v", err)
	}
	forged := bytes.Clone(again.Encoded)
	forged[len(forged)-2] ^= 1
	if _, err := groups[0].Commit(&sidecar.MlsCommitArgs{Adds: [][]byte{forged}, AuthenticatedData: []byte("add")}); !errors.Is(err, errFakeMlsRefused) {
		t.Errorf("an Add of a forged KeyPackage: %v", err)
	}
	groupInfo, err := groups[0].GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engines[1].JoinExternal(groupInfo, &sidecar.MlsCommitArgs{Path: true}); !errors.Is(err, errFakeMlsRefused) {
		t.Errorf("a resync keeping its old leaf: %v", err)
	}
	groupInfo[len(groupInfo)-1] ^= 1
	if _, err := engines[1].JoinExternal(groupInfo, &sidecar.MlsCommitArgs{Removes: []uint32{groups[1].Self().LeafIndex}, Path: true}); !errors.Is(err, errFakeMlsRefused) {
		t.Errorf("an external join from a forged GroupInfo: %v", err)
	}
	if _, err := engines[0].CreateGroup(groups[0].GroupId(), &sidecar.MlsUrGroup{}); !errors.Is(err, errFakeMlsRefused) {
		t.Errorf("a second group under one id: %v", err)
	}
}
