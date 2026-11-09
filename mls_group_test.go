// The group state machine (KEYS-M2-08): a lifecycle through every commit kind §10.4 takes, the mlswg's passive
// client vectors under 0x0001 with their skips named, and the subset's structural rules on received commits.

package sidecar

import (
	"bytes"
	"errors"
	"slices"
	"testing"
)

// Ten epochs and more through every commit kind: an Add-only commit with no path, a self-update, an Add with a
// path, a Remove, a GroupContextExtensions, a resync and a recovery self-join by external commit, and a Remove
// with an Add in one commit, each member processing each commit and every member agreeing on the epoch, its
// authenticator and its KEK.
func TestMlsGroupLifecycleThroughEveryCommitKind(t *testing.T) {
	world := newMlsTestWorld(t)
	a, b, c, d, e := world.sidecar(nil), world.sidecar(nil), world.sidecar(nil), world.sidecar(nil), world.sidecar(nil)
	members := map[*mlsTestSidecar]MlsGroup{}

	// epoch 0, then 1: an Add-only commit with no path adds b and c
	groups := mlsTestGroupOf(t, a, b, c)
	members[a], members[b], members[c] = groups[0], groups[1], groups[2]
	mlsTestAgree(t, groups)

	commitAll := func(committer *mlsTestSidecar, args *MlsCommitArgs) MlsStagedCommit {
		t.Helper()
		staged, err := members[committer].Commit(args)
		if err != nil {
			t.Fatal(err)
		}
		return staged
	}
	follow := func(committer *mlsTestSidecar, staged MlsStagedCommit) {
		t.Helper()
		adopted, err := staged.Adopt()
		if err != nil {
			t.Fatal(err)
		}
		for sidecar, group := range members {
			if sidecar == committer {
				continue
			}
			processed, err := group.Process(staged.Message())
			if err != nil {
				t.Fatalf("epoch %d: %v", staged.Epoch(), err)
			}
			followed, err := processed.Adopt()
			if errors.Is(err, ErrMlsNotMember) {
				delete(members, sidecar)
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			members[sidecar] = followed
		}
		if adopted != nil {
			members[committer] = adopted
		}
		all := []MlsGroup{}
		for _, group := range members {
			all = append(all, group)
		}
		mlsTestAgree(t, all)
	}

	// 2: b's self-update, which rotates its signature key and keeps its identity
	before := members[b].Self()
	follow(b, commitAll(b, &MlsCommitArgs{Path: true, AuthenticatedData: []byte("self-update")}))
	after := members[b].Self()
	if after.SidecarId != before.SidecarId || bytes.Equal(after.Credential, before.Credential) {
		t.Error("a self-update kept its credential or changed its sidecar")
	}

	// 3: an Add with a path adds d
	keyPackage, err := d.engine.CreateKeyPackage(false)
	if err != nil {
		t.Fatal(err)
	}
	staged := commitAll(a, &MlsCommitArgs{Adds: [][]byte{keyPackage.Encoded}, Path: true, AuthenticatedData: []byte("add d")})
	groupInfo, err := staged.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	follow(a, staged)
	pending, err := d.engine.JoinWelcome(staged.Welcome())
	if err != nil {
		t.Fatal(err)
	}
	if members[d], err = pending.Complete(groupInfo); err != nil {
		t.Fatal(err)
	}

	// 4: c removes b
	follow(c, commitAll(c, &MlsCommitArgs{Removes: []uint32{members[b].Self().LeafIndex}, Path: true, AuthenticatedData: []byte("remove b")}))
	if _, ok := members[b]; ok {
		t.Fatal("b survived its removal")
	}

	// 5: d's GroupContextExtensions, requiring application_id as well and keeping ur_group
	state := members[d].(*mlsRealGroup).state
	required, err := mlsMarshal(&mlsRequiredCapabilities{
		extensionTypes:  []uint16{mlsExtensionTypeUrGroup, mlsExtensionTypeApplicationId},
		credentialTypes: []uint16{mlsCredentialTypeUrSidecar},
	})
	if err != nil {
		t.Fatal(err)
	}
	extensions := slices.Clone(state.groupContext.extensions)
	for index := range extensions {
		if extensions[index].extensionType == mlsExtensionTypeRequiredCapabilities {
			extensions[index] = mlsExtension{extensionType: mlsExtensionTypeRequiredCapabilities, extensionData: required}
		}
	}
	extensionsCommit, err := members[d].(*mlsRealGroup).stage(&mlsCommitInput{
		path: true, groupContextExtensions: extensions, authenticatedData: []byte("extensions"), now: world.clock.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	follow(d, extensionsCommit)

	// 6: d resyncs by external commit, removing its own old leaf
	groupInfo, err = members[a].GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	external, err := d.engine.JoinExternal(groupInfo, &MlsCommitArgs{Removes: []uint32{members[d].Self().LeafIndex}, Path: true, AuthenticatedData: []byte("resync")})
	if err != nil {
		t.Fatal(err)
	}
	if committer := external.Committer(); committer.SidecarId != d.signer.sidecarId {
		t.Errorf("the resync's committer %v", committer)
	}
	follow(d, external)

	// 7: a's self-update
	follow(a, commitAll(a, &MlsCommitArgs{Path: true, AuthenticatedData: []byte("self-update a")}))

	// 8: b, which holds no leaf, rejoins by a recovery self-join that removes nothing
	groupInfo, err = members[c].GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	selfJoin, err := b.engine.JoinExternal(groupInfo, &MlsCommitArgs{Path: true, AuthenticatedData: []byte("self-join")})
	if err != nil {
		t.Fatal(err)
	}
	if len(selfJoin.Removed()) != 0 {
		t.Error("a self-join removed a leaf")
	}
	follow(b, selfJoin)

	// 9: a removes b and adds e in one commit
	keyPackage, err = e.engine.CreateKeyPackage(true)
	if err != nil {
		t.Fatal(err)
	}
	staged = commitAll(a, &MlsCommitArgs{Adds: [][]byte{keyPackage.Encoded}, Removes: []uint32{members[b].Self().LeafIndex}, Path: true, AuthenticatedData: []byte("swap")})
	if len(staged.Added()) != 1 || len(staged.Removed()) != 1 || staged.Removed()[0].SidecarId != b.signer.sidecarId {
		t.Errorf("added %v, removed %v", staged.Added(), staged.Removed())
	}
	groupInfo, err = staged.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	follow(a, staged)
	pending, err = e.engine.JoinWelcome(staged.Welcome())
	if err != nil {
		t.Fatal(err)
	}
	if members[e], err = pending.Complete(groupInfo); err != nil {
		t.Fatal(err)
	}

	// 10 and 11: c and e update themselves
	follow(c, commitAll(c, &MlsCommitArgs{Path: true, AuthenticatedData: []byte("self-update c")}))
	follow(e, commitAll(e, &MlsCommitArgs{Path: true, AuthenticatedData: []byte("self-update e")}))

	if epoch := members[a].Epoch(); epoch != 11 {
		t.Errorf("the lifecycle ends at epoch %d", epoch)
	}
	roster := members[a].Roster()
	sidecarIds := []Id{}
	for _, member := range roster {
		sidecarIds = append(sidecarIds, member.SidecarId)
	}
	for _, sidecar := range []*mlsTestSidecar{a, c, d, e} {
		if !slices.Contains(sidecarIds, sidecar.signer.sidecarId) {
			t.Errorf("a member missing from the roster")
		}
	}
	if slices.Contains(sidecarIds, b.signer.sidecarId) || len(roster) != 4 {
		t.Errorf("a roster of %d", len(roster))
	}
	// every member's state reloads equal to the one it drives
	for sidecar, group := range members {
		loaded, err := sidecar.engine.LoadGroup(group.GroupId())
		if err != nil {
			t.Fatal(err)
		}
		mlsTestAgree(t, []MlsGroup{group, loaded})
	}
}

// The mlswg's passive client vectors under 0x0001. Each Welcome joins in full, its tree from the GroupInfo or
// beside it, and lands on the epoch authenticator the vector names. Every later commit in the files is a
// member's commit framed as a PublicMessage, which §10.4 refuses (D-KEYS-3), so each epoch is refused at parse and
// the rest of its vector skipped, for that reason, named per file; a Welcome naming a PSK is refused likewise.
func TestMlsPassiveClientVectors(t *testing.T) {
	type passiveVector struct {
		CipherSuite               uint16      `json:"cipher_suite"`
		ExternalPsks              []any       `json:"external_psks"`
		KeyPackage                mlsHexBytes `json:"key_package"`
		SignaturePriv             mlsHexBytes `json:"signature_priv"`
		EncryptionPriv            mlsHexBytes `json:"encryption_priv"`
		InitPriv                  mlsHexBytes `json:"init_priv"`
		Welcome                   mlsHexBytes `json:"welcome"`
		RatchetTree               mlsHexBytes `json:"ratchet_tree"`
		InitialEpochAuthenticator mlsHexBytes `json:"initial_epoch_authenticator"`
		Epochs                    []struct {
			Proposals          []mlsHexBytes `json:"proposals"`
			Commit             mlsHexBytes   `json:"commit"`
			EpochAuthenticator mlsHexBytes   `json:"epoch_authenticator"`
		} `json:"epochs"`
	}
	suite := mlsTestSuiteX25519
	settings := &mlsGroupSettings{Tree: mlsVectorTreeSettings(), Message: defaultMlsMessageSettings()}
	totalJoined := 0
	for _, name := range []string{"passive-client-welcome", "passive-client-handling-commit", "passive-client-random"} {
		var vectors []passiveVector
		mlsLoadVectors(t, name, &vectors)
		joined, pskSkips, epochsRefused, ran := 0, 0, 0, 0
		for index, vector := range vectors {
			if vector.CipherSuite != suite.value {
				continue
			}
			ran += 1
			held := mlsTestVectorHeld(t, suite, vector.KeyPackage, vector.InitPriv, vector.EncryptionPriv, vector.SignaturePriv)
			welcome := &mlsWelcome{}
			if err := mlsUnmarshalMessageOf(vector.Welcome, mlsWireFormatWelcome, welcome); err != nil {
				t.Fatalf("%s %d: %v", name, index, err)
			}
			opened, err := openMlsWelcome(suite, welcome, held)
			if errors.Is(err, errMlsRefused) && len(vector.ExternalPsks) != 0 {
				// skipped: the Welcome names a PSK, which §10.4 refuses
				pskSkips += 1
				continue
			}
			if err != nil {
				t.Fatalf("%s %d: %v", name, index, err)
			}
			var tree *mlsRatchetTree
			if vector.RatchetTree != nil {
				tree, err = decodeMlsRatchetTree(suite, settings.Tree, vector.RatchetTree)
			} else {
				tree, err = opened.groupInfo.ratchetTree(suite, settings.Tree)
			}
			if err != nil {
				t.Fatalf("%s %d: %v", name, index, err)
			}
			state, err := opened.complete(tree, nil, settings, mlsAcceptBasicCredential)
			if err != nil {
				t.Fatalf("%s %d: %v", name, index, err)
			}
			if !bytes.Equal(state.epochAuthenticator, vector.InitialEpochAuthenticator) {
				t.Errorf("%s %d: another epoch authenticator", name, index)
			}
			joined += 1
			for _, epoch := range vector.Epochs {
				// skipped past here: a member's commit as a PublicMessage, which §10.4 refuses when parsed
				if _, err := state.processCommit(epoch.Commit); !errors.Is(err, errMlsRefused) {
					t.Errorf("%s %d: a member's PublicMessage commit: %v", name, index, err)
				}
				epochsRefused += 1
				break
			}
		}
		t.Logf("%s: %d joined, %d skipped for a PSK, %d epochs refused as a member's PublicMessage, the rest of each skipped", name, joined, pskSkips, epochsRefused)
		if ran == 0 || joined+pskSkips != ran {
			t.Errorf("%s: %d vectors, %d accounted for", name, ran, joined+pskSkips)
		}
		totalJoined += joined
	}
	if totalJoined == 0 {
		t.Error("no passive client joined")
	}
}

// A received path that keeps its committer's leaf but names another sidecar, though that sidecar is admitted, is
// refused: a self-update rotates the signature key and nothing else (§10.9's Self-update row).
func TestMlsPathChangingItsSidecarIsRefused(t *testing.T) {
	world := newMlsTestWorld(t)
	committer, member, other := world.sidecar(nil), world.sidecar(nil), world.sidecar(nil)
	groups := mlsTestGroupOf(t, committer, member)
	state := groups[0].(*mlsRealGroup).state
	impostor := mlsTestLeafIdentity(t, other.signer)
	generation, err := committer.engine.reserveGeneration(state)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := state.stageCommit(&mlsCommitInput{path: true, pathIdentity: impostor, authenticatedData: []byte("impostor"), generation: generation, now: world.clock.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := groups[1].Process(staged.message); !errors.Is(err, errMlsInvalid) {
		t.Errorf("a path naming another sidecar: %v", err)
	}
}

// One leaf per sidecar: an Add of a sidecar already a leaf is refused when staged.
func TestMlsAddOfASidecarAlreadyALeafIsRefused(t *testing.T) {
	world := newMlsTestWorld(t)
	creator, member := world.sidecar(nil), world.sidecar(nil)
	groups := mlsTestGroupOf(t, creator, member)
	keyPackage, err := member.engine.CreateKeyPackage(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := groups[0].Commit(&MlsCommitArgs{Adds: [][]byte{keyPackage.Encoded}, AuthenticatedData: []byte("again")}); !errors.Is(err, errMlsInvalid) {
		t.Errorf("a second leaf for one sidecar: %v", err)
	}
	if _, err := groups[0].Commit(&MlsCommitArgs{Adds: [][]byte{keyPackage.Encoded, keyPackage.Encoded}, Removes: []uint32{groups[1].Self().LeafIndex}, Path: true, AuthenticatedData: []byte("twice")}); err == nil {
		t.Error("one KeyPackage added twice")
	}
}

// An external commit removes only its sender's old leaf, found by sidecar and identity key: one naming another's
// leaf is refused when made and when received.
func TestMlsExternalCommitRemovesOnlyItsOwnLeaf(t *testing.T) {
	world := newMlsTestWorld(t)
	a, b, c := world.sidecar(nil), world.sidecar(nil), world.sidecar(nil)
	groups := mlsTestGroupOf(t, a, b, c)
	groupInfo, err := groups[0].GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.engine.JoinExternal(groupInfo, &MlsCommitArgs{Removes: []uint32{groups[2].Self().LeafIndex}, Path: true, AuthenticatedData: []byte("theft")}); !errors.Is(err, errMlsInvalid) {
		t.Errorf("removing another's leaf: %v", err)
	}
	if _, err := b.engine.JoinExternal(groupInfo, &MlsCommitArgs{Path: true, AuthenticatedData: []byte("twice")}); !errors.Is(err, errMlsInvalid) {
		t.Errorf("a resync that keeps its old leaf: %v", err)
	}
	if _, err := b.engine.JoinExternal(groupInfo, &MlsCommitArgs{Removes: []uint32{groups[1].Self().LeafIndex}, AuthenticatedData: []byte("no path")}); err == nil {
		t.Error("an external commit with no path")
	}

	// made by hand: b's new leaf removing c's
	decoded := &mlsGroupInfo{}
	if err := mlsUnmarshalMessageOf(groupInfo, mlsWireFormatGroupInfo, decoded); err != nil {
		t.Fatal(err)
	}
	tree, err := decoded.checkTree(mlsSuite, defaultMlsTreeSettings(), b.engine.credentialValidator)
	if err != nil {
		t.Fatal(err)
	}
	identity := mlsTestLeafIdentity(t, c.signer)
	forged, err := mlsStageExternalCommit(mlsSuite, defaultMlsGroupSettings(), b.engine.credentialValidator, decoded, tree, identity, []mlsLeafIndex{mlsLeafIndex(groups[2].Self().LeafIndex)}, []byte("theft"))
	if err != nil {
		t.Fatal(err)
	}
	// the forged one claims c's identity, so it removes c's leaf as c's own: a member takes it only as c's resync
	processed, err := groups[0].Process(forged.message)
	if err != nil {
		t.Fatal(err)
	}
	if processed.Committer().SidecarId != c.signer.sidecarId || processed.Removed()[0].SidecarId != c.signer.sidecarId {
		t.Error("a resync read as another sidecar's")
	}
	processed.Discard()
}
