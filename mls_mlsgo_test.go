// Owner decision 43's differential against thomas-vilte/mls-go under suite 0x0001 (§10.4; D-TEST-4), the root's
// half. mlsinterop/mlsgo_test.go says how the two halves meet: transcripts in the mlswg's passive-client form under
// testdata/mls/0x0001/, each replayed through both stacks in every test.sh. mlsgo.json is mls-go's writing, which
// TestMlsGoTranscripts holds mls_* to here; mls.json is mls_*'s, which TestMlsGoContinuation makes and mlsinterop's
// TestMlsGoReplaysTheTranscripts holds mls-go to.
//
// mls_* runs below the engine here, on the group state machine with the vectors' rules: suite 0x0001, basic
// credentials taken as they are, lifetimes without end, and groups with no ur_group, since mls-go refuses to join a
// group whose GroupContext holds an extension it does not implement (RFC 9420 §13.4) and has no credential 0xF552.
// So these runs check RFC 9420's mechanics, the key schedule, tree, TreeKEM, framing and Welcome, and none of the
// subset's own rules on credentials and ur_group, which the 0x0010 stacks row and the engine's tests hold.

package sidecar

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path"
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One passive client's view, as testdata/mls/0x0001/ holds it. RatchetTree is nil when the Welcome's GroupInfo
// carries the tree, as mls-go's does; mls_*'s Welcome never does (§10.6), so a view joining one gives its tree.
type mlsDifferentialView struct {
	CipherSuite               uint16                      `json:"cipher_suite"`
	ExternalPsks              []any                       `json:"external_psks"`
	KeyPackage                mlsHexBytes                 `json:"key_package"`
	SignaturePriv             mlsHexBytes                 `json:"signature_priv"`
	EncryptionPriv            mlsHexBytes                 `json:"encryption_priv"`
	InitPriv                  mlsHexBytes                 `json:"init_priv"`
	Welcome                   mlsHexBytes                 `json:"welcome"`
	RatchetTree               mlsHexBytes                 `json:"ratchet_tree"`
	InitialEpochAuthenticator mlsHexBytes                 `json:"initial_epoch_authenticator"`
	Epochs                    []*mlsDifferentialViewEpoch `json:"epochs"`
}

type mlsDifferentialViewEpoch struct {
	Proposals          []mlsHexBytes `json:"proposals"`
	Commit             mlsHexBytes   `json:"commit"`
	EpochAuthenticator mlsHexBytes   `json:"epoch_authenticator"`
}

// The vectors' rules, which mls-go's groups keep to.
func mlsDifferentialSettings() *mlsGroupSettings {
	return &mlsGroupSettings{Tree: mlsVectorTreeSettings(), Message: defaultMlsMessageSettings()}
}

// Every view of one file under testdata/mls/0x0001/.
func mlsLoadDifferentialViews(t *testing.T, name string) []*mlsDifferentialView {
	t.Helper()
	var views []*mlsDifferentialView
	mlsLoadVectorFile(t, "0x0001", name, &views)
	if len(views) == 0 {
		t.Fatalf("testdata/mls/0x0001/%s.json holds no view", name)
	}
	return views
}

// Joins view's Welcome as its passive client, on the tree beside it or in the Welcome's GroupInfo, at the
// initial epoch_authenticator.
func mlsDifferentialJoin(t *testing.T, view *mlsDifferentialView) *mlsGroupState {
	t.Helper()
	suite := mlsTestSuiteX25519
	settings := mlsDifferentialSettings()
	if view.CipherSuite != suite.value {
		t.Fatalf("a view of suite %#04x", view.CipherSuite)
	}
	held := mlsTestVectorHeld(t, suite, view.KeyPackage, view.InitPriv, view.EncryptionPriv, view.SignaturePriv)
	welcome := &mlsWelcome{}
	if err := mlsUnmarshalMessageOf(view.Welcome, mlsWireFormatWelcome, welcome); err != nil {
		t.Fatal(err)
	}
	opened, err := openMlsWelcome(suite, welcome, held)
	if err != nil {
		t.Fatalf("mls_* does not open the Welcome: %v", err)
	}
	var tree *mlsRatchetTree
	if view.RatchetTree != nil {
		tree, err = decodeMlsRatchetTree(suite, settings.Tree, view.RatchetTree)
	} else {
		tree, err = opened.groupInfo.ratchetTree(suite, settings.Tree)
	}
	if err != nil {
		t.Fatalf("mls_* does not read the tree: %v", err)
	}
	state, err := opened.complete(tree, nil, settings, mlsAcceptBasicCredential)
	if err != nil {
		t.Fatalf("mls_* does not complete the join: %v", err)
	}
	if !bytes.Equal(state.epochAuthenticator, view.InitialEpochAuthenticator) {
		t.Fatalf("mls_* joins at another epoch_authenticator")
	}
	return state
}

// Follows every commit of view from state, each landing on the epoch_authenticator the view names.
func mlsDifferentialFollow(t *testing.T, state *mlsGroupState, view *mlsDifferentialView) *mlsGroupState {
	t.Helper()
	for index, epoch := range view.Epochs {
		if len(epoch.Proposals) != 0 {
			t.Fatalf("epoch %d names a standalone proposal, which §10.4 refuses", index)
		}
		staged, err := state.processCommit(epoch.Commit)
		if err != nil {
			t.Fatalf("epoch %d: mls_* refuses the commit: %v", index, err)
		}
		if staged.next == nil {
			t.Fatalf("epoch %d removes the passive client", index)
		}
		state = staged.next
		if !bytes.Equal(state.epochAuthenticator, epoch.EpochAuthenticator) {
			t.Fatalf("epoch %d: mls_* computes another epoch_authenticator", index)
		}
	}
	return state
}

// Both files replay through mls_*: mlsgo.json is mls-go's Welcomes, path commits, Adds, Removes and external commits,
// a resync among them, which mls_* reads here; mls.json is mls_*'s own, read back as the stack that wrote it.
func TestMlsGoTranscripts(t *testing.T) {
	paths, err := fs.Glob(mlsVectorFiles, path.Join("testdata", "mls", "0x0001", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, filePath := range paths {
		names[path.Base(filePath)] = true
	}
	if !names["mlsgo.json"] || !names["mls.json"] {
		t.Fatalf("testdata/mls/0x0001/ holds %v, want mlsgo.json and mls.json", names)
	}
	followed := 0
	for _, filePath := range paths {
		name := path.Base(filePath)
		for index, view := range mlsLoadDifferentialViews(t, name[:len(name)-len(".json")]) {
			state := mlsDifferentialJoin(t, view)
			mlsDifferentialFollow(t, state, view)
			followed += len(view.Epochs)
			t.Logf("%s %d: joined and followed %d commits to epoch %d", name, index, len(view.Epochs), state.epoch()+uint64(len(view.Epochs)))
		}
	}
	if followed < 20 {
		t.Errorf("%d commits followed", followed)
	}
}

// What mls_*'s leaves carry in mls-go's group: a basic credential, advertised as mls-go's leaves advertise theirs.
func mlsDifferentialIdentity(t *testing.T, credential mlsCredential) *mlsLeafIdentity {
	t.Helper()
	signatureKey, err := mlsTestSuiteX25519.generateSignatureKey("test")
	if err != nil {
		t.Fatal(err)
	}
	return &mlsLeafIdentity{
		signatureKey: signatureKey,
		credential:   credential,
		capabilities: &mlsCapabilities{
			versions:     []uint16{mlsProtocolVersion10},
			cipherSuites: []uint16{mlsCipherSuiteX25519},
			credentials:  []uint16{mlsCredentialTypeBasic},
		},
	}
}

// The members of the continuation, mls_*'s alone, and the views it records.
type mlsContinuation struct {
	t       *testing.T
	members map[string]*mlsGroupState
	// Q's view, which grows by each commit
	view *mlsDifferentialView
	// the commit delivered since the last agreement
	delivered []byte
	header    uint64
}

// The authenticated_data mls_* sends, a GkmCommitHeader's encoding as gkm would read it.
func (self *mlsContinuation) authenticatedData() []byte {
	self.header += 1
	encoded, err := proto.Marshal(&protocol.GkmCommitHeader{Generation: self.header, Auth: &bridge.AuthPin{Version: self.header}})
	if err != nil {
		self.t.Fatal(err)
	}
	return encoded
}

// committer's commit of input, staged, adopted and taken in by every other member, removed ones aside.
func (self *mlsContinuation) commit(committer string, input *mlsCommitInput, removed ...string) *mlsStagedState {
	t := self.t
	t.Helper()
	state := self.members[committer]
	if input.path {
		input.pathIdentity = mlsDifferentialIdentity(t, state.tree.leafNode(state.ownLeaf()).credential)
	}
	input.generation = state.handshakeGeneration
	input.now = mlsTestTime
	input.authenticatedData = self.authenticatedData()
	staged, err := state.stageCommit(input)
	if err != nil {
		t.Fatalf("%s commits: %v", committer, err)
	}
	self.members[committer] = staged.next
	self.deliver(committer, staged.message, removed...)
	return staged
}

// message into every member but its sender and the removed.
func (self *mlsContinuation) deliver(sender string, message []byte, removed ...string) {
	t := self.t
	t.Helper()
	for _, name := range removed {
		delete(self.members, name)
	}
	for name, state := range self.members {
		if name == sender {
			continue
		}
		staged, err := state.processCommit(message)
		if err != nil {
			t.Fatalf("%s refuses %s's commit: %v", name, sender, err)
		}
		if staged.next == nil {
			t.Fatalf("%s's commit removes %s", sender, name)
		}
		self.members[name] = staged.next
	}
	self.delivered = message
}

// Every member at one epoch with one authenticator, which Q's view records with the commit that made it.
func (self *mlsContinuation) agree(step string) {
	t := self.t
	t.Helper()
	q := self.members["Q"]
	for name, state := range self.members {
		if state.epoch() != q.epoch() || !bytes.Equal(state.epochAuthenticator, q.epochAuthenticator) {
			t.Fatalf("%s: %s is at epoch %d with another authenticator", step, name, state.epoch())
		}
	}
	self.view.Epochs = append(self.view.Epochs, &mlsDifferentialViewEpoch{
		Proposals:          []mlsHexBytes{},
		Commit:             self.delivered,
		EpochAuthenticator: bytes.Clone(q.epochAuthenticator),
	})
	self.delivered = nil
	t.Logf("epoch %d after %s: %d members of mls_* agree", q.epoch(), step, len(self.members))
}

// The leaf whose basic credential names identity.
func (self *mlsContinuation) leafOf(identity string) mlsLeafIndex {
	t := self.t
	t.Helper()
	tree := self.members["Q"].tree
	for index := range tree.leafCount() {
		leaf := tree.leafNode(mlsLeafIndex(index))
		if leaf != nil && string(leaf.credential.identity) == identity {
			return mlsLeafIndex(index)
		}
	}
	t.Fatalf("no leaf of %s", identity)
	return 0
}

// The writing half of the differential: mls_* joins mls-go's group, mlsgo.json's, as its passive P, and goes on
// committing in it through its own code: path commits, an Add of a KeyPackage of its own with its Welcome, a Remove
// of one of mls-go's members, an external commit with ExternalInit from its own GroupInfo, and a Remove of that
// joiner. Q, also mlsgo.json's, follows as mls_*, and every member agrees at every epoch. Its view, mlsgo.json's
// commits then these, is mls.json's first, which mls-go follows; the joiner's is its second, its join alone, since
// mls-go takes no tree from beside a Welcome (mlsinterop/mlsgo_test.go). Set SIDECAR_MLS_TRANSCRIPT_OUT to an
// absolute path to write this run's mls.json.
func TestMlsGoContinuation(t *testing.T) {
	views := mlsLoadDifferentialViews(t, "mlsgo")
	if len(views) < 2 {
		t.Fatalf("mlsgo.json holds %d views, want P's and Q's", len(views))
	}
	suite := mlsTestSuiteX25519
	settings := mlsDifferentialSettings()
	life := &mlsContinuation{t: t, members: map[string]*mlsGroupState{
		"P": mlsDifferentialFollow(t, mlsDifferentialJoin(t, views[0]), views[0]),
		"Q": mlsDifferentialFollow(t, mlsDifferentialJoin(t, views[1]), views[1]),
	}}
	viewOfQ := *views[1]
	viewOfQ.Epochs = append([]*mlsDifferentialViewEpoch{}, views[1].Epochs...)
	life.view = &viewOfQ
	if life.members["P"].epoch() != life.members["Q"].epoch() {
		t.Fatal("P's and Q's views end at different epochs")
	}

	life.commit("P", &mlsCommitInput{path: true})
	life.agree("P commits a path")

	// P adds R, a KeyPackage of mls_*'s, and R joins its Welcome. The Add carries no path, so the Welcome carries no
	// path_secret: mls-go joins a Welcome with no tree on a one-leaf stand-in, and with a path_secret walks the
	// committer's direct path there forever (mlsinterop/mlsgo_test.go)
	identityOfR := mlsDifferentialIdentity(t, mlsCredential{credentialType: mlsCredentialTypeBasic, identity: []byte("mls_* R")})
	held, err := newMlsHeldKeyPackage(suite, identityOfR, mlsLifetime{notBefore: 0, notAfter: ^uint64(0)}, false)
	if err != nil {
		t.Fatal(err)
	}
	keyPackage, err := mlsDecodeKeyPackage(suite, settings.Tree, mlsAcceptBasicCredential, held.encoded, &mlsTestTime)
	if err != nil {
		t.Fatal(err)
	}
	staged := life.commit("P", &mlsCommitInput{adds: []*mlsKeyPackage{keyPackage}})
	treeExtension, err := mlsRatchetTreeExtension(staged.next.tree)
	if err != nil {
		t.Fatal(err)
	}
	initPriv, err := mlsKemKeyBytes(held.initKey)
	if err != nil {
		t.Fatal(err)
	}
	encryptionPriv, err := mlsKemKeyBytes(held.leafKey)
	if err != nil {
		t.Fatal(err)
	}
	viewOfR := &mlsDifferentialView{
		CipherSuite:    suite.value,
		ExternalPsks:   []any{},
		KeyPackage:     held.encoded,
		SignaturePriv:  held.signatureKey.Seed(),
		EncryptionPriv: encryptionPriv,
		InitPriv:       initPriv,
		Welcome:        staged.welcome,
		RatchetTree:    treeExtension.extensionData,
		Epochs:         []*mlsDifferentialViewEpoch{},
	}
	joined := mlsDifferentialJoin(t, &mlsDifferentialView{
		CipherSuite: suite.value, KeyPackage: held.encoded, SignaturePriv: held.signatureKey.Seed(), EncryptionPriv: encryptionPriv,
		InitPriv: initPriv, Welcome: staged.welcome, RatchetTree: treeExtension.extensionData,
		InitialEpochAuthenticator: staged.next.epochAuthenticator,
	})
	viewOfR.InitialEpochAuthenticator = bytes.Clone(joined.epochAuthenticator)
	life.members["R"] = joined
	life.agree("P adds R by Welcome")

	life.commit("R", &mlsCommitInput{path: true})
	life.agree("R commits a path")

	life.commit("P", &mlsCommitInput{removes: []mlsLeafIndex{life.leafOf("mls-go C")}, path: true})
	life.agree("P removes mls-go's C")

	// X joins by external commit with ExternalInit from P's full GroupInfo, through its bytes, checked as a joiner
	// checks one short of the subset's ur_group, which mls-go's group has none of
	encodedGroupInfo, err := life.members["P"].encodedGroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	groupInfo := &mlsGroupInfo{}
	if err := mlsUnmarshalMessageOf(encodedGroupInfo, mlsWireFormatGroupInfo, groupInfo); err != nil {
		t.Fatal(err)
	}
	tree, err := groupInfo.ratchetTree(suite, settings.Tree)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.validate(&mlsLeafValidation{groupId: groupInfo.groupContext.groupId, groupExtensions: groupInfo.groupContext.extensions,
		credentialValidator: mlsAcceptBasicCredential}); err != nil {
		t.Fatal(err)
	}
	if treeHash, err := tree.treeHash(); err != nil || !bytes.Equal(treeHash, groupInfo.groupContext.treeHash) {
		t.Fatalf("P's GroupInfo carries another tree: %v", err)
	}
	if err := groupInfo.verifyIn(suite, tree); err != nil {
		t.Fatal(err)
	}
	identityOfX := mlsDifferentialIdentity(t, mlsCredential{credentialType: mlsCredentialTypeBasic, identity: []byte("mls_* X")})
	external, err := mlsStageExternalCommit(suite, settings, mlsAcceptBasicCredential, groupInfo, tree, identityOfX, nil, life.authenticatedData())
	if err != nil {
		t.Fatalf("X's external commit: %v", err)
	}
	if header, err := ParseMlsHeader(external.message); err != nil || header.External == nil {
		t.Fatalf("gkm's parse of X's external commit: %v", err)
	}
	life.deliver("X", external.message)
	life.members["X"] = external.next
	life.agree("X joins by external commit")

	life.commit("X", &mlsCommitInput{path: true})
	life.agree("X commits a path")

	life.commit("R", &mlsCommitInput{removes: []mlsLeafIndex{life.leafOf("mls_* X")}, path: true}, "X")
	life.agree("R removes X")

	life.commit("P", &mlsCommitInput{path: true})
	life.agree("P commits a path")

	continued := len(life.view.Epochs) - len(views[1].Epochs)
	if continued < 8 {
		t.Errorf("mls_* wrote %d commits, want 8", continued)
	}
	// Q's view replays here as mls_*'s passive client too, from its join
	mlsDifferentialFollow(t, mlsDifferentialJoin(t, life.view), life.view)
	if outPath := os.Getenv("SIDECAR_MLS_TRANSCRIPT_OUT"); outPath != "" {
		encoded, err := json.MarshalIndent([]*mlsDifferentialView{life.view, viewOfR}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(outPath, append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote Q's view, %d commits of mls-go's then %d of mls_*'s, and R's join to %s", len(views[1].Epochs), continued, outPath)
	}
}

// An identity that names no capabilities, as every engine's, gives its leaves the subset's: the differential's
// basic-credential leaves are the only ones that carry others.
func TestMlsLeafIdentityCapabilitiesDefaultToTheSubset(t *testing.T) {
	for _, suite := range mlsTestSuites {
		if !reflect.DeepEqual((&mlsLeafIdentity{}).leafCapabilities(suite), mlsSubsetCapabilities(suite)) {
			t.Errorf("suite %#04x: an identity with no capabilities of its own carries other than the subset's", suite.value)
		}
	}
	basic := mlsDifferentialIdentity(t, mlsCredential{credentialType: mlsCredentialTypeBasic, identity: []byte("basic")})
	if !reflect.DeepEqual(basic.leafCapabilities(mlsSuite), *basic.capabilities) {
		t.Error("an identity's own capabilities are not its leaves'")
	}
}
