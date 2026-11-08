//go:build mlsinterop_tmc

// §22.10's stacks row (D-KEYS-10): one scripted lifecycle between mls_*, through the exported MlsEngine, and tmc/mls,
// under suite 0x0010 on both sides. tmc/mls's 0x004F carries 0x0010's algorithms, but the suite number sits inside
// signed and hashed structures, so it cannot be mapped on the wire: overlay_test.go builds this file with tmc/mls's
// wire.go patched to number its suite 0x0010, and TestTmcSuiteIsPatched fails any other build
// (plan-KEYS-interop-independence #1).
//
// Every step runs in both directions: a Welcome from mls_* that tmc/mls joins and one from tmc/mls that mls_* joins,
// path commits from each, a Remove by each of the other's member, and an external commit with ExternalInit by each
// into the other's view of the group. At every epoch every current member, of either stack, computes one
// epoch_authenticator and one exporter output under "UR evs 1.0 kek" and under a label of this test's. Member commits
// are PrivateMessages, so each epoch from the first has one the other stack decrypts; an epoch an external commit
// ends has one too, a member's commit that loses the race to it, which the other stack decrypts and drops as gkm's
// 409 would (KF6).
//
// A passive tmc/mls member, P, joins at the first Welcome and commits nothing; its view is the transcript §22.10's
// vectors row checks in, in the mlswg's passive-client form under testdata/mls/0x0010/. Set MLSINTEROP_TRANSCRIPT_OUT
// to an absolute path to write this run's. TestTmcReplaysTheInteropTranscripts replays every checked-in one through
// tmc/mls, and the root's TestMlsInteropTranscripts through mls_*, so both stacks hold to the same bytes in every
// test.sh.
//
// tmc/mls's leaves carry credential 0xF552, each a UrMlsCredential signed here for the leaf's signature key, and
// advertise ur_group, which the group requires: tmc/mls's default capabilities list no extension, so its KeyPackages
// are built and signed here. Its commits carry no authenticated_data, so mls_* runs here below gkm's header checks,
// which the engine leaves to its caller. It resyncs by the old leaf's signature key, so no external join here
// rejoins a leaf it held.

package mlsinterop

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/tmc/mls"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The suite mls_* runs, as tmc/mls numbers it under the overlay.
const tmcSuite = mls.MLKEM768X25519AES128GCMSHA256Ed25519

// Fails a build without the overlay, whose tmc/mls would sign and hash 0x004F.
func TestTmcSuiteIsPatched(t *testing.T) {
	if tmcSuite != 0x0010 {
		t.Fatalf("tmc/mls numbers its X-Wing suite %#04x: run under overlay_test.go's patch", uint16(tmcSuite))
	}
}

// The identity keys the test admitted, by sidecar, standing in for KEYS-M2-19's check against the log: a leaf of
// either stack passes only for a sidecar admitted under the identity key its credential names.
type tmcAdmissions struct {
	stateLock     sync.Mutex
	sidecarIdKeys map[sidecar.Id]ed25519.PublicKey
}

func (self *tmcAdmissions) admit(sidecarId sidecar.Id, publicKey ed25519.PublicKey) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.sidecarIdKeys[sidecarId] = publicKey
}

func (self *tmcAdmissions) check(credential *protocol.UrMlsCredential) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	publicKey, ok := self.sidecarIdKeys[sidecar.Id(credential.GetSidecarId())]
	if !ok || !bytes.Equal(publicKey, credential.GetIdentityPublicKey()) {
		return errors.New("not admitted")
	}
	return nil
}

// A sidecar's identity: its id, its admission's hash and its identity key's signer.
type tmcIdentity struct {
	sidecarId  sidecar.Id
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	admission  []byte
}

func newTmcIdentity(t *testing.T, admissions *tmcAdmissions) *tmcIdentity {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sidecarId := sidecar.NewId()
	admission := sha256.Sum256(append([]byte("interop admission "), sidecarId.Bytes()...))
	admissions.admit(sidecarId, publicKey)
	return &tmcIdentity{sidecarId: sidecarId, publicKey: publicKey, privateKey: privateKey, admission: admission[:]}
}

// Signs as Sidecar.Sign does.
func (self *tmcIdentity) sign(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
	return &bridge.Signed{
		Body:      bytes.Clone(body),
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.privateKey, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

// One member of the lifecycle, of either stack. Exactly one of ours and theirs is set.
type tmcMember struct {
	name     string
	identity *tmcIdentity

	// mls_*
	engine sidecar.MlsEngine
	ours   sidecar.MlsGroup

	// tmc/mls
	client *mls.Client
	theirs *mls.Group
}

func (self *tmcMember) stack() string {
	if self.engine != nil {
		return "mls_*"
	}
	return "tmc/mls"
}

func (self *tmcMember) epoch() uint64 {
	if self.ours != nil {
		return self.ours.Epoch()
	}
	return self.theirs.Epoch()
}

func (self *tmcMember) epochAuthenticator() []byte {
	if self.ours != nil {
		return self.ours.EpochAuthenticator()
	}
	return self.theirs.EpochAuthenticator()
}

func (self *tmcMember) export(t *testing.T, label string, context []byte) []byte {
	t.Helper()
	if self.ours != nil {
		exported, err := self.ours.Exporter(label, context, 32)
		if err != nil {
			t.Fatalf("%s: %v", self.name, err)
		}
		return exported
	}
	exported, err := self.theirs.Export(label, context, 32)
	if err != nil {
		t.Fatalf("%s: %v", self.name, err)
	}
	return exported
}

// The member's leaf index.
func (self *tmcMember) leaf() uint32 {
	if self.ours != nil {
		return self.ours.Self().LeafIndex
	}
	return uint32(self.theirs.Index)
}

// An mls_* member, not yet in a group.
func newTmcOurs(t *testing.T, name string, admissions *tmcAdmissions) *tmcMember {
	t.Helper()
	identity := newTmcIdentity(t, admissions)
	engine, err := sidecar.NewMlsEngine(&sidecar.MlsEngineArgs{
		SidecarId:         identity.sidecarId,
		IdentityPublicKey: identity.publicKey,
		AdmissionSha256:   identity.admission,
		Sign:              identity.sign,
		Store:             sidecartest.NewFakeStore().Root(),
		CheckCredential:   admissions.check,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &tmcMember{name: name, identity: identity, engine: engine}
}

// A tmc/mls member, not yet in a group: its KeyPackage built and signed here, its leaf carrying a 0xF552 credential
// for its signature key and advertising ur_group.
func newTmcTheirs(t *testing.T, name string, admissions *tmcAdmissions) *tmcMember {
	t.Helper()
	identity := newTmcIdentity(t, admissions)
	signaturePrivate, signaturePublic, err := tmcSuite.GenerateSignatureKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	initPrivate, initPublic, err := tmcSuite.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	encryptionPrivate, encryptionPublic, err := tmcSuite.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	credential, err := sidecar.SignUrMlsCredential(&sidecar.UrMlsCredentialArgs{
		SidecarId:             identity.sidecarId,
		IdentityPublicKey:     identity.publicKey,
		MlsSignaturePublicKey: signaturePublic,
		NotAfter:              now.Add(90 * 24 * time.Hour),
		AdmissionSha256:       identity.admission,
	}, identity.sign)
	if err != nil {
		t.Fatal(err)
	}
	keyPackage := &mls.KeyPackage{
		Version:     mls.Version10,
		CipherSuite: tmcSuite,
		InitKey:     initPublic,
		LeafNode: mls.LeafNode{
			EncryptionKey: encryptionPublic,
			SignatureKey:  signaturePublic,
			Credential:    mls.Credential{Type: tmcCredentialTypeUrSidecar, Body: &tmcUrCredential{encoded: credential}},
			Capabilities: mls.Capabilities{
				Versions:     []mls.ProtocolVersion{mls.Version10},
				CipherSuites: []mls.CipherSuite{tmcSuite},
				Extensions:   []mls.ExtensionType{tmcExtensionTypeUrGroup},
				Credentials:  []mls.CredentialType{tmcCredentialTypeUrSidecar},
			},
			Source:   mls.LeafNodeSourceKeyPackage,
			Lifetime: mls.Lifetime{NotBefore: uint64(now.Add(-10 * time.Minute).Unix()), NotAfter: uint64(now.Add(30 * 24 * time.Hour).Unix())},
		},
	}
	if err := keyPackage.LeafNode.Sign(tmcSuite, signaturePrivate, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := keyPackage.Sign(signaturePrivate); err != nil {
		t.Fatal(err)
	}
	client := &mls.Client{
		CipherSuite:    tmcSuite,
		KeyPackage:     keyPackage,
		InitPriv:       initPrivate,
		EncryptionPriv: encryptionPrivate,
		SignaturePriv:  signaturePrivate,
	}
	return &tmcMember{name: name, identity: identity, client: client}
}

// The member's KeyPackage as an MLSMessage.
func (self *tmcMember) keyPackage(t *testing.T) []byte {
	t.Helper()
	if self.engine != nil {
		keyPackage, err := self.engine.CreateKeyPackage(false)
		if err != nil {
			t.Fatal(err)
		}
		return keyPackage.Encoded
	}
	encoded, err := mls.Marshal(&mls.Message{Version: mls.Version10, WireFormat: mls.WireFormatKeyPackage, KeyPackage: self.client.KeyPackage})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// An encoded MLSMessage, read by tmc/mls.
func tmcMessage(t *testing.T, encoded []byte) *mls.Message {
	t.Helper()
	message := &mls.Message{}
	if err := mls.Unmarshal(encoded, message); err != nil {
		t.Fatalf("tmc/mls does not read the message: %v", err)
	}
	return message
}

func tmcEncode(t *testing.T, message *mls.Message) []byte {
	t.Helper()
	encoded, err := mls.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// The ratchet tree a full GroupInfo carries.
func tmcTree(t *testing.T, groupInfo []byte) mls.RatchetTree {
	t.Helper()
	tree := mls.RatchetTree{}
	ok, err := tmcMessage(t, groupInfo).GroupInfo.Extensions.Decode(mls.ExtensionTypeRatchetTree, &tree)
	if err != nil || !ok {
		t.Fatalf("a GroupInfo with no ratchet_tree: %v", err)
	}
	return tree
}

// What one epoch showed: its number, its authenticator and the exporter's outputs.
type tmcEpochRecord struct {
	epoch              uint64
	epochAuthenticator []byte
	kek                []byte
	exported           []byte
	members            []string
}

// One passive client's view of a group in the mlswg's form (test-vectors.md's passive client tests), hex throughout.
type tmcTranscript struct {
	CipherSuite               uint16                `json:"cipher_suite"`
	ExternalPsks              []any                 `json:"external_psks"`
	KeyPackage                string                `json:"key_package"`
	SignaturePriv             string                `json:"signature_priv"`
	EncryptionPriv            string                `json:"encryption_priv"`
	InitPriv                  string                `json:"init_priv"`
	Welcome                   string                `json:"welcome"`
	RatchetTree               string                `json:"ratchet_tree"`
	InitialEpochAuthenticator string                `json:"initial_epoch_authenticator"`
	Epochs                    []*tmcTranscriptEpoch `json:"epochs"`
}

type tmcTranscriptEpoch struct {
	Proposals          []string `json:"proposals"`
	Commit             string   `json:"commit"`
	EpochAuthenticator string   `json:"epoch_authenticator"`
}

// The lifecycle's state: its members now, and what every epoch showed.
type tmcLifecycle struct {
	t       *testing.T
	repoId  sidecar.Id
	groupId sidecar.Id
	members []*tmcMember
	epochs  []*tmcEpochRecord
	// per epoch, the PrivateMessages a member of the other stack decrypted
	decrypted map[uint64]int
	// the passive member's view, once it has joined, and the commit delivered since the last agreement
	transcript *tmcTranscript
	delivered  []byte
}

// Every current member at one epoch, with one authenticator and one output under each label, recorded.
func (self *tmcLifecycle) agree(step string) {
	t := self.t
	t.Helper()
	first := self.members[0]
	record := &tmcEpochRecord{
		epoch:              first.epoch(),
		epochAuthenticator: first.epochAuthenticator(),
		kek:                first.export(t, "UR evs 1.0 kek", self.repoId.Bytes()),
		exported:           first.export(t, "UR interop", []byte(step)),
	}
	if kek, err := sidecar.MlsKek(self.ourMember().ours, self.repoId); err != nil || !bytes.Equal(kek, record.kek) {
		t.Fatalf("%s: MlsKek is not the exporter's kek output: %v", step, err)
	}
	for _, member := range self.members {
		record.members = append(record.members, member.name)
		if member.epoch() != record.epoch {
			t.Fatalf("%s: %s (%s) is at epoch %d, %s at %d", step, member.name, member.stack(), member.epoch(), first.name, record.epoch)
		}
		if !bytes.Equal(member.epochAuthenticator(), record.epochAuthenticator) {
			t.Errorf("%s: %s (%s) computes another epoch_authenticator at epoch %d", step, member.name, member.stack(), record.epoch)
		}
		if !bytes.Equal(member.export(t, "UR evs 1.0 kek", self.repoId.Bytes()), record.kek) {
			t.Errorf("%s: %s (%s) exports another KEK at epoch %d", step, member.name, member.stack(), record.epoch)
		}
		if !bytes.Equal(member.export(t, "UR interop", []byte(step)), record.exported) {
			t.Errorf("%s: %s (%s) exports another value at epoch %d", step, member.name, member.stack(), record.epoch)
		}
	}
	self.epochs = append(self.epochs, record)
	if self.transcript != nil && self.delivered != nil {
		self.transcript.Epochs = append(self.transcript.Epochs, &tmcTranscriptEpoch{
			Proposals:          []string{},
			Commit:             hex.EncodeToString(self.delivered),
			EpochAuthenticator: hex.EncodeToString(record.epochAuthenticator),
		})
	}
	self.delivered = nil
	t.Logf("epoch %d after %s: %v agree, epoch_authenticator %x", record.epoch, step, record.members, record.epochAuthenticator[:8])
}

// Some member of mls_*'s.
func (self *tmcLifecycle) ourMember() *tmcMember {
	for _, member := range self.members {
		if member.ours != nil {
			return member
		}
	}
	self.t.Fatal("no mls_* member left")
	return nil
}

func (self *tmcLifecycle) member(name string) *tmcMember {
	for _, member := range self.members {
		if member.name == name {
			return member
		}
	}
	self.t.Fatalf("no member %s", name)
	return nil
}

// Takes a commit the committer made into every other current member's state, and, when a member of the other stack
// opened it from a PrivateMessage, counts it at its epoch, which its clear header gives (ParseMlsHeader, gkm's one
// parse). removed names the members it removes, whose stack must say so.
func (self *tmcLifecycle) deliver(committer *tmcMember, message []byte, removed ...*tmcMember) {
	t := self.t
	t.Helper()
	header, err := sidecar.ParseMlsHeader(message)
	if err != nil {
		t.Fatalf("gkm's header parse refuses %s's commit: %v", committer.name, err)
	}
	epoch := header.Epoch
	private := tmcMessage(t, message).WireFormat == mls.WireFormatPrivateMessage
	for _, member := range self.members {
		if member == committer {
			continue
		}
		isRemoved := slices.Contains(removed, member)
		if member.ours != nil {
			staged, err := member.ours.Process(message)
			if err != nil {
				t.Fatalf("%s (mls_*) refuses %s's commit in epoch %d: %v", member.name, committer.name, epoch, err)
			}
			group, err := staged.Adopt()
			switch {
			case isRemoved && errors.Is(err, sidecar.ErrMlsNotMember):
			case isRemoved:
				t.Fatalf("%s (mls_*) does not see its removal: %v", member.name, err)
			case err != nil:
				t.Fatalf("%s (mls_*) adopting %s's commit: %v", member.name, committer.name, err)
			default:
				member.ours = group
			}
		} else {
			group, _, err := member.theirs.Handle(tmcMessage(t, message))
			switch {
			case isRemoved && err != nil:
			case isRemoved && group != nil && tmcHolds(group, member):
				t.Fatalf("%s (tmc/mls) does not see its removal", member.name)
			case isRemoved:
			case err != nil:
				t.Fatalf("%s (tmc/mls) refuses %s's commit in epoch %d: %v", member.name, committer.name, epoch, err)
			default:
				member.theirs = group
			}
		}
		if private && member.stack() != committer.stack() {
			self.decrypted[epoch] += 1
		}
	}
	self.members = slices.DeleteFunc(self.members, func(member *tmcMember) bool { return slices.Contains(removed, member) })
	self.delivered = bytes.Clone(message)
}

// Whether a tmc/mls group still holds the member's leaf.
func tmcHolds(group *mls.Group, member *tmcMember) bool {
	leaf := group.Tree.Leaf(group.Index)
	return leaf != nil && bytes.Equal(leaf.SignatureKey, member.client.KeyPackage.LeafNode.SignatureKey)
}

// A member's commit that loses to another for its epoch: each other member of the other stack opens it, then drops
// it as a 409's loser does, and the committer discards it.
func (self *tmcLifecycle) loseRace(committer *tmcMember) {
	t := self.t
	t.Helper()
	epoch := committer.epoch()
	var message []byte
	var discard func()
	if committer.ours != nil {
		staged, err := committer.ours.Commit(&sidecar.MlsCommitArgs{Path: true, AuthenticatedData: []byte("losing")})
		if err != nil {
			t.Fatal(err)
		}
		message, discard = staged.Message(), staged.Discard
	} else {
		// tmc/mls leaves the group as it was; the new state is dropped
		_, commit, _, err := committer.theirs.Commit(nil)
		if err != nil {
			t.Fatal(err)
		}
		message, discard = tmcEncode(t, commit), func() {}
	}
	for _, member := range self.members {
		if member == committer || member.stack() == committer.stack() {
			continue
		}
		if member.ours != nil {
			staged, err := member.ours.Process(message)
			if err != nil {
				t.Fatalf("%s (mls_*) refuses %s's losing commit: %v", member.name, committer.name, err)
			}
			staged.Discard()
		} else if _, _, err := member.theirs.Handle(tmcMessage(t, message)); err != nil {
			t.Fatalf("%s (tmc/mls) refuses %s's losing commit: %v", member.name, committer.name, err)
		}
		self.decrypted[epoch] += 1
	}
	discard()
}

// The scripted lifecycle, both directions at every kind of step, at least 10 epochs.
func TestTmcLifecycleInBothDirections(t *testing.T) {
	admissions := &tmcAdmissions{sidecarIdKeys: map[sidecar.Id]ed25519.PublicKey{}}
	life := &tmcLifecycle{t: t, repoId: sidecar.NewId(), groupId: sidecar.NewId(), decrypted: map[uint64]int{}}
	header := func(step string) []byte { return []byte("GkmCommitHeader of " + step) }

	// mls_* creates the group
	a := newTmcOurs(t, "A", admissions)
	group, err := a.engine.CreateGroup(life.groupId, &sidecar.MlsUrGroup{NetworkId: sidecar.NewId(), RepoId: life.repoId, Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	if err != nil {
		t.Fatal(err)
	}
	a.ours = group
	life.members = []*tmcMember{a}
	life.agree("create")

	// mls_* adds tmc/mls's T and the passive P: tmc/mls joins mls_*'s Welcome, the tree from mls_*'s GroupInfo
	tee := newTmcTheirs(t, "T", admissions)
	passive := newTmcTheirs(t, "P", admissions)
	passiveKeyPackage := passive.keyPackage(t)
	staged, err := a.ours.Commit(&sidecar.MlsCommitArgs{Adds: [][]byte{tee.keyPackage(t), passiveKeyPackage}, AuthenticatedData: header("add T and P")})
	if err != nil {
		t.Fatal(err)
	}
	groupInfo, err := staged.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	if a.ours, err = staged.Adopt(); err != nil {
		t.Fatal(err)
	}
	for _, joiner := range []*tmcMember{tee, passive} {
		if joiner.theirs, err = joiner.client.Join(tmcMessage(t, staged.Welcome()).Welcome, tmcTree(t, groupInfo)); err != nil {
			t.Fatalf("tmc/mls's %s does not join mls_*'s Welcome: %v", joiner.name, err)
		}
		life.members = append(life.members, joiner)
	}
	life.agree("mls_* adds T and P by Welcome")
	treeExtension := tmcMessage(t, groupInfo).GroupInfo.Extensions.Find(mls.ExtensionTypeRatchetTree)
	if treeExtension == nil {
		t.Fatal("mls_*'s GroupInfo carries no ratchet_tree")
	}
	life.transcript = &tmcTranscript{
		CipherSuite:               uint16(tmcSuite),
		ExternalPsks:              []any{},
		KeyPackage:                hex.EncodeToString(passiveKeyPackage),
		SignaturePriv:             hex.EncodeToString(passive.client.SignaturePriv),
		EncryptionPriv:            hex.EncodeToString(passive.client.EncryptionPriv),
		InitPriv:                  hex.EncodeToString(passive.client.InitPriv),
		Welcome:                   hex.EncodeToString(staged.Welcome()),
		RatchetTree:               hex.EncodeToString(treeExtension.Data),
		InitialEpochAuthenticator: hex.EncodeToString(passive.epochAuthenticator()),
		Epochs:                    []*tmcTranscriptEpoch{},
	}

	// tmc/mls adds mls_*'s B, with a path: mls_* joins tmc/mls's Welcome in its two phases
	b := newTmcOurs(t, "B", admissions)
	addB := tmcMessage(t, b.keyPackage(t)).KeyPackage
	next, commit, welcome, err := tee.theirs.Commit([]*mls.Proposal{{Type: mls.ProposalTypeAdd, Add: &mls.Add{KeyPackage: *addB}}})
	if err != nil {
		t.Fatal(err)
	}
	life.deliver(tee, tmcEncode(t, commit))
	tee.theirs = next
	pending, err := b.engine.JoinWelcome(tmcEncode(t, welcome))
	if err != nil {
		t.Fatalf("mls_* does not open tmc/mls's Welcome: %v", err)
	}
	fullGroupInfo, err := tee.theirs.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	if b.ours, err = pending.Complete(tmcEncode(t, fullGroupInfo)); err != nil {
		t.Fatalf("mls_* does not complete the join on tmc/mls's GroupInfo: %v", err)
	}
	life.members = append(life.members, b)
	life.agree("tmc/mls adds B by Welcome")

	// a path commit from each
	staged, err = b.ours.Commit(&sidecar.MlsCommitArgs{Path: true, AuthenticatedData: header("B updates")})
	if err != nil {
		t.Fatal(err)
	}
	life.deliver(b, staged.Message())
	if b.ours, err = staged.Adopt(); err != nil {
		t.Fatal(err)
	}
	life.agree("mls_*'s B commits a path")
	next, commit, _, err = tee.theirs.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	life.deliver(tee, tmcEncode(t, commit))
	tee.theirs = next
	life.agree("tmc/mls's T commits a path")

	// mls_* adds tmc/mls's U with a path
	u := newTmcTheirs(t, "U", admissions)
	staged, err = a.ours.Commit(&sidecar.MlsCommitArgs{Adds: [][]byte{u.keyPackage(t)}, Path: true, AuthenticatedData: header("add U")})
	if err != nil {
		t.Fatal(err)
	}
	life.deliver(a, staged.Message())
	if groupInfo, err = staged.GroupInfo(); err != nil {
		t.Fatal(err)
	}
	if a.ours, err = staged.Adopt(); err != nil {
		t.Fatal(err)
	}
	if u.theirs, err = u.client.Join(tmcMessage(t, staged.Welcome()).Welcome, tmcTree(t, groupInfo)); err != nil {
		t.Fatalf("tmc/mls does not join mls_*'s Welcome with a path: %v", err)
	}
	life.members = append(life.members, u)
	life.agree("mls_* adds U by Welcome with a path")

	// tmc/mls removes mls_*'s B, then mls_* removes tmc/mls's U
	next, commit, _, err = u.theirs.Commit([]*mls.Proposal{{Type: mls.ProposalTypeRemove, Remove: &mls.Remove{Removed: b.leaf()}}})
	if err != nil {
		t.Fatal(err)
	}
	life.deliver(u, tmcEncode(t, commit), b)
	u.theirs = next
	life.agree("tmc/mls's U removes B")
	staged, err = a.ours.Commit(&sidecar.MlsCommitArgs{Removes: []uint32{u.leaf()}, Path: true, AuthenticatedData: header("remove U")})
	if err != nil {
		t.Fatal(err)
	}
	life.deliver(a, staged.Message(), u)
	if a.ours, err = staged.Adopt(); err != nil {
		t.Fatal(err)
	}
	life.agree("mls_*'s A removes U")

	next, commit, _, err = tee.theirs.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	life.deliver(tee, tmcEncode(t, commit))
	tee.theirs = next
	life.agree("tmc/mls's T commits a path")

	// tmc/mls's V joins by external commit from mls_*'s GroupInfo, past A's commit, which loses
	life.loseRace(a)
	v := newTmcTheirs(t, "V", admissions)
	ourGroupInfo, err := a.ours.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	joined, external, err := v.client.JoinExternal(tmcMessage(t, ourGroupInfo).GroupInfo, nil, nil)
	if err != nil {
		t.Fatalf("tmc/mls does not join externally from mls_*'s GroupInfo: %v", err)
	}
	if external.WireFormat != mls.WireFormatPublicMessage {
		t.Fatalf("an external commit as wire format %d", external.WireFormat)
	}
	life.deliver(v, tmcEncode(t, external))
	v.theirs = joined
	life.members = append(life.members, v)
	life.agree("tmc/mls's V joins by external commit")

	next, commit, _, err = v.theirs.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	life.deliver(v, tmcEncode(t, commit))
	v.theirs = next
	life.agree("tmc/mls's V commits a path")

	// mls_*'s C joins by external commit from tmc/mls's GroupInfo, past T's commit, which loses
	life.loseRace(tee)
	c := newTmcOurs(t, "C", admissions)
	theirGroupInfo, err := tee.theirs.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	staged, err = c.engine.JoinExternal(tmcEncode(t, theirGroupInfo), &sidecar.MlsCommitArgs{Path: true, AuthenticatedData: header("C joins")})
	if err != nil {
		t.Fatalf("mls_* does not join externally from tmc/mls's GroupInfo: %v", err)
	}
	if header, err := sidecar.ParseMlsHeader(staged.Message()); err != nil || header.External == nil {
		t.Fatalf("mls_*'s external commit: %v", err)
	}
	life.deliver(c, staged.Message())
	if c.ours, err = staged.Adopt(); err != nil {
		t.Fatal(err)
	}
	life.members = append(life.members, c)
	life.agree("mls_*'s C joins by external commit")

	staged, err = c.ours.Commit(&sidecar.MlsCommitArgs{Path: true, AuthenticatedData: header("C updates")})
	if err != nil {
		t.Fatal(err)
	}
	life.deliver(c, staged.Message())
	if c.ours, err = staged.Adopt(); err != nil {
		t.Fatal(err)
	}
	life.agree("mls_*'s C commits a path")
	next, commit, _, err = v.theirs.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	life.deliver(v, tmcEncode(t, commit))
	v.theirs = next
	life.agree("tmc/mls's V commits a path")

	// at least 10 epochs, each from the first with a PrivateMessage the other stack decrypted
	last := life.epochs[len(life.epochs)-1].epoch
	if last < 10 {
		t.Errorf("the lifecycle reached epoch %d, want 10 or more", last)
	}
	for epoch := uint64(1); epoch < last; epoch += 1 {
		if life.decrypted[epoch] == 0 {
			t.Errorf("no PrivateMessage of epoch %d decrypted across the stacks", epoch)
		}
	}
	fmt.Fprintf(testWriter{t}, "stacks: %d epochs, %d PrivateMessages decrypted across the stacks\n", last, tmcSum(life.decrypted))
	if !slices.Contains(life.members, passive) || len(life.transcript.Epochs) < 10 {
		t.Fatalf("the passive member's transcript holds %d epochs", len(life.transcript.Epochs))
	}
	if path := os.Getenv("MLSINTEROP_TRANSCRIPT_OUT"); path != "" {
		encoded, err := json.MarshalIndent([]*tmcTranscript{life.transcript}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote the passive member's transcript, %d epochs, to %s", len(life.transcript.Epochs), path)
	}
}

// Every checked-in transcript replays through tmc/mls as its passive client: it joins the Welcome on the tree beside
// it, and each commit lands it on the epoch_authenticator the transcript names.
func TestTmcReplaysTheInteropTranscripts(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(interopRootDirectory(t), "testdata", "mls", "0x0010", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no 0x0010 transcript is checked in")
	}
	decode := func(text string) []byte {
		decoded, err := hex.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	for _, path := range paths {
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		transcripts := []*tmcTranscript{}
		if err := json.Unmarshal(encoded, &transcripts); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for index, transcript := range transcripts {
			if transcript.CipherSuite != uint16(tmcSuite) {
				t.Fatalf("%s %d: suite %#04x", path, index, transcript.CipherSuite)
			}
			client := &mls.Client{
				CipherSuite:    tmcSuite,
				KeyPackage:     tmcMessage(t, decode(transcript.KeyPackage)).KeyPackage,
				InitPriv:       decode(transcript.InitPriv),
				EncryptionPriv: decode(transcript.EncryptionPriv),
				SignaturePriv:  decode(transcript.SignaturePriv),
			}
			tree := mls.RatchetTree{}
			if err := mls.Unmarshal(decode(transcript.RatchetTree), &tree); err != nil {
				t.Fatalf("%s %d: ratchet_tree: %v", path, index, err)
			}
			group, err := client.Join(tmcMessage(t, decode(transcript.Welcome)).Welcome, tree)
			if err != nil {
				t.Fatalf("%s %d: join: %v", path, index, err)
			}
			if !bytes.Equal(group.EpochAuthenticator(), decode(transcript.InitialEpochAuthenticator)) {
				t.Fatalf("%s %d: another initial epoch_authenticator", path, index)
			}
			for epochIndex, epoch := range transcript.Epochs {
				if group, _, err = group.Handle(tmcMessage(t, decode(epoch.Commit))); err != nil {
					t.Fatalf("%s %d: epoch %d: %v", path, index, epochIndex, err)
				}
				if !bytes.Equal(group.EpochAuthenticator(), decode(epoch.EpochAuthenticator)) {
					t.Fatalf("%s %d: epoch %d: another epoch_authenticator", path, index, epochIndex)
				}
			}
			t.Logf("%s %d: joined at epoch %d and followed %d commits to epoch %d", filepath.Base(path), index,
				group.Epoch()-uint64(len(transcript.Epochs)), len(transcript.Epochs), group.Epoch())
		}
	}
}

func tmcSum(counts map[uint64]int) int {
	sum := 0
	for _, count := range counts {
		sum += count
	}
	return sum
}

// t.Log as an io.Writer.
type testWriter struct {
	t *testing.T
}

func (self testWriter) Write(data []byte) (int, error) {
	self.t.Log(string(bytes.TrimRight(data, "\n")))
	return len(data), nil
}
