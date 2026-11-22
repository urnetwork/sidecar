// QD-1178 (question e2e-evs-concurrency-statement-pin-before-previous-base, option 1) on the stand-in evs, its readers
// judging every statement against a real authorization log (testConfigNet), and two bases folded past the pushes, as
// every confirmed ACL save and each fold land them: a path written before them reads on the device that verified it
// then and on a new device started at the newest base, a reader long offline walks what it missed, a writer plans over
// a parent written before them, and a removed device's earlier writes stay readable; a forged statement, one pinned
// off the chain or ahead of the state, and one whose signer no retained row admits at its pin are still refused.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A stand-in world whose readers judge against a real log: the repo created there by the owner, its writer a member
// device the log admits and grants writing, each push the world commits pinned at the log's tip as it then stood.
type evsTestRetainedWorld struct {
	net    *testConfigNet
	repoId Id
	writer testConfigDevice
	world  *evsTestWorld
}

func newEvsTestRetainedWorld(t *testing.T) *evsTestRetainedWorld {
	t.Helper()
	return newEvsTestRetainedWorldOn(t, newTestConfigNet(t))
}

// newEvsTestRetainedWorld's world on net, whose log its readers judge against: a ConfigClient's world's, say, which
// follows net through api's projection (evs_read_pin_ahead_test.go).
func newEvsTestRetainedWorldOn(t *testing.T, net *testConfigNet) *evsTestRetainedWorld {
	t.Helper()
	writer := net.admitMemberDevice("evs writer")
	repoId := net.createRepo("evs unretained")
	world := newEvsTestWorld(t)
	world.repoId = repoId
	refKey, err := NewEvsRefKey(evsTestRepoKey(repoId, 1))
	if err != nil {
		t.Fatal(err)
	}
	if world.refId, err = EvsRefId(refKey, EvsMainRefName); err != nil {
		t.Fatal(err)
	}
	world.config.repo = &protocol.AclRepo{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}
	self := &evsTestRetainedWorld{net: net, repoId: repoId, writer: writer, world: world}
	self.grantWriter(writer)
	self.signAs(writer)
	return self
}

// Grants device writing the repo through the log, at its tip.
func (self *evsTestRetainedWorld) grantWriter(device testConfigDevice) {
	self.net.t.Helper()
	self.net.mustPost(self.net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
		Header: self.net.header(), RepoId: self.repoId.Bytes(), Subject: device.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER,
	})
	if !slices.Contains(self.net.log.State().RepoWriters(self.repoId), device.sidecarId) {
		self.net.t.Fatal("the granted device does not write the repo")
	}
}

// Has the world's next pushes signed by key under sidecarId, whose key the stand-in's push route takes.
func (self *evsTestRetainedWorld) signWith(sidecarId Id, signer *evsTestSigner) {
	self.world.signer = &evsTestSigner{sidecarId: sidecarId, privateKey: signer.privateKey}
	self.world.config.stateLock.Lock()
	defer self.world.config.stateLock.Unlock()
	self.world.config.identityKeys[sidecarId] = signer.publicKey()
	self.world.config.writers = append(self.world.config.writers, sidecarId)
}

// Has the world's next pushes signed by device.
func (self *evsTestRetainedWorld) signAs(device testConfigDevice) {
	self.signWith(device.sidecarId, &evsTestSigner{sidecarId: device.sidecarId, privateKey: device.key})
}

// Commits changes pinned at pin.
func (self *evsTestRetainedWorld) pushAt(pin *bridge.AuthPin, changes ...*evsTestChange) uint64 {
	self.world.authVersion, self.world.authChain = pin.GetVersion(), bytes.Clone(pin.GetChain())
	return self.world.push(changes...)
}

// Commits changes pinned at the log's tip.
func (self *evsTestRetainedWorld) push(changes ...*evsTestChange) uint64 {
	return self.pushAt(self.net.log.Pin(), changes...)
}

// A reader whose config follows the log throughout.
func (self *evsTestRetainedWorld) follower(t *testing.T, label string) *evsTestClient {
	t.Helper()
	reader := self.world.reader(t, evsTestId(label))
	reader.client.args.Config = func() GkmAuthView { return self.net.log.State() }
	return reader
}

// A new device started at the newest base, its config a log restored from what the net's reader retains, and that
// log's own catch-up, which applies whatever entries the net sequenced since.
func (self *evsTestRetainedWorld) started(t *testing.T, label string) (*evsTestClient, func()) {
	t.Helper()
	restored, _ := self.net.startedReaders()
	reader := self.world.reader(t, evsTestId(label))
	reader.client.args.Config = func() GkmAuthView { return restored.State() }
	catchUp := func() {
		t.Helper()
		for _, entryBytes := range self.net.entries {
			entry := &bridge.AuthEntry{}
			if err := proto.Unmarshal(entryBytes, entry); err != nil {
				t.Fatal(err)
			}
			if entry.GetN() <= restored.State().Pin().GetVersion() {
				continue
			}
			if _, err := restored.Apply(entryBytes, self.net.source); err != nil {
				t.Fatal(err)
			}
		}
	}
	return reader, catchUp
}

// Two bases folded past every entry through at, failing the test unless reader no longer retains at.
func (self *evsTestRetainedWorld) foldPast(t *testing.T, at *bridge.AuthPin) {
	t.Helper()
	self.net.foldPast(at.GetVersion())
	if _, err := self.net.log.StateAt(at); !errors.Is(err, ErrConfigPinNotRetained) {
		t.Fatalf("the pin %d is still retained: %v", at.GetVersion(), err)
	}
}

// A writer over the world, its config the log's tip, signing as device.
func (self *evsTestRetainedWorld) writerOf(t *testing.T, device testConfigDevice) *evsTestWriter {
	t.Helper()
	server := newEvsTestPushServer(t, self.world)
	gkm := newEvsTestWriteGkm()
	test := newEvsTestClient(t, server, newEvsTestStore(t))
	test.client.args.Gkm = gkm
	test.client.args.Config = func() GkmAuthView { return self.net.log.State() }
	signer := &evsTestSigner{sidecarId: device.sidecarId, privateKey: device.key}
	test.client.args.Sign = signer.sign
	identity := &SidecarIdentity{NetworkId: testNetworkId, SidecarId: device.sidecarId, ClientId: evsTestId("retained world client")}
	test.client.args.Identity = func() *SidecarIdentity { return identity }
	return &evsTestWriter{world: self.world, server: server, gkm: gkm, test: test, repo: test.client.Repo(self.repoId)}
}

// Requires path to read as content on reader, with no alarm.
func (self *evsTestRetainedWorld) requireReads(t *testing.T, label string, reader *evsTestClient, path string, content string) {
	t.Helper()
	got, _, err := evsTestRead(t, reader, self.world, path)
	if err != nil {
		t.Errorf("%s: %s: %v", label, path, err)
		return
	}
	if string(got) != content {
		t.Errorf("%s: %s read %q, not %q", label, path, got, content)
	}
	evsTestRequireNoAlarm(t, label, reader)
}

// A path written before two bases reads on the device that verified it then, as does one written beside it that the
// device never read, whose statement lies below the device's pin: what this device verified when it was new is taken
// as verified, and its signature still checks.
func TestEvsPathWrittenBeforeTwoBasesReadsOnTheDeviceThatVerifiedIt(t *testing.T) {
	retained := newEvsTestRetainedWorld(t)
	written := retained.net.log.Pin()
	retained.push(&evsTestChange{path: "a.txt", content: []byte("written before the bases")})
	retained.push(&evsTestChange{path: "b.txt", content: []byte("never read before the bases")})
	device := retained.follower(t, "device that verified it")
	retained.requireReads(t, "before the bases", device, "a.txt", "written before the bases")

	retained.foldPast(t, written)
	retained.requireReads(t, "after the bases", device, "a.txt", "written before the bases")
	retained.requireReads(t, "after the bases", device, "b.txt", "never read before the bases")
	pin, ok, _ := device.client.pins.Pin(retained.repoId, retained.world.refId)
	if headVersion, _ := retained.world.head(); !ok || pin.Version != headVersion {
		t.Errorf("the pin %+v, the head %d", pin, headVersion)
	}
}

// A path written before two bases reads on a new device started at the newest base, whose walk from C_0 meets only
// statements pinned before what it retains: each taken on its signature, the chain reaching the head it verifies and
// pins. A reader long offline, pinned before the second write, walks it above its pin as the new device does; and once
// the ref moves past the bases, a statement pinned where both retain is judged again.
func TestEvsPathWrittenBeforeTwoBasesReadsOnANewDevice(t *testing.T) {
	retained := newEvsTestRetainedWorld(t)
	written := retained.net.log.Pin()
	retained.push(&evsTestChange{path: "a.txt", content: []byte("first")})
	offline := retained.follower(t, "reader long offline")
	retained.requireReads(t, "before it went offline", offline, "a.txt", "first")
	retained.push(&evsTestChange{path: "b.txt", content: []byte("second")})

	retained.foldPast(t, written)
	device, catchUp := retained.started(t, "new device")
	if _, err := device.client.args.Config().At(written); !errors.Is(err, ErrGkmAuthNotRetained) {
		t.Fatalf("the new device judges the first push's pin: %v", err)
	}
	retained.requireReads(t, "the new device", device, "a.txt", "first")
	retained.requireReads(t, "the new device", device, "b.txt", "second")
	retained.requireReads(t, "the reader long offline", offline, "b.txt", "second")

	// a push where both retain, which a writer the state no longer lists would fail
	retained.push(&evsTestChange{path: "c.txt", content: []byte("third")})
	catchUp()
	retained.requireReads(t, "the new device past the bases", device, "c.txt", "third")
	retained.requireReads(t, "the reader long offline past the bases", offline, "c.txt", "third")
}

// A writer plans over a parent written before two bases: its plan reads the standing directory, whose statement is
// pinned before what it retains, and its push lands; a new device then reads both files under it.
func TestEvsWriterPlansOverAParentWrittenBeforeTwoBases(t *testing.T) {
	retained := newEvsTestRetainedWorld(t)
	writer := retained.writerOf(t, retained.writer)
	written := retained.net.log.Pin()
	if _, err := writer.write(t, "docs/a.txt", []byte("under a parent")); err != nil {
		t.Fatal(err)
	}

	retained.foldPast(t, written)
	if _, err := writer.write(t, "docs/b.txt", []byte("planned over the parent")); err != nil {
		t.Fatalf("a write planned over a parent written before two bases: %v", err)
	}
	evsTestRequireNoAlarm(t, "the writer", writer.test)
	device, _ := retained.started(t, "new device")
	retained.requireReads(t, "the new device", device, "docs/a.txt", "under a parent")
	retained.requireReads(t, "the new device", device, "docs/b.txt", "planned over the parent")
}

// A removed device's writes made before its removal stay readable once two bases pass them, on a device that read
// them then and on a new one, though the rows hold its row revoked: a statement is judged at its own pin, never at a
// state it was not signed under.
func TestEvsRemovedDevicesEarlierWritesReadPastTwoBases(t *testing.T) {
	retained := newEvsTestRetainedWorld(t)
	removed := retained.net.admitMemberDevice("removed writer")
	retained.grantWriter(removed)
	retained.signAs(removed)
	written := retained.net.log.Pin()
	retained.push(&evsTestChange{path: "removed.txt", content: []byte("before its removal")})
	device := retained.follower(t, "device that read it")
	retained.requireReads(t, "before the removal", device, "removed.txt", "before its removal")
	retained.net.mustPost(retained.net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE,
		retained.net.revocation(removed, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))
	retained.signAs(retained.writer)
	retained.push(&evsTestChange{path: "kept.txt", content: []byte("by the writer that stays")})

	retained.foldPast(t, written)
	if row := retained.net.log.State().SidecarRow(removed.sidecarId); row.GetRevokedAt() == 0 {
		t.Fatal("the removed device's row is not revoked")
	}
	retained.requireReads(t, "the device that read it", device, "removed.txt", "before its removal")
	newDevice, _ := retained.started(t, "new device")
	retained.requireReads(t, "the new device", newDevice, "removed.txt", "before its removal")
	retained.requireReads(t, "the new device", newDevice, "kept.txt", "by the writer that stays")
}

// A statement pinned before two bases whose signature its signer's key does not verify is refused and alarmed as
// tampering, on the device that verified the ref before it and on a new device walking it from C_0; the paths the walk
// needs it for read on neither.
func TestEvsForgedStatementPinnedBeforeTwoBasesRefused(t *testing.T) {
	retained := newEvsTestRetainedWorld(t)
	written := retained.net.log.Pin()
	retained.push(&evsTestChange{path: "a.txt", content: []byte("genuine")})
	device := retained.follower(t, "device that verified it")
	retained.requireReads(t, "before the forgery", device, "a.txt", "genuine")
	// evs serves, as the ref's next version, a statement naming the writer that another key signed
	forger := newEvsTestSigner("forger")
	retained.world.signer = &evsTestSigner{sidecarId: retained.writer.sidecarId, privateKey: forger.privateKey}
	retained.pushAt(written, &evsTestChange{path: "b.txt", content: []byte("forged")})

	retained.foldPast(t, written)
	if _, _, err := evsTestRead(t, device, retained.world, "b.txt"); !errors.Is(err, ErrEvsStatementRefused) {
		t.Errorf("the device that verified the ref read a forged statement: %v", err)
	}
	evsTestRequireTamper(t, "the device that verified the ref", device, 1)
	newDevice, _ := retained.started(t, "new device")
	if _, _, err := evsTestRead(t, newDevice, retained.world, "a.txt"); !errors.Is(err, ErrEvsStatementRefused) {
		t.Errorf("the new device read past a forged statement: %v", err)
	}
	evsTestRequireTamper(t, "the new device", newDevice, 1)
}

// A statement pinned off the reader's chain before what it retains, where the reader still holds a base's chain value
// there, is refused as a fork whatever its signature; one pinned ahead of the reader's state, which has no log to wait
// on (EvsClientArgs.ConfigWait, QD-1202), is withheld with no alarm; one pinned before the window where the reader holds
// no chain value is taken on its signature, which must verify.
func TestEvsStatementPinOffTheChainOrAheadStillRefused(t *testing.T) {
	retained := newEvsTestRetainedWorld(t)
	written := retained.net.log.Pin()
	retained.push(&evsTestChange{path: "a.txt", content: []byte("genuine")})
	retained.foldPast(t, written)
	reader := retained.follower(t, "reader")
	verifier := reader.client.verifier
	state := retained.net.log.State()
	firstBase := retained.net.statesAt[1].Pin()
	if _, err := state.StateAt(firstBase); !errors.Is(err, ErrConfigPinNotRetained) {
		t.Fatalf("base 1's pin is still retained: %v", err)
	}
	statementAt := func(label string, pin *bridge.AuthPin, signer *evsTestSigner) []byte {
		plan := evsTestPlan(t, signer, label, 1)
		plan.RepoId, plan.RefId, plan.Auth = retained.repoId, retained.world.refId, pin
		built, err := NewEvsStatementBuilder(signer.sign).Build(plan)
		if err != nil {
			t.Fatal(err)
		}
		return built.Statement.Bytes
	}
	genuine := &evsTestSigner{sidecarId: retained.writer.sidecarId, privateKey: retained.writer.key}

	offChain := proto.Clone(firstBase).(*bridge.AuthPin)
	offChain.Chain[0] ^= 0xff
	_, err := verifier.VerifyStatement(t.Context(), statementAt("off the chain", offChain, genuine), retained.repoId, retained.world.refId)
	if !errors.Is(err, ErrEvsStatementRefused) || !errors.Is(err, ErrGkmAuthOffChain) {
		t.Errorf("a pin off the chain before the window: %v", err)
	}

	ahead := &bridge.AuthPin{Version: state.Pin().GetVersion() + 1, Chain: make([]byte, sha256.Size)}
	_, err = verifier.VerifyStatement(t.Context(), statementAt("ahead", ahead, genuine), retained.repoId, retained.world.refId)
	if !errors.Is(err, ErrGkmAuthAhead) {
		t.Errorf("a pin ahead of the state: %v", err)
	}

	// a position the reader keeps no chain value at, between base 1 and the window
	unknown := &bridge.AuthPin{Version: written.GetVersion(), Chain: make([]byte, sha256.Size)}
	if _, err := state.StateAt(unknown); !errors.Is(err, ErrConfigPinNotRetained) {
		t.Fatalf("the reader judges position %d: %v", unknown.GetVersion(), err)
	}
	if _, err := verifier.VerifyStatement(t.Context(), statementAt("unknown", unknown, genuine), retained.repoId, retained.world.refId); err != nil {
		t.Errorf("a genuine statement at a pin the reader cannot place: %v", err)
	}
	forged := &evsTestSigner{sidecarId: retained.writer.sidecarId, privateKey: newEvsTestSigner("forger").privateKey}
	if _, err := verifier.VerifyStatement(t.Context(), statementAt("forged", unknown, forged), retained.repoId, retained.world.refId); !errors.Is(err, ErrEvsStatementRefused) {
		t.Errorf("a forged statement at a pin the reader cannot place: %v", err)
	}
}

// A statement pinned before two bases is refused where no retained row admits its signer at that pin, and alarmed as
// tampering: a signer the log never admitted, one admitted after the pin, and one revoked at or before it, each
// signing with its own key.
func TestEvsSignerNoRetainedRowAdmitsAtItsPinRefused(t *testing.T) {
	cases := []struct {
		label string
		// the signer and the pin its statement names, set up on the world's log
		signer func(retained *evsTestRetainedWorld) (Id, *evsTestSigner, *bridge.AuthPin)
	}{
		{label: "never admitted", signer: func(retained *evsTestRetainedWorld) (Id, *evsTestSigner, *bridge.AuthPin) {
			stranger := newEvsTestSigner("stranger")
			return stranger.sidecarId, stranger, retained.net.log.Pin()
		}},
		{label: "admitted after the pin", signer: func(retained *evsTestRetainedWorld) (Id, *evsTestSigner, *bridge.AuthPin) {
			pin := retained.net.log.Pin()
			late := retained.net.admitMemberDevice("late writer")
			retained.grantWriter(late)
			return late.sidecarId, &evsTestSigner{sidecarId: late.sidecarId, privateKey: late.key}, pin
		}},
		{label: "revoked at or before the pin", signer: func(retained *evsTestRetainedWorld) (Id, *evsTestSigner, *bridge.AuthPin) {
			revoked := retained.net.admitMemberDevice("revoked writer")
			retained.grantWriter(revoked)
			retained.net.mustPost(retained.net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE,
				retained.net.revocation(revoked, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))
			return revoked.sidecarId, &evsTestSigner{sidecarId: revoked.sidecarId, privateKey: revoked.key}, retained.net.log.Pin()
		}},
	}
	for _, c := range cases {
		retained := newEvsTestRetainedWorld(t)
		written := retained.net.log.Pin()
		retained.push(&evsTestChange{path: "a.txt", content: []byte("genuine")})
		sidecarId, signer, pin := c.signer(retained)
		retained.signWith(sidecarId, signer)
		retained.pushAt(pin, &evsTestChange{path: "b.txt", content: []byte(c.label)})

		retained.foldPast(t, pin)
		if _, err := retained.net.log.StateAt(written); !errors.Is(err, ErrConfigPinNotRetained) {
			t.Fatalf("%s: the first push's pin is still retained: %v", c.label, err)
		}
		device, _ := retained.started(t, fmt.Sprint("new device ", c.label))
		_, _, err := evsTestRead(t, device, retained.world, "b.txt")
		if !errors.Is(err, ErrEvsStatementRefused) || !errors.Is(err, ErrConfigSignerNotAdmitted) {
			t.Errorf("%s: %v", c.label, err)
		}
		evsTestRequireTamper(t, c.label, device, 1)
	}
}

// The key a state gives a signer for a pin before what it retains, on the log's own reader and on a new device started
// at its newest base: the oldest retained rows' key for one admitted at or before the pin and not revoked by it, the
// Genesis's device's included; ErrConfigSignerNotAdmitted for one never admitted, admitted after the pin, or revoked at
// or before it, while what it signed before its revocation keeps its key.
func TestConfigRetainedIdentityKeyFromTheOldestRetainedRows(t *testing.T) {
	net := newTestConfigNet(t)
	device := net.admitMemberDevice("signer")
	admittedPin := net.log.Pin()
	net.admitMemberDevice("between")
	beforeRevokePin := net.log.Pin()
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(device, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	revokedPin := net.log.Pin()
	late := net.admitMemberDevice("late")
	net.foldPast(net.n)
	restored, _ := net.startedReaders()
	for _, state := range []*ConfigState{net.log.State(), restored.State()} {
		for _, pin := range []*bridge.AuthPin{admittedPin, beforeRevokePin, revokedPin} {
			if _, err := state.StateAt(pin); !errors.Is(err, ErrConfigPinNotRetained) {
				t.Fatalf("the pin %d is still retained: %v", pin.GetVersion(), err)
			}
		}
		key, err := state.retainedIdentityKey(device.sidecarId, beforeRevokePin)
		if err != nil || !bytes.Equal(key, device.publicKey()) {
			t.Errorf("before its revocation: %x %v", key, err)
		}
		if key, err := state.retainedIdentityKey(device.sidecarId, admittedPin); err != nil || !bytes.Equal(key, device.publicKey()) {
			t.Errorf("at its admission: %x %v", key, err)
		}
		if key, err := state.retainedIdentityKey(net.owner.sidecarId, admittedPin); err != nil || !bytes.Equal(key, net.owner.publicKey()) {
			t.Errorf("the Genesis's device: %x %v", key, err)
		}
		refusals := []struct {
			label     string
			sidecarId Id
			pin       *bridge.AuthPin
		}{
			{label: "at its revocation", sidecarId: device.sidecarId, pin: revokedPin},
			{label: "admitted after the pin", sidecarId: late.sidecarId, pin: revokedPin},
			{label: "never admitted", sidecarId: testConfigId("stranger"), pin: revokedPin},
		}
		for _, refusal := range refusals {
			if key, err := state.retainedIdentityKey(refusal.sidecarId, refusal.pin); !errors.Is(err, ErrConfigSignerNotAdmitted) || key != nil {
				t.Errorf("%s: %x %v", refusal.label, key, err)
			}
		}
	}
}
