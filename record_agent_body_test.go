//go:build !sidecar_http && !ios_extension

// record_agent_body.go's version-2 entries and record_receipt.go's audit read, on sidecartest's streams and
// authorization state: an agent's note sealed version 2 by a writer whose subkey a reader verifies, with its
// commitment opened by the AgentSignedBody and nothing of the subkey outside the sealed body; a body with no
// certificate reading agent_asserted; a bad subkey signature, a certificate another key signed and a body naming
// another agent each alarming bad_entry and never attributed, the body still shown; a revoked agent, a failing signer
// and the setting off each sealing version 1; a version the reader does not know kept, its header verified and its
// body shown generically; a T entry's copy in the vault opening by its AgentSignedBody; and FS-30's audit-reader
// case, the audit reader's second read journaled for the team record before anything is decrypted, once across a
// restart and a re-read, never for an EvsShare subject, and refusing the read where T takes nothing. External, as
// record_writer_test.go.

package sidecar_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A device's agent subkeys as Sidecar.SignProvenance holds them, made by hand so a test can break each part: one
// subkey an agent, its certificate signed by the device's identity key.
type testAgentSubkeys struct {
	t      *testing.T
	device *testRecordDevice

	stateLock sync.Mutex
	agentKeys map[sidecar.Id]ed25519.PrivateKey
	// what the signer answers in place of signing, when set
	err error
	// signs the certificate in place of the device's identity key, when set
	certKey ed25519.PrivateKey
	// leaves the certificate out
	noCert bool
	// signs these bytes in place of the message
	otherMessage []byte
	signCount    int
}

// Binds a device's record to subkeys made here, which turns version 2 on for it.
func newTestAgentSubkeys(t *testing.T, device *testRecordDevice) *testAgentSubkeys {
	subkeys := &testAgentSubkeys{t: t, device: device, agentKeys: map[sidecar.Id]ed25519.PrivateKey{}}
	device.signProvenance = subkeys.sign
	return subkeys
}

// The agent's subkey, made at first use.
func (self *testAgentSubkeys) keyWithLock(agentId sidecar.Id) ed25519.PrivateKey {
	if key, ok := self.agentKeys[agentId]; ok {
		return key
	}
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		self.t.Fatal(err)
	}
	self.agentKeys[agentId] = key
	return key
}

// The agent's subkey's public key.
func (self *testAgentSubkeys) publicKey(agentId sidecar.Id) ed25519.PublicKey {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.keyWithLock(agentId).Public().(ed25519.PublicKey)
}

func (self *testAgentSubkeys) signs() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.signCount
}

// sidecar.RecordAgentSignFunction.
func (self *testAgentSubkeys) sign(agentId sidecar.Id, purpose string, message []byte) (*sidecar.AgentProvenanceSignature, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.signCount += 1
	if self.err != nil {
		return nil, self.err
	}
	key := self.keyWithLock(agentId)
	publicKey := key.Public().(ed25519.PublicKey)
	keyId := sha256.Sum256(publicKey)
	if self.otherMessage != nil {
		message = self.otherMessage
	}
	signature := &sidecar.AgentProvenanceSignature{
		AgentId:   agentId,
		KeyId:     keyId[:],
		Signature: ed25519.Sign(key, sidecar.AgentProvenanceSignedBytes(purpose, message)),
	}
	if self.noCert {
		return signature, nil
	}
	body, err := proto.Marshal(&protocol.AgentCert{
		SidecarId:  self.device.sidecarId.Bytes(),
		AgentId:    agentId.Bytes(),
		PublicKey:  publicKey,
		NotAfterMs: self.device.world.clock.Now().Add(24 * time.Hour).UnixMilli(),
	})
	if err != nil {
		return nil, err
	}
	certKey := self.device.key
	if self.certKey != nil {
		certKey = self.certKey
	}
	cert, err := proto.Marshal(&bridge.Signed{
		Body:      body,
		SignerId:  self.device.sidecarId.Bytes(),
		Signature: ed25519.Sign(certKey, bridge.SignedBytes(sidecar.AgentCertPurpose, bridge.SignedType_SIGNED_AGENT_CERT, body)),
		Type:      uint32(bridge.SignedType_SIGNED_AGENT_CERT),
	})
	if err != nil {
		return nil, err
	}
	signature.Cert = cert
	return signature, nil
}

// A note the agent files.
func testAgentNote(agentId sidecar.Id, text string) *sidecar.RecordDraft {
	draft := testRecordNote(nil, text)
	draft.AgentId = &agentId
	return draft
}

// The text of a note's body as stored.
func testAgentNoteText(t *testing.T, body []byte) string {
	t.Helper()
	note := &protocol.CoordinationBody{}
	if err := proto.Unmarshal(body, note); err != nil {
		t.Fatal(err)
	}
	return note.GetText()
}

// An agent's note from a writer with a subkey seals as version 2: the stored plaintext is an AgentSignedBody naming
// the agent, which the header's commitment opens by, as a version-1 reader finds it; this reader shows the note
// itself, verified, with no alarm; and nothing of the subkey sits outside the sealed body in what evs was handed.
func TestRecordAgentBodySealsVersionTwoAndVerifies(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	subkeys := newTestAgentSubkeys(t, device)
	record := device.open()
	agentId := sidecar.NewId()
	ref := testRecordAppend(t, record, testAgentNote(agentId, "from the agent"))
	testRecordAppend(t, record, testRecordNote(nil, "from the daemon"))
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if subkeys.signs() != 1 {
		t.Fatalf("the subkey signed %d times for one agent entry", subkeys.signs())
	}

	stored := world.storedEntries(device.sidecarId)
	if len(stored) != 2 {
		t.Fatalf("%d entries stored", len(stored))
	}
	if stored[0].entry.GetVersion() != 2 || stored[1].entry.GetVersion() != 1 {
		t.Fatalf("versions %d and %d", stored[0].entry.GetVersion(), stored[1].entry.GetVersion())
	}
	// what a version-1 reader opens: the commitment holds over the AgentSignedBody
	signedBody := &protocol.AgentSignedBody{}
	if err := proto.Unmarshal(stored[0].body, signedBody); err != nil {
		t.Fatal(err)
	}
	keyId := sha256.Sum256(subkeys.publicKey(agentId))
	if !bytes.Equal(signedBody.GetAgentId(), agentId.Bytes()) || !bytes.Equal(signedBody.GetKeyId(), keyId[:]) ||
		len(signedBody.GetSignature()) != ed25519.SignatureSize || len(signedBody.GetAgentCert()) == 0 {
		t.Fatalf("the sealed body: %v", signedBody)
	}
	if testAgentNoteText(t, signedBody.GetBody()) != "from the agent" {
		t.Error("the sealed body holds another note")
	}
	message := sidecar.RecordAgentBodyMessage(world.vaultId, ref.EntryId, signedBody.GetBody())
	if !ed25519.Verify(subkeys.publicKey(agentId), sidecar.AgentProvenanceSignedBytes(sidecar.AgentProvenancePurposeRecord, message), signedBody.GetSignature()) {
		t.Error("the subkey did not sign log_id || entry_id || body under record-agent")
	}
	if !bytes.Equal(stored[0].header.GetAgentId(), agentId.Bytes()) {
		t.Error("the header names another agent")
	}

	// only the identity key signs what evs stores, and the subkey's material rides inside the sealed body alone
	for _, push := range device.tap.pushes {
		for _, entry := range push.Entries {
			stream := &protocol.RecordEntry{}
			if err := proto.Unmarshal(entry.Entry, stream); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(stream.GetHeader().GetSignerId(), device.sidecarId.Bytes()) || len(stream.GetHeader().GetKeyId()) != 0 {
				t.Error("a header's Signed is not the identity key's")
			}
			for name, secret := range map[string][]byte{
				"key id": keyId[:], "signature": signedBody.GetSignature(), "certificate": signedBody.GetAgentCert(),
				"public key": subkeys.publicKey(agentId),
			} {
				if bytes.Contains(entry.Entry, secret) {
					t.Errorf("an entry holds the subkey's %s outside its sealed body", name)
				}
			}
		}
	}

	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if len(entries) != 2 {
		t.Fatalf("%d entries read", len(entries))
	}
	agentEntry, daemonEntry := entries[0], entries[1]
	if agentEntry.EntryId != ref.EntryId {
		agentEntry, daemonEntry = entries[1], entries[0]
	}
	if agentEntry.Version != 2 || agentEntry.AgentProvenance != sidecar.RecordAgentProvenanceVerified || agentEntry.BodyInvalid ||
		agentEntry.BodyGeneric || agentEntry.State != sidecar.RecordEntryLive {
		t.Fatalf("the agent's entry reads version %d, provenance %q, invalid %t", agentEntry.Version, agentEntry.AgentProvenance, agentEntry.BodyInvalid)
	}
	if testAgentNoteText(t, agentEntry.Body) != "from the agent" {
		t.Error("the agent's entry shows another body")
	}
	if !bytes.Equal(agentEntry.CommittedBody(), stored[0].body) {
		t.Error("the committed body is not the AgentSignedBody as stored")
	}
	opening := &protocol.Opening{Header: agentEntry.SignedBytes, Salt: agentEntry.Salt, Body: agentEntry.CommittedBody()}
	if _, err := sidecar.VerifyRecordOpening(opening); err != nil {
		t.Errorf("the entry's opening: %v", err)
	}
	if daemonEntry.Version != 1 || daemonEntry.AgentProvenance != "" || daemonEntry.Sealed != nil ||
		!bytes.Equal(daemonEntry.CommittedBody(), daemonEntry.Body) {
		t.Errorf("the daemon's entry reads version %d, provenance %q", daemonEntry.Version, daemonEntry.AgentProvenance)
	}
	if reasons := reader.reasons(); len(reasons) != 0 {
		t.Errorf("the reader raised %v", reasons)
	}

	// the opened form, for a reader of an opening that knows its entry is version 2
	opened, err := sidecar.RecordAgentBodyOpen(agentEntry.Header, agentEntry.CommittedBody(), device.key.Public().(ed25519.PublicKey), nil)
	if err != nil || opened.Provenance != sidecar.RecordAgentProvenanceVerified || !bytes.Equal(opened.AgentId, agentId.Bytes()) {
		t.Errorf("the opening's agent body: %v", err)
	}
	if _, err := sidecar.RecordAgentBodyOpen(daemonEntry.Header, []byte{0xff, 0xff, 0xff}, nil, nil); !errors.Is(err, sidecar.ErrRecordBodyInvalid) {
		t.Errorf("bytes that are no AgentSignedBody: %v", err)
	}
}

// QD-159: a version-2 body with no certificate cannot be checked, so its agent reads agent_asserted, never verified,
// with no alarm.
func TestRecordAgentBodyWithoutACertReadsAsserted(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	subkeys := newTestAgentSubkeys(t, device)
	subkeys.noCert = true
	record := device.open()
	testRecordAppend(t, record, testAgentNote(sidecar.NewId(), "asserted"))
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if len(entries) != 1 || entries[0].Version != 2 || entries[0].AgentProvenance != sidecar.RecordAgentProvenanceAsserted {
		t.Fatalf("%d entries, the first %+v", len(entries), entries)
	}
	if testAgentNoteText(t, entries[0].Body) != "asserted" {
		t.Error("the body is not shown")
	}
	if reasons := reader.reasons(); len(reasons) != 0 {
		t.Errorf("the reader raised %v", reasons)
	}
}

// A subkey signature over other bytes and a certificate another key signed each read invalid: the reader alarms
// bad_entry once for each, attributes neither, and still shows the body, which stands on the writer's signature.
func TestRecordAgentBodyBadSubkeySignatureAlarms(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	subkeys := newTestAgentSubkeys(t, device)
	record := device.open()
	agentId := sidecar.NewId()

	subkeys.otherMessage = []byte("another entry's bytes")
	testRecordAppend(t, record, testAgentNote(agentId, "a signature over other bytes"))
	subkeys.otherMessage = nil
	_, otherKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	subkeys.certKey = otherKey
	testRecordAppend(t, record, testAgentNote(agentId, "a certificate another key signed"))
	subkeys.certKey = nil
	testRecordAppend(t, record, testAgentNote(agentId, "a good one"))
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}

	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if len(entries) != 3 {
		t.Fatalf("%d entries read", len(entries))
	}
	provenances := map[string]sidecar.RecordAgentProvenance{}
	for _, entry := range entries {
		if entry.BodyInvalid || entry.State != sidecar.RecordEntryLive || entry.Body == nil {
			t.Fatalf("an entry's body is not shown: %+v", entry)
		}
		provenances[testAgentNoteText(t, entry.Body)] = entry.AgentProvenance
	}
	if provenances["a signature over other bytes"] != sidecar.RecordAgentProvenanceInvalid ||
		provenances["a certificate another key signed"] != sidecar.RecordAgentProvenanceInvalid ||
		provenances["a good one"] != sidecar.RecordAgentProvenanceVerified {
		t.Errorf("provenances %v", provenances)
	}
	if reasons := reader.reasons(); !slices.Equal(reasons, []sidecar.SidecarRecordAlarm{sidecar.SidecarRecordAlarmBadEntry, sidecar.SidecarRecordAlarmBadEntry}) {
		t.Errorf("the reader raised %v", reasons)
	}
}

// An entry of the device's chain sealed by hand over stored bytes its writer chose: version as given, its header
// naming agentId, the chain adopting it.
func testAgentHandSeal(t *testing.T, device *testRecordDevice, hand *testRecordHandChain, agentId sidecar.Id, stored []byte, version uint32) *sidecar.RecordSealedEntry {
	t.Helper()
	world := device.world
	head, err := hand.env.Chain.Head(world.vaultId)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	salt := make([]byte, 32)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	for _, draw := range [][]byte{key, salt, nonce} {
		if _, err := rand.Read(draw); err != nil {
			t.Fatal(err)
		}
	}
	commitment, err := sidecar.RecordBodyCommitment(salt, stored)
	if err != nil {
		t.Fatal(err)
	}
	entryId := sidecar.NewId()
	headerBytes, err := proto.Marshal(&protocol.RecordHeader{
		EntryId:         entryId.Bytes(),
		LogId:           world.vaultId.Bytes(),
		WriterSidecarId: device.sidecarId.Bytes(),
		Seq:             head.Seq + 1,
		PrevSha256:      head.Leaf[:],
		Kind:            uint32(sidecar.RecordKindNote),
		TimeMillis:      world.clock.Now().UnixMilli(),
		Source:          uint32(sidecar.RecordSourceAgent),
		AgentSource:     uint32(sidecar.RecordAgentSourceAsserted),
		AgentId:         agentId.Bytes(),
		Tainted:         true,
		BodyCommitment:  commitment[:],
		PolicyVersion:   world.auth.Tip().Pin().GetVersion(),
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := device.sign(sidecar.RecordEntryPurpose, bridge.SignedType_SIGNED_RECORD_HEADER, headerBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	signedBytes, err := proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	aad := append(append([]byte("urnetwork-sidecar-v1/record-seal"), world.vaultId[:]...), entryId[:]...)
	sealed := &sidecar.RecordSealedEntry{
		LogId:      world.vaultId,
		EntryId:    entryId,
		Seq:        head.Seq + 1,
		Leaf:       sidecar.RecordLeafHash(headerBytes),
		Signed:     signedBytes,
		SealedBody: aead.Seal(bytes.Clone(nonce), nonce, stored, aad),
		Key:        key,
		Salt:       salt,
		Version:    version,
	}
	if _, err := hand.env.Chain.Adopt(world.vaultId, sidecar.RecordChainHead{Seq: sealed.Seq, Leaf: sealed.Leaf}); err != nil {
		t.Fatal(err)
	}
	return sealed
}

// A version-2 body naming another agent than its header, which the identity key signed, is never attributed and
// alarms; bytes that are no AgentSignedBody show as an invalid body with the header standing; and the seal itself
// refuses a signature that is not the header's agent's, moving no chain.
func TestRecordAgentBodyNamingAnotherAgentAlarms(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	hand := device.handChain()
	headerAgentId := sidecar.NewId()
	bodyAgentId := sidecar.NewId()
	subkeys := &testAgentSubkeys{t: t, device: device, agentKeys: map[sidecar.Id]ed25519.PrivateKey{}}
	if _, err := sidecar.RecordSeal(hand.env, &sidecar.RecordSealArgs{
		LogId: world.vaultId, Kind: sidecar.RecordKindNote, Source: sidecar.RecordSourceAgent,
		AgentSource: sidecar.RecordAgentSourceAsserted, AgentId: &headerAgentId, TimeMillis: world.clock.Now().UnixMilli(),
		Tainted: true, PolicyVersion: world.auth.Tip().Pin().GetVersion(), Body: &protocol.CoordinationBody{Text: "whose"},
		AgentSign: func(agentId sidecar.Id, purpose string, message []byte) (*sidecar.AgentProvenanceSignature, error) {
			return subkeys.sign(bodyAgentId, purpose, message)
		},
	}); !errors.Is(err, sidecar.ErrRecordSealInvalid) {
		t.Fatalf("a signature for another agent sealed: %v", err)
	}
	if head, err := hand.env.Chain.Head(world.vaultId); err != nil || head.Seq != 0 {
		t.Fatalf("the refused seal moved the chain: %v", err)
	}

	// version 2 over bytes the writer built itself: an AgentSignedBody naming another agent, and bytes that are none
	other, err := subkeys.sign(bodyAgentId, sidecar.AgentProvenancePurposeRecord, []byte("anything"))
	if err != nil {
		t.Fatal(err)
	}
	note, err := proto.Marshal(&protocol.CoordinationBody{Text: "whose"})
	if err != nil {
		t.Fatal(err)
	}
	mismatched, err := proto.Marshal(&protocol.AgentSignedBody{
		Body: note, AgentId: bodyAgentId.Bytes(), KeyId: other.KeyId, Signature: other.Signature, AgentCert: other.Cert,
	})
	if err != nil {
		t.Fatal(err)
	}
	first := testAgentHandSeal(t, device, hand, headerAgentId, mismatched, 2)
	second := testAgentHandSeal(t, device, hand, headerAgentId, []byte{0xff, 0xff, 0xff}, 2)
	third := hand.seal("after them")
	device.pushHand([]uint64{1, 2, 3}, []*sidecar.RecordSealedEntry{first, second, third}, nil)

	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if len(entries) != 3 {
		t.Fatalf("%d entries read", len(entries))
	}
	byId := map[sidecar.Id]*sidecar.RecordReadEntry{}
	for _, entry := range entries {
		byId[entry.EntryId] = entry
	}
	if entry := byId[first.EntryId]; entry.AgentProvenance != sidecar.RecordAgentProvenanceInvalid || entry.BodyInvalid ||
		entry.Body == nil || testAgentNoteText(t, entry.Body) != "whose" {
		t.Errorf("a body naming another agent reads %+v", entry)
	}
	if entry := byId[second.EntryId]; !entry.BodyInvalid || entry.Body != nil || entry.State != sidecar.RecordEntryLive {
		t.Errorf("bytes that are no AgentSignedBody read %+v", entry)
	}
	if entry := byId[third.EntryId]; entry.Version != 1 || entry.BodyInvalid || entry.AgentProvenance != "" {
		t.Errorf("the version-1 entry after them reads %+v", entry)
	}
	if reasons := reader.reasons(); !slices.Equal(reasons, []sidecar.SidecarRecordAlarm{sidecar.SidecarRecordAlarmBadEntry, sidecar.SidecarRecordAlarmBadEntry}) {
		t.Errorf("the reader raised %v", reasons)
	}
}

// An agent this daemon signs nothing more for still gets its entry: a revoked subkey and a signer that fails each
// seal version 1, the agent the writer's word, and so does a writer with no signer bound.
func TestRecordAgentBodyUnsignedSealsVersionOne(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	subkeys := newTestAgentSubkeys(t, device)
	record := device.open()
	agentId := sidecar.NewId()
	subkeys.err = sidecar.ErrAgentSubkeyRevoked
	testRecordAppend(t, record, testAgentNote(agentId, "revoked"))
	subkeys.err = errors.New("the keychain failed")
	testRecordAppend(t, record, testAgentNote(agentId, "failed"))
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if subkeys.signs() != 2 {
		t.Fatalf("the signer was asked %d times", subkeys.signs())
	}

	off := world.device(true)
	offRecord := off.open()
	testRecordAppend(t, offRecord, testAgentNote(agentId, "off"))
	if err := offRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}

	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if len(entries) != 3 {
		t.Fatalf("%d entries read", len(entries))
	}
	for _, entry := range entries {
		if entry.Version != 1 || entry.AgentProvenance != "" || entry.Sealed != nil || entry.BodyInvalid ||
			!bytes.Equal(entry.Header.Header.GetAgentId(), agentId.Bytes()) {
			t.Errorf("the %q entry reads version %d, provenance %q", testAgentNoteText(t, entry.Body), entry.Version, entry.AgentProvenance)
		}
	}
	if reasons := reader.reasons(); len(reasons) != 0 {
		t.Errorf("the reader raised %v", reasons)
	}
}

// The settings default leaves version 2 off until M6's rollout sets it.
func TestRecordAgentBodyOffByDefault(t *testing.T) {
	if sidecar.DefaultSidecarSettings().AgentSubkeys.SignRecordEntries {
		t.Fatal("version 2 seals by default")
	}
}

// An entry of a version this reader does not know is kept: its header verifies and chains, its body is shown
// generically, as its committed bytes and never parsed as its kind, and nothing alarms.
func TestRecordReaderKeepsAnUnknownVersion(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	hand := device.handChain()
	first := hand.seal("first")
	later := hand.seal("from a later version")
	later.Version = 3
	third := hand.seal("third")
	device.pushHand([]uint64{1, 2, 3}, []*sidecar.RecordSealedEntry{first, later, third}, nil)

	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if len(entries) != 3 {
		t.Fatalf("%d entries read", len(entries))
	}
	for _, entry := range entries {
		if entry.State != sidecar.RecordEntryLive || entry.BodyInvalid {
			t.Fatalf("entry %s reads %+v", entry.EntryId, entry)
		}
		if entry.EntryId != later.EntryId {
			if entry.Version != 1 || entry.BodyGeneric || entry.Body == nil {
				t.Errorf("a version-1 entry reads %+v", entry)
			}
			continue
		}
		if entry.Version != 3 || !entry.BodyGeneric || entry.Body != nil || entry.AgentProvenance != "" {
			t.Errorf("the later version's entry reads %+v", entry)
		}
		opening := &protocol.Opening{Header: entry.SignedBytes, Salt: entry.Salt, Body: entry.CommittedBody()}
		if _, err := sidecar.VerifyRecordOpening(opening); err != nil {
			t.Errorf("the later version's committed bytes: %v", err)
		}
	}
	if reasons := reader.reasons(); len(reasons) != 0 {
		t.Errorf("the reader raised %v", reasons)
	}
}

// A T entry an agent filed seals version 2 as well, and its copy in the author's vault opens it by the
// AgentSignedBody its commitment covers, whose body is T's projection.
func TestRecordAgentBodyTeamCopyOpensByTheSignedBody(t *testing.T) {
	world := newTestTeamWorld(t)
	device := world.memberDevice(true)
	admin := world.adminDevice()
	newTestAgentSubkeys(t, device)
	record := device.open()
	runId := sidecar.NewId()
	world.runs.StartRun(runId)
	agentId := sidecar.NewId()
	for _, draft := range testTeamRunDrafts(&runId) {
		draft.AgentId = &agentId
		if _, err := record.Writer().Append(draft); err != nil {
			t.Fatal(err)
		}
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	deposited := world.teamDeposits(device.sidecarId, admin.sidecarId)
	if len(deposited) != 3 {
		t.Fatalf("%d entries in T", len(deposited))
	}
	teamBodies := map[sidecar.Id][]byte{}
	for _, entry := range deposited {
		opened, err := sidecar.RecordAgentBodyOpen(entry.header, entry.body, device.key.Public().(ed25519.PublicKey), nil)
		if err != nil || opened.Provenance != sidecar.RecordAgentProvenanceVerified {
			t.Fatalf("T's %s entry: %v", entry.header.Kind(), err)
		}
		if err := sidecar.RecordBodyValidateStored(entry.header.Kind(), opened.Body); err != nil {
			t.Errorf("T's %s entry's body: %v", entry.header.Kind(), err)
		}
		teamBodies[sidecar.Id(entry.header.Header.GetEntryId())] = entry.body
	}
	copies := 0
	for _, entry := range world.storedEntries(device.sidecarId) {
		if sidecar.RecordKind(entry.header.GetKind()) != sidecar.RecordKindCopy {
			continue
		}
		// a copy is the daemon's own entry, whatever agent filed what it copies
		if len(entry.header.GetAgentId()) == 0 && entry.entry.GetVersion() != 1 {
			t.Errorf("a copy with no agent sealed version %d", entry.entry.GetVersion())
		}
		body := &protocol.CopyBody{}
		stored := entry.body
		if entry.entry.GetVersion() == 2 {
			signedBody := &protocol.AgentSignedBody{}
			if err := proto.Unmarshal(stored, signedBody); err != nil {
				t.Fatal(err)
			}
			stored = signedBody.GetBody()
		}
		if err := proto.Unmarshal(stored, body); err != nil || len(body.GetEntries()) != 1 {
			t.Fatalf("a copy: %v", err)
		}
		opened, err := sidecar.VerifyRecordOpening(body.GetEntries()[0])
		if err != nil {
			t.Fatalf("a copy's opening: %v", err)
		}
		if !bytes.Equal(opened.Body, teamBodies[sidecar.Id(opened.Header.Header.GetEntryId())]) {
			t.Error("a copy opens by other bytes than T's entry seals")
		}
		copies += 1
	}
	if copies != 3 {
		t.Errorf("%d copies", copies)
	}
}

// The world's audit reader: a sidecar of another member that reads the vault as the Team's audit block has it,
// depositing read receipts alone there, and, when inTeam, depositing to the team record.
func (self *testTeamWorld) auditReader(inTeam bool) *testRecordDevice {
	self.t.Helper()
	reader := self.shareReader()
	vault := self.fixture.Repos[self.vaultId]
	vault.AuditReaders = append(vault.AuditReaders, reader.sidecarId)
	self.publish()
	if inTeam {
		self.admitToTeam(reader)
	}
	return reader
}

// Makes a device a depositor of the team record.
func (self *testTeamWorld) admitToTeam(device *testRecordDevice) {
	self.t.Helper()
	repo := self.fixture.Repos[self.teamRecordId]
	repo.Depositors = append(repo.Depositors, device.sidecarId)
	if err := self.streams.Grant(self.teamRecordId, device.sidecarId, sidecartest.RecordStreamsScope{Deposit: true}); err != nil {
		self.t.Fatal(err)
	}
	self.publish()
}

// The read entries a device deposited to the team record and nothing consumed, each body parsed.
func (self *testTeamWorld) teamReads(depositorId sidecar.Id, adminId sidecar.Id) []*protocol.ReadBody {
	self.t.Helper()
	reads := []*protocol.ReadBody{}
	for _, entry := range self.teamDeposits(depositorId, adminId) {
		if entry.header.Kind() != sidecar.RecordKindRead || sidecar.RecordSource(entry.header.Header.GetSource()) != sidecar.RecordSourceObserved ||
			len(entry.header.Header.GetRunId()) != 0 || len(entry.header.Header.GetAgentId()) != 0 {
			self.t.Fatalf("a team deposit of kind %s: %v", entry.header.Kind(), entry.header.Header)
		}
		body := &protocol.ReadBody{}
		if err := proto.Unmarshal(entry.body, body); err != nil {
			self.t.Fatal(err)
		}
		reads = append(reads, body)
	}
	return reads
}

// FS-30's audit-reader case: the audit reader's read of a vault lands its receipt there before anything is
// decrypted, as any EvsShare reader's, and files a second read for the team record, naming the vault, its objects and
// purpose, journaled before the read returns and carried to T by the writer; a re-read the same day files neither
// again, and a restart before T's deposit went out sends it once. The team record's ingester takes it, and a reader
// of T shows who read what with no alarm.
func TestRecordAuditReaderFilesASecondReadToTheTeamRecord(t *testing.T) {
	world := newTestTeamWorld(t)
	author := world.device(true)
	admin := world.adminDevice()
	reader := world.auditReader(true)
	key := &testReceiptKey{}
	objectIds := testReceiptObjectIds(t, 2, 16)
	record := reader.open()
	if err := testReceiptRead(t.Context(), record, world.testRecordWorld, key, sidecar.RecordReadPurposeRead, objectIds); err != nil {
		t.Fatal(err)
	}
	if key.uses() != 2 {
		t.Fatalf("the read decrypted %d objects", key.uses())
	}
	waiting := world.receiptsWaiting(author, reader)
	if len(waiting) != 1 || len(waiting[0].body.GetReadLogId()) != 0 {
		t.Fatalf("%d receipts in the vault", len(waiting))
	}
	// journaled for T before the read returned, though nothing went out yet
	if reads := world.teamReads(reader.sidecarId, admin.sidecarId); len(reads) != 0 {
		t.Fatalf("%d reads reached T before a flush", len(reads))
	}

	// a kill before T's deposit goes out: the next process carries the journaled read, once
	record = reader.open()
	if err := testReceiptRead(t.Context(), record, world.testRecordWorld, key, sidecar.RecordReadPurposeRead, objectIds); err != nil {
		t.Fatal(err)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	reads := world.teamReads(reader.sidecarId, admin.sidecarId)
	if len(reads) != 1 {
		t.Fatalf("%d reads in T", len(reads))
	}
	if !bytes.Equal(reads[0].GetReadLogId(), world.vaultId.Bytes()) || reads[0].GetPurpose() != uint32(sidecar.RecordReadPurposeRead) ||
		!slices.EqualFunc(reads[0].GetObjectIds(), objectIds, bytes.Equal) {
		t.Errorf("T's read: %v", reads[0])
	}
	if waiting := world.receiptsWaiting(author, reader); len(waiting) != 1 {
		t.Errorf("%d receipts in the vault after the re-read", len(waiting))
	}

	// the team record's ingester takes it, and a reader of T shows it
	adminRecord := admin.open()
	if err := adminRecord.Ingester().Ingest(t.Context(), world.teamRecordId); err != nil {
		t.Fatal(err)
	}
	if err := adminRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	teamReader := world.newReader(nil, nil)
	if err := teamReader.reader.Sync(t.Context(), world.teamRecordId); err != nil {
		t.Fatal(err)
	}
	entries := teamReader.reader.Entries(world.teamRecordId)
	if len(entries) != 1 || entries[0].Kind() != sidecar.RecordKindRead || entries[0].State != sidecar.RecordEntryLive ||
		entries[0].BodyInvalid || sidecar.Id(entries[0].Header.Header.GetWriterSidecarId()) != reader.sidecarId {
		t.Fatalf("T reads %d entries", len(entries))
	}
	if reasons := teamReader.reasons(); len(reasons) != 0 {
		t.Errorf("T's reader raised %v", reasons)
	}
	if reasons := admin.alarmReasons(); len(reasons) != 0 {
		t.Errorf("T's ingest raised %v", reasons)
	}
}

// The trap: an EvsShare subject's reads stay between it and the author. A share reader the state does not list as
// the audit reader files its receipt in the vault and nothing for the team record, though it may deposit there.
func TestRecordShareSubjectsReadsStayWithTheAuthor(t *testing.T) {
	world := newTestTeamWorld(t)
	author := world.device(true)
	admin := world.adminDevice()
	subject := world.shareReader()
	world.admitToTeam(subject)
	key := &testReceiptKey{}
	record := subject.open()
	if err := testReceiptRead(t.Context(), record, world.testRecordWorld, key, sidecar.RecordReadPurposeRead, testReceiptObjectIds(t, 3, 16)); err != nil {
		t.Fatal(err)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if key.uses() != 3 {
		t.Fatalf("the read decrypted %d objects", key.uses())
	}
	if waiting := world.receiptsWaiting(author, subject); len(waiting) != 1 {
		t.Fatalf("%d receipts in the vault", len(waiting))
	}
	if reads := world.teamReads(subject.sidecarId, admin.sidecarId); len(reads) != 0 {
		t.Errorf("a share subject's read reached T: %v", reads)
	}
	for _, deposit := range subject.tap.depositAttempts() {
		if deposit.DepositorSidecarId != subject.sidecarId {
			t.Fatal("a deposit by another sidecar")
		}
	}
	if len(subject.tap.depositAttempts()) != 1 {
		t.Errorf("%d deposits by the share subject", len(subject.tap.depositAttempts()))
	}
}

// An audit reader the team record takes nothing from is refused its read, with nothing decrypted, since the read
// could not be reported; once it may deposit there, the same read goes through on the receipt evs already holds.
func TestRecordAuditReaderRefusedWithoutTheTeamRecord(t *testing.T) {
	world := newTestTeamWorld(t)
	author := world.device(true)
	admin := world.adminDevice()
	reader := world.auditReader(false)
	key := &testReceiptKey{}
	objectIds := testReceiptObjectIds(t, 1, 32)
	record := reader.open()
	err := testReceiptRead(t.Context(), record, world.testRecordWorld, key, sidecar.RecordReadPurposeRead, objectIds)
	if !errors.Is(err, sidecar.ErrRecordReceiptRefused) || !errors.Is(err, sidecar.ErrRecordReceiptNotDepositor) {
		t.Fatalf("the read: %v", err)
	}
	if key.uses() != 0 {
		t.Fatalf("a refused read decrypted %d objects", key.uses())
	}

	world.admitToTeam(reader)
	if err := testReceiptRead(t.Context(), record, world.testRecordWorld, key, sidecar.RecordReadPurposeRead, objectIds); err != nil {
		t.Fatal(err)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if key.uses() != 1 {
		t.Fatalf("the read decrypted %d objects", key.uses())
	}
	if waiting := world.receiptsWaiting(author, reader); len(waiting) != 1 {
		t.Errorf("%d receipts in the vault", len(waiting))
	}
	if reads := world.teamReads(reader.sidecarId, admin.sidecarId); len(reads) != 1 || !bytes.Equal(reads[0].GetReadLogId(), world.vaultId.Bytes()) {
		t.Errorf("%d reads in T", len(reads))
	}
}
