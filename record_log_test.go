//go:build !sidecar_http

// RECORD-M6-05's verifiable log on sidecartest's streams and authorization state, with a witness made here that keeps
// c2sp.org/tlog-witness's rules: RECORD.md section 20's log cases that need no hook. A batch a second reader rebuilds
// equals the first; batches run across two writers' streams by ref id; a witness at each error code is left out and
// named; a successor's note extends the log, and a witness without its key answers 403; a second entry for one batch
// is kept once and one with another note alarms; the leaf list survives its entries' expiry; a tampered batch alarms
// at every reader; and only a confirmed log admin turns the log on, on the team record alone.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A witness as a customer would run one, in memory: it cosigns a note of an origin it knows, signed by a key it
// trusts, that extends what it last cosigned, and answers c2sp.org/tlog-witness's codes otherwise. A test can make
// it answer one status to everything, or be unreachable.
type testLogWitness struct {
	t    *testing.T
	name string
	key  ed25519.PrivateKey

	stateLock sync.Mutex
	// the log keys it trusts, by origin
	originKeys map[string][]*sidecar.RecordLogVerifierKey
	sizes      map[string]uint64
	roots      map[string][sha256.Size]byte
	// every root it cosigned, by origin and size
	cosigned map[string]map[uint64][sha256.Size]byte
	// every note it cosigned, in order
	notes [][]byte
	// answers this status to everything, when not 0
	forcedStatus int
	unreachable  bool
	requestCount int
	timeSeconds  uint64
}

func newTestLogWitness(t *testing.T, name string) *testLogWitness {
	t.Helper()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &testLogWitness{
		t: t, name: name, key: key,
		originKeys:  map[string][]*sidecar.RecordLogVerifierKey{},
		sizes:       map[string]uint64{},
		roots:       map[string][sha256.Size]byte{},
		cosigned:    map[string]map[uint64][sha256.Size]byte{},
		timeSeconds: 1762387200,
	}
}

// The witness as a log_settings names it.
func (self *testLogWitness) args() *sidecar.RecordLogWitnessArgs {
	key, err := sidecar.NewRecordLogVerifierKey(self.name, sidecar.RecordLogKeyTypeCosignatureV1, self.key.Public().(ed25519.PublicKey))
	if err != nil {
		self.t.Fatal(err)
	}
	return &sidecar.RecordLogWitnessArgs{Name: self.name, Url: "https://" + self.name + ".witness.example/log", Vkey: key.String()}
}

// Trusts a log key for its origin, as the witness's operator does.
func (self *testLogWitness) trust(vkey string) {
	key, err := sidecar.ParseRecordLogVerifierKey(vkey)
	if err != nil {
		self.t.Fatal(err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.originKeys[key.Name] = append(self.originKeys[key.Name], key)
}

func (self *testLogWitness) force(status int, unreachable bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.forcedStatus = status
	self.unreachable = unreachable
}

func (self *testLogWitness) noteCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.notes)
}

func (self *testLogWitness) heldNotes() [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.notes)
}

func (self *testLogWitness) AddCheckpoint(ctx context.Context, url string, request []byte) (*sidecar.RecordLogWitnessAnswer, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.requestCount += 1
	if self.unreachable {
		return nil, errors.New("witness unreachable")
	}
	if self.forcedStatus != 0 {
		return &sidecar.RecordLogWitnessAnswer{Status: self.forcedStatus}, nil
	}
	if url != self.args().Url {
		return &sidecar.RecordLogWitnessAnswer{Status: http.StatusNotFound}, nil
	}
	oldSize, proof, noteBytes, err := sidecar.ParseRecordLogWitnessRequest(request)
	if err != nil {
		return &sidecar.RecordLogWitnessAnswer{Status: http.StatusBadRequest}, nil
	}
	note, err := sidecar.ParseRecordLogNote(noteBytes)
	if err != nil {
		return &sidecar.RecordLogWitnessAnswer{Status: http.StatusBadRequest}, nil
	}
	keys, known := self.originKeys[note.Origin]
	if !known {
		return &sidecar.RecordLogWitnessAnswer{Status: http.StatusNotFound}, nil
	}
	if !slices.ContainsFunc(keys, func(key *sidecar.RecordLogVerifierKey) bool { _, err := note.SignedBy(key); return err == nil }) {
		return &sidecar.RecordLogWitnessAnswer{Status: http.StatusForbidden}, nil
	}
	size := self.sizes[note.Origin]
	if oldSize != size || note.Size < size {
		return &sidecar.RecordLogWitnessAnswer{Status: http.StatusConflict, Body: []byte(fmt.Sprintf("%d\n", size))}, nil
	}
	if !sidecar.RecordLogVerifyConsistency(size, note.Size, self.roots[note.Origin], note.Root, proof) {
		return &sidecar.RecordLogWitnessAnswer{Status: http.StatusUnprocessableEntity}, nil
	}
	if self.cosigned[note.Origin] == nil {
		self.cosigned[note.Origin] = map[uint64][sha256.Size]byte{}
	}
	if root, held := self.cosigned[note.Origin][note.Size]; held && root != note.Root {
		self.t.Errorf("witness %s was asked to cosign a second root at size %d", self.name, note.Size)
	}
	self.cosigned[note.Origin][note.Size] = note.Root
	self.sizes[note.Origin] = note.Size
	self.roots[note.Origin] = note.Root
	self.notes = append(self.notes, bytes.Clone(noteBytes))
	self.timeSeconds += 1
	line, err := sidecar.RecordLogCosign(note.Body, self.name, self.key, self.timeSeconds)
	if err != nil {
		return nil, err
	}
	return &sidecar.RecordLogWitnessAnswer{Status: http.StatusOK, Body: line}, nil
}

// A team network whose team record has admins, and devices opened with a witness client.
type testLogWorld struct {
	*testTeamWorld
}

func newTestLogWorld(t *testing.T) *testLogWorld {
	t.Helper()
	return &testLogWorld{testTeamWorld: newTestTeamWorld(t)}
}

// A log admin's device: it reads and writes the team record's stream, and is an admin of the log.
func (self *testLogWorld) admin() *testRecordDevice {
	self.t.Helper()
	device := self.adminDevice()
	repo := self.fixture.Repos[self.teamRecordId]
	repo.Admins = append(repo.Admins, device.sidecarId)
	self.publish()
	return device
}

// A device that only reads the team record.
func (self *testLogWorld) reader() *testRecordDevice {
	self.t.Helper()
	device := self.device(false)
	repo := self.fixture.Repos[self.teamRecordId]
	repo.Readers = append(repo.Readers, device.sidecarId)
	if err := self.streams.Grant(self.teamRecordId, device.sidecarId, sidecartest.RecordStreamsScope{Read: true}); err != nil {
		self.t.Fatal(err)
	}
	self.publish()
	return device
}

// One process's life of a device's record, reaching witnesses through witness.
func (self *testRecordDevice) openWith(witness sidecar.RecordLogWitness) *sidecar.SidecarRecord {
	self.t.Helper()
	record, err := sidecar.NewSidecarRecord(&sidecar.SidecarRecordArgs{
		SidecarId:         self.sidecarId,
		IdentityPublicKey: self.key.Public().(ed25519.PublicKey),
		Store:             self.store,
		Sign:              self.sign,
		Spool:             self.spool,
		Runs:              self.world.runs,
		Streams:           self.tap,
		Auth:              func() sidecar.RecordAuthView { return self.world.auth.Tip() },
		Alarm: func(alarm *sidecar.RecordAlarm) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.alarms = append(self.alarms, alarm)
		},
		Clock:    self.world.clock,
		Settings: self.settings,
		Witness:  witness,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return record
}

// How many log_check alarms the device raised so far.
func (self *testRecordDevice) logCheckCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, alarm := range self.alarms {
		if alarm.Reason == sidecar.SidecarRecordAlarmLogCheck {
			count += 1
		}
	}
	return count
}

// A witness client no test expects to be called.
type testLogNoWitness struct {
	t *testing.T
}

func (self testLogNoWitness) AddCheckpoint(ctx context.Context, url string, request []byte) (*sidecar.RecordLogWitnessAnswer, error) {
	self.t.Errorf("a witness was called at %s", url)
	return nil, errors.New("no witness")
}

// An entry a log admin's device writes straight to the team record: a day's inventory naming one agent.
func testLogEntry(t *testing.T, record *sidecar.SidecarRecord) *sidecar.RecordEntryRef {
	t.Helper()
	ref := testRecordAppend(t, record, &sidecar.RecordDraft{
		Kind: sidecar.RecordKindInventory, Source: sidecar.RecordSourceObserved, NoSession: true,
		Body: &protocol.InventoryBody{Agents: []*protocol.InventoryAgent{{AgentId: sidecar.NewId().Bytes()}}},
	})
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	return ref
}

// Turns the log on from record's device, with witnesses.
func testLogOn(t *testing.T, world *testLogWorld, record *sidecar.SidecarRecord, witnesses ...*testLogWitness) {
	t.Helper()
	args := &sidecar.RecordLogOnArgs{LogId: world.teamRecordId, Confirmed: true}
	for _, witness := range witnesses {
		args.Witnesses = append(args.Witnesses, witness.args())
	}
	if err := record.Log().On(t.Context(), args); err != nil {
		t.Fatal(err)
	}
	status := testLogStatus(t, world, record)
	for _, witness := range witnesses {
		witness.trust(status.LogKey)
	}
}

// Syncs the team record and answers the log's status.
func testLogStatus(t *testing.T, world *testLogWorld, record *sidecar.SidecarRecord) *sidecar.RecordLogStatus {
	t.Helper()
	if err := record.Reader().Sync(t.Context(), world.teamRecordId); err != nil {
		t.Fatal(err)
	}
	status, err := record.Log().Status(world.teamRecordId)
	if err != nil {
		t.Fatal(err)
	}
	return status
}

// A checkpoint that must file a batch.
func testLogCheckpoint(t *testing.T, world *testLogWorld, record *sidecar.SidecarRecord) *sidecar.RecordLogCheckpointResult {
	t.Helper()
	result, err := record.Log().Checkpoint(t.Context(), world.teamRecordId, true)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("no batch was due")
	}
	return result
}

// The log key a device drew, read from its state file as only a test may.
func testLogKey(t *testing.T, world *testLogWorld, device *testRecordDevice) ed25519.PrivateKey {
	t.Helper()
	content, ok := device.files.Contents("record/log/" + hex.EncodeToString(world.teamRecordId[:]))
	if !ok {
		t.Fatalf("no log state among %v", device.files.Paths())
	}
	state := struct {
		KeySeed []byte `json:"key_seed"`
	}{}
	if err := json.Unmarshal(content, &state); err != nil || len(state.KeySeed) != ed25519.SeedSize {
		t.Fatalf("no log key in the state: %v", err)
	}
	return ed25519.NewKeyFromSeed(state.KeySeed)
}

// Every checkpoint entry the team record holds, as its reader opens them, in read order.
func testLogCheckpoints(t *testing.T, world *testLogWorld, record *sidecar.SidecarRecord) []*protocol.LogCheckpointBody {
	t.Helper()
	if err := record.Reader().Sync(t.Context(), world.teamRecordId); err != nil {
		t.Fatal(err)
	}
	entries, _ := record.Reader().EntriesOfKinds(world.teamRecordId, 0, sidecar.RecordKindCheckpoint)
	bodies := []*protocol.LogCheckpointBody{}
	for _, entry := range entries {
		body := &protocol.LogCheckpointBody{}
		if err := proto.Unmarshal(entry.Body, body); err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
	}
	return bodies
}

// RECORD.md section 20: a batch rebuilt by a second reader equals the first, and each entry's proof verifies under
// the note with nothing but the note, the path and the leaf.
func TestRecordLogSecondReaderRebuildsTheSameBatches(t *testing.T) {
	world := newTestLogWorld(t)
	admin := world.admin()
	record := admin.openWith(testLogNoWitness{t: t})
	testLogOn(t, world, record)
	refs := []*sidecar.RecordEntryRef{}
	for i := 0; i < 5; i += 1 {
		refs = append(refs, testLogEntry(t, record))
	}
	first := testLogCheckpoint(t, world, record)
	refs = append(refs, testLogEntry(t, record))
	second := testLogCheckpoint(t, world, record)
	if first.Batch != 1 || second.Batch != 2 || second.Size <= first.Size {
		t.Fatalf("batches %d (size %d) and %d (size %d)", first.Batch, first.Size, second.Batch, second.Size)
	}
	status := testLogStatus(t, world, record)
	if !status.On || !status.ThisDevice || status.Batch != 2 || status.Size != second.Size {
		t.Fatalf("the checkpointer's status: %+v", status)
	}

	reader := world.reader()
	other := reader.openWith(testLogNoWitness{t: t})
	otherStatus := testLogStatus(t, world, other)
	if otherStatus.Batch != status.Batch || otherStatus.Size != status.Size || !bytes.Equal(otherStatus.Root, status.Root) || otherStatus.ThisDevice {
		t.Fatalf("a second reader rebuilt batch %d size %d root %x, want batch %d size %d root %x",
			otherStatus.Batch, otherStatus.Size, otherStatus.Root, status.Batch, status.Size, status.Root)
	}
	if reader.logCheckCount() != 0 || admin.logCheckCount() != 0 || len(otherStatus.Findings) != 0 {
		t.Fatalf("an honest log alarmed: %v", otherStatus.Findings)
	}
	logKey, err := sidecar.ParseRecordLogVerifierKey(status.LogKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range refs {
		proof, err := other.Log().Proof(world.teamRecordId, ref.Leaf)
		if err != nil {
			t.Fatal(err)
		}
		note, err := sidecar.ParseRecordLogNote(proof.Checkpoint)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := note.SignedBy(logKey); err != nil {
			t.Fatalf("a proof's note is not the log key's: %v", err)
		}
		if !sidecar.RecordLogVerifyInclusion(ref.Leaf, proof.LeafIndex, note.Size, proof.InclusionPath, note.Root) {
			t.Fatalf("entry %s does not verify under batch %d", ref.EntryId, proof.Batch)
		}
	}
	// batch 1's own entry is a leaf of batch 2, and the newest checkpoint entry waits for the next
	if _, err := other.Log().Proof(world.teamRecordId, [sha256.Size]byte{1}); !errors.Is(err, sidecar.ErrRecordLogUncovered) {
		t.Fatalf("a leaf the log does not hold: %v", err)
	}
	if otherStatus.WaitingLeafCount != 1 {
		t.Fatalf("%d leaves wait, want the newest checkpoint entry alone", otherStatus.WaitingLeafCount)
	}
}

// Section 10.1's order across streams (record-md-log-order-across-streams): a batch takes each stream that moved, by
// ref id, and a second reader derives the same leaves in the same places.
func TestRecordLogBatchesRunAcrossStreamsByRefId(t *testing.T) {
	world := newTestLogWorld(t)
	adminA := world.admin()
	adminB := world.admin()
	recordA := adminA.openWith(testLogNoWitness{t: t})
	recordB := adminB.openWith(testLogNoWitness{t: t})
	testLogOn(t, world, recordA)
	refsA := []*sidecar.RecordEntryRef{testLogEntry(t, recordA), testLogEntry(t, recordA)}
	refsB := []*sidecar.RecordEntryRef{testLogEntry(t, recordB), testLogEntry(t, recordB)}
	testLogCheckpoint(t, world, recordA)
	checkpoints := testLogCheckpoints(t, world, recordA)
	if len(checkpoints) != 1 || len(checkpoints[0].GetFrontier()) != 2 {
		t.Fatalf("the batch's frontier: %v", checkpoints)
	}
	frontier := checkpoints[0].GetFrontier()
	if 0 <= bytes.Compare(frontier[0].GetRefId(), frontier[1].GetRefId()) {
		t.Fatalf("the frontier is not in ref id order")
	}
	refA := sidecartest.FakeRecordStreamRefId(world.teamRecordId, adminA.sidecarId)
	firstRefs, secondRefs := refsA, refsB
	if !bytes.Equal(frontier[0].GetRefId(), refA[:]) {
		firstRefs, secondRefs = refsB, refsA
	}
	proofOf := func(record *sidecar.SidecarRecord, ref *sidecar.RecordEntryRef) uint64 {
		proof, err := record.Log().Proof(world.teamRecordId, ref.Leaf)
		if err != nil {
			t.Fatal(err)
		}
		return proof.LeafIndex
	}
	for _, record := range []*sidecar.SidecarRecord{recordA, recordB} {
		if err := record.Reader().Sync(t.Context(), world.teamRecordId); err != nil {
			t.Fatal(err)
		}
		last := proofOf(record, firstRefs[len(firstRefs)-1])
		if next := proofOf(record, secondRefs[0]); next <= last {
			t.Fatalf("the later ref's leaves sit at %d, before the earlier ref's %d", next, last)
		}
		if proofOf(record, firstRefs[0]) >= proofOf(record, firstRefs[1]) || proofOf(record, secondRefs[0]) >= proofOf(record, secondRefs[1]) {
			t.Fatalf("a stream's leaves are out of its own order")
		}
	}
	if adminA.logCheckCount() != 0 || adminB.logCheckCount() != 0 {
		t.Fatalf("a log over two streams alarmed")
	}
	// the other writer does not govern the log
	if _, err := recordB.Log().Checkpoint(t.Context(), world.teamRecordId, true); !errors.Is(err, sidecar.ErrRecordLogNotCheckpointer) {
		t.Fatalf("a device that is not the checkpointer: %v", err)
	}
}

// A batch is cut when its interval has passed and entries other than checkpoint entries wait, never for a waiting
// checkpoint entry alone, so the log does not checkpoint itself forever.
func TestRecordLogCutsABatchOnlyWhenOneIsDue(t *testing.T) {
	world := newTestLogWorld(t)
	admin := world.admin()
	record := admin.openWith(testLogNoWitness{t: t})
	testLogOn(t, world, record)
	testLogCheckpoint(t, world, record)
	testLogEntry(t, record)
	result, err := record.Log().Checkpoint(t.Context(), world.teamRecordId, false)
	if err != nil || result != nil {
		t.Fatalf("a batch inside its interval: %v %v", result, err)
	}
	world.clock.Advance(admin.settings.CheckpointInterval)
	result, err = record.Log().Checkpoint(t.Context(), world.teamRecordId, false)
	if err != nil || result == nil || result.Batch != 2 {
		t.Fatalf("a batch past its interval: %v %v", result, err)
	}
	world.clock.Advance(admin.settings.CheckpointInterval)
	result, err = record.Log().Checkpoint(t.Context(), world.teamRecordId, false)
	if err != nil || result != nil {
		t.Fatalf("a batch for a checkpoint entry alone: %v %v", result, err)
	}
	if got := len(testLogCheckpoints(t, world, record)); got != 2 {
		t.Fatalf("%d checkpoint entries", got)
	}
}

// With a witness named, its cosignature of batch k rides batch k + 1's entry, every reader verifies it, and a note
// goes out at least every WitnessFreshInterval so its time stays fresh.
func TestRecordLogWitnessLinesRideTheNextEntry(t *testing.T) {
	world := newTestLogWorld(t)
	admin := world.admin()
	witness := newTestLogWitness(t, "auditor")
	record := admin.openWith(witness)
	testLogOn(t, world, record, witness)
	first := testLogCheckpoint(t, world, record)
	if !slices.Equal(first.CosignedNames, []string{"auditor"}) || witness.noteCount() != 1 {
		t.Fatalf("batch 1 cosigned by %v, the witness holding %d notes", first.CosignedNames, witness.noteCount())
	}
	checkpoints := testLogCheckpoints(t, world, record)
	if len(checkpoints[0].GetCosigned()) != 0 {
		t.Fatalf("a note's cosignature sits in its own entry")
	}
	world.clock.Advance(admin.settings.WitnessFreshInterval)
	result, err := record.Log().Checkpoint(t.Context(), world.teamRecordId, false)
	if err != nil || result == nil || result.Batch != 2 {
		t.Fatalf("no fresh note after the witness interval: %v %v", result, err)
	}
	checkpoints = testLogCheckpoints(t, world, record)
	if len(checkpoints) != 2 || len(checkpoints[1].GetCosigned()) != 1 || checkpoints[1].GetCosigned()[0].GetBatch() != 1 {
		t.Fatalf("batch 2's cosigned rows: %v", checkpoints[1].GetCosigned())
	}
	reader := world.reader()
	other := reader.openWith(testLogNoWitness{t: t})
	status := testLogStatus(t, world, other)
	if len(status.Witnesses) != 1 || status.Witnesses[0].CosignedBatch != 1 || reader.logCheckCount() != 0 {
		t.Fatalf("a reader's view of the witness: %+v, findings %v", status.Witnesses, status.Findings)
	}
	// a proof for an entry of batch 1 carries the cosigned note
	settings, _ := other.Reader().EntriesOfKinds(world.teamRecordId, 0, sidecar.RecordKindLogSettings)
	proof, err := other.Log().Proof(world.teamRecordId, settings[0].Leaf)
	if err != nil {
		t.Fatal(err)
	}
	note, err := sidecar.ParseRecordLogNote(proof.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	witnessKey, err := sidecar.ParseRecordLogVerifierKey(witness.args().Vkey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := note.SignedBy(witnessKey); err != nil || proof.Batch != 1 {
		t.Fatalf("the proof's note under batch %d is not cosigned: %v", proof.Batch, err)
	}
}

// RECORD.md section 20: a witness at each error code is left out of the note, the batch is filed all the same, and
// `ur record log status` names it; past WitnessMissCount misses it alarms. A 409 naming the witness's size has the
// proof rebuilt once, and then it cosigns.
func TestRecordLogWitnessAtEachErrorCodeIsLeftOut(t *testing.T) {
	cases := []struct {
		status      int
		unreachable bool
		refusal     string
	}{
		{status: http.StatusBadRequest, refusal: "400"},
		{status: http.StatusForbidden, refusal: "403"},
		{status: http.StatusNotFound, refusal: "404"},
		{status: http.StatusConflict, refusal: "409"},
		{status: http.StatusUnprocessableEntity, refusal: "422"},
		{status: http.StatusInternalServerError, refusal: "500"},
		{unreachable: true, refusal: "not reached"},
	}
	for _, c := range cases {
		world := newTestLogWorld(t)
		admin := world.admin()
		witness := newTestLogWitness(t, "auditor")
		record := admin.openWith(witness)
		testLogOn(t, world, record, witness)
		witness.force(c.status, c.unreachable)
		result := testLogCheckpoint(t, world, record)
		if result.Batch != 1 || len(result.CosignedNames) != 0 {
			t.Fatalf("%s: batch %d cosigned by %v", c.refusal, result.Batch, result.CosignedNames)
		}
		status := testLogStatus(t, world, record)
		if status.Batch != 1 || len(status.Witnesses) != 1 || status.Witnesses[0].MissCount != 1 || !strings.Contains(status.Witnesses[0].Refusal, c.refusal) {
			t.Fatalf("%s: status %+v", c.refusal, status.Witnesses[0])
		}
		alarmedAtOnce := c.status == http.StatusUnprocessableEntity
		if got := admin.logCheckCount(); (0 < got) != alarmedAtOnce {
			t.Fatalf("%s: %d alarms after one miss", c.refusal, got)
		}
		for i := 0; i < admin.settings.WitnessMissCount; i += 1 {
			testLogEntry(t, record)
			testLogCheckpoint(t, world, record)
		}
		if admin.logCheckCount() == 0 {
			t.Fatalf("%s: no alarm past %d misses", c.refusal, admin.settings.WitnessMissCount)
		}
		// back in order, it cosigns again, from the size it holds
		witness.force(0, false)
		testLogEntry(t, record)
		result = testLogCheckpoint(t, world, record)
		if !slices.Equal(result.CosignedNames, []string{"auditor"}) {
			t.Fatalf("%s: a witness back in order did not cosign", c.refusal)
		}
		status = testLogStatus(t, world, record)
		if status.Witnesses[0].MissCount != 0 || status.Witnesses[0].Refusal != "" || status.Witnesses[0].Size != result.Size {
			t.Fatalf("%s: status after a cosignature: %+v", c.refusal, status.Witnesses[0])
		}
	}
}

// A witness that cosigned through another route holds a size this checkpointer did not record: its 409 names that
// size, the proof is rebuilt from it once, and it cosigns.
func TestRecordLogWitnessConflictRebuildsTheProofOnce(t *testing.T) {
	world := newTestLogWorld(t)
	admin := world.admin()
	witness := newTestLogWitness(t, "auditor")
	record := admin.openWith(witness)
	testLogOn(t, world, record, witness)
	testLogCheckpoint(t, world, record)
	// the device's state loses what it knew of the witness, as a restored state file would
	path := "record/log/" + hex.EncodeToString(world.teamRecordId[:])
	content, _ := admin.files.Contents(path)
	state := map[string]json.RawMessage{}
	if err := json.Unmarshal(content, &state); err != nil {
		t.Fatal(err)
	}
	delete(state, "witnesses")
	rewritten, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := admin.store.Create("log/" + hex.EncodeToString(world.teamRecordId[:]))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(rewritten); err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	testLogEntry(t, record)
	before := witness.requestCount
	result := testLogCheckpoint(t, world, record)
	if !slices.Equal(result.CosignedNames, []string{"auditor"}) || witness.requestCount != before+2 {
		t.Fatalf("cosigned by %v after %d requests", result.CosignedNames, witness.requestCount-before)
	}
}

// RECORD.md section 20: a successor's note extends the log; the old checkpointer stops at step 1; a witness without
// the successor's key answers 403, is left out and named by status, and cosigns once its operator adds the key.
func TestRecordLogSuccessorExtendsTheLog(t *testing.T) {
	world := newTestLogWorld(t)
	oldAdmin := world.admin()
	newAdmin := world.admin()
	witness := newTestLogWitness(t, "auditor")
	oldRecord := oldAdmin.openWith(witness)
	newRecord := newAdmin.openWith(witness)
	testLogOn(t, world, oldRecord, witness)
	testLogEntry(t, oldRecord)
	first := testLogCheckpoint(t, world, oldRecord)

	// the successor replays every batch, then governs from the first it has not read
	args := &sidecar.RecordLogOnArgs{LogId: world.teamRecordId, Confirmed: true, Witnesses: []*sidecar.RecordLogWitnessArgs{witness.args()}}
	if err := newRecord.Log().On(t.Context(), args); err != nil {
		t.Fatal(err)
	}
	if _, err := oldRecord.Log().Checkpoint(t.Context(), world.teamRecordId, true); !errors.Is(err, sidecar.ErrRecordLogNotCheckpointer) {
		t.Fatalf("the old checkpointer after a successor's settings: %v", err)
	}
	oldStatus := testLogStatus(t, world, oldRecord)
	if oldStatus.ThisDevice || oldStatus.Stopped == "" || *oldStatus.CheckpointerSidecarId != newAdmin.sidecarId {
		t.Fatalf("the old checkpointer's status: %+v", oldStatus)
	}
	second := testLogCheckpoint(t, world, newRecord)
	if second.Batch != 2 || second.Size <= first.Size || len(second.CosignedNames) != 0 {
		t.Fatalf("the successor's batch %d size %d, cosigned by %v", second.Batch, second.Size, second.CosignedNames)
	}
	status := testLogStatus(t, world, newRecord)
	if !strings.Contains(status.Witnesses[0].Refusal, "403") {
		t.Fatalf("the witness without the successor's key: %+v", status.Witnesses[0])
	}
	witness.trust(status.LogKey)
	testLogEntry(t, newRecord)
	third := testLogCheckpoint(t, world, newRecord)
	if !slices.Equal(third.CosignedNames, []string{"auditor"}) {
		t.Fatalf("the witness with the successor's key did not cosign its note from size %d", first.Size)
	}
	// every reader verifies both signers' batches, each under the settings governing it
	reader := world.reader()
	other := reader.openWith(testLogNoWitness{t: t})
	if got := testLogStatus(t, world, other); got.Batch != 3 || reader.logCheckCount() != 0 {
		t.Fatalf("a reader across the succession: batch %d, findings %v", got.Batch, got.Findings)
	}
	if oldAdmin.logCheckCount() != 0 || newAdmin.logCheckCount() != 0 {
		t.Fatalf("a clean succession alarmed")
	}
}

// Files a checkpoint entry the test built, from device, signed by logKey over leaves.
func testLogForgeCheckpoint(t *testing.T, world *testLogWorld, record *sidecar.SidecarRecord, logKey ed25519.PrivateKey, change func(body *protocol.LogCheckpointBody, allLeaves [][sha256.Size]byte) [][sha256.Size]byte) {
	t.Helper()
	status := testLogStatus(t, world, record)
	streams, _ := record.Reader().Streams(world.teamRecordId)
	slices.SortFunc(streams, func(a, b *sidecar.RecordReadStream) int { return bytes.Compare(a.RefId[:], b.RefId[:]) })
	checkpoints := testLogCheckpoints(t, world, record)
	held := map[[sha256.Size]byte]bool{}
	tree := [][sha256.Size]byte{}
	versions := map[sidecar.Id]uint64{}
	for _, checkpoint := range checkpoints[:status.Batch] {
		for at := 0; at < len(checkpoint.GetLeaves()); at += sha256.Size {
			leaf := [sha256.Size]byte(checkpoint.GetLeaves()[at : at+sha256.Size])
			held[leaf] = true
			tree = append(tree, leaf)
		}
		for _, row := range checkpoint.GetFrontier() {
			versions[sidecar.Id(row.GetRefId())] = row.GetVersion()
		}
	}
	body := &protocol.LogCheckpointBody{Batch: status.Batch + 1, FirstIndex: uint64(len(tree))}
	fresh := [][sha256.Size]byte{}
	for _, stream := range streams {
		moved := false
		for _, push := range stream.Pushes {
			if push.Version <= versions[stream.RefId] {
				continue
			}
			moved = true
			for _, leaf := range push.Leaves {
				if !held[leaf.Leaf] {
					held[leaf.Leaf] = true
					fresh = append(fresh, leaf.Leaf)
				}
			}
		}
		if moved {
			last := stream.Pushes[len(stream.Pushes)-1]
			body.Frontier = append(body.Frontier, &protocol.LogFrontier{RefId: stream.RefId.Bytes(), Version: last.Version, Chain: last.Chain})
		}
	}
	fresh = change(body, fresh)
	for _, leaf := range fresh {
		body.Leaves = append(body.Leaves, leaf[:]...)
	}
	if body.Note == nil {
		root := sidecar.RecordLogRoot(append(tree, fresh...))
		note, err := sidecar.SignRecordLogNote(sidecar.RecordLogOrigin(world.teamRecordId), body.GetFirstIndex()+uint64(len(fresh)), root, logKey)
		if err != nil {
			t.Fatal(err)
		}
		body.Note = note
	}
	testRecordAppend(t, record, &sidecar.RecordDraft{Kind: sidecar.RecordKindCheckpoint, Source: sidecar.RecordSourceObserved, NoSession: true, Body: body})
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// RECORD.md section 20: a tampered batch alarms at every reader and is not taken. Each case is a checkpoint entry
// from the governing checkpointer's device, signed by its real log key unless the case says otherwise.
func TestRecordLogTamperedBatchAlarmsAtEveryReader(t *testing.T) {
	_, strangerKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(t *testing.T, world *testLogWorld, body *protocol.LogCheckpointBody, leaves [][sha256.Size]byte) [][sha256.Size]byte
		key    ed25519.PrivateKey
	}{
		{name: "an entry at or below the frontier left out", change: func(t *testing.T, world *testLogWorld, body *protocol.LogCheckpointBody, leaves [][sha256.Size]byte) [][sha256.Size]byte {
			return leaves[1:]
		}},
		{name: "two leaves swapped", change: func(t *testing.T, world *testLogWorld, body *protocol.LogCheckpointBody, leaves [][sha256.Size]byte) [][sha256.Size]byte {
			leaves[0], leaves[1] = leaves[1], leaves[0]
			return leaves
		}},
		{name: "a first index past the tree", change: func(t *testing.T, world *testLogWorld, body *protocol.LogCheckpointBody, leaves [][sha256.Size]byte) [][sha256.Size]byte {
			body.FirstIndex += 1
			return leaves
		}},
		{name: "a note over other leaves", change: func(t *testing.T, world *testLogWorld, body *protocol.LogCheckpointBody, leaves [][sha256.Size]byte) [][sha256.Size]byte {
			note, err := sidecar.SignRecordLogNote(sidecar.RecordLogOrigin(world.teamRecordId), body.GetFirstIndex()+uint64(len(leaves)), sha256.Sum256([]byte("another tree")), testLogKeyOf)
			if err != nil {
				t.Fatal(err)
			}
			body.Note = note
			return leaves
		}},
		{name: "a frontier chain value that is not the stream's", change: func(t *testing.T, world *testLogWorld, body *protocol.LogCheckpointBody, leaves [][sha256.Size]byte) [][sha256.Size]byte {
			body.Frontier[0].Chain = bytes.Repeat([]byte{0x5a}, sha256.Size)
			return leaves
		}},
		{name: "a note under another key", key: strangerKey, change: func(t *testing.T, world *testLogWorld, body *protocol.LogCheckpointBody, leaves [][sha256.Size]byte) [][sha256.Size]byte {
			return leaves
		}},
	}
	for _, c := range cases {
		world := newTestLogWorld(t)
		admin := world.admin()
		record := admin.openWith(testLogNoWitness{t: t})
		testLogOn(t, world, record)
		testLogEntry(t, record)
		testLogCheckpoint(t, world, record)
		testLogEntry(t, record)
		testLogEntry(t, record)
		logKey := testLogKey(t, world, admin)
		testLogKeyOf = logKey
		if c.key != nil {
			logKey = c.key
		}
		testLogForgeCheckpoint(t, world, record, logKey, func(body *protocol.LogCheckpointBody, leaves [][sha256.Size]byte) [][sha256.Size]byte {
			return c.change(t, world, body, leaves)
		})
		reader := world.reader()
		other := reader.openWith(testLogNoWitness{t: t})
		for _, at := range []struct {
			device *testRecordDevice
			record *sidecar.SidecarRecord
		}{{admin, record}, {reader, other}} {
			status := testLogStatus(t, world, at.record)
			if status.Batch != 1 || at.device.logCheckCount() == 0 || len(status.Findings) == 0 {
				t.Errorf("%s: batch %d, %d alarms, findings %v", c.name, status.Batch, at.device.logCheckCount(), status.Findings)
			}
			// the same finding alarms once however often the log is read
			alarms := at.device.logCheckCount()
			testLogStatus(t, world, at.record)
			if at.device.logCheckCount() != alarms {
				t.Errorf("%s: a finding alarmed again at the next sync", c.name)
			}
		}
	}
}

// The log key the forging cases sign a wrong note with: the case table cannot reach the world's device.
var testLogKeyOf ed25519.PrivateKey

// RECORD.md section 20: a second entry for one batch with the same note is a copy, kept once and raising nothing; one
// with another note is a fork, which alarms; one from a device that does not govern the batch is ignored with an
// alarm. None moves the tree.
func TestRecordLogSecondEntryForABatch(t *testing.T) {
	world := newTestLogWorld(t)
	admin := world.admin()
	stranger := world.admin()
	record := admin.openWith(testLogNoWitness{t: t})
	strangerRecord := stranger.openWith(testLogNoWitness{t: t})
	testLogOn(t, world, record)
	testLogEntry(t, record)
	testLogCheckpoint(t, world, record)
	held := testLogStatus(t, world, record)
	first := testLogCheckpoints(t, world, record)[0]

	refile := func(from *sidecar.SidecarRecord, body *protocol.LogCheckpointBody) {
		testRecordAppend(t, from, &sidecar.RecordDraft{Kind: sidecar.RecordKindCheckpoint, Source: sidecar.RecordSourceObserved, NoSession: true, Body: body})
		if err := from.Flush(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	refile(record, first)
	if status := testLogStatus(t, world, record); status.Batch != 1 || !bytes.Equal(status.Root, held.Root) || admin.logCheckCount() != 0 {
		t.Fatalf("a copy of batch 1: batch %d, findings %v", status.Batch, status.Findings)
	}
	refile(strangerRecord, first)
	if status := testLogStatus(t, world, record); status.Batch != 1 || admin.logCheckCount() != 1 {
		t.Fatalf("batch 1 from another signer: batch %d, %d alarms", status.Batch, admin.logCheckCount())
	}
	forked := proto.Clone(first).(*protocol.LogCheckpointBody)
	leaves := [][sha256.Size]byte{sha256.Sum256([]byte("another leaf"))}
	note, err := sidecar.SignRecordLogNote(sidecar.RecordLogOrigin(world.teamRecordId), 1, sidecar.RecordLogRoot(leaves), testLogKey(t, world, admin))
	if err != nil {
		t.Fatal(err)
	}
	forked.Note = note
	forked.Leaves = leaves[0][:]
	refile(record, forked)
	status := testLogStatus(t, world, record)
	if status.Batch != 1 || !bytes.Equal(status.Root, held.Root) || admin.logCheckCount() != 2 {
		t.Fatalf("a fork of batch 1: batch %d, %d alarms, findings %v", status.Batch, admin.logCheckCount(), status.Findings)
	}
	if !slices.ContainsFunc(status.Findings, func(finding string) bool { return strings.Contains(finding, "fork") }) {
		t.Fatalf("no finding names the fork: %v", status.Findings)
	}
}

// RECORD.md section 20: the leaf list survives its entries' expiry. A reader arriving after a BASE removed entry
// files rebuilds the tree from checkpoint entries alone and raises no alarm, and what it still holds still proves.
func TestRecordLogLeafListSurvivesItsEntriesExpiry(t *testing.T) {
	world := newTestLogWorld(t)
	admin := world.admin()
	record := admin.openWith(testLogNoWitness{t: t})
	testLogOn(t, world, record)
	expired := []*sidecar.RecordEntryRef{testLogEntry(t, record), testLogEntry(t, record)}
	kept := testLogEntry(t, record)
	testLogCheckpoint(t, world, record)
	held := testLogStatus(t, world, record)

	// the expired entries' files go, as a committed BASE takes them: their seqs are their stream counters here
	paths := []string{}
	for _, ref := range expired {
		path, err := sidecar.RecordStreamPath(ref.Seq)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	world.streams.RemoveStreamEntries(world.teamRecordId, admin.sidecarId, paths)

	reader := world.reader()
	other := reader.openWith(testLogNoWitness{t: t})
	status := testLogStatus(t, world, other)
	if status.Batch != held.Batch || status.Size != held.Size || !bytes.Equal(status.Root, held.Root) {
		t.Fatalf("a later reader rebuilt batch %d size %d, want %d and %d", status.Batch, status.Size, held.Batch, held.Size)
	}
	if reader.logCheckCount() != 0 || len(status.Findings) != 0 {
		t.Fatalf("expired entries alarmed a later reader: %v", status.Findings)
	}
	if status.UnbackedLeafCount != uint64(len(expired)) {
		t.Fatalf("%d leaves without an entry, want %d", status.UnbackedLeafCount, len(expired))
	}
	if _, err := other.Log().Proof(world.teamRecordId, kept.Leaf); err != nil {
		t.Fatalf("an entry still held no longer proves: %v", err)
	}
	// a leaf outlives its entry: the tree still places the expired ones
	for _, ref := range expired {
		if _, err := other.Log().Proof(world.teamRecordId, ref.Leaf); err != nil {
			t.Fatalf("an expired entry's leaf left the tree: %v", err)
		}
	}
}

// Only a confirmed log admin's device turns the log on or off, on the team record alone, within section 10.1's
// bounds; with the log off the checkpointer signs nothing.
func TestRecordLogOnTakesAConfirmedAdminOnTheTeamRecord(t *testing.T) {
	world := newTestLogWorld(t)
	admin := world.admin()
	writer := world.adminDevice()
	record := admin.openWith(testLogNoWitness{t: t})
	writerRecord := writer.openWith(testLogNoWitness{t: t})
	log := record.Log()
	on := func(change func(args *sidecar.RecordLogOnArgs)) error {
		args := &sidecar.RecordLogOnArgs{LogId: world.teamRecordId, Confirmed: true}
		change(args)
		return log.On(t.Context(), args)
	}
	if err := on(func(args *sidecar.RecordLogOnArgs) { args.Confirmed = false }); !errors.Is(err, sidecar.ErrRecordLogUnconfirmed) {
		t.Fatalf("an unconfirmed command: %v", err)
	}
	if err := on(func(args *sidecar.RecordLogOnArgs) { args.LogId = world.vaultId }); !errors.Is(err, sidecar.ErrRecordLogUnsupported) {
		t.Fatalf("a vault: %v", err)
	}
	if err := writerRecord.Log().On(t.Context(), &sidecar.RecordLogOnArgs{LogId: world.teamRecordId, Confirmed: true}); !errors.Is(err, sidecar.ErrRecordLogNotAdmin) {
		t.Fatalf("a writer that is no admin: %v", err)
	}
	for _, interval := range []time.Duration{4 * time.Minute, 25 * time.Hour, 301500 * time.Millisecond} {
		if err := on(func(args *sidecar.RecordLogOnArgs) { args.Interval = interval }); !errors.Is(err, sidecar.ErrRecordLogSettings) {
			t.Fatalf("an interval of %s: %v", interval, err)
		}
	}
	witness := newTestLogWitness(t, "auditor").args()
	witness.Url = "http://auditor.witness.example/log"
	if err := on(func(args *sidecar.RecordLogOnArgs) { args.Witnesses = []*sidecar.RecordLogWitnessArgs{witness} }); !errors.Is(err, sidecar.ErrRecordLogSettings) {
		t.Fatalf("a witness over plain http: %v", err)
	}
	if _, err := log.Checkpoint(t.Context(), world.teamRecordId, true); !errors.Is(err, sidecar.ErrRecordLogOff) {
		t.Fatalf("a checkpoint with the log off: %v", err)
	}
	if err := log.Off(t.Context(), world.teamRecordId, true); !errors.Is(err, sidecar.ErrRecordLogOff) {
		t.Fatalf("turning off a log that is off: %v", err)
	}
	if got := len(testLogCheckpoints(t, world, record)); got != 0 {
		t.Fatalf("%d checkpoint entries with the log never on", got)
	}

	if err := on(func(args *sidecar.RecordLogOnArgs) { args.Interval = 10 * time.Minute }); err != nil {
		t.Fatal(err)
	}
	status := testLogStatus(t, world, record)
	if !status.On || status.IntervalSeconds != 600 || !status.ThisDevice {
		t.Fatalf("status after on: %+v", status)
	}
	testLogCheckpoint(t, world, record)
	if err := log.Off(t.Context(), world.teamRecordId, false); !errors.Is(err, sidecar.ErrRecordLogUnconfirmed) {
		t.Fatalf("an unconfirmed off: %v", err)
	}
	if err := log.Off(t.Context(), world.teamRecordId, true); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Checkpoint(t.Context(), world.teamRecordId, true); !errors.Is(err, sidecar.ErrRecordLogOff) {
		t.Fatalf("a checkpoint after off: %v", err)
	}
	if status := testLogStatus(t, world, record); status.On || status.Batch != 1 || admin.logCheckCount() != 0 {
		t.Fatalf("status after off: %+v", status)
	}
	// a log_settings from a writer that is no admin is ignored, with an alarm, at every reader
	testRecordAppend(t, writerRecord, &sidecar.RecordDraft{
		Kind: sidecar.RecordKindLogSettings, Source: sidecar.RecordSourceApprover, NoSession: true,
		Body: &protocol.LogSettingsBody{
			Origin: sidecar.RecordLogOrigin(world.teamRecordId), CheckpointerSidecarId: writer.sidecarId.Bytes(),
			NotePublicKey: bytes.Repeat([]byte{7}, ed25519.PublicKeySize), IntervalSeconds: 600, FromBatch: 2,
		},
	})
	if err := writerRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if status := testLogStatus(t, world, record); status.On || admin.logCheckCount() != 1 {
		t.Fatalf("a log_settings from no admin: on %v, %d alarms", status.On, admin.logCheckCount())
	}
}

// The HTTPS witness client sends c2sp.org/tlog-witness's request to <prefix>/add-checkpoint and hands back the
// answer as it came; it dials nothing that is not https, and follows no redirect.
func TestRecordLogWitnessHttpClient(t *testing.T) {
	var got struct {
		sync.Mutex
		path string
		body []byte
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		got.Lock()
		defer got.Unlock()
		if request.URL.Path == "/moved/add-checkpoint" {
			http.Redirect(writer, request, "/log/add-checkpoint", http.StatusTemporaryRedirect)
			return
		}
		got.path = request.Method + " " + request.URL.Path
		got.body = make([]byte, request.ContentLength)
		request.Body.Read(got.body)
		writer.Header().Set("Content-Type", "text/x.tlog.size")
		writer.WriteHeader(http.StatusConflict)
		writer.Write([]byte("7\n"))
	}))
	defer server.Close()
	client := sidecar.NewRecordLogWitnessHttp(server.Client(), nil)
	request := []byte("old 3\n\nnote")
	answer, err := client.AddCheckpoint(t.Context(), server.URL+"/log", request)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Status != http.StatusConflict || string(answer.Body) != "7\n" || got.path != "POST /log/add-checkpoint" || !bytes.Equal(got.body, request) {
		t.Fatalf("answer %d %q for %s %q", answer.Status, answer.Body, got.path, got.body)
	}
	answer, err = client.AddCheckpoint(t.Context(), server.URL+"/moved", request)
	if err != nil || answer.Status != http.StatusTemporaryRedirect {
		t.Fatalf("a redirect was followed: %v %v", answer, err)
	}
	plain := strings.Replace(server.URL, "https://", "http://", 1)
	if _, err := client.AddCheckpoint(t.Context(), plain+"/log", request); !errors.Is(err, sidecar.ErrRecordLogSettings) {
		t.Fatalf("a plain http witness: %v", err)
	}
}
