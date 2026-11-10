// The posture's store: the file store tells absent from unreadable and writes whole, the manifest decodes strictly,
// and a kill at every step of every call leaves a store that restores the posture from before the call or after it,
// never a mix, never legacy in place of a state, and never an alarm.

package device

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Absent is the one answer for a record that is not there; a record that is there and cannot be read, or a store
// path that is not a directory, is a failure.
func TestFilePostureStoreTellsAbsentFromUnreadable(t *testing.T) {
	directory := t.TempDir()
	store, err := NewFilePostureStore(filepath.Join(directory, "posture-store"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open("posture"); !errors.Is(err, ErrPostureStoreAbsent) {
		t.Errorf("a store not yet made: %v", err)
	}
	if names, err := store.List(); err != nil || len(names) != 0 {
		t.Errorf("a store not yet made lists %v, %v", names, err)
	}
	if err := store.Write("posture", func(writer io.Writer) error {
		_, err := writer.Write([]byte("manifest"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	reader, err := store.Open("posture")
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || string(content) != "manifest" {
		t.Errorf("read %q, %v", content, err)
	}
	// a record that is a directory is there and cannot be read
	if err := os.Mkdir(filepath.Join(directory, "posture-store", "rows-1-1"), 0o700); err != nil {
		t.Fatal(err)
	}
	if reader, err := store.Open("rows-1-1"); err == nil {
		_, err = io.ReadAll(reader)
		reader.Close()
		if err == nil || errors.Is(err, ErrPostureStoreAbsent) {
			t.Errorf("a directory read as %v", err)
		}
	} else if errors.Is(err, ErrPostureStoreAbsent) {
		t.Errorf("a directory opened as absent")
	}
	if runtime.GOOS != "windows" && os.Getuid() != 0 {
		if err := os.Chmod(filepath.Join(directory, "posture-store", "posture"), 0o000); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Open("posture"); err == nil || errors.Is(err, ErrPostureStoreAbsent) {
			t.Errorf("an unreadable record opened as %v", err)
		}
	}
	// a store whose path is a file cannot write
	filePath := filepath.Join(directory, "a-file")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fileStore, err := NewFilePostureStore(filePath)
	if err == nil {
		err = fileStore.Write("posture", func(writer io.Writer) error { return nil })
	}
	if err == nil || errors.Is(err, ErrPostureStoreAbsent) {
		t.Errorf("a store over a file wrote: %v", err)
	}
}

// A write whose bytes fail leaves the old record whole, and leaves no temp file to be listed; a temp file a killed
// write left is swept at the next open and never listed meanwhile.
func TestFilePostureStoreWritesWhole(t *testing.T) {
	directory := t.TempDir()
	store, err := NewFilePostureStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	write := func(content string) error {
		return store.Write("state-1", func(writer io.Writer) error {
			_, err := writer.Write([]byte(content))
			return err
		})
	}
	if err := write("old"); err != nil {
		t.Fatal(err)
	}
	failed := errors.New("the write failed")
	err = store.Write("state-1", func(writer io.Writer) error {
		writer.Write([]byte("new, cut short"))
		return failed
	})
	if !errors.Is(err, failed) {
		t.Errorf("got %v", err)
	}
	reader, err := store.Open("state-1")
	if err != nil {
		t.Fatal(err)
	}
	content, _ := io.ReadAll(reader)
	reader.Close()
	if string(content) != "old" {
		t.Errorf("read %q", content)
	}
	if err := os.WriteFile(filepath.Join(directory, filePostureTempPrefix+"killed"), []byte("torn"), 0o600); err != nil {
		t.Fatal(err)
	}
	names, err := store.List()
	if err != nil || !slices.Equal(names, []string{"state-1"}) {
		t.Errorf("listed %v, %v", names, err)
	}
	if _, err := NewFilePostureStore(directory); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, filePostureTempPrefix+"killed")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the killed write's temp file is still there: %v", err)
	}
}

// Names outside the store are refused by every call.
func TestFilePostureStoreRefusesNamesOutsideIt(t *testing.T) {
	store, err := NewFilePostureStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "../posture", "Posture", "rows/1", ".write-x", "rows-1\x00"} {
		if _, err := store.Open(name); err == nil || errors.Is(err, ErrPostureStoreAbsent) {
			t.Errorf("open %q: %v", name, err)
		}
		if err := store.Write(name, func(writer io.Writer) error { return nil }); err == nil {
			t.Errorf("write %q took", name)
		}
		if err := store.Remove(name); err == nil {
			t.Errorf("remove %q took", name)
		}
	}
}

// The manifest round-trips and decodes strictly: another version, a field out of order, an unknown field or a
// record name outside the store fails.
func TestPostureManifestDecodesStrictly(t *testing.T) {
	manifest := &postureManifest{
		generation: 7, stored: postureStoredEnforcing, networkId: postureFixtureId(0x01), anchor: make([]byte, 32),
		pinN: 9, pinChain: make([]byte, 32), baseEntry: []byte{0x08, 0x01}, rowsRecord: "rows-7-5",
		rowsSha256: make([]byte, 32), entriesRecord: "entries-7", entriesSha256: make([]byte, 32), entriesCount: 4,
		stateRecord: "state-7", stateSha256: make([]byte, 32), documentSeenAt: 9,
		shareCerts: []postureShareCert{{shareId: postureFixtureId(0x05), generation: 2, cert: []byte{0x01}}},
		overlay: []PostureOverlayEntry{
			{Kind: PostureOverlaySuspend, N: 8, Id: postureFixtureId(0x06), SuspendId: postureFixtureId(0x07), Covered: true},
			{Kind: PostureOverlayBridgeWithdraw, N: 9, Id: postureFixtureId(0x08), WithdrawMode: bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN},
			{Kind: PostureOverlayDelegationRevoke, N: 9, Id: bytes.Repeat([]byte{0x09}, 32), Covered: true},
			{Kind: PostureOverlayForwardSupersede, N: 9, Id: postureFixtureId(0x0a), DelegationId: bytes.Repeat([]byte{0x0b}, 32)},
		},
		waiting: []PostureWaitingEntry{
			{N: 8, ThroughN: 8, FirstSeen: time.UnixMilli(1_800_000_000_000)},
			{N: 9, ThroughN: 12, FirstSeen: time.UnixMilli(1_800_000_060_000)},
		},
		fork: true,
	}
	encoded := manifest.encode()
	decoded, err := decodePostureManifest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded.encode()) != string(encoded) || !decoded.overlay[0].Covered || !decoded.fork ||
		!bytes.Equal(decoded.overlay[3].DelegationId, manifest.overlay[3].DelegationId) || len(decoded.waiting) != 2 ||
		decoded.waiting[1].ThroughN != 12 || !decoded.waiting[1].FirstSeen.Equal(manifest.waiting[1].FirstSeen) {
		t.Errorf("round trip lost something: %+v", decoded)
	}
	// the rest are written onto a manifest holding only its version and generation, so each fails on what it names
	minimal := (&postureManifest{generation: 1}).encode()
	onto := func(field ...byte) []byte {
		return append(append([]byte{}, minimal...), field...)
	}
	bad := map[string][]byte{
		"another version":      append([]byte{0x08, 0x02}, encoded[2:]...),
		"no version":           encoded[2:],
		"a field out of order": append(append([]byte{}, encoded...), 0x10, 0x01),
		"an unknown field":     append(append([]byte{}, encoded...), 0xb8, 0x01, 0x01),
		"a record outside":     (&postureManifest{rowsRecord: "../rows"}).encode(),
		"a truncated field":    encoded[:len(encoded)-1],
		// field 20: kind 0, n 1
		"an overlay of no kind": onto(0xa2, 0x01, 0x02, 0x10, 0x01),
		// field 20: a Suspend, n 1, id 0x01, and no suspend_id
		"a Suspend with no suspend_id": onto(0xa2, 0x01, 0x07, 0x08, 0x03, 0x10, 0x01, 0x1a, 0x01, 0x01),
		// field 20: kind 1, then id as a varint
		"an overlay id of another wire type": onto(0xa2, 0x01, 0x04, 0x08, 0x01, 0x18, 0x01),
		// field 20: a DelegationRevoke, n 1, an id of one byte
		"a DelegationRevoke of no delegation_id": onto(0xa2, 0x01, 0x07, 0x08, 0x06, 0x10, 0x01, 0x1a, 0x01, 0x01),
		// field 20: a ForwardSupersede, n 1, a sidecar id of 16 bytes and no newer delegation_id
		"a ForwardSupersede with no newer delegation": onto(append([]byte{0xa2, 0x01, 0x16, 0x08, 0x07, 0x10, 0x01, 0x1a, 0x10},
			postureFixtureId(0x0c)...)...),
		// field 20: a SidecarRevoke, n 1, id 0x01, with a delegation_id
		"a delegation_id on another kind": onto(0xa2, 0x01, 0x0a, 0x08, 0x01, 0x10, 0x01, 0x1a, 0x01, 0x01, 0x3a, 0x01, 0x01),
		// field 20: kind 8, past the last
		"an overlay of a kind past the last": onto(0xa2, 0x01, 0x07, 0x08, 0x08, 0x10, 0x01, 0x1a, 0x01, 0x01),
		// field 21: n 0
		"a waiting entry at 0": onto(0xaa, 0x01, 0x02, 0x08, 0x00),
		// field 21: n 5 through 4
		"a waiting entry through before it": onto(0xaa, 0x01, 0x04, 0x08, 0x05, 0x10, 0x04),
		// field 21: n as bytes
		"a waiting entry of another wire type": onto(0xaa, 0x01, 0x03, 0x0a, 0x01, 0x05),
		// field 22: 2
		"a fork of 2": onto(0xb0, 0x01, 0x02),
		// field 19: a share id and no certificate
		"a share with no cert": onto(0x9a, 0x01, 0x03, 0x0a, 0x01, 0x01),
		// field 19: the share id twice
		"a share field repeated": onto(0x9a, 0x01, 0x06, 0x0a, 0x01, 0x01, 0x0a, 0x01, 0x01),
	}
	if _, err := decodePostureManifest(minimal); err != nil {
		t.Fatalf("the minimal manifest: %v", err)
	}
	for name, encoded := range bad {
		if _, err := decodePostureManifest(encoded); !errors.Is(err, ErrPostureStoreFailed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The calls a kill test runs in order, over a log built once.
func postureKillScript(fixture *postureFixture) []func(posture *Posture) {
	fixture.base(fixture.ownerPhone, true)
	fixture.tick()
	fixture.tick()
	revoke := fixture.sidecarRevoke(fixture.ownerPhone, fixture.aliceLaptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
	base := fixture.base(fixture.ownerPhone, false)
	tick := fixture.tick()
	signOut := fixture.sidecarRevoke(fixture.self, fixture.self, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED)
	return []func(posture *Posture){
		func(posture *Posture) { posture.SetPending(fixture.pending()) },
		func(posture *Posture) { posture.SetState(fixture.state(3, true), fixture.log(1, 3)) },
		func(posture *Posture) { posture.ApplyDeltas(fixture.log(revoke, revoke)) },
		func(posture *Posture) { posture.ApplyDeltas(fixture.log(base, base)) },
		func(posture *Posture) { posture.SetState(fixture.state(tick, false), fixture.log(tick, tick)) },
		func(posture *Posture) { posture.ApplyDeltas(fixture.log(signOut, signOut)) },
	}
}

// What a restart must agree on: the state, the pin, the state in force and the overlay.
func postureDecisionSays(decision PostureDecision) [4]uint64 {
	return [4]uint64{uint64(decision.State), decision.Pin.GetVersion(), decision.BridgeState.GetAuth().GetVersion(), uint64(len(decision.Overlay))}
}

// A kill at each sync and rename of each write, and each remove, of every call: the store restores what was in
// force before the call or after it, with no alarm.
func TestKillAtEachStoreStepLeavesOldOrNew(t *testing.T) {
	fixture := newPostureFixture(t)
	script := postureKillScript(fixture)
	for index := range script {
		// the decisions before and after the call, with no kill
		store := newMemoryPostureStore()
		posture, _ := fixture.open(store)
		for _, call := range script[:index] {
			call(posture)
		}
		before := postureDecisionSays(posture.Decision())
		script[index](posture)
		after := postureDecisionSays(posture.Decision())
		if before == after {
			t.Errorf("call %d changes nothing, so it proves nothing", index)
		}
		killAt := 1
		for ; ; killAt += 1 {
			store := newMemoryPostureStore()
			posture, _ := fixture.open(store)
			for _, call := range script[:index] {
				call(posture)
			}
			store.killAtStep = store.steps + killAt
			script[index](posture)
			if !store.killed {
				break
			}
			_, restored := fixture.open(store.survivor())
			says := postureDecisionSays(restored)
			if says != before && says != after {
				t.Errorf("call %d killed at its step %d restored %v, neither %v nor %v", index, killAt, says, before, after)
			}
			if len(restored.Alarms) != 0 {
				t.Errorf("call %d killed at its step %d restored with alarms %v", index, killAt, restored.Alarms)
			}
		}
		// a manifest write alone is two steps, a sync and a rename
		if killAt < 3 {
			t.Errorf("call %d offered %d kill points", index, killAt-1)
		}
		t.Logf("call %d: %d kill points", index, killAt-1)
	}
}

// Where the posture's fixed vectors are, from this package (§22.5's byte-equal vectors). A format change regenerates
// them, and is read as one in review:
//
//	go test -run TestPostureVectorsAreByteEqual . -args -update-posture-vectors
const postureVectorsPath = "../testdata/device/posture_vectors.json"

var updatePostureVectors = flag.Bool("update-posture-vectors", false, "rewrite "+postureVectorsPath)

// The vectors: a fixed network's inputs, then each call of a script with the store's bytes after it.
type postureVectors struct {
	Pending string              `json:"pending"`
	Entries []string            `json:"entries"`
	Rows    map[string]string   `json:"rows"`
	States  map[string]string   `json:"states"`
	Steps   []postureVectorStep `json:"steps"`
}

// One call and what the store and the decision hold after it.
type postureVectorStep struct {
	Call     string            `json:"call"`
	State    string            `json:"state"`
	Pin      uint64            `json:"pin"`
	StatePin uint64            `json:"state_pin"`
	Overlay  int               `json:"overlay"`
	Manifest string            `json:"manifest"`
	Records  map[string]string `json:"records"`
}

// One step of the vectors' script: a call on the inputs, by name.
type postureVectorCall struct {
	name string
	run  func(posture *Posture, inputs *postureVectorInputs) (PostureDecision, error)
}

// The inputs as bytes.
type postureVectorInputs struct {
	pending *bridge.Pending
	entries [][]byte
	rows    map[[sha256.Size]byte][]byte
	states  map[uint64]*bridge.BridgeState
}

// Entries from to through, both included, with their rows.
func (self *postureVectorInputs) log(from uint64, through uint64) *PostureLog {
	return &PostureLog{
		Entries: slices.Clone(self.entries[from-1 : through]),
		OpenRows: func(rowsSha256 []byte) (io.ReadCloser, error) {
			rows, ok := self.rows[[sha256.Size]byte(rowsSha256)]
			if !ok {
				return nil, errors.New("no such rows")
			}
			return io.NopCloser(bytes.NewReader(rows)), nil
		},
	}
}

// The script the vectors run: Pending, a first state, a covered revocation, a base with no document, a state on it,
// and the sidecar's own sign-out.
var postureVectorScript = []postureVectorCall{
	{name: "SetPending", run: func(posture *Posture, inputs *postureVectorInputs) (PostureDecision, error) {
		return posture.SetPending(inputs.pending)
	}},
	{name: "SetState 3 on base 1", run: func(posture *Posture, inputs *postureVectorInputs) (PostureDecision, error) {
		return posture.SetState(inputs.states[3], inputs.log(1, 3))
	}},
	{name: "ApplyDeltas 4", run: func(posture *Posture, inputs *postureVectorInputs) (PostureDecision, error) {
		return posture.ApplyDeltas(inputs.log(4, 4))
	}},
	{name: "ApplyDeltas base 5", run: func(posture *Posture, inputs *postureVectorInputs) (PostureDecision, error) {
		return posture.ApplyDeltas(inputs.log(5, 5))
	}},
	{name: "SetState 6", run: func(posture *Posture, inputs *postureVectorInputs) (PostureDecision, error) {
		return posture.SetState(inputs.states[6], inputs.log(6, 6))
	}},
	{name: "ApplyDeltas sign-out 7", run: func(posture *Posture, inputs *postureVectorInputs) (PostureDecision, error) {
		return posture.ApplyDeltas(inputs.log(7, 7))
	}},
}

// The fixture's inputs for the script.
func postureVectorFixtureInputs(t *testing.T) *postureVectorInputs {
	fixture := newPostureFixture(t)
	fixture.base(fixture.ownerPhone, true)
	fixture.tick()
	fixture.tick()
	fixture.sidecarRevoke(fixture.ownerPhone, fixture.aliceLaptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
	fixture.base(fixture.ownerPhone, false)
	fixture.tick()
	fixture.sidecarRevoke(fixture.self, fixture.self, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED)
	return &postureVectorInputs{
		pending: fixture.pending(),
		entries: fixture.entries,
		rows:    fixture.rowsBySha256,
		states:  map[uint64]*bridge.BridgeState{3: fixture.state(3, true), 6: fixture.state(6, false)},
	}
}

// Runs the script on inputs and returns the vectors it gives.
func computePostureVectors(t *testing.T, inputs *postureVectorInputs) *postureVectors {
	deterministic := proto.MarshalOptions{Deterministic: true}
	pendingBytes, err := deterministic.Marshal(inputs.pending)
	if err != nil {
		t.Fatal(err)
	}
	vectors := &postureVectors{
		Pending: hex.EncodeToString(pendingBytes),
		Rows:    map[string]string{},
		States:  map[string]string{},
	}
	for _, entry := range inputs.entries {
		vectors.Entries = append(vectors.Entries, hex.EncodeToString(entry))
	}
	for rowsSha256, rows := range inputs.rows {
		vectors.Rows[hex.EncodeToString(rowsSha256[:])] = hex.EncodeToString(rows)
	}
	for n, state := range inputs.states {
		stateBytes, err := deterministic.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		vectors.States[strconv.FormatUint(n, 10)] = hex.EncodeToString(stateBytes)
	}
	store := newMemoryPostureStore()
	posture, _ := NewPosture(store, testPostureSettings())
	for _, call := range postureVectorScript {
		decision, err := call.run(posture, inputs)
		if err != nil {
			t.Fatalf("%s: %v", call.name, err)
		}
		step := postureVectorStep{
			Call: call.name, State: decision.State.String(), Pin: decision.Pin.GetVersion(),
			StatePin: decision.BridgeState.GetAuth().GetVersion(), Overlay: len(decision.Overlay),
			Manifest: hex.EncodeToString(store.record(postureManifestName)), Records: map[string]string{},
		}
		names, err := store.List()
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			recordSha256 := sha256.Sum256(store.record(name))
			step.Records[name] = hex.EncodeToString(recordSha256[:])
		}
		vectors.Steps = append(vectors.Steps, step)
	}
	return vectors
}

// The file as checked in, with what this leg computes from the same fixed inputs beside it.
func TestPostureVectorsAreByteEqual(t *testing.T) {
	encoded, err := json.MarshalIndent(computePostureVectors(t, postureVectorFixtureInputs(t)), "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if *updatePostureVectors {
		if err := os.WriteFile(postureVectorsPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	checkedIn, err := os.ReadFile(postureVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, checkedIn) {
		t.Errorf("a vector moved: this leg computes other bytes than %s holds", postureVectorsPath)
	}
}

// The file's inputs alone, decoded, give the file's steps, so it pins nothing a reader cannot replay.
func TestPostureVectorsReplay(t *testing.T) {
	checkedIn, err := os.ReadFile(postureVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	vectors := &postureVectors{}
	if err := json.Unmarshal(checkedIn, vectors); err != nil {
		t.Fatal(err)
	}
	decode := func(text string) []byte {
		decoded, err := hex.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	inputs := &postureVectorInputs{
		pending: &bridge.Pending{},
		rows:    map[[sha256.Size]byte][]byte{},
		states:  map[uint64]*bridge.BridgeState{},
	}
	if err := proto.Unmarshal(decode(vectors.Pending), inputs.pending); err != nil {
		t.Fatal(err)
	}
	for _, entry := range vectors.Entries {
		inputs.entries = append(inputs.entries, decode(entry))
	}
	for rowsSha256, rows := range vectors.Rows {
		inputs.rows[[sha256.Size]byte(decode(rowsSha256))] = decode(rows)
	}
	for n, stateHex := range vectors.States {
		position, err := strconv.ParseUint(n, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		state := &bridge.BridgeState{}
		if err := proto.Unmarshal(decode(stateHex), state); err != nil {
			t.Fatal(err)
		}
		inputs.states[position] = state
	}
	replayed := computePostureVectors(t, inputs)
	if !slices.EqualFunc(replayed.Steps, vectors.Steps, func(a postureVectorStep, b postureVectorStep) bool {
		return a.Call == b.Call && a.State == b.State && a.Pin == b.Pin && a.StatePin == b.StatePin &&
			a.Overlay == b.Overlay && a.Manifest == b.Manifest && maps.Equal(a.Records, b.Records)
	}) {
		t.Errorf("the file's inputs replay to other steps than it holds")
	}
	if len(vectors.Steps) != len(postureVectorScript) || vectors.Steps[len(vectors.Steps)-1].State != PostureLegacy.String() {
		t.Errorf("the file holds %d steps", len(vectors.Steps))
	}
}
