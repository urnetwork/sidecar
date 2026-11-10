//go:build sidecar_testhooks && !sidecar_http

// What needs the hooks linked: the checkpointer killed at each of RECORD.md section 10.2's steps. The next life of
// the device finishes the batch, and whatever step the kill cut, the log holds one entry for that batch, a note
// journaled before the kill is the note filed after it, no witness is asked to cosign a second root at one size, and
// every note a witness holds is in the log. The log key reaches testHookSecret where it is drawn and no entry, slot
// row or witness request holds it.

package sidecar_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The note of the batch a device signed and has not finished, from its state file; nil for none.
func testLogJournaledNote(t *testing.T, world *testLogWorld, device *testRecordDevice) []byte {
	t.Helper()
	content, ok := device.files.Contents("record/log/" + hex.EncodeToString(world.teamRecordId[:]))
	if !ok {
		return nil
	}
	state := struct {
		Pending *struct {
			Batch uint64 `json:"batch"`
			Body  []byte `json:"body"`
		} `json:"pending"`
	}{}
	if err := json.Unmarshal(content, &state); err != nil {
		t.Fatal(err)
	}
	if state.Pending == nil {
		return nil
	}
	body := &protocol.LogCheckpointBody{}
	if err := proto.Unmarshal(state.Pending.Body, body); err != nil {
		t.Fatal(err)
	}
	return body.GetNote()
}

// RECORD.md section 20: a crash at each step signs no second root at one size, and every note a witness holds is
// found in the log after it.
func TestRecordLogCrashAtEachStepSignsNoSecondRoot(t *testing.T) {
	steps := []string{
		"record.log.sign.before", "record.log.sign.after",
		"record.log.journal.before", "record.log.journal.after",
		"record.log.entry.before", "record.log.entry.after",
		"record.log.witness.before", "record.log.witness.after",
		"record.log.file.before", "record.log.file.after",
	}
	for _, step := range steps {
		world := newTestLogWorld(t)
		admin := world.admin()
		witness := newTestLogWitness(t, "auditor")
		record := admin.openWith(witness)
		testLogOn(t, world, record, witness)
		testLogEntry(t, record)
		testLogCheckpoint(t, world, record)
		testLogEntry(t, record)

		var killed atomic.Bool
		func() {
			_, remove := installTestRecordHooks(t, func(name string, key string) {
				if name == step && killed.CompareAndSwap(false, true) {
					runtime.Goexit()
				}
			})
			defer remove()
			done := make(chan struct{})
			go func() {
				defer close(done)
				record.Log().Checkpoint(t.Context(), world.teamRecordId, true)
				t.Errorf("%s: the checkpoint returned past its kill", step)
			}()
			<-done
		}()
		if !killed.Load() {
			t.Fatalf("%s: never reached", step)
		}
		journaled := testLogJournaledNote(t, world, admin)

		// the next life: an entry lands first, so a batch signed afresh would not be the one journaled
		next := admin.openWith(witness)
		testLogEntry(t, next)
		result, err := next.Log().Checkpoint(t.Context(), world.teamRecordId, true)
		if err != nil {
			t.Fatalf("%s: the next life's checkpoint: %v", step, err)
		}
		if result == nil {
			// the kill came after the batch was filed whole: the entry that landed since waits for the next one
			if step != "record.log.file.after" {
				t.Fatalf("%s: the next life found nothing to finish", step)
			}
			result = testLogCheckpoint(t, world, next)
			if result.Batch != 3 {
				t.Fatalf("%s: the batch after a finished one is %d", step, result.Batch)
			}
		} else if journaled != nil && !bytes.Equal(result.Note, journaled) {
			t.Fatalf("%s: the note filed is not the note journaled before the kill", step)
		}

		checkpoints := testLogCheckpoints(t, world, next)
		batchNotes := map[uint64][][]byte{}
		logNotes := [][]byte{}
		for _, checkpoint := range checkpoints {
			batchNotes[checkpoint.GetBatch()] = append(batchNotes[checkpoint.GetBatch()], checkpoint.GetNote())
			logNotes = append(logNotes, checkpoint.GetNote())
		}
		for batch, notes := range batchNotes {
			if len(notes) != 1 {
				t.Errorf("%s: %d entries for batch %d", step, len(notes), batch)
			}
		}
		if journaled != nil && !slices.ContainsFunc(logNotes, func(note []byte) bool { return bytes.Equal(note, journaled) }) {
			t.Errorf("%s: the journaled note is not in the log", step)
		}
		for _, held := range witness.heldNotes() {
			if !slices.ContainsFunc(logNotes, func(note []byte) bool { return bytes.Equal(note, held) }) {
				t.Errorf("%s: a note the witness holds is not in the log", step)
			}
		}
		status := testLogStatus(t, world, next)
		if admin.logCheckCount() != 0 || len(status.Findings) != 0 {
			t.Errorf("%s: the log alarmed: %v", step, status.Findings)
		}
		if testLogJournaledNote(t, world, admin) != nil {
			t.Errorf("%s: a finished batch is still journaled", step)
		}
		// the log goes on: the next batch is filed, and a second reader agrees with all of it
		testLogEntry(t, next)
		last := testLogCheckpoint(t, world, next)
		reader := world.reader()
		other := reader.openWith(testLogNoWitness{t: t})
		if got := testLogStatus(t, world, other); got.Batch != last.Batch || got.Size != last.Size || reader.logCheckCount() != 0 {
			t.Errorf("%s: a second reader rebuilt batch %d size %d, want %d and %d: %v", step, got.Batch, got.Size, last.Batch, last.Size, got.Findings)
		}
	}
}

// The log key reaches the secret hook where it is drawn, once, and nothing that leaves the device holds it: no entry
// or slot row a push carries, and no witness request.
func TestRecordLogKeyReachesTheHookAndNoPush(t *testing.T) {
	world := newTestLogWorld(t)
	admin := world.admin()
	witness := newTestLogWitness(t, "auditor")
	hooks, remove := installTestRecordHooks(t, nil)
	defer remove()
	record := admin.openWith(witness)
	testLogOn(t, world, record, witness)
	testLogEntry(t, record)
	testLogCheckpoint(t, world, record)
	testLogOn(t, world, record, witness)
	testLogCheckpoint(t, world, record)

	seed := testLogKey(t, world, admin).Seed()
	if got := hooks.count("record_log_key", seed); got != 1 {
		t.Fatalf("the log key reached the hook %d times", got)
	}
	admin.tap.stateLock.Lock()
	defer admin.tap.stateLock.Unlock()
	for _, push := range admin.tap.pushes {
		for _, entry := range push.Entries {
			if bytes.Contains(entry.Entry, seed) {
				t.Fatalf("an entry holds the log key")
			}
		}
		for _, row := range push.SlotRows {
			if bytes.Contains(row.Row, seed) {
				t.Fatalf("a slot row holds the log key")
			}
		}
	}
	for _, note := range witness.heldNotes() {
		if bytes.Contains(note, seed) {
			t.Fatalf("a note holds the log key")
		}
	}
}
