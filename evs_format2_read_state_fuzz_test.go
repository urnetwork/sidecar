//go:build !js && !ios_extension

// §22.6's read-state target for format 2 (EVS2-M10-32; R-EVS-12, FI-27): a path reply evs serves for a version a DROP
// lists, its state fields overwritten by any EvsReadPathReply, reads as the genuine answer or is refused. It reads the
// version's own content, never other bytes, or EVS_DROPPED only under the DROP's own id, statement and body, so a
// tampered state hides nothing it may not and shows nothing it should not. It needs go test's corpus directory and
// the drop read world, which the Worker and extension legs do not build.

package sidecar

import (
	"bytes"
	"embed"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The target's seeds: EvsReadPathReply bytes, each a patch of the state fields a server answers.
//
//go:embed testdata/fuzz/evs_format2/read_state
var evsReadStateFuzzSeeds embed.FS

// Every seed file of the target.
func evsReadStateSeeds(t testing.TB) [][]byte {
	t.Helper()
	const directory = "testdata/fuzz/evs_format2/read_state"
	entries, err := evsReadStateFuzzSeeds.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	seeds := [][]byte{}
	for _, entry := range entries {
		seed, err := evsReadStateFuzzSeeds.ReadFile(directory + "/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		seeds = append(seeds, seed)
	}
	if len(seeds) == 0 {
		t.Fatalf("no seeds in %s", directory)
	}
	return seeds
}

// The read-state target: see the file header.
func FuzzEvsReadState(f *testing.F) {
	for _, seed := range evsReadStateSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		checkEvsReadStateTampering(t, input)
	})
}

// One input over a world whose fifth version a DROP with now dropped: version 3 read through a reply carrying the
// input's state fields.
func checkEvsReadStateTampering(t *testing.T, input []byte) {
	patch := &protocol.EvsReadPathReply{}
	if proto.Unmarshal(input, patch) != nil {
		return
	}
	world := newEvsTestDropReadWorld(t, true)
	var served *protocol.EvsReadPathReply
	world.writer.world.stateLock.Lock()
	mutate := world.writer.world.mutatePath
	world.writer.world.mutatePath = func(reply *protocol.EvsReadPathReply) {
		mutate(reply)
		if reply.GetState() == protocol.EvsReadPathState_EVS_READ_PATH_STATE_UNSPECIFIED {
			return
		}
		evsReadStatePatch(reply, patch)
		served = proto.Clone(reply).(*protocol.EvsReadPathReply)
	}
	world.writer.world.stateLock.Unlock()
	content, err := world.readVersion(3)
	if proto.Size(patch) == 0 && !errors.Is(err, ErrEvsDropped) {
		// the untampered reply is the target's own check that the world serves what it means to
		t.Fatalf("the untampered drop reads %v", err)
	}
	switch {
	case err == nil:
		if !bytes.Equal(content, evsTestEdited("notes/plan.md", 3000, 2)) {
			t.Fatalf("a tampered read state read %d bytes of other content", len(content))
		}
	case errors.Is(err, ErrEvsDropped):
		if served == nil || !bytes.Equal(served.GetDropId(), world.dropId.Bytes()) || !bytes.Equal(served.GetDropStatement(), world.statement) ||
			(len(served.GetDropBody()) != 0 && !bytes.Equal(served.GetDropBody(), world.body)) {
			t.Fatal("a version read dropped under another drop's id, statement or body")
		}
	}
}

// The state fields patch sets, over reply's.
func evsReadStatePatch(reply *protocol.EvsReadPathReply, patch *protocol.EvsReadPathReply) {
	if patch.GetState() != protocol.EvsReadPathState_EVS_READ_PATH_STATE_UNSPECIFIED {
		reply.State = patch.GetState()
	}
	if patch.GetDropId() != nil {
		reply.DropId = patch.GetDropId()
	}
	if patch.GetNotBeforeMs() != 0 {
		reply.NotBeforeMs = patch.GetNotBeforeMs()
	}
	if patch.GetDropVersion() != 0 {
		reply.DropVersion = patch.GetDropVersion()
	}
	if patch.GetDropStatement() != nil {
		reply.DropStatement = patch.GetDropStatement()
	}
	if patch.GetDropBody() != nil {
		reply.DropBody = patch.GetDropBody()
	}
}
