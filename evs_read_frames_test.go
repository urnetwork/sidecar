// The read reply's frames as a reader takes them (QD-662; question evs1-m2-40-unfolded-listing-frame): a directory's
// delta frames folded back into its path in order, each refused unless it continues that path with one delta, each
// delta's proof folded with it (QD-681), and an error frame answered as evs's refusal.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A directory's deltas come one a frame after its path frame (QD-662): the reader folds each into the path's deltas in
// order and hands the path on in one frame, the frame after the last delta coming next; a delta frame first, of
// another path, carrying anything but its token path and one delta, or past ReadPathDeltaMaxCount is refused.
func TestEvsReadFramesFoldADirectorysDeltaFrames(t *testing.T) {
	directory := [][]byte{evsTestToken("d").Bytes()}
	encode := func(frames ...*protocol.EvsReadFrame) *bytes.Reader {
		encoded := []byte{}
		for _, frame := range frames {
			frameBytes, err := EncodeEvsReadFrame(frame)
			if err != nil {
				t.Fatal(err)
			}
			encoded = append(encoded, frameBytes...)
		}
		return bytes.NewReader(encoded)
	}
	delta := func(version uint64) *protocol.EvsIndexVersion {
		return &protocol.EvsIndexVersion{CommitVersion: version, EntryVersion: []byte(fmt.Sprintf("delta %d", version))}
	}
	deltaFrame := func(version uint64) *protocol.EvsReadFrame {
		return &protocol.EvsReadFrame{Path: &protocol.EvsReadPathReply{TokenPath: directory, Deltas: []*protocol.EvsIndexVersion{delta(version)}, Continues: true}}
	}
	pathFrame := func() *protocol.EvsReadFrame {
		return &protocol.EvsReadFrame{Path: &protocol.EvsReadPathReply{TokenPath: directory, Version: delta(3), NamesThrough: 0}}
	}
	other := &protocol.EvsReadFrame{Path: &protocol.EvsReadPathReply{TokenPath: [][]byte{evsTestToken("e").Bytes()}}}
	head := &protocol.EvsReadFrame{Head: &protocol.EvsHeadSummary{Version: 3}}
	end := &protocol.EvsReadFrame{End: true}

	frames := NewEvsReadFrames(encode(head, pathFrame(), deltaFrame(1), deltaFrame(2), deltaFrame(3), other, end))
	read := []*protocol.EvsReadFrame{}
	for {
		frame, err := frames.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		read = append(read, frame)
	}
	if len(read) != 4 || read[0].GetHead() == nil || !read[3].GetEnd() {
		t.Fatalf("%d frames", len(read))
	}
	folded := read[1].GetPath()
	if folded.GetContinues() || len(folded.GetDeltas()) != 3 || folded.GetVersion().GetCommitVersion() != 3 {
		t.Fatalf("the folded path %v", folded)
	}
	for i, delta := range folded.GetDeltas() {
		if delta.GetCommitVersion() != uint64(i+1) {
			t.Errorf("delta %d: %v", i, delta)
		}
	}
	if !bytes.Equal(read[2].GetPath().GetTokenPath()[0], other.GetPath().GetTokenPath()[0]) || len(read[2].GetPath().GetDeltas()) != 0 {
		t.Errorf("the next path %v", read[2].GetPath())
	}

	refused := map[string][]*protocol.EvsReadFrame{
		"a delta frame first":               {head, deltaFrame(1), end},
		"a delta of another path":           {head, pathFrame(), {Path: &protocol.EvsReadPathReply{TokenPath: other.GetPath().GetTokenPath(), Deltas: []*protocol.EvsIndexVersion{delta(1)}, Continues: true}}, end},
		"a delta frame with a version":      {head, pathFrame(), {Path: &protocol.EvsReadPathReply{TokenPath: directory, Deltas: []*protocol.EvsIndexVersion{delta(1)}, Version: delta(1), Continues: true}}, end},
		"a delta frame with names":          {head, pathFrame(), {Path: &protocol.EvsReadPathReply{TokenPath: directory, Deltas: []*protocol.EvsIndexVersion{delta(1)}, Names: &protocol.EvsNameTable{}, NamesThrough: 1, Continues: true}}, end},
		"two deltas in one delta frame":     {head, pathFrame(), {Path: &protocol.EvsReadPathReply{TokenPath: directory, Deltas: []*protocol.EvsIndexVersion{delta(1), delta(2)}, Continues: true}}, end},
		"a delta frame after the end":       {head, pathFrame(), end, deltaFrame(1)},
		"two proofs in one delta frame":     {head, pathFrame(), {Path: &protocol.EvsReadPathReply{TokenPath: directory, Deltas: []*protocol.EvsIndexVersion{delta(1)}, DeltaProofs: []*protocol.EvsDeltaProof{{}, {}}, Continues: true}}, end},
		"a path of more proofs than deltas": {head, {Path: &protocol.EvsReadPathReply{TokenPath: directory, Version: delta(3), DeltaProofs: []*protocol.EvsDeltaProof{{}}}}, deltaFrame(1), end},
	}
	tooMany := []*protocol.EvsReadFrame{head, pathFrame()}
	for version := range DefaultEvsFormatSettings().ReadPathDeltaMaxCount + 1 {
		tooMany = append(tooMany, deltaFrame(uint64(version+1)))
	}
	refused["deltas past ReadPathDeltaMaxCount"] = append(tooMany, end)
	for label, sent := range refused {
		frames := NewEvsReadFrames(encode(sent...))
		var err error
		for err == nil {
			_, err = frames.Next()
		}
		if label == "a delta frame after the end" {
			// nothing is read past the end frame
			if err != io.EOF {
				t.Errorf("%s: %v", label, err)
			}
			continue
		}
		if !errors.Is(err, ErrEvsReplyInvalid) {
			t.Errorf("%s: %v", label, err)
		}
	}
}

// A delta frame carries its delta's proof beside it (QD-681): the reader folds the proofs into the path's
// delta_proofs, one a delta in order, a frame with none standing as an empty proof, so each proof stays with its own
// delta.
func TestEvsReadFramesFoldEachDeltasProofWithIt(t *testing.T) {
	directory := [][]byte{evsTestToken("d").Bytes()}
	delta := func(version uint64) *protocol.EvsIndexVersion {
		return &protocol.EvsIndexVersion{CommitVersion: version, EntryVersion: []byte(fmt.Sprintf("delta %d", version))}
	}
	proof := func(version uint64) *protocol.EvsDeltaProof {
		return &protocol.EvsDeltaProof{Proof: []*protocol.EvsMerkleProof{{Leaf: []byte(fmt.Sprintf("leaf %d", version)), Index: version, Size: 9}}}
	}
	sent := []*protocol.EvsReadFrame{
		{Head: &protocol.EvsHeadSummary{Version: 4}},
		{Path: &protocol.EvsReadPathReply{TokenPath: directory, Version: delta(4)}},
		{Path: &protocol.EvsReadPathReply{TokenPath: directory, Deltas: []*protocol.EvsIndexVersion{delta(1)}, DeltaProofs: []*protocol.EvsDeltaProof{proof(1)}, Continues: true}},
		// an inline statement's delta, sent with an empty proof, and one sent with none
		{Path: &protocol.EvsReadPathReply{TokenPath: directory, Deltas: []*protocol.EvsIndexVersion{delta(2)}, DeltaProofs: []*protocol.EvsDeltaProof{{}}, Continues: true}},
		{Path: &protocol.EvsReadPathReply{TokenPath: directory, Deltas: []*protocol.EvsIndexVersion{delta(3)}, Continues: true}},
		{Path: &protocol.EvsReadPathReply{TokenPath: directory, Deltas: []*protocol.EvsIndexVersion{delta(4)}, DeltaProofs: []*protocol.EvsDeltaProof{proof(4)}, Continues: true}},
		{End: true},
	}
	encoded := []byte{}
	for _, frame := range sent {
		frameBytes, err := EncodeEvsReadFrame(frame)
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, frameBytes...)
	}
	frames := NewEvsReadFrames(bytes.NewReader(encoded))
	if _, err := frames.Next(); err != nil {
		t.Fatal(err)
	}
	frame, err := frames.Next()
	if err != nil {
		t.Fatal(err)
	}
	folded := frame.GetPath()
	if len(folded.GetDeltas()) != 4 || len(folded.GetDeltaProofs()) != 4 {
		t.Fatalf("%d deltas and %d proofs", len(folded.GetDeltas()), len(folded.GetDeltaProofs()))
	}
	for i, deltaProof := range folded.GetDeltaProofs() {
		version := uint64(i + 1)
		rooted := version == 1 || version == 4
		if folded.GetDeltas()[i].GetCommitVersion() != version {
			t.Errorf("delta %d: %v", i, folded.GetDeltas()[i])
		}
		if rooted != (len(deltaProof.GetProof()) == 1) || (rooted && deltaProof.GetProof()[0].GetIndex() != version) {
			t.Errorf("delta %d's proof: %v", version, deltaProof)
		}
	}
	if frame, err := frames.Next(); err != nil || !frame.GetEnd() {
		t.Fatalf("the end frame: %v", err)
	}
}

// A reply evs could not finish ends with an error frame (QD-662), which the reader answers as evs's refusal, a 503
// UNAVAILABLE that refuses nothing with its retry delay, after the path before it, and reads nothing past it.
func TestEvsReadFramesAnswerAnErrorFrameAsItsRefusal(t *testing.T) {
	directory := [][]byte{evsTestToken("d").Bytes()}
	encoded := []byte{}
	for _, frame := range []*protocol.EvsReadFrame{
		{Head: &protocol.EvsHeadSummary{Version: 3}},
		{Path: &protocol.EvsReadPathReply{TokenPath: directory}},
		{Error: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE, RetryAfterMs: 1500}},
		{End: true},
	} {
		frameBytes, err := EncodeEvsReadFrame(frame)
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, frameBytes...)
	}
	frames := NewEvsReadFrames(bytes.NewReader(encoded))
	if frame, err := frames.Next(); err != nil || frame.GetHead() == nil {
		t.Fatalf("the head: %v", err)
	}
	if frame, err := frames.Next(); err != nil || frame.GetPath() == nil {
		t.Fatalf("the path before the error: %v", err)
	}
	_, err := frames.Next()
	evsError, ok := EvsErrorOf(err)
	if !ok || evsError.Status != http.StatusServiceUnavailable || evsError.Code != protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE ||
		!evsError.RefusesNothing() || evsError.RetryAfter != 1500*time.Millisecond {
		t.Fatalf("the error frame: %v", err)
	}
	if _, err := frames.Next(); err != io.EOF {
		t.Fatalf("past the error frame: %v", err)
	}
	// a code that is no 503's reads as UNAVAILABLE: an error frame refuses nothing
	frameBytes, _ := EncodeEvsReadFrame(&protocol.EvsReadFrame{Error: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT}})
	_, err = NewEvsReadFrames(bytes.NewReader(frameBytes)).Next()
	if !IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE) {
		t.Fatalf("an error frame of another code: %v", err)
	}
}
