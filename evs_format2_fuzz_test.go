//go:build !js

// §22.6's format-2 evs targets, which need go test's corpus directory, so they stay off the Worker legs. Each target's
// seeds also run as a test on every leg (evs_format2_codec_test.go, evs_drop_payload_test.go), so the Worker leg
// checks what they check.

package sidecar

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The kind-5 segment target: a tampered kind-5 segment's one record opens to its body or fails before plaintext.
func FuzzEvsKind5Segment(f *testing.F) {
	for _, seed := range evsFuzzSeedFiles(f, "testdata/fuzz/evs_segment") {
		f.Add(seed)
	}
	fixture := newEvsFuzzKind5SegmentFixture(f)
	f.Fuzz(func(t *testing.T, input []byte) {
		checkEvsKind5SegmentTampering(t, fixture, input)
	})
}

// The format-2 batch target: a tampered batch fails or reads back the original's records and tails.
func FuzzEvsFormat2Batch(f *testing.F) {
	for _, seed := range evsFuzzSeedFiles(f, "testdata/fuzz/evs_batch") {
		f.Add(seed)
	}
	writer, _, _ := evsTestFormat2Batch(f)
	original, err := writer.Bytes()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		checkEvsFormat2BatchTampering(t, original, input)
	})
}

// The DROP target (§22.6's EvsDropHistory and its lists): a tampered body or lists that still check adopt exactly the
// original's.
func FuzzEvsDrop(f *testing.F) {
	for _, seed := range evsDropFuzzSeedFiles(f, "testdata/fuzz/evs_drop") {
		f.Add(seed)
	}
	push, body, lists := evsTestTwoPathDrop(f)
	f.Fuzz(func(t *testing.T, input []byte) {
		checkEvsDropTampering(t, push, body, lists, input)
	})
}

// The purge list target (§22.6's EvsPurgeList; EVS2-M10-32): decoding is total, and a list that decodes holds its
// shape and bound and re-encodes to bytes that decode to the same list.
func FuzzEvsPurgeList(f *testing.F) {
	for _, seed := range evsFormat2PurgeListSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		list, err := DecodeEvsPurgeList(input)
		if err != nil {
			return
		}
		ids := 0
		for _, candidate := range list.GetCandidates() {
			ids += len(candidate.GetSegmentIds()) + len(candidate.GetStagedSegmentIds()) + len(candidate.GetSlotIds())
		}
		if DefaultEvsFormatSettings().PurgeListMaxIdCount < ids {
			t.Fatalf("a purge list of %d ids decoded", ids)
		}
		encoded, err := EncodeEvsPurgeList(list)
		if err != nil {
			t.Fatalf("a decoded list does not encode: %v", err)
		}
		again, err := DecodeEvsPurgeList(encoded)
		if err != nil || !proto.Equal(list, again) {
			t.Fatalf("a list's own bytes decode to another: %v", err)
		}
	})
}

// A purge list of one candidate and a marked one, encoded, and cut and broken forms of them.
func evsFormat2PurgeListSeeds(t testing.TB) [][]byte {
	listed, err := EncodeEvsPurgeList(&protocol.EvsPurgeList{Candidates: []*protocol.EvsPurgeCandidate{{
		TokenPath: [][]byte{evsTestBytes("component", 16)}, ReplacedVersion: 3,
		SegmentIds: [][]byte{evsTestBytes("kind 5", 32)}, StagedSegmentIds: [][]byte{evsTestBytes("staged", 32)},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	marked, err := EncodeEvsPurgeList(&protocol.EvsPurgeList{Marked: true})
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{listed, marked, listed[:len(listed)/2], append(append([]byte{}, listed...), 0x10, 0x01), {0xff}, {}}
}

// The staged target (§22.6's staged segments; EVS2-M10-32): the framing decodes totally, no segment past its bound, and
// a segment whose header names another repo or push is refused before any byte is adopted.
func FuzzEvsStaged(f *testing.F) {
	segment := bytes.Repeat([]byte{7}, 64)
	f.Add(EvsEncodeStaged([][]byte{segment}))
	f.Add(EvsEncodeStaged([][]byte{segment, segment[:10]}))
	f.Add([]byte{0, 0, 0, 1, 0, 0})
	f.Add([]byte{})
	repoId, pushId := evsTestId("staged repo"), evsTestId("staged push")
	f.Fuzz(func(t *testing.T, input []byte) {
		segments, err := EvsDecodeStaged(input)
		if err != nil {
			return
		}
		for _, segment := range segments {
			if EvsStagedSegmentMaxByteCount < uint64(len(segment)) {
				t.Fatalf("a staged segment of %d bytes decoded", len(segment))
			}
			if staged, err := EvsStagedSegmentOf(segment, repoId, pushId); err == nil && staged == nil {
				t.Fatalf("a staged segment taken as nothing")
			}
		}
	})
}

// The drop status target (§22.6's EvsDropStatus; EVS2-M10-32): a drops listing decodes totally, and each state maps to
// one a device shows, or to none, which raises nothing.
func FuzzEvsDropStatus(f *testing.F) {
	listing, err := proto.Marshal(&protocol.EvsDropsReply{Drops: []*protocol.EvsDropStatus{
		{DropId: evsTestBytes("drop", 16), RefId: evsTestBytes("ref", 16), Version: 7, NotBeforeMs: 1767225600000, State: protocol.EvsDropState_EVS_DROP_PENDING},
		{DropId: evsTestBytes("held", 16), RefId: evsTestBytes("ref", 16), Version: 9, State: protocol.EvsDropState_EVS_DROP_OBSERVED},
	}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(listing)
	f.Add(listing[:len(listing)/2])
	f.Add([]byte{0x0a, 0x02, 0x30, 0x63})
	f.Fuzz(func(t *testing.T, input []byte) {
		reply := &protocol.EvsDropsReply{}
		if proto.Unmarshal(input, reply) != nil {
			return
		}
		for _, status := range reply.GetDrops() {
			state, ok := SidecarDropStateOf(status.GetState())
			if !ok {
				continue
			}
			dropId, err := IdFromBytes(status.GetDropId())
			refId, refErr := IdFromBytes(status.GetRefId())
			if err != nil || refErr != nil {
				continue
			}
			drop := &SidecarHistoryDrop{RepoId: evsTestId("repo"), RefId: refId, DropId: dropId, State: state, NotBefore: evsTime(status.GetNotBeforeMs())}
			if _, err := newSidecarHistoryDropEvent(drop); err != nil && state != SidecarDropPending {
				t.Fatalf("a listed state %q raises no event: %v", state, err)
			}
		}
	})
}
