// Hostile edits to real connections, through a fresh gate each time: E1 and E2 must refuse what is
// wrong without a panic, hold no more than their settings allow, and pass nothing once they refuse.

package smtpproof

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// Real connections captured once per process and shared read-only: FuzzEdgeHandshake and
// FuzzEdgeRecordOrder edit copies of them.
var testFixtures = struct {
	stateLock sync.Mutex
	byKey     map[string]*testGateFixture
}{byKey: map[string]*testGateFixture{}}

// A BDAT or DATA connection on one of the legs, with several DATA parts so later parts are reached.
func testCachedFixture(t *testing.T, legIndex int, data bool) *testGateFixture {
	t.Helper()
	leg := testTlsLegs()[legIndex%len(testTlsLegs())]
	key := fmt.Sprintf("%s %v", leg.name, data)
	testFixtures.stateLock.Lock()
	defer testFixtures.stateLock.Unlock()
	if fixture, ok := testFixtures.byKey[key]; ok {
		return fixture
	}
	settings := DefaultProverSettings()
	job := testJob("one line\r\nanother line\r\nand a third\r\n", "bob", "carol")
	if data {
		settings.ForceData = true
		settings.DataPartBytes = 12
	}
	fixture := testGateCapture(t, leg, testMxDefaults(), settings, job)
	testFixtures.byKey[key] = fixture
	return fixture
}

// One event of a replay: a record from either side, a disclosed SHTS, or a part.
type testReplayEvent struct {
	fromClient bool
	record     []byte
	shts       []byte
	part       int
}

// The fixture's trace with each part placed just before the first client record it opens, which is
// where an honest prover's proof lands at the latest.
func testReplayEvents(fixture *testGateFixture) []*testReplayEvent {
	// 1.3's first application_data record from the client is its Finished; 1.2's Finished is a
	// handshake record at sequence number 0
	seq := uint64(0)
	skip := 1
	if fixture.version() == tlsVersion12 {
		seq = 1
		skip = 0
	}
	var events []*testReplayEvent
	nextPart := 0
	for _, entry := range fixture.trace {
		if entry.fromClient && entry.record[0] == tlsRecordApplicationData {
			if 0 < skip {
				skip -= 1
			} else {
				for nextPart < len(fixture.parts) && fixture.parts[nextPart].FirstRecord <= seq {
					events = append(events, &testReplayEvent{part: nextPart + 1})
					nextPart += 1
				}
				seq += 1
			}
		}
		events = append(events, &testReplayEvent{fromClient: entry.fromClient, record: entry.record, shts: entry.shts})
	}
	for ; nextPart < len(fixture.parts); nextPart += 1 {
		events = append(events, &testReplayEvent{part: nextPart + 1})
	}
	return events
}

// Holds a gate to its settings: whatever arrives, what it keeps is bounded by them, give or take
// the one record that crossed a bound and ended it.
func testExpectGateBounds(t *testing.T, gate *edgeSession) {
	t.Helper()
	gate.stateLock.Lock()
	defer gate.stateLock.Unlock()
	settings := gate.settings
	slack := tlsRecordHeaderBytes + tlsMaxCiphertextBytes
	for name, held := range map[string][2]int{
		"transcript":      {len(gate.transcript), settings.maxHandshakeBytes + slack},
		"client buffer":   {len(gate.clientBuffer.pending), settings.maxHandshakeBytes + slack},
		"server buffer":   {len(gate.serverBuffer.pending), settings.maxHandshakeBytes + settings.maxServerBytes + slack},
		"held records":    {gate.heldBytes, settings.maxHeldBytes + slack},
		"server records":  {gate.serverRecordBytes, settings.maxServerBytes + slack},
		"client Finished": {len(gate.clientFinishedRecord), slack},
	} {
		if held[1] < held[0] {
			t.Fatalf("%s holds %d octets, bound %d", name, held[0], held[1])
		}
	}
}

// Applies a fuzzer's edits to a replay: each four octets name an edit, an event, a position and a
// value. Edits flip, drop, repeat, cut short or swap events, so every check of E1 and E2 is reached
// from a real connection's neighbourhood.
func testEditReplay(events []*testReplayEvent, edits []byte) []*testReplayEvent {
	edited := make([]*testReplayEvent, 0, len(events)+8)
	for _, event := range events {
		clone := *event
		clone.record = bytes.Clone(event.record)
		clone.shts = bytes.Clone(event.shts)
		edited = append(edited, &clone)
	}
	for count := 0; 4 <= len(edits) && count < 8; count += 1 {
		kind, index, position, value := edits[0], int(edits[1]), int(edits[2]), edits[3]
		edits = edits[4:]
		if len(edited) == 0 {
			break
		}
		target := index % len(edited)
		event := edited[target]
		octets := event.record
		if event.shts != nil {
			octets = event.shts
		}
		switch kind % 5 {
		case 0:
			if 0 < len(octets) {
				octets[position%len(octets)] ^= value | 1
			}
		case 1:
			edited = append(edited[:target], edited[target+1:]...)
		case 2:
			repeat := *event
			edited = append(edited[:target+1], append([]*testReplayEvent{&repeat}, edited[target+1:]...)...)
		case 3:
			// cut short, with the framing kept true so the cut reaches what reads inside the record
			if event.record != nil && tlsRecordHeaderBytes < len(event.record) {
				payload := event.record[tlsRecordHeaderBytes:]
				event.record = tlsFrameRecord(event.record[0], tlsVersion12, payload[:position%len(payload)])
			} else if 0 < len(event.shts) {
				// a repeated event shares its octets, so an earlier cut may already have emptied them
				event.shts = event.shts[:position%len(event.shts)]
			}
		case 4:
			if target+1 < len(edited) {
				edited[target], edited[target+1] = edited[target+1], edited[target]
			}
		}
	}
	return edited
}

// Replays events into a fresh gate, under a verifier that accepts every proof, and fails the test if
// anything passes after the gate's first refusal, the gate outgrows its bounds, or a refusal before
// application data is a cut: no client record has gone for a part to cover then, and every proof here
// verifies, so §14.7 names nothing there that cuts.
func testReplayHostile(t *testing.T, fixture *testGateFixture, events []*testReplayEvent) {
	t.Helper()
	gate := fixture.gate(&testFixedVerifier{})
	refused := false
	for _, event := range events {
		gate.stateLock.Lock()
		handshaking := gate.phase < edgePhaseApplication
		gate.stateLock.Unlock()
		var forwarded [][]byte
		var err error
		switch {
		case event.part != 0:
			forwarded, err = gate.VerifyPart(context.Background(), fixture.parts[event.part-1])
		case event.shts != nil:
			forwarded, err = gate.DiscloseShts(event.shts)
		case event.fromClient:
			forwarded, err = gate.ClientRecord(event.record)
		default:
			err = gate.ServerRecord(event.record)
		}
		if refused && len(forwarded) != 0 {
			t.Fatalf("%d records passed after a refusal", len(forwarded))
		}
		if handshaking && errors.Is(err, sidecar.ErrSmtpRecordCut) {
			t.Fatalf("a refusal during the handshake was a cut: %v", err)
		}
		refused = refused || err != nil
		testExpectGateBounds(t, gate)
	}
}

func FuzzEdgeHandshake(f *testing.F) {
	f.Add([]byte{0})
	f.Add([]byte{1, 0, 0, 0, 0})
	f.Add([]byte{2, 0, 1, 7, 9})
	// a dropped, repeated and swapped event early in each leg's handshake
	for leg := range 3 {
		for kind := range 5 {
			f.Add([]byte{byte(leg), byte(kind), 1, 40, 0x80})
			f.Add([]byte{byte(leg) | 4, byte(kind), 3, 9, 0x01})
		}
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) == 0 {
			return
		}
		fixture := testCachedFixture(t, int(input[0]&3), input[0]&4 != 0)
		testReplayHostile(t, fixture, testEditReplay(testReplayEvents(fixture), input[1:]))
	})
}

func TestTheHonestReplayPassesItsOwnGate(t *testing.T) {
	// the replay FuzzEdgeHandshake edits must itself be honest, or every edit would be refused for a
	// reason of the harness's own
	for legIndex := range testTlsLegs() {
		for _, data := range []bool{false, true} {
			fixture := testCachedFixture(t, legIndex, data)
			gate := fixture.gate(&testFixedVerifier{})
			forwardedCount := 0
			for i, event := range testReplayEvents(fixture) {
				var forwarded [][]byte
				var err error
				switch {
				case event.part != 0:
					forwarded, err = gate.VerifyPart(context.Background(), fixture.parts[event.part-1])
				case event.shts != nil:
					forwarded, err = gate.DiscloseShts(event.shts)
				case event.fromClient:
					forwarded, err = gate.ClientRecord(event.record)
				default:
					err = gate.ServerRecord(event.record)
				}
				if err != nil {
					t.Fatalf("%s data %v: event %d: %v", fixture.leg.name, data, i, err)
				}
				forwardedCount += len(forwarded)
			}
			clientRecords := 0
			for _, entry := range fixture.trace {
				if entry.fromClient {
					clientRecords += 1
				}
			}
			if forwardedCount != clientRecords {
				t.Errorf("%s data %v: %d of %d client records forwarded", fixture.leg.name, data, forwardedCount, clientRecords)
			}
		}
	}
}
