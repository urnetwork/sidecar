// §9.4's K_sock file and ring on fixed vectors from a separate implementation, the overlap's two clocks
// (a compile's file alone, a listener's own clock), and the rotation rule's table on fake times.

package sidecar

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// testdata/socket/key_file.json.
type testSocketKeyFileVectors struct {
	NetworkId string `json:"network_id"`
	Files     []struct {
		Name        string `json:"name"`
		CurrentKey  string `json:"current_key"`
		PreviousKey string `json:"previous_key"`
		RotatedAtMs int64  `json:"rotated_at_ms"`
		Bytes       string `json:"bytes"`
	} `json:"files"`
	Names []struct {
		Name          string `json:"name"`
		CurrentToken  string `json:"current_token"`
		PreviousToken string `json:"previous_token"`
	} `json:"names"`
	Prefixes []struct {
		Prefix        string `json:"prefix"`
		CurrentToken  string `json:"current_token"`
		PreviousToken string `json:"previous_token"`
	} `json:"prefixes"`
	Invalid []struct {
		Why   string `json:"why"`
		Bytes string `json:"bytes"`
	} `json:"invalid"`
}

// The vectors, and each named file parsed.
func testSocketKeyFiles(t *testing.T) (*testSocketKeyFileVectors, Id, map[string]*protocol.SocketKeyFile) {
	t.Helper()
	vectors := &testSocketKeyFileVectors{}
	testSocketVectors(t, "key_file.json", vectors)
	var networkId Id
	copy(networkId[:], testSocketHex(t, vectors.NetworkId))
	files := map[string]*protocol.SocketKeyFile{}
	for _, vector := range vectors.Files {
		file, err := ParseSocketKeyFile(testSocketHex(t, vector.Bytes))
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		files[vector.Name] = file
	}
	return vectors, networkId, files
}

func TestSocketKeyFileVectors(t *testing.T) {
	vectors, _, files := testSocketKeyFiles(t)
	for _, vector := range vectors.Files {
		file := files[vector.Name]
		if !bytes.Equal(file.GetCurrentKey(), testSocketHex(t, vector.CurrentKey)) ||
			!bytes.Equal(file.GetPreviousKey(), testSocketHex(t, vector.PreviousKey)) || file.GetRotatedAtMs() != vector.RotatedAtMs {
			t.Errorf("%s parsed to other fields", vector.Name)
		}
		// a writer's bytes for the same file are the vector's, so two writers agree
		marshaled, err := MarshalSocketKeyFile(&protocol.SocketKeyFile{
			CurrentKey:  testSocketHex(t, vector.CurrentKey),
			PreviousKey: testSocketHex(t, vector.PreviousKey),
			RotatedAtMs: vector.RotatedAtMs,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(marshaled, testSocketHex(t, vector.Bytes)) {
			t.Errorf("%s marshaled to %x", vector.Name, marshaled)
		}
	}
}

func TestSocketKeyFileRefusesWhatNoRuleAllows(t *testing.T) {
	vectors, _, _ := testSocketKeyFiles(t)
	for _, vector := range vectors.Invalid {
		if _, err := ParseSocketKeyFile(testSocketHex(t, vector.Bytes)); !errors.Is(err, ErrSocketKeyFileInvalid) {
			t.Errorf("%s: %v", vector.Why, err)
		}
	}
	if _, err := NewSocketKeyRing(testSocketNetworkId, nil, DefaultSocketKeyRingSettings()); !errors.Is(err, ErrSocketKeyFileInvalid) {
		t.Errorf("a ring from no file: %v", err)
	}
	if _, err := MarshalSocketKeyFile(&protocol.SocketKeyFile{CurrentKey: []byte{1}}); !errors.Is(err, ErrSocketKeyFileInvalid) {
		t.Errorf("a short key marshaled: %v", err)
	}
}

// §8's CompileAcl input: a target under each key the file holds, newest first, from the file alone.
func TestSocketKeyRingCompileVectors(t *testing.T) {
	vectors, networkId, files := testSocketKeyFiles(t)
	settings := DefaultSocketKeyRingSettings()
	rotating, err := NewSocketKeyRing(networkId, files["rotating"], settings)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := NewSocketKeyRing(networkId, files["fresh"], settings)
	if err != nil {
		t.Fatal(err)
	}
	if len(rotating.CompileKeys()) != 2 || len(fresh.CompileKeys()) != 1 || fresh.Previous() != nil {
		t.Fatalf("keys: %d rotating, %d fresh", len(rotating.CompileKeys()), len(fresh.CompileKeys()))
	}
	for _, vector := range vectors.Names {
		want := [][]byte{testSocketHex(t, vector.CurrentToken), testSocketHex(t, vector.PreviousToken)}
		got, err := rotating.CompileTokenPaths(vector.Name)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || !bytes.Equal(got[0], want[0]) || !bytes.Equal(got[1], want[1]) {
			t.Errorf("%s: rotating paths %x", vector.Name, got)
		}
		got, err = fresh.CompileTokenPaths(vector.Name)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || !bytes.Equal(got[0], want[0]) {
			t.Errorf("%s: fresh paths %x", vector.Name, got)
		}
	}
	for _, vector := range vectors.Prefixes {
		got, err := rotating.CompileTokenPrefixes(vector.Prefix)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || !bytes.Equal(got[0], testSocketHex(t, vector.CurrentToken)) || !bytes.Equal(got[1], testSocketHex(t, vector.PreviousToken)) {
			t.Errorf("%s: prefixes %x", vector.Prefix, got)
		}
	}
	if _, err := rotating.CompileTokenPaths("tls/443/blog"); !errors.Is(err, errSocketNameNotBlinded) {
		t.Errorf("an edge name compiled to a token path: %v", err)
	}
}

// Listeners register both paths until rotated_at_ms + 10 min by their own clock, whether or not a writer
// has cleared the file (§9.4).
func TestSocketKeyRingRegistersBothPathsOnlyInsideTheOverlap(t *testing.T) {
	vectors, networkId, files := testSocketKeyFiles(t)
	settings := DefaultSocketKeyRingSettings()
	ring, err := NewSocketKeyRing(networkId, files["rotating"], settings)
	if err != nil {
		t.Fatal(err)
	}
	overlapEndMs := files["rotating"].GetRotatedAtMs() + settings.Overlap.Milliseconds()
	name := vectors.Names[1].Name
	inside, err := ring.RegisterTokenPaths(name, overlapEndMs-1)
	if err != nil {
		t.Fatal(err)
	}
	if len(inside) != 2 || !bytes.Equal(inside[1], testSocketHex(t, vectors.Names[1].PreviousToken)) {
		t.Fatalf("inside the overlap: %x", inside)
	}
	after, err := ring.RegisterTokenPaths(name, overlapEndMs)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 || !bytes.Equal(after[0], testSocketHex(t, vectors.Names[1].CurrentToken)) {
		t.Fatalf("at the overlap's end: %x", after)
	}
	// a compile does not follow that clock: the file still holds both
	if paths, _ := ring.CompileTokenPaths(name); len(paths) != 2 {
		t.Fatal("a compile read a clock")
	}
	// the registrar wakes at the overlap's end, and a file with no previous key has none
	if untilMs, ok := ring.RegisterBothUntilMs(); !ok || untilMs != overlapEndMs {
		t.Errorf("both until %d, %v", untilMs, ok)
	}
	settled, err := NewSocketKeyRing(networkId, &protocol.SocketKeyFile{CurrentKey: files["rotating"].GetCurrentKey()}, settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := settled.RegisterBothUntilMs(); ok {
		t.Errorf("a ring with no previous key registers both")
	}
}

// A lister opens a seal under the previous key only while the file holds it.
func TestSocketKeyRingOpensUnderThePreviousKeyWhileHeld(t *testing.T) {
	_, networkId, files := testSocketKeyFiles(t)
	settings := DefaultSocketKeyRingSettings()
	rotating, err := NewSocketKeyRing(networkId, files["rotating"], settings)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := NewSocketKeyRing(networkId, files["fresh"], settings)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := rotating.Previous().Seal("db/primary")
	if err != nil {
		t.Fatal(err)
	}
	previousPath, err := rotating.Previous().TokenPath("db/primary")
	if err != nil {
		t.Fatal(err)
	}
	if name, ok := rotating.OpenName(previousPath, sealed); !ok || name != "db/primary" {
		t.Fatal("the previous key's seal did not open while the file held it")
	}
	if _, ok := fresh.OpenName(previousPath, sealed); ok {
		t.Fatal("the previous key's seal opened once the file let it go")
	}
}

// A writer creates, rotates and clears: the rotation keeps the old key as previous, and the first head at
// or after rotated_at_ms + Overlap clears it, no earlier.
func TestSocketKeyFileRotatesAndSettles(t *testing.T) {
	settings := DefaultSocketKeyRingSettings()
	created := NewSocketKeyFile()
	if err := CheckSocketKeyFile(created); err != nil {
		t.Fatal(err)
	}
	if again := NewSocketKeyFile(); bytes.Equal(again.GetCurrentKey(), created.GetCurrentKey()) {
		t.Fatal("two files share a key")
	}
	rotatedAtMs := int64(1767323045000)
	rotated, err := RotateSocketKeyFile(created, rotatedAtMs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rotated.GetPreviousKey(), created.GetCurrentKey()) || bytes.Equal(rotated.GetCurrentKey(), created.GetCurrentKey()) ||
		rotated.GetRotatedAtMs() != rotatedAtMs {
		t.Fatalf("a rotation: %+v", rotated)
	}
	if _, err := RotateSocketKeyFile(created, 0); !errors.Is(err, ErrSocketKeyFileInvalid) {
		t.Fatalf("a rotation at no time: %v", err)
	}
	overlapEndMs := rotatedAtMs + settings.Overlap.Milliseconds()
	kept, changed, err := SettleSocketKeyFile(rotated, overlapEndMs-1, settings)
	if err != nil || changed || kept != rotated {
		t.Fatalf("a head inside the overlap changed the file: %v %v", changed, err)
	}
	settled, changed, err := SettleSocketKeyFile(rotated, overlapEndMs, settings)
	if err != nil || !changed || len(settled.GetPreviousKey()) != 0 || settled.GetRotatedAtMs() != 0 ||
		!bytes.Equal(settled.GetCurrentKey(), rotated.GetCurrentKey()) {
		t.Fatalf("the head at the overlap's end: %+v %v %v", settled, changed, err)
	}
	if _, changed, _ := SettleSocketKeyFile(settled, overlapEndMs+1, settings); changed {
		t.Fatal("a settled file settled again")
	}
}

// A writer's head rotates, and a reader that recompiles from the bytes it stored gets the writer's
// paths byte for byte, at any time on any clock (§8.8: readers recompile, so nothing here reads one).
func TestSocketKeyRingRecompileEqualsTheWriters(t *testing.T) {
	settings := DefaultSocketKeyRingSettings()
	rotated, err := RotateSocketKeyFile(NewSocketKeyFile(), 1767323045000)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := MarshalSocketKeyFile(rotated)
	if err != nil {
		t.Fatal(err)
	}
	writerRing, err := NewSocketKeyRing(testSocketNetworkId, rotated, settings)
	if err != nil {
		t.Fatal(err)
	}
	readFile, err := ParseSocketKeyFile(stored)
	if err != nil {
		t.Fatal(err)
	}
	readerRing, err := NewSocketKeyRing(testSocketNetworkId, readFile, settings)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"db", "db/primary", "acme/b/c/d/e/f/g/h", "share/" + testSocketShareToken} {
		writerPaths, err := writerRing.CompileTokenPaths(name)
		if err != nil {
			t.Fatal(err)
		}
		readerPaths, err := readerRing.CompileTokenPaths(name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(bytes.Join(writerPaths, nil), bytes.Join(readerPaths, nil)) {
			t.Errorf("%s recompiled to other paths", name)
		}
	}
	// stored twice, the file is the same bytes
	if again, _ := MarshalSocketKeyFile(readFile); !bytes.Equal(again, stored) {
		t.Fatal("a reader's file marshaled to other bytes")
	}
}

// §9.4's rotation table: removals and compromise at once, other shrinks and expiries a day after the
// first, a covered agent's reap never, and an event this code does not know at once.
func TestSocketKeyRotationDueTable(t *testing.T) {
	settings := DefaultSocketKeyRingSettings()
	hourMs := time.Hour.Milliseconds()
	dayMs := 24 * hourMs
	startMs := int64(1767323045000)
	for _, c := range []struct {
		name     string
		triggers []*SocketKeyTrigger
		dueAtMs  int64
	}{
		{name: "nothing pending"},
		{name: "a member's removal", triggers: []*SocketKeyTrigger{{Event: SocketKeyEventMemberRemoved, TimeMs: startMs}}, dueAtMs: startMs},
		{name: "a member device's removal", triggers: []*SocketKeyTrigger{{Event: SocketKeyEventMemberDeviceRemoved, TimeMs: startMs}}, dueAtMs: startMs},
		{name: "a compromise retirement", triggers: []*SocketKeyTrigger{{Event: SocketKeyEventCompromise, TimeMs: startMs}}, dueAtMs: startMs},
		{name: "another shrink", triggers: []*SocketKeyTrigger{{Event: SocketKeyEventHolderShrink, TimeMs: startMs}}, dueAtMs: startMs + dayMs},
		{name: "an authorization expiry", triggers: []*SocketKeyTrigger{{Event: SocketKeyEventAuthorizationExpiry, TimeMs: startMs}}, dueAtMs: startMs + dayMs},
		{name: "a covered agent's reap", triggers: []*SocketKeyTrigger{{Event: SocketKeyEventCoveredAgentReap, TimeMs: startMs}}},
		{name: "an unknown event", triggers: []*SocketKeyTrigger{{Event: SocketKeyEvent(99), TimeMs: startMs}}, dueAtMs: startMs},
		{
			name: "a batch is due a day after its first",
			triggers: []*SocketKeyTrigger{
				{Event: SocketKeyEventHolderShrink, TimeMs: startMs + 5*hourMs},
				{Event: SocketKeyEventAuthorizationExpiry, TimeMs: startMs},
				{Event: SocketKeyEventHolderShrink, TimeMs: startMs + 20*hourMs},
			},
			dueAtMs: startMs + dayMs,
		},
		{
			name: "a removal during a batch is due at once",
			triggers: []*SocketKeyTrigger{
				{Event: SocketKeyEventHolderShrink, TimeMs: startMs},
				{Event: SocketKeyEventMemberRemoved, TimeMs: startMs + hourMs},
			},
			dueAtMs: startMs + hourMs,
		},
		{
			name: "a covered reap adds nothing to a batch",
			triggers: []*SocketKeyTrigger{
				{Event: SocketKeyEventCoveredAgentReap, TimeMs: startMs},
				{Event: SocketKeyEventHolderShrink, TimeMs: startMs + hourMs},
			},
			dueAtMs: startMs + hourMs + dayMs,
		},
	} {
		verdict := SocketKeyRotationDue(c.triggers, startMs, settings)
		if verdict.DueAtMs != c.dueAtMs {
			t.Errorf("%s: due at %d, want %d", c.name, verdict.DueAtMs, c.dueAtMs)
		}
		if c.dueAtMs == 0 {
			if verdict.Due || verdict.Alarm || verdict.AlarmAtMs != 0 {
				t.Errorf("%s: %+v", c.name, verdict)
			}
			continue
		}
		if want := c.dueAtMs <= startMs; verdict.Due != want {
			t.Errorf("%s: due %v at the start", c.name, verdict.Due)
		}
		if later := SocketKeyRotationDue(c.triggers, c.dueAtMs, settings); !later.Due {
			t.Errorf("%s: not due at its time", c.name)
		}
		if c.dueAtMs > startMs {
			if early := SocketKeyRotationDue(c.triggers, c.dueAtMs-1, settings); early.Due {
				t.Errorf("%s: due a millisecond early", c.name)
			}
		}
	}
}

// Member devices alarm at exactly 24 h after a removal no writer has rotated for, and not a millisecond
// before.
func TestSocketKeyRotationAlarmsAtExactly24Hours(t *testing.T) {
	settings := DefaultSocketKeyRingSettings()
	removedAtMs := int64(1767323045000)
	triggers := []*SocketKeyTrigger{{Event: SocketKeyEventMemberDeviceRemoved, TimeMs: removedAtMs}}
	alarmAtMs := removedAtMs + (24 * time.Hour).Milliseconds()
	if verdict := SocketKeyRotationDue(triggers, alarmAtMs-1, settings); verdict.Alarm || verdict.AlarmAtMs != alarmAtMs || !verdict.Due {
		t.Fatalf("a millisecond before: %+v", verdict)
	}
	if verdict := SocketKeyRotationDue(triggers, alarmAtMs, settings); !verdict.Alarm {
		t.Fatalf("at 24 h: %+v", verdict)
	}
	// a rotation in the head covers the trigger, and the alarm goes with it
	pending := PendingSocketKeyTriggers(triggers, removedAtMs)
	if verdict := SocketKeyRotationDue(pending, alarmAtMs, settings); verdict.Due || verdict.Alarm {
		t.Fatalf("after a rotation covering it: %+v", verdict)
	}
}

// A rotation covers what came at or before its time, and what came after stays pending.
func TestPendingSocketKeyTriggersFollowTheRotation(t *testing.T) {
	triggers := []*SocketKeyTrigger{
		{Event: SocketKeyEventHolderShrink, TimeMs: 100},
		{Event: SocketKeyEventMemberRemoved, TimeMs: 200},
		{Event: SocketKeyEventCompromise, TimeMs: 300},
	}
	pending := PendingSocketKeyTriggers(triggers, 200)
	if len(pending) != 1 || pending[0].TimeMs != 300 {
		t.Fatalf("pending %v", pending)
	}
	if len(PendingSocketKeyTriggers(triggers, 0)) != 3 {
		t.Fatal("a file never rotated covered something")
	}
}
