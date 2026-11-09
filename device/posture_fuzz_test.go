// §22.6's config-delta state machine for the device role: a program of Pending, states, deltas, changed bytes,
// garbage and restarts against one true log. Whatever the program, memory stays bounded, nothing changed is ever
// accepted (a base, a statement's effect or a state in force always is the true log's), a restart restores what was
// in force with no alarm, and at the end the true state at the tip, on its base, converges the posture.

package device

import (
	"bytes"
	"io"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The true log a program runs against: base 1 with a document, a revocation, two suspends, base 6 with none, an
// unsuspend and a grant's revocation.
func postureFuzzFixture(t *testing.T) (*postureFixture, map[uint64]PostureOverlayEntry) {
	fixture := newPostureFixture(t)
	fixture.base(fixture.ownerPhone, true)
	fixture.tick()
	revoke := fixture.sidecarRevoke(fixture.ownerPhone, fixture.aliceLaptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
	bySponsor := fixture.suspend(fixture.aliceLaptop, fixture.agent.id, postureFixtureId(0x81))
	byOwner := fixture.suspend(fixture.ownerPhone, fixture.agent.id, postureFixtureId(0x82))
	fixture.base(fixture.ownerPhone, false)
	fixture.tick()
	fixture.unsuspend(fixture.ownerPhone, fixture.agent.id, postureFixtureId(0x82))
	grant := fixture.statement(fixture.ownerPhone, bridge.SignedPurposeAcl, bridge.SignedType_SIGNED_GRANT_REVOKE,
		&bridge.GrantRevoke{Header: fixture.header(), GrantId: postureFixtureId(0x83)})
	fixture.tick()
	// what each true statement's overlay entry says, wherever a program lets it apply
	expected := map[uint64]PostureOverlayEntry{
		revoke:    {Kind: PostureOverlaySidecarRevoke, Id: fixture.aliceLaptop.id},
		bySponsor: {Kind: PostureOverlaySuspend, Id: fixture.agent.id, SuspendId: postureFixtureId(0x81)},
		byOwner:   {Kind: PostureOverlaySuspend, Id: fixture.agent.id, SuspendId: postureFixtureId(0x82)},
		grant:     {Kind: PostureOverlayGrantRevoke, Id: postureFixtureId(0x83)},
	}
	return fixture, expected
}

// The newest base at or before n, and whether its rows have a document.
func postureFuzzBaseOf(n uint64) (uint64, bool) {
	if n < 6 {
		return 1, true
	}
	return 6, false
}

func FuzzPostureApply(f *testing.F) {
	f.Add([]byte{0, 2, 8, 0, 1, 1, 1, 3, 1, 2, 1, 3})
	f.Add([]byte{0, 2, 2, 0, 1, 3, 0, 0, 7, 3, 1, 3, 1, 2, 9, 1})
	f.Add([]byte{0, 1, 0, 2, 4, 0, 4, 9, 9, 9, 1, 3, 3, 2, 9, 0})
	f.Add([]byte{0, 2, 5, 1, 1, 3, 1, 5, 3, 0, 1})
	f.Fuzz(func(t *testing.T, program []byte) {
		fixture, expected := postureFuzzFixture(t)
		tip := fixture.tip()
		settings := testPostureSettings()
		settings.EntriesMaxCount = 4
		settings.OverlayMaxCount = 2
		store := newMemoryPostureStore()
		posture, _ := NewPosture(store, settings)
		pendingSent := false
		read := func() byte {
			if len(program) == 0 {
				return 0
			}
			b := program[0]
			program = program[1:]
			return b
		}
		// a log of true entries from to through, with a byte of one entry changed when changeAt is not negative
		logOf := func(from uint64, through uint64, changeAt int, changeByte int, changeBit byte) *PostureLog {
			log := fixture.log(from, through)
			if 0 <= changeAt {
				index := changeAt % len(log.Entries)
				entry := bytes.Clone(log.Entries[index])
				entry[changeByte%len(entry)] ^= 1 << (changeBit % 8)
				log.Entries[index] = entry
			}
			return log
		}
		check := func(step int) {
			decision := posture.Decision()
			if pendingSent && decision.State == PostureLegacy {
				t.Fatalf("step %d: legacy with no sign-out in the log", step)
			}
			if !pendingSent && decision.State.Enforcing() {
				t.Fatalf("step %d: enforcing with no Pending", step)
			}
			if !decision.State.Enforcing() {
				return
			}
			held := posture.held
			baseN := held.base.entry.GetN()
			// everything of the base but time_ms, which api asserts and nothing signs (§7.9), is the true base's
			trueBase := &bridge.AuthEntry{}
			if err := proto.Unmarshal(fixture.entries[baseN-1], trueBase); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(held.base.entry.GetBody(), trueBase.GetBody()) || !bytes.Equal(held.base.entry.GetPrevChain(), trueBase.GetPrevChain()) ||
				!bytes.Equal(held.base.entry.GetNetworkId(), trueBase.GetNetworkId()) || held.base.entry.GetKind() != trueBase.GetKind() {
				t.Fatalf("step %d: a changed base at %d is in force", step, baseN)
			}
			statePin := decision.BridgeState.GetAuth()
			if want := fixture.chain(statePin.GetVersion()); !bytes.Equal(statePin.GetChain(), want[:]) {
				t.Fatalf("step %d: a state off the true chain is in force", step)
			}
			if _, hasDocument := postureFuzzBaseOf(baseN); decision.State == PostureEnforcingNoDocument && hasDocument {
				t.Fatalf("step %d: nodoc on a base with a document", step)
			}
			if settings.OverlayMaxCount < len(decision.Overlay) || uint64(settings.EntriesMaxCount) < held.entriesCount {
				t.Fatalf("step %d: past a bound: %d overlay entries, %d entries", step, len(decision.Overlay), held.entriesCount)
			}
			for _, entry := range decision.Overlay {
				want, ok := expected[entry.N]
				if !ok || entry.Kind != want.Kind || !bytes.Equal(entry.Id, want.Id) || !bytes.Equal(entry.SuspendId, want.SuspendId) {
					t.Fatalf("step %d: overlay entry %+v is no true statement's", step, entry)
				}
				if entry.N <= statePin.GetVersion() {
					t.Fatalf("step %d: overlay entry at %d at or before the state's pin %d", step, entry.N, statePin.GetVersion())
				}
			}
		}
		for step := 0; 0 < len(program) && step < 48; step += 1 {
			pinN := posture.Decision().Pin.GetVersion()
			switch read() % 6 {
			case 0:
				posture.SetPending(fixture.pending())
				pendingSent = true
			case 1:
				count := uint64(1 + read()%4)
				from := pinN + 1
				if tip < from {
					break
				}
				changeAt := -1
				if read()%3 == 0 {
					changeAt = int(read())
				}
				posture.ApplyDeltas(logOf(from, min(from+count-1, tip), changeAt, int(read()), read()))
			case 2:
				n := 1 + uint64(read())%tip
				baseN, hasDocument := postureFuzzBaseOf(n)
				var log *PostureLog
				switch read() % 3 {
				case 0:
					log = logOf(baseN, n, -1, 0, 0)
				case 1:
					if pinN < n {
						log = logOf(pinN+1, n, -1, 0, 0)
					}
				case 2:
					log = logOf(baseN, n, int(read()), int(read()), read())
				}
				posture.SetState(fixture.state(n, hasDocument), log)
			case 3:
				before := postureDecisionSays(posture.Decision())
				var restored PostureDecision
				posture, restored = NewPosture(store, settings)
				if says := postureDecisionSays(restored); says != before || len(restored.Alarms) != 0 {
					t.Fatalf("step %d: restored %v with alarms %v, was %v", step, says, restored.Alarms, before)
				}
			case 4:
				length := int(read() % 64)
				garbage := program[:min(len(program), length)]
				posture.ApplyDeltas(&PostureLog{Entries: [][]byte{bytes.Clone(garbage)}})
			case 5:
				// the next base, its rows changed in transit
				from := pinN + 1
				if from <= 6 && 6 <= tip && 0 < pinN {
					log := logOf(from, 6, -1, 0, 0)
					open := log.OpenRows
					flip := int(read())
					log.OpenRows = func(rowsSha256 []byte) (io.ReadCloser, error) {
						reader, err := open(rowsSha256)
						if err != nil {
							return nil, err
						}
						rows, _ := io.ReadAll(reader)
						rows[flip%len(rows)] ^= 0x01
						return io.NopCloser(bytes.NewReader(rows)), nil
					}
					posture.ApplyDeltas(log)
				}
			}
			check(step)
		}
		// the true state at the tip, on its base, converges whatever came before
		posture.SetPending(fixture.pending())
		baseN, hasDocument := postureFuzzBaseOf(tip)
		decision, err := posture.SetState(fixture.state(tip, hasDocument), logOf(baseN, tip, -1, 0, 0))
		if err != nil || decision.State != PostureEnforcingNoDocument || decision.Pin.GetVersion() != tip {
			t.Fatalf("the tip did not converge: %v, %v, %v, %v", err, decision.State, decision.Pin, decision.Alarms)
		}
		pendingSent = true
		check(-1)
	})
}
