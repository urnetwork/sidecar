// §22.6's config-delta state machine for the device role: a program of Pending, states, deltas, changed bytes,
// garbage and restarts against one true log. Whatever the program, memory stays bounded, nothing changed is ever
// accepted (a base, a statement's effect or a state in force always is the true log's), a restart restores what was
// in force with no alarm, and at the end the true state at the tip, on its base, converges the posture.

package device

import (
	"bytes"
	"io"
	"slices"
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

// §22.6's never-opens property for the forwarding role (DESIGN-DETAILS 4.3's OnlyJudgedOpens, SDK-M8-17's trap):
// over a generated log of every statement kind by every class of signer, a forged one included, delivered as deltas
// in any split and with bytes changed, with forks, restarts and true states between, only a state changes what is in
// force. Between states the state in force stays, no overlay entry leaves, each is the true statement's at its
// position and a denial, doc never becomes nodoc, and nothing is legacy; a state keeps every overlay and waiting
// entry above its pin.
func FuzzPostureNeverOpens(f *testing.F) {
	f.Add([]byte{20, 0, 1, 2, 0, 1, 1, 6, 2, 3, 0, 4, 7, 9, 1, 8, 0, 5, 0, 7, 1, 0, 12, 3, 1, 9, 0, 0, 8, 2, 0, 3})
	f.Add([]byte{12, 6, 0, 1, 6, 1, 3, 7, 2, 1, 2, 9, 0, 10, 1, 0, 8, 0, 4, 2, 0, 3, 3, 1, 2, 5, 0, 1, 1, 3})
	f.Add([]byte{23, 9, 9, 9, 2, 2, 2, 11, 3, 4, 5, 0, 0, 0, 1, 1, 1, 12, 0, 6, 1, 3, 0, 7, 2, 0, 3, 2, 1, 4, 0, 9})
	f.Add([]byte{8, 7, 0, 7, 2, 7, 3, 3, 0, 3, 1, 0, 1, 2, 3, 3, 4, 1, 0, 0, 5, 2})
	f.Fuzz(func(t *testing.T, program []byte) {
		read := func() byte {
			if len(program) == 0 {
				return 0
			}
			b := program[0]
			program = program[1:]
			return b
		}
		fixture := newPostureFixture(t)
		stranger := &postureFixtureSidecar{id: postureFixtureId(0x7a), key: postureFixtureKey(0x7a), member: fixture.owner}
		impostor := &postureFixtureSidecar{id: fixture.ownerPhone.id, key: postureFixtureKey(0x77), member: fixture.owner}
		signers := []*postureFixtureSidecar{fixture.ownerPhone, fixture.aliceLaptop, fixture.agent, fixture.aliceWorker, stranger, impostor}
		subjects := []*postureFixtureSidecar{fixture.ownerPhone, fixture.aliceLaptop, fixture.agent, fixture.aliceWorker}
		fixture.base(fixture.ownerPhone, true)
		_, forwarding := fixture.delegation(fixture.aliceLaptop, fixture.aliceLaptop)
		fixture.tick()
		// each base's position and whether its rows hold a document, and each position's statement kind, for what the
		// overlay may hold
		baseDocuments := map[uint64]bool{1: true}
		kinds := map[uint64]PostureOverlayKind{}
		count := 1 + int(read()%24)
		for range count {
			signer, subject := signers[int(read())%len(signers)], subjects[int(read())%len(subjects)]
			if signer == fixture.self && subject == fixture.self {
				// the sign-out wipes, which this property does not cover
				subject = fixture.agent
			}
			switch read() % 13 {
			case 0:
				kinds[fixture.sidecarRevoke(signer, subject, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)] = PostureOverlaySidecarRevoke
			case 1:
				kinds[fixture.statement(signer, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_MEMBER_REVOKE,
					&bridge.MemberRevoke{Header: fixture.header(), MemberId: fixture.alice.id})] = PostureOverlayMemberRevoke
			case 2:
				kinds[fixture.suspend(signer, subject.id, postureFixtureId(0x80+read()%4))] = PostureOverlaySuspend
			case 3:
				fixture.unsuspend(signer, subject.id, postureFixtureId(0x80+read()%4))
			case 4:
				kinds[fixture.statement(signer, bridge.SignedPurposeAcl, bridge.SignedType_SIGNED_GRANT_REVOKE,
					&bridge.GrantRevoke{Header: fixture.header(), GrantId: postureFixtureId(0x90 + read()%4)})] = PostureOverlayGrantRevoke
			case 5:
				kinds[fixture.statement(signer, bridge.SignedPurposeBridge, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW,
					&bridge.BridgeWithdraw{Header: fixture.header(), RuleId: postureFixtureId(0xa0 + read()%4)})] = PostureOverlayBridgeWithdraw
			case 6:
				delegationId := forwarding
				if read()%2 == 0 {
					delegationId = bytes.Repeat([]byte{0xb0 + read()%4}, 32)
				}
				kinds[fixture.delegationRevoke(signer, delegationId, uint64(read()%3))] = PostureOverlayDelegationRevoke
			case 7:
				var forwardSidecar *postureFixtureSidecar
				if read()%3 != 0 {
					forwardSidecar = subjects[int(read())%len(subjects)]
				}
				n, _ := fixture.delegation(signer, forwardSidecar)
				kinds[n] = PostureOverlayForwardSupersede
			case 8:
				fixture.tick()
			case 9:
				hasDocument := read()%2 == 0
				baseDocuments[fixture.base(fixture.ownerPhone, hasDocument)] = hasDocument
			case 10:
				fixture.opaqueStatement(signer, bridge.SignedPurposeAuthority, []bridge.SignedType{
					bridge.SignedType_SIGNED_ADMIN_SET, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
				}[read()%3])
			case 11:
				fixture.append(bridge.AuthEntryKindStatement, []byte{read(), read()})
			case 12:
				hasDocument := read()%2 == 0
				baseDocuments[fixture.baseWithHead(fixture.ownerPhone, hasDocument, postureFixtureId(0x41+read()%2))] = hasDocument
			}
		}
		tip := fixture.tip()
		baseOf := func(n uint64) (uint64, bool) {
			base := uint64(1)
			for position := range baseDocuments {
				if base < position && position <= n {
					base = position
				}
			}
			return base, baseDocuments[base]
		}
		clock := newPostureTestClock()
		settings := testPostureSettingsOn(clock)
		settings.OverlayMaxCount = 8
		settings.WaitingMaxCount = 4
		store := newMemoryPostureStore()
		posture, _ := NewPosture(store, settings)
		if _, err := posture.SetPending(fixture.pending()); err != nil {
			t.Fatal(err)
		}
		if _, err := posture.SetState(fixture.forwardingState(3, true, forwarding), fixture.log(1, 3)); err != nil {
			t.Fatal(err)
		}
		// what the posture holds beneath its decision, a fork's included
		type postureHeldView struct {
			state    PostureState
			statePin uint64
			rules    []byte
			overlay  []PostureOverlayEntry
			waiting  []PostureWaitingEntry
		}
		view := func() postureHeldView {
			held := posture.held
			heldView := postureHeldView{state: posture.Decision().State}
			if held != nil && held.stored == postureStoredEnforcing {
				heldView.statePin, heldView.rules = held.statePinN(), held.bridgeState.GetRules()
				heldView.overlay, heldView.waiting = held.overlay, held.waiting
			}
			return heldView
		}
		checkOverlay := func(step int, decision PostureDecision) {
			for _, entry := range decision.Overlay {
				if kind, ok := kinds[entry.N]; !ok || kind != entry.Kind {
					t.Fatalf("step %d: overlay entry %+v is no true denial", step, entry)
				}
			}
		}
		// between states: the same state in force, no overlay entry gone, no doc to nodoc, never legacy
		checkHeld := func(step int, before postureHeldView, after postureHeldView) {
			if after.state == PostureLegacy {
				t.Fatalf("step %d: legacy with no sign-out", step)
			}
			if before.statePin == 0 {
				return
			}
			if after.statePin != before.statePin || !bytes.Equal(after.rules, before.rules) {
				t.Fatalf("step %d: the state in force moved from %d to %d with no state", step, before.statePin, after.statePin)
			}
			for _, entry := range before.overlay {
				if !slices.ContainsFunc(after.overlay, func(other PostureOverlayEntry) bool { return postureOverlayEntryEqual(entry, other) }) {
					t.Fatalf("step %d: overlay entry %+v left with no state", step, entry)
				}
			}
			if before.state == PostureEnforcingDocument && after.state == PostureEnforcingNoDocument {
				t.Fatalf("step %d: doc to nodoc with no state", step)
			}
		}
		for step := 0; 0 < len(program) && step < 40; step += 1 {
			before := view()
			pinN := posture.Decision().Pin.GetVersion()
			if posture.held != nil && posture.held.stored == postureStoredEnforcing {
				pinN = posture.held.pinN
			}
			switch read() % 5 {
			case 0:
				from := pinN + 1
				if pinN == 0 || tip < from {
					break
				}
				log := fixture.log(from, min(tip, from+uint64(read()%5)))
				if read()%4 == 0 {
					index := int(read()) % len(log.Entries)
					entry := bytes.Clone(log.Entries[index])
					entry[int(read())%len(entry)] ^= 1 << (read() % 8)
					log.Entries[index] = entry
				}
				posture.ApplyDeltas(log)
				checkHeld(step, before, view())
			case 1:
				n := 1 + uint64(read())%tip
				base, hasDocument := baseOf(n)
				_, err := posture.SetState(fixture.forwardingState(n, hasDocument, forwarding), fixture.log(base, n))
				after := view()
				if err == nil && after.statePin == n && before.statePin != n {
					// a state keeps what lies above its pin
					for _, entry := range before.overlay {
						if n < entry.N && !slices.ContainsFunc(after.overlay, func(other PostureOverlayEntry) bool {
							return postureOverlayEntryEqual(entry, other)
						}) {
							t.Fatalf("step %d: a state at %d dropped the overlay entry at %d", step, n, entry.N)
						}
					}
					for _, entry := range before.waiting {
						if n < entry.ThroughN && !slices.ContainsFunc(after.waiting, func(other PostureWaitingEntry) bool {
							return other.N <= entry.ThroughN && entry.ThroughN <= other.ThroughN
						}) {
							t.Fatalf("step %d: a state at %d dropped the waiting entry through %d", step, n, entry.ThroughN)
						}
					}
				} else {
					checkHeld(step, before, after)
				}
			case 2:
				decision := posture.Decision()
				store = store.survivor()
				var restored PostureDecision
				posture, restored = NewPosture(store, settings)
				after := view()
				if postureDecisionSays(restored) != postureDecisionSays(decision) || len(restored.Waiting) != len(decision.Waiting) ||
					after.statePin != before.statePin || len(after.overlay) != len(before.overlay) {
					t.Fatalf("step %d: restored %v, was %v", step, postureDecisionSays(restored), postureDecisionSays(decision))
				}
			case 3:
				posture.SetFork(read()%2 == 0)
				checkHeld(step, before, view())
			case 4:
				posture.ApplyDeltas(&PostureLog{Entries: [][]byte{{read(), read(), read()}}})
				checkHeld(step, before, view())
			}
			checkOverlay(step, posture.Decision())
		}
	})
}
