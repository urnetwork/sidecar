//go:build !sidecar_http && !js

// §22.7's admission suite, §6's part (PROTO-M2-01): Hello's admission check between dispatchers whose
// peers the network's verified state names, on an authority held in memory as sidecartest.FakeAuthority
// holds one. An unadmitted, revoked or parked peer is refused, each beside a twin that passes; a key that
// is not the admission's is refused and alarmed; a late admission passes after one catch-up; an M1 pin
// that disagrees is resolved for the admission; a sidecar not itself admitted takes no peer; and a
// revocation closes a Hello that stood.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One network's verified state as the admission check reads it: admissions by sidecar_id and a pin,
// with a catch-up a test fills. The rest of SidecarAuthority answers nothing.
type testAdmissionAuthority struct {
	stateLock    sync.Mutex
	pin          *bridge.AuthPin
	sidecars     map[Id]*AclSidecar
	catchUp      func(ctx context.Context) error
	catchUpCount int
	// no side holds it installed: a sidecar whose follower has not started
	detached bool
}

func newTestAdmissionAuthority() *testAdmissionAuthority {
	return &testAdmissionAuthority{
		pin:      &bridge.AuthPin{Version: 1, Chain: make([]byte, 32)},
		sidecars: map[Id]*AclSidecar{},
	}
}

// Admits a sidecar whose identity key comes from seed, untagged under a member of its own unless
// edit says otherwise, at the next position.
func (self *testAdmissionAuthority) admit(sidecarId Id, identitySeed []byte, edit func(admission *AclSidecar)) {
	identityPublicKey := ed25519.NewKeyFromSeed(identitySeed).Public().(ed25519.PublicKey)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	memberId := NewId()
	admission := &AclSidecar{
		Row: &bridge.SidecarRow{
			SidecarId:         sidecarId.Bytes(),
			AdmittedAt:        self.pin.GetVersion() + 1,
			IdentityPublicKey: bytes.Clone(identityPublicKey),
			IdentityAlg:       "ed25519",
			MemberId:          memberId.Bytes(),
		},
		MemberId: memberId,
	}
	if edit != nil {
		edit(admission)
	}
	self.sidecars[sidecarId] = admission
	self.advanceWithLock()
}

// Changes a sidecar's row at the next position, as a later entry does: a revocation, a park.
func (self *testAdmissionAuthority) edit(sidecarId Id, edit func(row *bridge.SidecarRow)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	admission := cloneAclSidecar(self.sidecars[sidecarId])
	edit(admission.Row)
	self.sidecars[sidecarId] = admission
	self.advanceWithLock()
}

func (self *testAdmissionAuthority) advanceWithLock() {
	self.pin = &bridge.AuthPin{Version: self.pin.GetVersion() + 1, Chain: bytes.Repeat([]byte{byte(self.pin.GetVersion() + 1)}, 32)}
}

func (self *testAdmissionAuthority) detach() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.detached = true
}

func (self *testAdmissionAuthority) setCatchUp(catchUp func(ctx context.Context) error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.catchUp = catchUp
}

func (self *testAdmissionAuthority) catchUps() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.catchUpCount
}

func (self *testAdmissionAuthority) Pin() *bridge.AuthPin {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return &bridge.AuthPin{Version: self.pin.GetVersion(), Chain: bytes.Clone(self.pin.GetChain())}
}

func (self *testAdmissionAuthority) Admission(sidecarId Id) *AclSidecar {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return cloneAclSidecar(self.sidecars[sidecarId])
}

func (self *testAdmissionAuthority) MemberDevices(memberId Id) []*AclSidecar { return nil }

func (self *testAdmissionAuthority) Consented(sidecarId Id, memberId Id) bool { return false }

func (self *testAdmissionAuthority) CurrentBinding(memberId Id) *bridge.RecoveryBindingRow {
	return nil
}

func (self *testAdmissionAuthority) PresenceRequired(statement *SidecarStatement) bool { return false }

func (self *testAdmissionAuthority) LiveKeys(sidecarId Id) []*bridge.KeyRow { return nil }

func (self *testAdmissionAuthority) Cascade(targetId Id, sinceN uint64) ([]DeviceRevokeItem, error) {
	return nil, nil
}

func (self *testAdmissionAuthority) ProposedSince(lostAt time.Time) (uint64, time.Time, bool) {
	return 0, time.Time{}, false
}

func (self *testAdmissionAuthority) AddEntryCallback(callback SidecarAuthorityEntryFunction) func() {
	return func() {}
}

func (self *testAdmissionAuthority) CatchUp(ctx context.Context) error {
	var catchUp func(ctx context.Context) error
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.catchUpCount += 1
		catchUp = self.catchUp
	}()
	if catchUp == nil {
		return nil
	}
	return catchUp(ctx)
}

// One side's admissions: the shared state, read for its own sidecar_id as Sidecar.Admitted reads it,
// a parked admission still admitting.
type testSideAdmissions struct {
	authority *testAdmissionAuthority
	sidecarId Id
	clock     Clock
}

func (self *testSideAdmissions) Authority() SidecarAuthority {
	self.authority.stateLock.Lock()
	detached := self.authority.detached
	self.authority.stateLock.Unlock()
	if detached {
		return nil
	}
	return self.authority
}

func (self *testSideAdmissions) Admitted() bool {
	admission := self.authority.Admission(self.sidecarId)
	if admission == nil || admission.Row.GetRevokedAt() != 0 {
		return false
	}
	notAfter := admission.Row.GetNotAfter()
	return notAfter == 0 || self.clock.Now().UnixMilli() < notAfter
}

// The admissions a side added to this pair reads, nil while the pair runs M1's first-use pins.
func (self *testRpcPair) admissionsFor(sidecarId Id, clock Clock) SubprotocolAdmissions {
	if self.authority == nil {
		return nil
	}
	return &testSideAdmissions{authority: self.authority, sidecarId: sidecarId, clock: clock}
}

// Adds a side whose own verified state is view rather than the pair's, as a peer whose follower has seen
// another position of the log.
func (self *testRpcPair) addViewing(identity *testRpcIdentity, view *testAdmissionAuthority) *testRpcSide {
	shared := self.authority
	self.authority = view
	defer func() {
		self.authority = shared
	}()
	return self.add(identity, nil)
}

// A view that admits each identity under its own key.
func newTestAdmissionView(identities ...*testRpcIdentity) *testAdmissionAuthority {
	view := newTestAdmissionAuthority()
	for _, identity := range identities {
		view.admit(identity.sidecarId, identity.identitySeed, nil)
	}
	return view
}

// A pair on admissions, with two identities the state admits, not yet added as sides.
func newTestAdmissionPair(t *testing.T) (*testRpcPair, *testAdmissionAuthority, *testRpcIdentity, *testRpcIdentity) {
	pair := newTestRpcPair(t)
	pair.authority = newTestAdmissionAuthority()
	a := newTestRpcIdentity()
	b := newTestRpcIdentity()
	pair.authority.admit(a.sidecarId, a.identitySeed, nil)
	pair.authority.admit(b.sidecarId, b.identitySeed, nil)
	return pair, pair.authority, a, b
}

// Both sides admitted: Hello opens both gates, and each side's PeerIdentity carries the other's
// admission and the position it was read at.
func TestHelloAdmissionOpensBothGates(t *testing.T) {
	pair, authority, aIdentity, bIdentity := newTestAdmissionPair(t)
	a := pair.add(aIdentity, nil)
	b := pair.add(bIdentity, nil)
	if err := a.subprotocol.EnsureHello(t.Context(), Id(b.clientId)); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		from *testRpcSide
		to   *testRpcSide
	}{{from: a, to: b}, {from: b, to: a}} {
		peer, ok := c.from.subprotocol.PeerIdentity(Id(c.to.clientId))
		if !ok {
			t.Fatalf("no identity for the peer")
		}
		want := authority.Admission(c.to.sidecarId)
		if peer.Admission == nil || peer.Admission.MemberId != want.MemberId ||
			!bytes.Equal(peer.Admission.Row.GetSidecarId(), c.to.sidecarId.Bytes()) {
			t.Errorf("admission %+v", peer.Admission)
		}
		if peer.AdmissionVersion != authority.Pin().GetVersion() {
			t.Errorf("admission read at %d, the state at %d", peer.AdmissionVersion, authority.Pin().GetVersion())
		}
	}
	if authority.catchUps() != 0 {
		t.Errorf("%d catch-ups for peers the state named", authority.catchUps())
	}
}

// §22.7's refusals: a peer no admission names, a revoked one and a parked one are each refused
// UNAUTHENTICATED with no alarm and no gate open, beside the twin that passes. An unknown peer gets one
// catch-up first.
func TestHelloRefusesUnadmittedRevokedAndParkedPeers(t *testing.T) {
	cases := []struct {
		name string
		// changes the initiator's admission before its Hello
		change       func(authority *testAdmissionAuthority, sidecarId Id)
		code         protocol.ErrorCode
		catchUpCount int
	}{
		{name: "the twin that passes", code: protocol.ErrorCode_ERR_OK},
		{
			name: "unadmitted",
			change: func(authority *testAdmissionAuthority, sidecarId Id) {
				authority.stateLock.Lock()
				defer authority.stateLock.Unlock()
				delete(authority.sidecars, sidecarId)
			},
			code:         protocol.ErrorCode_ERR_UNAUTHENTICATED,
			catchUpCount: 1,
		},
		{
			name: "revoked",
			change: func(authority *testAdmissionAuthority, sidecarId Id) {
				authority.edit(sidecarId, func(row *bridge.SidecarRow) { row.RevokedAt = row.GetAdmittedAt() + 1 })
			},
			code: protocol.ErrorCode_ERR_UNAUTHENTICATED,
		},
		{
			name: "parked",
			change: func(authority *testAdmissionAuthority, sidecarId Id) {
				authority.edit(sidecarId, func(row *bridge.SidecarRow) { row.ParkedAt = row.GetAdmittedAt() + 1 })
			},
			code: protocol.ErrorCode_ERR_UNAUTHENTICATED,
		},
	}
	for _, c := range cases {
		pair, authority, aIdentity, bIdentity := newTestAdmissionPair(t)
		b := pair.add(bIdentity, nil)
		// the initiator is admitted in its own view, which the responder's need not share
		a := pair.addViewing(aIdentity, newTestAdmissionView(aIdentity, bIdentity))
		if c.change != nil {
			c.change(authority, a.sidecarId)
		}
		err := a.subprotocol.EnsureHello(t.Context(), Id(b.clientId))
		code, _ := SubprotocolErrorCode(err)
		if c.code == protocol.ErrorCode_ERR_OK {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
		} else if code != c.code {
			t.Errorf("%s: %v", c.name, err)
		}
		if opened := b.subprotocol.peerVerified(a.clientId); opened != (c.code == protocol.ErrorCode_ERR_OK) {
			t.Errorf("%s: responder's gate open %t", c.name, opened)
		}
		if authority.catchUps() != c.catchUpCount {
			t.Errorf("%s: %d catch-ups", c.name, authority.catchUps())
		}
		select {
		case event := <-b.events:
			t.Errorf("%s: an alarm %+v", c.name, event)
		default:
		}
	}
}

// A binding whose identity key is not the admission's is refused UNAUTHENTICATED and raises key_changed
// naming the sidecar_id; the twin under the admission's key passes.
func TestHelloRefusesAKeyNotTheAdmissions(t *testing.T) {
	pair, _, aIdentity, bIdentity := newTestAdmissionPair(t)
	b := pair.add(bIdentity, nil)
	impostor := newTestRpcIdentity()
	impostor.sidecarId = aIdentity.sidecarId
	// the impostor's own view admits it under its own key, so it sends its Hello
	c := pair.addViewing(impostor, newTestAdmissionView(impostor, bIdentity))
	err := c.subprotocol.EnsureHello(t.Context(), Id(b.clientId))
	if code, _ := SubprotocolErrorCode(err); code != protocol.ErrorCode_ERR_UNAUTHENTICATED {
		t.Fatalf("a key not the admission's: %v", err)
	}
	event := testAwait(t, b.events, "key_changed")
	if event.Kind != SidecarEventKeyChanged || event.SidecarId == nil || *event.SidecarId != aIdentity.sidecarId {
		t.Errorf("event %+v", event)
	}
	if b.subprotocol.peerVerified(c.clientId) {
		t.Errorf("the gate opened for a key not the admission's")
	}
	a := pair.add(aIdentity, nil)
	if err := a.subprotocol.EnsureHello(t.Context(), Id(b.clientId)); err != nil {
		t.Errorf("the admission's key: %v", err)
	}
}

// A peer whose admission landed after the responder last followed the log: one catch-up applies it, with
// no alarm, and the Hello passes. A second unknown peer, whose catch-up applies nothing, is refused.
func TestHelloLateAdmissionPassesAfterCatchUp(t *testing.T) {
	pair, authority, _, bIdentity := newTestAdmissionPair(t)
	b := pair.add(bIdentity, nil)
	late := newTestRpcIdentity()
	// the late peer's own view already admits it
	c := pair.addViewing(late, newTestAdmissionView(late, bIdentity))
	authority.setCatchUp(func(ctx context.Context) error {
		authority.admit(late.sidecarId, late.identitySeed, nil)
		return nil
	})
	if err := c.subprotocol.EnsureHello(t.Context(), Id(b.clientId)); err != nil {
		t.Fatalf("a late admission: %v", err)
	}
	if authority.catchUps() != 1 {
		t.Errorf("%d catch-ups", authority.catchUps())
	}
	select {
	case event := <-b.events:
		t.Errorf("an alarm %+v", event)
	default:
	}

	// a peer the catch-up does not bring is refused after it
	authority.setCatchUp(nil)
	stranger := newTestRpcIdentity()
	d := pair.addViewing(stranger, newTestAdmissionView(stranger, bIdentity))
	if code, _ := SubprotocolErrorCode(d.subprotocol.EnsureHello(t.Context(), Id(b.clientId))); code != protocol.ErrorCode_ERR_UNAUTHENTICATED {
		t.Errorf("a stranger after its catch-up: %v", code)
	}
	if authority.catchUps() != 2 {
		t.Errorf("%d catch-ups", authority.catchUps())
	}
}

// A peer a catch-up left unknown gets no second one while the state stands at that position: its next
// Hello is refused UNAUTHENTICATED at once. Once the state moves it gets one again, and the memory of
// unknown peers stays within HelloUnknownPeerCount, the oldest forgotten.
func TestHelloUnknownPeerCatchesUpOncePerPosition(t *testing.T) {
	pair, authority, _, bIdentity := newTestAdmissionPair(t)
	b := pair.add(bIdentity, nil)
	stranger := newTestRpcIdentity()
	c := pair.addViewing(stranger, newTestAdmissionView(stranger, bIdentity))
	for range 3 {
		if code, _ := SubprotocolErrorCode(c.subprotocol.EnsureHello(t.Context(), Id(b.clientId))); code != protocol.ErrorCode_ERR_UNAUTHENTICATED {
			t.Errorf("an unknown peer: %v", code)
		}
	}
	if authority.catchUps() != 1 {
		t.Errorf("%d catch-ups for one unknown peer at one position", authority.catchUps())
	}

	// the state moves: one more catch-up, and the admission it brings passes
	authority.admit(NewId(), newTestRpcIdentity().identitySeed, nil)
	authority.setCatchUp(func(ctx context.Context) error {
		authority.admit(stranger.sidecarId, stranger.identitySeed, nil)
		return nil
	})
	if err := c.subprotocol.EnsureHello(t.Context(), Id(b.clientId)); err != nil {
		t.Errorf("after the state moved: %v", err)
	}
	if authority.catchUps() != 2 {
		t.Errorf("%d catch-ups after the state moved", authority.catchUps())
	}

	// the memory is bounded
	pins := newAdmissionIdentityPins(t.Context(), nil, newTestMemoryStore(), &SidecarProtocolSettings{HelloUnknownPeerCount: 2}, newTestEnvelopeClock(), func(SidecarEvent) {})
	first, second, third := NewId(), NewId(), NewId()
	for _, sidecarId := range []Id{first, second, third} {
		pins.noteUnknown(sidecarId, 7)
	}
	if pins.unknownAt(first, 7) || !pins.unknownAt(second, 7) || !pins.unknownAt(third, 7) || len(pins.unknownSidecarIds) != 2 {
		t.Errorf("remembered %v", pins.unknownSidecarIds)
	}
	if pins.unknownAt(third, 8) {
		t.Errorf("an unknown mark held past its position")
	}
}

// A catch-up that fails reads nothing: the Hello is refused UNAVAILABLE, not as unknown.
func TestHelloCatchUpFailureRefusesUnavailable(t *testing.T) {
	pair, authority, _, bIdentity := newTestAdmissionPair(t)
	b := pair.add(bIdentity, nil)
	late := newTestRpcIdentity()
	c := pair.addViewing(late, newTestAdmissionView(late, bIdentity))
	authority.setCatchUp(func(ctx context.Context) error {
		return errors.New("synthetic api outage")
	})
	if code, _ := SubprotocolErrorCode(c.subprotocol.EnsureHello(t.Context(), Id(b.clientId))); code != protocol.ErrorCode_ERR_UNAVAILABLE {
		t.Errorf("a failed catch-up: %v", code)
	}
	if b.subprotocol.peerVerified(c.clientId) {
		t.Errorf("a failed catch-up opened the gate")
	}
}

// An M1 first-use pin that names another key than the admission: the admission wins, key_changed names
// the sidecar_id, the pin file is dropped, and its generation stays a floor.
func TestHelloResolvesAFirstUsePinForTheAdmission(t *testing.T) {
	pair, _, aIdentity, bIdentity := newTestAdmissionPair(t)
	// b's store holds M1's pins: a's under another key at generation 3, and one for a sidecar that
	// agrees with nothing the state names
	conflicting := &identityPin{generation: 3}
	copy(conflicting.identityPublicKey[:], ed25519.NewKeyFromSeed(newTestRpcIdentity().identitySeed).Public().(ed25519.PublicKey))
	unknownId := NewId()
	for sidecarId, pin := range map[Id]*identityPin{aIdentity.sidecarId: conflicting, unknownId: {generation: 1}} {
		writer, err := bIdentity.store.Create(identityPinName(sidecarId))
		if err != nil {
			t.Fatal(err)
		}
		writer.Write(pin.encode())
		if err := writer.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	b := pair.add(bIdentity, nil)

	// generation 1 from the admission's key: the pin's floor of 3 refuses it, after the pin's conflict
	// alarmed
	a := pair.add(aIdentity, nil)
	if code, _ := SubprotocolErrorCode(a.subprotocol.EnsureHello(t.Context(), Id(b.clientId))); code != protocol.ErrorCode_ERR_UNAUTHENTICATED {
		t.Errorf("below the carried floor: %v", code)
	}
	event := testAwait(t, b.events, "key_changed")
	if event.Kind != SidecarEventKeyChanged || event.SidecarId == nil || *event.SidecarId != aIdentity.sidecarId {
		t.Errorf("event %+v", event)
	}
	entries, err := b.store.List("pins/")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("first-use pins left: %+v", entries)
	}

	// the admission's key at generation 3 passes, the pin's key having lost
	aIdentity.generation = 3
	a3 := pair.add(aIdentity, nil)
	if err := a3.subprotocol.EnsureHello(t.Context(), Id(b.clientId)); err != nil {
		t.Errorf("the admission's key at the floor: %v", err)
	}
}

// A sidecar that is not itself admitted, or holds no verified state, sends no Hello, and answers one
// UNAVAILABLE without opening its gate.
func TestUnadmittedSidecarTakesNoPeer(t *testing.T) {
	pair, authority, aIdentity, bIdentity := newTestAdmissionPair(t)
	a := pair.add(aIdentity, nil)
	b := pair.add(bIdentity, nil)

	// a's own admission revoked: it sends nothing
	authority.edit(a.sidecarId, func(row *bridge.SidecarRow) { row.RevokedAt = row.GetAdmittedAt() + 1 })
	sentCount := len(a.sent())
	if code, _ := SubprotocolErrorCode(a.subprotocol.EnsureHello(t.Context(), Id(b.clientId))); code != protocol.ErrorCode_ERR_UNAVAILABLE {
		t.Errorf("an unadmitted initiator: %v", code)
	}
	if len(a.sent()) != sentCount {
		t.Errorf("an unadmitted sidecar sent a Hello")
	}
	// a responder holding no verified state answers UNAVAILABLE
	cIdentity := newTestRpcIdentity()
	statelessIdentity := newTestRpcIdentity()
	c := pair.addViewing(cIdentity, newTestAdmissionView(cIdentity, statelessIdentity))
	statelessView := newTestAdmissionView(cIdentity, statelessIdentity)
	statelessView.detach()
	stateless := pair.addViewing(statelessIdentity, statelessView)
	if code, _ := SubprotocolErrorCode(c.subprotocol.EnsureHello(t.Context(), Id(stateless.clientId))); code != protocol.ErrorCode_ERR_UNAVAILABLE {
		t.Errorf("a responder with no state: %v", code)
	}
	if stateless.subprotocol.peerVerified(c.clientId) {
		t.Errorf("a responder with no state opened its gate")
	}
}

// Agents and read_only devices are peers like any other; an agent past its not_after is not admitted.
func TestHelloAdmitsAgentsAndReadOnlyDevices(t *testing.T) {
	pair, authority, _, bIdentity := newTestAdmissionPair(t)
	b := pair.add(bIdentity, nil)
	agent := newTestRpcIdentity()
	readOnly := newTestRpcIdentity()
	notAfter := b.clock.Now().Add(time.Hour).UnixMilli()
	authority.admit(agent.sidecarId, agent.identitySeed, func(admission *AclSidecar) {
		tagId := NewId()
		admission.MemberId = Id{}
		admission.TagIds = []Id{tagId}
		admission.Row.MemberId = nil
		admission.Row.TagIds = [][]byte{tagId.Bytes()}
		admission.Row.NotAfter = notAfter
	})
	authority.admit(readOnly.sidecarId, readOnly.identitySeed, func(admission *AclSidecar) {
		admission.Row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	})
	agentSide := pair.add(agent, nil)
	readOnlySide := pair.add(readOnly, nil)
	for _, side := range []*testRpcSide{agentSide, readOnlySide} {
		if err := side.subprotocol.EnsureHello(t.Context(), Id(b.clientId)); err != nil {
			t.Errorf("%s: %v", side.sidecarId, err)
		}
	}
	peer, ok := b.subprotocol.PeerIdentity(Id(agentSide.clientId))
	if !ok || !slices.Equal(peer.Admission.TagIds, authority.Admission(agent.sidecarId).TagIds) {
		t.Errorf("the agent's admission %+v", peer)
	}

	// past its not_after on b's clock: a new client generation of the agent, whose own clock has not
	// reached it, is refused
	b.clock.Advance(time.Hour)
	agent.generation = 2
	agentLater := pair.add(agent, nil)
	if code, _ := SubprotocolErrorCode(agentLater.subprotocol.EnsureHello(t.Context(), Id(b.clientId))); code != protocol.ErrorCode_ERR_UNAUTHENTICATED {
		t.Errorf("an agent past its not_after: %v", code)
	}
}

// A revocation that lands while a peer's Hello stands closes the gate before HelloCacheTimeout: its next
// request is refused UNAUTHENTICATED, and a call to it runs a Hello the state refuses.
func TestRevocationClosesAStandingHello(t *testing.T) {
	pair, authority, aIdentity, bIdentity := newTestAdmissionPair(t)
	// a's own view, which never sees its revocation, so a keeps sending
	a := pair.addViewing(aIdentity, newTestAdmissionView(aIdentity, bIdentity))
	b := pair.add(bIdentity, nil)
	if _, err := b.subprotocol.Handle(testCallType, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		return []byte("answered"), nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	body, err := a.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, []byte("ask"), nil)
	if err != nil || string(body) != "answered" {
		t.Fatalf("before the revocation: %q %v", body, err)
	}

	// a still holds its Hello with b, so its request goes out; b's gate closes on it, and the fresh
	// Hello Call then runs is refused
	authority.edit(a.sidecarId, func(row *bridge.SidecarRow) { row.RevokedAt = row.GetAdmittedAt() + 1 })
	_, err = a.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, []byte("ask"), nil)
	if code, _ := SubprotocolErrorCode(err); code != protocol.ErrorCode_ERR_UNAUTHENTICATED {
		t.Errorf("after the revocation: %v", err)
	}
	if b.subprotocol.peerVerified(a.clientId) {
		t.Errorf("a revoked peer's Hello still stands")
	}
	if _, ok := b.subprotocol.PeerIdentity(Id(a.clientId)); ok {
		t.Errorf("a revoked peer's identity is still served")
	}
}

// An agent's admission ends at its not_after on the receiver's clock while the state stands still: a
// Hello that stood closes, its next request is refused UNAUTHENTICATED, and the Hello Call runs then is
// refused, well inside HelloCacheTimeout and with no entry landing.
func TestAgentPastItsNotAfterLosesAStandingHello(t *testing.T) {
	pair, authority, _, bIdentity := newTestAdmissionPair(t)
	b := pair.add(bIdentity, nil)
	agent := newTestRpcIdentity()
	untilNotAfter := b.settings.HelloCacheTimeout / 10
	notAfter := b.clock.Now().Add(untilNotAfter).UnixMilli()
	authority.admit(agent.sidecarId, agent.identitySeed, func(admission *AclSidecar) {
		tagId := NewId()
		admission.MemberId = Id{}
		admission.TagIds = []Id{tagId}
		admission.Row.MemberId = nil
		admission.Row.TagIds = [][]byte{tagId.Bytes()}
		admission.Row.NotAfter = notAfter
	})
	agentSide := pair.add(agent, nil)
	if _, err := b.subprotocol.Handle(testCallType, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		return []byte("answered"), nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	body, err := agentSide.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, []byte("ask"), nil)
	if err != nil || string(body) != "answered" {
		t.Fatalf("before its not_after: %q %v", body, err)
	}
	stateVersion := authority.Pin().GetVersion()

	// b's clock reaches the agent's not_after, its Hello's cache far from ending; the agent's own clock has
	// not, so it still sends
	b.clock.Advance(untilNotAfter)
	_, err = agentSide.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, []byte("ask"), nil)
	if code, _ := SubprotocolErrorCode(err); code != protocol.ErrorCode_ERR_UNAUTHENTICATED {
		t.Errorf("past its not_after: %v", err)
	}
	if b.subprotocol.peerVerified(agentSide.clientId) {
		t.Errorf("an expired agent's Hello still stands")
	}
	if authority.Pin().GetVersion() != stateVersion {
		t.Errorf("the state moved, so this shows nothing of not_after alone")
	}
}

// The generation floor holds under admissions and survives a restart on the same store.
func TestHelloAdmissionGenerationFloorSurvivesARestart(t *testing.T) {
	pair, _, aIdentity, bIdentity := newTestAdmissionPair(t)
	b := pair.add(bIdentity, nil)
	aIdentity.generation = 2
	a := pair.add(aIdentity, nil)
	if err := a.subprotocol.EnsureHello(t.Context(), Id(b.clientId)); err != nil {
		t.Fatal(err)
	}
	restarted := pair.add(&testRpcIdentity{sidecarId: b.sidecarId, identitySeed: b.identitySeed, clientKeySeed: b.clientKeySeed, generation: 1, store: b.store}, nil)
	older := &testRpcIdentity{sidecarId: aIdentity.sidecarId, identitySeed: aIdentity.identitySeed, clientKeySeed: aIdentity.clientKeySeed, generation: 1, store: newTestMemoryStore()}
	c := pair.add(older, nil)
	if code, _ := SubprotocolErrorCode(c.subprotocol.EnsureHello(t.Context(), Id(restarted.clientId))); code != protocol.ErrorCode_ERR_UNAUTHENTICATED {
		t.Errorf("a generation below the floor after a restart: %v", code)
	}
	if _, err := b.store.Open(admissionGenerationName(aIdentity.sidecarId)); err != nil {
		t.Errorf("no floor kept: %v", err)
	}
	if _, err := b.store.Open(identityPinName(aIdentity.sidecarId)); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("a first-use pin was written under admissions: %v", err)
	}
}
