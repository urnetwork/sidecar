// T2's socketsservice.SocketGate (DESIGN-DETAILS 13.2.3) until SOCK-M5-07's production gate, and a fixture
// beside it after. A test states each network's grants and identity keys, and Load publishes them as an
// immutable view at the next position, so a test chooses exactly when a process's state moves, and two
// engines on two fakes over one store are two processes at two positions.
//
// Evidence works as the production gate's: Observe, or NoteEvidence standing for the {acl_<N>}v key event,
// of a position above the view's starts a clock, and once BehindGrace has passed on the injected clock with no
// Load reaching that position, View answers ErrSocketGateBehind for that network alone. A Load at or above
// every evidence covers it.
//
// The grants are the fake's own, simpler than §8's evaluator, which is not what is under test here:
//
//   - listen and dial grants name a subject and a name key, exactly or by a byte prefix: listen by the
//     request's sidecar, else its subject client; dial by its subject client, and an urnetwork-edge caller's
//     dial by autogroup:public;
//   - a publish grant names a name key, whoever asks;
//   - a grant has an id and an expiry in milliseconds, 0 for none, and one past its expiry at the time asked
//     refuses.
//
// Safe for concurrent use.

package sidecartest

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/socketsservice"
)

var _ socketsservice.SocketGate = (*FakeSocketGate)(nil)

// One grant as the fake states it.
type FakeSocketGrant struct {
	GrantId []byte
	// In milliseconds. 0: none.
	ExpireMillis uint64
}

// Who a fake rule is for.
type fakeSocketGateSubject struct {
	// "listen", "dial" or "publish".
	right string
	// A sidecar or client id, "public" for autogroup:public, "" for a publish.
	subject string
}

// One rule: an exact name key, or every name key with a prefix.
type fakeSocketGateRule struct {
	nameKey []byte
	prefix  bool
	grant   *FakeSocketGrant
}

// A network's rules as a test states them, copied whole into each view.
type fakeSocketGateRules struct {
	subjectRules map[fakeSocketGateSubject][]*fakeSocketGateRule
	identityKeys map[connect.Id][]byte
}

func newFakeSocketGateRules() *fakeSocketGateRules {
	return &fakeSocketGateRules{
		subjectRules: map[fakeSocketGateSubject][]*fakeSocketGateRule{},
		identityKeys: map[connect.Id][]byte{},
	}
}

// A deep enough copy that later statements reach no published view.
func (self *fakeSocketGateRules) clone() *fakeSocketGateRules {
	cloned := newFakeSocketGateRules()
	for subject, rules := range self.subjectRules {
		cloned.subjectRules[subject] = slices.Clone(rules)
	}
	for sidecarId, publicKey := range self.identityKeys {
		cloned.identityKeys[sidecarId] = bytes.Clone(publicKey)
	}
	return cloned
}

// One network at the fake.
type fakeSocketGateNetwork struct {
	// What the next Load publishes.
	pending *fakeSocketGateRules
	// nil: never loaded, or unloaded.
	view *fakeSocketGateView
	// The highest position evidence named, and when the first evidence not covered came, zero for none.
	evidencePosition uint64
	evidenceTime     time.Time
	observed         []uint64
	viewCount        int
	spent            bool
}

// The gate. NewFakeSocketGate makes one.
type FakeSocketGate struct {
	clock Clock
	// How long uncovered evidence leaves a network fresh: GateBehindGrace, 5 s.
	BehindGrace time.Duration

	stateLock     sync.Mutex
	edgeNetworkId *connect.Id
	ready         *bool
	networks      map[connect.Id]*fakeSocketGateNetwork
}

// A gate on clock, nil being real time, where callers of edgeNetworkId, when set, dial as autogroup:public.
// Every network is unloaded until its first Load.
func NewFakeSocketGate(clock Clock, edgeNetworkId *connect.Id) *FakeSocketGate {
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	return &FakeSocketGate{
		clock:         clock,
		BehindGrace:   5 * time.Second,
		edgeNetworkId: copySocketId(edgeNetworkId),
		networks:      map[connect.Id]*fakeSocketGateNetwork{},
	}
}

// The network's state, made on first use.
func (self *FakeSocketGate) networkWithLock(networkId connect.Id) *fakeSocketGateNetwork {
	network := self.networks[networkId]
	if network == nil {
		network = &fakeSocketGateNetwork{pending: newFakeSocketGateRules()}
		self.networks[networkId] = network
	}
	return network
}

// Adds a rule for the next Load.
func (self *FakeSocketGate) addRule(networkId connect.Id, subject fakeSocketGateSubject, nameKey []byte, prefix bool, grant FakeSocketGrant) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	rules := self.networkWithLock(networkId).pending
	kept := []*fakeSocketGateRule{}
	for _, rule := range rules.subjectRules[subject] {
		if rule.prefix != prefix || !bytes.Equal(rule.nameKey, nameKey) {
			kept = append(kept, rule)
		}
	}
	grantCopy := FakeSocketGrant{GrantId: bytes.Clone(grant.GrantId), ExpireMillis: grant.ExpireMillis}
	rules.subjectRules[subject] = append(kept, &fakeSocketGateRule{nameKey: bytes.Clone(nameKey), prefix: prefix, grant: &grantCopy})
}

// Removes a subject's rules for nameKey, exact and prefix alike, for the next Load.
func (self *FakeSocketGate) removeRules(networkId connect.Id, subject fakeSocketGateSubject, nameKey []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	rules := self.networkWithLock(networkId).pending
	kept := []*fakeSocketGateRule{}
	for _, rule := range rules.subjectRules[subject] {
		if !bytes.Equal(rule.nameKey, nameKey) {
			kept = append(kept, rule)
		}
	}
	rules.subjectRules[subject] = kept
}

// listen on nameKey for sidecarId, from the next Load.
func (self *FakeSocketGate) AllowListen(networkId connect.Id, sidecarId connect.Id, nameKey []byte, grant FakeSocketGrant) {
	self.addRule(networkId, fakeSocketGateSubject{right: "listen", subject: sidecarId.String()}, nameKey, false, grant)
}

// listen on every name key starting with prefix for sidecarId, from the next Load.
func (self *FakeSocketGate) AllowListenPrefix(networkId connect.Id, sidecarId connect.Id, prefix []byte, grant FakeSocketGrant) {
	self.addRule(networkId, fakeSocketGateSubject{right: "listen", subject: sidecarId.String()}, prefix, true, grant)
}

// Takes sidecarId's listen on nameKey away from the next Load.
func (self *FakeSocketGate) RevokeListen(networkId connect.Id, sidecarId connect.Id, nameKey []byte) {
	self.removeRules(networkId, fakeSocketGateSubject{right: "listen", subject: sidecarId.String()}, nameKey)
}

// dial on nameKey for subjectClientId, from the next Load.
func (self *FakeSocketGate) AllowDial(networkId connect.Id, subjectClientId connect.Id, nameKey []byte, grant FakeSocketGrant) {
	self.addRule(networkId, fakeSocketGateSubject{right: "dial", subject: subjectClientId.String()}, nameKey, false, grant)
}

// Takes subjectClientId's dial on nameKey away from the next Load.
func (self *FakeSocketGate) RevokeDial(networkId connect.Id, subjectClientId connect.Id, nameKey []byte) {
	self.removeRules(networkId, fakeSocketGateSubject{right: "dial", subject: subjectClientId.String()}, nameKey)
}

// dial on nameKey for autogroup:public, which urnetwork-edge callers dial as, from the next Load.
func (self *FakeSocketGate) AllowPublicDial(networkId connect.Id, nameKey []byte, grant FakeSocketGrant) {
	self.addRule(networkId, fakeSocketGateSubject{right: "dial", subject: "public"}, nameKey, false, grant)
}

// publish on nameKey's host, whoever asks, from the next Load.
func (self *FakeSocketGate) AllowPublish(networkId connect.Id, nameKey []byte, grant FakeSocketGrant) {
	self.addRule(networkId, fakeSocketGateSubject{right: "publish"}, nameKey, false, grant)
}

// Takes the publish on nameKey away from the next Load.
func (self *FakeSocketGate) RevokePublish(networkId connect.Id, nameKey []byte) {
	self.removeRules(networkId, fakeSocketGateSubject{right: "publish"}, nameKey)
}

// sidecarId's identity key, from the next Load. nil removes its row.
func (self *FakeSocketGate) SetIdentityKey(networkId connect.Id, sidecarId connect.Id, publicKey []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	rules := self.networkWithLock(networkId).pending
	if publicKey == nil {
		delete(rules.identityKeys, sidecarId)
		return
	}
	rules.identityKeys[sidecarId] = bytes.Clone(publicKey)
}

// Publishes what the network's statements say as its view at the next position, which it returns, covering
// every evidence at or below it.
func (self *FakeSocketGate) Load(networkId connect.Id) uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	network := self.networkWithLock(networkId)
	position := uint64(1)
	if network.view != nil {
		position = network.view.position + 1
	}
	self.loadWithLock(network, position)
	return position
}

// Publishes the network's statements at position, which must be above the view's.
func (self *FakeSocketGate) LoadAt(networkId connect.Id, position uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	network := self.networkWithLock(networkId)
	if network.view != nil && position <= network.view.position {
		panic("a fake gate never installs a lower or equal position")
	}
	self.loadWithLock(network, position)
}

func (self *FakeSocketGate) loadWithLock(network *fakeSocketGateNetwork, position uint64) {
	network.view = &fakeSocketGateView{
		position:      position,
		rules:         network.pending.clone(),
		edgeNetworkId: copySocketId(self.edgeNetworkId),
	}
	if network.evidencePosition <= position {
		network.evidenceTime = time.Time{}
	}
}

// Forgets the network's view, as a process that never loaded it.
func (self *FakeSocketGate) Unload(networkId connect.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkWithLock(networkId).view = nil
}

// Evidence that the network's log reached position, as the {acl_<N>}v key event is.
func (self *FakeSocketGate) NoteEvidence(networkId connect.Id, position uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.noteEvidenceWithLock(self.networkWithLock(networkId), position)
}

func (self *FakeSocketGate) noteEvidenceWithLock(network *fakeSocketGateNetwork, position uint64) {
	if network.view != nil && position <= network.view.position {
		return
	}
	network.evidencePosition = max(network.evidencePosition, position)
	if network.evidenceTime.IsZero() {
		network.evidenceTime = self.clock.Now()
	}
}

// Marks the network spent in §20.7's over-limit snapshot, or not.
func (self *FakeSocketGate) SetSpent(networkId connect.Id, spent bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkWithLock(networkId).spent = spent
}

// Overrides readiness, which is otherwise true once any network has loaded.
func (self *FakeSocketGate) SetReady(ready bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.ready = &ready
}

// Every position Observe was handed for the network, in order.
func (self *FakeSocketGate) Observed(networkId connect.Id) []uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.networkWithLock(networkId).observed)
}

// How many times View was asked for the network.
func (self *FakeSocketGate) ViewCount(networkId connect.Id) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.networkWithLock(networkId).viewCount
}

// See socketsservice.SocketGate.
func (self *FakeSocketGate) Ready() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.ready != nil {
		return *self.ready
	}
	for _, network := range self.networks {
		if network.view != nil {
			return true
		}
	}
	return false
}

// See socketsservice.SocketGate.
func (self *FakeSocketGate) View(networkId connect.Id) (socketsservice.SocketGateView, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	network := self.networkWithLock(networkId)
	network.viewCount += 1
	if network.view == nil {
		return nil, socketsservice.ErrSocketGateUnloaded
	}
	if !network.evidenceTime.IsZero() && self.BehindGrace <= self.clock.Now().Sub(network.evidenceTime) {
		return nil, socketsservice.ErrSocketGateBehind
	}
	return network.view, nil
}

// See socketsservice.SocketGate.
func (self *FakeSocketGate) Observe(networkId connect.Id, position uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	network := self.networkWithLock(networkId)
	network.observed = append(network.observed, position)
	self.noteEvidenceWithLock(network, position)
}

// See socketsservice.SocketGate.
func (self *FakeSocketGate) Spent(networkId connect.Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.networkWithLock(networkId).spent
}

// See socketsservice.SocketGate: a View and one call on it.
func (self *FakeSocketGate) MayListen(ctx context.Context, request *socketsservice.SocketGateRequest) (*socketsservice.SocketGateVerdict, error) {
	view, err := self.View(request.NetworkId)
	if err != nil {
		return nil, err
	}
	return view.MayListen(request, self.clock.Now()), nil
}

// See socketsservice.SocketGate: a View and one call on it.
func (self *FakeSocketGate) MayDial(ctx context.Context, request *socketsservice.SocketGateRequest) (*socketsservice.SocketGateVerdict, error) {
	view, err := self.View(request.NetworkId)
	if err != nil {
		return nil, err
	}
	return view.MayDial(request, self.clock.Now()), nil
}

// See socketsservice.SocketGate: a View and one call on it.
func (self *FakeSocketGate) MayPublish(ctx context.Context, request *socketsservice.SocketGateRequest) (*socketsservice.SocketGateVerdict, error) {
	view, err := self.View(request.NetworkId)
	if err != nil {
		return nil, err
	}
	return view.MayPublish(request, self.clock.Now()), nil
}

// See socketsservice.SocketGate: a View and one call on it.
func (self *FakeSocketGate) IdentityKey(ctx context.Context, networkId connect.Id, sidecarId connect.Id) ([]byte, bool, error) {
	view, err := self.View(networkId)
	if err != nil {
		return nil, false, err
	}
	publicKey, found := view.IdentityKey(sidecarId)
	return publicKey, found, nil
}

// One published view, never changed.
type fakeSocketGateView struct {
	position      uint64
	rules         *fakeSocketGateRules
	edgeNetworkId *connect.Id
}

// See socketsservice.SocketGateView.
func (self *fakeSocketGateView) Position() uint64 {
	return self.position
}

// The verdict of subject's rules on the request's name at now.
func (self *fakeSocketGateView) verdict(subject fakeSocketGateSubject, request *socketsservice.SocketGateRequest, now time.Time) *socketsservice.SocketGateVerdict {
	nameKey := []byte(request.Name)
	if request.Name == "" {
		nameKey = request.NameToken
	}
	nowMillis := uint64(max(now.UnixMilli(), 0))
	for _, rule := range self.rules.subjectRules[subject] {
		matches := bytes.Equal(rule.nameKey, nameKey) || (rule.prefix && bytes.HasPrefix(nameKey, rule.nameKey))
		if !matches || (rule.grant.ExpireMillis != 0 && rule.grant.ExpireMillis <= nowMillis) {
			continue
		}
		return &socketsservice.SocketGateVerdict{
			Allowed:           true,
			GrantId:           bytes.Clone(rule.grant.GrantId),
			PolicyVersion:     self.position,
			GrantExpireMillis: rule.grant.ExpireMillis,
		}
	}
	return &socketsservice.SocketGateVerdict{}
}

// See socketsservice.SocketGateView.
func (self *fakeSocketGateView) MayListen(request *socketsservice.SocketGateRequest, now time.Time) *socketsservice.SocketGateVerdict {
	subject := request.SubjectClientId.String()
	if request.SidecarId != nil {
		subject = request.SidecarId.String()
	}
	return self.verdict(fakeSocketGateSubject{right: "listen", subject: subject}, request, now)
}

// See socketsservice.SocketGateView.
func (self *fakeSocketGateView) MayDial(request *socketsservice.SocketGateRequest, now time.Time) *socketsservice.SocketGateVerdict {
	subject := request.SubjectClientId.String()
	if self.edgeNetworkId != nil && request.CallerNetworkId == *self.edgeNetworkId {
		subject = "public"
	}
	return self.verdict(fakeSocketGateSubject{right: "dial", subject: subject}, request, now)
}

// See socketsservice.SocketGateView.
func (self *fakeSocketGateView) MayPublish(request *socketsservice.SocketGateRequest, now time.Time) *socketsservice.SocketGateVerdict {
	return self.verdict(fakeSocketGateSubject{right: "publish"}, request, now)
}

// See socketsservice.SocketGateView.
func (self *fakeSocketGateView) IdentityKey(sidecarId connect.Id) ([]byte, bool) {
	publicKey, found := self.rules.identityKeys[sidecarId]
	return bytes.Clone(publicKey), found
}
