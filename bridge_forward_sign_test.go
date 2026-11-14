// The forwarding signer (BRIDGE-M8-05): what it signs verifies at a host by the signer's length alone, and each rule
// it holds refuses beside a twin that signs.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A forwarding signer over a fixed key, a clock the test moves and link targets the test sets.
type testForwardingSigner struct {
	signer       *ForwardingSigner
	clock        *testEnvelopeClock
	networkId    Id
	sidecarId    Id
	target       Id
	delegationId [sha256.Size]byte
	publicKey    ed25519.PublicKey
	// what Sign was asked to sign
	signed [][]byte
	// the state in force: its link targets, and whether there is one
	targets []Id
	inForce bool
}

func newTestForwardingSigner(t *testing.T) *testForwardingSigner {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	self := &testForwardingSigner{
		clock:        newTestEnvelopeClock(),
		networkId:    NewId(),
		sidecarId:    NewId(),
		target:       NewId(),
		delegationId: sha256.Sum256([]byte("a synthetic forwarding delegation")),
		publicKey:    privateKey.Public().(ed25519.PublicKey),
		inForce:      true,
	}
	self.targets = []Id{self.target}
	signer, err := NewForwardingSigner(&ForwardingSignerArgs{
		NetworkId:    self.networkId,
		SidecarId:    self.sidecarId,
		DelegationId: self.delegationId,
		PublicKey:    self.publicKey,
		Sign: func(message []byte) ([]byte, error) {
			self.signed = append(self.signed, bytes.Clone(message))
			return ed25519.Sign(privateKey, message), nil
		},
		LinkTargets: func() ([]Id, bool) {
			return self.targets, self.inForce
		},
		Clock: self.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	self.signer = signer
	return self
}

// A request the signer signs: a window client of this sidecar's link to the target, an hour ahead.
func (self *testForwardingSigner) request() *ForwardingSignRequest {
	return &ForwardingSignRequest{
		NetworkId:             self.networkId,
		SubjectSidecarId:      self.sidecarId,
		WindowClientId:        Id{1, 2, 3},
		WindowClientPublicKey: bytes.Repeat([]byte{9}, ed25519.PublicKeySize),
		TargetSidecarId:       self.target,
		NotAfter:              self.clock.Now().Add(time.Hour),
	}
}

// The host's check of what a request's delegation must bind, with the state listing the forwarding key for S.
func (self *testForwardingSigner) check(request *ForwardingSignRequest) *bridge.WindowDelegationCheck {
	return &bridge.WindowDelegationCheck{
		NetworkId:             request.NetworkId.Bytes(),
		WindowClientId:        request.WindowClientId.Bytes(),
		WindowClientPublicKey: request.WindowClientPublicKey,
		TargetSidecarId:       request.TargetSidecarId.Bytes(),
		NowMs:                 self.clock.Now().UnixMilli(),
		IdentityKey: func(sidecarId []byte) ([]byte, bool) {
			return nil, false
		},
		ForwardingKey: func(delegationId []byte) ([]byte, []byte, bool) {
			if !bytes.Equal(delegationId, self.delegationId[:]) {
				return nil, nil, false
			}
			return self.sidecarId.Bytes(), self.publicKey, true
		},
	}
}

// What the signer signs carries subject S, the Delegation's id as its 32-byte signer, the key's SHA-256 as key_id
// and the window client's strict_exp, and a host admits it under the forwarding key its state lists for S, by the
// signer's length, with no identity key in reach.
func TestForwardingSignerSignsWhatAHostAdmitsByTheForwardingKey(t *testing.T) {
	world := newTestForwardingSigner(t)
	request := world.request()
	signedBytes, err := world.signer.SignWindowDelegation(request)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := bridge.VerifyWindowDelegationAdmission(signedBytes, world.check(request))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(admission.ForwardDelegationId, world.delegationId[:]) {
		t.Fatalf("admitted by %x", admission.ForwardDelegationId)
	}
	delegation := admission.Delegation
	if !bytes.Equal(delegation.GetSubjectSidecarId(), world.sidecarId.Bytes()) || delegation.GetNotAfterMs() != request.NotAfter.UnixMilli() {
		t.Fatalf("the delegation: %v", delegation)
	}
	if len(world.signed) != 1 {
		t.Fatalf("the key signed %d messages", len(world.signed))
	}
	// a host whose state lists another key for the Delegation refuses it
	other := world.check(request)
	other.ForwardingKey = func(delegationId []byte) ([]byte, []byte, bool) {
		return world.sidecarId.Bytes(), bytes.Repeat([]byte{1}, ed25519.PublicKeySize), true
	}
	if _, err := bridge.VerifyWindowDelegationAdmission(signedBytes, other); err == nil {
		t.Fatal("a host admitted the delegation under another key")
	}
}

// The signer signs only its own sidecar's delegations: another subject, another network, a target the state in force
// links to nowhere, a not_after past or too far, a malformed window client and a share link are each refused, alone,
// and the key signs nothing for them.
func TestForwardingSignerRefusesEachRuleAlone(t *testing.T) {
	world := newTestForwardingSigner(t)
	for name, mutate := range map[string]func(request *ForwardingSignRequest){
		"another subject":  func(request *ForwardingSignRequest) { request.SubjectSidecarId = NewId() },
		"another network":  func(request *ForwardingSignRequest) { request.NetworkId = NewId() },
		"another target":   func(request *ForwardingSignRequest) { request.TargetSidecarId = NewId() },
		"no target":        func(request *ForwardingSignRequest) { request.TargetSidecarId = Id{} },
		"no window client": func(request *ForwardingSignRequest) { request.WindowClientId = Id{} },
		"a short client key": func(request *ForwardingSignRequest) {
			request.WindowClientPublicKey = request.WindowClientPublicKey[:31]
		},
		"a not_after now": func(request *ForwardingSignRequest) { request.NotAfter = world.clock.Now() },
		"a not_after too far": func(request *ForwardingSignRequest) {
			request.NotAfter = world.clock.Now().Add(168*time.Hour + time.Millisecond)
		},
		"a share link": func(request *ForwardingSignRequest) { request.ShareId = NewId() },
	} {
		request := world.request()
		mutate(request)
		if _, err := world.signer.SignWindowDelegation(request); !errors.Is(err, ErrForwardingDelegationRefused) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := world.signer.SignWindowDelegation(nil); !errors.Is(err, ErrForwardingDelegationRefused) {
		t.Fatalf("no request: %v", err)
	}
	if len(world.signed) != 0 {
		t.Fatalf("the key signed %d refused delegations", len(world.signed))
	}
	// the twin: the longest lifetime signs
	longest := world.request()
	longest.NotAfter = world.clock.Now().Add(168 * time.Hour)
	if _, err := world.signer.SignWindowDelegation(longest); err != nil {
		t.Fatal(err)
	}
}

// With no state in force the signer signs nothing, and signs again once one is; a key that fails, or answers a
// signature of the wrong length, is a refusal.
func TestForwardingSignerSignsNothingWhilePending(t *testing.T) {
	world := newTestForwardingSigner(t)
	world.inForce = false
	if _, err := world.signer.SignWindowDelegation(world.request()); !errors.Is(err, ErrForwardingDelegationRefused) {
		t.Fatalf("pending: %v", err)
	}
	if len(world.signed) != 0 {
		t.Fatal("the key signed while pending")
	}
	world.inForce = true
	if _, err := world.signer.SignWindowDelegation(world.request()); err != nil {
		t.Fatal(err)
	}
	for name, sign := range map[string]func(message []byte) ([]byte, error){
		"a failing key":     func(message []byte) ([]byte, error) { return nil, errors.New("the key is locked") },
		"a short signature": func(message []byte) ([]byte, error) { return make([]byte, 63), nil },
	} {
		args := *world.signer.args
		args.Sign = sign
		signer, err := NewForwardingSigner(&args)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := signer.SignWindowDelegation(world.request()); !errors.Is(err, ErrForwardingDelegationRefused) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// A signer is built only over its network, sidecar, Delegation, a 32-byte key, the key's Sign and the state's targets.
func TestForwardingSignerNeedsItsKeyAndItsState(t *testing.T) {
	world := newTestForwardingSigner(t)
	for name, mutate := range map[string]func(args *ForwardingSignerArgs){
		"no network":    func(args *ForwardingSignerArgs) { args.NetworkId = Id{} },
		"no sidecar":    func(args *ForwardingSignerArgs) { args.SidecarId = Id{} },
		"no delegation": func(args *ForwardingSignerArgs) { args.DelegationId = [sha256.Size]byte{} },
		"a short key":   func(args *ForwardingSignerArgs) { args.PublicKey = args.PublicKey[:31] },
		"no sign":       func(args *ForwardingSignerArgs) { args.Sign = nil },
		"no state":      func(args *ForwardingSignerArgs) { args.LinkTargets = nil },
	} {
		args := *world.signer.args
		mutate(&args)
		if _, err := NewForwardingSigner(&args); err == nil {
			t.Fatalf("%s built a signer", name)
		}
	}
	if _, err := NewForwardingSigner(nil); err == nil {
		t.Fatal("no args built a signer")
	}
}

// A Forwarder's signer signs by its last compile: its sidecar's link to a sidecar the state in force links, and
// nothing for another subject, for a sidecar the state does not link, or while the sink is forked.
func TestTheForwardersSignerSignsByItsLastCompile(t *testing.T) {
	world := newTestForwarderWorld(t)
	world.rotate(world.recipient())
	world.bind(world.peer)
	forwarder := world.forwarder()
	signer, err := forwarder.NewSigner(nil)
	if err != nil {
		t.Fatal(err)
	}
	request := func() *ForwardingSignRequest {
		return &ForwardingSignRequest{
			NetworkId: world.net.networkId, SubjectSidecarId: world.host.sidecarId, WindowClientId: Id{1, 2, 3},
			WindowClientPublicKey: bytes.Repeat([]byte{9}, ed25519.PublicKeySize), TargetSidecarId: world.peer.sidecarId,
			NotAfter: world.clock.Now().Add(time.Hour),
		}
	}
	if signed, err := signer.SignWindowDelegation(request()); err != nil || len(signed) == 0 {
		t.Fatalf("the link the state holds: %v", err)
	}
	anotherSubject := request()
	anotherSubject.SubjectSidecarId = world.peer.sidecarId
	if _, err := signer.SignWindowDelegation(anotherSubject); !errors.Is(err, ErrForwardingDelegationRefused) {
		t.Errorf("another subject: %v", err)
	}
	unlinked := request()
	unlinked.TargetSidecarId = world.net.owner.sidecarId
	if _, err := signer.SignWindowDelegation(unlinked); !errors.Is(err, ErrForwardingDelegationRefused) {
		t.Errorf("a sidecar the state does not link: %v", err)
	}
	if err := forwarder.Witness(world.net.log.State().Pin(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.SignWindowDelegation(request()); !errors.Is(err, ErrForwardingDelegationRefused) {
		t.Errorf("while forked: %v", err)
	}
	if err := forwarder.Witness(world.net.log.State().Pin(), false); err != nil {
		t.Fatal(err)
	}
	world.settle(forwarder)
	if _, err := signer.SignWindowDelegation(request()); err != nil {
		t.Errorf("after the fork cleared: %v", err)
	}

	world.keys.stateLock.Lock()
	world.keys.key = nil
	world.keys.stateLock.Unlock()
	if _, err := forwarder.NewSigner(nil); !errors.Is(err, ErrForwardingDelegationRefused) {
		t.Errorf("a signer with no current key set: %v", err)
	}
}
