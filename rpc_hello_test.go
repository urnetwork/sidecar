//go:build !sidecar_http && !js

// §6.4's Hello between two dispatchers, each with an identity of its own: the exchange that opens both
// gates, the identity check's refusals one at a time beside a twin that passes, the pin's first use
// surviving a restart, generations, the floor, feature bits, and two Hellos crossing. A pair delivers
// each side's sends to the other's inline handler as connect would, under the C15 key its binding
// names, on clocks the test moves.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A SidecarStore in memory, one map for a store and every directory under it. failing makes every call
// answer ErrSidecarStoreFailed, as a medium that broke does.
type testMemoryStore struct {
	prefix string
	shared *testMemoryStoreFiles
}

type testMemoryStoreFiles struct {
	stateLock sync.Mutex
	files     map[string][]byte
	failing   bool
}

func newTestMemoryStore() *testMemoryStore {
	return &testMemoryStore{shared: &testMemoryStoreFiles{files: map[string][]byte{}}}
}

func (self *testMemoryStore) fail() bool {
	self.shared.stateLock.Lock()
	defer self.shared.stateLock.Unlock()
	return self.shared.failing
}

func (self *testMemoryStore) Open(name string) (io.ReadCloser, error) {
	if self.fail() {
		return nil, ErrSidecarStoreFailed
	}
	self.shared.stateLock.Lock()
	defer self.shared.stateLock.Unlock()
	value, ok := self.shared.files[self.prefix+name]
	if !ok {
		return nil, ErrSidecarStoreAbsent
	}
	return io.NopCloser(bytes.NewReader(bytes.Clone(value))), nil
}

type testMemoryStoreWriter struct {
	store  *testMemoryStore
	name   string
	buffer bytes.Buffer
}

func (self *testMemoryStoreWriter) Write(data []byte) (int, error) {
	return self.buffer.Write(data)
}

func (self *testMemoryStoreWriter) Commit() error {
	if self.store.fail() {
		return ErrSidecarStoreFailed
	}
	self.store.shared.stateLock.Lock()
	defer self.store.shared.stateLock.Unlock()
	self.store.shared.files[self.store.prefix+self.name] = bytes.Clone(self.buffer.Bytes())
	return nil
}

func (self *testMemoryStoreWriter) Close() error {
	return nil
}

func (self *testMemoryStore) Create(name string) (SidecarStoreWriter, error) {
	if self.fail() {
		return nil, ErrSidecarStoreFailed
	}
	return &testMemoryStoreWriter{store: self, name: name}, nil
}

func (self *testMemoryStore) Remove(name string) error {
	self.shared.stateLock.Lock()
	defer self.shared.stateLock.Unlock()
	delete(self.shared.files, self.prefix+name)
	return nil
}

func (self *testMemoryStore) List(prefix string) ([]SidecarStoreEntry, error) {
	self.shared.stateLock.Lock()
	defer self.shared.stateLock.Unlock()
	entries := []SidecarStoreEntry{}
	for name, value := range self.shared.files {
		if relative, found := strings.CutPrefix(name, self.prefix); found && strings.HasPrefix(relative, prefix) {
			entries = append(entries, SidecarStoreEntry{Name: relative, ByteCount: int64(len(value))})
		}
	}
	slices.SortFunc(entries, func(a SidecarStoreEntry, b SidecarStoreEntry) int {
		return strings.Compare(a.Name, b.Name)
	})
	return entries, nil
}

func (self *testMemoryStore) Directory(name string, class string) (SidecarStore, error) {
	return &testMemoryStore{prefix: self.prefix + name + "/", shared: self.shared}, nil
}

// The pair's C15 reader: the key the Peer's Principal holds in hex, and none for an empty one.
func testRpcClientPublicKeyOf(peer connect.Peer) ([ed25519.PublicKeySize]byte, bool) {
	var key [ed25519.PublicKeySize]byte
	decoded, err := hex.DecodeString(peer.Principal)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return key, false
	}
	copy(key[:], decoded)
	return key, true
}

// Two or more dispatchers of one network, each delivering its sends to the side they name.
type testRpcPair struct {
	t         testing.TB
	networkId Id

	stateLock sync.Mutex
	sides     map[connect.Id]*testRpcSide
	// what delivery does to each envelope: nil delivers it as sent; a hook may rewrite it, or drop it by
	// answering nil
	deliver func(from *testRpcSide, to *testRpcSide, envelope *protocol.Envelope) *protocol.Envelope
	// the network's verified state every side added from now on reads for M2's admission check; nil
	// runs M1's first-use pins (rpc_admission_test.go)
	authority *testAdmissionAuthority
}

func newTestRpcPair(t testing.TB) *testRpcPair {
	return &testRpcPair{t: t, networkId: NewId(), sides: map[connect.Id]*testRpcSide{}}
}

// One side: its dispatcher, identity, keys, store and clock, with what it sent and raised.
type testRpcSide struct {
	pair            *testRpcPair
	subprotocol     *Subprotocol
	clientId        connect.Id
	sidecarId       Id
	identitySeed    []byte
	clientKeySeed   []byte
	generation      int64
	binding         []byte
	clientPublicKey [ed25519.PublicKeySize]byte
	clock           *testEnvelopeClock
	store           *testMemoryStore
	settings        *SidecarProtocolSettings
	events          chan SidecarEvent
	cancel          context.CancelFunc

	stateLock sync.Mutex
	// envelopes this side sent, in order
	sentEnvelopes []*protocol.Envelope
	// sends left to refuse at once
	refuseCount int
	// a frame's C15 key, if not its binding's
	presentedKey *[ed25519.PublicKeySize]byte
	// frames carry no C15 key at all
	presentsNoKey bool
}

// The side's identity for a new side: fresh seeds and ids.
type testRpcIdentity struct {
	sidecarId     Id
	identitySeed  []byte
	clientKeySeed []byte
	generation    int64
	store         *testMemoryStore
}

func newTestRpcIdentity() *testRpcIdentity {
	identitySeed := make([]byte, ed25519.SeedSize)
	clientKeySeed := make([]byte, ed25519.SeedSize)
	rand.Read(identitySeed)
	rand.Read(clientKeySeed)
	return &testRpcIdentity{sidecarId: NewId(), identitySeed: identitySeed, clientKeySeed: clientKeySeed, generation: 1, store: newTestMemoryStore()}
}

// A binding for identity on clientId, signed with its seeds, its network networkId.
func testRpcBinding(t testing.TB, networkId Id, clientId connect.Id, identity *testRpcIdentity) []byte {
	t.Helper()
	binding, err := NewSidecarIdentityBinding(&SidecarIdentityBinding{
		NetworkId:  networkId,
		SidecarId:  identity.sidecarId,
		ClientId:   Id(clientId),
		Generation: identity.generation,
		IssuedAt:   time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
	}, identity.identitySeed, identity.clientKeySeed)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

// Adds a side with identity, nil for a fresh one, its settings adjusted by adjust.
func (self *testRpcPair) add(identity *testRpcIdentity, adjust func(settings *SidecarProtocolSettings)) *testRpcSide {
	t := self.t
	t.Helper()
	if identity == nil {
		identity = newTestRpcIdentity()
	}
	clientId := connect.NewId()
	binding := testRpcBinding(t, self.networkId, clientId, identity)
	verified, err := VerifySidecarIdentityBinding(binding)
	if err != nil {
		t.Fatal(err)
	}
	clock := newTestEnvelopeClock()
	clock.firesWaits = true
	settings := DefaultSidecarProtocolSettings()
	if adjust != nil {
		adjust(settings)
	}
	ctx, cancel := context.WithCancel(context.Background())
	side := &testRpcSide{
		pair:          self,
		clientId:      clientId,
		sidecarId:     identity.sidecarId,
		identitySeed:  identity.identitySeed,
		clientKeySeed: identity.clientKeySeed,
		generation:    identity.generation,
		binding:       binding,
		clock:         clock,
		store:         identity.store,
		settings:      settings,
		events:        make(chan SidecarEvent, 16),
		cancel:        cancel,
	}
	copy(side.clientPublicKey[:], verified.ClientPublicKey)
	client := newTestRequiredClient(t, ctx)
	subprotocol, err := newSubprotocol(ctx, &SubprotocolEnv{
		Client:    client,
		Store:     identity.store,
		Log:       NewNoopLogger(),
		Settings:  settings,
		Budget:    NewSubprotocolBudget(settings, 128*1024*1024),
		Clock:     clock,
		Inbound:   SubprotocolInboundWithoutPolicy,
		NetworkId: self.networkId,
		Binding:   binding,
		Event: func(event SidecarEvent) {
			side.events <- event
		},
		Admissions: self.admissionsFor(identity.sidecarId, clock),
	}, &subprotocolSeams{clientPublicKeyOf: testRpcClientPublicKeyOf, send: side.send})
	if err != nil {
		t.Fatal(err)
	}
	side.subprotocol = subprotocol
	t.Cleanup(func() {
		subprotocol.Close()
		cancel()
	})
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.sides[clientId] = side
	return side
}

// The Peer a frame from this side arrives with: same network, on h1, under its binding's client key
// or the one presentedKey names.
func (self *testRpcSide) peer() connect.Peer {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := self.clientPublicKey
	if self.presentedKey != nil {
		key = *self.presentedKey
	}
	principal := hex.EncodeToString(key[:])
	if self.presentsNoKey {
		principal = ""
	}
	return connect.Peer{
		ProvideMode:   connectprotocol.ProvideMode_Network,
		TransportType: connect.TransportTypeH1,
		Principal:     principal,
	}
}

// The side's send: refuses while refuseCount lasts, else records the envelope and hands a copy to the
// side it names, through the pair's deliver hook.
func (self *testRpcSide) send(destinationId connect.Id, envelope *protocol.Envelope, ack connect.AckFunction, timeout time.Duration, opts ...any) (bool, error) {
	refused := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.sentEnvelopes = append(self.sentEnvelopes, proto.Clone(envelope).(*protocol.Envelope))
		if 0 < self.refuseCount {
			self.refuseCount -= 1
			refused = true
		}
	}()
	if refused {
		return false, nil
	}
	var to *testRpcSide
	var deliver func(from *testRpcSide, to *testRpcSide, envelope *protocol.Envelope) *protocol.Envelope
	func() {
		self.pair.stateLock.Lock()
		defer self.pair.stateLock.Unlock()
		to = self.pair.sides[destinationId]
		deliver = self.pair.deliver
	}()
	if to == nil {
		return true, nil
	}
	delivered := proto.Clone(envelope).(*protocol.Envelope)
	if deliver != nil {
		delivered = deliver(self, to, delivered)
	}
	if delivered != nil {
		to.subprotocol.receive(connect.SourceId(self.clientId), delivered, self.peer())
	}
	return true, nil
}

// What this side sent so far.
func (self *testRpcSide) sent() []*protocol.Envelope {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.sentEnvelopes)
}

func (self *testRpcSide) setDeliver(deliver func(from *testRpcSide, to *testRpcSide, envelope *protocol.Envelope) *protocol.Envelope) {
	self.pair.stateLock.Lock()
	defer self.pair.stateLock.Unlock()
	self.pair.deliver = deliver
}

// One side runs Hello with another; both gates open and each side holds the other's identity.
func TestHelloOpensBothGates(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
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
		if peer.SidecarId != c.to.sidecarId || peer.Generation != 1 || !bytes.Equal(peer.Binding, c.to.binding) ||
			peer.MaxBodyByteCount != uint32(c.to.settings.ReassemblyMaxBodyByteCount) || peer.Features != 0 {
			t.Errorf("peer %+v", peer)
		}
	}
	// a second EnsureHello sends nothing more
	sentCount := len(a.sent())
	if err := a.subprotocol.EnsureHello(t.Context(), Id(b.clientId)); err != nil {
		t.Fatal(err)
	}
	if len(a.sent()) != sentCount {
		t.Errorf("a standing Hello was run again")
	}
	// Hello and HelloResult each fit their budget: 512 B with connect's 7 B wrapper
	for _, envelope := range append(a.sent(), b.sent()...) {
		if size := proto.Size(envelope) + 7; 512 < size {
			t.Errorf("type %d: %d B", envelope.Type, size)
		}
	}
}

// Hello's checks, each failing alone beside the twin that passes: the responder refuses each with its
// code and opens nothing, and the initiator's call fails.
func TestHelloRefusesEachCheckAlone(t *testing.T) {
	cases := []struct {
		name string
		// changes the initiator's Hello as it is delivered
		edit func(t testing.TB, pair *testRpcPair, a *testRpcSide, b *testRpcSide, hello *protocol.Hello)
		// changes the initiator's frames' C15 key
		presented func(a *testRpcSide) *[ed25519.PublicKeySize]byte
		code      protocol.ErrorCode
	}{
		{name: "the twin that passes", code: protocol.ErrorCode_ERR_OK},
		{
			name: "wrong network",
			edit: func(t testing.TB, pair *testRpcPair, a *testRpcSide, b *testRpcSide, hello *protocol.Hello) {
				hello.Binding = testRpcBinding(t, NewId(), a.clientId, &testRpcIdentity{sidecarId: a.sidecarId, identitySeed: a.identitySeed, clientKeySeed: a.clientKeySeed, generation: 1})
			},
			code: protocol.ErrorCode_ERR_UNAUTHENTICATED,
		},
		{
			name: "client id not the source",
			edit: func(t testing.TB, pair *testRpcPair, a *testRpcSide, b *testRpcSide, hello *protocol.Hello) {
				hello.Binding = testRpcBinding(t, pair.networkId, connect.NewId(), &testRpcIdentity{sidecarId: a.sidecarId, identitySeed: a.identitySeed, clientKeySeed: a.clientKeySeed, generation: 1})
			},
			code: protocol.ErrorCode_ERR_UNAUTHENTICATED,
		},
		{
			name: "a bad client signature",
			edit: func(t testing.TB, pair *testRpcPair, a *testRpcSide, b *testRpcSide, hello *protocol.Hello) {
				hello.Binding = testTamperBinding(t, hello.Binding, func(signed *bridge.SignedSidecarIdentityBinding) {
					signed.ClientSignature[0] ^= 1
				})
			},
			code: protocol.ErrorCode_ERR_UNAUTHENTICATED,
		},
		{
			name: "a bad identity signature",
			edit: func(t testing.TB, pair *testRpcPair, a *testRpcSide, b *testRpcSide, hello *protocol.Hello) {
				hello.Binding = testTamperBinding(t, hello.Binding, func(signed *bridge.SignedSidecarIdentityBinding) {
					signed.IdentitySignature[0] ^= 1
				})
			},
			code: protocol.ErrorCode_ERR_UNAUTHENTICATED,
		},
		{
			name: "no binding",
			edit: func(t testing.TB, pair *testRpcPair, a *testRpcSide, b *testRpcSide, hello *protocol.Hello) {
				hello.Binding = nil
			},
			code: protocol.ErrorCode_ERR_UNAUTHENTICATED,
		},
		{
			name: "the binding's key is not C15's",
			presented: func(a *testRpcSide) *[ed25519.PublicKeySize]byte {
				key := testClientKey("another session")
				return &key
			},
			code: protocol.ErrorCode_ERR_UNAUTHENTICATED,
		},
		{
			name: "no C15 key",
			presented: func(a *testRpcSide) *[ed25519.PublicKeySize]byte {
				return nil
			},
			code: protocol.ErrorCode_ERR_UNAUTHENTICATED,
		},
		{
			name: "a secure_version below the floor",
			edit: func(t testing.TB, pair *testRpcPair, a *testRpcSide, b *testRpcSide, hello *protocol.Hello) {
				hello.SecureVersion = MinSecureVersion - 1
			},
			code: protocol.ErrorCode_ERR_VERSION,
		},
		{
			name: "an unknown major",
			edit: func(t testing.TB, pair *testRpcPair, a *testRpcSide, b *testRpcSide, hello *protocol.Hello) {
				hello.MinVersion = WireVersionMajor + 1
				hello.MaxVersion = WireVersionMajor + 1
			},
			code: protocol.ErrorCode_ERR_VERSION,
		},
		{
			name: "every feature bit set changes nothing",
			edit: func(t testing.TB, pair *testRpcPair, a *testRpcSide, b *testRpcSide, hello *protocol.Hello) {
				hello.Features = ^uint64(0)
			},
			code: protocol.ErrorCode_ERR_OK,
		},
		{
			name: "every feature bit set saves no binding",
			edit: func(t testing.TB, pair *testRpcPair, a *testRpcSide, b *testRpcSide, hello *protocol.Hello) {
				hello.Features = ^uint64(0)
				hello.Binding = nil
			},
			code: protocol.ErrorCode_ERR_UNAUTHENTICATED,
		},
	}
	for _, c := range cases {
		pair := newTestRpcPair(t)
		a := pair.add(nil, nil)
		b := pair.add(nil, nil)
		if c.presented != nil {
			key := c.presented(a)
			func() {
				a.stateLock.Lock()
				defer a.stateLock.Unlock()
				if key == nil {
					a.presentsNoKey = true
				} else {
					a.presentedKey = key
				}
			}()
		}
		if c.edit != nil {
			a.setDeliver(func(from *testRpcSide, to *testRpcSide, envelope *protocol.Envelope) *protocol.Envelope {
				if from != a || envelope.Type != uint32(protocol.MessageType_HELLO) {
					return envelope
				}
				hello := &protocol.Hello{}
				if err := proto.Unmarshal(envelope.Body, hello); err != nil {
					t.Fatal(err)
				}
				c.edit(t, pair, a, b, hello)
				body, err := proto.Marshal(hello)
				if err != nil {
					t.Fatal(err)
				}
				envelope.Body = body
				return envelope
			})
		}
		err := a.subprotocol.EnsureHello(t.Context(), Id(b.clientId))
		code, _ := SubprotocolErrorCode(err)
		if c.code == protocol.ErrorCode_ERR_OK {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			if !b.subprotocol.peerVerified(a.clientId) {
				t.Errorf("%s: the responder's gate stayed closed", c.name)
			}
			continue
		}
		if code != c.code {
			t.Errorf("%s: code %v, err %v", c.name, code, err)
		}
		if b.subprotocol.peerVerified(a.clientId) || a.subprotocol.peerVerified(b.clientId) {
			t.Errorf("%s: a gate opened", c.name)
		}
	}
}

// The marshalled binding with edit applied to its wrapper, the body as it was.
func testTamperBinding(t testing.TB, binding []byte, edit func(signed *bridge.SignedSidecarIdentityBinding)) []byte {
	t.Helper()
	signed := &bridge.SignedSidecarIdentityBinding{}
	if err := proto.Unmarshal(binding, signed); err != nil {
		t.Fatal(err)
	}
	edit(signed)
	tampered, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return tampered
}

// The first Hello of a sidecar_id pins its identity key: a second identity key for that sidecar_id is
// refused with key_changed, a lower generation is refused, and generation n+1 on a new client under the
// same identity key passes. The pin outlives a restart of the dispatcher on the same store.
func TestHelloPinsTheIdentityKey(t *testing.T) {
	pair := newTestRpcPair(t)
	b := pair.add(nil, nil)
	identity := newTestRpcIdentity()
	identity.generation = 2
	a := pair.add(identity, nil)
	if err := a.subprotocol.EnsureHello(t.Context(), Id(b.clientId)); err != nil {
		t.Fatal(err)
	}

	// another identity key under the same sidecar_id
	impostor := newTestRpcIdentity()
	impostor.sidecarId = identity.sidecarId
	impostor.generation = 3
	c := pair.add(impostor, nil)
	err := c.subprotocol.EnsureHello(t.Context(), Id(b.clientId))
	if code, _ := SubprotocolErrorCode(err); code != protocol.ErrorCode_ERR_UNAUTHENTICATED {
		t.Fatalf("a second identity key: %v", err)
	}
	event := testAwait(t, b.events, "key_changed")
	if event.Kind != SidecarEventKeyChanged || event.SidecarId == nil || *event.SidecarId != identity.sidecarId {
		t.Errorf("event %+v", event)
	}

	// a lower generation of the pinned identity
	older := &testRpcIdentity{sidecarId: identity.sidecarId, identitySeed: identity.identitySeed, clientKeySeed: identity.clientKeySeed, generation: 1, store: newTestMemoryStore()}
	d := pair.add(older, nil)
	if code, _ := SubprotocolErrorCode(d.subprotocol.EnsureHello(t.Context(), Id(b.clientId))); code != protocol.ErrorCode_ERR_UNAUTHENTICATED {
		t.Errorf("a lower generation: %v", code)
	}

	// generation n+1 on a new client and a new client key, the same identity key
	newClientKeySeed := make([]byte, ed25519.SeedSize)
	rand.Read(newClientKeySeed)
	repaired := &testRpcIdentity{sidecarId: identity.sidecarId, identitySeed: identity.identitySeed, clientKeySeed: newClientKeySeed, generation: 3, store: newTestMemoryStore()}
	e := pair.add(repaired, nil)
	if err := e.subprotocol.EnsureHello(t.Context(), Id(b.clientId)); err != nil {
		t.Fatalf("generation n+1: %v", err)
	}

	// a restart of b on its store keeps the pin and the generation it reached
	restarted := pair.add(&testRpcIdentity{sidecarId: b.sidecarId, identitySeed: b.identitySeed, clientKeySeed: b.clientKeySeed, generation: 1, store: b.store}, nil)
	f := pair.add(&testRpcIdentity{sidecarId: identity.sidecarId, identitySeed: impostor.identitySeed, clientKeySeed: impostor.clientKeySeed, generation: 4, store: newTestMemoryStore()}, nil)
	if code, _ := SubprotocolErrorCode(f.subprotocol.EnsureHello(t.Context(), Id(restarted.clientId))); code != protocol.ErrorCode_ERR_UNAUTHENTICATED {
		t.Errorf("after a restart, a second identity key: %v", code)
	}
	g := pair.add(&testRpcIdentity{sidecarId: identity.sidecarId, identitySeed: identity.identitySeed, clientKeySeed: identity.clientKeySeed, generation: 2, store: newTestMemoryStore()}, nil)
	if code, _ := SubprotocolErrorCode(g.subprotocol.EnsureHello(t.Context(), Id(restarted.clientId))); code != protocol.ErrorCode_ERR_UNAUTHENTICATED {
		t.Errorf("after a restart, a generation below the one reached: %v", code)
	}
}

// A store that cannot answer pins nothing and opens nothing: the Hello is refused UNAVAILABLE.
func TestHelloRefusesWhenThePinStoreFails(t *testing.T) {
	pair := newTestRpcPair(t)
	b := pair.add(nil, nil)
	a := pair.add(nil, nil)
	func() {
		b.store.shared.stateLock.Lock()
		defer b.store.shared.stateLock.Unlock()
		b.store.shared.failing = true
	}()
	if code, _ := SubprotocolErrorCode(a.subprotocol.EnsureHello(t.Context(), Id(b.clientId))); code != protocol.ErrorCode_ERR_UNAVAILABLE {
		t.Errorf("code %v", code)
	}
	if b.subprotocol.peerVerified(a.clientId) {
		t.Errorf("a failed pin opened the gate")
	}
}

// A HelloResult that fails the initiator's checks leaves its gate closed, though the responder opened
// its own, and a later call through the responder's open gate is refused at the initiator's.
func TestHelloResultCheckedByTheInitiator(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
	b.setDeliver(func(from *testRpcSide, to *testRpcSide, envelope *protocol.Envelope) *protocol.Envelope {
		if from == b && envelope.Type == uint32(protocol.MessageType_HELLO_RESULT) {
			result := &protocol.HelloResult{}
			proto.Unmarshal(envelope.Body, result)
			result.Binding = testTamperBinding(t, result.Binding, func(signed *bridge.SignedSidecarIdentityBinding) {
				signed.IdentitySignature[1] ^= 1
			})
			envelope.Body, _ = proto.Marshal(result)
		}
		return envelope
	})
	if err := a.subprotocol.EnsureHello(t.Context(), Id(b.clientId)); !errors.Is(err, ErrSidecarBindingInvalid) {
		t.Fatalf("err %v", err)
	}
	if a.subprotocol.peerVerified(b.clientId) {
		t.Errorf("a bad HelloResult opened the initiator's gate")
	}
	if !b.subprotocol.peerVerified(a.clientId) {
		t.Errorf("the responder did not open its gate for a good Hello")
	}
}

// Both sides send Hello at once: each answers the other's, and both gates open.
func TestSimultaneousHellosConverge(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
	errs := make(chan error, 2)
	go func() {
		errs <- a.subprotocol.EnsureHello(context.Background(), Id(b.clientId))
	}()
	go func() {
		errs <- b.subprotocol.EnsureHello(context.Background(), Id(a.clientId))
	}()
	for range 2 {
		if err := testAwait(t, errs, "hello"); err != nil {
			t.Fatal(err)
		}
	}
	if !a.subprotocol.peerVerified(b.clientId) || !b.subprotocol.peerVerified(a.clientId) {
		t.Errorf("the gates did not both open")
	}
}

// Concurrent EnsureHellos to one peer run one Hello.
func TestEnsureHelloRunsOneHelloAtATime(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
	// hold the first Hello's delivery until both callers wait
	release := make(chan struct{})
	a.setDeliver(func(from *testRpcSide, to *testRpcSide, envelope *protocol.Envelope) *protocol.Envelope {
		if from == a && envelope.Type == uint32(protocol.MessageType_HELLO) {
			go func() {
				<-release
				to.subprotocol.receive(connect.SourceId(from.clientId), envelope, from.peer())
			}()
			return nil
		}
		return envelope
	})
	waitCount, _ := a.clock.waitCount.Get()
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			errs <- a.subprotocol.EnsureHello(context.Background(), Id(b.clientId))
		}()
	}
	// the owner waits on its response timer; the joiner on the flight
	a.clock.awaitWaitCount(waitCount + 1)
	close(release)
	for range 2 {
		if err := testAwait(t, errs, "hello"); err != nil {
			t.Fatal(err)
		}
	}
	helloCount := 0
	for _, envelope := range a.sent() {
		if envelope.Type == uint32(protocol.MessageType_HELLO) {
			helloCount += 1
		}
	}
	if helloCount != 1 {
		t.Errorf("%d Hellos", helloCount)
	}
}

// A send's ack error ends the peer's Hello (reading 1).
func TestAckErrorEndsTheHello(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
	if err := a.subprotocol.EnsureHello(t.Context(), Id(b.clientId)); err != nil {
		t.Fatal(err)
	}
	a.subprotocol.forgetPeerOnAckError(b.clientId)(nil)
	if !a.subprotocol.peerVerified(b.clientId) {
		t.Fatalf("an ack with no error ended the Hello")
	}
	a.subprotocol.forgetPeerOnAckError(b.clientId)(errors.New("synthetic ack timeout"))
	if a.subprotocol.peerVerified(b.clientId) {
		t.Errorf("an ack error left the Hello standing")
	}
}

// core's raise of the floor applies live and never past this release's own SecureVersion (QD-032).
func TestRaisedSecureFloorIsClamped(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	if floor := a.subprotocol.secureFloor(); floor != MinSecureVersion {
		t.Errorf("floor %d", floor)
	}
	a.subprotocol.SetRaisedSecureFloor(SecureVersion + 100)
	if floor := a.subprotocol.secureFloor(); floor != SecureVersion {
		t.Errorf("a raise past this release: floor %d", floor)
	}
	a.subprotocol.SetRaisedSecureFloor(0)
	if floor := a.subprotocol.secureFloor(); floor != MinSecureVersion {
		t.Errorf("a dropped raise: floor %d", floor)
	}
}

//go:embed testdata/wire/hello.json
var testHelloVectorsJson []byte

// testdata/wire/hello.json: a Hello and a HelloResult over the first vector binding of
// testdata/binding/vectors.json, and the envelope bytes each makes, within 512 B with connect's wrapper.
type testHelloVector struct {
	Name          string `json:"name"`
	Type          uint32 `json:"type"`
	RequestId     uint64 `json:"request_id"`
	Flags         uint32 `json:"flags"`
	TimeoutMs     uint32 `json:"timeout_ms"`
	SecureVersion uint32 `json:"secure_version"`
	MaxBody       uint32 `json:"max_body_byte_count"`
	InitialWindow uint32 `json:"initial_window"`
	Binding       string `json:"binding"`
	Envelope      string `json:"envelope"`
	ByteCount     int    `json:"byte_count"`
}

func TestHelloVectors(t *testing.T) {
	vectors := []*testHelloVector{}
	if err := json.Unmarshal(testHelloVectorsJson, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 2 {
		t.Fatalf("%d vectors", len(vectors))
	}
	for _, vector := range vectors {
		binding, err := hex.DecodeString(vector.Binding)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifySidecarIdentityBinding(binding); err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		fields := &helloFields{
			minVersion:       WireVersionMajor,
			maxVersion:       WireVersionMajor,
			secureVersion:    vector.SecureVersion,
			maxBodyByteCount: vector.MaxBody,
			initialWindow:    vector.InitialWindow,
			binding:          binding,
		}
		var message proto.Message = fields.hello()
		if vector.Type == uint32(protocol.MessageType_HELLO_RESULT) {
			message = fields.helloResult()
		}
		body, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.Envelope{
			Version:   WireVersionMajor,
			Type:      vector.Type,
			RequestId: vector.RequestId,
			Flags:     vector.Flags,
			TimeoutMs: vector.TimeoutMs,
			Body:      body,
		})
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(envelope) != vector.Envelope || len(envelope) != vector.ByteCount {
			t.Errorf("%s: %d B %x", vector.Name, len(envelope), envelope)
		}
		if 512 < len(envelope)+7 {
			t.Errorf("%s: %d B with the wrapper", vector.Name, len(envelope)+7)
		}
	}
}
