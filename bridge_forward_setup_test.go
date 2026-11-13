//go:build !ios_extension && !sidecar_http

// BRIDGE-M8-06's setup on the test network, through a real Sidecar's act posting to the net's log, gkm and api's mint
// standing in: a setup hands off after its six steps, its Delegation live and verifying under the sidecar's identity
// key and its hand-off holding no key of the sidecar's and its token in no log line; a kill after each step resumes to
// one Delegation and one F; a setup is due at a new client generation and after 90 days and no sooner; another
// signer's revocation holds it until the person confirms, the sidecar's own does not; keys a setup cannot take are
// refused with nothing signed; and the witness hint carries the pin, §6.4's where one stands, and a fork.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A synthetic client token naming clientId, expiring at expires, as api's mint answers one.
func testForwardingJwt(clientId Id, expires time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{"client_id": clientId.String(), "exp": expires.Unix(), "strict_exp": true})
	return header + "." + base64.RawURLEncoding.EncodeToString(claims) + "." + base64.RawURLEncoding.EncodeToString([]byte("a synthetic signature"))
}

// A VPN component's key set's public halves, from a label.
func testForwardingKeys(label string) *bridge.ForwardingKeys {
	digest := sha256.Sum256([]byte("forwarding reader key " + label))
	return &bridge.ForwardingKeys{
		KeySetId:             testConfigId("forwarding key set " + label).Bytes(),
		ForwardPublicKey:     testConfigDeviceKey("forwarding key " + label).Public().(ed25519.PublicKey),
		ReaderXwingPublicKey: bytes.Repeat(digest[:], configXwingPublicKeyByteCount/sha256.Size),
		ClientPublicKey:      testConfigDeviceKey("forwarding client " + label).Public().(ed25519.PublicKey),
	}
}

// The net's state as the setup reads it: the filer's, and the entries its log keeps.
type testForwardingConfig struct {
	testBridgeFileConfig
}

func (self testForwardingConfig) BridgeEntries(from uint64, through uint64) []*BridgeConfigEntry {
	reads := []*BridgeConfigEntry{}
	for n := max(from, 1); n <= min(through, self.net.n); n += 1 {
		read := bridgeConfigEntryOf(self.net.log, n)
		if read == nil {
			break
		}
		reads = append(reads, read)
	}
	return reads
}

// The filer's world with forwarding's setup installed on its sidecar: gkm's two calls and api's mint stand in, each
// failing as many times as a test asks, and a logger keeps every line the sidecar writes.
type testForwardingWorld struct {
	*testBridgeFileWorld
	logger *testApprovalLogger
	store  *testMemoryStore

	stateLock sync.Mutex
	// the reader key each delegation id's object holds
	uploads     map[string][]byte
	uploadFails int
	wraps       [][]byte
	wrapFails   int
	mints       []*sidecarAuthClientWire
	mintFails   int
	// F by its client key, one a key as api keeps it
	forwardClients map[string]Id
}

func newTestForwardingWorld(t *testing.T) *testForwardingWorld {
	t.Helper()
	files := newTestBridgeFileWorld(t, false)
	world := &testForwardingWorld{
		testBridgeFileWorld: files, logger: &testApprovalLogger{}, store: newTestMemoryStore(),
		uploads: map[string][]byte{}, forwardClients: map[string]Id{},
	}
	files.sidecar.log = world.logger
	files.api.authClient = world.mint
	t.Cleanup(files.sidecar.InstallForwardingSetup(&ForwardingSetupSources{
		Config:                 testForwardingConfig{testBridgeFileConfig: testBridgeFileConfig{net: files.net}},
		UploadDelegationKey:    world.upload,
		DeliverDelegationWraps: world.wrap,
		Store:                  world.store,
	}))
	return world
}

func (self *testForwardingWorld) upload(ctx context.Context, delegationId []byte, readerKey []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if 0 < self.uploadFails {
		self.uploadFails -= 1
		return errors.New("gkm's state does not hold the row yet")
	}
	// gkm creates the object once, and the same bytes again answer success
	if held, ok := self.uploads[string(delegationId)]; ok && !bytes.Equal(held, readerKey) {
		return errors.New("another key for the delegation")
	}
	self.uploads[string(delegationId)] = bytes.Clone(readerKey)
	return nil
}

func (self *testForwardingWorld) wrap(ctx context.Context, delegationId []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if 0 < self.wrapFails {
		self.wrapFails -= 1
		return errors.New("the rotation's flow is busy")
	}
	self.wraps = append(self.wraps, bytes.Clone(delegationId))
	return nil
}

// POST /network/auth-client as server answers a forwarding mint: a child of the bearer's client, forward_only with its
// client key, and the same F for a repeat of that key.
func (self *testForwardingWorld) mint(wire *sidecarAuthClientWire) (int, any) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.mints = append(self.mints, wire)
	if 0 < self.mintFails {
		self.mintFails -= 1
		return http.StatusServiceUnavailable, map[string]any{"error": "unavailable"}
	}
	identity := self.sidecar.currentIdentity()
	if !wire.ForwardOnly || len(wire.ClientPublicKey) != ed25519.PublicKeySize || wire.SourceClientId == nil ||
		*wire.SourceClientId != identity.ClientId || !wire.AdminRefused || !wire.StrictExp {
		return http.StatusOK, map[string]any{"error": map[string]any{"message": "A forwarding client's mint is refused."}}
	}
	clientId, ok := self.forwardClients[string(wire.ClientPublicKey)]
	if !ok {
		clientId = testConfigId("forwarding client " + hex.EncodeToString(wire.ClientPublicKey))
		self.forwardClients[string(wire.ClientPublicKey)] = clientId
	}
	return http.StatusOK, map[string]any{
		"by_client_jwt": testForwardingJwt(clientId, self.clock.Now().Add(7*24*time.Hour)), "client_id": clientId,
		"admin_refused": true, "strict_exp": true,
	}
}

// The record as the setup keeps it.
func (self *testForwardingWorld) record() *forwardingSetupRecord {
	self.t.Helper()
	setup, _, err := self.sidecar.forwardingSetupFor(self.sidecar.currentIdentity().NetworkId)
	if err != nil {
		self.t.Fatal(err)
	}
	record, err := self.sidecar.loadForwardingSetupRecord(setup)
	if err != nil {
		self.t.Fatal(err)
	}
	return record
}

// The forwarding Delegation rows of the host the net's state holds, ended and superseded ones included.
func (self *testForwardingWorld) forwardingRows() []*bridge.DelegationRow {
	rows := []*bridge.DelegationRow{}
	for _, row := range self.net.log.State().delegations {
		if bytes.Equal(row.GetForwardSidecarId(), self.hostId.Bytes()) {
			rows = append(rows, row)
		}
	}
	return rows
}

// The distinct forwarding clients api answered.
func (self *testForwardingWorld) forwardClientCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.forwardClients)
}

// The network's id.
func (self *testForwardingWorld) networkId() Id {
	return self.sidecar.currentIdentity().NetworkId
}

// A setup hands off after its six steps: the Delegation is live in the log under the component's keys and verifies
// under the sidecar's identity key; gkm holds its reader key and was asked for its DelegationWrap; F is a forward_only
// child of the sidecar's client under the component's client key; the hand-off names all of it and the anchor, holds no
// key of the sidecar's, and its token reaches no log line; and the setup is due no more.
func TestForwardingSetupHandsOffAfterSixSteps(t *testing.T) {
	world := newTestForwardingWorld(t)
	ctx := context.Background()
	identity := world.sidecar.currentIdentity()
	if due, err := world.sidecar.ForwardingSetupDue(identity.NetworkId); err != nil || due != ForwardingSetupNoneLive {
		t.Fatalf("before any setup: %q %v", due, err)
	}
	keys := testForwardingKeys("first")
	handOff, err := world.sidecar.SetUpForwarding(ctx, identity.NetworkId, keys)
	if err != nil {
		t.Fatal(err)
	}
	state := world.net.log.State()
	live := state.ForwardingDelegation(world.hostId)
	readerKeySha256 := sha256.Sum256(keys.GetReaderXwingPublicKey())
	if live == nil || !bytes.Equal(live.GetDelegationId(), handOff.GetPending().GetForwardDelegationId()) || live.GetAt() != handOff.GetDelegationAt().GetVersion() ||
		!bytes.Equal(live.GetPubkey(), keys.GetForwardPublicKey()) || !bytes.Equal(live.GetReaderKeySha256(), readerKeySha256[:]) {
		t.Fatalf("the live Delegation: %v, the hand-off %v", live, handOff)
	}
	if chain, _ := state.chainAt(live.GetAt()); !bytes.Equal(handOff.GetDelegationAt().GetChain(), chain[:]) {
		t.Error("the hand-off's position is not the entry's")
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(handOff.GetSignedDelegation(), signed); err != nil {
		t.Fatal(err)
	}
	if err := bridge.VerifySigned(signed, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_DELEGATION, bridge.SignedKeyAlgEd25519, identity.IdentityPublicKey); err != nil {
		t.Errorf("the hand-off's Delegation does not verify under the identity key: %v", err)
	}
	delegation := &protocol.Delegation{}
	if err := proto.Unmarshal(signed.GetBody(), delegation); err != nil || !bytes.Equal(delegation.GetForward().GetForwardSidecarId(), world.hostId.Bytes()) {
		t.Errorf("the Delegation forwards for %x: %v", delegation.GetForward().GetForwardSidecarId(), err)
	}
	genesisChain := bridge.GenesisChain(world.net.signedGenesis)
	pending := handOff.GetPending()
	if !bytes.Equal(pending.GetNetworkId(), world.net.networkId.Bytes()) || !bytes.Equal(pending.GetGenesisSha256(), genesisChain[:]) ||
		!bytes.Equal(pending.GetSidecarId(), world.hostId.Bytes()) || !bytes.Equal(pending.GetIdentityPublicKey(), identity.IdentityPublicKey) {
		t.Errorf("the hand-off's Pending: %v", pending)
	}
	forwardClientId := world.forwardClients[string(keys.GetClientPublicKey())]
	if !bytes.Equal(handOff.GetForwardClientId(), forwardClientId.Bytes()) || handOff.GetForwardClientJwt() == "" ||
		handOff.GetStrictExpMs() != sidecarJwtExpiration(handOff.GetForwardClientJwt()).UnixMilli() || !bytes.Equal(handOff.GetKeySetId(), keys.GetKeySetId()) ||
		!bytes.Equal(handOff.GetConfigRepoId(), testConfigId("config repo").Bytes()) || len(handOff.GetConfigGroupId()) != len(Id{}) {
		t.Errorf("the hand-off: %v", handOff)
	}
	if len(world.uploads) != 1 || !bytes.Equal(world.uploads[string(live.GetDelegationId())], keys.GetReaderXwingPublicKey()) ||
		len(world.wraps) != 1 || !bytes.Equal(world.wraps[0], live.GetDelegationId()) {
		t.Errorf("gkm: %d uploads, wraps %x", len(world.uploads), world.wraps)
	}
	if len(world.mints) != 1 || !world.mints[0].ForwardOnly || !bytes.Equal(world.mints[0].ClientPublicKey, keys.GetClientPublicKey()) ||
		*world.mints[0].SourceClientId != identity.ClientId {
		t.Errorf("the mints: %+v", world.mints)
	}
	if due, err := world.sidecar.ForwardingSetupDue(identity.NetworkId); err != nil || due != ForwardingSetupNotDue {
		t.Errorf("after the setup: %q %v", due, err)
	}

	// no key of the sidecar's rides the hand-off, and its token reaches no log line
	record, err := loadSidecarIdentity(world.sidecar.coreSecrets)
	if err != nil {
		t.Fatal(err)
	}
	defer record.keys.erase()
	encoded, err := proto.Marshal(handOff)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{record.keys.identitySeed, record.keys.clientKeySeed} {
		if bytes.Contains(encoded, secret) {
			t.Error("the hand-off carries a seed of the sidecar's")
		}
	}
	if strings.Contains(world.logger.all(), handOff.GetForwardClientJwt()) {
		t.Error("F's token reached a log line")
	}
	if stored := world.record(); stored.Step != 6 || bytes.Contains(world.storeBytes(t), []byte(handOff.GetForwardClientJwt())) {
		t.Errorf("the record at step %d, or holding F's token", stored.Step)
	}
}

// Every byte the setup's store holds.
func (self *testForwardingWorld) storeBytes(t *testing.T) []byte {
	t.Helper()
	self.store.shared.stateLock.Lock()
	defer self.store.shared.stateLock.Unlock()
	all := []byte{}
	for _, value := range self.store.shared.files {
		all = append(all, value...)
	}
	return all
}

// A kill after each step resumes after the steps done: a lost post's same bytes post again, gkm's and api's refusals
// are tried again, and the setup ends with one Delegation and one F.
func TestForwardingSetupResumesAfterEachStep(t *testing.T) {
	world := newTestForwardingWorld(t)
	ctx := context.Background()
	keys := testForwardingKeys("resumed")
	resume := func(wantStep int) {
		t.Helper()
		if _, err := world.sidecar.SetUpForwarding(ctx, world.networkId(), keys); !errors.Is(err, ErrForwardingSetupIncomplete) {
			t.Fatalf("a kill after step %d: %v", wantStep, err)
		}
		if step := world.record().Step; step != wantStep {
			t.Fatalf("the record at step %d, want %d", step, wantStep)
		}
	}
	world.api.answers = []string{"dropped"}
	resume(1)
	world.uploadFails = 1
	resume(2)
	world.wrapFails = 1
	resume(3)
	world.mintFails = 1
	resume(4)
	handOff, err := world.sidecar.SetUpForwarding(ctx, world.networkId(), keys)
	if err != nil {
		t.Fatal(err)
	}
	// a repeat after the hand-off, its answer lost, hands off the same F again
	again, err := world.sidecar.SetUpForwarding(ctx, world.networkId(), keys)
	if err != nil || !bytes.Equal(again.GetForwardClientId(), handOff.GetForwardClientId()) || !bytes.Equal(again.GetSignedDelegation(), handOff.GetSignedDelegation()) {
		t.Fatalf("a repeat: %v %v", again, err)
	}
	if rows := world.forwardingRows(); len(rows) != 1 || rows[0].GetSupersededAt() != 0 || rows[0].GetEndedAt() != 0 {
		t.Fatalf("%d forwarding Delegations", len(rows))
	}
	if world.forwardClientCount() != 1 {
		t.Errorf("%d forwarding clients", world.forwardClientCount())
	}
	delegationPosts := 0
	for _, signedType := range world.api.postedTypes(t) {
		if signedType == bridge.SignedType_SIGNED_DELEGATION {
			delegationPosts += 1
		}
	}
	if delegationPosts != 2 {
		t.Errorf("%d posts of the Delegation, want the lost one and its same bytes again", delegationPosts)
	}
}

// A setup is due at a new client generation, an enrollment's, a re-enrollment's or a pairing's, and 90 days after the
// last, and no sooner; a new key set's setup supersedes the one before at its position and is due no more.
func TestForwardingSetupIsDueAtANewGenerationAndAfterNinetyDays(t *testing.T) {
	world := newTestForwardingWorld(t)
	ctx := context.Background()
	first, err := world.sidecar.SetUpForwarding(ctx, world.networkId(), testForwardingKeys("first"))
	if err != nil {
		t.Fatal(err)
	}
	rotation := DefaultForwardingSetupSettings().RotationInterval
	world.clock.advance(rotation - time.Millisecond)
	if due, _ := world.sidecar.ForwardingSetupDue(world.networkId()); due != ForwardingSetupNotDue {
		t.Errorf("just before 90 days: %q", due)
	}
	world.clock.advance(time.Millisecond)
	if due, _ := world.sidecar.ForwardingSetupDue(world.networkId()); due != ForwardingSetupNinetyDays {
		t.Errorf("at 90 days: %q", due)
	}
	// the log's time moves with the device's, so the next statement's not_after lies within its 7 days
	world.net.timeMs = world.clock.Now().UnixMilli()

	// a re-enrollment or a pairing: the next client generation
	nextClientId := testConfigId("the host's next client")
	func() {
		world.sidecar.stateLock.Lock()
		defer world.sidecar.stateLock.Unlock()
		world.sidecar.identity.Generation += 1
		world.sidecar.identity.ClientId = nextClientId
	}()
	if due, _ := world.sidecar.ForwardingSetupDue(world.networkId()); due != ForwardingSetupNewClientGeneration {
		t.Fatalf("at a new client generation: %q", due)
	}
	second, err := world.sidecar.SetUpForwarding(ctx, world.networkId(), testForwardingKeys("second"))
	if err != nil {
		t.Fatal(err)
	}
	state := world.net.log.State()
	old := state.Delegation(first.GetPending().GetForwardDelegationId())
	live := state.ForwardingDelegation(world.hostId)
	if old.GetSupersededAt() != second.GetDelegationAt().GetVersion() || !bytes.Equal(live.GetDelegationId(), second.GetPending().GetForwardDelegationId()) {
		t.Fatalf("the earlier Delegation superseded at %d, the live one %x", old.GetSupersededAt(), live.GetDelegationId())
	}
	if last := world.mints[len(world.mints)-1]; *last.SourceClientId != nextClientId {
		t.Error("F was minted under the earlier client")
	}
	if due, _ := world.sidecar.ForwardingSetupDue(world.networkId()); due != ForwardingSetupNotDue {
		t.Errorf("after the new generation's setup: %q", due)
	}
}

// Another signer's DelegationRevoke of the sidecar's forwarding Delegation holds the setup until the person confirms,
// with nothing signed meanwhile; the sidecar's own revocation does not hold it.
func TestForwardingSetupWaitsForConfirmAfterAForeignRevocation(t *testing.T) {
	world := newTestForwardingWorld(t)
	ctx := context.Background()
	first, err := world.sidecar.SetUpForwarding(ctx, world.networkId(), testForwardingKeys("first"))
	if err != nil {
		t.Fatal(err)
	}
	world.net.mustPost(world.net.owner, bridge.SignedType_SIGNED_DELEGATION_REVOKE, &protocol.DelegationRevoke{
		Header: world.net.header(), DelegationId: first.GetPending().GetForwardDelegationId(),
	})
	if due, _ := world.sidecar.ForwardingSetupDue(world.networkId()); due != ForwardingSetupForeignRevocation {
		t.Fatalf("after an admin's revocation: %q", due)
	}
	posts := world.api.postCount()
	if _, err := world.sidecar.SetUpForwarding(ctx, world.networkId(), testForwardingKeys("second")); !errors.Is(err, ErrForwardingSetupNeedsConfirm) {
		t.Fatalf("an unconfirmed setup: %v", err)
	}
	if witness, err := world.sidecar.ForwardingWitness(world.networkId()); err != nil || witness.SetupDue != ForwardingSetupForeignRevocation {
		t.Errorf("the witness hint: %+v %v", witness, err)
	}
	if world.api.postCount() != posts {
		t.Fatal("an unconfirmed setup signed")
	}
	if err := world.sidecar.ConfirmForwardingSetup(world.networkId()); err != nil {
		t.Fatal(err)
	}
	if due, _ := world.sidecar.ForwardingSetupDue(world.networkId()); due != ForwardingSetupNoneLive {
		t.Fatalf("after the person's confirmation: %q", due)
	}
	second, err := world.sidecar.SetUpForwarding(ctx, world.networkId(), testForwardingKeys("second"))
	if err != nil {
		t.Fatal(err)
	}

	// the sidecar's own revocation of its forwarding Delegation holds nothing
	act, err := world.sidecar.newAct(SidecarActConfirmed)
	if err != nil {
		t.Fatal(err)
	}
	if err := act.Add(bridge.SignedType_SIGNED_DELEGATION_REVOKE, &protocol.DelegationRevoke{DelegationId: second.GetPending().GetForwardDelegationId()}); err != nil {
		t.Fatal(err)
	}
	if _, err := act.Run(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if due, _ := world.sidecar.ForwardingSetupDue(world.networkId()); due != ForwardingSetupNoneLive {
		t.Fatalf("after its own revocation: %q", due)
	}
	if _, err := world.sidecar.SetUpForwarding(ctx, world.networkId(), testForwardingKeys("third")); err != nil {
		t.Fatalf("a setup after its own revocation: %v", err)
	}
}

// Keys a setup cannot take, a second set under a recorded key_set_id, a sidecar with no setup installed and another
// network are refused, with nothing signed.
func TestForwardingSetupRefusesKeysItCannotTake(t *testing.T) {
	world := newTestForwardingWorld(t)
	ctx := context.Background()
	for name, edit := range map[string]func(keys *bridge.ForwardingKeys){
		"a short key set id":     func(keys *bridge.ForwardingKeys) { keys.KeySetId = keys.KeySetId[:8] },
		"a short forwarding key": func(keys *bridge.ForwardingKeys) { keys.ForwardPublicKey = keys.ForwardPublicKey[:31] },
		"a short reader key":     func(keys *bridge.ForwardingKeys) { keys.ReaderXwingPublicKey = keys.ReaderXwingPublicKey[:1215] },
		"no client key":          func(keys *bridge.ForwardingKeys) { keys.ClientPublicKey = nil },
		"a host client, unpaired": func(keys *bridge.ForwardingKeys) {
			keys.HostClientId, keys.HostClientPublicKey = NewId().Bytes(), keys.ClientPublicKey
		},
		"a host client key with no one": func(keys *bridge.ForwardingKeys) { keys.HostClientPublicKey = keys.ClientPublicKey },
	} {
		keys := testForwardingKeys(name)
		edit(keys)
		if _, err := world.sidecar.SetUpForwarding(ctx, world.networkId(), keys); !errors.Is(err, ErrForwardingSetupRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if world.api.postCount() != 0 {
		t.Fatal("a refused key set signed")
	}
	keys := testForwardingKeys("first")
	if _, err := world.sidecar.SetUpForwarding(ctx, world.networkId(), keys); err != nil {
		t.Fatal(err)
	}
	other := testForwardingKeys("other")
	other.KeySetId = keys.GetKeySetId()
	if _, err := world.sidecar.SetUpForwarding(ctx, world.networkId(), other); !errors.Is(err, ErrForwardingSetupRefused) {
		t.Errorf("another set under a recorded key_set_id: %v", err)
	}
	if _, err := world.sidecar.SetUpForwarding(ctx, testConfigId("another network"), keys); !errors.Is(err, ErrForwardingSetupUnavailable) {
		t.Errorf("another network: %v", err)
	}
	bare := newTestBridgeFileSidecar(t, world.net.networkId, testConfigId("a sidecar with no setup"))
	if _, err := bare.SetUpForwarding(ctx, world.net.networkId, keys); !errors.Is(err, ErrForwardingSetupUnavailable) {
		t.Errorf("no setup installed: %v", err)
	}
}

// §6.4's state as a test holds it, with the pin its newest witness compared.
type testForwardingHeadCheck struct {
	pin *bridge.AuthPin
}

func (self *testForwardingHeadCheck) WitnessedAt() time.Time {
	return time.UnixMilli(testConfigStartMs)
}
func (self *testForwardingHeadCheck) Unverified() [][]byte          { return nil }
func (self *testForwardingHeadCheck) WitnessedPin() *bridge.AuthPin { return self.pin }

// A config whose full reading found a fork.
type testForwardingForkedConfig struct {
	testForwardingConfig
}

func (self testForwardingForkedConfig) Fork() *ConfigForkError {
	return &ConfigForkError{N: 1}
}

// The witness hint: the verified pin before any witness, §6.4's witnessed pin once one stands, and a fork the config
// reports.
func TestForwardingWitnessCarriesThePinAndAFork(t *testing.T) {
	world := newTestForwardingWorld(t)
	witness, err := world.sidecar.ForwardingWitness(world.networkId())
	if err != nil || !proto.Equal(witness.Pin, world.net.log.State().Pin()) || witness.Witnessed || witness.Fork || witness.SetupDue != ForwardingSetupNoneLive {
		t.Fatalf("before a witness: %+v %v", witness, err)
	}
	witnessed := &bridge.AuthPin{Version: 1, Chain: bytes.Repeat([]byte{0x77}, sha256.Size)}
	t.Cleanup(world.sidecar.InstallHeadCheckStatus(&testForwardingHeadCheck{pin: witnessed}))
	if witness, err := world.sidecar.ForwardingWitness(world.networkId()); err != nil || !witness.Witnessed || !proto.Equal(witness.Pin, witnessed) {
		t.Fatalf("with a witness: %+v %v", witness, err)
	}
	t.Cleanup(world.sidecar.InstallForwardingSetup(&ForwardingSetupSources{Config: testForwardingForkedConfig{testForwardingConfig: testForwardingConfig{testBridgeFileConfig: testBridgeFileConfig{net: world.net}}}, Store: world.store}))
	if witness, err := world.sidecar.ForwardingWitness(world.networkId()); err != nil || !witness.Fork {
		t.Fatalf("a fork: %+v %v", witness, err)
	}
}
