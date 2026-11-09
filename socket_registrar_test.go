//go:build !sidecar_http

// §9.5's registrar (socket_registrar.go): the state stepped by hand with explicit times, for pages of 1,024 under one
// set_version, the heartbeat's jitter, eager reports one page at a time at most every 2 s, a stale set_version jumped
// past, a hint asking for one round, revoked and other refusals ending an entry, both paths through a rotation's
// 10 min overlap, retry_after_ms and backoff, names outside tls/, smtp/ and ur/ never in the clear, claims under the
// identity key, and admission's state; then the loop on a fake clock and a fake service, one call at a time.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Where every state test starts its clock: a fixed date, so a trace repeats.
var testSocketNow = time.Date(2026, time.March, 4, 5, 6, 7, 0, time.UTC)

// How long a test waits for what it expects before it fails, so a broken loop fails with a message instead of
// hanging. No outcome depends on it.
const testSocketAwaitTimeout = 30 * time.Second

// One value, failing the test after testSocketAwaitTimeout.
func testSocketAwait[T any](t testing.TB, values <-chan T, what string) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(testSocketAwaitTimeout):
		t.Fatalf("no %s", what)
		var zero T
		return zero
	}
}

// A synthetic id named by label.
func testSocketId(label string) Id {
	sum := sha256.Sum256([]byte("socket test " + label))
	var id Id
	copy(id[:], sum[:])
	return id
}

// The network every test registers in.
var testRegistrarNetworkId = testSocketId("network")

// A 32-byte K_sock named by label.
func testRegistrarKey(label string) []byte {
	sum := sha256.Sum256([]byte("socket test key " + label))
	return sum[:]
}

// A ring of the test network's: the current key alone, or with a previous one rotated at rotatedAtMs.
func newTestSocketRing(t testing.TB, current string, previous string, rotatedAtMs int64) *SocketKeyRing {
	t.Helper()
	file := &protocol.SocketKeyFile{CurrentKey: testRegistrarKey(current)}
	if previous != "" {
		file.PreviousKey = testRegistrarKey(previous)
		file.RotatedAtMs = rotatedAtMs
	}
	ring, err := NewSocketKeyRing(testRegistrarNetworkId, file, DefaultSocketKeyRingSettings())
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

// Stands in for Sidecar.Sign: Ed25519 by a synthetic identity key, counting what it signs, refusing while refuse is
// set as a Locked sidecar would.
type testSocketSigner struct {
	privateKey ed25519.PrivateKey
	sidecarId  Id

	stateLock sync.Mutex
	signCount int
	refuse    bool
}

func newTestSocketSigner(label string) *testSocketSigner {
	seed := sha256.Sum256([]byte("socket test identity " + label))
	return &testSocketSigner{
		privateKey: ed25519.NewKeyFromSeed(seed[:]),
		sidecarId:  testSocketId("sidecar " + label),
	}
}

// See socketSignFunction.
func (self *testSocketSigner) sign(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.refuse {
		return nil, fmt.Errorf("sign: %w", ErrSidecarStoreLocked)
	}
	self.signCount += 1
	return &bridge.Signed{
		Body:      bytes.Clone(body),
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.privateKey, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

func (self *testSocketSigner) publicKey() ed25519.PublicKey {
	return self.privateKey.Public().(ed25519.PublicKey)
}

func (self *testSocketSigner) count() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.signCount
}

func (self *testSocketSigner) setRefuse(refuse bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refuse = refuse
}

// §9.5's defaults for a Listen of name, as SOCK-M5-11's settings fill them.
func testSocketArgs(name string) *socketRegistrationArgs {
	appMode := ""
	if strings.HasPrefix(name, "tls/") {
		appMode = "http"
	}
	return &socketRegistrationArgs{
		Name:       name,
		ListenId:   testSocketId("listen " + name),
		Protocol:   "tcp",
		AppMode:    appMode,
		Weight:     100,
		MaxStreams: 256,
	}
}

// A state attached to a generation, whose jitter draws random each time.
func newTestSocketState(settings *SidecarSocketSettings, random float64) *socketRegistrarState {
	if settings == nil {
		settings = DefaultSidecarSocketSettings()
	}
	state := newSocketRegistrarState(settings, func() float64 { return random })
	state.attach()
	return state
}

// Adds a Listen of args to state as the registrar would, its rows made under ring at now.
func addTestSocketEntry(t testing.TB, state *socketRegistrarState, signer *testSocketSigner, ring *SocketKeyRing, args *socketRegistrationArgs, now time.Time) *socketRegistrarEntry {
	t.Helper()
	entry, err := newSocketRegistrarEntry(args)
	if err != nil {
		t.Fatal(err)
	}
	entry.owner = &socketRegistration{listenId: entry.listenId, verdictDone: make(chan struct{})}
	rows, err := makeSocketRegistrarRows(testRegistrarNetworkId, signer.sign, entry, ring, now.UnixMilli(), nil, state.identityEpoch)
	if err != nil {
		t.Fatal(err)
	}
	entry.setRows(rows, ring, state.ringEpoch, state.identityEpoch)
	if err := state.addEntry(entry); err != nil {
		t.Fatal(err)
	}
	return entry
}

// The answer of a service that refuses nothing: status for every entry of call, with admission's fields.
func testSocketAnswer(call *socketRegistrarCall, status SocketRegistrationStatus) *SocketRegistrationsResult {
	statuses := make([]SocketRegistrationStatus, len(call.args.Registrations))
	for i := range statuses {
		statuses[i] = status
	}
	return &SocketRegistrationsResult{
		Statuses:         statuses,
		SetVersion:       call.args.SetVersion,
		ServerTimeMillis: uint64(testSocketNow.UnixMilli()),
		TicketKeys:       []*SocketTicketKey{{KeyId: "key-1", PublicKey: make([]byte, ed25519.PublicKeySize), ExpireTimeMillis: 1 << 50}},
	}
}

// Runs the round due at now to its end, every page answered ok, and returns its calls.
func runTestSocketRound(t testing.TB, state *socketRegistrarState, now time.Time) []*socketRegistrarCall {
	t.Helper()
	calls := []*socketRegistrarCall{}
	for {
		call, _ := state.next(now)
		if call == nil || call.round == nil {
			t.Fatalf("page %d: no round's call", len(calls))
		}
		calls = append(calls, call)
		state.finish(call, testSocketAnswer(call, SocketRegistrationStatusOk), nil, now, now)
		if state.round == nil {
			return calls
		}
		if 16 < len(calls) {
			t.Fatal("a round that does not end")
		}
	}
}

// A name of a set of count blinded names.
func testSocketSetName(index int) string {
	return fmt.Sprintf("app/n%04d", index)
}

// A set of 3,000 blinded names goes as three pages of at most 1,024 under one set_version, sorted, contiguous and
// covering every key once, with nothing left over (§22.5's 3,000-name set).
func TestSocketRegistrarSendsTheSetAsPagesOf1024(t *testing.T) {
	state := newTestSocketState(nil, 0.5)
	signer := newTestSocketSigner("a")
	ring := newTestSocketRing(t, "k1", "", 0)
	tokenPaths := map[string]bool{}
	for i := 0; i < 3000; i += 1 {
		entry := addTestSocketEntry(t, state, signer, ring, testSocketArgs(testSocketSetName(i)), testSocketNow)
		tokenPaths[string(entry.rows[0].tokenPath)] = true
	}

	calls := runTestSocketRound(t, state, testSocketNow)
	if len(calls) != 3 {
		t.Fatalf("%d pages", len(calls))
	}
	seen := map[string]bool{}
	for index, call := range calls {
		args := call.args
		if wantCount := []int{1024, 1024, 952}[index]; len(args.Registrations) != wantCount {
			t.Errorf("page %d: %d entries", index, len(args.Registrations))
		}
		if args.SetVersion != uint64(testSocketNow.UnixMilli()) {
			t.Errorf("page %d: set_version %d", index, args.SetVersion)
		}
		if (index == 0) != (args.KeyStart == nil) {
			t.Errorf("page %d: key_start %x", index, args.KeyStart)
		}
		if index+1 < len(calls) && !bytes.Equal(args.KeyEnd, calls[index+1].args.KeyStart) {
			t.Errorf("page %d: does not meet the next", index)
		}
		if (index == len(calls)-1) != (args.KeyEnd == nil) {
			t.Errorf("page %d: key_end %x", index, args.KeyEnd)
		}
		for i, registration := range args.Registrations {
			nameKey := registration.NameKey()
			if 0 < i && bytes.Compare(args.Registrations[i-1].NameKey(), nameKey) >= 0 {
				t.Fatalf("page %d: not sorted at %d", index, i)
			}
			if bytes.Compare(nameKey, args.KeyStart) < 0 || args.KeyEnd != nil && bytes.Compare(nameKey, args.KeyEnd) >= 0 {
				t.Fatalf("page %d: an entry outside the page's range", index)
			}
			if registration.Name != "" || len(registration.SealedName) != socketSealByteCount {
				t.Fatalf("page %d: a blinded name went %q with a %d B seal", index, registration.Name, len(registration.SealedName))
			}
			seen[string(nameKey)] = true
		}
	}
	if len(seen) != 3000 || !func() bool {
		for tokenPath := range tokenPaths {
			if !seen[tokenPath] {
				return false
			}
		}
		return true
	}() {
		t.Errorf("the pages carried %d of the set's 3,000", len(seen))
	}
	if want := testSocketNow.Add(15 * time.Second); !state.heartbeatAt.Equal(want) {
		t.Errorf("heartbeat at %v, want %v", state.heartbeatAt, want)
	}
}

// Heartbeats come 15 s ± 20% apart, drawn uniformly, each under a newer set_version (§9.5).
func TestSocketRegistrarHeartbeatIsJitteredWithin20Percent(t *testing.T) {
	signer := newTestSocketSigner("a")
	for _, c := range []struct {
		random float64
		want   time.Duration
	}{
		{random: 0, want: 12 * time.Second},
		{random: 0.5, want: 15 * time.Second},
		{random: 0.75, want: 16500 * time.Millisecond},
	} {
		state := newTestSocketState(nil, c.random)
		addTestSocketEntry(t, state, signer, nil, testSocketArgs("tls/443/blog"), testSocketNow)
		runTestSocketRound(t, state, testSocketNow)
		if got := state.heartbeatAt.Sub(testSocketNow); got != c.want {
			t.Errorf("draw %v: %v, want %v", c.random, got, c.want)
		}
	}

	draws := rand.New(rand.NewPCG(1, 2))
	state := newSocketRegistrarState(DefaultSidecarSocketSettings(), draws.Float64)
	state.attach()
	addTestSocketEntry(t, state, signer, nil, testSocketArgs("tls/443/blog"), testSocketNow)
	now := testSocketNow
	lastSetVersion := uint64(0)
	for i := 0; i < 500; i += 1 {
		calls := runTestSocketRound(t, state, now)
		if calls[0].args.SetVersion <= lastSetVersion {
			t.Fatalf("round %d: set_version %d after %d", i, calls[0].args.SetVersion, lastSetVersion)
		}
		lastSetVersion = calls[0].args.SetVersion
		interval := state.heartbeatAt.Sub(now)
		if interval < 12*time.Second || 18*time.Second < interval {
			t.Fatalf("round %d: a heartbeat %v later", i, interval)
		}
		if call, wakeAt := state.next(now); call != nil || !wakeAt.Equal(state.heartbeatAt) {
			t.Fatalf("round %d: before the heartbeat, a call %v or a wake at %v", i, call != nil, wakeAt)
		}
		now = state.heartbeatAt
	}
}

// Between rounds an entry whose in-flight count moved by max(8, 25% of max_streams) sends its own page alone, the one
// a round would cut around it, at most one such page every 2 s (§9.5).
func TestSocketRegistrarEagerReportIsItsOwnPageAtMostEvery2s(t *testing.T) {
	state := newTestSocketState(nil, 0.5)
	signer := newTestSocketSigner("a")
	ring := newTestSocketRing(t, "k1", "", 0)
	for i := 0; i < 3000; i += 1 {
		addTestSocketEntry(t, state, signer, ring, testSocketArgs(testSocketSetName(i)), testSocketNow)
	}
	round := runTestSocketRound(t, state, testSocketNow)
	rows := state.sendRows(testSocketNow.UnixMilli())
	entry := rows[1500].entry

	now := testSocketNow.Add(1 * time.Second)
	if state.setInflight(entry.listenId, 63, now) {
		t.Errorf("a move of 63 on a 256-stream listener asked for an eager report")
	}
	if call, _ := state.next(now); call != nil {
		t.Fatalf("a call for a move of 63")
	}
	if !state.setInflight(entry.listenId, 64, now) {
		t.Fatalf("a move of 64 asked for nothing")
	}
	call, _ := state.next(now)
	if call == nil || call.round != nil {
		t.Fatalf("no eager page")
	}
	if len(call.args.Registrations) != 1024 || !bytes.Equal(call.args.KeyStart, round[1].args.KeyStart) ||
		!bytes.Equal(call.args.KeyEnd, round[1].args.KeyEnd) {
		t.Errorf("an eager page of %d entries that is not the second page", len(call.args.Registrations))
	}
	if call.args.SetVersion <= round[0].args.SetVersion {
		t.Errorf("an eager page under set_version %d after %d", call.args.SetVersion, round[0].args.SetVersion)
	}
	index := slices.IndexFunc(call.args.Registrations, func(registration *SocketRegistration) bool {
		return bytes.Equal(registration.NameToken, entry.rows[0].tokenPath)
	})
	if index < 0 || call.args.Registrations[index].Inflight != 64 {
		t.Fatalf("the page does not carry the entry's count")
	}
	state.finish(call, testSocketAnswer(call, SocketRegistrationStatusOk), nil, now, now)
	if entry.reportedInflight != 64 || !entry.eagerSince.IsZero() {
		t.Errorf("reported %d, eager since %v", entry.reportedInflight, entry.eagerSince)
	}

	// a second move a second later waits until 2 s after the first page
	later := now.Add(1 * time.Second)
	if !state.setInflight(entry.listenId, 128, later) {
		t.Fatalf("a second move asked for nothing")
	}
	if call, wakeAt := state.next(later); call != nil || !wakeAt.Equal(now.Add(2*time.Second)) {
		t.Fatalf("within 2 s: a call %v, a wake at %v", call != nil, wakeAt)
	}
	call, _ = state.next(now.Add(2 * time.Second))
	if call == nil || call.round != nil || len(call.args.Registrations) != 1024 {
		t.Fatalf("no eager page 2 s after the first")
	}
	state.finish(call, testSocketAnswer(call, SocketRegistrationStatusOk), nil, now.Add(2*time.Second), now.Add(2*time.Second))

	// a count that moves back before its page goes asks for nothing
	other := rows[10].entry
	state.setInflight(other.listenId, 100, later)
	state.setInflight(other.listenId, 1, later)
	if call, _ := state.next(now.Add(10 * time.Second)); call != nil {
		t.Errorf("an eager page for a count back where the service saw it")
	}
}

// The eager amount is max(8, 25% of max_streams): a small listener reports a move of 8, never one of 7.
func TestSocketRegistrarEagerAmountHasAFloorOf8(t *testing.T) {
	state := newTestSocketState(nil, 0.5)
	signer := newTestSocketSigner("a")
	args := testSocketArgs("tls/443/blog")
	args.MaxStreams = 10
	entry := addTestSocketEntry(t, state, signer, nil, args, testSocketNow)
	runTestSocketRound(t, state, testSocketNow)
	if state.setInflight(entry.listenId, 7, testSocketNow) {
		t.Errorf("a move of 7 asked for a report")
	}
	if !state.setInflight(entry.listenId, 8, testSocketNow) {
		t.Errorf("a move of 8 asked for nothing")
	}
	// before the service has answered for an entry, its round carries its count, and nothing is eager
	fresh := addTestSocketEntry(t, state, signer, nil, testSocketArgs("tls/443/api"), testSocketNow)
	if state.setInflight(fresh.listenId, 200, testSocketNow) {
		t.Errorf("an entry the service has not answered for asked for an eager report")
	}
}

// A restarted daemon whose set_version is older than the stored one jumps past the value the refusal returns and is
// taken at once; a second stale refusal in a row waits a backoff (plan reading 11).
func TestSocketRegistrarRecoversFromAStaleSetVersion(t *testing.T) {
	state := newTestSocketState(nil, 0.5)
	signer := newTestSocketSigner("a")
	entry := addTestSocketEntry(t, state, signer, nil, testSocketArgs("tls/443/blog"), testSocketNow)
	call, _ := state.next(testSocketNow)
	if call == nil || call.args.SetVersion != uint64(testSocketNow.UnixMilli()) {
		t.Fatalf("set_version is not millisecond time")
	}
	stored := uint64(testSocketNow.Add(1 * time.Hour).UnixMilli())
	state.finish(call, &SocketRegistrationsResult{SetVersion: stored, Error: &SocketError{Code: SocketErrorCodeStale}}, nil, testSocketNow, testSocketNow)
	again, _ := state.next(testSocketNow)
	if again == nil || again.args.SetVersion != stored+1 {
		t.Fatalf("after a stale refusal: %v", again != nil)
	}
	state.finish(again, &SocketRegistrationsResult{SetVersion: stored + 5, Error: &SocketError{Code: SocketErrorCodeStale}}, nil, testSocketNow, testSocketNow)
	if call, wakeAt := state.next(testSocketNow); call != nil || !wakeAt.Equal(testSocketNow.Add(1*time.Second)) {
		t.Fatalf("a second stale refusal: a call %v, a wake at %v", call != nil, wakeAt)
	}
	third, _ := state.next(testSocketNow.Add(1 * time.Second))
	if third == nil || third.args.SetVersion != stored+6 {
		t.Fatalf("after the backoff")
	}
	effects := state.finish(third, testSocketAnswer(third, SocketRegistrationStatusOk), nil, testSocketNow, testSocketNow)
	if len(effects) != 1 || !effects[0].first || effects[0].owner != entry.owner || effects[0].status != SocketRegistrationStatusOk {
		t.Errorf("effects %+v", effects)
	}
	if state.staleCount != 0 {
		t.Errorf("stale count %d after an answer", state.staleCount)
	}
}

// A hint asks for one round, and the round's answer is all that changes anything; with nothing registered and
// nothing held it asks for none (§9.5).
func TestSocketRegistrarHintAsksForOneRound(t *testing.T) {
	state := newTestSocketState(nil, 0.5)
	signer := newTestSocketSigner("a")
	if state.hint(nil); state.roundPending {
		t.Errorf("a hint with nothing registered asked for a round")
	}
	entry := addTestSocketEntry(t, state, signer, nil, testSocketArgs("tls/443/blog"), testSocketNow)
	runTestSocketRound(t, state, testSocketNow)
	now := testSocketNow.Add(1 * time.Second)
	state.hint(nil)
	state.hint(nil)
	calls := runTestSocketRound(t, state, now)
	if len(calls) != 1 || len(calls[0].args.Registrations) != 1 {
		t.Fatalf("%d calls", len(calls))
	}
	if call, wakeAt := state.next(now); call != nil || !wakeAt.Equal(now.Add(15*time.Second)) {
		t.Errorf("after the hint's round: a call %v, a wake at %v", call != nil, wakeAt)
	}
	// a forced drain is handed to its entry, once, and a revoked hint closes nothing by itself
	state.hint(&entry.listenId)
	unknown := testSocketId("unknown listen")
	state.hint(&unknown)
	effects := state.takeEffects()
	if len(effects) != 1 || !effects[0].drain || effects[0].owner != entry.owner {
		t.Errorf("drain effects %+v", effects)
	}
	if len(state.takeEffects()) != 0 || state.entries[entry.listenId] != entry {
		t.Errorf("a hint changed the set")
	}
}

// revoked ends an entry the service had taken, which leaves the set; a first refusal answers the Listen; an unknown
// status holds no lease either (§9.5).
func TestSocketRegistrarRevokedEndsTheEntry(t *testing.T) {
	state := newTestSocketState(nil, 0.5)
	signer := newTestSocketSigner("a")
	kept := addTestSocketEntry(t, state, signer, nil, testSocketArgs("tls/443/blog"), testSocketNow)
	revoked := addTestSocketEntry(t, state, signer, nil, testSocketArgs("tls/443/api"), testSocketNow)
	odd := addTestSocketEntry(t, state, signer, nil, testSocketArgs("tls/443/www"), testSocketNow)
	call, _ := state.next(testSocketNow)
	effects := state.finish(call, testSocketAnswer(call, SocketRegistrationStatusOk), nil, testSocketNow, testSocketNow)
	if len(effects) != 3 {
		t.Fatalf("%d first verdicts", len(effects))
	}

	now := testSocketNow.Add(15 * time.Second)
	call, _ = state.next(now)
	answer := testSocketAnswer(call, SocketRegistrationStatusOk)
	for index, registration := range call.args.Registrations {
		switch registration.Name {
		case revoked.name:
			answer.Statuses[index] = SocketRegistrationStatusRevoked
		case odd.name:
			answer.Statuses[index] = SocketRegistrationStatus("not-a-status")
		}
	}
	effects = state.finish(call, answer, nil, now, now)
	ended := map[*socketRegistration]SocketRegistrationStatus{}
	for _, effect := range effects {
		if effect.first || effect.drain {
			t.Errorf("effect %+v", effect)
		}
		ended[effect.owner] = effect.status
	}
	if len(ended) != 2 || ended[revoked.owner] != SocketRegistrationStatusRevoked || ended[odd.owner] != "not-a-status" {
		t.Errorf("ended %v", ended)
	}
	if len(state.entries) != 1 || state.entries[kept.listenId] != kept {
		t.Fatalf("%d entries left", len(state.entries))
	}
	// the name is free again, and the next round carries only what is left
	addTestSocketEntry(t, state, signer, nil, testSocketArgs("tls/443/api"), now)
	next, _ := state.next(now)
	names := []string{}
	for _, registration := range next.args.Registrations {
		names = append(names, registration.Name)
	}
	if !slices.Equal(names, []string{"tls/443/api", "tls/443/blog"}) {
		t.Errorf("next round %v", names)
	}

	// a first verdict that refuses answers the Listen and takes the entry out
	state = newTestSocketState(nil, 0.5)
	denied := addTestSocketEntry(t, state, signer, nil, testSocketArgs("tls/443/blog"), testSocketNow)
	call, _ = state.next(testSocketNow)
	effects = state.finish(call, testSocketAnswer(call, SocketRegistrationStatusDenied), nil, testSocketNow, testSocketNow)
	if len(effects) != 1 || !effects[0].first || effects[0].status != SocketRegistrationStatusDenied || effects[0].owner != denied.owner {
		t.Errorf("effects %+v", effects)
	}
	if len(state.entries) != 0 {
		t.Errorf("a denied entry stayed")
	}
}

// Through a rotation's overlap a blinded name registers both paths, each sealed and claimed under its own key, and the
// overlap's end by this device's clock asks for a round with the newest alone (§9.4, plan-SOCK-ksock-rotation).
func TestSocketRegistrarRegistersBothPathsThroughARotation(t *testing.T) {
	settings := DefaultSidecarSocketSettings()
	settings.HeartbeatInterval = 1 * time.Hour
	state := newTestSocketState(settings, 0.5)
	signer := newTestSocketSigner("a")
	rotatedAt := testSocketNow.Add(-1 * time.Minute)
	ring := newTestSocketRing(t, "k2", "k1", rotatedAt.UnixMilli())
	state.setRing(ring)
	entry := addTestSocketEntry(t, state, signer, ring, testSocketArgs("db/primary"), testSocketNow)
	state.rowsStale = false

	calls := runTestSocketRound(t, state, testSocketNow)
	currentPath, _ := ring.Current().TokenPath("db/primary")
	previousPath, _ := ring.Previous().TokenPath("db/primary")
	registrations := calls[0].args.Registrations
	if len(registrations) != 2 {
		t.Fatalf("%d registrations through the overlap", len(registrations))
	}
	byPath := map[string]*SocketRegistration{}
	for _, registration := range registrations {
		byPath[string(registration.NameToken)] = registration
	}
	for _, c := range []struct {
		path []byte
		keys *SocketKeys
	}{
		{path: currentPath, keys: ring.Current()},
		{path: previousPath, keys: ring.Previous()},
	} {
		registration := byPath[string(c.path)]
		if registration == nil {
			t.Fatalf("a path missing")
		}
		if name, ok := c.keys.Open(c.path, registration.SealedName); !ok || name != "db/primary" {
			t.Errorf("a seal that does not open under its own key")
		}
		checkTestSocketClaim(t, signer, registration, "", c.path)
	}

	overlapEnd := rotatedAt.Add(10 * time.Minute)
	if call, wakeAt := state.next(testSocketNow); call != nil || !wakeAt.Equal(overlapEnd) {
		t.Fatalf("a call %v, a wake at %v, want the overlap's end", call != nil, wakeAt)
	}
	if call, _ := state.next(overlapEnd.Add(-1 * time.Millisecond)); call != nil {
		t.Fatalf("a round before the overlap ended")
	}
	calls = runTestSocketRound(t, state, overlapEnd)
	if len(calls[0].args.Registrations) != 1 || !bytes.Equal(calls[0].args.Registrations[0].NameToken, currentPath) {
		t.Errorf("after the overlap: %d registrations", len(calls[0].args.Registrations))
	}

	// a refused previous path stops alone, and the entry stays
	state = newTestSocketState(settings, 0.5)
	state.setRing(ring)
	entry = addTestSocketEntry(t, state, signer, ring, testSocketArgs("db/primary"), testSocketNow)
	call, _ := state.next(testSocketNow)
	answer := testSocketAnswer(call, SocketRegistrationStatusOk)
	for index, registration := range call.args.Registrations {
		if bytes.Equal(registration.NameToken, previousPath) {
			answer.Statuses[index] = SocketRegistrationStatusDenied
		}
	}
	effects := state.finish(call, answer, nil, testSocketNow, testSocketNow)
	if len(effects) != 1 || effects[0].status != SocketRegistrationStatusOk || !entry.previousRefused || state.entries[entry.listenId] != entry {
		t.Fatalf("effects %+v, previous refused %v", effects, entry.previousRefused)
	}
	calls = runTestSocketRound(t, state, testSocketNow.Add(1*time.Second))
	if len(calls[0].args.Registrations) != 1 || !bytes.Equal(calls[0].args.Registrations[0].NameToken, currentPath) {
		t.Errorf("a refused previous path went again")
	}
}

// Holds a registration's claim to §9.5: a Signed by the identity key, purpose socket-registration, over the network,
// the name or token path, the listen id, the protocol and the app mode.
func checkTestSocketClaim(t testing.TB, signer *testSocketSigner, registration *SocketRegistration, name string, tokenPath []byte) {
	t.Helper()
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(registration.Claim, signed); err != nil {
		t.Fatal(err)
	}
	err := bridge.VerifySigned(signed, SocketRegistrationPurpose, bridge.SignedType_SIGNED_SOCKET_REGISTRATION,
		bridge.SignedKeyAlgEd25519, signer.publicKey())
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	claim := &protocol.SocketRegistrationClaim{}
	if err := proto.Unmarshal(signed.GetBody(), claim); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(claim.GetNetworkId(), testRegistrarNetworkId.Bytes()) || !bytes.Equal(claim.GetListenId(), registration.ListenId[:]) ||
		claim.GetProtocol() != registration.Protocol || claim.GetAppMode() != registration.AppMode ||
		claim.GetName() != name || !bytes.Equal(claim.GetNameToken(), tokenPath) {
		t.Errorf("claim %v", claim)
	}
}

// unavailable's retry_after_ms is waited out, up to RetryAfterMaxWait, as a 503's Retry-After is; a failure that
// names no wait backs off from 1 s, doubling to 15 s (§9.5, §9.10).
func TestSocketRegistrarHonorsRetryAfter(t *testing.T) {
	signer := newTestSocketSigner("a")
	for _, c := range []struct {
		name   string
		result *SocketRegistrationsResult
		err    error
		want   time.Duration
	}{
		{name: "unavailable", result: &SocketRegistrationsResult{Error: &SocketError{Code: SocketErrorCodeUnavailable, RetryAfterMs: 1500}}, want: 1500 * time.Millisecond},
		{name: "past the cap", result: &SocketRegistrationsResult{Error: &SocketError{Code: SocketErrorCodeUnavailable, RetryAfterMs: 3600 * 1000}}, want: 5 * time.Minute},
		{name: "a 503", err: &SidecarApiError{Route: socketRegistrationsRoute, Status: 503, RetryAfterMs: 2000}, want: 2 * time.Second},
		{name: "a transport failure", err: errors.New("synthetic transport failure"), want: 1 * time.Second},
		{name: "an invalid page", result: &SocketRegistrationsResult{Error: &SocketError{Code: SocketErrorCodeInvalid}}, want: 1 * time.Second},
		{name: "a short answer", result: &SocketRegistrationsResult{}, want: 1 * time.Second},
	} {
		state := newTestSocketState(nil, 0.5)
		entry := addTestSocketEntry(t, state, signer, nil, testSocketArgs("tls/443/blog"), testSocketNow)
		call, _ := state.next(testSocketNow)
		if effects := state.finish(call, c.result, c.err, testSocketNow, testSocketNow); len(effects) != 0 {
			t.Errorf("%s: effects %+v", c.name, effects)
		}
		if call, wakeAt := state.next(testSocketNow); call != nil || !wakeAt.Equal(testSocketNow.Add(c.want)) {
			t.Errorf("%s: a call %v, a wake at %v, want %v", c.name, call != nil, wakeAt.Sub(testSocketNow), c.want)
			continue
		}
		if call, _ := state.next(testSocketNow.Add(c.want - time.Millisecond)); call != nil {
			t.Errorf("%s: a call before the wait", c.name)
		}
		if call, _ := state.next(testSocketNow.Add(c.want)); call == nil || call.round == nil {
			t.Errorf("%s: no round after the wait", c.name)
		}
		if state.entries[entry.listenId] != entry {
			t.Errorf("%s: a failed call took the entry out", c.name)
		}
	}

	// failures in a row double the wait to the heartbeat's 15 s, and an answer resets it
	state := newTestSocketState(nil, 0.5)
	addTestSocketEntry(t, state, signer, nil, testSocketArgs("tls/443/blog"), testSocketNow)
	now := testSocketNow
	for _, want := range []time.Duration{1, 2, 4, 8, 15, 15} {
		call, _ := state.next(now)
		if call == nil {
			t.Fatalf("no call at %v", now.Sub(testSocketNow))
		}
		state.finish(call, nil, errors.New("synthetic transport failure"), now, now)
		if !state.retryAt.Equal(now.Add(want * time.Second)) {
			t.Fatalf("a wait of %v, want %v s", state.retryAt.Sub(now), want)
		}
		now = state.retryAt
	}
	runTestSocketRound(t, state, now)
	if state.failureCount != 0 {
		t.Errorf("an answer left %d failures", state.failureCount)
	}
}

// A name outside tls/, smtp/ and ur/ reaches the service only as its token path and its seal, which opens to it under
// the ring; a reserved name is refused; and a blinded name with no ring is refused before anything leaves (D-SOCK-13).
func TestSocketRegistrarNeverSendsAnApplicationNameInTheClear(t *testing.T) {
	state := newTestSocketState(nil, 0.5)
	signer := newTestSocketSigner("a")
	ring := newTestSocketRing(t, "k1", "", 0)
	shareName := "share/" + strings.Repeat("a", socketShareTokenByteCount)
	for _, name := range []string{"db/primary", shareName, "tls/443/blog", "smtp/25/mx"} {
		addTestSocketEntry(t, state, signer, ring, testSocketArgs(name), testSocketNow)
	}
	call, _ := state.next(testSocketNow)
	body, err := json.Marshal(call.args)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"db/primary", "primary", shareName} {
		if bytes.Contains(body, []byte(name)) {
			t.Errorf("the page carries %q in the clear", name)
		}
	}
	for _, registration := range call.args.Registrations {
		switch {
		case registration.Name == "tls/443/blog" || registration.Name == "smtp/25/mx":
			if registration.NameToken != nil || registration.SealedName != nil {
				t.Errorf("an edge name with a token path")
			}
			checkTestSocketClaim(t, signer, registration, registration.Name, nil)
		case registration.Name == "":
			name, ok := ring.OpenName(registration.NameToken, registration.SealedName)
			if !ok || (name != "db/primary" && name != shareName) {
				t.Errorf("a seal that opens to %q, %v", name, ok)
			}
			tokenPath, _ := ring.Current().TokenPath(name)
			if !bytes.Equal(tokenPath, registration.NameToken) {
				t.Errorf("a token path that is not the ring's")
			}
			checkTestSocketClaim(t, signer, registration, "", tokenPath)
		default:
			t.Errorf("a registration named %q", registration.Name)
		}
	}

	for _, name := range []string{"sys/a", "c/old", "_private/db", "a/b"} {
		if _, err := newSocketRegistrarEntry(testSocketArgs(name)); !errors.Is(err, errSocketRegistrationInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	entry, err := newSocketRegistrarEntry(testSocketArgs("db/primary"))
	if err != nil {
		t.Fatal(err)
	}
	countBefore := signer.count()
	if _, err := makeSocketRegistrarRows(testRegistrarNetworkId, signer.sign, entry, nil, testSocketNow.UnixMilli(), nil, 0); !errors.Is(err, errSocketNoKeyRing) || !errors.Is(err, ErrSocketUnavailable) {
		t.Errorf("no ring: %v", err)
	}
	if signer.count() != countBefore {
		t.Errorf("a claim was signed for a name with no ring")
	}
}

// What §9.5 refuses of a registration is refused before it joins the set, and a second Listen of a name, however it
// is spelled, is refused while the first holds it.
func TestSocketRegistrarRefusesWhatSection95Refuses(t *testing.T) {
	for _, c := range []struct {
		name   string
		adjust func(args *socketRegistrationArgs)
	}{
		{name: "weight 0", adjust: func(args *socketRegistrationArgs) { args.Weight = 0 }},
		{name: "weight 1001", adjust: func(args *socketRegistrationArgs) { args.Weight = 1001 }},
		{name: "max_streams 0", adjust: func(args *socketRegistrationArgs) { args.MaxStreams = 0 }},
		{name: "no protocol", adjust: func(args *socketRegistrationArgs) { args.Protocol = "" }},
		{name: "a negative version", adjust: func(args *socketRegistrationArgs) { args.Version = -1 }},
		{name: "no listen id", adjust: func(args *socketRegistrationArgs) { args.ListenId = Id{} }},
		{name: "tls/ with no app_mode", adjust: func(args *socketRegistrationArgs) { args.AppMode = "" }},
		{name: "tls/ with another app_mode", adjust: func(args *socketRegistrationArgs) { args.AppMode = "ftp" }},
		{name: "a name that does not parse", adjust: func(args *socketRegistrationArgs) { args.Name = "tls/443/a/b" }},
		{name: "an app_mode outside tls/", adjust: func(args *socketRegistrationArgs) { args.Name = "smtp/25/mx"; args.AppMode = "raw" }},
	} {
		args := testSocketArgs("tls/443/blog")
		c.adjust(args)
		if _, err := newSocketRegistrarEntry(args); !errors.Is(err, errSocketRegistrationInvalid) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	for _, appMode := range []string{"http", "raw"} {
		args := testSocketArgs("tls/443/blog")
		args.AppMode = appMode
		if _, err := newSocketRegistrarEntry(args); err != nil {
			t.Errorf("%s: %v", appMode, err)
		}
	}

	state := newTestSocketState(nil, 0.5)
	signer := newTestSocketSigner("a")
	addTestSocketEntry(t, state, signer, nil, testSocketArgs("tls/443/blog"), testSocketNow)
	again, err := newSocketRegistrarEntry(&socketRegistrationArgs{
		Name: "TLS/443/Blog", ListenId: testSocketId("another listen"), Protocol: "tcp", AppMode: "raw", Weight: 1, MaxStreams: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := state.addEntry(again); !errors.Is(err, errSocketNameRegistered) {
		t.Errorf("a second Listen of a name: %v", err)
	}
}

// An answer that refuses nothing leaves the ticket keys, the service's clock offset taken at the call's midpoint, the
// edge network and §20's stop for admission; a failure leaves them as they were (§9.6's steps 1, 3, 4 and 5).
func TestSocketRegistrarKeepsAdmissionState(t *testing.T) {
	state := newTestSocketState(nil, 0.5)
	signer := newTestSocketSigner("a")
	addTestSocketEntry(t, state, signer, nil, testSocketArgs("tls/443/blog"), testSocketNow)
	if state.admission.known {
		t.Errorf("known before any answer")
	}
	call, _ := state.next(testSocketNow)
	answer := testSocketAnswer(call, SocketRegistrationStatusOk)
	urnetworkEdge := connect.Id(testSocketId("urnetwork-edge"))
	answer.UrnetworkEdge = &urnetworkEdge
	answer.StreamsStopped = true
	// 10 min ahead, read at the midpoint of a call that took 2 s
	receivedAt := testSocketNow.Add(2 * time.Second)
	answer.ServerTimeMillis = uint64(testSocketNow.Add(1*time.Second + 10*time.Minute).UnixMilli())
	state.finish(call, answer, nil, testSocketNow, receivedAt)
	admission := state.admission.clone()
	if !admission.known || len(admission.ticketKeys) != 1 || admission.ticketKeys[0].KeyId != "key-1" || !admission.streamsStopped ||
		admission.urnetworkEdge == nil || *admission.urnetworkEdge != testSocketId("urnetwork-edge") {
		t.Fatalf("admission %+v", admission)
	}
	if admission.serverTimeOffsetMillis != (10 * time.Minute).Milliseconds() {
		t.Errorf("offset %d ms", admission.serverTimeOffsetMillis)
	}
	if got := admission.serverNowMillis(receivedAt); got != uint64(receivedAt.Add(10*time.Minute).UnixMilli()) {
		t.Errorf("the service's now %d", got)
	}
	admission.ticketKeys[0].PublicKey[0] = 1
	if state.admission.ticketKeys[0].PublicKey[0] != 0 {
		t.Errorf("a copy shares its keys")
	}

	// the heartbeat runs from the answer
	now := receivedAt.Add(15 * time.Second)
	call, _ = state.next(now)
	if call == nil {
		t.Fatal("no heartbeat")
	}
	state.finish(call, nil, errors.New("synthetic transport failure"), now, now)
	if !state.admission.known || !state.admission.streamsStopped || len(state.admission.ticketKeys) != 1 {
		t.Errorf("a failure changed admission's state")
	}
	call, _ = state.next(state.retryAt)
	answer = testSocketAnswer(call, SocketRegistrationStatusOk)
	answer.ServerTimeMillis = 0
	answer.TicketKeys = nil
	state.finish(call, answer, nil, now, now)
	if state.admission.serverTimeOffsetMillis != (10*time.Minute).Milliseconds() || len(state.admission.ticketKeys) != 0 ||
		state.admission.streamsStopped || state.admission.urnetworkEdge != nil {
		t.Errorf("admission %+v after an answer naming no time or keys", state.admission)
	}
}

// Unlisten goes at once: the next page lacks the entry, so the service drops it; an empty set goes once, as one page
// over every key, and then the heartbeat stops.
func TestSocketRegistrarUnlistensAndStopsWhenTheSetIsEmpty(t *testing.T) {
	state := newTestSocketState(nil, 0.5)
	signer := newTestSocketSigner("a")
	first := addTestSocketEntry(t, state, signer, nil, testSocketArgs("tls/443/blog"), testSocketNow)
	second := addTestSocketEntry(t, state, signer, nil, testSocketArgs("tls/443/api"), testSocketNow)
	runTestSocketRound(t, state, testSocketNow)
	now := testSocketNow.Add(1 * time.Second)
	if !state.removeEntry(first.listenId) || state.removeEntry(first.listenId) {
		t.Fatalf("remove")
	}
	calls := runTestSocketRound(t, state, now)
	if len(calls[0].args.Registrations) != 1 || calls[0].args.Registrations[0].Name != "tls/443/api" {
		t.Errorf("after an unlisten: %d registrations", len(calls[0].args.Registrations))
	}
	state.removeEntry(second.listenId)
	calls = runTestSocketRound(t, state, now)
	if len(calls) != 1 || len(calls[0].args.Registrations) != 0 || calls[0].args.KeyStart != nil || calls[0].args.KeyEnd != nil {
		t.Fatalf("the empty set went as %d calls", len(calls))
	}
	if call, wakeAt := state.next(now.Add(1 * time.Hour)); call != nil || !wakeAt.IsZero() {
		t.Errorf("after the empty set: a call %v, a wake at %v", call != nil, wakeAt)
	}
	if state.hint(nil); state.roundPending {
		t.Errorf("a hint with nothing held asked for a round")
	}
}

// serving and draining change the set, which goes at once; setting what is already set changes nothing.
func TestSocketRegistrarServingAndDrainingGoAtOnce(t *testing.T) {
	state := newTestSocketState(nil, 0.5)
	signer := newTestSocketSigner("a")
	entry := addTestSocketEntry(t, state, signer, nil, testSocketArgs("tls/443/blog"), testSocketNow)
	runTestSocketRound(t, state, testSocketNow)
	if state.setServing(entry.listenId, true) || state.setDraining(entry.listenId, false) {
		t.Errorf("a change to what was set")
	}
	now := testSocketNow.Add(1 * time.Second)
	if !state.setServing(entry.listenId, false) {
		t.Fatal("serving did not change")
	}
	calls := runTestSocketRound(t, state, now)
	if registration := calls[0].args.Registrations[0]; registration.Serving || registration.Draining {
		t.Errorf("serving %v, draining %v", registration.Serving, registration.Draining)
	}
	if !state.setDraining(entry.listenId, true) {
		t.Fatal("draining did not change")
	}
	calls = runTestSocketRound(t, state, now)
	if registration := calls[0].args.Registrations[0]; !registration.Draining {
		t.Errorf("draining did not go")
	}
}

// A change during a round's call reaches the next round, and an answer to a generation that has ended changes nothing.
func TestSocketRegistrarDropsAnswersOfAnEndedGeneration(t *testing.T) {
	state := newTestSocketState(nil, 0.5)
	signer := newTestSocketSigner("a")
	entry := addTestSocketEntry(t, state, signer, nil, testSocketArgs("tls/443/blog"), testSocketNow)
	call, _ := state.next(testSocketNow)
	state.detach(state.attachmentSeq)
	attachmentSeq := state.attach()
	if effects := state.finish(call, testSocketAnswer(call, SocketRegistrationStatusDenied), nil, testSocketNow, testSocketNow); len(effects) != 0 {
		t.Errorf("an ended generation's answer gave %+v", effects)
	}
	if state.entries[entry.listenId] != entry || entry.answered {
		t.Errorf("an ended generation's answer changed the entry")
	}
	if !state.detach(attachmentSeq) || state.detach(attachmentSeq) {
		t.Errorf("detach")
	}
	if call, wakeAt := state.next(testSocketNow); call != nil || !wakeAt.IsZero() {
		t.Errorf("a detached state called")
	}
}

// §9.5's numbers, and the readings beside them, as DefaultSidecarSettings gives them; validate refuses what would
// make a wait zero or the eager amount past the whole.
func TestDefaultSocketSettingsMatchDesign(t *testing.T) {
	want := SidecarSocketSettings{
		HeartbeatInterval:       15 * time.Second,
		Jitter:                  0.2,
		EagerReportInterval:     2 * time.Second,
		EagerReportMinMove:      8,
		EagerReportMoveFraction: 0.25,
		RequestTimeout:          10 * time.Second,
		RetryInterval:           1 * time.Second,
		RetryMaxInterval:        15 * time.Second,
		RetryAfterMaxWait:       5 * time.Minute,
	}
	if got := *DefaultSidecarSettings().Sockets; got != want {
		t.Errorf("%+v, want %+v", got, want)
	}
	for _, c := range []struct {
		name   string
		adjust func(settings *SidecarSocketSettings)
	}{
		{name: "Jitter", adjust: func(settings *SidecarSocketSettings) { settings.Jitter = 1 }},
		{name: "EagerReportMoveFraction", adjust: func(settings *SidecarSocketSettings) { settings.EagerReportMoveFraction = 1.5 }},
		{name: "RetryInterval", adjust: func(settings *SidecarSocketSettings) { settings.RetryInterval = 16 * time.Second }},
		{name: "HeartbeatInterval", adjust: func(settings *SidecarSocketSettings) { settings.HeartbeatInterval = 0 }},
		{name: "EagerReportMinMove", adjust: func(settings *SidecarSocketSettings) { settings.EagerReportMinMove = -1 }},
	} {
		settings := validSidecarSettings()
		c.adjust(settings.Sockets)
		if err := settings.validate(); !errors.Is(err, errInvalidSettings) || !strings.Contains(err.Error(), c.name) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if _, err := newSocketRegistrar(context.Background(), &socketRegistrarArgs{
		NetworkId: testRegistrarNetworkId,
		Settings:  &SidecarSocketSettings{},
		Sign:      newTestSocketSigner("a").sign,
	}); !errors.Is(err, errInvalidSettings) {
		t.Errorf("a registrar on zero settings: %v", err)
	}
}

// A clock the test moves. AfterFunc's calls run in advance, on the test's goroutine, in time order.
type testSocketClock struct {
	stateLock sync.Mutex
	now       time.Time
	timers    []*testSocketTimer
}

type testSocketTimer struct {
	at       time.Time
	function func()
}

func newTestSocketClock() *testSocketClock {
	return &testSocketClock{now: testSocketNow}
}

// See Clock.
func (self *testSocketClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

// See Clock.
func (self *testSocketClock) After(timeout time.Duration) <-chan time.Time {
	fired := make(chan time.Time, 1)
	self.AfterFunc(timeout, func() {
		fired <- self.Now()
	})
	return fired
}

// See Clock.
func (self *testSocketClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	if timeout <= 0 {
		function()
		return func() bool { return false }
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	timer := &testSocketTimer{at: self.now.Add(timeout), function: function}
	self.timers = append(self.timers, timer)
	return func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		index := slices.Index(self.timers, timer)
		if index < 0 {
			return false
		}
		self.timers = slices.Delete(self.timers, index, index+1)
		return true
	}
}

// Moves the clock by by, firing each timer it reaches at its own time.
func (self *testSocketClock) advance(by time.Duration) {
	target := self.Now().Add(by)
	for {
		var next *testSocketTimer
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			for _, timer := range self.timers {
				if !timer.at.After(target) && (next == nil || timer.at.Before(next.at)) {
					next = timer
				}
			}
			if next == nil {
				self.now = target
				return
			}
			self.timers = slices.DeleteFunc(self.timers, func(timer *testSocketTimer) bool { return timer == next })
			self.now = next.at
		}()
		if next == nil {
			return
		}
		next.function()
	}
}

// One call the fake service holds until the test answers it.
type testSocketServiceCall struct {
	args   *SocketRegistrationsArgs
	answer chan *SocketRegistrationsResult
}

// A sockets service that hands each call to the test, counting how many are open at once.
type testSocketService struct {
	calls    chan *testSocketServiceCall
	open     atomic.Int64
	mostOpen atomic.Int64
}

func newTestSocketService() *testSocketService {
	return &testSocketService{calls: make(chan *testSocketServiceCall, 64)}
}

// See socketRegistrationsFunction.
func (self *testSocketService) registrations(ctx context.Context, args *SocketRegistrationsArgs) (*SocketRegistrationsResult, error) {
	open := self.open.Add(1)
	defer self.open.Add(-1)
	for {
		mostOpen := self.mostOpen.Load()
		if open <= mostOpen || self.mostOpen.CompareAndSwap(mostOpen, open) {
			break
		}
	}
	// a copy, as the bytes on the wire are
	body, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	copied := &SocketRegistrationsArgs{}
	if err := json.Unmarshal(body, copied); err != nil {
		return nil, err
	}
	call := &testSocketServiceCall{args: copied, answer: make(chan *SocketRegistrationsResult, 1)}
	self.calls <- call
	select {
	case result := <-call.answer:
		return result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Answers call with status for every entry.
func (self *testSocketServiceCall) answerAll(status SocketRegistrationStatus) {
	statuses := make([]SocketRegistrationStatus, len(self.args.Registrations))
	for i := range statuses {
		statuses[i] = status
	}
	self.answer <- &SocketRegistrationsResult{
		Statuses:         statuses,
		SetVersion:       self.args.SetVersion,
		ServerTimeMillis: uint64(testSocketNow.UnixMilli()),
	}
}

// A registrar on a fake clock and a fake service, its jitter fixed at none, closed at the test's end.
type testSocketRegistrarWorld struct {
	clock     *testSocketClock
	service   *testSocketService
	signer    *testSocketSigner
	registrar *socketRegistrar
}

func newTestSocketRegistrarWorld(t *testing.T) *testSocketRegistrarWorld {
	t.Helper()
	world := &testSocketRegistrarWorld{
		clock:   newTestSocketClock(),
		service: newTestSocketService(),
		signer:  newTestSocketSigner("a"),
	}
	registrar, err := newSocketRegistrar(context.Background(), &socketRegistrarArgs{
		NetworkId: testRegistrarNetworkId,
		Settings:  DefaultSidecarSocketSettings(),
		Sign:      world.signer.sign,
		Clock:     world.clock,
		Log:       NewNoopLogger(),
		Random:    func() float64 { return 0.5 },
	})
	if err != nil {
		t.Fatal(err)
	}
	world.registrar = registrar
	t.Cleanup(registrar.close)
	return world
}

// The next call the service gets.
func (self *testSocketRegistrarWorld) awaitCall(t *testing.T) *testSocketServiceCall {
	t.Helper()
	return testSocketAwait(t, self.service.calls, "a registrations call")
}

// How many times the loop has waited so far. Read while the loop is held in a call, the next wait is the one after its
// answer.
func (self *testSocketRegistrarWorld) waits() uint64 {
	return self.registrar.waitCount.Value()
}

// Waits until the loop has gone to wait more than waitCount times, and returns its count: the loop has nothing left
// to do at the clock's time, and its timer, if any, is armed.
func (self *testSocketRegistrarWorld) awaitWait(t *testing.T, waitCount uint64) uint64 {
	t.Helper()
	deadline := time.After(testSocketAwaitTimeout)
	for {
		count, changed := self.registrar.waitCount.Get()
		if waitCount < count {
			return count
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("the loop never waited")
		}
	}
}

// Answers call with result and waits until the loop, held in that call until now, has gone to wait: it has nothing
// left to do at the clock's time, and its timer, if any, is armed. Only for an answer after which no call is due.
func (self *testSocketRegistrarWorld) answerAndSettle(t *testing.T, call *testSocketServiceCall, result *SocketRegistrationsResult) {
	t.Helper()
	waitCount := self.waits()
	call.answer <- result
	self.awaitWait(t, waitCount)
}

// The answer of a service that takes every entry of call with status.
func (self *testSocketServiceCall) answerOf(status SocketRegistrationStatus) *SocketRegistrationsResult {
	statuses := make([]SocketRegistrationStatus, len(self.args.Registrations))
	for i := range statuses {
		statuses[i] = status
	}
	return &SocketRegistrationsResult{
		Statuses:         statuses,
		SetVersion:       self.args.SetVersion,
		ServerTimeMillis: uint64(testSocketNow.UnixMilli()),
	}
}

// The registrar makes one call at a time: what changes during a call goes in one round after it, together, and
// nothing goes before a generation is attached.
func TestSocketRegistrarLoopCallsOnceAtATime(t *testing.T) {
	world := newTestSocketRegistrarWorld(t)
	registration, err := world.registrar.add(testSocketArgs("tls/443/blog"))
	if err != nil {
		t.Fatal(err)
	}
	world.awaitWait(t, 0)
	if 0 < len(world.service.calls) {
		t.Fatalf("a call before any generation")
	}
	world.registrar.attach(context.Background(), world.service.registrations, world.signer.publicKey())
	first := world.awaitCall(t)
	if len(first.args.Registrations) != 1 || first.args.Registrations[0].Name != "tls/443/blog" {
		t.Fatalf("first call %+v", first.args)
	}
	// while the first call is out
	world.registrar.hint(PushNotice{Topic: PushTopicSock, Version: 7})
	world.registrar.hint(PushNotice{Topic: PushTopicSock, Version: 8})
	registration.setServing(false)
	if _, err := world.registrar.add(testSocketArgs("tls/443/api")); err != nil {
		t.Fatal(err)
	}
	first.answer <- first.answerOf(SocketRegistrationStatusOk)
	status, err := registration.verdict(context.Background())
	if err != nil || status != SocketRegistrationStatusOk {
		t.Fatalf("verdict %q, %v", status, err)
	}
	second := world.awaitCall(t)
	if len(second.args.Registrations) != 2 || second.args.SetVersion <= first.args.SetVersion {
		t.Fatalf("second call %+v", second.args)
	}
	for _, registration := range second.args.Registrations {
		if registration.Name == "tls/443/blog" && registration.Serving {
			t.Errorf("serving did not go")
		}
	}
	world.answerAndSettle(t, second, second.answerOf(SocketRegistrationStatusOk))
	if 0 < len(world.service.calls) || world.service.mostOpen.Load() != 1 {
		t.Errorf("%d more calls, %d open at once", len(world.service.calls), world.service.mostOpen.Load())
	}
}

// The heartbeat goes on the registrar's clock, 15 s after a round with the jitter fixed at none, and not before; a
// hint's round goes at once, and only one.
func TestSocketRegistrarLoopHeartbeatsOnItsClock(t *testing.T) {
	world := newTestSocketRegistrarWorld(t)
	if _, err := world.registrar.add(testSocketArgs("tls/443/blog")); err != nil {
		t.Fatal(err)
	}
	world.registrar.attach(context.Background(), world.service.registrations, world.signer.publicKey())
	first := world.awaitCall(t)
	world.answerAndSettle(t, first, first.answerOf(SocketRegistrationStatusOk))
	world.clock.advance(15*time.Second - time.Millisecond)
	if 0 < len(world.service.calls) {
		t.Fatalf("a heartbeat before 15 s")
	}
	world.clock.advance(time.Millisecond)
	heartbeat := world.awaitCall(t)
	if heartbeat.args.SetVersion <= first.args.SetVersion {
		t.Errorf("the heartbeat's set_version %d after %d", heartbeat.args.SetVersion, first.args.SetVersion)
	}
	world.answerAndSettle(t, heartbeat, heartbeat.answerOf(SocketRegistrationStatusOk))

	world.registrar.hint(PushNotice{Topic: PushTopicSock, Version: 9, Kind: uint32(protocol.MessageType_SOCKET_HINT)})
	hinted := world.awaitCall(t)
	world.answerAndSettle(t, hinted, hinted.answerOf(SocketRegistrationStatusOk))
	if 0 < len(world.service.calls) {
		t.Errorf("a hint asked for more than one call")
	}
	// a notice on another topic is not the registrar's
	waitCount := world.waits()
	world.registrar.hint(PushNotice{Topic: PushTopicTls, Version: 10})
	world.clock.advance(time.Second)
	if 0 < len(world.service.calls) || world.waits() != waitCount {
		t.Errorf("a notice on another topic asked for a call")
	}
}

// unavailable's retry_after_ms holds the next call until the registrar's clock passes it, and the call after it gives
// the verdict a Listen waits for.
func TestSocketRegistrarLoopWaitsOutRetryAfter(t *testing.T) {
	world := newTestSocketRegistrarWorld(t)
	registration, err := world.registrar.add(testSocketArgs("tls/443/blog"))
	if err != nil {
		t.Fatal(err)
	}
	world.registrar.attach(context.Background(), world.service.registrations, world.signer.publicKey())
	first := world.awaitCall(t)
	world.answerAndSettle(t, first, &SocketRegistrationsResult{Error: &SocketError{Code: SocketErrorCodeUnavailable, RetryAfterMs: 3000}})
	world.clock.advance(3*time.Second - time.Millisecond)
	if 0 < len(world.service.calls) {
		t.Fatalf("a call inside retry_after_ms")
	}
	world.clock.advance(time.Millisecond)
	retried := world.awaitCall(t)
	world.answerAndSettle(t, retried, retried.answerOf(SocketRegistrationStatusDenied))
	status, err := registration.verdict(context.Background())
	if err != nil || status != SocketRegistrationStatusDenied {
		t.Errorf("verdict %q, %v", status, err)
	}
}

// A new ring makes blinded names' rows again, signing only the new path and keeping the claim of the one it had, and the
// set goes at once; a new identity key signs every claim again (§9.4, plan-SOCK-ksock-rotation).
func TestSocketRegistrarLoopMakesRowsAgainForANewRingOrKey(t *testing.T) {
	world := newTestSocketRegistrarWorld(t)
	if _, err := world.registrar.add(testSocketArgs("db/primary")); !errors.Is(err, errSocketNoKeyRing) {
		t.Fatalf("a blinded Listen with no ring: %v", err)
	}
	firstRing := newTestSocketRing(t, "k1", "", 0)
	if err := world.registrar.setKeyRing(firstRing); err != nil {
		t.Fatal(err)
	}
	otherNetworkRing, err := NewSocketKeyRing(testSocketId("other network"), &protocol.SocketKeyFile{CurrentKey: testRegistrarKey("k1")}, DefaultSocketKeyRingSettings())
	if err != nil {
		t.Fatal(err)
	}
	if err := world.registrar.setKeyRing(otherNetworkRing); !errors.Is(err, errInvalidSettings) {
		t.Errorf("another network's ring: %v", err)
	}
	if err := world.registrar.setKeyRing(nil); !errors.Is(err, errInvalidSettings) {
		t.Errorf("no ring: %v", err)
	}
	if _, err := world.registrar.add(testSocketArgs("db/primary")); err != nil {
		t.Fatal(err)
	}
	world.registrar.attach(context.Background(), world.service.registrations, world.signer.publicKey())
	first := world.awaitCall(t)
	firstPath, _ := firstRing.Current().TokenPath("db/primary")
	if len(first.args.Registrations) != 1 || !bytes.Equal(first.args.Registrations[0].NameToken, firstPath) {
		t.Fatalf("first call %+v", first.args)
	}
	world.answerAndSettle(t, first, first.answerOf(SocketRegistrationStatusOk))
	signCount := world.signer.count()

	rotatedRing := newTestSocketRing(t, "k2", "k1", world.clock.Now().UnixMilli())
	if err := world.registrar.setKeyRing(rotatedRing); err != nil {
		t.Fatal(err)
	}
	second := world.awaitCall(t)
	secondPath, _ := rotatedRing.Current().TokenPath("db/primary")
	paths := [][]byte{}
	for _, registration := range second.args.Registrations {
		paths = append(paths, registration.NameToken)
	}
	if len(paths) != 2 || !slices.ContainsFunc(paths, func(path []byte) bool { return bytes.Equal(path, firstPath) }) ||
		!slices.ContainsFunc(paths, func(path []byte) bool { return bytes.Equal(path, secondPath) }) {
		t.Fatalf("after the rotation: %d paths", len(paths))
	}
	if world.signer.count() != signCount+1 {
		t.Errorf("the rotation signed %d claims", world.signer.count()-signCount)
	}
	world.answerAndSettle(t, second, second.answerOf(SocketRegistrationStatusOk))

	// the same generation's key again changes nothing; a new key signs both paths again
	signCount = world.signer.count()
	world.registrar.attach(context.Background(), world.service.registrations, world.signer.publicKey())
	same := world.awaitCall(t)
	world.answerAndSettle(t, same, same.answerOf(SocketRegistrationStatusOk))
	if world.signer.count() != signCount {
		t.Errorf("the same key signed %d claims again", world.signer.count()-signCount)
	}
	otherKey := newTestSocketSigner("b").publicKey()
	world.registrar.attach(context.Background(), world.service.registrations, otherKey)
	renewed := world.awaitCall(t)
	world.answerAndSettle(t, renewed, renewed.answerOf(SocketRegistrationStatusOk))
	if world.signer.count() != signCount+2 {
		t.Errorf("a new key signed %d claims again", world.signer.count()-signCount)
	}

	// with signing refused, rows made again for another key wait, and the old ones go on
	world.signer.setRefuse(true)
	world.registrar.attach(context.Background(), world.service.registrations, newTestSocketSigner("c").publicKey())
	kept := world.awaitCall(t)
	if len(kept.args.Registrations) != 2 {
		t.Errorf("while signing is refused: %d registrations", len(kept.args.Registrations))
	}
	world.answerAndSettle(t, kept, kept.answerOf(SocketRegistrationStatusOk))
}

// A Listen waiting for its verdict ends when its entry is removed or the registrar closes, never with a verdict it
// did not get.
func TestSocketRegistrarVerdictEndsWithTheEntry(t *testing.T) {
	world := newTestSocketRegistrarWorld(t)
	removed, err := world.registrar.add(testSocketArgs("tls/443/blog"))
	if err != nil {
		t.Fatal(err)
	}
	removed.remove()
	if _, err := removed.verdict(context.Background()); !errors.Is(err, errSocketRegistrationRemoved) {
		t.Errorf("removed: %v", err)
	}
	waiting, err := world.registrar.add(testSocketArgs("tls/443/api"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := waiting.verdict(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("an ended ctx: %v", err)
	}
	world.signer.setRefuse(true)
	if _, err := world.registrar.add(testSocketArgs("tls/443/www")); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("a Listen whose claim cannot be signed: %v", err)
	}
	world.registrar.close()
	if _, err := waiting.verdict(context.Background()); !errors.Is(err, errSocketRegistrarClosed) {
		t.Errorf("closed: %v", err)
	}
	if _, err := world.registrar.add(testSocketArgs("tls/443/mail")); !errors.Is(err, errSocketRegistrarClosed) {
		t.Errorf("a Listen after close: %v", err)
	}
}

// The route: POST to the sockets service with the client's token as a bearer and no proof, the page as JSON, and the
// answer read as it came, a page's refusal included; a short answer and a 503 are errors with their wait.
func TestSocketRegistrationsRoute(t *testing.T) {
	transport := &scriptedApiTransport{
		answer: func(request *http.Request, body []byte) (*http.Response, error) {
			args := &SocketRegistrationsArgs{}
			if err := json.Unmarshal(body, args); err != nil {
				return syntheticResponse(request, 400, "{}", nil), nil
			}
			switch len(args.Registrations) {
			case 0:
				return syntheticResponse(request, 200, `{"statuses":[],"set_version":99,"error":{"code":"stale"}}`, nil), nil
			case 1:
				return syntheticResponse(request, 200, `{"statuses":["ok"],"set_version":5,"server_time":7}`, nil), nil
			case 2:
				return syntheticResponse(request, 200, `{"statuses":["ok"]}`, nil), nil
			}
			return syntheticResponse(request, 503, `{}`, http.Header{"Retry-After": []string{"7"}}), nil
		},
	}
	api := newTestSidecarApi(t, transport)
	listenId := connect.Id(testSocketId("listen"))
	registration := &SocketRegistration{Name: "tls/443/blog", ListenId: &listenId, Protocol: "tcp", Weight: 100, MaxStreams: 256, Serving: true}
	result, err := api.SocketRegistrations(context.Background(), &SocketRegistrationsArgs{SetVersion: 5, Registrations: []*SocketRegistration{registration}})
	if err != nil || len(result.Statuses) != 1 || result.Statuses[0] != SocketRegistrationStatusOk || result.ServerTimeMillis != 7 {
		t.Fatalf("result %+v, %v", result, err)
	}
	request, body := transport.onlyRequest(t)
	if request.Method != "POST" || request.URL.String() != "https://sockets.example/socket/registrations" ||
		request.Header.Get("Authorization") != "Bearer "+testByJwt || request.Header.Get("DPoP") != "" ||
		request.Header.Get("Content-Type") != "application/json" {
		t.Errorf("request %s %s", request.Method, request.URL)
	}
	if !bytes.Contains(body, []byte(`"set_version":5`)) || !bytes.Contains(body, []byte(`"name":"tls/443/blog"`)) {
		t.Errorf("body %s", body)
	}

	result, err = api.SocketRegistrations(context.Background(), &SocketRegistrationsArgs{SetVersion: 4})
	if err != nil || result.Error == nil || result.Error.Code != SocketErrorCodeStale || result.SetVersion != 99 {
		t.Errorf("a page's refusal: %+v, %v", result, err)
	}
	if _, err := api.SocketRegistrations(context.Background(), &SocketRegistrationsArgs{Registrations: []*SocketRegistration{registration, registration}}); !errors.Is(err, ErrSidecarApiReply) {
		t.Errorf("a short answer: %v", err)
	}
	_, err = api.SocketRegistrations(context.Background(), &SocketRegistrationsArgs{Registrations: []*SocketRegistration{registration, registration, registration}})
	var apiErr *SidecarApiError
	if !errors.As(err, &apiErr) || apiErr.Status != 503 || apiErr.RetryAfterMs != 7000 {
		t.Errorf("a 503: %v", err)
	}
	if _, err := api.SocketRegistrations(context.Background(), nil); !errors.Is(err, ErrSidecarApiArgs) {
		t.Errorf("no args: %v", err)
	}
}
