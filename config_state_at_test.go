// ConfigLog.StateAt on the test network: S(k) for any pin from the previous base to the tip, kept or rebuilt equal to
// the state the log published at k; a pin above the tip waits, one before the previous base is unjudged, and one off
// the chain is a fork alarm that leaves the log going; GkmAuthView.At answers through it; and reads race the log's
// one applying goroutine safely.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A network whose log keeps a state every interval positions, its reader under test built with those settings.
func newTestConfigNetEvery(t testing.TB, interval int) *testConfigNet {
	net := newTestConfigNet(t)
	settings := testConfigLogSettings()
	settings.StateAtCheckpointInterval = interval
	log, err := NewConfigLog(settings, net.signedGenesis)
	if err != nil {
		t.Fatal(err)
	}
	for _, entryBytes := range net.entries {
		if _, err := log.Apply(entryBytes, net.source); err != nil {
			t.Fatal(err)
		}
	}
	net.log = log
	net.statesAt = map[uint64]*ConfigState{0: net.statesAt[0], net.n: log.State()}
	return net
}

// Admits a fresh member and one device of it at the tip, signed by the owner, so states differ by rows.
func (self *testConfigNet) admitMemberDevice(label string) testConfigDevice {
	self.t.Helper()
	memberId := testConfigId(label + " member")
	self.admitMember(self.owner, memberId, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	device := self.device(label+" device", memberId)
	self.admitDevice(self.owner, device, 0)
	return device
}

// What StateAt answers at k must be the state the log published at k: its pin, rows and open proposals.
func testConfigStateAtEqual(t *testing.T, net *testConfigNet, k uint64) {
	t.Helper()
	want := net.statesAt[k]
	got, err := net.log.StateAt(want.Pin())
	if err != nil {
		t.Fatalf("StateAt(%d): %v", k, err)
	}
	testConfigStatesEqual(t, got, want)
	if got.TimeMs() != want.TimeMs() || got.RetentionPoint() != want.RetentionPoint() {
		t.Errorf("StateAt(%d): time %d and %d, retention %d and %d", k, got.TimeMs(), want.TimeMs(), got.RetentionPoint(), want.RetentionPoint())
	}
}

// StateAt serves the previous base, the tip and every position between, kept or rebuilt; a pin above the tip waits;
// one before the previous base is unjudged; and one off the chain is a fork alarm with its evidence.
func TestStateAtServesThePreviousBaseToTheTip(t *testing.T) {
	net := newTestConfigNetEvery(t, 4)
	for i := range 6 {
		net.admitMemberDevice(string(rune('a' + i)))
	}
	previousBase := net.n + 1
	if verdict := net.fold(net.owner, net.n, 2); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	for i := range 5 {
		net.admitMemberDevice(string(rune('k' + i)))
	}
	net.tick(&bridge.ApiTick{})
	if verdict := net.fold(net.owner, net.n-3, 3); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	for i := range 3 {
		net.admitMemberDevice(string(rune('s' + i)))
	}
	if base := net.log.State().previousBase; base == nil || base.n != previousBase {
		t.Fatalf("the previous base is not at %d", previousBase)
	}

	for k := previousBase; k <= net.n; k += 1 {
		testConfigStateAtEqual(t, net, k)
	}

	ahead := &bridge.AuthPin{Version: net.n + 1, Chain: make([]byte, sha256.Size)}
	if _, err := net.log.StateAt(ahead); !errors.Is(err, ErrConfigPinAhead) || !errors.Is(err, ErrGkmAuthAhead) {
		t.Errorf("a pin above the tip: %v", err)
	}
	below := net.statesAt[previousBase-1].Pin()
	if _, err := net.log.StateAt(below); !errors.Is(err, ErrConfigPinNotRetained) || !errors.Is(err, ErrGkmAuthNotRetained) {
		t.Errorf("a pin before the previous base: %v", err)
	}

	forged := proto.Clone(net.statesAt[previousBase+2].Pin()).(*bridge.AuthPin)
	forged.Chain[0] ^= 0xff
	_, err := net.log.StateAt(forged)
	fork := &ConfigForkError{}
	if !errors.Is(err, ErrConfigPinOffChain) || !errors.Is(err, ErrGkmAuthOffChain) || !errors.As(err, &fork) {
		t.Fatalf("a pin off the chain: %v", err)
	}
	wantChain := net.statesAt[previousBase+2].chain
	if fork.N != previousBase+2 || fork.LocalChain != wantChain || !bytes.Equal(fork.RemoteChain[:], forged.GetChain()) {
		t.Errorf("the evidence: %+v", fork)
	}
	if net.log.Fork() != nil {
		t.Error("a presented pin stopped the log")
	}
	net.admitMemberDevice("after the alarm")

	// the tip's own pin off the chain, and one before the window that the state still holds A_k for
	tipForged := proto.Clone(net.log.Pin()).(*bridge.AuthPin)
	tipForged.Chain[31] ^= 0x01
	if _, err := net.log.StateAt(tipForged); !errors.Is(err, ErrConfigPinOffChain) {
		t.Errorf("the tip off the chain: %v", err)
	}
	if _, err := net.log.StateAt(&bridge.AuthPin{Version: 1, Chain: make([]byte, 7)}); !errors.Is(err, ErrConfigPinOffChain) {
		t.Errorf("a malformed pin: %v", err)
	}
}

// Every state StateAt serves, kept or rebuilt, equals the one the log published, whatever the interval, through
// statements, refusals, ticks, proposals and bases.
func TestStateAtRebuildsTheStatesTheLogPublished(t *testing.T) {
	for _, interval := range []int{1, 3, 64} {
		net := newTestConfigNetEvery(t, interval)
		worker := net.device("worker", net.ownerMemberId)
		net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(worker, nil, true, net.timeMs+60*60*1000, 0))
		for i := range 4 {
			net.admitMemberDevice(string(rune('a' + i)))
		}
		net.post(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("a member"))
		net.post(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("a member"))
		net.tick(&bridge.ApiTick{ReapedSidecarIds: [][]byte{worker.sidecarId.Bytes()}})
		net.tick(&bridge.ApiTick{ReapedSidecarIds: [][]byte{testConfigId("nobody").Bytes()}})
		for k := uint64(0); k <= net.n; k += 1 {
			testConfigStateAtEqual(t, net, k)
		}
		// again, from the rebuild cache
		for k := net.n; 0 < k; k -= 1 {
			testConfigStateAtEqual(t, net, k)
		}
	}
}

// GkmAuthView.At answers through StateAt, at any state of the log: an older state reaches back, and a pin above it
// waits even when the log is further on.
func TestConfigStateAtAnswersGkmViewsThroughTheLog(t *testing.T) {
	net := newTestConfigNetEvery(t, 2)
	for i := range 5 {
		net.admitMemberDevice(string(rune('a' + i)))
	}
	older := net.statesAt[net.n-2]
	view, err := older.At(net.statesAt[net.n-5].Pin())
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(view.Pin(), net.statesAt[net.n-5].Pin()) {
		t.Errorf("the view's pin %v", view.Pin())
	}
	if _, err := older.At(net.log.Pin()); !errors.Is(err, ErrGkmAuthAhead) {
		t.Errorf("a pin above the older state: %v", err)
	}
	// a state no log made answers its own pin alone
	lone := configCopyState(net.log.State())
	lone.history = nil
	if _, err := lone.At(net.statesAt[net.n-1].Pin()); !errors.Is(err, ErrGkmAuthNotRetained) {
		t.Errorf("a lone state: %v", err)
	}
}

// A log restored at a base never built the states before it, so its window starts there: a pin between the
// previous base and the restored one is unjudged, and every pin from the base on is served.
func TestStateAtOnARestoredLogStartsAtItsBase(t *testing.T) {
	net := newTestConfigNet(t)
	for i := range 3 {
		net.admitMemberDevice(string(rune('a' + i)))
	}
	net.fold(net.owner, net.n, 2)
	between := net.n + 1
	net.admitMemberDevice("between")
	base := net.n + 1
	net.fold(net.owner, net.n, 3)
	net.admitMemberDevice("after")

	restored, err := RestoreConfigLog(testConfigLogSettings(), net.log.Retained(), net.source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restored.StateAt(net.statesAt[between].Pin()); !errors.Is(err, ErrConfigPinNotRetained) {
		t.Errorf("a pin before the restored base: %v", err)
	}
	for k := base; k <= net.n; k += 1 {
		got, err := restored.StateAt(net.statesAt[k].Pin())
		if err != nil {
			t.Fatalf("StateAt(%d): %v", k, err)
		}
		testConfigStatesEqual(t, got, net.statesAt[k])
	}
}

// Reads at every position race the log's applying goroutine and each other, under -race, and each answer is the
// published state or a wait.
func TestStateAtReadsRaceTheLog(t *testing.T) {
	net := newTestConfigNetEvery(t, 3)
	for i := range 4 {
		net.admitMemberDevice(string(rune('a' + i)))
	}
	pins := []*bridge.AuthPin{}
	for k := uint64(1); k <= net.n; k += 1 {
		pins = append(pins, net.statesAt[k].Pin())
	}
	var group sync.WaitGroup
	for reader := range 4 {
		group.Add(1)
		go func() {
			defer group.Done()
			for round := range 50 {
				pin := pins[(reader+round)%len(pins)]
				state, err := net.log.StateAt(pin)
				if err != nil && !errors.Is(err, ErrConfigPinNotRetained) {
					t.Errorf("StateAt(%d): %v", pin.GetVersion(), err)
					return
				}
				if err == nil && !proto.Equal(state.Pin(), pin) {
					t.Errorf("StateAt(%d) gave %d", pin.GetVersion(), state.n)
					return
				}
			}
		}()
	}
	for i := range 6 {
		net.admitMemberDevice(string(rune('k' + i)))
	}
	group.Wait()
}
