package sidecartest

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
)

func newTestNet(t *testing.T) *Net {
	net := NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	return net
}

// Waits for one message. Real time bounds it only so a broken link fails rather than hangs.
func awaitMessage(t *testing.T, messages <-chan *NetMessage) *NetMessage {
	t.Helper()
	select {
	case message := <-messages:
		return message
	case <-time.After(45 * time.Second):
		t.Fatal("no message came")
		return nil
	}
}

// Q-TEST-1 end to end: two Required clients on the exported API alone, a real TLS session between
// them, and a canary that reaches the peer and appears in no frame on the way.
func TestNetDeliversOnlySealedFrames(t *testing.T) {
	net := newTestNet(t)
	a := net.AddClient("a", nil)
	b := net.AddClient("b", nil)
	messages := make(chan *NetMessage, 16)
	defer b.ReceiveMessages(messages)()

	canary := net.Capture().Canary("message body")
	if err := a.SendMessage(b.ClientId, canary); err != nil {
		t.Fatal(err)
	}
	message := awaitMessage(t, messages)
	if message.Content != canary || message.Source != a.ClientId {
		t.Errorf("message %+v", message)
	}
	if !a.Sealed(b.ClientId) {
		t.Error("the sender has no sealed session")
	}
	if net.Capture().ItemCount("CC2") == 0 {
		t.Fatal("the capture saw no frames, so a clean scan proves nothing")
	}
	if hits := net.Capture().Scan(); len(hits) != 0 {
		t.Errorf("hits %v", hits)
	}
}

func TestNetClientsOtherThanRequiredPanic(t *testing.T) {
	net := newTestNet(t)
	settings := netClientSettings()
	settings.EncryptionSettings.Mode = connect.EncryptionModeOpportunistic
	defer func() {
		if recover() == nil {
			t.Error("an Opportunistic client started")
		}
	}()
	net.AddClient("a", settings)
}

func TestNetSidecarRunsTheModeItsSettingsShip(t *testing.T) {
	net := newTestNet(t)
	settings := sidecar.DefaultSidecarSettings()
	testSidecar := net.AddSidecar("laptop", settings)
	if testSidecar.Client == nil || testSidecar.Settings != settings {
		t.Fatalf("sidecar %+v", testSidecar)
	}

	other := net.AddSidecar("phone", nil)
	messages := make(chan *NetMessage, 16)
	defer other.Client.ReceiveMessages(messages)()
	if err := testSidecar.Client.SendMessage(other.Client.ClientId, "hello"); err != nil {
		t.Fatal(err)
	}
	if message := awaitMessage(t, messages); message.Content != "hello" {
		t.Errorf("message %+v", message)
	}
}

func TestNetPartitionHoldsTrafficAndHealingLetsItThrough(t *testing.T) {
	net := newTestNet(t)
	a := net.AddClient("a", nil)
	b := net.AddClient("b", nil)
	messages := make(chan *NetMessage, 16)
	defer b.ReceiveMessages(messages)()

	if err := a.SendMessage(b.ClientId, "before"); err != nil {
		t.Fatal(err)
	}
	awaitMessage(t, messages)

	net.SetLink(a.ClientId, b.ClientId, &LinkConditions{Partition: true})
	if err := a.SendMessage(b.ClientId, "during"); err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-messages:
		t.Fatalf("crossed a partition: %+v", message)
	default:
	}

	net.SetLink(a.ClientId, b.ClientId, nil)
	// connect's reliable sequence resends what the partition dropped
	if message := awaitMessage(t, messages); message.Content != "during" {
		t.Errorf("message %+v", message)
	}
}

func TestNetLinkCarriesItsTransportType(t *testing.T) {
	net := newTestNet(t)
	a := net.AddClient("a", nil)
	b := net.AddClient("b", nil)
	messages := make(chan *NetMessage, 16)
	defer b.ReceiveMessages(messages)()

	net.SetLink(a.ClientId, b.ClientId, &LinkConditions{TransportType: connect.TransportTypeP2p})
	if err := a.SendMessage(b.ClientId, "direct"); err != nil {
		t.Fatal(err)
	}
	if message := awaitMessage(t, messages); message.TransportType != connect.TransportTypeP2p {
		t.Errorf("message %+v", message)
	}
}

func TestNetLossyLinkStillDelivers(t *testing.T) {
	net := newTestNet(t)
	a := net.AddClient("a", nil)
	b := net.AddClient("b", nil)
	messages := make(chan *NetMessage, 64)
	defer b.ReceiveMessages(messages)()
	net.SetLink(a.ClientId, b.ClientId, &LinkConditions{LossProbability: 0.2})

	for index := range 5 {
		if err := a.SendMessage(b.ClientId, fmt.Sprintf("message-%d", index)); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	for len(seen) < 5 {
		seen[awaitMessage(t, messages).Content] = true
	}
}

func TestNetHostDefaultsToTheFakesAndRecordsBlobs(t *testing.T) {
	net := newTestNet(t)
	cluster, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(t.Context(), "head/a/_", []byte("v1"), nil); err != nil {
		t.Fatal(err)
	}
	if history := net.BlobHistory(); len(history) != 1 || history[0].Key != "head/a/_" {
		t.Errorf("history %v", history)
	}
	if got := net.Fakes().Blobs.RequestCount("meta-1", FaultOpPut); got != 1 {
		t.Errorf("the fake served %d", got)
	}
}

func TestNetAddEnginesTakesAnotherHost(t *testing.T) {
	net := newTestNet(t)
	other := NewFakeBlobs(net.Clock(), nil, nil, nil)
	host := *net.Fakes().ServiceHost()
	host.Blobs = other
	net.AddEngines(&host)
	cluster, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(t.Context(), "head/a/_", []byte("v1"), nil); err != nil {
		t.Fatal(err)
	}
	if got := other.RequestCount("meta-1", FaultOpPut); got != 1 {
		t.Errorf("served %d", got)
	}
}

type countingEngine struct {
	closed int
}

func (self *countingEngine) Ready() bool { return true }
func (self *countingEngine) Drain()      {}
func (self *countingEngine) Close()      { self.closed += 1 }

func TestNetClosesLiveEnginesAndNotAKilledOne(t *testing.T) {
	net := NewNet(t.Context(), nil)
	engines := []*countingEngine{}
	build := func(ctx any, host *sidecar.ServiceHost) *countingEngine {
		engine := &countingEngine{}
		engines = append(engines, engine)
		return engine
	}
	for _, name := range []string{"evs1", "evs2"} {
		if _, err := net.AddEngine(name, func(ctx contextForTest, host *sidecar.ServiceHost) (sidecar.Engine, error) {
			return build(ctx, host), nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := net.Kill("evs1"); err != nil {
		t.Fatal(err)
	}
	if net.Process("evs1") != nil {
		t.Error("a dead process kept its memory")
	}
	net.Close()
	if engines[0].closed != 0 {
		t.Error("a killed engine got a clean shutdown")
	}
	if engines[1].closed != 1 {
		t.Errorf("closed %d", engines[1].closed)
	}
}

func TestNetRestartRebuildsFromTheBuilderOnAnInstance(t *testing.T) {
	net := newTestNet(t)
	built := []string{}
	if _, err := net.AddProcess("evs1", func(ctx contextForTest, instance string) (any, error) {
		built = append(built, instance)
		return instance, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := net.Kill("evs1"); err != nil {
		t.Fatal(err)
	}
	if err := net.Restart("evs1", "evs2"); err != nil {
		t.Fatal(err)
	}
	if net.Process("evs2") != "evs2" || net.Process("evs1") != nil {
		t.Errorf("evs1 %v evs2 %v", net.Process("evs1"), net.Process("evs2"))
	}
	if len(built) != 2 || built[1] != "evs2" {
		t.Errorf("built %v", built)
	}
}

func TestNetRestartPassesABuilderFailureBack(t *testing.T) {
	net := newTestNet(t)
	builds := 0
	if _, err := net.AddProcess("evs1", func(ctx contextForTest, instance string) (any, error) {
		builds += 1
		if builds == 2 {
			return nil, errors.New("durable state unreadable")
		}
		return "evs", nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := net.Kill("evs1"); err != nil {
		t.Fatal(err)
	}
	if err := net.Restart("evs1", "evs1"); err == nil {
		t.Error("a failed rebuild passed")
	}
}

func TestNetKillOfNobodyFails(t *testing.T) {
	net := newTestNet(t)
	if err := net.Kill("nobody"); err == nil {
		t.Error("killed nobody")
	}
}

func TestNetDriveCountersReadBack(t *testing.T) {
	net := newTestNet(t)
	if net.DriveCounters("meta-1") != nil {
		t.Error("counters before any were set")
	}
	counters := &DriveCounters{ClusterId: "meta-1", Drives: []*DriveCounter{{DriveId: "nvme0n1", SectorsWritten: 8}}}
	net.SetDriveCounters(counters)
	if net.DriveCounters("meta-1") != counters {
		t.Error("counters did not read back")
	}
}
