//go:build !sidecar_http

package sidecar

import (
	"os"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/urnetwork/connect"
)

// The bucket every percent gate reads, pinned by testdata/gates/table.yml, which server's
// SidecarGateBucket answers too: a network's place in a rollout never moves.
func TestServiceGateBucketHoldsTheTablesVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/gates/table.yml")
	if err != nil {
		t.Fatal(err)
	}
	table := struct {
		Buckets map[string]int `yaml:"buckets"`
	}{}
	if err := yaml.Unmarshal(data, &table); err != nil {
		t.Fatal(err)
	}
	if len(table.Buckets) < 4 {
		t.Fatalf("the table pins %d buckets", len(table.Buckets))
	}
	for idStr, want := range table.Buckets {
		networkId, err := connect.ParseId(idStr)
		if err != nil {
			t.Fatal(err)
		}
		if got := ServiceGateBucket(networkId); got != want {
			t.Errorf("%s is in bucket %d, not the table's %d", idStr, got, want)
		}
	}
}

// Every bucket is in 0 to 99, whatever the id.
func TestServiceGateBucketIsAPercent(t *testing.T) {
	for range 1000 {
		if bucket := ServiceGateBucket(connect.NewId()); bucket < 0 || 99 < bucket {
			t.Fatalf("bucket %d", bucket)
		}
	}
}

// The one rule: enabled, and listed or under the percent; listed beats percent; enabled false closes
// even a listed network.
func TestServiceGateAdmitsByListOrBucket(t *testing.T) {
	networkId := connect.NewId()
	bucket := ServiceGateBucket(networkId)
	for _, c := range []struct {
		gate   ServiceGate
		admits bool
	}{
		{gate: NewServiceGate(true, true, nil, bucket+1), admits: true},
		{gate: NewServiceGate(true, true, nil, bucket), admits: false},
		{gate: NewServiceGate(true, true, []connect.Id{networkId}, 0), admits: true},
		{gate: NewServiceGate(false, true, []connect.Id{networkId}, 100), admits: false},
		{gate: NewServiceGate(true, true, nil, 100), admits: true},
		{gate: NewServiceGate(true, true, nil, 0), admits: false},
		{gate: ServiceGate{}, admits: false},
	} {
		if got := c.gate.Admits(networkId); got != c.admits {
			t.Errorf("%+v admits %t, want %t", c.gate, got, c.admits)
		}
	}
}

// A percent outside 0 to 100 reads 0, so a typo opens nothing.
func TestServiceGatePercentOutOfRangeReadsZero(t *testing.T) {
	for _, percent := range []int{-1, 101, 1000} {
		gate := NewServiceGate(true, true, nil, percent)
		if gate.Percent() != 0 {
			t.Errorf("percent %d reads %d", percent, gate.Percent())
		}
		for range 100 {
			if gate.Admits(connect.NewId()) {
				t.Fatalf("percent %d admits a network", percent)
			}
		}
	}
}

// writes is the incident switch, and a closed gate takes no writes either.
func TestServiceGateWritesNeedTheGateOpen(t *testing.T) {
	if !NewServiceGate(true, true, nil, 0).Writes() {
		t.Error("an open gate with writes on refuses writes")
	}
	if NewServiceGate(true, false, nil, 0).Writes() {
		t.Error("writes: false takes writes")
	}
	if NewServiceGate(false, true, nil, 0).Writes() {
		t.Error("a closed gate takes writes")
	}
}

// Only exactly `on` deletes.
func TestFormat2ModesDeleteOnlyWhenOn(t *testing.T) {
	for mode, want := range map[string]Format2Mode{"on": Format2On, "On": Format2Observe, "ON": Format2Observe, "true": Format2Observe, "": Format2Observe, "observe": Format2Observe} {
		gate := NewFormat2Gate(ServiceGate{}, mode, mode)
		if gate.Purge() != want || gate.Drop() != want {
			t.Errorf("%q reads purge %s drop %s, want %s", mode, gate.Purge(), gate.Drop(), want)
		}
	}
	if (Format2Gate{}).Purge() != Format2Observe || (Format2Gate{}).Drop() != Format2Observe {
		t.Error("the zero gate deletes")
	}
}

// A host with no gates answers every gate closed, never a nil to call.
func TestAHostWithNoGatesIsClosed(t *testing.T) {
	gates := (&ServiceHost{}).GatesOrClosed()
	networkId := connect.NewId()
	if gates.Service(ServiceGateEvs).Admits(networkId) || gates.Format2().Admits(networkId) || gates.Switch(GateSwitchPush) ||
		gates.Reseed() || gates.PlaceNew() != "" || len(gates.Drained()) != 0 || gates.FileCluster("meta-1") != (FileClusterGate{}) {
		t.Fatal("a host with no gates opens one")
	}
	if _, _, ok := gates.SocketsControlQps(); ok {
		t.Fatal("a host with no gates sets the control rate")
	}
	if _, ok := gates.UrnetworkEdge(); ok {
		t.Fatal("a host with no gates names the platform network")
	}
	if gates.RetryAfter() != 60*time.Second {
		t.Fatalf("retry after %s", gates.RetryAfter())
	}
	opened := &ServiceHost{Gates: ClosedServiceGates{}}
	if _, ok := opened.GatesOrClosed().(ClosedServiceGates); !ok {
		t.Fatal("a host's own gates were not the ones answered")
	}
}

// A host with no clock gives its engines real time (TEST-M0-02).
func TestAHostWithNoClockReadsRealTime(t *testing.T) {
	if _, ok := (&ServiceHost{}).ClockOrReal().(RealClock); !ok {
		t.Fatal("a host with no clock reads something other than real time")
	}
	clock := fixedClock{at: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	if got := (&ServiceHost{Clock: clock}).ClockOrReal().Now(); !got.Equal(clock.at) {
		t.Fatalf("read %s, want the host's %s", got, clock.at)
	}
}
