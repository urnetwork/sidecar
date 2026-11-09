package sidecartest

import (
	"testing"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
)

// A network nobody loaded answers ok false for both facts, never a pass (I-12), and so does every
// network of a fresh fake host.
func TestFakeAbuseGateStartsWithNoNetworkLoaded(t *testing.T) {
	host, _, _ := newHostFixture(t)
	for _, gate := range []sidecar.AbuseGate{NewFakeAbuseGate(), host.ServiceHost().AbuseOrUnloaded()} {
		networkId := connect.NewId()
		if standing, ok := gate.Standing(networkId); ok || standing != "" {
			t.Errorf("standing %q, %v", standing, ok)
		}
		if verified, ok := gate.Verified(networkId); ok || verified {
			t.Errorf("verified %v, %v", verified, ok)
		}
	}
}

// What a test loads reads back, per network, and a network it did not load stays unloaded.
func TestFakeAbuseGateReadsBackWhatWasSet(t *testing.T) {
	gate := NewFakeAbuseGate()
	suspendedId := connect.NewId()
	trustedId := connect.NewId()
	otherId := connect.NewId()
	gate.Set(suspendedId, sidecar.AbuseStandingSuspended, false)
	gate.Set(trustedId, sidecar.AbuseStandingTrusted, true)

	for _, c := range []struct {
		networkId    connect.Id
		wantStanding sidecar.AbuseStanding
		wantVerified bool
	}{
		{networkId: suspendedId, wantStanding: sidecar.AbuseStandingSuspended, wantVerified: false},
		{networkId: trustedId, wantStanding: sidecar.AbuseStandingTrusted, wantVerified: true},
	} {
		if standing, ok := gate.Standing(c.networkId); !ok || standing != c.wantStanding {
			t.Errorf("standing %q, %v, want %q", standing, ok, c.wantStanding)
		}
		if verified, ok := gate.Verified(c.networkId); !ok || verified != c.wantVerified {
			t.Errorf("verified %v, %v, want %v", verified, ok, c.wantVerified)
		}
	}
	if _, ok := gate.Standing(otherId); ok {
		t.Error("a network nobody loaded reads as loaded")
	}

	// a later load replaces the earlier one
	gate.SetStanding(suspendedId, sidecar.AbuseStandingStandard)
	if standing, _ := gate.Standing(suspendedId); standing != sidecar.AbuseStandingStandard {
		t.Errorf("standing %q after a reload", standing)
	}
}

// The two facts load apart, as a real gate may load one first, and an unload forgets both.
func TestFakeAbuseGateLoadsEachFactApartAndUnloadsBoth(t *testing.T) {
	gate := NewFakeAbuseGate()
	networkId := connect.NewId()

	gate.SetStanding(networkId, sidecar.AbuseStandingProbation)
	if _, ok := gate.Verified(networkId); ok {
		t.Error("verification loaded with the standing alone")
	}
	gate.SetVerified(networkId, true)
	if standing, ok := gate.Standing(networkId); !ok || standing != sidecar.AbuseStandingProbation {
		t.Errorf("standing %q, %v after loading verification", standing, ok)
	}

	gate.Unload(networkId)
	if _, ok := gate.Standing(networkId); ok {
		t.Error("standing still loaded")
	}
	if _, ok := gate.Verified(networkId); ok {
		t.Error("verification still loaded")
	}
}

// A test may load a standing this build does not know, which a gate then refuses through Known.
func TestFakeAbuseGateHoldsAStandingThisBuildDoesNotKnow(t *testing.T) {
	gate := NewFakeAbuseGate()
	networkId := connect.NewId()
	gate.SetStanding(networkId, sidecar.AbuseStanding("frozen"))
	standing, ok := gate.Standing(networkId)
	if !ok || standing != "frozen" || standing.Known() {
		t.Errorf("standing %q, %v", standing, ok)
	}
}
