//go:build !sidecar_http

package sidecar

import (
	"testing"

	"github.com/urnetwork/connect"
)

// The two methods, verbatim, which ACL's gate view, TLS's listen facts, DNS's record writes and SMTP's
// send gate are written against. Assigning to these stops the build if one drifts.
var (
	_ func(AbuseGate, connect.Id) (AbuseStanding, bool) = AbuseGate.Standing
	_ func(AbuseGate, connect.Id) (bool, bool)          = AbuseGate.Verified
	_ AbuseGate                                         = UnloadedAbuseGate{}
)

// A loaded network in one fixed state, for the host's own tests.
type hostAbuseGate struct {
	networkId connect.Id
	standing  AbuseStanding
	verified  bool
}

func (self hostAbuseGate) Standing(networkId connect.Id) (AbuseStanding, bool) {
	if networkId != self.networkId {
		return "", false
	}
	return self.standing, true
}

func (self hostAbuseGate) Verified(networkId connect.Id) (bool, bool) {
	if networkId != self.networkId {
		return false, false
	}
	return self.verified, true
}

// A host that sets no gate has loaded no network, so every gate that reads it refuses (I-12): no
// standing, no verification, and never a pass.
func TestAHostWithNoAbuseGateHasLoadedNoNetwork(t *testing.T) {
	host := &ServiceHost{}
	gate := host.AbuseOrUnloaded()
	for _, networkId := range []connect.Id{{}, connect.NewId()} {
		if standing, ok := gate.Standing(networkId); ok || standing != "" {
			t.Errorf("standing %q, %v", standing, ok)
		}
		if verified, ok := gate.Verified(networkId); ok || verified {
			t.Errorf("verified %v, %v", verified, ok)
		}
	}
}

// A host's own gate is the one its engines read.
func TestAHostsAbuseGateReachesItsEngines(t *testing.T) {
	networkId := connect.NewId()
	host := &ServiceHost{Abuse: hostAbuseGate{networkId: networkId, standing: AbuseStandingTrusted, verified: true}}
	gate := host.AbuseOrUnloaded()
	if standing, ok := gate.Standing(networkId); !ok || standing != AbuseStandingTrusted {
		t.Errorf("standing %q, %v", standing, ok)
	}
	if verified, ok := gate.Verified(networkId); !ok || !verified {
		t.Errorf("verified %v, %v", verified, ok)
	}
	if _, ok := gate.Standing(connect.NewId()); ok {
		t.Error("another network read as loaded")
	}
}
