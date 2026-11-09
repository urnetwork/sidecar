package sidecartest

import (
	"errors"
	"testing"

	"github.com/urnetwork/sidecar"
)

// The fake answers by the table's rules and records each call with its interactive flag.
func TestFakeNetworkLabelsResolvesAndRecords(t *testing.T) {
	labels := NewFakeNetworkLabels()
	networkId := sidecar.NewId()
	if err := labels.Set(sidecar.NetworkLabelRow{Root: "zone.example", NetworkId: networkId, Label: "k7q2m9x4a1", LegacyName: "team-name"}); err != nil {
		t.Fatal(err)
	}
	if resolved, kind, err := labels.ResolveNetworkLabel("zone.example", "k7q2m9x4a1", false); err != nil || resolved != networkId || kind != sidecar.NetworkLabelKindLabel {
		t.Fatalf("resolved %s %q (%v)", resolved, kind, err)
	}
	if _, _, err := labels.ResolveNetworkLabel("zone.example", "team-name", false); !errors.Is(err, sidecar.ErrNetworkLabelUnknown) {
		t.Fatalf("a legacy name answered a caller that is not interactive: %v", err)
	}
	if err := labels.Set(sidecar.NetworkLabelRow{Root: "zone.example", NetworkId: sidecar.NewId(), Label: "k7q2m9x4a1"}); err == nil {
		t.Fatal("two networks took one label")
	}
	if err := labels.Remove(networkId); err != nil {
		t.Fatal(err)
	}
	if _, _, err := labels.ResolveNetworkLabel("zone.example", "", true); !errors.Is(err, sidecar.ErrNetworkLabelUnknown) {
		t.Fatalf("a client of no network answered %v", err)
	}
	calls := labels.Calls()
	if len(calls) != 3 || calls[0].Interactive || calls[1].Text != "team-name" || !calls[2].Interactive {
		t.Fatalf("calls %+v", calls)
	}
}
