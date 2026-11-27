//go:build !ios_extension && !sidecar_http && !js

// The support client on a Sidecar reads its host from the attest component's store (attest_policy_support.go): a
// build from this tree pins no release key, so its store holds no policy, the source names no host, and the client's
// messages wait in its outbox. Off the js test leg, which links no Sidecar test fixture.

package sidecar

import (
	"errors"
	"testing"
)

// A running Sidecar's support client takes its policy source from the store, which names no host with no policy.
func TestSidecarSupportReadsThePolicysSupportLine(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, testSidecarSettings(newTestSidecarPlatform()))
	client, err := sidecar.Support()
	if err != nil {
		t.Fatal(err)
	}
	source, ok := client.currentSources().Policy.(*computePolicySupportSource)
	if !ok || source.sidecar != sidecar {
		t.Fatalf("the client's policy source is %T", client.currentSources().Policy)
	}
	if _, err := source.SupportLine(); !errors.Is(err, errComputePolicySupportAbsent) {
		t.Errorf("a store with no policy: %v", err)
	}
	if _, _, err := client.hostAndToken(t.Context()); SupportRefusalOf(err) != SupportRefusalNoHost {
		t.Errorf("the client with no host: %v", err)
	}
}
