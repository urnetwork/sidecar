//go:build !js && !ios && !android && !sdk_mobile_bind

// The fake api's tokens carry server's admin_refused claim (§7.4; owner decision 291, QD-907), as server/session's
// by_jwt does: from the client's mark at mint, kept by bind's re-mint, a refresh and a child, and absent from a client
// with no mark. The daemon's pairing check (sidecar.DaemonPairNetwork, which Sidecar.Pair's check shares) takes a
// marked strict_exp child's token and refuses an unmarked client's, so a schedule that pairs through this api reads
// what server's tokens say. Built where the daemon's pair file is.

package sidecartest

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar"
)

// Requires token to carry admin_refused as a JSON true, or no such claim at all.
func requireFakeApiAdminRefusedClaim(t *testing.T, name string, token string, adminRefused bool) {
	t.Helper()
	claim, present := fakeApiTestClaims(t, token)["admin_refused"]
	if adminRefused && claim != true || !adminRefused && present {
		t.Errorf("%s: admin_refused claim %v (present %t), want %t", name, claim, present, adminRefused)
	}
}

// An enrolled sidecar's token, its re-mint, the re-mint's refresh and the child it mints carry the claim, and the
// child pairs; a client enrolled while the api drops the marks carries none, and does not pair.
func TestFakeApiTokensCarryAdminRefused(t *testing.T) {
	world := newFakeApiTestWorld(t)
	networkId := sidecar.NewId()
	laptop := newCoreRouteClient(t, world, networkId)
	requireFakeApiAdminRefusedClaim(t, "the enrollment's token", laptop.token, true)

	if status, code, _ := laptop.bind(laptop.binding(1)); status != http.StatusOK {
		t.Fatalf("bind: %d %s", status, code)
	}
	requireFakeApiAdminRefusedClaim(t, "bind's re-mint", laptop.reminted, true)
	laptop.token = laptop.reminted
	status, code, refreshed := laptop.refresh(laptop.proof(laptop.clientKey, http.MethodGet, "/auth/refresh"))
	if status != http.StatusOK || refreshed == "" {
		t.Fatalf("refresh: %d %s", status, code)
	}
	requireFakeApiAdminRefusedClaim(t, "the refresh", refreshed, true)

	clientId := laptop.clientId
	child, refusal := laptop.authClient(laptop.clientKey, &fakeApiAuthClientArgs{
		SourceClientId: &clientId, Description: "child", DeviceSpec: "sdk", AdminRefused: true, StrictExp: true,
	})
	if refusal != "" {
		t.Fatalf("a child: %q", refusal)
	}
	requireFakeApiAdminRefusedClaim(t, "the child", child.ByClientJwt, true)
	if named, ok := sidecar.DaemonPairNetwork(child.ByClientJwt); !ok || named != networkId {
		t.Errorf("the child's token names %s for pairing, %t", named, ok)
	}

	world.api.SetEnrollDropsMarks(true)
	_, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	result := &fakeApiEnrollResult{}
	status, enrollRefusal, err := world.call(http.MethodPost, "/network/enroll", "", &fakeApiEnrollArgs{
		AuthKey:         world.api.NewAuthKey(&FakeApiAuthKeyArgs{NetworkId: networkId}),
		ClientPublicKey: clientKey.Public().(ed25519.PublicKey),
		DeviceSpec:      "ur",
		AdminRefused:    true,
		StrictExp:       true,
	}, result)
	if err != nil || status != http.StatusOK || result.AdminRefused {
		t.Fatalf("enroll with the marks dropped: %d %v %v", status, enrollRefusal, err)
	}
	requireFakeApiAdminRefusedClaim(t, "an unmarked enrollment's token", result.ByClientJwt, false)
	if _, ok := sidecar.DaemonPairNetwork(result.ByClientJwt); ok {
		t.Error("an unmarked client's token pairs")
	}
}
