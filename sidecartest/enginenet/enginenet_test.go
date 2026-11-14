// The engine world's own seams on an admission network whose log api holds: the exchange's scopes come from the gate's
// state of the token's network, a network the gate has not loaded answers a server error and is asked for, and a
// bootstrap window answers in the gate's place for its network alone, honoring its bootstrapping device on its config
// repo and nothing else.

package enginenet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The exchange's scopes for the owner's device: refused with a server error until the gate holds the network, then
// §8's table at the gate's state, which grants the config's r and refuses a repo the state does not hold.
func TestEnginesScopesComeFromTheGatesState(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	tier, err := net.AdmissionTier()
	if err != nil {
		t.Fatal(err)
	}
	tier.AclCompile = sidecartest.AclAdmissionCompile
	network := sidecartest.NewAdmissionNet(t, tier)
	t.Cleanup(network.Close)
	engines := NewEngines(t, net, nil)
	owner := network.Owner().SidecarId
	configScope := "repo:" + network.ConfigRepoId().String() + ":r"
	unknownScope := "repo:" + sidecar.NewId().String() + ":r"
	request := &sidecartest.FakeApiScopeRequest{
		NetworkId: network.NetworkId(), SidecarId: &owner, Audience: "evs", Scopes: []string{configScope, unknownScope},
	}
	if _, err := engines.exchangeScopes(ctx, request); err == nil || errors.Is(err, sidecartest.ErrFakeApiInvalidScope) {
		t.Fatalf("scopes before the gate holds the network: %v", err)
	}
	if err := engines.Sync(ctx, network.NetworkId()); err != nil {
		t.Fatal(err)
	}
	grant, err := engines.exchangeScopes(ctx, request)
	if err != nil || !slices.Equal(grant.Scopes, []string{configScope}) || grant.ProjVersion != network.Tip().GetVersion() {
		t.Fatalf("the gate's scopes: %+v %v", grant, err)
	}
	if grant.MemberId == nil || *grant.MemberId != network.Owner().MemberId {
		t.Fatal("the grant names no member")
	}
}

// A bootstrap window answers for its network alone: its device takes every role on the config repo and nothing else,
// another sidecar takes nothing, gkm and evs honor the device on the config repo alone and pin only the genesis state's
// pin, evs's push views read that state, and another network's requests go to the real gate, which has loaded nothing
// of it.
func TestEnginesBootstrapWindowHonorsItsDeviceAlone(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	engines := NewEngines(t, net, nil)
	windowNetworkId, deviceId, otherId, configRepoId := sidecar.NewId(), sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	deviceKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x6e}, ed25519.SeedSize))
	genesisBody, err := enginesMarshal(&bridge.Genesis{
		NetworkId: windowNetworkId.Bytes(), ConfigRepoId: configRepoId.Bytes(), OwnerMemberId: sidecar.NewId().Bytes(),
		OwnerSidecarId: deviceId.Bytes(), OwnerIdentityPublicKey: deviceKey.Public().(ed25519.PublicKey),
		TimeMs: net.Clock().Now().UnixMilli(),
	})
	if err != nil {
		t.Fatal(err)
	}
	signedGenesis, err := enginesMarshal(&bridge.Signed{
		Body:      genesisBody,
		SignerId:  deviceId.Bytes(),
		Signature: ed25519.Sign(deviceKey, bridge.SignedBytes(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_GENESIS, genesisBody)),
		Type:      uint32(bridge.SignedType_SIGNED_GENESIS),
	})
	if err != nil {
		t.Fatal(err)
	}
	logSettings := sidecar.DefaultConfigLogSettings()
	logSettings.Log = sidecar.NewNoopLogger()
	genesisLog, err := sidecar.NewConfigLog(logSettings, signedGenesis)
	if err != nil {
		t.Fatal(err)
	}
	engines.windows[windowNetworkId] = &bootstrapWindow{
		networkId: windowNetworkId, sidecarId: deviceId, memberId: sidecar.NewId(), configRepoId: configRepoId,
		identityKey: deviceKey.Public().(ed25519.PublicKey), genesisState: genesisLog.State(),
	}
	principal := func(networkId sidecar.Id, sidecarId sidecar.Id) *sidecar.Principal {
		connectSidecarId := connect.Id(sidecarId)
		return &sidecar.Principal{NetworkId: connect.Id(networkId), ClientId: connect.Id(sidecar.NewId()), SidecarId: &connectSidecarId}
	}

	configScopes := []string{"repo:" + configRepoId.String() + ":admin", "repo:" + configRepoId.String() + ":rw"}
	if grant, err := engines.exchangeScopes(ctx, &sidecartest.FakeApiScopeRequest{
		NetworkId: windowNetworkId, SidecarId: &deviceId, Audience: "gkm", Scopes: configScopes,
	}); err != nil || !slices.Equal(grant.Scopes, configScopes) {
		t.Fatalf("the device's config scopes: %+v %v", grant, err)
	}
	if _, err := engines.exchangeScopes(ctx, &sidecartest.FakeApiScopeRequest{
		NetworkId: windowNetworkId, SidecarId: &deviceId, Audience: "evs", Scopes: []string{"repo:" + sidecar.NewId().String() + ":r"},
	}); !errors.Is(err, sidecartest.ErrFakeApiInvalidScope) {
		t.Fatalf("another repo's scope in the window: %v", err)
	}
	if _, err := engines.exchangeScopes(ctx, &sidecartest.FakeApiScopeRequest{
		NetworkId: windowNetworkId, SidecarId: &otherId, Audience: "evs", Scopes: configScopes[:1],
	}); !errors.Is(err, sidecartest.ErrFakeApiInvalidScope) {
		t.Fatalf("another sidecar's scope in the window: %v", err)
	}

	gkm, evs := engines.gkmState, engines.evsState
	device, other := principal(windowNetworkId, deviceId), principal(windowNetworkId, otherId)
	now := net.Clock().Now()
	if gkm.HonorScope(device, configRepoId, sidecar.AclEvsAdmin, now) != gkmservice.GkmAuthAllowed ||
		gkm.HonorScope(device, sidecar.NewId(), sidecar.AclEvsRead, now) != gkmservice.GkmAuthDenied ||
		gkm.HonorScope(other, configRepoId, sidecar.AclEvsRead, now) != gkmservice.GkmAuthDenied {
		t.Fatal("gkm's window honors more than its device on the config repo")
	}
	if facts, answer := gkm.Sidecar(device, deviceId); answer != gkmservice.GkmAuthAllowed || !facts.MemberDevice {
		t.Fatal("gkm's window does not know its device")
	}
	if gkm.CheckPin(device, genesisLog.Pin()) != gkmservice.GkmAuthAllowed ||
		gkm.CheckPin(device, &bridge.AuthPin{Version: 1, Chain: bytes.Repeat([]byte{1}, 32)}) == gkmservice.GkmAuthAllowed {
		t.Fatal("gkm's window pins more than the genesis state")
	}
	if evs.MatchBinding(device) != evsservice.EvsAuthAllowed || evs.MatchBinding(other) != evsservice.EvsAuthDenied {
		t.Fatal("evs's window binds more than its device")
	}
	if facts, answer := evs.Repo(device, configRepoId); answer != evsservice.EvsAuthAllowed || facts.NetworkId != windowNetworkId {
		t.Fatal("evs's window does not hold the config repo")
	}
	if view, answer := engines.evsViews.View(windowNetworkId); answer != evsservice.EvsAuthAllowed || view.Pin().GetVersion() != 0 {
		t.Fatal("evs's push views do not read the window's genesis state")
	}

	// the real gate answers every other network: one it has not loaded is unknown
	elsewhere := sidecar.NewId()
	if gkm.HonorScope(principal(elsewhere, deviceId), configRepoId, sidecar.AclEvsRead, now) != gkmservice.GkmAuthUnknown ||
		evs.MatchBinding(principal(elsewhere, deviceId)) != evsservice.EvsAuthUnknown {
		t.Fatal("a network the gate has not loaded was answered")
	}
}
