// The fake api's host-client check of a forwarding Delegation, case for case with server's
// TestAForwardingDelegationsHostClientIsCheckedAtApi (TEAM-M8-01; D-TEAM-33): a host client that is not the source
// client of the sidecar's current client, another key for the right client and a host client with no registered key
// are each refused with config_refused; the source client with its registered key is sequenced, and so is a Delegation
// naming no host client.

package sidecartest

import (
	"bytes"
	"crypto/ed25519"
	"net/http"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

func TestFakeApiChecksAForwardingDelegationsHostClient(t *testing.T) {
	world := newFakeApiTestWorld(t)
	env := world.env
	hostClientId, otherClientId, sidecarClientId := configLogSuiteId(), configLogSuiteId(), configLogSuiteId()
	topLevel := world.api.ClientToken(env.networkId, configLogSuiteId(), env.owner.sidecarId)

	genesisChain := bridge.GenesisChain(env.signedGenesis)
	env.tip = &bridge.AuthPin{Version: 0, Chain: genesisChain[:]}
	rows := env.baseOneRows(env.owner)
	pin := &fakeApiConfigPin{}
	status, refusal, err := world.call(http.MethodPost, "/network/config/projection", topLevel, &fakeApiConfigProjectionPublishArgs{
		SignedHeader: env.base(env.owner, env.tip, rows, 0, 1), Rows: rows, Genesis: env.signedGenesis, ConfigPushes: env.configRepo.pushes(0, 1),
	}, pin)
	if err != nil || status != http.StatusOK || pin.N != 1 {
		t.Fatalf("base 1: %d %v %v", status, refusal, err)
	}
	env.tip = &bridge.AuthPin{Version: pin.N, Chain: pin.Chain}

	hostKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	otherKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x32}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	forwardingKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	delegation := func(hostId *sidecar.Id, hostPublicKey []byte) []byte {
		forward := &bridge.ForwardScope{ForwardSidecarId: env.owner.sidecarId.Bytes(), HostClientPublicKey: hostPublicKey}
		if hostId != nil {
			forward.HostClientId = hostId.Bytes()
		}
		return env.sign(env.owner, bridge.SignedType_SIGNED_DELEGATION, &protocol.Delegation{
			Header: env.header(), Pubkey: forwardingKey, ReaderXwingPublicKey: bytes.Repeat([]byte{0x34}, 1216), Forward: forward,
		})
	}
	post := func(bearer string, hostId *sidecar.Id, hostPublicKey []byte) (int, map[string]any) {
		t.Helper()
		world.clock.Advance(time.Second)
		status, refusal, err := world.call(http.MethodPost, "/network/config/delta", bearer, &fakeApiConfigDeltaArgs{Signed: delegation(hostId, hostPublicKey)}, pin)
		if err != nil {
			t.Fatal(err)
		}
		return status, refusal
	}
	refused := func(name string, bearer string, hostId *sidecar.Id, hostPublicKey []byte) {
		t.Helper()
		if status, refusal := post(bearer, hostId, hostPublicKey); status != http.StatusForbidden || refusal["code"] != "config_refused" {
			t.Errorf("%s: %d %v", name, status, refusal)
		}
	}

	// the sidecar's one client is top-level: it has no source client to be a host
	world.api.BindClientKey(otherClientId, otherKey)
	refused("a host client for a top-level sidecar client", topLevel, &otherClientId, otherKey)
	world.api.RemoveClient(world.api.clientOfToken(topLevel).clientId)

	// the sidecar's client on the app device, minted from the device's own client, which has registered no key yet
	child := world.api.ChildClientToken(env.networkId, sidecarClientId, env.owner.sidecarId, hostClientId)
	refused("a host client with no registered key", child, &hostClientId, hostKey)
	world.api.BindClientKey(hostClientId, hostKey)
	refused("another client of the network", child, &otherClientId, otherKey)
	refused("another key for the source client", child, &hostClientId, otherKey)
	refused("a short key for the source client", child, &hostClientId, hostKey[:16])
	refused("a host client key with no host client", child, nil, hostKey)

	if status, refusal := post(child, &hostClientId, hostKey); status != http.StatusOK || pin.N != 2 {
		t.Fatalf("the source client and its registered key: %d %v", status, refusal)
	}
	env.tip = &bridge.AuthPin{Version: pin.N, Chain: pin.Chain}
	if status, refusal := post(child, nil, nil); status != http.StatusOK || pin.N != 3 {
		t.Fatalf("no host client: %d %v", status, refusal)
	}
	env.tip = &bridge.AuthPin{Version: pin.N, Chain: pin.Chain}

	// what the check leaves to the log's rule
	for name, signed := range map[string][]byte{
		"bytes that are no Signed": {0xff, 0xff, 0xff},
		"a MemberAdmit":            env.memberAdmit(),
	} {
		if err := world.api.checkForwardingHost(env.networkId, signed); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
