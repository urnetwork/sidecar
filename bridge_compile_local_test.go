// The compile's local inputs (bridge_compile_local.go; QD-161, DESIGN-DETAILS 12.2.4's bindings): a binding verified
// against the network, the sidecar and the identity key the config admits; a replaced client kept for the retain
// timeout and dropped after it; at most the count a sidecar, the newest kept; an older answer never current again;
// snapshots that do not move under later records; and the cache across its store, a binding that no longer verifies
// dropped at the load.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"
	"time"
)

// A sidecar's binding signed by its identity and client keys, both from labels, at a generation.
func testBridgeSignedBinding(t testing.TB, networkId Id, sidecarId Id, identityLabel string, clientLabel string, generation int64) ([]byte, Id, []byte) {
	t.Helper()
	identitySeed := sha256.Sum256([]byte("bridge binding identity " + identityLabel))
	clientSeed := sha256.Sum256([]byte("bridge binding client " + clientLabel))
	clientDigest := sha256.Sum256([]byte("bridge binding client id " + clientLabel))
	clientId := Id(clientDigest[:len(Id{})])
	signed, err := NewSidecarIdentityBinding(&SidecarIdentityBinding{
		NetworkId: networkId, SidecarId: sidecarId, ClientId: clientId, Generation: generation, IssuedAt: time.UnixMilli(testConfigStartMs),
	}, identitySeed[:], clientSeed[:])
	if err != nil {
		t.Fatal(err)
	}
	identityKey := ed25519.NewKeyFromSeed(identitySeed[:]).Public().(ed25519.PublicKey)
	return signed, clientId, identityKey
}

// A binding verifies only for the network and sidecar asked about, under the identity key the config admits, both
// signatures over the bytes api answered; each mismatch alone is refused beside the binding that passes.
func TestVerifyBridgeBindingHoldsAnAnswerToWhatWasAsked(t *testing.T) {
	networkId, sidecarId := testConfigId("binding network"), testConfigId("binding sidecar")
	signed, clientId, identityKey := testBridgeSignedBinding(t, networkId, sidecarId, "sidecar", "client", 1)
	binding, err := VerifyBridgeBinding(signed, networkId, sidecarId, identityKey)
	if err != nil || binding.ClientId != clientId || binding.Generation != 1 || !bytes.Equal(binding.Signed, signed) || binding.SidecarId != sidecarId {
		t.Fatalf("the binding: %+v, %v", binding, err)
	}
	_, _, otherKey := testBridgeSignedBinding(t, networkId, sidecarId, "another sidecar", "client", 1)
	flipped := bytes.Clone(signed)
	flipped[len(flipped)-1] ^= 1
	refusals := []struct {
		name        string
		signed      []byte
		networkId   Id
		sidecarId   Id
		identityKey []byte
	}{
		{name: "another network", signed: signed, networkId: testConfigId("another network"), sidecarId: sidecarId, identityKey: identityKey},
		{name: "another sidecar", signed: signed, networkId: networkId, sidecarId: testConfigId("another sidecar"), identityKey: identityKey},
		{name: "another identity key", signed: signed, networkId: networkId, sidecarId: sidecarId, identityKey: otherKey},
		{name: "no identity key", signed: signed, networkId: networkId, sidecarId: sidecarId},
		{name: "a flipped signature", signed: flipped, networkId: networkId, sidecarId: sidecarId, identityKey: identityKey},
		{name: "nothing", networkId: networkId, sidecarId: sidecarId, identityKey: identityKey},
	}
	for _, refusal := range refusals {
		if _, err := VerifyBridgeBinding(refusal.signed, refusal.networkId, refusal.sidecarId, refusal.identityKey); !errors.Is(err, ErrSidecarBindingInvalid) {
			t.Errorf("%s: %v", refusal.name, err)
		}
	}
}

// A binding of a fixed client, as the cache holds one; the cache verifies nothing itself.
func testBridgeCacheBinding(sidecarId Id, clientLabel string, generation int64) *BridgeBinding {
	return &BridgeBinding{SidecarId: sidecarId, ClientId: testConfigId(clientLabel), Generation: generation, Signed: []byte(clientLabel)}
}

// QD-161's kept ids: a replaced client stays among the sidecar's ids for BindingRetainTimeout after it stopped being
// current, by the cache's clock, then leaves; an older answer than the current one is kept, never current again.
func TestABindingCacheKeepsAReplacedClientForItsRetainTimeout(t *testing.T) {
	retain := 7 * 24 * time.Hour
	cache := NewBridgeBindingCache(retain, 16)
	sidecarId := testConfigId("cached sidecar")
	start := time.UnixMilli(testConfigStartMs)
	if !cache.Record(testBridgeCacheBinding(sidecarId, "first client", 1), start) {
		t.Fatal("the first binding changed nothing")
	}
	if cache.Record(testBridgeCacheBinding(sidecarId, "first client", 1), start) {
		t.Error("the same binding again changed the cache")
	}
	replacedAt := start.Add(time.Hour)
	cache.Record(testBridgeCacheBinding(sidecarId, "second client", 2), replacedAt)
	first, second := testConfigId("first client"), testConfigId("second client")
	want := slices.SortedFunc(slices.Values([]Id{first, second}), Id.Cmp)
	if got := cache.Snapshot().ClientIds(sidecarId); !slices.Equal(got, want) {
		t.Fatalf("client ids %v, want %v", got, want)
	}
	if current := cache.Current(sidecarId); current == nil || current.ClientId != second {
		t.Fatalf("current %+v", current)
	}

	// an older answer arriving late is kept, not current
	cache.Record(testBridgeCacheBinding(sidecarId, "stale client", 1), replacedAt)
	if current := cache.Current(sidecarId); current.ClientId != second || !slices.Contains(cache.Snapshot().ClientIds(sidecarId), testConfigId("stale client")) {
		t.Fatalf("a stale answer: current %+v, ids %v", current, cache.Snapshot().ClientIds(sidecarId))
	}

	before := cache.Snapshot()
	if cache.Expire(replacedAt.Add(retain - time.Millisecond)) {
		t.Error("an id expired before its retain timeout")
	}
	if !cache.Expire(replacedAt.Add(retain)) {
		t.Fatal("nothing expired at the retain timeout")
	}
	if got := cache.Snapshot().ClientIds(sidecarId); !slices.Equal(got, []Id{second}) {
		t.Errorf("after the retain timeout: %v", got)
	}
	if !slices.Contains(before.ClientIds(sidecarId), first) {
		t.Error("an earlier snapshot moved with the cache")
	}
	if !cache.Forget(sidecarId) || cache.Current(sidecarId) != nil || len(cache.Snapshot().ClientIds(sidecarId)) != 0 {
		t.Error("a forgotten sidecar is held")
	}
}

// BindingMaxCount: a sidecar's ids are at most the count, the current one and the newest kept.
func TestABindingCacheKeepsAtMostItsCountASidecar(t *testing.T) {
	cache := NewBridgeBindingCache(7*24*time.Hour, 3)
	sidecarId := testConfigId("busy sidecar")
	start := time.UnixMilli(testConfigStartMs)
	labels := []string{"client 1", "client 2", "client 3", "client 4", "client 5"}
	for i, label := range labels {
		cache.Record(testBridgeCacheBinding(sidecarId, label, int64(i+1)), start.Add(time.Duration(i)*time.Minute))
	}
	want := slices.SortedFunc(slices.Values([]Id{testConfigId("client 3"), testConfigId("client 4"), testConfigId("client 5")}), Id.Cmp)
	if got := cache.Snapshot().ClientIds(sidecarId); !slices.Equal(got, want) {
		t.Fatalf("client ids %v, want %v", got, want)
	}
}

// The cache across its store: a load holds what the save wrote, each current binding verified again, and one whose
// sidecar's identity key the config no longer admits is dropped while its kept ids stay; nothing stored loads nothing.
func TestABindingCacheSurvivesItsStore(t *testing.T) {
	networkId := testConfigId("stored network")
	kept, dropped := testConfigId("kept sidecar"), testConfigId("dropped sidecar")
	keptSigned, keptClient, keptKey := testBridgeSignedBinding(t, networkId, kept, "kept", "kept client", 1)
	droppedSigned, _, droppedKey := testBridgeSignedBinding(t, networkId, dropped, "dropped", "dropped client", 2)
	start := time.UnixMilli(testConfigStartMs)
	cache := NewBridgeBindingCache(7*24*time.Hour, 16)
	for _, binding := range []struct {
		signed    []byte
		sidecarId Id
		key       []byte
	}{
		{signed: keptSigned, sidecarId: kept, key: keptKey},
		{signed: droppedSigned, sidecarId: dropped, key: droppedKey},
	} {
		verified, err := VerifyBridgeBinding(binding.signed, networkId, binding.sidecarId, binding.key)
		if err != nil {
			t.Fatal(err)
		}
		cache.Record(verified, start)
	}
	cache.Record(testBridgeCacheBinding(kept, "kept old client", 0), start)
	store := newTestConfigClientStore()
	if err := cache.Save(store); err != nil {
		t.Fatal(err)
	}

	loaded := NewBridgeBindingCache(7*24*time.Hour, 16)
	identityKeys := map[Id][]byte{kept: keptKey, dropped: keptKey}
	if err := loaded.Load(store, networkId, func(sidecarId Id) []byte { return identityKeys[sidecarId] }); err != nil {
		t.Fatal(err)
	}
	if current := loaded.Current(kept); current == nil || current.ClientId != keptClient || !bytes.Equal(current.Signed, keptSigned) {
		t.Fatalf("the kept sidecar's binding: %+v", current)
	}
	want := slices.SortedFunc(slices.Values([]Id{keptClient, testConfigId("kept old client")}), Id.Cmp)
	if got := loaded.Snapshot().ClientIds(kept); !slices.Equal(got, want) {
		t.Errorf("the kept sidecar's ids %v, want %v", got, want)
	}
	if loaded.Current(dropped) != nil {
		t.Error("a binding under a key the config no longer admits loaded")
	}

	empty := NewBridgeBindingCache(7*24*time.Hour, 16)
	if err := empty.Load(newTestConfigClientStore(), networkId, func(Id) []byte { return nil }); err != nil || len(empty.Snapshot().ClientIds(kept)) != 0 {
		t.Errorf("an empty store: %v", err)
	}
}
