//go:build !sidecar_http && !js

package sidecar

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

// R-CORE-5 and owner decision 81: a commit names its sidecar by <client_id>@ur.invalid. The writer lists its own
// client ids across generations; a reader resolves a committer that is not the push's own client only through a
// binding that verifies to the push's signer, and refuses the rest (plan-CORE-client-to-sidecar-lookup).

// EVS1-M2-36's pre-receive check reads every generation's client: a re-enrolled sidecar lists its first and second
// clients beside its third, oldest first.
func TestOwnClientIdsAllGenerations(t *testing.T) {
	world := newTestEnrollWorld(t)
	if _, err := world.sidecar.ClientIds(); !errors.Is(err, ErrSidecarNoIdentity) {
		t.Fatalf("before enrollment: %v", err)
	}
	clientIds := []Id{}
	world.platform.connected.Set(true)
	for generation := int64(1); generation <= 3; generation += 1 {
		if err := world.enroll(context.Background()); err != nil {
			t.Fatal(err)
		}
		awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOnline, generation))
		opened := world.platform.awaitOpened(t, int(generation))
		identity := world.sidecar.currentIdentity()
		clientIds = append(clientIds, identity.ClientId)
		listed, err := world.sidecar.ClientIds()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(listed, clientIds) {
			t.Fatalf("generation %d lists %v, want %v", generation, listed, clientIds)
		}
		if generation < 3 {
			world.sidecar.runningGeneration().tokenManager.Load().end(SidecarReasonRefused)
			awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateUnenrolled, generation))
			<-opened.closed
		}
	}
	// a restart reads the same list from the keychain
	secrets := world.instance.secrets(world.api.networkId, sidecarCoreSecretsNamespace)
	clients, err := loadSidecarClientIds(secrets)
	if err != nil || len(clients) != 3 || clients[2].generation != 3 || clients[0].clientId != clientIds[0] {
		t.Fatalf("the record: %+v %v", clients, err)
	}
}

// The record keeps generations rising, takes a generation bound again after a kill in its first try's place, and
// refuses bytes that are not one record.
func TestClientIdsRecordForm(t *testing.T) {
	_, instance, _ := newIdentityTestSidecar(t)
	networkId := testBindingFields().NetworkId
	secrets := instance.secrets(networkId, sidecarCoreSecretsNamespace)
	first, second, again := NewId(), NewId(), NewId()
	for _, step := range []struct {
		generation int64
		clientId   Id
	}{{generation: 2, clientId: first}, {generation: 3, clientId: second}, {generation: 3, clientId: again}} {
		if err := rememberSidecarClientId(secrets, step.generation, step.clientId); err != nil {
			t.Fatal(err)
		}
	}
	clients, err := loadSidecarClientIds(secrets)
	if err != nil {
		t.Fatal(err)
	}
	ids := []Id{}
	for _, client := range clients {
		ids = append(ids, client.clientId)
	}
	// generation 1 is the helper's own persist
	if len(ids) != 3 || ids[1] != first || ids[2] != again {
		t.Fatalf("clients %+v", clients)
	}
	encoded := encodeSidecarClientIds(clients)
	for _, bad := range [][]byte{
		nil,
		encoded[:len(encoded)-1],
		append(bytes.Clone(encoded), 0),
		append([]byte("XXCI"), encoded[4:]...),
		encodeSidecarClientIds([]sidecarGenerationClient{{generation: 2, clientId: first}, {generation: 2, clientId: second}}),
		encodeSidecarClientIds([]sidecarGenerationClient{{generation: 0, clientId: first}}),
		encodeSidecarClientIds([]sidecarGenerationClient{{generation: 1, clientId: Id{}}}),
	} {
		if _, err := decodeSidecarClientIds(bad); !errors.Is(err, ErrSidecarStoreFailed) {
			t.Errorf("decoded %x: %v", bad, err)
		}
	}
}

// One form for one client: the canonical id at ur.invalid, and nothing else.
func TestCommitterEmailForm(t *testing.T) {
	clientId := NewId()
	email := SidecarCommitterEmail(clientId)
	if parsed, err := ParseSidecarCommitterEmail(email); err != nil || parsed != clientId {
		t.Fatalf("%s: %v %v", email, parsed, err)
	}
	for _, bad := range []string{
		strings.ToUpper(email),
		strings.ReplaceAll(clientId.String(), "-", "") + "@ur.invalid",
		clientId.String() + "@ur.invalid.",
		clientId.String() + "@example.com",
		clientId.String(),
		"<" + email + ">",
		" " + email,
		Id{}.String() + "@ur.invalid",
		"",
	} {
		if _, err := ParseSidecarCommitterEmail(bad); !errors.Is(err, ErrSidecarCommitterEmail) {
			t.Errorf("parsed %q: %v", bad, err)
		}
	}
}

// A sidecar's binding of one generation, signed by its keys, and the record api would answer about it.
type testCommitterSidecar struct {
	networkId Id
	sidecarId Id
	keys      *sidecarIdentityKeys
}

func newTestCommitterSidecar(t *testing.T, networkId Id) *testCommitterSidecar {
	t.Helper()
	keys, err := newSidecarIdentityKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testCommitterSidecar{networkId: networkId, sidecarId: NewId(), keys: keys}
}

func (self *testCommitterSidecar) record(t *testing.T, clientId Id, generation int64) *SidecarIdentityRecord {
	t.Helper()
	keys, err := self.keys.withNewClientKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := NewSidecarIdentityBinding(&SidecarIdentityBinding{
		NetworkId:  self.networkId,
		SidecarId:  self.sidecarId,
		ClientId:   clientId,
		Generation: generation,
		IssuedAt:   time.Date(2026, time.May, 6, 7, 8, 9, 0, time.UTC),
	}, keys.identitySeed, keys.clientKeySeed)
	if err != nil {
		t.Fatal(err)
	}
	return &SidecarIdentityRecord{
		SidecarId:         self.sidecarId,
		IdentityPublicKey: self.keys.identityPublicKey(),
		IdentityAlg:       "ed25519",
		Status:            "active",
		Binding:           binding,
	}
}

// A lookup over records by client, counting its calls.
type testCommitterLookup struct {
	records map[Id]*SidecarIdentityRecord
	calls   int
}

func (self *testCommitterLookup) lookup(ctx context.Context, clientId Id) (*SidecarIdentityRecord, error) {
	self.calls += 1
	record, ok := self.records[clientId]
	if !ok {
		return nil, &SidecarApiError{Status: http.StatusNotFound, Code: "not_found"}
	}
	return record, nil
}

// #1: a committer that is the push's own client passes with no lookup.
func TestCommitterOwnPushNeedsNoLookup(t *testing.T) {
	networkId := NewId()
	signer := newTestCommitterSidecar(t, networkId)
	lookup := &testCommitterLookup{records: map[Id]*SidecarIdentityRecord{}}
	committer := NewSidecarCommitter(&SidecarCommitterArgs{NetworkId: networkId, Lookup: lookup.lookup})
	pushClientId := NewId()
	err := committer.Check(context.Background(), &SidecarCommitterClaim{
		CommitterEmail:          SidecarCommitterEmail(pushClientId),
		PushClientId:            pushClientId,
		SignerSidecarId:         signer.sidecarId,
		SignerIdentityPublicKey: signer.keys.identityPublicKey(),
	})
	if err != nil || lookup.calls != 0 {
		t.Fatalf("%v, %d lookups", err, lookup.calls)
	}
}

// #2: an older generation's client resolves through its verified binding to the push's signer, once.
func TestCommitterResolvesAnotherGeneration(t *testing.T) {
	networkId := NewId()
	signer := newTestCommitterSidecar(t, networkId)
	olderClientId := NewId()
	lookup := &testCommitterLookup{records: map[Id]*SidecarIdentityRecord{olderClientId: signer.record(t, olderClientId, 1)}}
	committer := NewSidecarCommitter(&SidecarCommitterArgs{NetworkId: networkId, Lookup: lookup.lookup})
	claim := &SidecarCommitterClaim{
		CommitterEmail:          SidecarCommitterEmail(olderClientId),
		PushClientId:            NewId(),
		SignerSidecarId:         signer.sidecarId,
		SignerIdentityPublicKey: signer.keys.identityPublicKey(),
	}
	for range 2 {
		if err := committer.Check(context.Background(), claim); err != nil {
			t.Fatal(err)
		}
	}
	if lookup.calls != 1 {
		t.Errorf("%d lookups, want one and then the cache", lookup.calls)
	}
}

// What does not resolve is refused, never passed: no binding, another sidecar's, another identity key's, another
// network's, a binding naming another client, a tampered binding, a malformed email, and no lookup at all.
func TestCommitterRefusesUnresolved(t *testing.T) {
	networkId := NewId()
	signer := newTestCommitterSidecar(t, networkId)
	other := newTestCommitterSidecar(t, networkId)
	foreign := newTestCommitterSidecar(t, NewId())
	unbound, othersClient, foreignClient, misnamedClient, tamperedClient := NewId(), NewId(), NewId(), NewId(), NewId()
	tampered := signer.record(t, tamperedClient, 1)
	tampered.Binding = bytes.Clone(tampered.Binding)
	tampered.Binding[len(tampered.Binding)-1] ^= 1
	lookup := &testCommitterLookup{records: map[Id]*SidecarIdentityRecord{
		othersClient:   other.record(t, othersClient, 1),
		foreignClient:  foreign.record(t, foreignClient, 1),
		misnamedClient: signer.record(t, NewId(), 1),
		tamperedClient: tampered,
	}}
	committer := NewSidecarCommitter(&SidecarCommitterArgs{NetworkId: networkId, Lookup: lookup.lookup})
	claimOf := func(clientId Id) *SidecarCommitterClaim {
		return &SidecarCommitterClaim{
			CommitterEmail:          SidecarCommitterEmail(clientId),
			PushClientId:            NewId(),
			SignerSidecarId:         signer.sidecarId,
			SignerIdentityPublicKey: signer.keys.identityPublicKey(),
		}
	}
	for _, clientId := range []Id{unbound, othersClient, foreignClient, misnamedClient, tamperedClient} {
		if err := committer.Check(context.Background(), claimOf(clientId)); !errors.Is(err, ErrSidecarCommitterUnresolved) {
			t.Errorf("client %s passed: %v", clientId, err)
		}
	}
	// the signer's own older client, checked against a pin of another key, is refused too
	ownClient := NewId()
	lookup.records[ownClient] = signer.record(t, ownClient, 1)
	wrongPin := claimOf(ownClient)
	wrongPin.SignerIdentityPublicKey = other.keys.identityPublicKey()
	if err := committer.Check(context.Background(), wrongPin); !errors.Is(err, ErrSidecarCommitterUnresolved) {
		t.Errorf("another pin passed: %v", err)
	}
	malformed := claimOf(ownClient)
	malformed.CommitterEmail = "someone@example.com"
	if err := committer.Check(context.Background(), malformed); !errors.Is(err, ErrSidecarCommitterEmail) {
		t.Errorf("a malformed email: %v", err)
	}
	blind := NewSidecarCommitter(&SidecarCommitterArgs{NetworkId: networkId})
	if err := blind.Check(context.Background(), claimOf(ownClient)); !errors.Is(err, ErrSidecarCommitterUnresolved) {
		t.Errorf("no lookup passed: %v", err)
	}
}
