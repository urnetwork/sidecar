//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !ios_extension

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A child's token as an app's POST /network/auth-client mints it under its device client: strict_exp, of networkId.
func testPairChildToken(networkId Id, clientId Id, strictExp bool) string {
	now := time.Now()
	return testClientJwt(fmt.Sprintf(`{"jti":%q,"iat":%d,"exp":%d,"network_id":%q,"client_id":%q,"device_id":%q,"strict_exp":%t}`,
		NewId().String(), now.Unix(), now.Add(7*24*time.Hour).Unix(), networkId, clientId, NewId(), strictExp))
}

// A world enrolled top-level by ur login, its first generation Online.
func newPairTestWorld(t *testing.T) *testEnrollWorld {
	t.Helper()
	world := newTestEnrollWorld(t)
	if err := world.enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	world.platform.connected.Set(true)
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOnline, 1))
	return world
}

// §5.8's pair row: the child's token binds generation n+1 on a new ClientKey under the same sidecar_id, the record turns
// a child's, the run loop moves to it from Online, and the top-level client goes with its own token.
func TestPairBindsNextGeneration(t *testing.T) {
	world := newPairTestWorld(t)
	first := world.sidecar.currentIdentity()
	firstToken, _ := loadSidecarByJwt(world.instance.secrets(first.NetworkId, sidecarCoreSecretsNamespace))
	childId := NewId()
	childToken := testPairChildToken(world.api.networkId, childId, true)
	if err := world.sidecar.Pair(context.Background(), childToken); err != nil {
		t.Fatal(err)
	}
	if generation := world.sidecar.BoundGeneration(); generation != 2 {
		t.Fatalf("the bound generation %d", generation)
	}
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOnline, 2))
	second := world.sidecar.currentIdentity()
	if second.SidecarId != first.SidecarId || second.ClientId != childId || bytes.Equal(second.ClientPublicKey, first.ClientPublicKey) {
		t.Fatalf("the paired generation: %+v", second)
	}
	records := world.instance.Networks()
	if len(records) != 1 || !records[0].Child || records[0].ClientId != childId || !world.sidecar.Paired() {
		t.Fatalf("the record: %+v", records)
	}
	world.api.stateLock.Lock()
	removed, removers := append([]Id{}, world.api.removed...), append([]string{}, world.api.removers...)
	world.api.stateLock.Unlock()
	if len(removed) != 1 || removed[0] != first.ClientId || removers[0] != firstToken {
		t.Fatalf("the top-level client's removal: %v by %d tokens", removed, len(removers))
	}
	// the keychain and the generation hold bind's re-mint of the child's token, which names the sidecar (QD-797)
	kept, _ := loadSidecarByJwt(world.instance.secrets(first.NetworkId, sidecarCoreSecretsNamespace))
	reminted := world.api.remintedTokens()
	if kept == childToken || kept != reminted[len(reminted)-1] || world.sidecar.sidecarApi.currentByJwt() != kept {
		t.Fatal("the keychain and the generation do not hold bind's re-mint of the child's token")
	}
	keptIdentity, _ := sidecarJwtIdentityOf(kept)
	childIdentity, _ := sidecarJwtIdentityOf(childToken)
	if claimed, ok := sidecarJwtSidecarId(kept); !ok || claimed != first.SidecarId || keptIdentity != childIdentity {
		t.Fatalf("the kept token names sidecar %s, %+v", claimed, keptIdentity)
	}

	// refusals send nothing: no strict_exp, another network, no client, the client it runs on
	sent := len(world.api.requestedPaths())
	for name, token := range map[string]string{
		"no strict_exp":   testPairChildToken(world.api.networkId, NewId(), false),
		"another network": testPairChildToken(NewId(), NewId(), true),
		"no client":       testClientJwt(`{"network_id":"` + world.api.networkId.String() + `","strict_exp":true}`),
		"not a token":     "synthetic",
	} {
		if err := world.sidecar.Pair(context.Background(), token); !errors.Is(err, ErrSidecarPairToken) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := world.sidecar.Pair(context.Background(), childToken); !errors.Is(err, ErrSidecarPairSame) {
		t.Errorf("the client it runs on: %v", err)
	}
	if paths := world.api.requestedPaths()[sent:]; 0 < len(slicesWithout(paths, "/sidecar/sync/")) {
		t.Fatalf("a refused pairing sent %v", paths)
	}
}

// The paths that are not the push client's own resyncs (§6.8).
func slicesWithout(paths []string, prefix string) []string {
	kept := []string{}
	for _, path := range paths {
		if !strings.HasPrefix(path, prefix) {
			kept = append(kept, path)
		}
	}
	return kept
}

// The SidecarAdmit stands because it names the sidecar_id: a pairing keeps the sidecar_id, the identity key, the
// ReaderKey and the anchor, and its binding names the same identity key; an unenrolled sidecar pairs as generation 1.
func TestPairKeepsAdmission(t *testing.T) {
	world := newPairTestWorld(t)
	first := world.sidecar.currentIdentity()
	secrets := world.instance.secrets(first.NetworkId, sidecarCoreSecretsNamespace)
	readerKey, err := secrets.Get(sidecarReaderKeyRecordName)
	if err != nil {
		t.Fatal(err)
	}
	if err := world.sidecar.Pair(context.Background(), testPairChildToken(world.api.networkId, NewId(), true)); err != nil {
		t.Fatal(err)
	}
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOnline, 2))
	record, err := loadSidecarIdentity(secrets)
	if err != nil {
		t.Fatal(err)
	}
	defer record.keys.erase()
	binding, err := VerifySidecarIdentityBinding(record.binding)
	if err != nil {
		t.Fatal(err)
	}
	if record.identity.SidecarId != first.SidecarId || !bytes.Equal(record.identity.IdentityPublicKey, first.IdentityPublicKey) ||
		binding.Generation != 2 || !bytes.Equal(binding.IdentityPublicKey, first.IdentityPublicKey) {
		t.Fatalf("the paired identity: %+v, binding %+v", record.identity, binding)
	}
	if kept, err := secrets.Get(sidecarReaderKeyRecordName); err != nil || !bytes.Equal(kept, readerKey) {
		t.Fatal("the pairing replaced the ReaderKey")
	}

	// an unenrolled sidecar pairs into the child's network as its first generation, marked a child
	fresh := newTestEnrollWorld(t)
	if err := fresh.sidecar.Pair(context.Background(), testPairChildToken(fresh.api.networkId, NewId(), true)); err != nil {
		t.Fatal(err)
	}
	fresh.platform.connected.Set(true)
	awaitSidecarStatus(t, fresh.sidecar, atStatus(SidecarStateOnline, 1))
	if records := fresh.instance.Networks(); len(records) != 1 || !records[0].Child {
		t.Fatalf("a first pairing's record: %+v", records)
	}
}

// §5.8's lost row: a confirmed rejection of the paired generation reads parent_lost by the child mark, and Unenrolled
// keeps the identity, the record and the keychain for ur login or a re-pair.
func TestParentLostKeepsIdentity(t *testing.T) {
	world := newPairTestWorld(t)
	first := world.sidecar.currentIdentity()
	if err := world.sidecar.Pair(context.Background(), testPairChildToken(world.api.networkId, NewId(), true)); err != nil {
		t.Fatal(err)
	}
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOnline, 2))
	manager := world.sidecar.runningGeneration().tokenManager.Load()
	if !manager.args.Child {
		t.Fatal("the paired generation's refresher does not know it is a child's")
	}
	reason := manager.refusedReason(&SidecarApiError{Status: http.StatusUnauthorized})
	if reason != SidecarReasonParentLost {
		t.Fatalf("a 401 of a child reads %s", reason)
	}
	if revoked := manager.refusedReason(&SidecarApiError{Status: http.StatusUnauthorized, Code: SidecarApiCodeSessionRevoked}); revoked != SidecarReasonSessionEnded {
		t.Fatalf("session_revoked reads %s", revoked)
	}
	manager.end(reason)
	awaitSidecarStatus(t, world.sidecar, func(status SidecarStatus) bool {
		return status.State == SidecarStateUnenrolled && status.Reason == SidecarReasonParentLost
	})
	identity := world.sidecar.currentIdentity()
	if identity == nil || identity.SidecarId != first.SidecarId || identity.Generation != 2 {
		t.Fatalf("parent loss dropped the identity: %+v", identity)
	}
	if records := world.instance.Networks(); len(records) != 1 || !records[0].Child {
		t.Fatalf("parent loss dropped the record: %+v", records)
	}
	// a re-pair binds the next generation
	if err := world.sidecar.Pair(context.Background(), testPairChildToken(world.api.networkId, NewId(), true)); err != nil {
		t.Fatal(err)
	}
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOnline, 3))
}

// §5.8's unpair row: ur login on a paired sidecar enrolls a top-level client as the next generation, while it runs,
// clearing the child mark, and removes the child with the child's own token.
func TestUnpairRemovesChild(t *testing.T) {
	world := newPairTestWorld(t)
	childId := NewId()
	childToken := testPairChildToken(world.api.networkId, childId, true)
	if err := world.sidecar.Pair(context.Background(), childToken); err != nil {
		t.Fatal(err)
	}
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOnline, 2))
	// the child's token as the keychain keeps it: bind's re-mint, with which the child goes (QD-797)
	keptChildToken, _ := loadSidecarByJwt(world.instance.secrets(world.api.networkId, sidecarCoreSecretsNamespace))
	if err := world.enroll(context.Background()); err != nil {
		t.Fatalf("ur login on a paired sidecar: %v", err)
	}
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOnline, 3))
	third := world.sidecar.currentIdentity()
	if third.ClientId == childId {
		t.Fatal("the unpairing kept the child")
	}
	if records := world.instance.Networks(); len(records) != 1 || records[0].Child || world.sidecar.Paired() {
		t.Fatalf("the unpaired record: %+v", records)
	}
	world.api.stateLock.Lock()
	removed, removers := append([]Id{}, world.api.removed...), append([]string{}, world.api.removers...)
	world.api.stateLock.Unlock()
	if len(removed) != 2 || removed[1] != childId || removers[1] != keptChildToken {
		t.Fatalf("the child's removal: %v", removed)
	}
	if claimed, ok := sidecarJwtSidecarId(keptChildToken); !ok || claimed != third.SidecarId {
		t.Fatalf("the child's kept token names sidecar %s", claimed)
	}
	// a top-level sidecar running is not re-enrolled by ur login: the person logs out first
	if err := world.enroll(context.Background()); !errors.Is(err, ErrSidecarEnrolled) {
		t.Fatalf("ur login on a running top-level sidecar: %v", err)
	}
}

// pair's reply names the network and the generation and never a token, and the token reaches no log line.
func TestPairRepliesHoldNoToken(t *testing.T) {
	world := newPairTestWorld(t)
	childToken := testPairChildToken(world.api.networkId, NewId(), true)
	method := DaemonPairMethod(&testPairTarget{sidecar: world.sidecar})
	params, _ := json.Marshal(&DaemonPairParams{ChildJwt: childToken})
	result, err := method.Handler(context.Background(), &DaemonCall{Hello: &DaemonHello{Mode: DaemonModeControl}, Params: params})
	if err != nil {
		t.Fatal(err)
	}
	if err := checkDaemonReply(result); err != nil {
		t.Fatalf("the reply holds a secret: %v", err)
	}
	encoded, _ := json.Marshal(result)
	reply := &DaemonPairReply{}
	if err := json.Unmarshal(encoded, reply); err != nil || reply.NetworkId != world.api.networkId || reply.Generation != 2 {
		t.Fatalf("the reply: %s", encoded)
	}
	if strings.Contains(string(encoded), childToken) || strings.Contains(string(encoded), strings.Split(childToken, ".")[1]) {
		t.Fatal("the reply carries the token")
	}
	world.log.stateLock.Lock()
	defer world.log.stateLock.Unlock()
	for _, line := range world.log.lines {
		if strings.Contains(line, strings.Split(childToken, ".")[1]) {
			t.Fatal("a log line carries the token")
		}
	}
	if _, err := method.Handler(context.Background(), &DaemonCall{Hello: &DaemonHello{Mode: DaemonModeControl}}); err == nil {
		t.Fatal("pair took no token")
	}
}

// A host target over one Sidecar.
type testPairTarget struct {
	sidecar *Sidecar
}

func (self *testPairTarget) PairChild(ctx context.Context, childJwt string) (*DaemonPairReply, error) {
	networkId, ok := DaemonPairNetwork(childJwt)
	if !ok {
		return nil, ErrSidecarPairToken
	}
	if err := self.sidecar.Pair(ctx, childJwt); err != nil {
		return nil, err
	}
	return &DaemonPairReply{NetworkId: networkId, Generation: self.sidecar.BoundGeneration()}, nil
}
