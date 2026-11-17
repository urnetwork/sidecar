//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !ios_extension

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

// The marks a pairing requires of a child's token it did not mint (§5.4, D-CORE-7; owner decision 291): strict_exp
// and admin_refused, each a JSON true, checked by the daemon's pair method before any host is reached and by
// Sidecar.Pair before anything is sent.

// A host target that records each token that reaches it and answers as a pairing would.
type testPairRecordingTarget struct {
	stateLock sync.Mutex
	childJwts []string
}

func (self *testPairRecordingTarget) PairChild(ctx context.Context, childJwt string) (*DaemonPairReply, error) {
	networkId, _ := DaemonPairNetwork(childJwt)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.childJwts = append(self.childJwts, childJwt)
	return &DaemonPairReply{NetworkId: networkId, Generation: int64(len(self.childJwts))}, nil
}

// The tokens that reached the target, in order.
func (self *testPairRecordingTarget) reached() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.childJwts...)
}

// Calls the pair method with childJwt as a control session's app would.
func testDaemonPair(t *testing.T, method *DaemonMethod, childJwt string) (any, error) {
	t.Helper()
	params, err := json.Marshal(&DaemonPairParams{ChildJwt: childJwt})
	if err != nil {
		t.Fatal(err)
	}
	return method.Handler(context.Background(), &DaemonCall{Hello: &DaemonHello{Mode: DaemonModeControl}, Params: params})
}

// Tokens of networkId that a pairing refuses on their claims alone, by what each lacks.
func testPairUnmarkedTokens(networkId Id) map[string]string {
	return map[string]string{
		// what api's mint of a client whose owner row has no admin_refused mark gives
		"no admin_refused":         testPairChildTokenMarked(networkId, NewId(), `"strict_exp":true`),
		"admin_refused false":      testPairChildTokenMarked(networkId, NewId(), `"strict_exp":true,"admin_refused":false`),
		"admin_refused a string":   testPairChildTokenMarked(networkId, NewId(), `"strict_exp":true,"admin_refused":"true"`),
		"admin_refused a number":   testPairChildTokenMarked(networkId, NewId(), `"strict_exp":true,"admin_refused":1`),
		"admin_refused null":       testPairChildTokenMarked(networkId, NewId(), `"strict_exp":true,"admin_refused":null`),
		"no strict_exp":            testPairChildTokenMarked(networkId, NewId(), `"admin_refused":true`),
		"strict_exp false":         testPairChildToken(networkId, NewId(), false),
		"strict_exp a string":      testPairChildTokenMarked(networkId, NewId(), `"strict_exp":"true","admin_refused":true`),
		"no marks":                 testPairChildTokenMarked(networkId, NewId(), ""),
		"no client":                testClientJwt(`{"network_id":"` + networkId.String() + `","strict_exp":true,"admin_refused":true}`),
		"no network":               testClientJwt(`{"client_id":"` + NewId().String() + `","strict_exp":true,"admin_refused":true}`),
		"not a token":              "synthetic",
		"the claims, not a token":  `{"network_id":"` + networkId.String() + `","strict_exp":true,"admin_refused":true}`,
		"a token of two segments":  strings.Join(strings.Split(testPairChildToken(networkId, NewId(), true), ".")[:2], "."),
		"a token of four segments": testPairChildToken(networkId, NewId(), true) + ".",
	}
}

// DaemonPairNetwork, which hosts choose a Sidecar by, names the network only of a token with both marks as JSON trues:
// a token api minted for a client with no admin_refused mark, which carries no claim, names none.
func TestDaemonPairNetworkRequiresBothMarks(t *testing.T) {
	networkId := NewId()
	if named, ok := DaemonPairNetwork(testPairChildToken(networkId, NewId(), true)); !ok || named != networkId {
		t.Fatalf("a marked child's token names %s, %t", named, ok)
	}
	for name, token := range testPairUnmarkedTokens(networkId) {
		if named, ok := DaemonPairNetwork(token); ok || named != (Id{}) {
			t.Errorf("%s: names %s", name, named)
		}
	}
}

// The pair method refuses a token without both marks before any host is reached, so no Sidecar is chosen or started
// for it, and its answer carries no token; a token with both reaches the host as it was sent.
func TestDaemonPairMethodRefusesUnmarkedTokenBeforeAnyHost(t *testing.T) {
	target := &testPairRecordingTarget{}
	method := DaemonPairMethod(target)
	networkId := NewId()
	for name, token := range testPairUnmarkedTokens(networkId) {
		result, err := testDaemonPair(t, method, token)
		if !errors.Is(err, ErrSidecarPairToken) || result != nil {
			t.Errorf("%s: %v %v", name, result, err)
			continue
		}
		if strings.Contains(err.Error(), token) {
			t.Errorf("%s: the refusal carries the token", name)
		}
	}
	if reached := target.reached(); len(reached) != 0 {
		t.Fatalf("%d refused tokens reached the host", len(reached))
	}

	marked := testPairChildToken(networkId, NewId(), true)
	result, err := testDaemonPair(t, method, marked)
	if err != nil {
		t.Fatal(err)
	}
	if reply, ok := result.(*DaemonPairReply); !ok || reply.NetworkId != networkId || reply.Generation != 1 {
		t.Fatalf("the reply: %+v", result)
	}
	if reached := target.reached(); len(reached) != 1 || reached[0] != marked {
		t.Fatalf("the host got %d tokens", len(reached))
	}
}

// Pair refuses a child whose token lacks admin_refused before anything is sent, through Sidecar.Pair and the daemon's
// method alike, and the running generation, its identity, record and keychain stay as they were; the same child, once
// api's mint marks its token, pairs as the next generation.
func TestPairRefusesChildWithoutAdminRefused(t *testing.T) {
	world := newPairTestWorld(t)
	first := world.sidecar.currentIdentity()
	secrets := world.instance.secrets(first.NetworkId, sidecarCoreSecretsNamespace)
	firstToken, _ := loadSidecarByJwt(secrets)
	method := DaemonPairMethod(&testPairTarget{sidecar: world.sidecar})
	childId := NewId()
	sent := len(world.api.requestedPaths())

	for _, marks := range []string{`"strict_exp":true`, `"strict_exp":true,"admin_refused":false`} {
		unmarked := testPairChildTokenMarked(world.api.networkId, childId, marks)
		if err := world.sidecar.Pair(context.Background(), unmarked); !errors.Is(err, ErrSidecarPairToken) {
			t.Fatalf("Pair of %s: %v", marks, err)
		}
		if _, err := testDaemonPair(t, method, unmarked); !errors.Is(err, ErrSidecarPairToken) {
			t.Fatalf("the pair method of %s: %v", marks, err)
		}
	}
	if paths := world.api.requestedPaths()[sent:]; 0 < len(slicesWithout(paths, "/sidecar/sync/")) {
		t.Fatalf("a refused pairing sent %v", paths)
	}
	if generation := world.sidecar.BoundGeneration(); generation != 1 {
		t.Fatalf("a refused pairing bound generation %d", generation)
	}
	if identity := world.sidecar.currentIdentity(); identity.ClientId != first.ClientId || identity.Generation != 1 {
		t.Fatalf("a refused pairing moved the identity: %+v", identity)
	}
	if records := world.instance.Networks(); len(records) != 1 || records[0].Child || world.sidecar.Paired() {
		t.Fatalf("a refused pairing marked the record a child: %+v", records)
	}
	if kept, _ := loadSidecarByJwt(secrets); kept != firstToken {
		t.Fatal("a refused pairing replaced the keychain's token")
	}

	result, err := testDaemonPair(t, method, testPairChildToken(world.api.networkId, childId, true))
	if err != nil {
		t.Fatal(err)
	}
	if reply, ok := result.(*DaemonPairReply); !ok || reply.NetworkId != world.api.networkId || reply.Generation != 2 {
		t.Fatalf("the reply: %+v", result)
	}
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOnline, 2))
	if second := world.sidecar.currentIdentity(); second.ClientId != childId || second.SidecarId != first.SidecarId {
		t.Fatalf("the paired generation: %+v", second)
	}
}
