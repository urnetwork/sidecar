//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

package sidecar

// tls.edge_login.sign (QD-827) on the dispatcher with no socket, so each mode's call is the one a session sends, over
// a Sidecar holding a real identity of fresh keys and a test authority: a confirmed control call's statement verifies
// as the front verifies one, under the device's identity key, for that origin and nonce alone; an unconfirmed call, or
// one from mcp or hook, never reaches the handler, which refuses one again on its own; and an origin or nonce no front
// issues is refused before the device's standing is read. The authority counts its admission reads, the first thing
// Sidecar.SignTlsEdgeLogin asks, so a test can say that signing never began.

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The act authority, counting the admission reads Sidecar.SignTlsEdgeLogin begins with.
type tlsEdgeLoginDaemonTestAuthority struct {
	*testActAuthority
	admissionReadCount atomic.Int64
}

func (self *tlsEdgeLoginDaemonTestAuthority) Admission(sidecarId Id) *AclSidecar {
	self.admissionReadCount.Add(1)
	return self.testActAuthority.Admission(sidecarId)
}

// A daemon hosting one network's Sidecar, with the edge-login method registered, and the member its device belongs to.
type tlsEdgeLoginDaemonTestWorld struct {
	daemon    *Daemon
	sidecar   *Sidecar
	keys      *sidecarIdentityKeys
	networkId Id
	sidecarId Id
	memberId  Id
	authority *tlsEdgeLoginDaemonTestAuthority
}

func newTlsEdgeLoginDaemonTestWorld(t *testing.T) *tlsEdgeLoginDaemonTestWorld {
	t.Helper()
	sidecar, _, keys := newIdentityTestSidecar(t)
	identity := sidecar.Identity()
	authority := &tlsEdgeLoginDaemonTestAuthority{testActAuthority: newTestActAuthority()}
	t.Cleanup(sidecar.InstallAuthority(authority))
	daemon := newDispatchTestDaemon(t)
	if err := daemon.AddSidecar(identity.NetworkId, sidecar); err != nil {
		t.Fatal(err)
	}
	for _, method := range DaemonTlsEdgeLoginMethods() {
		if err := daemon.RegisterMethod(method); err != nil {
			t.Fatal(err)
		}
	}
	return &tlsEdgeLoginDaemonTestWorld{
		daemon:    daemon,
		sidecar:   sidecar,
		keys:      keys,
		networkId: identity.NetworkId,
		sidecarId: identity.SidecarId,
		memberId:  NewId(),
		authority: authority,
	}
}

// Admits this device for the member, consented for it when consented.
func (self *tlsEdgeLoginDaemonTestWorld) admit(consented bool) {
	self.authority.stateLock.Lock()
	defer self.authority.stateLock.Unlock()
	self.authority.sidecars[self.sidecarId] = &AclSidecar{Row: &bridge.SidecarRow{SidecarId: self.sidecarId.Bytes()}, MemberId: self.memberId}
	self.authority.consents[[2]Id{self.sidecarId, self.memberId}] = consented
}

// One tls.edge_login.sign request line in mode, its params as given (none when empty), confirmed as asked.
func (self *tlsEdgeLoginDaemonTestWorld) call(t *testing.T, mode string, params string, confirmed bool) *daemonRpcResponse {
	t.Helper()
	request := &daemonRpcRequest{JsonRpc: "2.0", Id: json.RawMessage("1"), Method: DaemonMethodTlsEdgeLoginSign, UrConfirmed: confirmed}
	if params != "" {
		request.Params = json.RawMessage(params)
	}
	line, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return dispatchTest(self.daemon, mode, string(line))
}

// The params of a call for origin and nonce on the world's network.
func (self *tlsEdgeLoginDaemonTestWorld) params(t *testing.T, origin string, nonce []byte) string {
	t.Helper()
	encoded, err := json.Marshal(&DaemonTlsEdgeLoginSignParams{Network: self.networkId.String(), Origin: origin, Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// The front's policy for the world: the member active, the device's identity key known and consented for it.
func (self *tlsEdgeLoginDaemonTestWorld) frontPolicy() *tlsFrontTestPolicy {
	policy := newTlsFrontTestPolicy()
	policy.members[self.memberId] = true
	policy.identityKeys[self.sidecarId] = self.keys.identityPublicKey()
	policy.consentedDevices[[2]Id{self.sidecarId, self.memberId}] = true
	return policy
}

func tlsEdgeLoginDaemonTestNonce(t *testing.T) []byte {
	t.Helper()
	nonce := make([]byte, tlsEdgeLoginNonceByteCount)
	if _, err := cryptorand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return nonce
}

// One method, acting on a network, that only a person's confirmed control call runs.
func TestDaemonTlsEdgeLoginSignIsAConfirmMethod(t *testing.T) {
	methods := DaemonTlsEdgeLoginMethods()
	if len(methods) != 1 {
		t.Fatalf("%d methods", len(methods))
	}
	method := methods[0]
	if method.Name != "tls.edge_login.sign" || !method.Network || !method.Confirm || method.Handler == nil {
		t.Errorf("%s: network %t, confirm %t", method.Name, method.Network, method.Confirm)
	}
	// beside the publish methods, none of which is a person's act
	for _, other := range DaemonTlsMethods() {
		if other.Name == method.Name {
			t.Errorf("%s is also a publish method", other.Name)
		}
	}
}

// A confirmed control call answers the statement, and it is the one the front's check takes: the Signed verifies under
// the device's identity key as SIGNED_TLS_EDGE_LOGIN for that origin and that nonce, and for no other origin or nonce.
// The reply holds the statement alone. A device its member has not consented answers a refusal and no statement.
func TestDaemonTlsEdgeLoginSignConfirmedVerifies(t *testing.T) {
	world := newTlsEdgeLoginDaemonTestWorld(t)
	nonce := tlsEdgeLoginDaemonTestNonce(t)

	// an admitted device whose member has not consented to it vouches for nothing
	world.admit(false)
	refused := world.call(t, DaemonModeControl, world.params(t, tlsFrontTestOrigin, nonce), true)
	if refused.Error == nil || len(refused.Result) != 0 || !strings.Contains(refused.Error.Message, ErrTlsEdgeLoginNotConsented.Error()) {
		t.Fatalf("an unconsented device: %+v %s", refused.Error, refused.Result)
	}

	world.admit(true)
	response := world.call(t, DaemonModeControl, world.params(t, tlsFrontTestOrigin, nonce), true)
	if response.Error != nil {
		t.Fatalf("a confirmed call: %+v", response.Error)
	}
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(response.Result, &fields); err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for name := range fields {
		names = append(names, name)
	}
	if !slices.Equal(names, []string{"statement"}) {
		t.Errorf("the reply holds %v", names)
	}
	reply := &DaemonTlsEdgeLoginSignReply{}
	if err := json.Unmarshal(response.Result, reply); err != nil || len(reply.Statement) == 0 {
		t.Fatalf("the reply: %s %v", response.Result, err)
	}
	if err := checkDaemonReply(reply); err != nil {
		t.Errorf("the reply walk refuses the statement: %v", err)
	}

	value := base64.RawURLEncoding.EncodeToString(reply.Statement)
	policy := world.frontPolicy()
	maxByteCount := DefaultTlsFrontSettings().EdgeLoginMaxByteCount
	now := time.Now()
	deviceId, err := tlsEdgeLoginVerify(value, tlsFrontTestOrigin, nonce, world.memberId, policy, maxByteCount, now)
	if err != nil || deviceId != world.sidecarId {
		t.Fatalf("the front's check: %s %v", deviceId, err)
	}
	if _, err := tlsEdgeLoginVerify(value, "https://"+tlsFrontTestOtherName, nonce, world.memberId, policy, maxByteCount, now); err == nil {
		t.Error("taken at another origin")
	}
	if _, err := tlsEdgeLoginVerify(value, tlsFrontTestOrigin, tlsEdgeLoginDaemonTestNonce(t), world.memberId, policy, maxByteCount, now); err == nil {
		t.Error("taken for another nonce")
	}
	// under no other key: a device the front holds another key for vouches for nothing
	otherPublicKey, _, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPolicy := world.frontPolicy()
	otherPolicy.identityKeys[world.sidecarId] = otherPublicKey
	if _, err := tlsEdgeLoginVerify(value, tlsFrontTestOrigin, nonce, world.memberId, otherPolicy, maxByteCount, now); err == nil {
		t.Error("verified under another identity key")
	}

	// the network argument may be left out: the only network hosted is the call's
	unnamed, err := json.Marshal(&DaemonTlsEdgeLoginSignParams{Origin: tlsFrontTestOrigin + ":8443", Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	portResponse := world.call(t, DaemonModeControl, string(unnamed), true)
	if portResponse.Error != nil {
		t.Fatalf("a call naming no network: %+v", portResponse.Error)
	}
	portReply := &DaemonTlsEdgeLoginSignReply{}
	if err := json.Unmarshal(portResponse.Result, portReply); err != nil {
		t.Fatal(err)
	}
	portValue := base64.RawURLEncoding.EncodeToString(portReply.Statement)
	if _, err := tlsEdgeLoginVerify(portValue, tlsFrontTestOrigin+":8443", nonce, world.memberId, policy, maxByteCount, now); err != nil {
		t.Errorf("the 8443 endpoint's statement: %v", err)
	}
	if _, err := tlsEdgeLoginVerify(portValue, tlsFrontTestOrigin, nonce, world.memberId, policy, maxByteCount, now); err == nil {
		t.Error("the 8443 endpoint's statement taken on 443")
	}
}

// An unconfirmed control call, and an mcp or hook call whatever its flag says, is refused CONFIRMATION_REQUIRED before
// the handler runs, so signing never begins; the handler alone, handed an unconfirmed call, refuses it too. A
// confirmed control call afterwards signs, so the refusals are not a world that cannot sign.
func TestDaemonTlsEdgeLoginSignUnconfirmedSignsNothing(t *testing.T) {
	world := newTlsEdgeLoginDaemonTestWorld(t)
	world.admit(true)
	nonce := tlsEdgeLoginDaemonTestNonce(t)
	params := world.params(t, tlsFrontTestOrigin, nonce)
	for _, c := range []struct {
		mode      string
		confirmed bool
	}{
		{mode: DaemonModeControl, confirmed: false},
		{mode: DaemonModeMcp, confirmed: true},
		{mode: DaemonModeMcp, confirmed: false},
		{mode: DaemonModeHook, confirmed: true},
		{mode: DaemonModeHook, confirmed: false},
	} {
		response := world.call(t, c.mode, params, c.confirmed)
		if response.Error == nil || response.Error.Code != DaemonRpcConfirmationRequired || len(response.Result) != 0 {
			t.Errorf("%s, confirmed %t: %+v %s", c.mode, c.confirmed, response.Error, response.Result)
		}
	}
	if count := world.authority.admissionReadCount.Load(); count != 0 {
		t.Fatalf("an unconfirmed call began signing: %d admission reads", count)
	}

	// a host that registered the handler without Confirm still gets nothing signed
	handler := DaemonTlsEdgeLoginMethods()[0].Handler
	reply, err := handler(t.Context(), &DaemonCall{Params: json.RawMessage(params), NetworkId: world.networkId, Sidecar: world.sidecar})
	if !errors.Is(err, errDaemonTlsEdgeLoginUnconfirmed) || reply != nil {
		t.Errorf("the handler on an unconfirmed call: %v %v", reply, err)
	}
	if count := world.authority.admissionReadCount.Load(); count != 0 {
		t.Fatalf("the handler began signing an unconfirmed call: %d admission reads", count)
	}

	response := world.call(t, DaemonModeControl, params, true)
	if response.Error != nil || len(response.Result) == 0 || world.authority.admissionReadCount.Load() == 0 {
		t.Fatalf("CONTROL FAILED: a confirmed call: %+v", response.Error)
	}
}

// An origin or a nonce no front issues, params that do not decode or that name a field the method does not know, and no
// params at all are refused before the device's standing is read, and the refusal names nothing they held. A
// well-formed call afterwards signs.
func TestDaemonTlsEdgeLoginSignRefusesAMalformedOriginOrNonce(t *testing.T) {
	world := newTlsEdgeLoginDaemonTestWorld(t)
	world.admit(true)
	nonce := tlsEdgeLoginDaemonTestNonce(t)
	nonceText := base64.StdEncoding.EncodeToString(nonce)
	for _, c := range []struct {
		name   string
		params string
	}{
		{name: "an http origin", params: world.params(t, "http://"+tlsFrontTestServerName, nonce)},
		{name: "an origin with a path", params: world.params(t, tlsFrontTestOrigin+"/login", nonce)},
		{name: "an origin naming 443", params: world.params(t, tlsFrontTestOrigin+":443", nonce)},
		{name: "an origin with a port past 16 bits", params: world.params(t, tlsFrontTestOrigin+":65536", nonce)},
		{name: "an origin that is not canonical", params: world.params(t, "https://App.abcdefghij.ur.example", nonce)},
		{name: "an origin with a user", params: world.params(t, "https://user@"+tlsFrontTestServerName, nonce)},
		{name: "a wildcard origin", params: world.params(t, "https://*.abcdefghij.ur.example", nonce)},
		{name: "no origin", params: world.params(t, "", nonce)},
		{name: "a short nonce", params: world.params(t, tlsFrontTestOrigin, nonce[:16])},
		{name: "a long nonce", params: world.params(t, tlsFrontTestOrigin, append(append([]byte{}, nonce...), 7))},
		{name: "no nonce", params: world.params(t, tlsFrontTestOrigin, nil)},
		{name: "a nonce that is not base64", params: `{"origin":"` + tlsFrontTestOrigin + `","nonce":"not base64 !"}`},
		{name: "a nonce as base64url", params: `{"origin":"` + tlsFrontTestOrigin + `","nonce":"` + base64.RawURLEncoding.EncodeToString(nonce) + `"}`},
		{name: "an unknown field", params: `{"origin":"` + tlsFrontTestOrigin + `","nonce":"` + nonceText + `","key":"a-secret-value"}`},
		{name: "params that are not an object", params: `["` + tlsFrontTestOrigin + `","` + nonceText + `"]`},
		{name: "no params", params: ""},
	} {
		response := world.call(t, DaemonModeControl, c.params, true)
		if response.Error == nil || len(response.Result) != 0 {
			t.Errorf("%s: %+v %s", c.name, response.Error, response.Result)
			continue
		}
		for _, held := range []string{tlsFrontTestServerName, "abcdefghij", nonceText, base64.RawURLEncoding.EncodeToString(nonce), "a-secret-value", "not base64"} {
			if strings.Contains(response.Error.Message, held) {
				t.Errorf("%s: the refusal repeats %q: %s", c.name, held, response.Error.Message)
			}
		}
	}
	if count := world.authority.admissionReadCount.Load(); count != 0 {
		t.Fatalf("a malformed call began signing: %d admission reads", count)
	}

	response := world.call(t, DaemonModeControl, world.params(t, tlsFrontTestOrigin, nonce), true)
	if response.Error != nil || len(response.Result) == 0 {
		t.Fatalf("CONTROL FAILED: a well-formed call: %+v", response.Error)
	}
}
