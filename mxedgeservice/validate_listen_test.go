package mxedgeservice_test

// §15's check of an smtp/ listen (MAIL-M7-22): the name, the caller, the network's mail and a scope's consent, each
// refusal by its kind, and the hooks under the sockets engine's own smtp/ namespace.

import (
	"context"
	"errors"
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mxedgeservice"
	"github.com/urnetwork/sidecar/socketsservice"
)

// Mail networks in memory; an unknown network cannot be told.
type testMailNetworks struct {
	enabled map[connect.Id]bool
}

func (self *testMailNetworks) MailEnabled(ctx context.Context, networkId connect.Id) (bool, error) {
	enabled, known := self.enabled[networkId]
	if !known {
		return false, errors.New("the mail_network read failed")
	}
	return enabled, nil
}

// Scopes in memory: a member scope's consented device, and a scope source that cannot decide.
type testSmtpScopes struct {
	networkId connect.Id
	scope     string
	sidecarId connect.Id
	undecided bool
	broken    bool
}

func (self *testSmtpScopes) ConsentListen(networkId connect.Id, scope string, sidecarId *connect.Id) error {
	switch {
	case self.broken:
		return errors.New("the scope read failed")
	case self.undecided:
		return socketsservice.ErrSocketListenUnavailable
	case networkId != self.networkId || scope != self.scope:
		return socketsservice.ErrSocketListenRefused
	case sidecarId == nil || *sidecarId != self.sidecarId:
		return socketsservice.ErrSocketListenRefused
	}
	return nil
}

func testSmtpListenCheck(networkId connect.Id, sidecarId *connect.Id, name string) *socketsservice.SocketListenCheck {
	return &socketsservice.SocketListenCheck{
		NetworkId: networkId, ListenerClientId: connect.NewId(), SidecarId: sidecarId, Name: name,
		Namespace:    sidecar.SocketNamespaceSmtp,
		Registration: &sidecar.SocketRegistration{Protocol: "smtp-starttls"},
	}
}

func TestSmtpListenScopeReadsOnlyAReceiversName(t *testing.T) {
	for name, want := range map[string]string{"smtp/25/mx": "", "smtp/25/mx.team": "team", "smtp/25/mx.a.b": "a.b"} {
		if scope, ok := mxedgeservice.SmtpListenScope(name); !ok || scope != want {
			t.Errorf("%s: %q, %t", name, scope, ok)
		}
	}
	for _, name := range []string{
		"smtp/587/mx", "smtp/25/mail", "smtp/25/mx.", "smtp/25/", "smtp/25", "smtp/25/mx/extra", "tls/25/mx", "25/mx", "mx", "",
		"smtp/25/MX", "smtp/025/mx", "smtp/25/mxx",
	} {
		if _, ok := mxedgeservice.SmtpListenScope(name); ok {
			t.Errorf("%q read as a receiver's name", name)
		}
	}
}

// A mail network's sidecar listens at smtp/25/mx; every other case is refused by its kind.
func TestValidateSmtpListenAdmitsOnlyAMailNetworksReceiver(t *testing.T) {
	ctx := context.Background()
	mailNetworkId, plainNetworkId, unknownNetworkId := connect.NewId(), connect.NewId(), connect.NewId()
	networks := &testMailNetworks{enabled: map[connect.Id]bool{mailNetworkId: true, plainNetworkId: false}}
	sidecarId := connect.NewId()

	if err := mxedgeservice.ValidateSmtpListen(ctx, testSmtpListenCheck(mailNetworkId, &sidecarId, "smtp/25/mx"), networks, nil); err != nil {
		t.Fatalf("a mail network's receiver: %v", err)
	}
	refused := map[string]*socketsservice.SocketListenCheck{
		"another port":       testSmtpListenCheck(mailNetworkId, &sidecarId, "smtp/587/mx"),
		"another host":       testSmtpListenCheck(mailNetworkId, &sidecarId, "smtp/25/inbox"),
		"no sidecar":         testSmtpListenCheck(mailNetworkId, nil, "smtp/25/mx"),
		"no mail":            testSmtpListenCheck(plainNetworkId, &sidecarId, "smtp/25/mx"),
		"a scope, no source": testSmtpListenCheck(mailNetworkId, &sidecarId, "smtp/25/mx.team"),
		"no check":           nil,
	}
	tlsCheck := testSmtpListenCheck(mailNetworkId, &sidecarId, "smtp/25/mx")
	tlsCheck.Namespace = sidecar.SocketNamespaceTls
	refused["another namespace"] = tlsCheck
	for name, check := range refused {
		if err := mxedgeservice.ValidateSmtpListen(ctx, check, networks, nil); !errors.Is(err, socketsservice.ErrSocketListenRefused) {
			t.Errorf("%s: %v, want a refusal", name, err)
		}
	}
	if err := mxedgeservice.ValidateSmtpListen(ctx, testSmtpListenCheck(mailNetworkId, &sidecarId, "smtp/25/mx"), nil, nil); !errors.Is(err, socketsservice.ErrSocketListenRefused) {
		t.Errorf("no network source: %v, want a refusal", err)
	}
	err := mxedgeservice.ValidateSmtpListen(ctx, testSmtpListenCheck(unknownNetworkId, &sidecarId, "smtp/25/mx"), networks, nil)
	if !errors.Is(err, socketsservice.ErrSocketListenUnavailable) || errors.Is(err, socketsservice.ErrSocketListenRefused) {
		t.Errorf("a network that cannot be told: %v, want undecided", err)
	}
}

// A scope's host takes only the scope source's consent: a member scope's own consented device.
func TestValidateSmtpListenAsksAScopesConsent(t *testing.T) {
	ctx := context.Background()
	networkId, memberSidecarId, otherSidecarId := connect.NewId(), connect.NewId(), connect.NewId()
	networks := &testMailNetworks{enabled: map[connect.Id]bool{networkId: true}}
	scopes := &testSmtpScopes{networkId: networkId, scope: "alice", sidecarId: memberSidecarId}

	if err := mxedgeservice.ValidateSmtpListen(ctx, testSmtpListenCheck(networkId, &memberSidecarId, "smtp/25/mx.alice"), networks, scopes); err != nil {
		t.Fatalf("the member's consented device: %v", err)
	}
	if err := mxedgeservice.ValidateSmtpListen(ctx, testSmtpListenCheck(networkId, &otherSidecarId, "smtp/25/mx.alice"), networks, scopes); !errors.Is(err, socketsservice.ErrSocketListenRefused) {
		t.Errorf("another member's device: %v, want a refusal", err)
	}
	if err := mxedgeservice.ValidateSmtpListen(ctx, testSmtpListenCheck(networkId, &memberSidecarId, "smtp/25/mx.bob"), networks, scopes); !errors.Is(err, socketsservice.ErrSocketListenRefused) {
		t.Errorf("a scope that does not stand: %v, want a refusal", err)
	}
	// the network's own mx asks no scope
	if err := mxedgeservice.ValidateSmtpListen(ctx, testSmtpListenCheck(networkId, &otherSidecarId, "smtp/25/mx"), networks, scopes); err != nil {
		t.Errorf("the network's own mx: %v", err)
	}
	for _, undecided := range []*testSmtpScopes{{undecided: true}, {broken: true}} {
		err := mxedgeservice.ValidateSmtpListen(ctx, testSmtpListenCheck(networkId, &memberSidecarId, "smtp/25/mx.alice"), networks, undecided)
		if !errors.Is(err, socketsservice.ErrSocketListenUnavailable) {
			t.Errorf("a scope source that cannot decide: %v, want undecided", err)
		}
	}
}

// The hooks under the sockets engine's smtp/ namespace: the engine's own checks, then §15's, and the first listen
// and last unlisten reach the host.
func TestSmtpListenHooksUnderTheSocketsNamespace(t *testing.T) {
	ctx := context.Background()
	networkId, sidecarId := connect.NewId(), connect.NewId()
	type change struct {
		networkId connect.Id
		name      string
		listening bool
	}
	changes := []change{}
	hooks := mxedgeservice.NewSmtpListenHooks(&mxedgeservice.SmtpListenHooksArgs{
		Networks: &testMailNetworks{enabled: map[connect.Id]bool{networkId: true}},
		ListenersChanged: func(networkId connect.Id, name string, listening bool) {
			changes = append(changes, change{networkId, name, listening})
		},
	})
	namespace, err := socketsservice.NewSocketSmtpNamespace(hooks, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := namespace.ValidateListen(ctx, testSmtpListenCheck(networkId, &sidecarId, "smtp/25/mx")); err != nil {
		t.Fatalf("a receiver through the namespace: %v", err)
	}
	if err := namespace.ValidateListen(ctx, testSmtpListenCheck(networkId, &sidecarId, "smtp/587/mx")); !errors.Is(err, socketsservice.ErrSocketListenRefused) {
		t.Errorf("port 587 through the namespace: %v", err)
	}
	if err := namespace.ValidateListen(ctx, testSmtpListenCheck(connect.NewId(), &sidecarId, "smtp/25/mx")); !errors.Is(err, socketsservice.ErrSocketListenUnavailable) {
		t.Errorf("an unknown network through the namespace: %v", err)
	}
	namespace.FirstListen(networkId, "smtp/25/mx")
	namespace.LastUnlisten(networkId, "smtp/25/mx")
	if len(changes) != 2 || changes[0] != (change{networkId, "smtp/25/mx", true}) || changes[1] != (change{networkId, "smtp/25/mx", false}) {
		t.Errorf("changes %+v", changes)
	}
	// hooks with no sources refuse every listen and take the transitions
	bare := mxedgeservice.NewSmtpListenHooks(nil)
	if err := bare.ValidateListen(ctx, testSmtpListenCheck(networkId, &sidecarId, "smtp/25/mx")); !errors.Is(err, socketsservice.ErrSocketListenRefused) {
		t.Errorf("hooks with no source: %v", err)
	}
	bare.FirstListen(networkId, "smtp/25/mx")
	bare.LastUnlisten(networkId, "smtp/25/mx")
}
