// The smtp/ namespace on the engine (§9.4, §9.10, §15.4, §15.5; SOCK-M7-01): a receiver's registration of
// smtp/25/mx, or a Team scope's smtp/25/mx.<scope>, in the clear (D-SOCK-13), protocol smtp-starttls. The
// registration path keeps an edge namespace closed until its owner registers hooks; these are smtp/'s, the
// engine's own rules for the namespace before §15's ValidateListen (MAIL-M7-22), which holds what only mail knows,
// such as whether the network is mail-enabled. Hooks with no §15 check cannot be made, so smtp/ stays closed until
// mail's exist.
//
// The rules, in order, on an entry that already passed the kill set, its listen grant and its claim
// (registrations.go):
//
//   - the host is mx, or mx.<scope>: any other smtp/ host is no receiver's (§15.5);
//   - the protocol is smtp-starttls, which every receiver of the group shares (one protocol a group, §9.5);
//   - a scope host only where the scope source says the scope stands in the network's verified state and, in a
//     member scope, that the listener's sidecar is one of that member's consented devices (§8.5, owner decision
//     126). With no scope source, which SOCK-M6-01's §7.9 scopes and §8.5 consent will give, every scope host is
//     refused: the closed direction;
//   - then §15's check, whose refusal or undecided answer stands as the registration path reads it.
//
// A Find of smtp/ is mxedge's alone and checks each receiver's own listen grant, not a publish (find.go, §9.10,
// §15.4). FirstListen and LastUnlisten go to §15's hooks. Safe for concurrent use.

package socketsservice

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// What §7.9's verified state and §8.5's consent say of a Team scope, for a scope host's registration, read from
// memory as the gate is (I-12). SOCK-M6-01 provides one.
type SocketScopeConsent interface {
	// nil allows: the scope stands in the network and, in a member scope, sidecarId is one of the member's
	// consented devices. ErrSocketListenRefused refuses, and ErrSocketListenUnavailable cannot decide yet.
	ConsentListen(networkId connect.Id, scope string, sidecarId *connect.Id) error
}

// smtp/'s hooks.
type socketSmtpNamespace struct {
	// §15's own check and transitions (MAIL-M7-22).
	mail SocketNamespaceHooks
	// nil until a scope source exists, which refuses every scope host.
	scopes SocketScopeConsent
}

var _ SocketNamespaceHooks = (*socketSmtpNamespace)(nil)

// smtp/'s hooks over §15's mail hooks, which must be given, and scopes, nil refusing every scope host.
func NewSocketSmtpNamespace(mail SocketNamespaceHooks, scopes SocketScopeConsent) (SocketNamespaceHooks, error) {
	if mail == nil {
		return nil, errors.New("smtp/ opens only with §15's ValidateListen")
	}
	return &socketSmtpNamespace{mail: mail, scopes: scopes}, nil
}

// Opens smtp/ on the engine: its hooks over §15's mail hooks and scopes, registered once. The sockets host calls
// this before serving, once mail's hooks exist.
func (self *SocketsService) RegisterSmtpNamespace(mail SocketNamespaceHooks, scopes SocketScopeConsent) error {
	hooks, err := NewSocketSmtpNamespace(mail, scopes)
	if err != nil {
		return err
	}
	return self.RegisterNamespace(sidecar.SocketNamespaceSmtp, hooks)
}

// See SocketNamespaceHooks.
func (self *socketSmtpNamespace) ValidateListen(ctx context.Context, check *SocketListenCheck) error {
	if check.Namespace != sidecar.SocketNamespaceSmtp || check.Registration == nil {
		return fmt.Errorf("%w: not an smtp/ entry", ErrSocketListenRefused)
	}
	host := check.Name[strings.LastIndexByte(check.Name, '/')+1:]
	label, scope, scoped := strings.Cut(host, ".")
	if label != "mx" {
		return fmt.Errorf("%w: no receiver's host", ErrSocketListenRefused)
	}
	if check.Registration.Protocol != socketDefaultSmtpProtocol {
		return fmt.Errorf("%w: a receiver speaks smtp-starttls", ErrSocketListenRefused)
	}
	if scoped {
		if self.scopes == nil {
			return fmt.Errorf("%w: no scope source", ErrSocketListenRefused)
		}
		if err := self.scopes.ConsentListen(check.NetworkId, scope, check.SidecarId); err != nil {
			return err
		}
	}
	return self.mail.ValidateListen(ctx, check)
}

// See SocketNamespaceHooks.
func (self *socketSmtpNamespace) FirstListen(networkId connect.Id, name string) {
	self.mail.FirstListen(networkId, name)
}

// See SocketNamespaceHooks.
func (self *socketSmtpNamespace) LastUnlisten(networkId connect.Id, name string) {
	self.mail.LastUnlisten(networkId, name)
}
