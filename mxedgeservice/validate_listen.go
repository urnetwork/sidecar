// §15.5's ValidateListen for smtp/ (§13.9, MAIL-M7-22): what §15 itself asks of a receiver's listen before the
// sockets engine admits `smtp/25/mx` or `smtp/25/mx.<scope>`. The engine's smtp/ namespace (socketsservice's
// NewSocketSmtpNamespace) wraps these hooks, so a host opens smtp/ with RegisterSmtpNamespace(NewSmtpListenHooks(...),
// scopes).
//
//	name     port 25 and host `mx` or `mx.<scope>`, nothing else: the name mxedge splices a network's sessions to
//	caller   a sidecar, since a receiver's deposits are signed as one; a client with no sidecar is refused
//	network  one with a mail_network row. A source that cannot tell yet leaves the listen undecided
//	         (ErrSocketListenUnavailable), which refuses the page as unavailable rather than the entry for good
//	scope    a scope's host only where the scope stands in the network, a member scope taking only its member's
//	         consented devices: the scope source's answer, and no source refuses every scope host
//
// No listen is admitted on a default: no network source refuses every one. Safe for concurrent use.

package mxedgeservice

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/socketsservice"
)

// The parts of a receiver's socket name, `smtp/25/mx` and `smtp/25/mx.<scope>`: identifiers of §15.5's name, not
// limits.
const (
	smtpListenNamespace = "smtp"
	smtpListenPort      = "25"
	smtpListenHostLabel = "mx"
)

// Which networks have mail enabled, as the platform's mail_network rows say. Implementations are safe for
// concurrent use.
type MailNetworkSource interface {
	// Whether networkId has a mail_network row. An error where that cannot be told now.
	MailEnabled(ctx context.Context, networkId connect.Id) (bool, error)
}

// The scope of a receiver's socket name, "" for the network's own `mx`; false where name is no receiver's.
func SmtpListenScope(name string) (scope string, ok bool) {
	parts := strings.Split(name, "/")
	if len(parts) != 3 || parts[0] != smtpListenNamespace || parts[1] != smtpListenPort {
		return "", false
	}
	label, scope, scoped := strings.Cut(parts[2], ".")
	if label != smtpListenHostLabel || (scoped && scope == "") {
		return "", false
	}
	return scope, true
}

// §15's check of one smtp/ listen: see the file header. nil admits it, ErrSocketListenRefused refuses the entry,
// and ErrSocketListenUnavailable leaves it undecided.
func ValidateSmtpListen(ctx context.Context, check *socketsservice.SocketListenCheck, networks MailNetworkSource, scopes socketsservice.SocketScopeConsent) error {
	if check == nil || check.Namespace != sidecar.SocketNamespaceSmtp {
		return fmt.Errorf("%w: not an smtp/ entry", socketsservice.ErrSocketListenRefused)
	}
	scope, ok := SmtpListenScope(check.Name)
	if !ok {
		return fmt.Errorf("%w: a receiver listens at smtp/25/mx or smtp/25/mx.<scope>", socketsservice.ErrSocketListenRefused)
	}
	if check.SidecarId == nil {
		return fmt.Errorf("%w: a receiver is a sidecar", socketsservice.ErrSocketListenRefused)
	}
	if networks == nil {
		return fmt.Errorf("%w: no mail network source", socketsservice.ErrSocketListenRefused)
	}
	enabled, err := networks.MailEnabled(ctx, check.NetworkId)
	if err != nil {
		return fmt.Errorf("%w: %v", socketsservice.ErrSocketListenUnavailable, err)
	}
	if !enabled {
		return fmt.Errorf("%w: the network has no mail", socketsservice.ErrSocketListenRefused)
	}
	if scope == "" {
		return nil
	}
	if scopes == nil {
		return fmt.Errorf("%w: no scope source", socketsservice.ErrSocketListenRefused)
	}
	err = scopes.ConsentListen(check.NetworkId, scope, check.SidecarId)
	if err == nil || errors.Is(err, socketsservice.ErrSocketListenRefused) || errors.Is(err, socketsservice.ErrSocketListenUnavailable) {
		return err
	}
	return fmt.Errorf("%w: %v", socketsservice.ErrSocketListenUnavailable, err)
}

// What NewSmtpListenHooks builds on.
type SmtpListenHooksArgs struct {
	// Nil refuses every listen.
	Networks MailNetworkSource
	// Nil refuses every scope host.
	Scopes socketsservice.SocketScopeConsent
	// Called, when set, as a receiver's name gains its first listener in a network (true) or loses its last
	// (false): the moment the network's route is projected again. It must not block.
	ListenersChanged func(networkId connect.Id, name string, listening bool)
}

// smtp/'s mail hooks: ValidateSmtpListen over a network source and a scope source.
type SmtpListenHooks struct {
	networks         MailNetworkSource
	scopes           socketsservice.SocketScopeConsent
	listenersChanged func(networkId connect.Id, name string, listening bool)
}

var _ socketsservice.SocketNamespaceHooks = (*SmtpListenHooks)(nil)

// The hooks a sockets host hands RegisterSmtpNamespace.
func NewSmtpListenHooks(args *SmtpListenHooksArgs) *SmtpListenHooks {
	if args == nil {
		args = &SmtpListenHooksArgs{}
	}
	return &SmtpListenHooks{networks: args.Networks, scopes: args.Scopes, listenersChanged: args.ListenersChanged}
}

// See socketsservice.SocketNamespaceHooks.
func (self *SmtpListenHooks) ValidateListen(ctx context.Context, check *socketsservice.SocketListenCheck) error {
	return ValidateSmtpListen(ctx, check, self.networks, self.scopes)
}

// See socketsservice.SocketNamespaceHooks.
func (self *SmtpListenHooks) FirstListen(networkId connect.Id, name string) {
	if self.listenersChanged != nil {
		self.listenersChanged(networkId, name, true)
	}
}

// See socketsservice.SocketNamespaceHooks.
func (self *SmtpListenHooks) LastUnlisten(networkId connect.Id, name string) {
	if self.listenersChanged != nil {
		self.listenersChanged(networkId, name, false)
	}
}
