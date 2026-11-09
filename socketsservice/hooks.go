// §9.4's namespace hooks: what each edge namespace's owner checks before a lease is written, and what
// it is told when a name gains its first listener or loses its last. §13 registers tls/ (TLS-M5-22),
// §15 smtp/ (MAIL-M7-22) and the platform ur/ (SOCK-M9-01); SOCK-M6-01 adds scope hosts. A namespace no
// owner has registered is refused, so smtp/ and ur/ stay closed until M7 and M9, and an application or
// share name needs no hook, since the gate alone decides it (§9.10).
//
// Hooks run on the registration path with no state lock held. ValidateListen reads what it needs from
// memory, as the gate does (plan-SOCK-gate-data's facts), and FirstListen and LastUnlisten only note the
// change for a worker of their own: they fire on explicit transitions, and a lease that expires fires
// nothing (SOCK.md reading 5).

package socketsservice

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// ValidateListen refuses the entry: the engine answers denied, or revoked when the entry held a lease.
var ErrSocketListenRefused = errors.New("socket listen refused by its namespace")

// ValidateListen cannot decide yet, such as a tls/ entry with no cached facts (plan-SOCK-gate-data):
// the engine refuses the page with unavailable, so the client retries and keeps what it held.
var ErrSocketListenUnavailable = errors.New("socket listen undecided by its namespace")

// What ValidateListen judges: one entry that passed its claim and the gate's listen.
type SocketListenCheck struct {
	NetworkId        connect.Id
	ListenerClientId connect.Id
	// The caller's sidecar, when its token names one.
	SidecarId *connect.Id
	// Canonical, in the namespace the hooks were registered for.
	Name      string
	Namespace sidecar.SocketNamespace
	// What the entry registers, defaults applied: AppMode is tls/'s http or raw (§9.5).
	Registration *sidecar.SocketRegistration
	// The gate's allow, whose grant §13.9's quota and certificate checks read.
	Listen *SocketGateVerdict
}

// One namespace's owner (§9.4). Safe for concurrent use.
type SocketNamespaceHooks interface {
	// nil allows the entry. ErrSocketListenRefused refuses it, and ErrSocketListenUnavailable or any
	// other error refuses the page as unavailable.
	ValidateListen(ctx context.Context, check *SocketListenCheck) error
	// A name of the namespace gained its first live listener in its network.
	FirstListen(networkId connect.Id, name string)
	// A name of the namespace lost its last listener by an unlisten or a removal.
	LastUnlisten(networkId connect.Id, name string)
}

// The engine's registered owners, by namespace. Safe for concurrent use.
type socketNamespaceRegistry struct {
	stateLock      sync.Mutex
	namespaceHooks map[sidecar.SocketNamespace]SocketNamespaceHooks
}

func newSocketNamespaceRegistry() *socketNamespaceRegistry {
	return &socketNamespaceRegistry{
		namespaceHooks: map[sidecar.SocketNamespace]SocketNamespaceHooks{},
	}
}

// Registers the owner of an edge namespace. Only tls/, smtp/ and ur/ take hooks: an application or
// share name is the gate's alone, and a reserved name has no owner at all. A second registration of
// one namespace is a host's bug.
func (self *socketNamespaceRegistry) register(namespace sidecar.SocketNamespace, hooks SocketNamespaceHooks) error {
	switch namespace {
	case sidecar.SocketNamespaceTls, sidecar.SocketNamespaceSmtp, sidecar.SocketNamespacePlatform:
	default:
		return fmt.Errorf("namespace %d takes no hooks", namespace)
	}
	if hooks == nil {
		return errors.New("no hooks")
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, registered := self.namespaceHooks[namespace]; registered {
		return fmt.Errorf("namespace %d already has hooks", namespace)
	}
	self.namespaceHooks[namespace] = hooks
	return nil
}

// The namespace's owner, and false for an edge namespace nobody registered, which refuses every
// entry. Application and share names answer false too: they need no hook, and the caller asks this
// only for an edge name.
func (self *socketNamespaceRegistry) lookup(namespace sidecar.SocketNamespace) (SocketNamespaceHooks, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	hooks, registered := self.namespaceHooks[namespace]
	return hooks, registered
}
