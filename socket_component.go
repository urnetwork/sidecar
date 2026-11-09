//go:build !sidecar_http

// The sockets SidecarComponent (§5.4, §9): the registrar (socket_registrar.go) on a Sidecar's client generations. The
// registrar and its set live for the network across generations, since a Listen outlives a reconnect; each generation
// it follows lends it the SidecarApi call on its token, its identity key and its push feed's topic sock, and takes them
// back when it ends. SOCK-M5-11's listener registers through it and admits on what it keeps, and SOCK-M5-12's dialer
// shares its ring.
//
// K_sock's ring comes through SetKeyRing from whoever reads the verified config head (§7.9), which nothing in the core
// does yet. Until a ring is set, a Listen on an application or share/ name is refused, since that name has no token
// path and never leaves the device in the clear (D-SOCK-13); edge names register without one.
//
// Nothing adds this component yet: the daemon's composition does, beside evs's, as SOCK-M5-11 lands Sidecar.Listen.
// connect legs only: the sidecar_http leg runs no component (§18.10). Safe for concurrent use.

package sidecar

import (
	"context"
	"fmt"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Its keychain namespace and its sealed directory (§5.9).
const socketComponentName = "sockets"

// What NewSocketComponent takes. Sidecar.SocketComponentArgs fills it for the network a Sidecar is enrolled in.
type SocketComponentArgs struct {
	NetworkId Id
	// SidecarSettings.Sockets.
	Settings *SidecarSocketSettings
	// Sidecar.Sign, which claims each registration (§9.5).
	Sign func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error)
	// nil is real time.
	Clock Clock
	// nil is the default logger.
	Log Logger
}

// The sockets component.
type SocketComponent struct {
	registrar *socketRegistrar
}

// The args a SocketComponent takes from this Sidecar for the network it is enrolled in: its settings, Sign, the clock
// and the log.
func (self *Sidecar) SocketComponentArgs() (*SocketComponentArgs, error) {
	networkId := self.enrolledNetworkId()
	if networkId == nil {
		return nil, fmt.Errorf("%w: sockets needs an enrolled network", errInvalidSettings)
	}
	return &SocketComponentArgs{
		NetworkId: *networkId,
		Settings:  self.settings.Sockets,
		Sign:      self.Sign,
		Clock:     self.clock,
		Log:       self.log,
	}, nil
}

// A component whose registrar runs until Close or ctx ends, attached to no generation yet.
func NewSocketComponent(ctx context.Context, args *SocketComponentArgs) (*SocketComponent, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no socket component args", errInvalidSettings)
	}
	registrar, err := newSocketRegistrar(ctx, &socketRegistrarArgs{
		NetworkId: args.NetworkId,
		Settings:  args.Settings,
		Sign:      args.Sign,
		Clock:     args.Clock,
		Log:       args.Log,
	})
	if err != nil {
		return nil, err
	}
	return &SocketComponent{registrar: registrar}, nil
}

// "sockets".
func (self *SocketComponent) Name() string {
	return socketComponentName
}

// Follows one generation: the registrar calls on its token until env.Ctx ends, and its push feed's notices on topic
// sock ask for the set at once. A generation whose dispatcher has no push client yet attaches without hints, and the
// heartbeat carries it. A generation of another network is refused.
func (self *SocketComponent) Attach(env *SidecarEnv) error {
	if env == nil || env.SidecarApi == nil || env.Identity == nil {
		return fmt.Errorf("%w: sockets needs the generation's api and identity", errInvalidSettings)
	}
	if env.Identity.NetworkId != self.registrar.networkId {
		return fmt.Errorf("%w: a generation of another network", errInvalidSettings)
	}
	attachmentSeq := self.registrar.attach(env.Ctx, env.SidecarApi.SocketRegistrations, env.Identity.IdentityPublicKey)
	remove := func() {}
	if env.Subprotocol != nil {
		if unsubscribe, err := env.Subprotocol.Subscribe(PushTopicSock, self.registrar.hint); err == nil {
			remove = unsubscribe
		}
	}
	go func() {
		<-env.Ctx.Done()
		remove()
		self.registrar.detach(attachmentSeq)
	}()
	return nil
}

// Ends the registrar, after the Sidecar's last generation. Never from a registration's callback, which runs on the
// registrar's own goroutine.
func (self *SocketComponent) Close() {
	self.registrar.close()
}

// Installs the newest K_sock ring of the network's verified config head (§7.9): blinded names register under it, both
// paths through a rotation's overlap, and the set goes at once. A ring of another network is refused.
func (self *SocketComponent) SetKeyRing(ring *SocketKeyRing) error {
	return self.registrar.setKeyRing(ring)
}

// The registrar SOCK-M5-11's listener registers through.
func (self *SocketComponent) socketRegistrar() *socketRegistrar {
	return self.registrar
}
