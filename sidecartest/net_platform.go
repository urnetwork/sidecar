// A platform under a Net's connect clients (§22.4, Q-TEST-1): what a client runs on in place of the fake contract
// issuer and ControlId sink when NetSettings.Platform gives one. On T3 it is server's exchange (server's sidecart3): a
// client authenticates there as itself, takes its contracts and its control answers from server's controller, and
// reaches its peers through server's exchange, so a row's clients run on what they meet in production, and a row that
// passed on T2's fakes either passes there too or diverges (Q-TEST-1).
//
// What a platform cannot do, the Net refuses rather than fakes: a link's conditions, which T2's exchange sets per pair
// and server's exchange has no seam for, and a pair's contract class, which server's controller seals itself. Each is
// kept as unapplied (Net.Unapplied), and fault.Run fails a row that asked for one, since the row ran without it. A
// platform's frames pass no exchange of the Net's, so its clients' frames are not in the capture's CC2.
//
// The Net builds its platform at its first client, so a Net with none needs nothing a platform needs, and closes it at
// its end, after every client it opened has closed. A platform is safe for concurrent use.

package sidecartest

import (
	"context"
	"errors"
	"fmt"

	"github.com/urnetwork/connect"
)

// What a Net's connect clients run on in place of the fake contract issuer and ControlId sink.
type NetPlatform interface {
	// Opens a Required client called name, under the id the platform gives it, until ctx ends. Answers once the
	// platform routes to the client and its controller takes the client's control, so a peer's contract to it can be
	// issued. The waits are in real time, bounded by the platform's own settings, since connect's timers are real (X9).
	OpenClient(ctx context.Context, name string, settings *connect.ClientSettings) (*NetPlatformClient, error)
	// Ends what the platform runs. The Net calls it once, after canceling every client the platform opened and closing
	// what each one's Close closes.
	Close()
}

// One client a NetPlatform opened.
type NetPlatformClient struct {
	ClientId connect.Id
	Client   *connect.Client
	// Closes what the platform opened beside the client, such as its transport, after the Net cancels the client.
	// nil when there is nothing.
	Close func()
}

// Why OpenClient refuses after the Net closed.
var errNetClosed = errors.New("the Net is closed")

// A client on the platform, with what ends it.
type netPlatformClient struct {
	netClient *NetClient
	// ends the client's context
	cancel context.CancelFunc
	// the platform's NetPlatformClient.Close, or nil
	close func()
}

// The platform, built at the first call, or what building it failed with. A Net with no NetSettings.Platform has none,
// and nil comes back with no error. The build, and a later caller's wait for it, run with the caller's baton given up
// (BarrierDriver.Blocking): the build is real I/O no barrier sees, and an actor waiting for another's build while it
// held the baton would keep that build from ever handing back.
func (self *netExchange) platformOrErr() (NetPlatform, error) {
	if self.net.settings.Platform == nil {
		return nil, nil
	}
	self.net.barriers.Blocking(func() {
		self.platformOnce.Do(func() {
			platform, err := self.net.settings.Platform(self.ctx, self.net)
			if err != nil {
				self.platformErr = fmt.Errorf("the Net's platform did not start: %w", err)
				return
			}
			if platform == nil {
				self.platformErr = errors.New("the Net's platform builder gave no platform")
				return
			}
			self.platform = platform
		})
	})
	return self.platform, self.platformErr
}

// Opens a client on the platform, with its own context under the exchange's. The platform's waits run with the
// caller's baton given up (BarrierDriver.Blocking), since they are on real I/O no barrier sees.
func (self *netExchange) openPlatformClient(platform NetPlatform, name string, settings *connect.ClientSettings) (*NetClient, error) {
	ctx, cancel := context.WithCancel(self.ctx)
	var platformClient *NetPlatformClient
	var err error
	self.net.barriers.Blocking(func() {
		platformClient, err = platform.OpenClient(ctx, name, settings)
	})
	if err == nil && (platformClient == nil || platformClient.Client == nil) {
		err = errors.New("the platform gave no client")
	}
	if err != nil {
		cancel()
		return nil, fmt.Errorf("the platform opened no client %q: %w", name, err)
	}
	netClient := &NetClient{
		Name:          name,
		ClientId:      platformClient.ClientId,
		Client:        platformClient.Client,
		exchange:      self,
		ctx:           ctx,
		receiveRoutes: map[connect.TransportType]connect.Route{},
	}
	closed := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			closed = true
			return
		}
		self.platformClients = append(self.platformClients, &netPlatformClient{
			netClient: netClient,
			cancel:    cancel,
			close:     platformClient.Close,
		})
	}()
	if closed {
		// the Net closed while the platform opened it: nothing will close it later
		platformClient.Client.Cancel()
		cancel()
		if platformClient.Close != nil {
			platformClient.Close()
		}
		return nil, errNetClosed
	}
	return netClient, nil
}

// Cancels every platform client, closes what the platform opened beside each, then the platform. Runs once, from close.
func (self *netExchange) closePlatform() {
	var platformClients []*netPlatformClient
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		platformClients = self.platformClients
		self.platformClients = nil
	}()
	for _, platformClient := range platformClients {
		platformClient.netClient.Client.Cancel()
		platformClient.cancel()
		if platformClient.close != nil {
			platformClient.close()
		}
	}
	// a platform never built is never built now
	self.platformOnce.Do(func() {
		self.platformErr = errNetClosed
	})
	if self.platform != nil {
		self.platform.Close()
	}
}

// Records what a row asked of the Net that its platform cannot apply.
func (self *netExchange) refuseOnPlatform(asked string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.unapplied = append(self.unapplied, asked)
}

// What a row asked of this Net that its platform cannot apply, in the order asked: each a reason the row's run proves
// nothing here (fault.Run fails it). Empty on a Net with no platform.
func (self *Net) Unapplied() []string {
	exchange := self.exchange
	exchange.stateLock.Lock()
	defer exchange.stateLock.Unlock()
	return append([]string{}, exchange.unapplied...)
}

// Whether this Net's connect clients run on a platform rather than on the fake contract issuer and ControlId sink.
func (self *Net) OnPlatform() bool {
	return self.settings.Platform != nil
}
