// The CLI's BridgeHost (§17.10; BRIDGE-M4-18): each link of a daemon's device.Bridge is a RemoteUserNatMultiClient of
// one window client to its target (Q-BRIDGE-2), in ProvideMode_Network, drawn from connect's ApiMultiClientGenerator.
// The generator's mints go through the Sidecar's own api, ApiMultiClientGeneratorSettings.ClientCredentials, never
// connect's plain path: POST /network/auth-client needs a DPoP proof from a strict_exp bearer (§7.4), which only
// SidecarApi signs, so a generator on BringYourApi would fail every mint. Each window client is a child of the
// sidecar's own client (sourceClientId), so C13 seals the subject the delegation names. device.NewBridgeLinkGenerator
// wraps the generator, so every window client carries its signed WindowDelegation and its contracts answer to the
// target's pinned key before it can send; the multi client runs device.BridgeLinkMultiClientSettings, a fixed window
// of one, post-quantum Required, no direct mode before C3 and ICMP on, never DefaultMultiClientSettings.
//
// A share link (FriendsAndFamily) is refused until shares land (BRIDGE-M6-05). With no generation attached, every
// build is refused and the link fails closed.

package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
)

// A build the host refuses.
var errUrBridgeHostRefused = errors.New("bridge link refused")

// connect's mint and removal through the Sidecar's api, which signs the DPoP proof POST /network/auth-client needs
// (connect.NetworkClientCredentials). A mint whose answer does not confirm admin_refused and strict_exp is refused:
// a sidecar keeps nothing of such a client (§5.6).
type urBridgeCredentials struct {
	api *sidecar.SidecarApi
}

var _ connect.NetworkClientCredentials = (*urBridgeCredentials)(nil)

func (self *urBridgeCredentials) AuthNetworkClient(ctx context.Context, args *connect.AuthNetworkClientArgs) (*connect.AuthNetworkClientResult, error) {
	sidecarArgs := &sidecar.SidecarAuthClientArgs{Description: args.Description, DeviceSpec: args.DeviceSpec, DeclaresNoEgress: true}
	if args.ClientId != nil {
		clientId := sidecar.Id(*args.ClientId)
		sidecarArgs.ClientId = &clientId
	}
	if args.SourceClientId != nil {
		sourceClientId := sidecar.Id(*args.SourceClientId)
		sidecarArgs.SourceClientId = &sourceClientId
	}
	result, err := self.api.AuthClient(ctx, sidecarArgs)
	if err != nil {
		apiError := &sidecar.SidecarApiError{}
		if errors.As(err, &apiError) && apiError.Status == 200 {
			switch apiError.Code {
			case "client_limit_exceeded":
				return &connect.AuthNetworkClientResult{Error: &connect.AuthNetworkClientError{ClientLimitExceeded: true, Message: apiError.Code}}, nil
			case "upgrade_required":
				return &connect.AuthNetworkClientResult{Error: &connect.AuthNetworkClientError{UpgradeRequired: true, Message: apiError.Code}}, nil
			}
		}
		return nil, err
	}
	if !result.AdminRefused || !result.StrictExp {
		return nil, fmt.Errorf("%w: a window client api did not mark admin_refused and strict_exp", errUrBridgeHostRefused)
	}
	return &connect.AuthNetworkClientResult{ByClientJwt: result.ByClientJwt}, nil
}

func (self *urBridgeCredentials) RemoveNetworkClient(ctx context.Context, args *connect.RemoveNetworkClientArgs) (*connect.RemoveNetworkClientResult, error) {
	if err := self.api.RemoveClient(ctx, sidecar.Id(args.ClientId)); err != nil {
		return nil, err
	}
	return &connect.RemoveNetworkClientResult{}, nil
}

// What a link's generator mints under: one client generation of the daemon's Sidecar.
type urBridgeGeneration struct {
	// the Sidecar's api, for the target key lookups
	api *sidecar.SidecarApi
	// the mints and removals, through that api (urBridgeCredentials)
	credentials    connect.NetworkClientCredentials
	byJwt          string
	sourceClientId connect.Id
	strategy       *connect.ClientStrategy
	apiUrl         string
	platformUrl    string
}

// The CLI's device.BridgeHost (the file's comment). Safe for concurrent use.
type urBridgeHost struct {
	ctx      context.Context
	settings *device.BridgeSettings
	// the tun's writer, which a link's replies go to; nil drops them until ur tun is up
	receive func(source connect.TransferPath, provideMode protocol.ProvideMode, ipPath *connect.IpPath, packet []byte)

	stateLock  sync.Mutex
	generation *urBridgeGeneration
	// stands in for connect's generator in tests; nil is connect's
	newGenerator func(ctx context.Context, generation *urBridgeGeneration, target connect.Id) connect.MultiClientGenerator
}

var _ device.BridgeHost = (*urBridgeHost)(nil)

// A host whose links run on settings, nil the defaults, and hand their replies to receive.
func newUrBridgeHost(ctx context.Context, settings *device.BridgeSettings) *urBridgeHost {
	if settings == nil {
		settings = device.DefaultBridgeSettings()
	}
	return &urBridgeHost{ctx: ctx, settings: settings}
}

// Takes the generation the next links mint under.
func (self *urBridgeHost) setGeneration(generation *urBridgeGeneration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.generation = generation
}

// Takes the function a link's replies go to.
func (self *urBridgeHost) setReceive(receive func(source connect.TransferPath, provideMode protocol.ProvideMode, ipPath *connect.IpPath, packet []byte)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.receive = receive
}

// The source a send into a link names: the sidecar's own client in the current generation, whose children the window
// clients are; none before a generation, when no link builds.
func (self *urBridgeHost) sourcePath() connect.TransferPath {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.generation == nil {
		return connect.TransferPath{}
	}
	return connect.SourceId(self.generation.sourceClientId)
}

// device.BridgeHost: one link to target, a fixed window of one window client whose delegation sign returns.
func (self *urBridgeHost) NewBridgeLink(ctx context.Context, target connect.Id, subject connect.Id, shareAliases []netip.Prefix,
	sign func(windowClientId connect.Id, windowClientPublicKey []byte, notAfter time.Time) ([]byte, error),
) (connect.UserNatClient, error) {
	if shareAliases != nil {
		return nil, fmt.Errorf("%w: share links come with shares", errUrBridgeHostRefused)
	}
	var generation *urBridgeGeneration
	newGenerator := self.newGenerator
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		generation = self.generation
	}()
	if generation == nil {
		return nil, fmt.Errorf("%w: no client generation", errUrBridgeHostRefused)
	}
	if newGenerator == nil {
		newGenerator = urBridgeApiGenerator
	}
	generator := newGenerator(ctx, generation, target)
	multiClientSettings := device.BridgeLinkMultiClientSettings(self.settings)
	if err := device.CheckBridgeLinkMultiClientSettings(multiClientSettings, self.settings.LinkAllowDirect); err != nil {
		return nil, err
	}
	receive := func(source connect.TransferPath, provideMode protocol.ProvideMode, ipPath *connect.IpPath, packet []byte) {
		var receive func(connect.TransferPath, protocol.ProvideMode, *connect.IpPath, []byte)
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			receive = self.receive
		}()
		if receive != nil {
			receive(source, provideMode, ipPath, packet)
		}
	}
	return connect.NewRemoteUserNatMultiClient(ctx, device.NewBridgeLinkGenerator(ctx, generator, sign), receive,
		protocol.ProvideMode_Network, multiClientSettings), nil
}

// connect's generator for one link: target alone, minted as children of the sidecar's client through the Sidecar's api
// with no identity reuse (device.BridgeLinkApiMultiClientGeneratorSettings).
func urBridgeApiGenerator(ctx context.Context, generation *urBridgeGeneration, target connect.Id) connect.MultiClientGenerator {
	settings := device.BridgeLinkApiMultiClientGeneratorSettings(nil)
	settings.ClientCredentials = generation.credentials
	sourceClientId := generation.sourceClientId
	return connect.NewApiMultiClientGenerator(
		ctx,
		[]*connect.ProviderSpec{{ClientId: &target}},
		generation.strategy,
		nil,
		generation.apiUrl,
		generation.byJwt,
		generation.platformUrl,
		"ur bridge link",
		urBridgeDeviceSpec,
		sidecar.Version,
		&sourceClientId,
		connect.DefaultClientSettings,
		settings,
	)
}

// The device spec a window client is minted with.
const urBridgeDeviceSpec = "ur-bridge"
