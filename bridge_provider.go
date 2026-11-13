//go:build !ios_extension && !sidecar_http

// The host's NAT and provider for one client generation (DESIGN-DETAILS 12.2.5's gate): the generation's LocalUserNat is
// built with the device role's hook in its settings, so no flow of it ever runs unhooked (12.1's D.3, a provider before
// its hook), and the RemoteUserNatProvider that lets a source's frames reach it is built only once the component's
// catch-up has run. Both end with the generation's context, and with them its flows, so a new generation keeps the sink
// and binds a new NAT when its hook is set.
//
// The provider takes contracts as the generation's client provides them; which sources may open one is C13's and the
// contract gate's (ACL-M4-01). A daemon's client sets ExposeVerifiedPeerClientKey (rpc_subprotocol.go), which the hook's
// VerifyPrincipal needs: with it off a peer reads as no session and is refused (BRIDGE-M4-10).

package sidecar

import (
	"context"
	"errors"
	"sync"

	"github.com/urnetwork/connect"
)

// One generation's gate: its NAT from the start, its provider once serve runs.
type bridgeProviderGate struct {
	env         *SidecarEnv
	nat         *connect.LocalUserNat
	newProvider func(client *connect.Client, nat *connect.LocalUserNat) (func(), error)

	stateLock     sync.Mutex
	closeProvider func()
	closed        bool
}

// The connect parts a gate builds, which tests stand in for.
type bridgeProviderParts struct {
	// Builds the NAT from its settings, which carry the hook.
	newNat func(ctx context.Context, settings *connect.LocalUserNatSettings) *connect.LocalUserNat
	// Builds the provider over the generation's client and the NAT, and the function that closes it.
	newProvider func(client *connect.Client, nat *connect.LocalUserNat) (func(), error)
}

// connect's own parts, on the component's settings.
func defaultBridgeProviderParts(settings *BridgeComponentSettings) *bridgeProviderParts {
	return &bridgeProviderParts{
		newNat: func(ctx context.Context, natSettings *connect.LocalUserNatSettings) *connect.LocalUserNat {
			return connect.NewLocalUserNat(ctx, "bridge", natSettings)
		},
		newProvider: func(client *connect.Client, nat *connect.LocalUserNat) (func(), error) {
			providerSettings := settings.Provider
			if providerSettings == nil {
				providerSettings = connect.DefaultRemoteUserNatProviderSettings()
			}
			provider, err := connect.TryNewRemoteUserNatProvider(client, nat, providerSettings)
			if err != nil {
				return nil, err
			}
			return provider.Close, nil
		},
	}
}

// The generation's NAT, built now with hook in a copy of the settings' NAT settings; no provider yet. hook must be
// the device role's, never nil: a NAT with no hook carries flows as before hooks existed.
func newBridgeProviderGate(env *SidecarEnv, hook connect.EgressHook, settings *BridgeComponentSettings, parts *bridgeProviderParts) (*bridgeProviderGate, error) {
	if hook == nil {
		return nil, errors.New("bridge provider: the device role gives no hook")
	}
	natSettings := connect.DefaultLocalUserNatSettings()
	if settings.Nat != nil {
		copied := *settings.Nat
		natSettings = &copied
	}
	natSettings.EgressHook = hook
	return &bridgeProviderGate{
		env:         env,
		nat:         parts.newNat(env.Ctx, natSettings),
		newProvider: parts.newProvider,
	}, nil
}

// Builds the provider on the generation's client: from here on a source's frame can reach the NAT.
func (self *bridgeProviderGate) serve() error {
	closeProvider, err := self.newProvider(self.env.Client, self.nat)
	if err != nil {
		return err
	}
	keep := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.closeProvider = closeProvider
		return true
	}()
	if !keep {
		closeProvider()
		return errors.New("bridge provider: the generation ended")
	}
	return nil
}

// Ends the provider, then the NAT, and with it every flow the generation carried. Idempotent.
func (self *bridgeProviderGate) close() {
	var closeProvider func()
	first := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.closed = true
		closeProvider = self.closeProvider
		return true
	}()
	if !first {
		return
	}
	if closeProvider != nil {
		closeProvider()
	}
	if self.nat != nil {
		self.nat.Close()
	}
}
