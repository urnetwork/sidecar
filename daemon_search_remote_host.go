//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http

// A daemon serves the same verified index snapshots held by its network's local search engine.
package sidecar

import (
	"context"
	"sync/atomic"

	"github.com/urnetwork/sidecar/protocol"
)

// Registers the network's server on each client generation. Registration waits for a signed
// designation, a verified config client, and a local engine over this Sidecar's cache.
func (self *Daemon) HostRemoteSearch(networkId Id, budget *SidecarRemoteBudget) (func(), error) {
	running, ok := self.SidecarForNetwork(networkId)
	if !ok || budget == nil {
		return nil, ErrDaemonRegistration
	}
	host := &daemonSearchRemoteHost{searchRemoteHostAuthority: newSearchRemoteHostAuthority(running, networkId), budget: budget.For(running)}
	return self.ServeRemoteSearch(networkId, &DaemonSearchServe{open: host.open, Services: host.services, Designated: host.designated})
}

type daemonSearchRemoteHost struct {
	*searchRemoteHostAuthority
	budget *SidecarRemoteBudget
}

func (self *daemonSearchRemoteHost) designated() bool {
	state, err := self.config()
	selfId, ok := self.selfId()
	if err != nil || !ok {
		return false
	}
	_, standing := state.standingSidecar(selfId, self.running.clock.Now().UnixMilli())
	return standing && searchRemoteServesSearch(state, selfId, self.services)
}

// The underlying verified Hello identifies the requester. Bind its identity key to the current
// admission before opening a page, including a retry of a previously authorized page.
func (self *daemonSearchRemoteHost) open() (*searchServeRegistration, error) {
	installed, err := self.running.searchEngine()
	if err != nil {
		return nil, err
	}
	engine, ok := installed.(*SearchEngine)
	if !ok {
		return nil, ErrSidecarSearchUnavailable
	}
	cache, err := self.running.SearchCache()
	if err != nil || engine.args.Cache != cache {
		return nil, ErrSidecarSearchUnavailable
	}
	state, err := self.running.SearchState()
	if err != nil {
		return nil, err
	}
	server, err := NewSearchRemoteServer(&SearchRemoteServerArgs{
		Settings: self.running.settings.Search, Wire: &self.running.settings.ProtocolSettings.Search,
		Config: self.config, Services: self.services, SelfId: self.selfId, Budget: self.budget,
		State: state, Engine: engine, HeldRepoKey: self.running.GkmHeldKey, Clock: self.running.clock, Log: self.running.log,
	})
	if err != nil {
		return nil, err
	}
	removeHooks, err := cache.AddDeleteHooks(&SearchDeleteHooks{EndRepo: server.EndRepo})
	if err != nil {
		server.Close()
		return nil, err
	}
	var locked atomic.Bool
	removeLockHook := cache.AddCursor(func() {
		locked.Store(true)
		server.Close()
	})
	current := func() bool {
		installed, err := self.running.searchEngine()
		return !locked.Load() && err == nil && installed == engine
	}
	handler := func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		if request == nil || request.Peer == nil || len(request.Peer.IdentityPublicKey) == 0 {
			return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAUTHENTICATED}
		}
		if !current() {
			return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAVAILABLE}
		}
		return server.Handle(ctx, request)
	}
	return &searchServeRegistration{handler: handler, current: current, close: func() {
		removeLockHook()
		server.Close()
		removeHooks()
	}}, nil
}
