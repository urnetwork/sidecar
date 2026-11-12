//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http

// Remote serving's registration (CORE-M10-05; R-CORE-19, D-CORE-17, I-9, I-13, I-19, FI-24, FS-83; §5.8, §6.11): where a
// network designates this daemon for search (§7.9's IndexerSet naming this device, its services naming search) and
// Search.RemoteServe is on, the network's Sidecar serves §6.11's SEARCH with the engine's handler (SEARCH-M10-32's
// SearchRemoteServer.Handle) and sets Hello feature bit 0, so a requester's Hello learns it and a control contract
// accepts SEARCH (rpc_contract_class.go); where it does not, neither. It rides a component of its own, search-serve,
// so each client generation registers it with that generation's dispatcher, and it follows the verified config: at
// each entry the installed authority applies, and every Search.ServeRecheckInterval besides for an authority installed
// later, it registers or unregisters. The handler goes before bit 0 is set and after it is cleared, so no requester
// learns the bit while no handler answers.
//
// Each request is checked against the designation before the handler runs, PERMISSION_DENIED otherwise (DESIGN-DETAILS
// 7.2.5's step 2, which reads no byte of the body), and the handler's outcome is counted into the network's
// SidecarStats: a reply as a page served, an Error by its code, with no requester, repo or query label (I-13). A
// *SidecarRemoteRefusal from the budget answers RESOURCE_EXHAUSTED with its retry_after_ms. Serving runs on the
// dispatcher's handler goroutines, outside every MCP session and run, so it taints none (I-9), and it persists nothing
// but the served record the server writes (SidecarSearchState.RecordServed). While designated the network's index cache
// keeps a designated daemon's bound, and the all of each repo this device reads among those it holds
// (state_search_bounds.go).
//
// Daemon hosts only: phones never serve (§11.14), and Search.RemoteServe is false on app hosts.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
)

// The component that serves remote search, beside a network's others.
const searchServeComponentName = "search-serve"

// What a network serves remote search with (ServeRemoteSearch).
type DaemonSearchServe struct {
	// SEARCH's handler: SEARCH-M10-32's SearchRemoteServer.Handle, built on this network's handle on the daemon's
	// SidecarRemoteBudget (SidecarRemoteBudget.For). Required.
	Handler SubprotocolHandler
	// Opens a designation's sealed services with the config generation's key, as ConfigState.SearchIndexersFor's
	// argument does. Nil opens none, so no designation names search and nothing is served.
	Services func(indexer ConfigIndexer) ([]protocol.IndexerService, bool)
	// Whether this device is designated for search now. Nil reads the verified config through Services.
	Designated func() bool
}

// Serves networkId's remote searches with serve while the network designates this device for search and
// Search.RemoteServe is on: the network's Sidecar gains the search-serve component. The answer removes it, ending
// serving on every generation.
func (self *Daemon) ServeRemoteSearch(networkId Id, serve *DaemonSearchServe) (func(), error) {
	if serve == nil || serve.Handler == nil {
		return nil, fmt.Errorf("%w: remote serving needs its handler", ErrDaemonRegistration)
	}
	sidecar, ok := self.SidecarForNetwork(networkId)
	if !ok {
		return nil, fmt.Errorf("%w: no hosted network serves it", ErrDaemonRegistration)
	}
	if !sidecar.settings.Search.RemoteServe {
		return nil, fmt.Errorf("%w: Search.RemoteServe is off on this host", ErrSidecarSearchRefused)
	}
	return sidecar.AddComponent(newSearchServeComponent(sidecar, serve))
}

// The search-serve component of one network's Sidecar.
type searchServeComponent struct {
	sidecar *Sidecar
	serve   *DaemonSearchServe
}

// The search-serve component of sidecar, serving with serve.
func newSearchServeComponent(sidecar *Sidecar, serve *DaemonSearchServe) *searchServeComponent {
	return &searchServeComponent{sidecar: sidecar, serve: serve}
}

// See SidecarComponent.
func (self *searchServeComponent) Name() string {
	return searchServeComponentName
}

// Follows the designation on this generation's dispatcher until the generation ends. See SidecarComponent.
func (self *searchServeComponent) Attach(env *SidecarEnv) error {
	if env.Subprotocol == nil {
		return errors.New("remote serving needs the generation's dispatcher")
	}
	go self.follow(env.Ctx, env.Subprotocol)
	return nil
}

// Nothing outlives the generations, whose contexts end their registrations. See SidecarComponent.
func (self *searchServeComponent) Close() {}

// What serving registers on: a generation's *Subprotocol, which a test fakes.
type searchServeDispatcher interface {
	Handle(messageType protocol.MessageType, handler SubprotocolHandler, options *HandleOptions) (remove func(), err error)
	SetFeatures(features uint64, asksSearch func(clientId Id) bool) error
}

// Registers or unregisters as the designation stands, at each entry the installed authority applies and every
// Search.ServeRecheckInterval, until ctx ends, when it unregisters.
func (self *searchServeComponent) follow(ctx context.Context, dispatcher searchServeDispatcher) {
	var registered func()
	var authority SidecarAuthority
	var removeCallback func()
	entries := make(chan struct{}, 1)
	defer func() {
		if removeCallback != nil {
			removeCallback()
		}
		if registered != nil {
			self.unregister(dispatcher, registered)
		}
	}()
	for {
		if current := self.sidecar.authority(); current != authority {
			if removeCallback != nil {
				removeCallback()
				removeCallback = nil
			}
			authority = current
			if authority != nil {
				removeCallback = authority.AddEntryCallback(func(*SidecarAuthorityEntry) {
					select {
					case entries <- struct{}{}:
					default:
					}
				})
			}
		}
		registered = self.apply(dispatcher, registered)
		select {
		case <-ctx.Done():
			return
		case <-entries:
		case <-self.sidecar.clock.After(self.sidecar.settings.Search.ServeRecheckInterval):
		}
	}
}

// Brings the registration to the designation: registered, nil when not, is what the last apply left, and the answer
// is what this one leaves.
func (self *searchServeComponent) apply(dispatcher searchServeDispatcher, registered func()) func() {
	designated := self.designated()
	switch {
	case designated && registered == nil:
		remove, err := dispatcher.Handle(protocol.MessageType_SEARCH, self.handle, nil)
		if err != nil {
			self.sidecar.log.Warningf("[search]remote serving could not register: %s", err)
			return nil
		}
		if err := dispatcher.SetFeatures(SubprotocolFeatureServesSearch, nil); err != nil {
			self.sidecar.log.Warningf("[search]remote serving could not set its bit: %s", err)
			remove()
			return nil
		}
		self.setCacheDesignated(true)
		return remove
	case !designated && registered != nil:
		self.unregister(dispatcher, registered)
		return nil
	}
	return registered
}

// Clears bit 0, then takes the handler away.
func (self *searchServeComponent) unregister(dispatcher searchServeDispatcher, registered func()) {
	if err := dispatcher.SetFeatures(0, nil); err != nil {
		self.sidecar.log.Warningf("[search]remote serving could not clear its bit: %s", err)
	}
	registered()
	self.setCacheDesignated(false)
}

// Whether this device serves now: Search.RemoteServe on and a designation that names search.
func (self *searchServeComponent) designated() bool {
	if !self.sidecar.settings.Search.RemoteServe {
		return false
	}
	if self.serve.Designated != nil {
		return self.serve.Designated()
	}
	return self.sidecar.searchDesignated(self.serve.Services)
}

// Whether the verified config holds a designation of this device whose services, opened by services, name search.
// Fails closed: no identity, no verified config, or services nil or unable to open them, is no designation.
func (self *Sidecar) searchDesignated(services func(indexer ConfigIndexer) ([]protocol.IndexerService, bool)) bool {
	identity := self.currentIdentity()
	if identity == nil || services == nil {
		return false
	}
	state, err := self.configState()
	if err != nil {
		return false
	}
	for _, indexer := range state.Indexers() {
		if indexer.SidecarId != identity.SidecarId {
			continue
		}
		if offered, opened := services(indexer); opened && slices.Contains(offered, protocol.IndexerService_INDEXER_SERVICE_SEARCH) {
			return true
		}
	}
	return false
}

// Sets the network's cache to a designated daemon's bound, keeping the all of each repo this device reads among those it
// holds, or back.
func (self *searchServeComponent) setCacheDesignated(designated bool) {
	cache, err := self.sidecar.SearchCache()
	if err != nil {
		if self.sidecar.log.V(1).Enabled() {
			self.sidecar.log.Infof("[search]the index cache did not open for serving: %s", err)
		}
		return
	}
	if !designated {
		cache.SetDesignated(false, nil)
		return
	}
	servedRepoIds := []Id{}
	identity := self.sidecar.currentIdentity()
	if state, err := self.sidecar.configState(); err == nil && identity != nil {
		heldRepoIds, err := cache.HeldRepoIds()
		if err == nil {
			for _, repoId := range heldRepoIds {
				if slices.Contains(state.RepoReaders(repoId), identity.SidecarId) {
					servedRepoIds = append(servedRepoIds, repoId)
				}
			}
		}
	}
	cache.SetDesignated(true, servedRepoIds)
}

// SEARCH's handler beneath searchHandler's size rules: the designation checked before the engine's handler runs, and
// the outcome counted.
func (self *searchServeComponent) handle(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
	stats := &self.sidecar.stats
	if !self.designated() {
		stats.remoteRefused(protocol.ErrorCode_ERR_PERMISSION_DENIED.String())
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_PERMISSION_DENIED}
	}
	body, err := self.serve.Handler(ctx, request)
	if err != nil {
		var refusal *SidecarRemoteRefusal
		if errors.As(err, &refusal) {
			err = refusal.SubprotocolError()
		}
		code, ok := SubprotocolErrorCode(err)
		if !ok {
			// the dispatcher answers any other error UNAVAILABLE
			code = protocol.ErrorCode_ERR_UNAVAILABLE
		}
		stats.remoteRefused(code.String())
		return nil, err
	}
	stats.remotePageCount.Add(1)
	return body, nil
}

// Raises settings to a daemon designated for search's (owner decision 175, D-CORE-17): Search.CacheByteCount to at least
// Search.DesignatedCacheByteCount and MemoryBudgetByteCount to at least Search.DesignatedMemoryBudgetByteCount. The
// host applies it before NewSidecar where it runs as an indexer, as `ur indexer add`'s unit does; the cache also holds
// the designated bound itself while designated (SearchCache.SetDesignated).
func ApplySearchDesignatedSettings(settings *SidecarSettings) {
	settings.Search.CacheByteCount = max(settings.Search.CacheByteCount, settings.Search.DesignatedCacheByteCount)
	settings.MemoryBudgetByteCount = max(settings.MemoryBudgetByteCount, settings.Search.DesignatedMemoryBudgetByteCount)
}
