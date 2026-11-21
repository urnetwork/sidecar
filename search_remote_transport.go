//go:build !sidecar_http && !ios_extension

// Remote search's transport (SEARCH-M10-33; §11.14's auth row; §6.4, §6.6; I-3; DESIGN-DETAILS 7.2.4): one client
// generation's dispatcher, as the asker reaches an indexer through it. It names indexers by sidecar_id, as the config
// does, and the dispatcher by client id, so it resolves one to the other as HeadCheck does: a standing Hello's client,
// else the sidecar's current binding from api, which counts only once it verifies, names this network and the sidecar,
// and carries the identity key the sidecar's admission in this device's state holds.
//
// Before the first request to an indexer its Hello stands (Subprotocol.EnsureHello, which checks §6.4's identity binding
// and admission), and the HelloResult must name the indexer's sidecar_id and set bit 0; a failure of either is
// errSearchRemoteAuth, which alarms and drops the indexer until its row or designation changes (§11.14's auth row). The
// SEARCH itself rides Subprotocol.Call, which keeps SEARCH's one size and timeout and never sends a Cancel. The pair's
// contracts are accounted like any peer's: nothing here marks the pair or keeps it warm (owner decision 609).

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// One generation's dispatcher as the asker's transport.
type searchRemoteSubprotocolTransport struct {
	subprotocol *Subprotocol
	api         *SidecarApi
	config      func() (*ConfigState, error)
	clock       Clock

	stateLock sync.Mutex
	// each indexer's client, once resolved, and back
	clients  map[Id]connect.Id
	sidecars map[connect.Id]Id
}

// The transport over one generation's subprotocol, resolving through api where no Hello stands.
func newSearchRemoteSubprotocolTransport(subprotocol *Subprotocol, api *SidecarApi, config func() (*ConfigState, error), clock Clock) *searchRemoteSubprotocolTransport {
	return &searchRemoteSubprotocolTransport{
		subprotocol: subprotocol, api: api, config: config, clock: clockOrReal(clock),
		clients: map[Id]connect.Id{}, sidecars: map[connect.Id]Id{},
	}
}

// The client the indexer is reached at, if known without asking api.
func (self *searchRemoteSubprotocolTransport) knownClient(indexerId Id) (connect.Id, bool) {
	if clientId, ok := self.subprotocol.verifiedClientOf(indexerId); ok {
		self.remember(indexerId, clientId)
		return clientId, true
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	clientId, ok := self.clients[indexerId]
	return clientId, ok
}

// Keeps a resolution, both ways.
func (self *searchRemoteSubprotocolTransport) remember(indexerId Id, clientId connect.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if previous, ok := self.clients[indexerId]; ok && previous != clientId {
		delete(self.sidecars, previous)
	}
	self.clients[indexerId] = clientId
	self.sidecars[clientId] = indexerId
}

// The client the indexer is reached at: known, else its binding from api, checked against this device's state.
func (self *searchRemoteSubprotocolTransport) resolve(ctx context.Context, indexerId Id) (connect.Id, error) {
	if clientId, ok := self.knownClient(indexerId); ok {
		return clientId, nil
	}
	if self.api == nil {
		return connect.Id{}, fmt.Errorf("%w: no api to resolve the indexer's client", errSearchRemoteNoTransport)
	}
	state, err := self.config()
	if err != nil || state == nil {
		return connect.Id{}, ErrSidecarSearchUnavailable
	}
	admission := state.Sidecar(indexerId)
	if admission == nil || admission.Row == nil {
		return connect.Id{}, errSearchRemoteAuth
	}
	record, err := self.api.GetIdentity(ctx, indexerId, 0)
	if err != nil {
		return connect.Id{}, err
	}
	binding, err := VerifySidecarIdentityBinding(record.Binding)
	if err != nil {
		return connect.Id{}, fmt.Errorf("%w: %w", errSearchRemoteAuth, err)
	}
	if binding.SidecarId != indexerId || binding.NetworkId != state.NetworkId() ||
		!slices.Equal(binding.IdentityPublicKey, admission.Row.GetIdentityPublicKey()) {
		return connect.Id{}, errSearchRemoteAuth
	}
	clientId := connect.Id(binding.ClientId)
	self.remember(indexerId, clientId)
	return clientId, nil
}

// See searchRemoteTransport.
func (self *searchRemoteSubprotocolTransport) Call(ctx context.Context, indexerId Id, body []byte, allowed func() bool) ([]byte, error) {
	if !allowed() {
		return nil, errSearchRemotePermission
	}
	clientId, err := self.resolve(ctx, indexerId)
	if err != nil {
		return nil, err
	}
	if err := self.subprotocol.EnsureHello(ctx, Id(clientId)); err != nil {
		var subprotocolError *SubprotocolError
		switch {
		case errors.As(err, &subprotocolError) && subprotocolError.Code == protocol.ErrorCode_ERR_UNAUTHENTICATED:
			return nil, fmt.Errorf("%w: %w", errSearchRemoteAuth, err)
		case errors.As(err, &subprotocolError), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded),
			errors.Is(err, errSubprotocolClosed):
			return nil, err
		}
		// the peer's own HelloResult failed this side's checks: its identity binding or admission
		return nil, fmt.Errorf("%w: %w", errSearchRemoteAuth, err)
	}
	peer, ok := self.subprotocol.PeerIdentity(Id(clientId))
	if !ok || peer.SidecarId != indexerId || peer.Features&SubprotocolFeatureServesSearch == 0 {
		return nil, errSearchRemoteAuth
	}
	// Resolving a binding and authenticating a new Hello can span a revocation or a changed notice.
	if !allowed() {
		return nil, errSearchRemotePermission
	}
	return self.subprotocol.Call(ctx, Id(clientId), protocol.MessageType_SEARCH, body, nil)
}

// See searchRemoteTransport.
func (self *searchRemoteSubprotocolTransport) Peer(indexerId Id) (bool, bool) {
	clientId, ok := self.knownClient(indexerId)
	if !ok {
		return false, false
	}
	peer, ok := self.subprotocol.PeerIdentity(Id(clientId))
	if !ok || peer.SidecarId != indexerId {
		return false, false
	}
	return peer.Features&SubprotocolFeatureServesSearch != 0, true
}

// See searchRemoteTransport.
func (self *searchRemoteSubprotocolTransport) SeenSince(indexerId Id, at time.Time) bool {
	clientId, ok := self.knownClient(indexerId)
	if !ok {
		return false
	}
	sessionTime, standing := self.subprotocol.sessionTime(clientId)
	return standing && sessionTime.After(at)
}

// See searchRemoteTransport. The dispatcher keeps the indexer by its sidecar_id, as HeadCheck's candidates name it, so
// nothing is resolved or sent.
func (self *searchRemoteSubprotocolTransport) SetSearchIndexer(indexerId Id) {
	self.subprotocol.SetSearchIndexer(indexerId)
}

// See searchRemoteTransport.
func (self *searchRemoteSubprotocolTransport) SetForeground(foreground bool) {
	self.subprotocol.SetForeground(foreground)
}

// See searchRemoteTransport: bit 1 toward each client whose sidecar asksSearch names, the client one this transport
// resolved, as it does before every request. It reads nothing of the dispatcher's, whose Hello calls it.
func (self *searchRemoteSubprotocolTransport) SetAsksSearch(asksSearch func(indexerId Id) bool) error {
	if asksSearch == nil {
		return self.subprotocol.SetFeatures(0, nil)
	}
	return self.subprotocol.SetFeatures(0, func(clientId Id) bool {
		self.stateLock.Lock()
		indexerId, ok := self.sidecars[connect.Id(clientId)]
		self.stateLock.Unlock()
		return ok && asksSearch(indexerId)
	})
}
