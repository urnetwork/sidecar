// api's half of §7.9's forwarding row on the fake api (TEAM-M8-01; D-TEAM-33; owner decision 197), the copy of
// server/controller/config_delegation_check.go: POST /network/config/delta sequences a forwarding Delegation naming a
// host client only when that client is the source client of its sidecar's current client and the key is that
// client's registered ClientKey. The statement's form, its signer and its sidecar's standing are the log's rule,
// which the fake's rows-only ConfigLog judges as every reader does; no reader holds a client row, so this is api's
// alone, and a schedule on T2 meets the same refusal it would meet at server.
//
// A sidecar's current client is the one its newest binding names (POST /sidecar/bind), or, for a sidecar a test's
// ClientToken named with no bind, the one client whose token names it. A host client's registered key is the key
// BindClientKey set for it.

package sidecartest

import (
	"bytes"
	"errors"
	"net/http"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A bearer for a client of networkId that sourceClientId minted, bound to sidecarId when it is not zero: a sidecar's
// client on an app device, whose source client is the device's own (§18.6), as ClientToken's is top-level.
func (self *FakeApi) ChildClientToken(networkId sidecar.Id, clientId sidecar.Id, sidecarId sidecar.Id, sourceClientId sidecar.Id) string {
	return self.mintClientToken(&fakeApiClient{
		networkId:      networkId,
		clientId:       clientId,
		sidecarId:      sidecarId,
		deviceId:       sidecar.NewId(),
		sessionId:      sidecar.NewId(),
		strictExp:      true,
		adminRefused:   true,
		sourceClientId: sourceClientId,
		createTime:     self.clock.Now(),
	})
}

// The source client of the sidecar's current client in networkId, false for a sidecar with no current client, more
// than one, or a top-level one. Under stateLock.
func (self *FakeApi) sidecarSourceClientWithLock(networkId sidecar.Id, sidecarId sidecar.Id) (sidecar.Id, bool) {
	currentIds := map[sidecar.Id]bool{}
	if identity := self.core.identities[sidecarId]; identity != nil {
		if identity.networkId != networkId || identity.status != fakeApiIdentityActive {
			return sidecar.Id{}, false
		}
		for clientId, binding := range self.core.clientBindings {
			if binding.sidecarId == sidecarId && binding.generation == identity.newest {
				currentIds[clientId] = true
			}
		}
	} else {
		for _, client := range self.bearerClients {
			if client.networkId == networkId && client.sidecarId == sidecarId && !self.removedClientIds[client.clientId] {
				currentIds[client.clientId] = true
			}
		}
	}
	if len(currentIds) != 1 {
		return sidecar.Id{}, false
	}
	for _, client := range self.bearerClients {
		if currentIds[client.clientId] && client.networkId == networkId && !self.removedClientIds[client.clientId] {
			return client.sourceClientId, client.sourceClientId != sidecar.Id{}
		}
	}
	return sidecar.Id{}, false
}

// api's check of a statement before it is sequenced in networkId: nil for anything but a forwarding Delegation
// naming a host client, which the log's rule judges whole; for one, nil only when the host client is the source
// client of its sidecar's current client and the key is that client's registered key, else a 403.
func (self *FakeApi) checkForwardingHost(networkId sidecar.Id, signedBytes []byte) error {
	signed := &bridge.Signed{}
	if proto.Unmarshal(signedBytes, signed) != nil || bridge.SignedType(signed.GetType()) != bridge.SignedType_SIGNED_DELEGATION {
		return nil
	}
	message, err := sidecar.ParseConfigStatement(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_DELEGATION, signed.GetBody())
	if err != nil {
		return nil
	}
	delegation, ok := message.(*protocol.Delegation)
	if !ok || !sidecar.ConfigDelegationForwards(delegation) {
		return nil
	}
	forward := delegation.GetForward()
	if len(forward.GetHostClientId()) == 0 && len(forward.GetHostClientPublicKey()) == 0 {
		return nil
	}
	refused := func(text string) error {
		return &ConfigLogRefusal{Status: http.StatusForbidden, Err: errors.New(text)}
	}
	sidecarId, err := sidecar.IdFromBytes(forward.GetForwardSidecarId())
	if err != nil {
		return refused("a malformed forward_sidecar_id")
	}
	hostClientId, err := sidecar.IdFromBytes(forward.GetHostClientId())
	if err != nil || len(forward.GetHostClientPublicKey()) == 0 {
		return refused("a host client and its key do not come together")
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	sourceClientId, found := self.sidecarSourceClientWithLock(networkId, sidecarId)
	if !found || sourceClientId != hostClientId {
		return refused("the host client is not the source client of the sidecar's current client")
	}
	registeredKey := self.exchange.clientKeys[hostClientId]
	if len(registeredKey) == 0 || !bytes.Equal(registeredKey, forward.GetHostClientPublicKey()) {
		return refused("the host client key is not the host client's registered key")
	}
	return nil
}
