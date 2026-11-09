// §6's subprotocol on the Net (PROTO-M1-11): sidecars enrolled in one network, each admitted by one
// shared FakeAuthority as the network's verified state, with its running client generation's dispatcher
// in reach, so a T2 test runs §6 through the public entry points, with Hello's admission check, retries
// and refusals on, over the in-process exchange's real connect clients. Contracts between two clients
// carry the class SetContractClass gives the pair, data by default, as the gate issues where reach
// allows (§8.10).
//
// Later tasks reuse this: AddSubprotocolSidecars for a network of admitted sidecars, Subprotocol for a
// sidecar's dispatcher, and SetContractClass for a pair's contracts, which the fake issuer alone takes:
// on a platform (T3), the platform's controller seals the class.

package sidecartest

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// How long AddSubprotocolSidecars waits, in real time, for a sidecar's first dispatcher.
const subprotocolAttachTimeout = 30 * time.Second

// One sidecar on the Net with its dispatcher in reach.
type SubprotocolSidecar struct {
	*TestSidecar

	stateLock sync.Mutex
	// the running generation's dispatcher and client, as the component last attached
	subprotocol *sidecar.Subprotocol
	clientId    connect.Id
	attached    chan struct{}
}

// The running generation's dispatcher.
func (self *SubprotocolSidecar) Subprotocol() *sidecar.Subprotocol {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.subprotocol
}

// The running generation's client id, the id a peer calls.
func (self *SubprotocolSidecar) ClientId() connect.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.clientId
}

// A component whose only part is handing each generation's dispatcher to its sidecar.
type subprotocolComponent struct {
	owner *SubprotocolSidecar
}

func (self *subprotocolComponent) Name() string {
	return "subprotocol-test"
}

func (self *subprotocolComponent) Attach(env *sidecar.SidecarEnv) error {
	self.owner.stateLock.Lock()
	defer self.owner.stateLock.Unlock()
	self.owner.subprotocol = env.Subprotocol
	self.owner.clientId = connect.Id(env.Identity.ClientId)
	select {
	case <-self.owner.attached:
	default:
		close(self.owner.attached)
	}
	return nil
}

func (self *subprotocolComponent) Close() {
}

// Enrolls a sidecar of each name in the Net's default network, Online, admits every one of them in one
// FakeAuthority, installs it in each as the network's verified state, and waits for each one's
// dispatcher. Answers the sidecars, in order, and the authority, which a test moves to revoke, park or
// admit more.
func (self *Net) AddSubprotocolSidecars(names ...string) ([]*SubprotocolSidecar, *FakeAuthority, error) {
	authority := NewFakeAuthority()
	sidecars := []*SubprotocolSidecar{}
	for _, name := range names {
		testSidecar, err := self.AddSidecar(name, nil)
		if err != nil {
			return nil, nil, err
		}
		identity := testSidecar.Sidecar().Identity()
		if identity == nil {
			return nil, nil, fmt.Errorf("%s has no identity", name)
		}
		at := authority.AdmitSidecar(&FakeAuthorityAdmission{
			SidecarId:         identity.SidecarId,
			MemberId:          sidecar.NewId(),
			IdentityPublicKey: identity.IdentityPublicKey,
		})
		// the admission's entry moves the state, as a follower applying it would
		chain := sha256.Sum256(binary.BigEndian.AppendUint64([]byte("urnetwork-sidecar-test/subprotocol-pin/"), at))
		authority.SetPin(&bridge.AuthPin{Version: at, Chain: chain[:]})
		subprotocolSidecar := &SubprotocolSidecar{TestSidecar: testSidecar, attached: make(chan struct{})}
		sidecars = append(sidecars, subprotocolSidecar)
	}
	for _, subprotocolSidecar := range sidecars {
		running := subprotocolSidecar.Sidecar()
		running.InstallAuthority(authority)
		if _, err := running.AddComponent(&subprotocolComponent{owner: subprotocolSidecar}); err != nil {
			return nil, nil, err
		}
	}
	ctx, cancel := context.WithTimeout(self.ctx, subprotocolAttachTimeout)
	defer cancel()
	for _, subprotocolSidecar := range sidecars {
		select {
		case <-subprotocolSidecar.attached:
		case <-ctx.Done():
			return nil, nil, fmt.Errorf("%s: no dispatcher attached", subprotocolSidecar.Name)
		}
	}
	return sidecars, authority, nil
}

// Seals class into every contract the issuer creates between a and b from now on, either way, as the
// contract gate classes a pair (§8.10). The default is data. A Net on a platform takes its contracts from
// the platform's controller, which seals the class its own gate gives, so a class set there is kept as
// unapplied (Net.Unapplied).
func (self *Net) SetContractClass(a connect.Id, b connect.Id, class connectprotocol.ContractClass) {
	exchange := self.exchange
	if self.OnPlatform() {
		exchange.refuseOnPlatform(fmt.Sprintf("SetContractClass %s %s %s: the platform's controller seals each contract's class itself", a, b, class))
		return
	}
	exchange.stateLock.Lock()
	defer exchange.stateLock.Unlock()
	for _, key := range []netLinkKey{{source: a, destination: b}, {source: b, destination: a}} {
		exchange.contractClasses[key] = class
	}
}

// The class the issuer seals into a contract from source to destination.
func (self *netExchange) contractClass(source connect.Id, destination connect.Id) connectprotocol.ContractClass {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if class, ok := self.contractClasses[netLinkKey{source: source, destination: destination}]; ok {
		return class
	}
	return connectprotocol.ContractClass_ContractClassData
}
