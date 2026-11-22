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

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One sidecar on the Net with its dispatcher in reach.
type SubprotocolSidecar struct {
	*TestSidecar

	stateLock sync.Mutex
	// the running generation's dispatcher and client, as the component last attached
	subprotocol *sidecar.Subprotocol
	clientId    connect.Id
	attached    chan struct{}
}

// The fake issuer's stable client slots and stream ID ranges, with platform tokens the Net's API recognizes.
type netEdgeClientSource struct {
	*FakeServiceClientSource
	api       *FakeApi
	networkId sidecar.Id
}

// Mints the slot's credential on the same fake API that authenticates its transport.
func (self *netEdgeClientSource) ServiceClient(ctx context.Context, index int) (*sidecar.ServiceClientAuth, error) {
	credential, err := self.FakeServiceClientSource.ServiceClient(ctx, index)
	if err != nil {
		return nil, err
	}
	credential.ByJwt = self.api.ClientToken(self.networkId, sidecar.Id(credential.ClientId), sidecar.Id{})
	return credential, nil
}

// Supplies a stock edge pool with credentials for its network and a transport on this in-process exchange.
// The caller sets the pool's settings and inbound policy as its block does, and closes the resulting pool.
func (self *Net) EdgeClientPoolArgs(networkId sidecar.Id) (*sidecar.EdgeClientPoolArgs, error) {
	if self.OnPlatform() {
		return nil, fmt.Errorf("a platform-backed Net takes edge clients from its platform")
	}
	api, err := self.Api()
	if err != nil {
		return nil, err
	}
	return &sidecar.EdgeClientPoolArgs{
		Source: &netEdgeClientSource{
			FakeServiceClientSource: NewFakeServiceClientSource(self.faults, nil),
			api:                     api,
			networkId:               networkId,
		},
		Platform: newNetSidecarPlatform(self, "edge", api),
	}, nil
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
	return self.AddSubprotocolSidecarsWith(nil, names...)
}

// AddSubprotocolSidecars, each sidecar on the settings settings makes for it, nil making the defaults, which the
// Net fills as AddSidecar does: how a test turns on what a release leaves off, SidecarProtocolSettings.EnablePeerP2p
// among them.
func (self *Net) AddSubprotocolSidecarsWith(settings func() *sidecar.SidecarSettings, names ...string) ([]*SubprotocolSidecar, *FakeAuthority, error) {
	authority := NewFakeAuthority()
	sidecars := []*SubprotocolSidecar{}
	for _, name := range names {
		var sidecarSettings *sidecar.SidecarSettings
		if settings != nil {
			sidecarSettings = settings()
		}
		testSidecar, err := self.AddSidecar(name, sidecarSettings)
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
	attachTimeout := self.settings.SubprotocolAttachTimeout
	if attachTimeout <= 0 {
		// a NetSettings built before the field, as T3's are
		attachTimeout = DefaultNetSettings().SubprotocolAttachTimeout
	}
	ctx, cancel := context.WithTimeout(self.ctx, attachTimeout)
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

// Gives every contract the issuer creates from source to destination from now on provideMode, as CreateContract
// decides a pair's relationship: FriendsAndFamily for a share's (§6.10.1 item 4), which the destination must provide
// (Subprotocol.HoldProvideMode). The default is Network. One direction only, since a share's two directions are its
// dialer's forward contract and the destination's companion. A Net on a platform takes its contracts from the
// platform's controller, so a mode set there is kept as unapplied (Net.Unapplied).
func (self *Net) SetContractProvideMode(source connect.Id, destination connect.Id, provideMode connectprotocol.ProvideMode) {
	exchange := self.exchange
	if self.OnPlatform() {
		exchange.refuseOnPlatform(fmt.Sprintf("SetContractProvideMode %s %s %s: the platform's controller decides each contract's mode itself", source, destination, provideMode))
		return
	}
	exchange.stateLock.Lock()
	defer exchange.stateLock.Unlock()
	exchange.contractProvideModes[netLinkKey{source: source, destination: destination}] = provideMode
}

// Commits every contract the issuer creates from now on to its destination's sequence TLS certificate, the chain the
// destination's EncryptedKey publishes and its client key's signature over it, as CreateContract seals them
// (StoredContract.provide_tls_certificate), so a source checks the certificate its destination presents against the
// contract it holds, as it does on a platform. Off by default, when contracts commit to no certificate and a source
// checks none. A Net on a platform takes its contracts from the platform's controller, which commits them itself, so
// this is kept as unapplied there (Net.Unapplied).
func (self *Net) CommitSequenceCertificates() {
	exchange := self.exchange
	if self.OnPlatform() {
		exchange.refuseOnPlatform("CommitSequenceCertificates: the platform's controller commits each contract to its destination's certificate itself")
		return
	}
	exchange.stateLock.Lock()
	defer exchange.stateLock.Unlock()
	exchange.commitSequenceCertificates = true
}

// Whether the issuer commits contracts to their destination's sequence certificate.
func (self *netExchange) commitsSequenceCertificates() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.commitSequenceCertificates
}

// The provide mode the issuer gives a contract from source to destination.
func (self *netExchange) contractProvideMode(source connect.Id, destination connect.Id) connectprotocol.ProvideMode {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if provideMode, ok := self.contractProvideModes[netLinkKey{source: source, destination: destination}]; ok {
		return provideMode
	}
	return connectprotocol.ProvideMode_Network
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
