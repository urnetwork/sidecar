// §6.4's HeadCheck on the Net (PROTO-M2-05, FS-17): sidecars of one network, each admitted by one
// FakeAuthority as AddSubprotocolSidecars admits them, each with HeadCheck attached to its running
// dispatcher over sidecartest's fakes (headcheck_fakes.go) on one FakeHeadCheckApi, its HeadStopState on
// the Net's clock, every group shared, so a fork, a withheld tip or a lapsed witness stops sealing as
// §6.4's stops row says. Exchanges run between the sidecars' real connect clients on the in-process
// exchange, through Hello's admission check, so a link the Net partitions drops HeadCheck's frames as a
// relay dropping them would.
//
// Each sidecar's alarms are recorded in order, and every HeadCheckNet a Net holds is what FI-10's oracle
// reads (sidecartest/fault/fi10.go): each device's pins, stops, witnessed_at and the pin it witnessed.
// The peer states are each device's own (FakeHeadCheckPeers), apart from the authority Hello reads:
// RevokePeer moves both, as a revocation applied everywhere would, and SetPeer moves one device's view
// alone.
//
// AddHeadCheckSidecarsOver gives each sidecar a real auth source instead of the fake, a device follower
// of another network's log (TEAM-M2-10's ConfigClient), so a schedule connects readers a server served
// two views (FS-14). Its dispatchers still stand on the Net's default network under the FakeAuthority,
// so Hello is the one part of such an exchange not on that log. Detach joins what a sidecar's HeadCheck
// still runs, a responder's acts and witness among them, so a schedule's last check reads them final.

package sidecartest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What an Identity lookup answers for a sidecar the fake api holds no binding of.
var errHeadCheckNetNoIdentity = errors.New("head check net: no such sidecar identity")

// One network's sidecars with HeadCheck attached.
type HeadCheckNet struct {
	net       *Net
	Api       *FakeHeadCheckApi
	Authority *FakeAuthority

	stateLock sync.Mutex
	sidecars  []*HeadCheckSidecar
	// what each device reads as ServiceSettings.witness_bound_hours
	witnessBoundHours uint32
	// FI-10's notes between its checks, by sidecar (sidecartest/fault/fi10.go)
	notes map[sidecar.Id]*HeadCheckNote
}

// One sidecar with HeadCheck attached: its dispatcher, its sources, its stops and its alarms.
type HeadCheckSidecar struct {
	*SubprotocolSidecar
	SidecarId sidecar.Id
	// Its fakes: the generation, epoch and ref pins, the peer state, and the auth source, which is nil
	// when AddHeadCheckSidecarsOver gave it another (AuthSource).
	Device    *FakeHeadCheckDevice
	Stop      *sidecar.HeadStopState
	headCheck *HeadCheckNet
	// the auth source AddHeadCheckSidecarsOver gave it, nil for Device.Auth
	auth sidecar.HeadCheckAuthSource
	// detaches HeadCheck from the dispatcher, joining what it still runs; once
	detach func()

	stateLock sync.Mutex
	alarms    []sidecar.SidecarEvent
	// counts alarms, so a test waits for one with no sleep
	alarmCount *sidecar.MonitorValue[int]
}

// What FI-10's oracle keeps of one device between its checks.
type HeadCheckNote struct {
	// witnessed_at at the last check
	WitnessedAt time.Time
	// whether the device held an UNVERIFIED pin then
	HeldUnverified bool
	// whether it held proof of withholding then
	HeldWithheld bool
	// the witnessed_at a conflict with another device's pin first found, while that conflict lasts
	ConflictWitnessedAt *time.Time
}

// Enrolls a sidecar of each name with AddSubprotocolSidecars, then attaches HeadCheck to each over a
// device of its own on one api at genesis, every device admitting every other. A witness bound of 0
// reads as unset, so 72 h, as the config's default.
func (self *Net) AddHeadCheckSidecars(names ...string) (*HeadCheckNet, error) {
	return self.addHeadCheckSidecars(nil, nil, names)
}

// AddHeadCheckSidecars with each sidecar's HeadCheck comparing auths' source at its name's index, a real
// follower of networkId's log, in place of the fake on the api: how a schedule connects readers a
// server served two views (FS-14). Each sidecar's stops are of networkId, its other pins fakes holding
// none, and each admits every other, as AddHeadCheckSidecars admits them.
func (self *Net) AddHeadCheckSidecarsOver(networkId sidecar.Id, auths []sidecar.HeadCheckAuthSource, names ...string) (*HeadCheckNet, error) {
	if len(auths) != len(names) || slices.Contains(auths, nil) {
		return nil, fmt.Errorf("head check net: %d auth sources for %d sidecars", len(auths), len(names))
	}
	return self.addHeadCheckSidecars(&networkId, auths, names)
}

// The sidecars of names with HeadCheck: on networkId's stops, else the sidecars' own network's, each
// comparing auths' source at its index, else its fake's.
func (self *Net) addHeadCheckSidecars(networkId *sidecar.Id, auths []sidecar.HeadCheckAuthSource, names []string) (*HeadCheckNet, error) {
	subprotocolSidecars, authority, err := self.AddSubprotocolSidecars(names...)
	if err != nil {
		return nil, err
	}
	if len(subprotocolSidecars) == 0 {
		return nil, errors.New("head check net: no sidecars")
	}
	stopNetworkId := subprotocolSidecars[0].NetworkId()
	if networkId != nil {
		stopNetworkId = *networkId
	}
	headCheck := &HeadCheckNet{
		net:       self,
		Api:       NewFakeHeadCheckApi(stopNetworkId),
		Authority: authority,
		notes:     map[sidecar.Id]*HeadCheckNote{},
	}
	for i, subprotocolSidecar := range subprotocolSidecars {
		identity := subprotocolSidecar.Sidecar().Identity()
		if identity == nil {
			return nil, fmt.Errorf("%s has no identity", subprotocolSidecar.Name)
		}
		side := &HeadCheckSidecar{
			SubprotocolSidecar: subprotocolSidecar,
			SidecarId:          identity.SidecarId,
			Device:             NewFakeHeadCheckDevice(identity.SidecarId, headCheck.Api),
			headCheck:          headCheck,
			alarmCount:         sidecar.NewMonitorValue(0),
		}
		if auths != nil {
			side.auth = auths[i]
			side.Device.Auth = nil
		}
		headCheck.sidecars = append(headCheck.sidecars, side)
	}
	for _, side := range headCheck.sidecars {
		for _, other := range headCheck.sidecars {
			if other != side {
				side.Device.Peers.Admit(other.SidecarId)
			}
		}
		if err := headCheck.attach(side); err != nil {
			return nil, err
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.headCheckNets = append(self.headCheckNets, headCheck)
	return headCheck, nil
}

// Builds side's HeadStopState and attaches HeadCheck to its running dispatcher until the Net closes.
func (self *HeadCheckNet) attach(side *HeadCheckSidecar) error {
	net := self.net
	stop, err := sidecar.NewHeadStopState(net.ctx, &sidecar.HeadStopStateEnv{
		SidecarId: side.SidecarId,
		NetworkId: self.Api.NetworkId(),
		Sources: &sidecar.HeadCheckSources{
			Auth:   side.AuthSource(),
			Gens:   side.Device.Heads,
			Groups: side.Device.Heads,
			Refs:   side.Device.Heads,
			Peers:  side.Device.Peers,
		},
		Store:    NewFakeStore().Root(),
		Settings: sidecar.DefaultSidecarProtocolSettings(),
		Clock:    net.clock,
		Log:      sidecar.NewNoopLogger(),
		WitnessBoundHours: func() (uint32, bool) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.witnessBoundHours, true
		},
		SharedGroup: func(groupId sidecar.Id) bool { return true },
		Alarm:       side.recordAlarm,
		// each exchange here is one a schedule starts; the revoker's asks are left to them
		RequestRound: func() {},
	})
	if err != nil {
		return err
	}
	detach, err := side.Subprotocol().AttachHeadCheck(&sidecar.HeadCheckEnv{
		Stop:       stop,
		Candidates: func() []sidecar.HeadCheckCandidate { return nil },
		// what GET /sidecar/identity answers: the newest binding the fake api holds, which a proof request
		// to a claimant whose Hello has lapsed resolves its client by
		Identity: func(ctx context.Context, sidecarId sidecar.Id) (*sidecar.SidecarIdentityRecord, error) {
			api, err := net.Api()
			if err != nil {
				return nil, err
			}
			binding, ok := api.newestSidecarBinding(sidecarId)
			if !ok {
				return nil, errHeadCheckNetNoIdentity
			}
			return &sidecar.SidecarIdentityRecord{SidecarId: sidecarId, Binding: binding}, nil
		},
	})
	if err != nil {
		stop.Close()
		return err
	}
	side.Stop = stop
	side.detach = detach
	go func() {
		<-net.ctx.Done()
		detach()
		stop.Close()
	}()
	return nil
}

// The auth source its HeadCheck compares, which FI-10's oracle reads: the one AddHeadCheckSidecarsOver
// gave it, else Device.Auth.
func (self *HeadCheckSidecar) AuthSource() sidecar.HeadCheckAuthSource {
	if self.auth != nil {
		return self.auth
	}
	return self.Device.Auth
}

// Detaches HeadCheck from the sidecar's dispatcher and joins every exchange and act it still runs, a
// responder's acts and witness among them, so its stops, alarms and witnessed_at are final: what a
// schedule's last check reads. It runs no exchange after. Its HeadStopState stays, read as before,
// until the Net closes. A sidecar never attached has nothing to join.
func (self *HeadCheckSidecar) Detach() {
	if self.detach != nil {
		self.detach()
	}
}

// Every network of sidecars with HeadCheck the Net holds, for FI-10's oracle.
func (self *Net) HeadCheckNets() []*HeadCheckNet {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.headCheckNets)
}

// The sidecars, in the order they were named.
func (self *HeadCheckNet) Sidecars() []*HeadCheckSidecar {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.sidecars)
}

// The sidecar of one name.
func (self *HeadCheckNet) Sidecar(name string) *HeadCheckSidecar {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, side := range self.sidecars {
		if side.Name == name {
			return side
		}
	}
	return nil
}

// Sets ServiceSettings.witness_bound_hours as every device reads it, 0 for unset.
func (self *HeadCheckNet) SetWitnessBoundHours(hours uint32) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.witnessBoundHours = hours
}

// The note FI-10's oracle keeps of a device, made at first use. The oracle runs between steps, alone.
func (self *HeadCheckNet) Note(sidecarId sidecar.Id) *HeadCheckNote {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	note := self.notes[sidecarId]
	if note == nil {
		note = &HeadCheckNote{}
		self.notes[sidecarId] = note
	}
	return note
}

// Revokes target in the authority Hello reads and in every device's view of the state, as a revocation
// every device has applied: no Hello with it stands, and no device counts it.
func (self *HeadCheckNet) RevokePeer(target *HeadCheckSidecar) {
	self.Authority.EditSidecar(target.SidecarId, func(row *bridge.SidecarRow) {
		row.RevokedAt = self.Authority.Pin().GetVersion() + 1
	})
	for _, side := range self.Sidecars() {
		if side != target {
			side.Device.Peers.Set(target.SidecarId, sidecar.HeadCheckPeer{Admitted: true, Revoked: true})
		}
	}
}

// Records one alarm. Never blocks, as HeadStopStateEnv.Alarm must not.
func (self *HeadCheckSidecar) recordAlarm(event sidecar.SidecarEvent) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.alarms = append(self.alarms, event)
	}()
	self.alarmCount.Update(func(count int) int { return count + 1 })
}

// The head_alarm events of kind raised so far, in order; every one for an empty kind.
func (self *HeadCheckSidecar) Alarms(kind sidecar.SidecarHeadAlarm) []sidecar.SidecarEvent {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	alarms := []sidecar.SidecarEvent{}
	for _, alarm := range self.alarms {
		if kind == "" || alarm.HeadAlarm == kind {
			alarms = append(alarms, alarm)
		}
	}
	return alarms
}

// Waits until an alarm of kind has been raised, or ctx ends.
func (self *HeadCheckSidecar) AwaitAlarm(ctx context.Context, kind sidecar.SidecarHeadAlarm) error {
	for {
		_, changed := self.alarmCount.Get()
		if 0 < len(self.Alarms(kind)) {
			return nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return fmt.Errorf("%s: no %s alarm: %w", self.Name, kind, ctx.Err())
		}
	}
}

// The client a peer reaches this sidecar at.
func (self *HeadCheckSidecar) PeerClientId() sidecar.Id {
	return sidecar.Id(self.ClientId())
}

// One HeadCheck exchange with peer now, as the initiator, its Hello first: whether it counted as a
// consistent witness here.
func (self *HeadCheckSidecar) HeadCheckWith(ctx context.Context, peer *HeadCheckSidecar) (bool, error) {
	return self.Subprotocol().HeadCheckNow(ctx, peer.PeerClientId())
}

// Drops every frame between a and b, both ways, as a relay dropping a pair's traffic does, or ends that.
func (self *HeadCheckNet) Partition(a *HeadCheckSidecar, b *HeadCheckSidecar, partitioned bool) {
	var link *LinkConditions
	if partitioned {
		link = &LinkConditions{Partition: true}
	}
	self.net.SetLink(connect.Id(a.ClientId()), connect.Id(b.ClientId()), link)
}

// The newest binding wrapper api holds for sidecarId, as GET /sidecar/identity serves it, and false for
// none.
func (self *FakeApi) newestSidecarBinding(sidecarId sidecar.Id) ([]byte, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	identity := self.core.identities[sidecarId]
	if identity == nil {
		return nil, false
	}
	binding, ok := identity.bindings[identity.newest]
	return slices.Clone(binding), ok
}
