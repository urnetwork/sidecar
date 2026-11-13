// The daemon's wiring of the bridge (BRIDGE-M4-18, §17.10): one device.Bridge beside a network's Sidecar, on a
// posture store under the instance's state directory (device.NewFilePostureStore), with the CLI's BridgeHost
// (bridge_host.go) and the Sidecar's own signer and identity lookups, fed by the root's BridgeComponent through
// urBridgeSink, the adapter 12.2.5 names. The component is the Sidecar's "bridge" component: it follows the
// network's ConfigClient, compiles and serves bridge flows on each client generation (bridge_component.go).
//
// What the wiring needs of the network's config, the ConfigClient and the head, rows, keys and local policy beside
// it, comes from the daemon's config follower. A daemon whose Sidecar follows no config log builds no bridge: ur tun
// refuses, naming it, the closed direction.

package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The daemon runs no bridge for the network.
var errUrBridgeUnwired = errors.New("no bridge runs for this network")

// device.Bridge as the component's sink: each call through, a log run converted to the posture's, and the decision
// read off what the bridge adopted.
type urBridgeSink struct {
	bridge *device.Bridge
}

var _ sidecar.BridgeStateSink = (*urBridgeSink)(nil)

func (self *urBridgeSink) SetPending(pending *bridge.Pending) error {
	return self.bridge.SetPending(pending)
}

func (self *urBridgeSink) SetState(state *bridge.BridgeState, log *sidecar.BridgeStateLog) error {
	return self.bridge.SetState(state, urPostureLog(log))
}

func (self *urBridgeSink) ApplyDeltas(log *sidecar.BridgeStateLog) error {
	return self.bridge.ApplyDeltas(urPostureLog(log))
}

func (self *urBridgeSink) SetFork(fork bool) error {
	return self.bridge.SetFork(fork)
}

func (self *urBridgeSink) Decision() sidecar.BridgeSinkDecision {
	decision := self.bridge.Decision()
	sinkDecision := sidecar.BridgeSinkDecision{Pin: decision.Pin, Fork: decision.Fork}
	switch decision.State {
	case device.PostureLegacy:
		sinkDecision.State = sidecar.BridgeSinkLegacy
	case device.PostureEnforcingDocument, device.PostureEnforcingNoDocument:
		sinkDecision.State = sidecar.BridgeSinkEnforcing
	default:
		sinkDecision.State = sidecar.BridgeSinkPending
	}
	if decision.BridgeState != nil {
		sinkDecision.StatePin = decision.BridgeState.GetAuth()
	}
	return sinkDecision
}

func (self *urBridgeSink) Revoke(statementType bridge.SignedType, id []byte, n uint64) error {
	return self.bridge.Revoke(statementType, id, n)
}

func (self *urBridgeSink) EgressHook() connect.EgressHook {
	return self.bridge.EgressHook()
}

// A log run as the posture reads it.
func urPostureLog(log *sidecar.BridgeStateLog) *device.PostureLog {
	if log == nil {
		return nil
	}
	return &device.PostureLog{Entries: log.Entries, OpenRows: log.OpenRows}
}

// What the wiring is built over: a network's Sidecar and its config follower.
type urBridgeWireArgs struct {
	NetworkId sidecar.Id
	Sidecar   *sidecar.Sidecar
	// The network's config follower and what reads beside it (sidecar.BridgeComponentArgs).
	Config    sidecar.BridgeConfigSource
	Heads     sidecar.ConfigHeadReader
	Rows      sidecar.ConfigRowsSource
	RepoKeyAt func(generation uint64) *sidecar.EvsRepoKey
	AclLocal  func() *sidecar.AclLocalPolicy
	// The instance's state directory: the posture's store is bridge/<network_id> under it.
	StateDirectory  string
	DaemonListeners func() []string
	// The connect settings a link's generator dials with.
	SidecarSettings *sidecar.SidecarSettings
	Log             sidecar.Logger
}

// One network's bridge: the device role, its host and the component that feeds it.
type urBridgeWire struct {
	args      *urBridgeWireArgs
	bridge    *device.Bridge
	host      *urBridgeHost
	component *sidecar.BridgeComponent
	remove    func()
	cancel    context.CancelFunc
}

// Builds a network's bridge and adds its component to the Sidecar: the posture restored first, so the device role is
// in force before any generation serves (DP1, 12.2.5's step 1).
func newUrBridgeWire(ctx context.Context, args *urBridgeWireArgs) (*urBridgeWire, error) {
	if args == nil || args.Sidecar == nil || args.Config == nil {
		return nil, errUrBridgeUnwired
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &urBridgeWire{args: args, cancel: cancel}
	store, err := device.NewFilePostureStore(filepath.Join(args.StateDirectory, "bridge", args.NetworkId.String()))
	if err != nil {
		cancel()
		return nil, err
	}
	settings := device.DefaultBridgeSettings()
	settings.LinkSign = self.sign
	settings.LinkTargetKey = self.targetKey
	self.host = newUrBridgeHost(cancelCtx, settings)
	self.bridge, err = device.NewBridge(cancelCtx, store, self.host, settings)
	if err != nil {
		cancel()
		return nil, err
	}
	self.component, err = sidecar.NewBridgeComponent(cancelCtx, &sidecar.BridgeComponentArgs{
		NetworkId:       args.NetworkId,
		Identity:        args.Sidecar.Identity,
		Config:          args.Config,
		Heads:           args.Heads,
		Rows:            args.Rows,
		RepoKeyAt:       args.RepoKeyAt,
		AclLocal:        args.AclLocal,
		DaemonListeners: args.DaemonListeners,
		Log:             args.Log,
		OnAttach:        self.attach,
	})
	if err != nil {
		self.bridge.Close()
		cancel()
		return nil, err
	}
	if err := self.component.SetDeviceRole(&urBridgeSink{bridge: self.bridge}); err != nil {
		self.close()
		return nil, err
	}
	self.remove, err = args.Sidecar.AddComponent(self.component)
	if err != nil {
		self.close()
		return nil, err
	}
	return self, nil
}

// Takes a client generation for the links the next builds mint under.
func (self *urBridgeWire) attach(env *sidecar.SidecarEnv) {
	if env.Identity == nil || env.SidecarApi == nil || env.Api == nil || self.args.SidecarSettings == nil {
		self.host.setGeneration(nil)
		return
	}
	self.host.setGeneration(&urBridgeGeneration{
		api:            env.SidecarApi,
		credentials:    &urBridgeCredentials{api: env.SidecarApi},
		byJwt:          env.Api.ByJwt(),
		sourceClientId: connect.Id(env.Identity.ClientId),
		strategy:       connect.NewClientStrategy(env.Ctx, self.args.SidecarSettings.Connect.ClientStrategySettings),
		apiUrl:         self.args.SidecarSettings.ApiUrl,
		platformUrl:    self.args.SidecarSettings.PlatformUrl,
	})
}

// device.BridgeSignFunction over the Sidecar's signer (§17.9's sign row): it refuses what it would not sign.
func (self *urBridgeWire) sign(ctx context.Context, delegation *bridge.WindowDelegation) ([]byte, error) {
	ids := []sidecar.Id{}
	for _, idBytes := range [][]byte{delegation.GetNetworkId(), delegation.GetSubjectSidecarId(), delegation.GetWindowClientId(), delegation.GetTargetSidecarId()} {
		id, err := sidecar.IdFromBytes(idBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: a delegation's id", sidecar.ErrBridgeDelegationRefused)
		}
		ids = append(ids, id)
	}
	return self.args.Sidecar.SignWindowDelegation(&sidecar.BridgeDelegationRequest{
		NetworkId:             ids[0],
		SubjectSidecarId:      ids[1],
		WindowClientId:        ids[2],
		WindowClientPublicKey: delegation.GetWindowClientPublicKey(),
		TargetSidecarId:       ids[3],
		NotAfter:              time.UnixMilli(delegation.GetNotAfterMs()),
	})
}

// device.BridgeTargetKeyFunction: the binding api answers for the target client, which the link verifies against the
// identity key the rules pin, so api stays untrusted (§17.9's target row).
func (self *urBridgeWire) targetKey(ctx context.Context, targetSidecarId connect.Id, targetClientId connect.Id) ([]byte, error) {
	generation := func() *urBridgeGeneration {
		self.host.stateLock.Lock()
		defer self.host.stateLock.Unlock()
		return self.host.generation
	}()
	if generation == nil {
		return nil, fmt.Errorf("%w: no client generation", errUrBridgeHostRefused)
	}
	record, err := generation.api.GetIdentityByClient(ctx, sidecar.Id(targetClientId))
	if err != nil {
		return nil, err
	}
	if record.SidecarId != sidecar.Id(targetSidecarId) {
		return nil, fmt.Errorf("%w: api names another sidecar for the target client", errUrBridgeHostRefused)
	}
	return record.Binding, nil
}

// Takes the network's bridge out of the Sidecar and ends it: the component first, then the device role and its links.
// The posture's store stays for the next start.
func (self *urBridgeWire) close() {
	if self.remove != nil {
		self.remove()
	} else if self.component != nil {
		self.component.Close()
	}
	if self.bridge != nil {
		self.bridge.Close()
	}
	self.cancel()
}
