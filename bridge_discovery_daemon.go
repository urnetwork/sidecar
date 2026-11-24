//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The daemon's discovery methods (§17.11's ur bridge devices, share and discovery rows; §17.7.1; owner decision 778),
// over each network's discovery component, and the component's switches they call:
//
//	bridge.devices            this host's LAN devices that discovery finds, shared or not, what this host publishes,
//	                          and the instances this device sees from the network's hosts, each with its address and
//	                          why any is withheld; it asks the gatherer to run, and marks the own-services notice seen
//	bridge.share              Confirm: share or unshare a LAN device (bridge_discovery_share.go), from control with the
//	                          person's confirmation, never MCP (§5.8); answers a filing's approval while it waits
//	bridge.discovery          own on|off, hide a port or an instance, proxy on|off: the host's own switches and its one
//	                          hide set, which `ur listeners hide` also writes (§17.7.1's Hiding)
//	bridge.discovery.unhide   Confirm: an unhide reopens what the hide closed, so it is the person's own act, on
//	                          /dev/tty or in the app's UI, never MCP (§17.7.1's Hiding; DESIGN-COMPUTE.md §26.6)
//
// Replies carry this network's own addresses and the hosts' words, which a person reads; no MCP tool calls these
// (§17.7.1's who sees what: no MCP tool reads a discovery name). Errors name no value.
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The discovery methods.
const (
	DaemonMethodBridgeDevices         = "bridge.devices"
	DaemonMethodBridgeShare           = "bridge.share"
	DaemonMethodBridgeDiscovery       = "bridge.discovery"
	DaemonMethodBridgeDiscoveryUnhide = "bridge.discovery.unhide"
)

// What bridge.discovery's setting names.
const (
	DaemonBridgeDiscoveryOwn   = "own"
	DaemonBridgeDiscoveryProxy = "proxy"
	DaemonBridgeDiscoveryHide  = "hide"
	DaemonBridgeDiscoveryOn    = "on"
	DaemonBridgeDiscoveryOff   = "off"
	// hide's target for the whole device
	DaemonBridgeDiscoveryDevice = "device"
)

// No discovery runs for the network.
var ErrDaemonBridgeDiscoveryUnwired = errors.New("no discovery runs for this network")

// One instance as `ur bridge devices` lists it.
type DaemonBridgeInstance struct {
	Name    string `json:"name"`
	Service string `json:"service"`
	// Where the network reaches it, and its port there.
	Address string `json:"address,omitempty"`
	Port    uint16 `json:"port"`
	// The host's own service, a shared device's, or a listed entry's.
	Own bool `json:"own,omitempty"`
	// Why it is not published or kept, empty where it is.
	Withheld string `json:"withheld,omitempty"`
	// Seconds left.
	Ttl int64 `json:"ttl,omitempty"`
}

// One LAN device this host's gatherer finds.
type DaemonBridgeLanDevice struct {
	HostLabel string `json:"host_label"`
	Name      string `json:"name,omitempty"`
	Model     string `json:"model,omitempty"`
	Address   string `json:"address,omitempty"`
	// Its share's state, empty where not shared: active, waiting, moved or absent.
	Share string `json:"share,omitempty"`
	// The /32 route its share filed, hex; the approval it waits on.
	RuleId     string `json:"rule_id,omitempty"`
	ApprovalId string `json:"approval_id,omitempty"`
	// What it announces of the effective list.
	Services []*DaemonBridgeInstance `json:"services,omitempty"`
}

// One host's instances this device keeps.
type DaemonBridgeRemoteHost struct {
	SidecarId Id     `json:"sidecar_id"`
	Name      string `json:"name,omitempty"`
	// What its answers held that the checks dropped: an address it does not serve, one this router sends elsewhere,
	// or an instance not of the watch's shape.
	DroppedCount int                     `json:"dropped_count,omitempty"`
	Instances    []*DaemonBridgeInstance `json:"instances,omitempty"`
}

// bridge.devices' reply.
type DaemonBridgeDevicesReply struct {
	// The own-services notice while the person has not seen it.
	Notice string `json:"notice,omitempty"`
	// The switches: own services published, the advertising proxy on, the device hidden whole.
	Own          bool     `json:"own"`
	Proxy        bool     `json:"proxy"`
	HiddenDevice bool     `json:"hidden_device,omitempty"`
	Hides        []string `json:"hides,omitempty"`
	// The effective list of types.
	Types []string `json:"types,omitempty"`
	// This host's LAN devices and its own instances, what it publishes, and what this device sees.
	Lan       []*DaemonBridgeLanDevice  `json:"lan,omitempty"`
	Published []*DaemonBridgeInstance   `json:"published,omitempty"`
	Remote    []*DaemonBridgeRemoteHost `json:"remote,omitempty"`
}

// bridge.devices' params.
type DaemonBridgeDevicesParams struct {
	Network string `json:"network,omitempty"`
}

// bridge.share's params: a device by its host label, shared or, with Unshare, unshared. With Disclosure the call
// answers the disclosure the person reads first, sharing nothing.
type DaemonBridgeShareParams struct {
	Network    string `json:"network,omitempty"`
	Device     string `json:"device"`
	Unshare    bool   `json:"unshare,omitempty"`
	Disclosure bool   `json:"disclosure,omitempty"`
}

// bridge.share's reply.
type DaemonBridgeShareReply struct {
	Disclosure        string `json:"disclosure,omitempty"`
	State             string `json:"state,omitempty"`
	RuleId            string `json:"rule_id,omitempty"`
	ApprovalPendingId *Id    `json:"approval_pending_id,omitempty"`
}

// bridge.discovery's and bridge.discovery.unhide's params: setting own or proxy with value on or off; hide with value
// "device", a port as "<port>[/udp]", or an instance as "<name>.<_service>.<_tcp|_udp>".
type DaemonBridgeDiscoveryParams struct {
	Network string `json:"network,omitempty"`
	Setting string `json:"setting"`
	Value   string `json:"value"`
}

// What the daemon's discovery methods are built over.
type DaemonBridgeDiscoveryArgs struct {
	// The network's discovery component; nil, or a nil answer, where none runs (ErrDaemonBridgeDiscoveryUnwired).
	Component func(networkId Id, running *Sidecar) *BridgeDiscoveryComponent
	// Whether the call's process has a harness among its ancestors, which a share and an unhide refuse (DESIGN-COMPUTE.md
	// §26.6). Nil asks the call's Sidecar by the pid its socket gave, refusing where there is none.
	HarnessAncestor func(ctx context.Context, call *DaemonCall) bool
}

// Whether call comes from under a harness, which the person's own acts refuse: the args' answer, else the Sidecar's,
// and true where neither can tell, the closed direction.
func (self *DaemonBridgeDiscovery) underHarness(ctx context.Context, call *DaemonCall) bool {
	if self.args != nil && self.args.HarnessAncestor != nil {
		return self.args.HarnessAncestor(ctx, call)
	}
	if call.Sidecar == nil || call.Hello == nil {
		return true
	}
	return call.Sidecar.HarnessAncestor(ctx, int(call.Hello.PeerPid))
}

// The daemon's discovery methods.
type DaemonBridgeDiscovery struct {
	args *DaemonBridgeDiscoveryArgs
}

// The methods over args.
func NewDaemonBridgeDiscovery(args *DaemonBridgeDiscoveryArgs) *DaemonBridgeDiscovery {
	return &DaemonBridgeDiscovery{args: args}
}

// The network's component, refusing where none runs.
func (self *DaemonBridgeDiscovery) component(call *DaemonCall) (*BridgeDiscoveryComponent, error) {
	if self.args == nil || self.args.Component == nil {
		return nil, ErrDaemonBridgeDiscoveryUnwired
	}
	component := self.args.Component(call.NetworkId, call.Sidecar)
	if component == nil {
		return nil, ErrDaemonBridgeDiscoveryUnwired
	}
	return component, nil
}

// The methods, each on one network.
func (self *DaemonBridgeDiscovery) Methods() []*DaemonMethod {
	return []*DaemonMethod{
		{
			Name:    DaemonMethodBridgeDevices,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonBridgeDevicesParams{}
				if err := decodeDaemonBridgeParams(call, params); err != nil {
					return nil, err
				}
				component, err := self.component(call)
				if err != nil {
					return nil, err
				}
				return component.Devices(), nil
			},
		},
		{
			Name:    DaemonMethodBridgeShare,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonBridgeShareParams{}
				if err := decodeDaemonBridgeParams(call, params); err != nil {
					return nil, err
				}
				component, err := self.component(call)
				if err != nil {
					return nil, err
				}
				if self.underHarness(ctx, call) {
					return nil, fmt.Errorf("%w: a share is refused under a harness process", ErrBridgeDiscoveryRefused)
				}
				if params.Disclosure {
					disclosure, err := component.ShareDisclosure(params.Device)
					if err != nil {
						return nil, err
					}
					return &DaemonBridgeShareReply{Disclosure: disclosure}, nil
				}
				var result *BridgeDiscoveryShareResult
				if params.Unshare {
					result, err = component.Unshare(ctx, daemonBridgeOrigin(call), params.Device)
				} else {
					result, err = component.Share(ctx, daemonBridgeOrigin(call), params.Device)
				}
				if err != nil {
					return nil, err
				}
				reply := &DaemonBridgeShareReply{State: result.State, ApprovalPendingId: result.ApprovalPendingId}
				if 0 < len(result.RuleId) {
					reply.RuleId = hex.EncodeToString(result.RuleId)
				}
				return reply, nil
			},
		},
		{
			Name:    DaemonMethodBridgeDiscovery,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonBridgeDiscoveryParams{}
				if err := decodeDaemonBridgeParams(call, params); err != nil {
					return nil, err
				}
				component, err := self.component(call)
				if err != nil {
					return nil, err
				}
				return component.Devices(), component.Set(params.Setting, params.Value, false)
			},
		},
		{
			Name:    DaemonMethodBridgeDiscoveryUnhide,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonBridgeDiscoveryParams{}
				if err := decodeDaemonBridgeParams(call, params); err != nil {
					return nil, err
				}
				component, err := self.component(call)
				if err != nil {
					return nil, err
				}
				if daemonBridgeOrigin(call).Act != SidecarActConfirmed || self.underHarness(ctx, call) {
					return nil, fmt.Errorf("%w: an unhide is the person's confirmed act alone", ErrBridgeDiscoveryRefused)
				}
				return component.Devices(), component.Set(DaemonBridgeDiscoveryHide, params.Value, true)
			},
		},
	}
}

// A hide's key from what a person writes: "device", "<port>" or "<port>/udp" at the host's overlay address, or an
// instance as "<name>.<_service>.<_tcp|_udp>".
func bridgeDiscoveryHideOf(value string) (device bool, portKey string, instanceKey string, err error) {
	if value == DaemonBridgeDiscoveryDevice {
		return true, "", "", nil
	}
	portText, transport := value, protocol.DnsSdTransportTcp
	if cut, isUdp := strings.CutSuffix(value, "/udp"); isUdp {
		portText, transport = cut, protocol.DnsSdTransportUdp
	} else if cut, isTcp := strings.CutSuffix(value, "/tcp"); isTcp {
		portText = cut
	}
	if port, parseErr := strconv.ParseUint(portText, 10, 16); parseErr == nil && port != 0 {
		return false, bridgeDiscoveryPortKey(transport, uint16(port)), "", nil
	}
	// an instance: its type is the last two labels, and its name the rest, which may hold dots
	lastDot := strings.LastIndexByte(value, '.')
	if lastDot <= 0 {
		return false, "", "", fmt.Errorf("%w: not a port, an instance or the device", ErrBridgeDiscoveryRefused)
	}
	typeDot := strings.LastIndexByte(value[:lastDot], '.')
	if typeDot <= 0 || !protocol.ValidDnsSdServiceType(value[typeDot+1:]) {
		return false, "", "", fmt.Errorf("%w: not a port, an instance or the device", ErrBridgeDiscoveryRefused)
	}
	return false, "", bridgeDiscoveryInstanceKey(value[:typeDot], value[typeDot+1:]), nil
}

// Sets one switch (the file's bridge.discovery and bridge.discovery.unhide rows): own or proxy on or off, a hide, or,
// with unhide, the person's unhide of what value names.
func (self *BridgeDiscoveryComponent) Set(setting string, value string, unhide bool) error {
	var edit func(state *bridgeDiscoveryState) error
	switch {
	case setting == DaemonBridgeDiscoveryOwn || setting == DaemonBridgeDiscoveryProxy:
		if unhide || (value != DaemonBridgeDiscoveryOn && value != DaemonBridgeDiscoveryOff) {
			return fmt.Errorf("%w: %s takes on or off", ErrBridgeDiscoveryRefused, setting)
		}
		off := value == DaemonBridgeDiscoveryOff
		edit = func(state *bridgeDiscoveryState) error {
			if setting == DaemonBridgeDiscoveryOwn {
				state.OwnOff = off
			} else {
				state.ProxyOff = off
			}
			return nil
		}
	case setting == DaemonBridgeDiscoveryHide:
		device, portKey, instanceKey, err := bridgeDiscoveryHideOf(value)
		if err != nil {
			return err
		}
		edit = func(state *bridgeDiscoveryState) error {
			switch {
			case device:
				state.HiddenDevice = !unhide
			case portKey != "":
				state.HiddenPorts = bridgeDiscoveryToggle(state.HiddenPorts, portKey, !unhide)
			default:
				state.HiddenInstances = bridgeDiscoveryToggle(state.HiddenInstances, instanceKey, !unhide)
			}
			if self.settings.HideCount < len(state.HiddenPorts)+len(state.HiddenInstances) {
				return fmt.Errorf("%w: the hide set holds its limit", ErrBridgeDiscoveryRefused)
			}
			return nil
		}
	default:
		return fmt.Errorf("%w: no such setting", ErrBridgeDiscoveryRefused)
	}
	if _, err := self.editableState(); err != nil {
		return err
	}
	var editErr error
	err := self.commitState(func(state *bridgeDiscoveryState) {
		state.NoticeSeen = true
		editErr = edit(state)
	})
	if editErr != nil {
		return editErr
	}
	return err
}

// keys with key in where on, and without it otherwise, sorted.
func bridgeDiscoveryToggle(keys []string, key string, on bool) []string {
	keys = slices.DeleteFunc(slices.Clone(keys), func(held string) bool { return held == key })
	if on {
		keys = append(keys, key)
		slices.Sort(keys)
	}
	return keys
}

// Whether the advertising proxy runs on this host: off only by `ur bridge discovery proxy off` (Q-BRIDGE-9).
func (self *BridgeDiscoveryComponent) ProxyOn() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return !self.stateWithLock().ProxyOff
}

// The own-services notice while the person has not seen it, empty once seen (§17.7.1's Disclosure and opt-out): what
// ur status shows.
func (self *BridgeDiscoveryComponent) PendingNotice() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.stateErr != nil || self.state == nil || self.state.NoticeSeen {
		return ""
	}
	return BridgeDiscoveryOwnNotice
}

// What `ur bridge devices` lists (the file's bridge.devices row), asking the gatherer to run and marking the notice
// seen.
func (self *BridgeDiscoveryComponent) Devices() *DaemonBridgeDevicesReply {
	self.demand(true)
	now := self.clock.Now()
	input := self.hostInput()
	reply := &DaemonBridgeDevicesReply{
		Notice:       self.PendingNotice(),
		Own:          !input.state.OwnOff,
		Proxy:        !input.state.ProxyOff,
		HiddenDevice: input.state.HiddenDevice,
		Hides:        slices.Concat(input.state.HiddenPorts, input.state.HiddenInstances),
		Types:        input.types,
	}
	for i, hide := range reply.Hides {
		// an instance's key holds its type, then its name
		if service, name, isInstance := strings.Cut(hide, "\x00"); isInstance {
			reply.Hides[i] = name + "." + service
		}
	}
	serving := bridgeDiscoveryServes(input)
	published := bridgeDiscoveryPublish(input, now, self.settings)
	if !serving {
		published = nil
	}
	for _, item := range published {
		reply.Published = append(reply.Published, &DaemonBridgeInstance{
			Name:    item.instance.GetName(),
			Service: item.instance.GetService(),
			Address: item.address.String(),
			Port:    uint16(item.instance.GetPort()),
			Own:     item.instance.GetOwn(),
			Ttl:     int64(item.expires.Sub(now) / time.Second),
		})
	}
	// the LAN's devices, each with its services and why any is withheld
	devices := map[string]*DaemonBridgeLanDevice{}
	labels := []string{}
	for _, gathered := range input.gathered {
		if gathered.Own || gathered.PointToPoint || gathered.LocalOnly {
			continue
		}
		label := BridgeDiscoveryHostLabel(gathered.HostName)
		device := devices[label]
		if device == nil {
			device = &DaemonBridgeLanDevice{HostLabel: label}
			if address := bridgeDiscoveryDeviceAddress(gathered); address.IsValid() {
				device.Address = address.String()
			}
			if share := input.state.share(label); share != nil {
				device.Share, device.RuleId, device.ApprovalId = share.State, share.RuleId, share.ApprovalId
			}
			devices[label] = device
			labels = append(labels, label)
		}
		service := strings.ToLower(gathered.Service)
		if service == "_device-info._tcp" {
			device.Model = bridgeDiscoveryTxtValue(gathered.Txt, "model")
			continue
		}
		if device.Name == "" {
			device.Name = gathered.Name
		}
		instance := &DaemonBridgeInstance{Name: gathered.Name, Service: service, Port: gathered.Port}
		switch {
		case device.Share == "":
			instance.Withheld = "not shared"
		case device.Share != bridgeDiscoveryShareActive:
			instance.Withheld = "share " + device.Share
		case input.state.hidesInstance(gathered.Name, service):
			instance.Withheld = "hidden"
		case !slices.ContainsFunc(published, func(item *bridgeDiscoveryPublished) bool {
			return item.instance.GetName() == gathered.Name && item.instance.GetService() == service
		}):
			instance.Withheld = "no route or map of this host serves it"
		}
		device.Services = append(device.Services, instance)
	}
	slices.Sort(labels)
	for _, label := range labels {
		reply.Lan = append(reply.Lan, devices[label])
	}
	// what this device sees, by host
	view := self.View()
	dropped := func() map[Id]int {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		counts := map[Id]int{}
		for hostId, count := range self.droppedCount {
			counts[hostId] = count
		}
		return counts
	}()
	hosts := map[Id]*DaemonBridgeRemoteHost{}
	for _, instance := range view {
		host := hosts[instance.HostSidecarId]
		if host == nil {
			host = &DaemonBridgeRemoteHost{SidecarId: instance.HostSidecarId, Name: instance.HostName, DroppedCount: dropped[instance.HostSidecarId]}
			hosts[instance.HostSidecarId] = host
			reply.Remote = append(reply.Remote, host)
		}
		host.Instances = append(host.Instances, &DaemonBridgeInstance{
			Name:    instance.Name,
			Service: instance.Service,
			Address: netip.AddrPortFrom(instance.Address, instance.Port).Addr().String(),
			Port:    instance.Port,
			Own:     instance.Own,
			Ttl:     int64(instance.Expires.Sub(now) / time.Second),
		})
	}
	for hostId, count := range dropped {
		if _, held := hosts[hostId]; !held && 0 < count {
			reply.Remote = append(reply.Remote, &DaemonBridgeRemoteHost{SidecarId: hostId, DroppedCount: count})
		}
	}
	// the person has seen the notice once ur bridge devices showed it
	if reply.Notice != "" {
		seen := true
		self.commitStateIf(func(state *bridgeDiscoveryState) { state.NoticeSeen = true }, &seen)
	}
	return reply
}
