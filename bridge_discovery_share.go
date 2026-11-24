//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// Sharing a LAN device (§17.7.1's Sharing a device, D-BRIDGE-24; owner decision 778): a device is published only by its
// person's act on its host, since its name and model belong to whoever uses it.
//
//	share     the Confirm daemon method bridge.share (from control with the person's confirmation, never MCP; §5.8):
//	          <device> is a LAN host the host's own view lists, by its mDNS host label, after the disclosure
//	route     a served prefix of this host that covers the device's IPv4 address serves it as it is; otherwise the
//	          host files a BridgeRoute of that /32 remapped to an exposed /32 of the upper /17, first fit, an expose
//	          under §16.6's approval (I-8), and publishes once the route is in force; a filing that waits answers its
//	          approval, and the person's next share once it lands files nothing twice, the gate answering from its record
//	keep      the share sits in the host's own sealed settings, by host label, in no statement and at no server
//	moves     within a served prefix, the records follow the device's new address; out of a /32 share's route the host
//	          stops publishing the device and withdraws the route (BridgeWithdraw, drain), since another device may take
//	          the address, and `ur bridge devices` asks its person to share again; a device unseen for
//	          ShareRouteAbsentTimeout loses its /32 route and keeps its share, which its person shares again
//	unshare   no longer published, and a /32 route its share filed is withdrawn
//
// Each disclosure's words are §17.7.1's. Logs and errors name opaque ids alone, never a device's name or address (I-13).

package sidecar

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

var (
	// The device is not on this host's view now: `ur bridge devices` lists what is.
	ErrBridgeDiscoveryNoDevice = errors.New("no such device on this host's network now: ur bridge devices lists them")
	// The call is not the person's confirmed act, the sealed settings do not read, or a limit is reached.
	ErrBridgeDiscoveryRefused = errors.New("discovery refused the call")
)

// The filings a share makes: the network's bridge backend's (DaemonBridgeBackend), BridgeFiler's own.
type BridgeDiscoveryFiler interface {
	Expose(ctx context.Context, origin *BridgeFileOrigin, request *BridgeRouteRequest) (*BridgeFiling, error)
	Close(ctx context.Context, origin *BridgeFileOrigin, id []byte, reset bool) (*BridgeFiling, error)
}

// What a share or an unshare answers.
type BridgeDiscoveryShareResult struct {
	HostLabel string
	// the device's address on this host's network
	Address netip.Addr
	// the share's state: active, waiting, moved, absent, or empty once unshared
	State string
	// the /32 route its share filed, nil where a served prefix covers it
	RuleId []byte
	// the decision the route's filing waits on, nil for none
	ApprovalPendingId *Id
}

// What the own-services notice says, at ur daemon's first start after discovery ships, in ur status until seen, and
// once in the desktop app (§17.7.1's Disclosure and opt-out; Q-BRIDGE-9).
const BridgeDiscoveryOwnNotice = "This computer's services that it announces on its own network (file sharing, screen sharing, SSH, " +
	"printers it shares) show by name, with this computer's name, on the devices of your URnetwork network whose policy " +
	"lets them reach those services. `ur bridge discovery off` stops it; `ur bridge discovery hide` hides one, from the " +
	"Listeners section too."

// What sharing a LAN device shows before its approval (§17.7.1's Disclosure and opt-out): name and model as the device
// announces them, model empty for none, and address where the network's devices connect to it, empty while its route
// is yet to be drawn.
func BridgeDiscoveryShareDisclosure(name string, model string, address string) string {
	device := "`" + name + "`"
	if model != "" {
		device += " (`" + model + "`)"
	}
	at := "at `" + address + "`"
	if address == "" {
		at = "at an address of your network's block, drawn when its route is filed"
	}
	return "Sharing " + device + " lets the devices of your network that its policy lets reach it see its name, its model " +
		"and the services it offers, with their ports, and connect to it through this computer " + at + ". Devices on this " +
		"computer's network that you do not share stay unseen."
}

// A share's origin, held to the person's confirmed act.
func bridgeDiscoveryCheckOrigin(origin *BridgeFileOrigin) error {
	if origin == nil || origin.Act != SidecarActConfirmed {
		return fmt.Errorf("%w: sharing is the person's confirmed act alone", ErrBridgeDiscoveryRefused)
	}
	return nil
}

// The device of hostLabel as the gatherer holds it now: its first LAN address, its first instance's name, and its
// model from _device-info._tcp's TXT, where it announces one.
func (self *BridgeDiscoveryComponent) gatheredDevice(hostLabel string) (address netip.Addr, name string, model string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, gathered := range self.gathered {
		if gathered.Own || gathered.PointToPoint || gathered.LocalOnly || BridgeDiscoveryHostLabel(gathered.HostName) != hostLabel {
			continue
		}
		if !address.IsValid() {
			address = bridgeDiscoveryDeviceAddress(gathered)
		}
		if name == "" && strings.ToLower(gathered.Service) != "_device-info._tcp" {
			name = gathered.Name
		}
		if strings.ToLower(gathered.Service) == "_device-info._tcp" {
			model = bridgeDiscoveryTxtValue(gathered.Txt, "model")
		}
	}
	return address, name, model
}

// The value of key=... in a TXT rdata, empty for none (RFC 6763 §6.3, keys compared without case).
func bridgeDiscoveryTxtValue(txt []byte, key string) string {
	for at := 0; at < len(txt); {
		count := int(txt[at])
		if len(txt) < at+1+count {
			return ""
		}
		entry := string(txt[at+1 : at+1+count])
		at += 1 + count
		if found, value, ok := strings.Cut(entry, "="); ok && strings.EqualFold(found, key) {
			return value
		}
	}
	return ""
}

// The disclosure for sharing hostLabel's device as it stands now, which the caller shows before it confirms.
func (self *BridgeDiscoveryComponent) ShareDisclosure(hostLabel string) (string, error) {
	self.demand(true)
	hostLabel = BridgeDiscoveryHostLabel(hostLabel)
	address, name, model := self.gatheredDevice(hostLabel)
	if !address.IsValid() {
		return "", ErrBridgeDiscoveryNoDevice
	}
	if name == "" {
		name = hostLabel
	}
	at := ""
	if self.args.Routes != nil {
		if routes := self.args.Routes(); routes != nil {
			for _, served := range routes.Served {
				if served.Prefix.Contains(address) {
					published, _ := routes.sharedAddress(address, "_tcp", 1)
					at = published.String()
				}
			}
		}
	}
	return BridgeDiscoveryShareDisclosure(name, model, at), nil
}

// Shares hostLabel's device (the file's share and route rows), from origin, the person's confirmed act.
func (self *BridgeDiscoveryComponent) Share(ctx context.Context, origin *BridgeFileOrigin, hostLabel string) (*BridgeDiscoveryShareResult, error) {
	if err := bridgeDiscoveryCheckOrigin(origin); err != nil {
		return nil, err
	}
	self.demand(true)
	hostLabel = BridgeDiscoveryHostLabel(hostLabel)
	address, _, _ := self.gatheredDevice(hostLabel)
	if hostLabel == "" || !address.IsValid() {
		return nil, ErrBridgeDiscoveryNoDevice
	}
	state, err := self.editableState()
	if err != nil {
		return nil, err
	}
	share := state.share(hostLabel)
	if share == nil && self.settings.ShareCount <= len(state.Shares) {
		return nil, fmt.Errorf("%w: this host shares its limit of devices; unshare one first", ErrBridgeDiscoveryRefused)
	}
	if share != nil && share.State == bridgeDiscoveryShareActive && share.Address == address.String() {
		return bridgeDiscoveryShareResultOf(share, address), nil
	}
	var routes *BridgeDiscoveryRoutes
	if self.args.Routes != nil {
		routes = self.args.Routes()
	}
	next := &bridgeDiscoveryShare{HostLabel: hostLabel, Address: address.String(), SeenMs: self.clock.Now().UnixMilli()}
	served := routes != nil && func() bool {
		for _, servedPrefix := range routes.Served {
			if servedPrefix.Prefix.Contains(address) && servedPrefix.Prefix.Bits() < 32 {
				return true
			}
		}
		return false
	}()
	if served {
		next.State = bridgeDiscoveryShareActive
	} else {
		if self.args.Filer == nil {
			return nil, fmt.Errorf("%w: no bridge files routes for this network", ErrBridgeDiscoveryRefused)
		}
		filing, err := self.args.Filer.Expose(ctx, origin, &BridgeRouteRequest{
			Prefixes: []netip.Prefix{netip.PrefixFrom(address, 32)},
			Remap:    true,
		})
		var pending *ApprovalPendingError
		switch {
		case errors.As(err, &pending):
			next.State = bridgeDiscoveryShareWaiting
			next.ApprovalId = pending.ApprovalId.String()
		case err != nil:
			return nil, err
		default:
			next.State = bridgeDiscoveryShareActive
			next.RuleId = hex.EncodeToString(filing.RuleId)
		}
	}
	err = self.commitState(func(state *bridgeDiscoveryState) {
		for i, held := range state.Shares {
			if held.HostLabel == hostLabel {
				state.Shares[i] = next
				return
			}
		}
		state.Shares = append(state.Shares, next)
	})
	if err != nil {
		return nil, err
	}
	return bridgeDiscoveryShareResultOf(next, address), nil
}

// A share as its result.
func bridgeDiscoveryShareResultOf(share *bridgeDiscoveryShare, address netip.Addr) *BridgeDiscoveryShareResult {
	result := &BridgeDiscoveryShareResult{HostLabel: share.HostLabel, Address: address, State: share.State}
	if ruleId, err := hex.DecodeString(share.RuleId); err == nil && 0 < len(ruleId) {
		result.RuleId = ruleId
	}
	if share.State == bridgeDiscoveryShareWaiting {
		if approvalId, err := ParseId(share.ApprovalId); err == nil {
			result.ApprovalPendingId = &approvalId
		}
	}
	return result
}

// Ends hostLabel's share (the file's unshare row), withdrawing a /32 route it filed, from origin, the person's
// confirmed act.
func (self *BridgeDiscoveryComponent) Unshare(ctx context.Context, origin *BridgeFileOrigin, hostLabel string) (*BridgeDiscoveryShareResult, error) {
	if err := bridgeDiscoveryCheckOrigin(origin); err != nil {
		return nil, err
	}
	hostLabel = BridgeDiscoveryHostLabel(hostLabel)
	state, err := self.editableState()
	if err != nil {
		return nil, err
	}
	share := state.share(hostLabel)
	if share == nil {
		return nil, ErrBridgeDiscoveryNoDevice
	}
	// unpublished first, so no answer names the device while its route drains
	err = self.commitState(func(state *bridgeDiscoveryState) {
		for i, held := range state.Shares {
			if held.HostLabel == hostLabel {
				state.Shares = append(state.Shares[:i], state.Shares[i+1:]...)
				return
			}
		}
	})
	if err != nil {
		return nil, err
	}
	if err := self.withdrawShareRoute(ctx, origin, share); err != nil {
		return nil, err
	}
	return &BridgeDiscoveryShareResult{HostLabel: hostLabel}, nil
}

// Withdraws the /32 route share filed, draining, where it filed one.
func (self *BridgeDiscoveryComponent) withdrawShareRoute(ctx context.Context, origin *BridgeFileOrigin, share *bridgeDiscoveryShare) error {
	ruleId, err := hex.DecodeString(share.RuleId)
	if err != nil || len(ruleId) == 0 {
		return nil
	}
	if self.args.Filer == nil {
		return fmt.Errorf("%w: no bridge files routes for this network", ErrBridgeDiscoveryRefused)
	}
	if _, err := self.args.Filer.Close(ctx, origin, ruleId, false); err != nil && !errors.Is(err, ErrBridgeFileRefused) {
		return err
	}
	return nil
}

// The shares' moves and absences (the file's moves row), judged on the host loop: a /32 share whose device left its
// address, or that went unseen for ShareRouteAbsentTimeout, is unpublished at once and its route withdrawn off the loop.
func (self *BridgeDiscoveryComponent) upkeepShares(input *bridgeDiscoveryHostInput, now time.Time) {
	if input.state == nil || len(input.state.Shares) == 0 {
		return
	}
	seen := map[string]netip.Addr{}
	for _, gathered := range input.gathered {
		if gathered.Own || gathered.PointToPoint || gathered.LocalOnly {
			continue
		}
		label := BridgeDiscoveryHostLabel(gathered.HostName)
		if _, held := seen[label]; !held {
			if address := bridgeDiscoveryDeviceAddress(gathered); address.IsValid() {
				seen[label] = address
			}
		}
	}
	withdrawn := []*bridgeDiscoveryShare{}
	changed := false
	edit := func(state *bridgeDiscoveryState) {
		for _, share := range state.Shares {
			address, isSeen := seen[share.HostLabel]
			if isSeen && share.SeenMs < now.UnixMilli() {
				share.SeenMs = now.UnixMilli()
				changed = true
			}
			if share.State != bridgeDiscoveryShareActive || share.RuleId == "" {
				continue
			}
			switch {
			case isSeen && address.String() != share.Address:
				share.State = bridgeDiscoveryShareMoved
			case !isSeen && self.settings.ShareRouteAbsentTimeout <= now.Sub(time.UnixMilli(share.SeenMs)):
				share.State = bridgeDiscoveryShareAbsent
			default:
				continue
			}
			held := *share
			withdrawn = append(withdrawn, &held)
			share.RuleId = ""
			changed = true
		}
	}
	if err := self.commitStateIf(edit, &changed); err != nil {
		self.log.Warningf("[discovery]a share's upkeep did not save: %v", err)
		return
	}
	for _, share := range withdrawn {
		go func() {
			ctx, cancel := context.WithTimeout(self.ctx, self.settings.WatchCallTimeout)
			defer cancel()
			// the host withdraws its own route, an own-resource filing any mode signs (§5.8, §16.6)
			if err := self.withdrawShareRoute(ctx, &BridgeFileOrigin{Act: SidecarActUnconfirmed}, share); err != nil {
				self.log.Warningf("[discovery]a moved or absent share's route was not withdrawn: %v", err)
			}
		}()
	}
}

// The sealed settings as they stand, for an edit: refused while the file does not read or before the first generation.
func (self *BridgeDiscoveryComponent) editableState() (*bridgeDiscoveryState, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.stateErr != nil {
		return nil, fmt.Errorf("%w: the sealed settings do not read", ErrBridgeDiscoveryRefused)
	}
	if self.state == nil {
		return nil, fmt.Errorf("%w: the network is not connected yet", ErrBridgeDiscoveryRefused)
	}
	return self.state.clone(), nil
}

// Applies edit to the sealed settings, writes them whole and wakes the host loop.
func (self *BridgeDiscoveryComponent) commitState(edit func(state *bridgeDiscoveryState)) error {
	changed := true
	return self.commitStateIf(edit, &changed)
}

// Applies edit, which sets *changed where it changed anything, and writes the settings where it did.
func (self *BridgeDiscoveryComponent) commitStateIf(edit func(state *bridgeDiscoveryState), changed *bool) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.stateErr != nil || self.state == nil {
		return fmt.Errorf("%w: the sealed settings are not in hand", ErrBridgeDiscoveryRefused)
	}
	next := self.state.clone()
	edit(next)
	if !*changed {
		return nil
	}
	if err := writeBridgeDiscoveryState(self.store, next); err != nil {
		return err
	}
	self.state = next
	self.pokeWithLock()
	return nil
}
