//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// A host's own discovery settings (§17.7.1; owner decision 778), kept sealed in its component's store and at no server:
//
//	switches  own off (`ur bridge discovery off`, Q-BRIDGE-9), which withholds the Bonjour names of the host's own
//	          services and listed entries alone; proxy off (`ur bridge discovery proxy off`); the first-start notice
//	          seen
//	hides     one set, which `ur bridge discovery hide` and `ur listeners hide` both write and both views honor
//	          (§17.7.1's Hiding; DESIGN-COMPUTE.md §26.6): a protocol and port at the host's overlay address, which takes
//	          a listed entry, its Bonjour name and an own service its mDNS announces on that port alike; an instance by
//	          name and type, a shared device's among them; and the device whole, which publishes no instance at its
//	          overlay address
//	shares    each LAN device its person shared, by its mDNS host label: the address it was shared at, the /32 route
//	          its share filed, or the approval that filing waits on, and when the gatherer last saw it
//
// The file is JSON, local to the device and versioned; a file that does not read, or a version this build does not
// know, is refused and kept, and the component runs from defaults with sharing stopped, the closed direction, until
// the person writes again.

package sidecar

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// The state file's name in the component's store, and its version.
const (
	bridgeDiscoveryStateName    = "discovery.json"
	bridgeDiscoveryStateVersion = 1
)

// A share's state.
const (
	// published once its route stands
	bridgeDiscoveryShareActive = "active"
	// its /32 route waits for §16.6's approval
	bridgeDiscoveryShareWaiting = "waiting"
	// the device left its /32 route's address: unpublished and its route withdrawn, until its person shares again
	bridgeDiscoveryShareMoved = "moved"
	// unseen for ShareRouteAbsentTimeout: its /32 route withdrawn, the share kept until its person shares again
	bridgeDiscoveryShareAbsent = "absent"
)

// One LAN device its person shared.
type bridgeDiscoveryShare struct {
	// the device's mDNS host label, lowercase
	HostLabel string `json:"host_label"`
	// the IPv4 address it was shared at
	Address string `json:"address"`
	// the /32 route its share filed, hex; empty where a served prefix covers it
	RuleId string `json:"rule_id,omitempty"`
	// the approval the filing waits on
	ApprovalId string `json:"approval_id,omitempty"`
	State      string `json:"state"`
	// when the gatherer last saw it, unix milliseconds
	SeenMs int64 `json:"seen_ms,omitempty"`
}

// The state file.
type bridgeDiscoveryState struct {
	Version      int  `json:"version"`
	OwnOff       bool `json:"own_off,omitempty"`
	ProxyOff     bool `json:"proxy_off,omitempty"`
	NoticeSeen   bool `json:"notice_seen,omitempty"`
	HiddenDevice bool `json:"hidden_device,omitempty"`
	// "tcp/445"
	HiddenPorts []string `json:"hidden_ports,omitempty"`
	// "<type>\x00<name>", the name lowercased in ASCII
	HiddenInstances []string                `json:"hidden_instances,omitempty"`
	Shares          []*bridgeDiscoveryShare `json:"shares,omitempty"`
}

// A state with nothing set.
func newBridgeDiscoveryState() *bridgeDiscoveryState {
	return &bridgeDiscoveryState{Version: bridgeDiscoveryStateVersion}
}

// A copy the caller may change.
func (self *bridgeDiscoveryState) clone() *bridgeDiscoveryState {
	clone := *self
	clone.HiddenPorts = slices.Clone(self.HiddenPorts)
	clone.HiddenInstances = slices.Clone(self.HiddenInstances)
	clone.Shares = make([]*bridgeDiscoveryShare, 0, len(self.Shares))
	for _, share := range self.Shares {
		held := *share
		clone.Shares = append(clone.Shares, &held)
	}
	return &clone
}

// An instance's hide key.
func bridgeDiscoveryInstanceKey(name string, service string) string {
	return strings.ToLower(service) + "\x00" + strings.ToLower(name)
}

// Whether the hide set holds transport and port at the host's overlay address.
func (self *bridgeDiscoveryState) hidesPort(transport string, port uint16) bool {
	return slices.Contains(self.HiddenPorts, bridgeDiscoveryPortKey(transport, port))
}

// Whether the hide set holds an instance.
func (self *bridgeDiscoveryState) hidesInstance(name string, service string) bool {
	return slices.Contains(self.HiddenInstances, bridgeDiscoveryInstanceKey(name, service))
}

// The share of a host label, nil for none.
func (self *bridgeDiscoveryState) share(hostLabel string) *bridgeDiscoveryShare {
	for _, share := range self.Shares {
		if share.HostLabel == hostLabel {
			return share
		}
	}
	return nil
}

// The state as the store holds it; a fresh one where none is kept. A file that does not read is refused.
func readBridgeDiscoveryState(store SidecarStore) (*bridgeDiscoveryState, error) {
	if store == nil {
		return newBridgeDiscoveryState(), nil
	}
	reader, err := store.Open(bridgeDiscoveryStateName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return newBridgeDiscoveryState(), nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	state := &bridgeDiscoveryState{}
	if err := json.Unmarshal(data, state); err != nil {
		return nil, fmt.Errorf("the discovery state does not read: %w", err)
	}
	if state.Version != bridgeDiscoveryStateVersion {
		return nil, fmt.Errorf("the discovery state is of version %d", state.Version)
	}
	for _, share := range state.Shares {
		if share == nil {
			return nil, errors.New("the discovery state holds an empty share")
		}
	}
	return state, nil
}

// Writes state whole into store; nothing shows until it commits.
func writeBridgeDiscoveryState(store SidecarStore, state *bridgeDiscoveryState) error {
	if store == nil {
		return nil
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	writer, err := store.Create(bridgeDiscoveryStateName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}
