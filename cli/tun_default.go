// ur tun's plan for the host's default traffic (QD-1052, amending QD-1048 and owner decisions 479, 480 and 482): the
// tun takes the host's default routes, IPv4's and IPv6's with each platform's rules, halves and carve (SetExits), only
// when default egress is in force and the client has an egress destination, or when it has none and route local
// traffic is off, which keeps today's capture and refusal, the closed direction:
//
//	destination  under the egress mode exits, an exit of the network the bridge can use (device.BridgeStatus's
//	             EgressExitCount); under auto, the connect client's destination (urTunDestination), which no client
//	             of the daemon's declares yet (§20.8), so there is none; under none, never one
//	egress       default egress on and a destination: the default routes ride the tun to it, the exits under exits
//	local        default egress on, no destination and route local traffic on: the host's own default routes stay,
//	             and the tun carries only the block, the granted prefixes and the private names
//	refused      default egress on, no destination and route local traffic off: the default routes ride the tun,
//	             which refuses what it takes, by the bridge's rejects under exits and none and dropped and counted
//	             under auto
//	off          default egress off: the host's own default routes stay, in every mode
//
// Default egress and route local traffic are the person's two choices for each network (urTunChoices), which ur tun
// sets and shows and the daemon keeps in the network's sealed local state (urTunSealedChoices): default egress is on
// unless the person turns it off, and route local traffic on, as the sdk's DefaultRouteLocal is, each default a field
// of urTunSettings (QD-702). Under exits, the network's admin, owner or sponsor may require default egress on in the
// egress spec's sealed exits body (QD-1053; device.BridgeStatus's DefaultEgressRequired): the plan then keeps it on
// whatever the person chose, and ur tun refuses to turn it off, naming the requirement, while the other rules hold, so
// with no destination default traffic still keeps the host's routes, or with route local traffic off is refused. The
// network's egress mode stays its admin's policy for traffic that enters URnetwork, and §8.10's gate is unchanged.
// Each sync plans again (tun_device.go), so a change of either choice, a destination that appears or goes, or a
// requirement that comes or is lifted, puts the default routes on or takes them off with no restart of the tun.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What the tun does with the host's default traffic, as the plan names it (the file's comment).
const (
	urTunDefaultTrafficEgress  = "egress"
	urTunDefaultTrafficLocal   = "local"
	urTunDefaultTrafficRefused = "refused"
	urTunDefaultTrafficOff     = "off"
)

// How ur tun spells a choice on its command line and in its output.
const (
	urTunChoiceOn  = "on"
	urTunChoiceOff = "off"
)

// Where the daemon keeps a network's choices, in the network's sealed local state: the directory, its class and the
// record's name, and the record's version.
const (
	urTunChoicesDirectory     = "tun"
	urTunChoicesClass         = "tun"
	urTunChoicesRecordName    = "choices"
	urTunChoicesRecordVersion = 1
)

// A choice that is neither on nor off.
var errUrTunChoice = errors.New("a choice is on or off")

// Default egress turned off for a network whose egress spec requires it on (QD-1053).
var errUrTunDefaultEgressRequired = errors.New("the network requires its devices to keep default egress on: its " +
	"admin, owner or sponsor set it with the egress mode exits, and ur tun --default-egress=off waits for them to lift it")

// One network's choices for the host's default traffic (QD-1052): what the person chose, else the settings' defaults.
type urTunChoices struct {
	// Whether the host's default traffic goes to the client's egress destination through the tun.
	DefaultEgress bool
	// Whether default traffic with no destination keeps the host's own routes; off, the tun takes it and refuses it.
	RouteLocal bool
}

// The settings' defaults, which hold until the person chooses.
func urTunDefaultChoices(settings *urTunSettings) urTunChoices {
	return urTunChoices{DefaultEgress: settings.DefaultEgress, RouteLocal: settings.DefaultRouteLocal}
}

// A change of a network's choices that ur tun asks for: nil leaves a choice as it is.
type urTunChoiceChange struct {
	DefaultEgress *bool
	RouteLocal    *bool
}

// Whether the change changes anything.
func (self *urTunChoiceChange) empty() bool {
	return self == nil || (self.DefaultEgress == nil && self.RouteLocal == nil)
}

// A choice as ur tun takes it: on, off, or empty for unchanged, nil.
func parseUrTunChoice(text string) (*bool, error) {
	switch text {
	case "":
		return nil, nil
	case urTunChoiceOn:
		on := true
		return &on, nil
	case urTunChoiceOff:
		off := false
		return &off, nil
	}
	return nil, fmt.Errorf("%w, not %q", errUrTunChoice, text)
}

// A choice as ur tun prints it.
func urTunChoiceName(on bool) string {
	if on {
		return urTunChoiceOn
	}
	return urTunChoiceOff
}

// A network's choices as the daemon keeps them, JSON: a choice the person never made is absent, so it follows the
// settings' default.
type urTunChoiceRecord struct {
	Version       int   `json:"version"`
	DefaultEgress *bool `json:"default_egress,omitempty"`
	RouteLocal    *bool `json:"route_local,omitempty"`
}

// The choices the record holds, the settings' defaults where it holds none.
func (self *urTunChoiceRecord) choices(settings *urTunSettings) urTunChoices {
	choices := urTunDefaultChoices(settings)
	if self == nil {
		return choices
	}
	if self.DefaultEgress != nil {
		choices.DefaultEgress = *self.DefaultEgress
	}
	if self.RouteLocal != nil {
		choices.RouteLocal = *self.RouteLocal
	}
	return choices
}

// Where a network's choices are kept.
type urTunChoiceStore interface {
	// The record kept, nil for none.
	Load() (*urTunChoiceRecord, error)
	// Replaces the record, whole, at once.
	Save(record *urTunChoiceRecord) error
}

// The choices in the network's sealed local state (§5.9's net/<network_id>/), tun/choices under its own class, so a
// process that cannot open the instance's keychain can neither read nor change them. A store that does not open, a
// locked instance's, answers its error, and ur tun refuses rather than guess a choice.
type urTunSealedChoices struct {
	store func() (sidecar.SidecarStore, error)
}

var _ urTunChoiceStore = (*urTunSealedChoices)(nil)

// The choices of running's network.
func newUrTunSealedChoices(running *sidecar.Sidecar) *urTunSealedChoices {
	return &urTunSealedChoices{store: func() (sidecar.SidecarStore, error) {
		return running.LocalStore().Directory(urTunChoicesDirectory, urTunChoicesClass)
	}}
}

func (self *urTunSealedChoices) Load() (*urTunChoiceRecord, error) {
	store, err := self.store()
	if err != nil {
		return nil, err
	}
	reader, err := store.Open(urTunChoicesRecordName)
	if errors.Is(err, sidecar.ErrSidecarStoreAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	encoded, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	record := &urTunChoiceRecord{}
	if err := json.Unmarshal(encoded, record); err != nil || record.Version != urTunChoicesRecordVersion {
		return nil, fmt.Errorf("the tun's choices do not read at version %d", urTunChoicesRecordVersion)
	}
	return record, nil
}

func (self *urTunSealedChoices) Save(record *urTunChoiceRecord) error {
	store, err := self.store()
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	writer, err := store.Create(urTunChoicesRecordName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(encoded); err != nil {
		return err
	}
	return writer.Commit()
}

// Choices kept for the daemon's life alone: a network whose bridge no Sidecar's state backs, as a test's is.
type urTunMemoryChoices struct {
	stateLock sync.Mutex
	record    *urTunChoiceRecord
}

var _ urTunChoiceStore = (*urTunMemoryChoices)(nil)

func (self *urTunMemoryChoices) Load() (*urTunChoiceRecord, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.record == nil {
		return nil, nil
	}
	record := *self.record
	return &record, nil
}

func (self *urTunMemoryChoices) Save(record *urTunChoiceRecord) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	saved := *record
	self.record = &saved
	return nil
}

// The connect client's egress destination under the egress mode auto (QD-1052), which carries the host's default
// traffic once the tun takes it: the bridge leaves such a packet to today's route, a nil client, and the tun sends it
// here. The daemon wires none: no client of its declares a destination until ur proxy or a public exit sets one
// (§20.8), so under auto the client has no destination, and the plan reads route local traffic.
type urTunDestination interface {
	// The client that carries default traffic now, nil for none.
	Client() connect.UserNatClient
	// Calls changed on each change of Client, never blocking; the answer removes it.
	AddChangeCallback(changed func()) func()
}

// What the tun does with the host's default traffic, as each sync plans it (the file's comment).
type urTunDefaultPlan struct {
	// Whether the tun takes the host's default routes.
	Take bool
	// Whether default egress is in force: the person's choice, or the network's requirement.
	DefaultEgress bool
	// Whether the network requires it, under exits alone (QD-1053).
	Required bool
	// Whether the client has an egress destination.
	Destination bool
	// egress, local, refused or off (urTunDefaultTraffic...).
	Traffic string
}

// Whether the bridge's state requires default egress on, under exits alone (QD-1053).
func urTunDefaultEgressRequired(status device.BridgeStatus) bool {
	return status.EgressMode == bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS && status.DefaultEgressRequired
}

// The plan for the bridge's state, whether the connect client has a destination under auto, and the network's choices.
func urTunPlanDefault(status device.BridgeStatus, autoDestination bool, choices urTunChoices) urTunDefaultPlan {
	plan := urTunDefaultPlan{DefaultEgress: choices.DefaultEgress}
	switch status.EgressMode {
	case bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS:
		plan.Destination = 0 < status.EgressExitCount
		// the network's requirement holds default egress on whatever the person chose (QD-1053)
		plan.Required = status.DefaultEgressRequired
		plan.DefaultEgress = plan.DefaultEgress || plan.Required
	case bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE:
		// no egress at all, so no destination
	default:
		// auto, and a state that names no mode, which keeps today's route as auto does
		plan.Destination = autoDestination
	}
	switch {
	case !plan.DefaultEgress:
		plan.Traffic = urTunDefaultTrafficOff
	case plan.Destination:
		plan.Traffic = urTunDefaultTrafficEgress
		plan.Take = true
	case choices.RouteLocal:
		plan.Traffic = urTunDefaultTrafficLocal
	default:
		plan.Traffic = urTunDefaultTrafficRefused
		plan.Take = true
	}
	return plan
}

// The client a nil route's run goes to under auto while the plan sends default traffic to the destination, as a send
// reads it, swapped whole.
type urTunDestinationClient struct {
	client connect.UserNatClient
}

// The network's choices for default traffic with change applied, kept before they are planned, so a choice the person
// makes holds for the network from then on, the tun up or not. Refuses where the kept choices do not read, unless change
// makes both anew, and where a change does not keep, so the tun never plans on a choice the daemon would forget, or
// guesses one: a person who turned route local traffic off is not quietly given it back. Under operationLock.
func (self *urBridgeDaemon) choicesWithLock(network *urBridgeNetwork, change *urTunChoiceChange) (urTunChoices, error) {
	record, err := network.choices.Load()
	if err != nil {
		if change == nil || change.DefaultEgress == nil || change.RouteLocal == nil {
			return urTunChoices{}, fmt.Errorf("the network's choices for default traffic do not read (%v): ur tun "+
				"--default-egress=on|off --route-local=on|off makes both anew", err)
		}
		record = nil
	}
	if record == nil {
		record = &urTunChoiceRecord{}
	}
	if change.empty() {
		return record.choices(self.settings), nil
	}
	if change.DefaultEgress != nil && !*change.DefaultEgress && urTunDefaultEgressRequired(network.bridge.Status()) {
		return urTunChoices{}, fmt.Errorf("network %s: %w", network.networkId, errUrTunDefaultEgressRequired)
	}
	next := *record
	next.Version = urTunChoicesRecordVersion
	if change.DefaultEgress != nil {
		defaultEgress := *change.DefaultEgress
		next.DefaultEgress = &defaultEgress
	}
	if change.RouteLocal != nil {
		routeLocal := *change.RouteLocal
		next.RouteLocal = &routeLocal
	}
	if err := network.choices.Save(&next); err != nil {
		return urTunChoices{}, fmt.Errorf("the network's choices for default traffic were not kept, and stay as they "+
			"were (%v)", err)
	}
	return next.choices(self.settings), nil
}
