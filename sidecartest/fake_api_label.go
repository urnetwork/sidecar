// GET /sidecar/label on the fake api (§12.5's label row; plan-DNS-labels-before-m5, QD-021; QD-935), the copy of
// server/controller/sidecar_label_controller.go: the bearer's own network's label, allocated on first need, its live
// alias and its retiring aliases, as sidecar.SidecarLabel, the body SidecarApi.GetSidecarLabel reads. The network is
// the token's: the route reads no parameter and no body, so no request names another network. So a world's sidecars,
// whose label refresh files the answer in their network's table under their user root at each client generation
// (dns_label_refresh.go), resolve `.ur` and git remotes by the names the Net's api gives, as by server's.
//
//	label      what a test set (SetNetworkLabel), else drawn at the network's first read by sidecar.NewDnsLabel, as
//	           model.EnsureNetworkLabelInTx draws it, a name another network holds drawn again, at most LabelDrawCount
//	           draws before the read answers 503; two first reads at once allocate one label, and it never changes
//	           (owner decision 14)
//	names      one namespace, as dns_label's (root, label) key is in api's one root: a label, a live alias or a
//	           retiring alias holds its name against every other network's names
//	refusals   401 to a bearer the api does not know, as at every Client route; 403 to a forwarding client's token, as
//	           route_authz refuses one off its shorter allowlist, which this route is not on (§7.4's mark row, owner
//	           decision 197); 503 while labels are unavailable (SetNetworkLabelsUnavailable), as api answers while it
//	           links no MG2, has no root or its root restores, in plain text as server's router writes a declared
//	           status, so a client reads again later
//
// The answer names no root, as server's names none: each sidecar files it under its own. Safe for concurrent use.

package sidecartest

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/urnetwork/sidecar"
)

// The route as RouteCount names it.
const fakeApiLabelRoute = "GET /sidecar/label"

// What a read answers once LabelDrawCount draws were each refused or held by another network.
var errFakeApiLabelDrawsSpent = errors.New("no label could be drawn")

// A network's names at the fake api, what api's dns_label rows hold of it.
type FakeApiNetworkLabel struct {
	// The label, which api allocates on the first read that needs one and never changes (owner decision 14).
	Label string
	// The live alias, empty while the network has none.
	Alias string
	// The aliases the network changed or released, in their 90 days of retiring, each with when it tombstones; a
	// zero time is an api that names none.
	RetiringAliases []sidecar.NetworkLabelRetiringAlias
}

// A copy, nil for nil, sharing nothing with this one.
func (self *FakeApiNetworkLabel) clone() *FakeApiNetworkLabel {
	if self == nil {
		return nil
	}
	return &FakeApiNetworkLabel{Label: self.Label, Alias: self.Alias, RetiringAliases: slices.Clone(self.RetiringAliases)}
}

// Every name the network holds: its label, its live alias and its retiring aliases.
func (self *FakeApiNetworkLabel) names() []string {
	names := []string{self.Label}
	if self.Alias != "" {
		names = append(names, self.Alias)
	}
	for _, retiring := range self.RetiringAliases {
		names = append(names, retiring.Alias)
	}
	return names
}

// The route's state, under the api's stateLock.
type fakeApiLabelState struct {
	// each network's names, set by a test or drawn at its first read
	networkLabels map[sidecar.Id]*FakeApiNetworkLabel
	// every read answers 503 while set
	unavailable bool
}

func newFakeApiLabelState() fakeApiLabelState {
	return fakeApiLabelState{networkLabels: map[sidecar.Id]*FakeApiNetworkLabel{}}
}

// The network other than networkId holding name, as a label, a live alias or a retiring alias, and whether there is
// one. Under stateLock.
func (self *fakeApiLabelState) holderWithLock(name string, networkId sidecar.Id) (sidecar.Id, bool) {
	for holderId, label := range self.networkLabels {
		if holderId != networkId && slices.Contains(label.names(), name) {
			return holderId, true
		}
	}
	return sidecar.Id{}, false
}

// The route, on the api's mux.
func (self *FakeApi) addLabelRoutes() {
	self.mux.HandleFunc(fakeApiLabelRoute, self.counted(fakeApiLabelRoute, self.handleLabel))
}

// Names networkId's label, its live alias and its retiring aliases from now on, as api's dns_label rows would hold
// them, so a test knows the names its network's sidecars file. Each name must be one api could hold
// (sidecar.ValidateDnsName), the network's names distinct and none another network's. A network's label never changes
// once it holds one, set or drawn (owner decision 14), so naming another label refuses; its aliases may change.
func (self *FakeApi) SetNetworkLabel(networkId sidecar.Id, label *FakeApiNetworkLabel) error {
	if networkId == (sidecar.Id{}) || label == nil || label.Label == "" {
		return errors.New("fake api: a network's names need its id and its label")
	}
	names := label.names()
	for index, name := range names {
		if err := sidecar.ValidateDnsName(name); err != nil {
			return fmt.Errorf("fake api: %q is no name api holds: %w", name, err)
		}
		if slices.Contains(names[:index], name) {
			return fmt.Errorf("fake api: the network holds %q twice", name)
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if held := self.labels.networkLabels[networkId]; held != nil && held.Label != label.Label {
		return fmt.Errorf("fake api: network %s's label is %q, which never changes", networkId, held.Label)
	}
	for _, name := range names {
		if holderId, held := self.labels.holderWithLock(name, networkId); held {
			return fmt.Errorf("fake api: network %s holds %q", holderId, name)
		}
	}
	self.labels.networkLabels[networkId] = label.clone()
	return nil
}

// What GET /sidecar/label answers networkId now, false while the network has no label, neither set nor drawn.
func (self *FakeApi) NetworkLabel(networkId sidecar.Id) (*FakeApiNetworkLabel, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	label := self.labels.networkLabels[networkId]
	return label.clone(), label != nil
}

// Answers every GET /sidecar/label 503 while unavailable is set, drawing nothing, as api answers while it links no MG2,
// has no root or its root restores.
func (self *FakeApi) SetNetworkLabelsUnavailable(unavailable bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.labels.unavailable = unavailable
}

// networkId's names, its label drawn on first need (the file's comment): errFakeApiLabelDrawsSpent past LabelDrawCount
// draws.
func (self *FakeApi) ensureNetworkLabel(networkId sidecar.Id) (*FakeApiNetworkLabel, error) {
	held := func() *FakeApiNetworkLabel {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.labels.networkLabels[networkId].clone()
	}()
	if held != nil {
		return held, nil
	}
	for range self.settings.LabelDrawCount {
		// drawn outside the lock, and taken under it only while the network holds none and no other holds the name
		drawnLabel, err := sidecar.NewDnsLabel(rand.Reader)
		if errors.Is(err, sidecar.ErrDnsLabelDrawRefused) {
			continue
		}
		if err != nil {
			return nil, err
		}
		label, taken := func() (*FakeApiNetworkLabel, bool) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if held := self.labels.networkLabels[networkId]; held != nil {
				// another first read, or a test, gave the network its label meanwhile, which stands
				return held.clone(), true
			}
			if _, held := self.labels.holderWithLock(drawnLabel, networkId); held {
				return nil, false
			}
			drawn := &FakeApiNetworkLabel{Label: drawnLabel}
			self.labels.networkLabels[networkId] = drawn
			return drawn.clone(), true
		}()
		if taken {
			return label, nil
		}
	}
	return nil, errFakeApiLabelDrawsSpent
}

// GET /sidecar/label (the file's comment).
func (self *FakeApi) handleLabel(writer http.ResponseWriter, request *http.Request) {
	client, _ := self.requireClient(writer, request)
	if client == nil {
		return
	}
	if client.forwardOnly {
		http.Error(writer, fakeApiStrictExpRefusedText, http.StatusForbidden)
		return
	}
	unavailable := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.labels.unavailable
	}()
	if unavailable {
		http.Error(writer, "unavailable: network labels are not available", http.StatusServiceUnavailable)
		return
	}
	label, err := self.ensureNetworkLabel(client.networkId)
	if err != nil {
		http.Error(writer, "unavailable: "+errFakeApiLabelDrawsSpent.Error(), http.StatusServiceUnavailable)
		return
	}
	fakeApiWriteJson(writer, http.StatusOK, &sidecar.SidecarLabel{
		NetworkId:       client.networkId,
		Label:           label.Label,
		Alias:           label.Alias,
		RetiringAliases: label.RetiringAliases,
	})
}
