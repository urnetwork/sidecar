// ServiceHost.Gates in memory (host_gates.go): a test sets the text of config/<env>/sidecar.yml, as
// an operator would, and this answers what server's reader would answer for that text. Both answer
// testdata/gates/table.yml, so the fake cannot drift from the real reader without a test failing.
// It starts with every gate closed, as an absent file is. Set refuses text the real reader could not
// read, and keeps what it held, as a process does after a good read.
//
// A test's shorthands edit one service's gate as an edit of the file would: OpenService writes its
// list anew, so a service opened to some networks is closed to every other it listed, and
// AddServiceNetworks adds to the list, so a world that opens its networks one at a time keeps each
// open. Each read keeps the networks every gate lists, as the file spells them, for the next add.

package sidecartest

import (
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
)

type FakeServiceGatesSettings struct {
	// What RetryAfter answers: §19.11's reread interval.
	RetryAfter time.Duration
}

func DefaultFakeServiceGatesSettings() *FakeServiceGatesSettings {
	return &FakeServiceGatesSettings{
		RetryAfter: 60 * time.Second,
	}
}

// One gate as the file spells it: writes is a pointer, since it defaults true inside a present gate.
type fakeGateYaml struct {
	Enabled  bool     `yaml:"enabled"`
	Writes   *bool    `yaml:"writes"`
	Networks []string `yaml:"networks"`
	Percent  int      `yaml:"percent"`
	Purge    string   `yaml:"purge"`
	Drop     string   `yaml:"drop"`
}

type fakeSwitchYaml struct {
	Enabled bool `yaml:"enabled"`
}

// The keys of §19.11's file the gates read. preview_networks and restore_hold are server's own and
// are not read here.
type fakeSidecarYaml struct {
	Sidecar struct {
		Evs               *fakeGateYaml   `yaml:"evs"`
		Format2           *fakeGateYaml   `yaml:"format2"`
		Gkm               *fakeGateYaml   `yaml:"gkm"`
		Sockets           *fakeGateYaml   `yaml:"sockets"`
		Tlsedge           *fakeGateYaml   `yaml:"tlsedge"`
		Mxedge            *fakeGateYaml   `yaml:"mxedge"`
		Smtpedge          *fakeGateYaml   `yaml:"smtpedge"`
		Dns               *fakeGateYaml   `yaml:"dns"`
		Compute           *fakeGateYaml   `yaml:"compute"`
		Push              *fakeSwitchYaml `yaml:"push"`
		Wake              *fakeSwitchYaml `yaml:"wake"`
		Bridge            *fakeSwitchYaml `yaml:"bridge"`
		EscrowDrawOrder   *fakeSwitchYaml `yaml:"escrow_draw_order"`
		Reseed            bool            `yaml:"reseed"`
		PlaceNew          string          `yaml:"place_new"`
		Drained           []string        `yaml:"drained"`
		SocketsControlQps *struct {
			Rate  float64 `yaml:"rate"`
			Burst int     `yaml:"burst"`
		} `yaml:"sockets_control_qps"`
		UrnetworkEdge string `yaml:"urnetwork_edge"`
		FileClusters  map[string]struct {
			SettlePassedBuild string `yaml:"settle_passed_build"`
			HddCapacityOps    int64  `yaml:"hdd_capacity_ops"`
		} `yaml:"file_clusters"`
	} `yaml:"sidecar"`
}

// What one Set answers. Immutable once built.
type fakeGatesRead struct {
	services map[string]sidecar.ServiceGate
	// each service's listed networks, as its gate names them, enabled or not: what an add keeps
	serviceNetworkIds map[string][]connect.Id
	format2           sidecar.Format2Gate
	switches          map[string]bool
	placeNew          string
	reseed            bool
	drained           []string
	socketsRate       float64
	socketsBurst      int
	socketsSet        bool
	urnetworkEdge     connect.Id
	urnetworkEdgeSet  bool
	fileClusters      map[string]sidecar.FileClusterGate
}

// The networks a gate's yaml lists, none for an absent gate: one bad id costs only its own entry.
func fakeServiceGateNetworkIds(gate *fakeGateYaml) []connect.Id {
	networkIds := []connect.Id{}
	if gate == nil {
		return networkIds
	}
	for _, networkIdStr := range gate.Networks {
		networkId, err := connect.ParseId(networkIdStr)
		if err != nil {
			continue
		}
		networkIds = append(networkIds, networkId)
	}
	return networkIds
}

// A gate from its yaml: absent is closed; one bad id costs only its own entry.
func fakeServiceGate(gate *fakeGateYaml) sidecar.ServiceGate {
	if gate == nil {
		return sidecar.ServiceGate{}
	}
	writes := gate.Writes == nil || *gate.Writes
	return sidecar.NewServiceGate(gate.Enabled, writes, fakeServiceGateNetworkIds(gate), gate.Percent)
}

// Reads the text of a sidecar.yml as server's reader does (server/sidecar_config.go).
func parseFakeGates(text string) (*fakeGatesRead, error) {
	y := &fakeSidecarYaml{}
	if err := yaml.Unmarshal([]byte(text), y); err != nil {
		return nil, err
	}
	serviceYamls := map[string]*fakeGateYaml{
		sidecar.ServiceGateEvs:      y.Sidecar.Evs,
		sidecar.ServiceGateGkm:      y.Sidecar.Gkm,
		sidecar.ServiceGateSockets:  y.Sidecar.Sockets,
		sidecar.ServiceGateTlsedge:  y.Sidecar.Tlsedge,
		sidecar.ServiceGateMxedge:   y.Sidecar.Mxedge,
		sidecar.ServiceGateSmtpedge: y.Sidecar.Smtpedge,
		sidecar.ServiceGateDns:      y.Sidecar.Dns,
		sidecar.ServiceGateCompute:  y.Sidecar.Compute,
	}
	read := &fakeGatesRead{
		services:          map[string]sidecar.ServiceGate{},
		serviceNetworkIds: map[string][]connect.Id{},
		switches: map[string]bool{
			sidecar.GateSwitchPush:            y.Sidecar.Push != nil && y.Sidecar.Push.Enabled,
			sidecar.GateSwitchWake:            y.Sidecar.Wake != nil && y.Sidecar.Wake.Enabled,
			sidecar.GateSwitchBridge:          y.Sidecar.Bridge != nil && y.Sidecar.Bridge.Enabled,
			sidecar.GateSwitchEscrowDrawOrder: y.Sidecar.EscrowDrawOrder != nil && y.Sidecar.EscrowDrawOrder.Enabled,
		},
		placeNew:     y.Sidecar.PlaceNew,
		reseed:       y.Sidecar.Reseed,
		fileClusters: map[string]sidecar.FileClusterGate{},
	}
	for service, gate := range serviceYamls {
		read.services[service] = fakeServiceGate(gate)
		read.serviceNetworkIds[service] = fakeServiceGateNetworkIds(gate)
	}
	if format2 := y.Sidecar.Format2; format2 != nil {
		read.format2 = sidecar.NewFormat2Gate(fakeServiceGate(format2), format2.Purge, format2.Drop)
	}
	for _, name := range y.Sidecar.Drained {
		if name != "" {
			read.drained = append(read.drained, name)
		}
	}
	if qps := y.Sidecar.SocketsControlQps; qps != nil && 0 < qps.Rate && 0 < qps.Burst {
		read.socketsRate, read.socketsBurst, read.socketsSet = qps.Rate, qps.Burst, true
	}
	if y.Sidecar.UrnetworkEdge != "" {
		if networkId, err := connect.ParseId(y.Sidecar.UrnetworkEdge); err == nil {
			read.urnetworkEdge, read.urnetworkEdgeSet = networkId, true
		}
	}
	for clusterId, cluster := range y.Sidecar.FileClusters {
		if cluster.SettlePassedBuild == "" && cluster.HddCapacityOps <= 0 {
			continue
		}
		read.fileClusters[clusterId] = sidecar.FileClusterGate{
			SettlePassedBuild: cluster.SettlePassedBuild,
			HddCapacityOps:    max(cluster.HddCapacityOps, 0),
		}
	}
	return read, nil
}

// Safe for concurrent use.
type FakeServiceGates struct {
	settings *FakeServiceGatesSettings

	stateLock sync.Mutex
	read      *fakeGatesRead
}

// Every gate closed, as an absent file is. A nil settings takes the defaults.
func NewFakeServiceGates(settings *FakeServiceGatesSettings) *FakeServiceGates {
	if settings == nil {
		settings = DefaultFakeServiceGatesSettings()
	}
	read, _ := parseFakeGates("")
	return &FakeServiceGates{settings: settings, read: read}
}

// Answers from now on what server's reader answers for text, the whole of a sidecar.yml. Text the
// reader could not read is refused and changes nothing.
func (self *FakeServiceGates) Set(text string) error {
	read, err := parseFakeGates(text)
	if err != nil {
		return fmt.Errorf("sidecar.yml: %w", err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.read = read
	return nil
}

// Opens one service to the networks given and to no other it listed, keeping every other service: a
// test's shorthand for a file whose gate lists them alone, writes on and no percent. So it replaces
// the gate's list, and opening with none darkens every network the gate listed. AddServiceNetworks
// keeps the list.
func (self *FakeServiceGates) OpenService(service string, networkIds ...connect.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	listed := slices.Clone(networkIds)
	self.read = self.read.withService(service, sidecar.NewServiceGate(true, true, listed, 0), listed)
}

// Opens one service to the networks given beside every network its gate lists, keeping everything
// else: a test's shorthand for adding them to the file's list, so a world opening a second network
// keeps the first open. An enabled gate keeps its writes switch and its percent. A gate the file
// leaves disabled or absent opens as OpenService opens one, writes on and no percent, listing what it
// listed and these.
func (self *FakeServiceGates) AddServiceNetworks(service string, networkIds ...connect.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	listed := slices.Clone(self.read.serviceNetworkIds[service])
	for _, networkId := range networkIds {
		if !slices.Contains(listed, networkId) {
			listed = append(listed, networkId)
		}
	}
	writes, percent := true, 0
	if gate := self.read.services[service]; gate.Enabled() {
		writes, percent = gate.Writes(), gate.Percent()
	}
	self.read = self.read.withService(service, sidecar.NewServiceGate(true, writes, listed, percent), listed)
}

// A read whose service has gate, listing networkIds, every other answer this read's. A read is never
// changed once built, so readers holding this one keep it whole.
func (self *fakeGatesRead) withService(service string, gate sidecar.ServiceGate, networkIds []connect.Id) *fakeGatesRead {
	next := *self
	next.services = maps.Clone(self.services)
	next.services[service] = gate
	next.serviceNetworkIds = maps.Clone(self.serviceNetworkIds)
	next.serviceNetworkIds[service] = networkIds
	return &next
}

func (self *FakeServiceGates) current() *fakeGatesRead {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.read
}

func (self *FakeServiceGates) Service(service string) sidecar.ServiceGate {
	return self.current().services[service]
}

func (self *FakeServiceGates) Format2() sidecar.Format2Gate {
	return self.current().format2
}

func (self *FakeServiceGates) Switch(name string) bool {
	return self.current().switches[name]
}

func (self *FakeServiceGates) PlaceNew() string {
	return self.current().placeNew
}

func (self *FakeServiceGates) Reseed() bool {
	return self.current().reseed
}

func (self *FakeServiceGates) Drained() []string {
	return append([]string(nil), self.current().drained...)
}

func (self *FakeServiceGates) SocketsControlQps() (float64, int, bool) {
	read := self.current()
	return read.socketsRate, read.socketsBurst, read.socketsSet
}

func (self *FakeServiceGates) UrnetworkEdge() (connect.Id, bool) {
	read := self.current()
	return read.urnetworkEdge, read.urnetworkEdgeSet
}

func (self *FakeServiceGates) FileCluster(clusterId string) sidecar.FileClusterGate {
	return self.current().fileClusters[clusterId]
}

func (self *FakeServiceGates) RetryAfter() time.Duration {
	return self.settings.RetryAfter
}
