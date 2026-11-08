package sidecartest

import (
	"os"
	"slices"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
)

// testdata/gates/table.yml, which server's reader answers too (server/sidecar_gates_test.go).
type gateTable struct {
	Buckets map[string]int  `yaml:"buckets"`
	Cases   []gateTableCase `yaml:"cases"`
}

type gateTableCase struct {
	Name   string          `yaml:"name"`
	File   string          `yaml:"file"`
	Broken bool            `yaml:"broken"`
	Expect gateTableExpect `yaml:"expect"`
}

type gateTableService struct {
	Enabled bool     `yaml:"enabled"`
	Writes  bool     `yaml:"writes"`
	Percent int      `yaml:"percent"`
	Admits  []string `yaml:"admits"`
	Refuses []string `yaml:"refuses"`
}

type gateTableExpect struct {
	Services map[string]gateTableService `yaml:"services"`
	Format2  *struct {
		Admits  []string `yaml:"admits"`
		Refuses []string `yaml:"refuses"`
		Purge   string   `yaml:"purge"`
		Drop    string   `yaml:"drop"`
	} `yaml:"format2"`
	Switches          map[string]bool `yaml:"switches"`
	PlaceNew          string          `yaml:"place_new"`
	Reseed            bool            `yaml:"reseed"`
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
	NoFileClusters []string            `yaml:"no_file_clusters"`
	GatesFor       map[string][]string `yaml:"gates_for"`
}

func readGateTable(t *testing.T) *gateTable {
	t.Helper()
	data, err := os.ReadFile("../testdata/gates/table.yml")
	if err != nil {
		t.Fatal(err)
	}
	table := &gateTable{}
	if err := yaml.Unmarshal(data, table); err != nil {
		t.Fatal(err)
	}
	if len(table.Cases) == 0 || len(table.Buckets) == 0 {
		t.Fatal("the gate table holds nothing")
	}
	return table
}

func mustId(t *testing.T, idStr string) connect.Id {
	t.Helper()
	id, err := connect.ParseId(idStr)
	if err != nil {
		t.Fatalf("%q: %s", idStr, err)
	}
	return id
}

// Holds gates to one case of the table: what it names, and every other gate closed.
func requireGateTableCase(t *testing.T, table *gateTable, c gateTableCase, gates sidecar.ServiceGates) {
	t.Helper()
	bucketIds := []connect.Id{}
	for idStr := range table.Buckets {
		bucketIds = append(bucketIds, mustId(t, idStr))
	}
	for _, service := range []string{
		sidecar.ServiceGateEvs, sidecar.ServiceGateGkm, sidecar.ServiceGateSockets, sidecar.ServiceGateTlsedge,
		sidecar.ServiceGateMxedge, sidecar.ServiceGateSmtpedge, sidecar.ServiceGateDns, "storage",
	} {
		gate := gates.Service(service)
		want, ok := c.Expect.Services[service]
		if !ok {
			if gate.Enabled() || gate.Writes() {
				t.Errorf("%s: %s is open", c.Name, service)
			}
			for _, networkId := range bucketIds {
				if gate.Admits(networkId) {
					t.Errorf("%s: closed %s admits %s", c.Name, service, networkId)
				}
			}
			continue
		}
		if gate.Enabled() != want.Enabled || gate.Writes() != want.Writes || gate.Percent() != want.Percent {
			t.Errorf("%s: %s enabled %t writes %t percent %d, want %+v", c.Name, service, gate.Enabled(), gate.Writes(), gate.Percent(), want)
		}
		for _, idStr := range want.Admits {
			if !gate.Admits(mustId(t, idStr)) {
				t.Errorf("%s: %s refuses %s", c.Name, service, idStr)
			}
		}
		for _, idStr := range want.Refuses {
			if gate.Admits(mustId(t, idStr)) {
				t.Errorf("%s: %s admits %s", c.Name, service, idStr)
			}
		}
	}

	format2 := gates.Format2()
	if c.Expect.Format2 == nil {
		for _, networkId := range bucketIds {
			if format2.Admits(networkId) {
				t.Errorf("%s: closed format2 admits %s", c.Name, networkId)
			}
		}
		if format2.Purge() != sidecar.Format2Observe || format2.Drop() != sidecar.Format2Observe {
			t.Errorf("%s: closed format2 deletes", c.Name)
		}
	} else {
		for _, idStr := range c.Expect.Format2.Admits {
			if !format2.Admits(mustId(t, idStr)) {
				t.Errorf("%s: format2 refuses %s", c.Name, idStr)
			}
		}
		for _, idStr := range c.Expect.Format2.Refuses {
			if format2.Admits(mustId(t, idStr)) {
				t.Errorf("%s: format2 admits %s", c.Name, idStr)
			}
		}
		if string(format2.Purge()) != c.Expect.Format2.Purge || string(format2.Drop()) != c.Expect.Format2.Drop {
			t.Errorf("%s: format2 purge %s drop %s, want %s and %s", c.Name, format2.Purge(), format2.Drop(), c.Expect.Format2.Purge, c.Expect.Format2.Drop)
		}
	}

	for _, name := range []string{sidecar.GateSwitchPush, sidecar.GateSwitchWake, sidecar.GateSwitchBridge, sidecar.GateSwitchEscrowDrawOrder, "other"} {
		if gates.Switch(name) != c.Expect.Switches[name] {
			t.Errorf("%s: switch %s is %t", c.Name, name, gates.Switch(name))
		}
	}
	if gates.PlaceNew() != c.Expect.PlaceNew {
		t.Errorf("%s: place_new %q, want %q", c.Name, gates.PlaceNew(), c.Expect.PlaceNew)
	}
	if gates.Reseed() != c.Expect.Reseed {
		t.Errorf("%s: reseed %t", c.Name, gates.Reseed())
	}
	if drained := gates.Drained(); !slices.Equal(drained, c.Expect.Drained) && (len(drained) != 0 || len(c.Expect.Drained) != 0) {
		t.Errorf("%s: drained %q, want %q", c.Name, drained, c.Expect.Drained)
	}
	rate, burst, ok := gates.SocketsControlQps()
	if want := c.Expect.SocketsControlQps; want == nil {
		if ok {
			t.Errorf("%s: sockets_control_qps set to %v and %d", c.Name, rate, burst)
		}
	} else if !ok || rate != want.Rate || burst != want.Burst {
		t.Errorf("%s: sockets_control_qps %v %d %t, want %+v", c.Name, rate, burst, ok, *want)
	}
	edge, ok := gates.UrnetworkEdge()
	if c.Expect.UrnetworkEdge == "" {
		if ok {
			t.Errorf("%s: urnetwork_edge set to %s", c.Name, edge)
		}
	} else if !ok || edge != mustId(t, c.Expect.UrnetworkEdge) {
		t.Errorf("%s: urnetwork_edge %s %t, want %s", c.Name, edge, ok, c.Expect.UrnetworkEdge)
	}
	for clusterId, want := range c.Expect.FileClusters {
		got := gates.FileCluster(clusterId)
		if got.SettlePassedBuild != want.SettlePassedBuild || got.HddCapacityOps != want.HddCapacityOps {
			t.Errorf("%s: cluster %s %+v, want %+v", c.Name, clusterId, got, want)
		}
	}
	for _, clusterId := range c.Expect.NoFileClusters {
		if got := gates.FileCluster(clusterId); got != (sidecar.FileClusterGate{}) {
			t.Errorf("%s: cluster %s has passed %+v", c.Name, clusterId, got)
		}
	}
}

// The fake answers every case of the table server's reader answers, and refuses what that reader
// cannot read, keeping what it held.
func TestFakeServiceGatesAnswersTheGateTable(t *testing.T) {
	table := readGateTable(t)
	for _, c := range table.Cases {
		gates := NewFakeServiceGates(nil)
		err := gates.Set(c.File)
		if c.Broken {
			if err == nil {
				t.Errorf("%s: Set took a file the reader cannot read", c.Name)
			}
			requireGateTableCase(t, table, gateTableCase{Name: c.Name}, gates)
			continue
		}
		if err != nil {
			t.Errorf("%s: %s", c.Name, err)
			continue
		}
		requireGateTableCase(t, table, c, gates)
	}
}

// A refused Set keeps the last good text, as a reader keeps its last good read.
func TestFakeServiceGatesKeepsItsLastGoodText(t *testing.T) {
	gates := NewFakeServiceGates(nil)
	networkId := connect.NewId()
	if err := gates.Set("sidecar:\n  evs: {enabled: true, networks: [" + networkId.String() + "]}\n"); err != nil {
		t.Fatal(err)
	}
	if err := gates.Set("sidecar: [unterminated\n"); err == nil {
		t.Fatal("a broken file was taken")
	}
	if !gates.Service(sidecar.ServiceGateEvs).Admits(networkId) {
		t.Fatal("a refused Set dropped the last good text")
	}
}

func TestFakeServiceGatesStartsClosed(t *testing.T) {
	gates := NewFakeServiceGates(nil)
	networkId := connect.NewId()
	for _, service := range []string{sidecar.ServiceGateEvs, sidecar.ServiceGateDns} {
		if gates.Service(service).Admits(networkId) || gates.Service(service).Writes() {
			t.Errorf("%s is open before any Set", service)
		}
	}
	if gates.RetryAfter() != 60*time.Second {
		t.Errorf("retry after %s", gates.RetryAfter())
	}
}

func TestFakeServiceGatesOpensOneService(t *testing.T) {
	gates := NewFakeServiceGates(nil)
	networkId := connect.NewId()
	gates.OpenService(sidecar.ServiceGateGkm, networkId)
	if !gates.Service(sidecar.ServiceGateGkm).Admits(networkId) || !gates.Service(sidecar.ServiceGateGkm).Writes() {
		t.Fatal("the opened service refuses its network")
	}
	if gates.Service(sidecar.ServiceGateEvs).Admits(networkId) {
		t.Fatal("opening gkm opened evs")
	}
}
