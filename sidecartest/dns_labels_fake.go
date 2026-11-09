// A fake of sidecar.NetworkLabelResolver (DNS-M2-01), the seam CORE-M3-05, EVS1-M2-33, EVS1-M2-38,
// ACL-M2-05 and SOCK-M5-12 resolve <net> through. It is the client's own NetworkLabelTable over a
// store in memory, so a fake answers by the rules a device does: label, then alias, then a retiring
// alias, then the legacy name only for interactive input. It records each call, so a test can show a
// caller passing interactive as false for `.ur` and git remotes.
//
// Safe for concurrent use.

package sidecartest

import (
	"sync"

	"github.com/urnetwork/sidecar"
)

// One ResolveNetworkLabel call.
type FakeNetworkLabelCall struct {
	Root        string
	Text        string
	Interactive bool
}

// The networks a test's client belongs to.
type FakeNetworkLabels struct {
	table *sidecar.NetworkLabelTable

	stateLock sync.Mutex
	calls     []FakeNetworkLabelCall
}

// A client that belongs to no network yet.
func NewFakeNetworkLabels() *FakeNetworkLabels {
	table, err := sidecar.OpenNetworkLabelTable(NewFakeStore().Root())
	if err != nil {
		// an empty store in memory always opens
		panic(err)
	}
	return &FakeNetworkLabels{table: table}
}

// Adds a network, or replaces its row, as a refresh from api would. A row the table refuses, such as
// one whose label another network holds, answers its error.
func (self *FakeNetworkLabels) Set(row sidecar.NetworkLabelRow) error {
	return self.table.SetNetwork(row)
}

// Takes a network away, as leaving it does.
func (self *FakeNetworkLabels) Remove(networkId sidecar.Id) error {
	return self.table.RemoveNetwork(networkId)
}

// Every call so far, in order.
func (self *FakeNetworkLabels) Calls() []FakeNetworkLabelCall {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]FakeNetworkLabelCall{}, self.calls...)
}

// See sidecar.NetworkLabelResolver.
func (self *FakeNetworkLabels) ResolveNetworkLabel(root string, text string, interactive bool) (sidecar.Id, sidecar.NetworkLabelKind, error) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.calls = append(self.calls, FakeNetworkLabelCall{Root: root, Text: text, Interactive: interactive})
	}()
	return self.table.ResolveNetworkLabel(root, text, interactive)
}

var _ sidecar.NetworkLabelResolver = (*FakeNetworkLabels)(nil)
