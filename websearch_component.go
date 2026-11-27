//go:build !ios_extension && !sidecar_http

// Web search's component on a Sidecar (DESIGN-COMPUTE §21, §3.3; SRCH-M13-02): the x402 client over the Sidecar's
// seams, each read at use, and the daily report of outcomes on the Sidecar's lifetime.
//
//	policy    ATTEST's gate and newest policy, INFER's catalog (webSearchSidecarPolicy, websearch_policy.go)
//	broker    INFER's compute service client (webSearchComputeBroker, websearch_broker.go)
//	budget    the device's budget ledger, a search holding its price as a remote call holds its worst case
//	outcomes  the network's sealed store, websearch/outcomes.json, class websearch
//	egress    FETCH-M13-01's SidecarEgress on auto, which has not landed: until it does every search answers
//	          unavailable before a byte leaves, the closed side
//
// Until G-SRCH-parallel passes, the signed policy carries no search line, so even with every seam in place the client
// answers search_off and sends nothing.

package sidecar

import (
	"context"
	"errors"
	"io"
)

// The name web search registers its component under.
const webSearchComponentName = "websearch"

// What a search answers until FETCH-M13-01's egress lands: there is no way out for it but the device's own, which a
// search never takes (R-SRCH-4).
var ErrWebSearchNoEgress = errors.New("web search: no auto egress on this device yet (FETCH-M13-01)")

// Registers web search's component, which every Sidecar on a compute leg then constructs.
func init() {
	registerComputeComponent(webSearchComponentName, newWebSearchComponent, nil)
}

// Web search's parts on one Sidecar.
type webSearchComponent struct {
	client *WebSearchClient
}

// The client over sidecar's seams. Reads nothing of the network: each seam reads at use.
func newWebSearchComponent(sidecar *Sidecar) (*webSearchComponent, error) {
	settings := sidecar.settings.WebSearch
	if settings == nil {
		settings = DefaultWebSearchSettings()
	}
	outcomes, err := NewWebSearchOutcomeLog(&WebSearchOutcomeLogArgs{
		Store:    &webSearchSidecarStore{sidecar: sidecar},
		Settings: settings,
		Clock:    sidecar.clock,
	})
	if err != nil {
		return nil, err
	}
	client, err := NewWebSearchClient(&WebSearchClientArgs{
		Settings: settings,
		Policy:   &webSearchSidecarPolicy{sidecar: sidecar, settings: settings},
		Broker:   &webSearchComputeBroker{sidecar: sidecar},
		Dialer:   &webSearchEgressDialer{sidecar: sidecar},
		Budget:   &webSearchSidecarBudget{sidecar: sidecar},
		Outcomes: outcomes,
		Clock:    sidecar.clock,
		Log:      sidecar.log,
		Version:  sidecar.settings.AppVersion,
	})
	if err != nil {
		return nil, err
	}
	if sidecar.ctx != nil {
		go client.run(sidecar.ctx)
	}
	return &webSearchComponent{client: client}, nil
}

// This Sidecar's web search client, or an error wrapping ErrComputeComponentUnavailable that says why there is none.
func (self *Sidecar) WebSearchClient() (*WebSearchClient, error) {
	component, err := sidecarComputeComponent[webSearchComponent](self, webSearchComponentName)
	if err != nil {
		return nil, err
	}
	return component.client, nil
}

// The egress a search leaves through, FETCH-M13-01's: refused until it lands.
type webSearchEgressDialer struct {
	sidecar *Sidecar
}

// See WebSearchDialer.
func (self *webSearchEgressDialer) Session(ctx context.Context, args *WebSearchSessionArgs) (WebSearchSession, error) {
	return nil, ErrWebSearchNoEgress
}

// The device's budget ledger as a search spends it: the budgets a call from this sidecar naming the agent spends, the
// search's price held, settled or released as a remote call's worst case is (budget_ledger.go).
type webSearchSidecarBudget struct {
	sidecar *Sidecar
}

// See WebSearchBudget.
func (self *webSearchSidecarBudget) Hold(ctx context.Context, holdId Id, agentId *Id, priceNanoUsd int64) error {
	if priceNanoUsd < 0 {
		return errors.New("a negative price")
	}
	now := self.sidecar.clock.Now()
	call, err := self.sidecar.computeBudgetCall(agentId, now)
	if err != nil {
		return err
	}
	ledger, err := self.sidecar.BudgetLedger()
	if err != nil {
		return err
	}
	settings := self.sidecar.settings.Budget
	if settings == nil {
		settings = DefaultBudgetSettings()
	}
	return ledger.Hold(holdId, ComputeBudgetsFor(call, settings, now), uint64(priceNanoUsd))
}

// See WebSearchBudget.
func (self *webSearchSidecarBudget) Settle(holdId Id, priceNanoUsd int64) error {
	ledger, err := self.sidecar.BudgetLedger()
	if err != nil {
		return err
	}
	return ledger.Settle(holdId, uint64(max(priceNanoUsd, 0)))
}

// See WebSearchBudget.
func (self *webSearchSidecarBudget) Release(holdId Id) error {
	ledger, err := self.sidecar.BudgetLedger()
	if err != nil {
		return err
	}
	return ledger.Release(holdId)
}

// The Sidecar's web search directory, resolved at each call from the network it has enrolled in: before that, and
// while its keychain is locked, every call answers ErrSidecarStoreLocked.
type webSearchSidecarStore struct {
	sidecar *Sidecar
}

// The directory now.
func (self *webSearchSidecarStore) directory() (SidecarStore, error) {
	return self.sidecar.LocalStore().Directory(webSearchStoreDirectory, webSearchStoreClass)
}

// See SidecarStore.
func (self *webSearchSidecarStore) Open(name string) (io.ReadCloser, error) {
	directory, err := self.directory()
	if err != nil {
		return nil, err
	}
	return directory.Open(name)
}

// See SidecarStore.
func (self *webSearchSidecarStore) Create(name string) (SidecarStoreWriter, error) {
	directory, err := self.directory()
	if err != nil {
		return nil, err
	}
	return directory.Create(name)
}

// See SidecarStore.
func (self *webSearchSidecarStore) Remove(name string) error {
	directory, err := self.directory()
	if err != nil {
		return err
	}
	return directory.Remove(name)
}

// See SidecarStore.
func (self *webSearchSidecarStore) List(prefix string) ([]SidecarStoreEntry, error) {
	directory, err := self.directory()
	if err != nil {
		return nil, err
	}
	return directory.List(prefix)
}

// See SidecarStore.
func (self *webSearchSidecarStore) Directory(name string, class string) (SidecarStore, error) {
	directory, err := self.directory()
	if err != nil {
		return nil, err
	}
	return directory.Directory(name, class)
}
