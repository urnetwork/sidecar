//go:build !ios_extension && !sidecar_http && !js

// The device's budgets as a search spends them, on the legs that run the budget ledger (DESIGN-COMPUTE §16.4, §21.9;
// SRCH-M13-02; budget_ledger.go): a search's price held against the budgets a call from this sidecar naming its agent
// spends, settled where its payment may have settled and released where nothing was paid. The js leg runs no ledger,
// and websearch_budget_js.go refuses every hold there.

package sidecar

import (
	"context"
	"errors"
)

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
