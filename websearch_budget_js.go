//go:build js && !ios_extension && !sidecar_http

// The device's budgets as a search spends them on the js leg, which runs no budget ledger (budget_ledger.go is off it):
// every hold is refused, so no search leaves from this leg until ur.io's web search builds its own (SRCH-M13-13).

package sidecar

import (
	"context"
	"errors"
)

// What a hold answers on this leg.
var errWebSearchNoBudgetLedger = errors.New("web search: the device's budget ledger does not run on this leg")

// A Sidecar's budgets for search, which refuse every hold on this leg.
type webSearchSidecarBudget struct {
	sidecar *Sidecar
}

// See WebSearchBudget: refused, so nothing leaves.
func (self *webSearchSidecarBudget) Hold(ctx context.Context, holdId Id, agentId *Id, priceNanoUsd int64) error {
	return errWebSearchNoBudgetLedger
}

// See WebSearchBudget: no hold was taken.
func (self *webSearchSidecarBudget) Settle(holdId Id, priceNanoUsd int64) error {
	return errWebSearchNoBudgetLedger
}

// See WebSearchBudget: no hold was taken.
func (self *webSearchSidecarBudget) Release(holdId Id) error {
	return nil
}
