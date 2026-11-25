//go:build !ios_extension && !sidecar_http

// The model failure choice (DESIGN-COMPUTE §7.4's Model failure row, §6.6, §9.10, §16.3): the error names the model
// and its code, and the Harness asks the person a select of what to do: retry, another model, or local; for
// insufficient_quota where the balance ran out, add credit to a person who may buy (BAL's purchase rights), else the
// question names who may; where the agent's budget ran out, raise the budget, which files compute_budget_raise (kind
// 21) for the person to approve. Every pick of a model passes the router's checks at its call (SetModel), and nothing
// switches a model on its own (R-INFER-3). A run no person watches cannot ask: it stops, its stop reason the error.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// The choice's options, as the select offers them.
const (
	HarnessFailureRetry        = "retry"
	HarnessFailureAnotherModel = "another model"
	HarnessFailureLocal        = "local"
	HarnessFailureAddCredit    = "add credit"
	HarnessFailureRaiseBudget  = "raise the budget"
)

// Asks the person what to do about failure: true to call again, on whatever model they picked; else the run's end.
func (self *harnessAgent) failureChoice(ctx context.Context, failure *InferError) (bool, *harnessRunEnd) {
	stop := &harnessRunEnd{stopReason: HarnessStopError, errorMessage: failure.Error()}
	if !self.harness.ui.Attached(self.run.Id()) {
		return false, stop
	}
	options := []string{HarnessFailureRetry, HarnessFailureAnotherModel, HarnessFailureLocal}
	message := failure.Message
	if failure.Code == InferErrorInsufficientQuota {
		switch failure.Reason {
		case InferQuotaReasonBalance:
			if self.harness.purchases != nil {
				mayBuy, who, err := self.harness.purchases.MayBuy(ctx)
				switch {
				case err == nil && mayBuy:
					options = append(options, HarnessFailureAddCredit)
				case err == nil && who != "":
					message += fmt.Sprintf(" %s may add credit.", who)
				}
			}
		case InferQuotaReasonBudget:
			if self.harness.budgetRaiser != nil && self.spec.Budget != nil {
				options = append(options, HarnessFailureRaiseBudget)
			}
		}
	}
	for {
		response, err := self.harness.ui.Ask(ctx, self.run.Id(), self.id, &HarnessUiRequest{
			Method:  HarnessUiSelect,
			Title:   fmt.Sprintf("%s failed: %s", failure.Model, failure.Code),
			Message: message,
			Options: options,
		})
		if err != nil {
			if ctx.Err() != nil {
				return false, self.aborted()
			}
			return false, stop
		}
		if response.Cancelled || response.Value == nil {
			return false, stop
		}
		switch *response.Value {
		case HarnessFailureRetry:
			return true, nil
		case HarnessFailureAnotherModel:
			picked, end := self.pickModel(ctx, failure)
			if end != nil {
				return false, end
			}
			if picked {
				return true, nil
			}
		case HarnessFailureLocal:
			if err := self.pickLocal(ctx); err == nil {
				return true, nil
			}
		case HarnessFailureAddCredit:
			// the app's purchase sheet takes it from here; the choice stands until the person retries
		case HarnessFailureRaiseBudget:
			if err := self.raiseBudget(ctx, failure); err == nil {
				return true, nil
			} else if ctx.Err() != nil {
				return false, self.aborted()
			} else if errors.Is(err, ErrHarnessApprovalRefused) {
				return false, stop
			}
		default:
			return false, stop
		}
	}
}

// Asks which other model, among those the catalog lists available, and takes it at the next call: true where one
// was picked.
func (self *harnessAgent) pickModel(ctx context.Context, failure *InferError) (bool, *harnessRunEnd) {
	catalog, err := self.harness.router.Catalog(ctx)
	if err != nil {
		return false, nil
	}
	names := []string{}
	for _, entry := range catalog.Entries() {
		if entry.Unavailable != "" || entry.Kind == InferCatalogKindSearch || len(entry.Efforts) == 0 {
			continue
		}
		name := entry.Name(entry.DefaultEffort)
		if name != "" && name != failure.Model {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	if len(names) == 0 {
		return false, nil
	}
	response, err := self.harness.ui.Ask(ctx, self.run.Id(), self.id, &HarnessUiRequest{Method: HarnessUiSelect,
		Title: "Another model", Options: names})
	if err != nil || response.Cancelled || response.Value == nil {
		if ctx.Err() != nil {
			return false, self.aborted()
		}
		return false, nil
	}
	return self.setModel(*response.Value, HarnessModelChangedByFailureChoice) == nil, nil
}

// Takes the catalog's recommended local model at the next call.
func (self *harnessAgent) pickLocal(ctx context.Context) error {
	catalog, err := self.harness.router.Catalog(ctx)
	if err != nil {
		return err
	}
	name, entry := catalog.Recommended()
	if entry == nil {
		return errors.New("no local model is recommended for this device")
	}
	return self.setModel(name, HarnessModelChangedByFailureChoice)
}

// Files compute_budget_raise (kind 21) for the person through the run's gate and waits for its decision.
func (self *harnessAgent) raiseBudget(ctx context.Context, failure *InferError) error {
	request, err := self.harness.budgetRaiser.BudgetRaise(ctx, &HarnessBudgetRaise{RunId: self.run.Id(), AgentId: self.id,
		Budget: self.spec.Budget, Period: failure.Period})
	if err != nil {
		return err
	}
	if request.Kind != SidecarActionComputeBudgetRaise {
		return fmt.Errorf("%w: a budget raise of kind %d", ErrSidecarActionInvalid, request.Kind)
	}
	_, err = self.run.Authorize(ctx, request)
	return err
}
