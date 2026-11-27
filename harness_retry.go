//go:build !ios_extension && !sidecar_http

// A call's recovery (DESIGN-COMPUTE §7.4's Retry and Model failure rows, R-INFER-3, §6.4, §6.6, §2.8): what the loop
// does when the router answers a call with an error, every wait on the Harness's clock, never a sleep.
//
//   - capacity and engine_failed, the router's codes for a provider at capacity and a transport or engine failure, are
//     retried HarnessSettings.RetryCount times from RetryBase, doubling, at the broker's time where it gives one,
//     always on the same model (R-INFER-3), with Pi's auto_retry_start and auto_retry_end.
//   - context_length compacts the context (compaction_start's reason overflow) and calls again, once.
//   - insufficient_quota with reason held waits for the broker's time and calls again, HeldRetryCount times, offering
//     nothing, then reports.
//   - disclosure_required: an attached run raises the disclosure request (§6.4's "the run the person is attached to
//     raises the request"), waits for the person's acknowledgment and calls again, a "Not now" taking it to the failure
//     choice; an unattached run stops, its stop reason naming the disclosure (§2.8).
//   - anything else, and a retry or a held wait that ran out, goes to the failure choice (harness_failure.go).

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Whether code is one a retry may cure: a provider at capacity, or a transport or engine failure.
func harnessRetryable(code InferErrorCode) bool {
	return code == InferErrorCapacity || code == InferErrorEngineFailed
}

// When retry attempt (1 for the first) goes, from now: RetryBase doubled per attempt on, or the broker's time where it
// gives a later one.
func (self *harnessAgent) retryTime(now time.Time, attempt int, failure *InferError) time.Time {
	retryTime := now
	if 0 < self.harness.settings.RetryBase {
		retryTime = now.Add(self.harness.settings.RetryBase << (attempt - 1))
	}
	if 0 < failure.RetryAtMs {
		retryTime = laterTime(retryTime, time.UnixMilli(failure.RetryAtMs))
	}
	return retryTime
}

// Waits on the Harness's clock until at, which a wait sets for that time itself (QD-1425), false where ctx ended
// first.
func (self *harnessAgent) waitUntil(ctx context.Context, at time.Time) bool {
	select {
	case <-ClockAfterAt(self.harness.clock, at):
		return true
	case <-ctx.Done():
		return false
	}
}

// Calls the model for one turn, recovering as the file header says. Answers the message, or the run's end.
func (self *harnessAgent) callWithRecovery(ctx context.Context) (*HarnessPiMessage, *harnessRunEnd) {
	retries := 0
	heldRetries := 0
	compacted := false
	for {
		if !self.foreground() {
			return nil, &harnessRunEnd{stopReason: HarnessStopBackgrounded}
		}
		message, failure, fatal := self.callOnce(ctx)
		if fatal != nil {
			if ctx.Err() != nil {
				return nil, self.aborted()
			}
			return nil, &harnessRunEnd{stopReason: HarnessStopError, errorMessage: fatal.Error()}
		}
		if failure == nil {
			if 0 < retries {
				self.emit(NewHarnessAutoRetryEndEvent(true, retries, ""))
			}
			return message, nil
		}
		if ctx.Err() != nil {
			return nil, self.aborted()
		}
		switch {
		case harnessRetryable(failure.Code) && retries < self.harness.settings.RetryCount:
			retries += 1
			now := self.harness.clock.Now()
			retryTime := self.retryTime(now, retries, failure)
			self.emit(NewHarnessAutoRetryStartEvent(retries, self.harness.settings.RetryCount, retryTime.Sub(now).Milliseconds(), failure.Error()))
			if !self.waitUntil(ctx, retryTime) {
				return nil, self.aborted()
			}
			continue
		case harnessRetryable(failure.Code) && 0 < retries:
			self.emit(NewHarnessAutoRetryEndEvent(false, retries, failure.Error()))
		case failure.Code == InferErrorContextLength && !compacted:
			compacted = true
			if err := self.compact(ctx, HarnessCompactionOverflow, ""); err == nil {
				continue
			} else if ctx.Err() != nil {
				return nil, self.aborted()
			}
		case failure.Code == InferErrorInsufficientQuota && failure.Reason == InferQuotaReasonHeld:
			if heldRetries < self.harness.settings.HeldRetryCount {
				heldRetries += 1
				// the broker's time, none going again at once
				var retryTime time.Time
				if 0 < failure.RetryAtMs {
					retryTime = time.UnixMilli(failure.RetryAtMs)
				}
				if !self.waitUntil(ctx, retryTime) {
					return nil, self.aborted()
				}
				continue
			}
			// held past its retries: reported, nothing offered
			return nil, &harnessRunEnd{stopReason: HarnessStopError, errorMessage: failure.Error()}
		case failure.Code == InferErrorDisclosureRequired && failure.Reason != InferDisclosureReasonDeclined:
			acknowledged, end := self.askDisclosure(ctx, failure)
			if end != nil {
				return nil, end
			}
			if acknowledged {
				continue
			}
			failure = &InferError{Code: InferErrorDisclosureRequired, Reason: InferDisclosureReasonDeclined, Model: failure.Model,
				Message: "the person declined the disclosure for now", DisclosureId: failure.DisclosureId,
				DisclosureVersion: failure.DisclosureVersion}
		}
		again, end := self.failureChoice(ctx, failure)
		if end != nil {
			return nil, end
		}
		if again {
			retries = 0
			heldRetries = 0
			compacted = false
			continue
		}
	}
}

// Raises the disclosure the router named in an attached run and waits for the person's acknowledgment: true once it
// landed, false at "Not now"; the run's end where no person is attached, naming the disclosure (§2.8).
func (self *harnessAgent) askDisclosure(ctx context.Context, failure *InferError) (bool, *harnessRunEnd) {
	if !self.harness.ui.Attached(self.run.Id()) {
		return false, &harnessRunEnd{stopReason: HarnessStopDisclosureRequired,
			errorMessage: fmt.Sprintf("disclosure %s version %d is not acknowledged", failure.DisclosureId, failure.DisclosureVersion)}
	}
	_, err := self.harness.ui.Ask(ctx, self.run.Id(), self.id, &HarnessUiRequest{Method: HarnessUiDisclosure,
		DisclosureId: failure.DisclosureId, DisclosureVersion: failure.DisclosureVersion})
	switch {
	case err == nil:
		return true, nil
	case ctx.Err() != nil:
		return false, self.aborted()
	case InferErrorCodeOf(err) == InferErrorDisclosureRequired:
		required := &InferError{}
		if errors.As(err, &required) && required.Reason == InferDisclosureReasonDeclined {
			return false, nil
		}
		return false, &harnessRunEnd{stopReason: HarnessStopDisclosureRequired,
			errorMessage: fmt.Sprintf("disclosure %s version %d is not acknowledged", failure.DisclosureId, failure.DisclosureVersion)}
	}
	return false, &harnessRunEnd{stopReason: HarnessStopError, errorMessage: err.Error()}
}
