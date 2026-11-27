// Disputes (DESIGN-COMPUTE §6.7, D-BAL-11, compute-8; BAL-M12-14): a device's charge_mismatch, which INFER's
// POST compute/v1/infer/dispute hands the ledger, and a person's decision on it.
//
//	ComputeDispute        the charge held for review in compute_dispute, once by its request id; at most the settings'
//	                      10 a network a UTC day, the rest refused dispute_limit; and the dispute metrics §14.7's
//	                      providers family pages from (disputes by provider, and the networks that disputed a
//	                      provider's calls today), so disputes from at least 3 networks past 0.5% of a provider's
//	                      requests in a UTC day page a person. Nothing here changes the catalog: a few modified clients
//	                      must not remove a provider
//	ComputeDecideDispute  a person's decision: rejected, or upheld and the charge refunded (ComputeRefundCharge), the
//	                      refund's claim keeping a decision repeated, or racing an operator's refund, to one refund; the
//	                      charge refunded only where it is the disputed request's, in the dispute's network
//
// A dispute names ids and usage counts alone; the metrics' labels are provider codes, a closed set, never a network.

package controller

import (
	"context"
	"fmt"
	"strconv"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/model"
)

// Why a dispute was refused, the code INFER's route answers.
type ComputeDisputeRefusal string

const (
	// The network made the settings' 10 disputes this UTC day.
	ComputeDisputeRefusalLimit ComputeDisputeRefusal = "dispute_limit"
)

// The dispute metrics §14.7's providers family reads (server/monitor's computeMetricDisputes and
// computeMetricDisputeNetworks).
const (
	computeDisputesMetric        = "urnetwork_compute_disputes_total"
	computeDisputeNetworksMetric = "urnetwork_compute_dispute_networks"
)

// One charge_mismatch.
type ComputeDisputeRequest struct {
	NetworkId operator.Id
	// The call's request id, the charge's subject.
	RequestId operator.Id
	Provider  int16
	// The device's own count and the provider's usage as charged.
	DeviceUnits   model.ComputeUnits
	ProviderUnits model.ComputeUnits
	// The charge it disputes, where the device names it.
	ChargeId *operator.Id
}

// What a dispute came to.
type ComputeDisputeAnswer struct {
	Refusal ComputeDisputeRefusal
	// The dispute as it stands: recorded now, or by the request's first delivery.
	Dispute  *model.ComputeDispute
	Recorded bool
	// The provider's disputes and the networks they came from this UTC day, its booked requests, and whether they are
	// past §14.7's page: at least the settings' 3 networks past 0.5% of its requests.
	ProviderDisputes int64
	ProviderNetworks int64
	ProviderRequests int64
	Paging           bool
}

// Records request (see the file header).
func ComputeDispute(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, request *ComputeDisputeRequest) (*ComputeDisputeAnswer, error) {
	var zero operator.Id
	if request.NetworkId == zero || request.RequestId == zero || request.Provider <= 0 || !request.DeviceUnits.Valid() || !request.ProviderUnits.Valid() {
		return nil, fmt.Errorf("%w: a dispute names its network, request, provider and two counts", ErrComputeRefundArgs)
	}
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	now := clock.Now()
	answer := &ComputeDisputeAnswer{}
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		*answer = ComputeDisputeAnswer{}
		// under the network's fence, so two disputes at once cannot both pass the day's limit
		if err := model.ComputeFenceInTx(env, ctx, tx, request.NetworkId); err != nil {
			return err
		}
		stands, err := model.ComputeDisputeGetInTx(env, ctx, tx, request.RequestId, false)
		if err != nil {
			return err
		}
		if stands == nil {
			count, err := model.ComputeDisputeNetworkCountInTx(env, ctx, tx, request.NetworkId, model.ComputeUtcDay(now))
			if err != nil {
				return err
			}
			if int64(settings.DisputeNetworkDayMaxCount) <= count {
				answer.Refusal = ComputeDisputeRefusalLimit
				return nil
			}
		}
		inserted, dispute, err := model.ComputeDisputeInsertInTx(env, ctx, tx, &model.ComputeDispute{
			RequestId: request.RequestId, NetworkId: request.NetworkId, Provider: request.Provider,
			DeviceUnits: request.DeviceUnits, ProviderUnits: request.ProviderUnits, ChargeId: request.ChargeId, CreateTime: now,
		})
		if err != nil {
			return err
		}
		answer.Dispute, answer.Recorded = dispute, inserted
		if answer.ProviderDisputes, answer.ProviderNetworks, err = model.ComputeDisputeProviderDayInTx(env, ctx, tx, request.Provider, now); err != nil {
			return err
		}
		answer.ProviderRequests, err = model.ComputeProviderRequestsDayInTx(env, ctx, tx, request.Provider, now)
		return err
	}, operator.DbIsolationReadCommitted)
	if err != nil {
		return nil, err
	}
	if answer.Refusal != "" {
		return answer, nil
	}
	// D-BAL-11's page: networks enough, and a share of the provider's requests past the settings' basis points
	answer.Paging = int64(settings.DisputePageNetworkCount) <= answer.ProviderNetworks &&
		answer.ProviderRequests*settings.DisputePageBasisPoints < answer.ProviderDisputes*10_000
	if metrics, err := env.Metrics(); err == nil {
		provider := strconv.Itoa(int(request.Provider))
		if answer.Recorded {
			metrics.Counter(computeDisputesMetric, "compute charge disputes, by provider", "provider").Add(1, provider)
		}
		metrics.Gauge(computeDisputeNetworksMetric, "networks that disputed a provider's calls this UTC day", "provider").Set(float64(answer.ProviderNetworks), provider)
	}
	return answer, nil
}

// What a decision came to.
type ComputeDecideAnswer struct {
	Dispute *model.ComputeDispute
	// Whether this call decided it; false for a repeat, which keeps the first decision.
	Decided bool
	// For an upheld dispute that names a charge, its refund.
	Refund *ComputeRefundChargeAnswer
}

// Decides requestId's dispute (see the file header): upheld refunds its charge, rejected closes it; a decision made
// before is kept, and an upheld one's refund asked again, which its claim makes one.
func ComputeDecideDispute(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, requestId operator.Id, upheld bool) (*ComputeDecideAnswer, error) {
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	state := model.ComputeDisputeStateRejected
	if upheld {
		state = model.ComputeDisputeStateUpheld
	}
	answer := &ComputeDecideAnswer{}
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		dispute, decided, err := model.ComputeDisputeDecideInTx(env, ctx, tx, requestId, state, clock.Now())
		answer.Dispute, answer.Decided = dispute, decided
		return err
	}, operator.DbIsolationReadCommitted)
	if err != nil {
		return nil, err
	}
	if answer.Dispute == nil {
		return nil, fmt.Errorf("%w: no dispute of the request", ErrComputeRefundArgs)
	}
	if answer.Dispute.State != model.ComputeDisputeStateUpheld || answer.Dispute.ChargeId == nil {
		return answer, nil
	}
	networkId, requestId := answer.Dispute.NetworkId, answer.Dispute.RequestId
	refund, err := ComputeRefundCharge(env, ctx, settings, &ComputeRefundChargeRequest{
		NetworkId: &networkId, ChargeId: *answer.Dispute.ChargeId, SubjectRef: &requestId,
	})
	if err != nil {
		return nil, err
	}
	answer.Refund = refund
	return answer, nil
}
