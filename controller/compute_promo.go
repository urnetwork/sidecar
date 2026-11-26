// Promotion codes (DESIGN-COMPUTE §9.11, §14.3, §14.5, D-BAL-12, CO-35; BAL-M12-13): URnetwork's own codes, apart
// from the stores' offer codes, which arrive as store purchases (§9.5).
//
//	ComputeCreatePromo  an operator's code (`sidecarctl compute promo create`): its campaign, its value (at most
//	                    $10), its cap on redemptions and its last UTC day, and whether a network must hold an
//	                    unreversed paid lot, which every code with a cap above one asks. A code is 8 to 32 letters and
//	                    digits, the operator's or drawn; one made for a single network is drawn, 16 characters of a
//	                    32-letter alphabet, 80 bits. Only a keyed hash of the code, its case folded, is kept, with who
//	                    made it and why; the code itself is answered once, to the operator, and never stored or logged.
//	ComputeRedeemPromo  POST api/compute/promo/redeem, for a person who may buy (§9.10, the frame's check): in one
//	                    transaction under the network's fence, the code known, before its last day and under its cap;
//	                    the network with no earlier redemption of it, none of any code in the last 30 days, a paid lot
//	                    where the code asks, no chargeback's suspension, and the value counted as a load with the
//	                    day's purchases against the daily load and the balance cap; then a promotional lot of market
//	                    promotion, market_ref the redemption's id, lapsing 30 days on, the redemption and the code's
//	                    count. A retry within the settings' window answers the redemption's lot, crediting nothing;
//	                    past it the code is code_redeemed. Five failed codes in a UTC day, unknown or ended, and the
//	                    network's attempts answer rate_limited until the next ({cmpk_<network_id>}).
//	ComputeLapsePromos  compute_promo_lapse, hourly: each promotional lot past its expiry keeps what is left as its
//	                    lapsed_nano_usd, and settled falls by as much, in one transaction a network under its fence and
//	                    through the drop script's version guard into the projection's settled and promo, never as a
//	                    charge.
//
// A promotional lot has no payer: it counts toward no payer's limits and no new-account limit, which bound cards, and
// raises none. It pays for remote inference and enclaves, drawn first (§9.4), and never for a search (§9.11).

package controller

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/model"
)

// A code, its case folded, hashes under this domain word: an identifier, so a hash never changes meaning.
const computePromoCodeDomain = "compute_promo_code"

// The alphabet a drawn code takes its characters from: 32 letters and digits, none mistaken for another (no 0, 1, I
// or O), so 16 of them hold 80 bits. A format's identifier.
const computePromoCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// Why a redemption was refused (§9.11), the code the route answers.
type ComputePromoRefusal string

const (
	ComputePromoRefusalCodeUnknown      ComputePromoRefusal = "code_unknown"
	ComputePromoRefusalCodeEnded        ComputePromoRefusal = "code_ended"
	ComputePromoRefusalCodeRedeemed     ComputePromoRefusal = "code_redeemed"
	ComputePromoRefusalRedeemedRecently ComputePromoRefusal = "redeemed_recently"
	ComputePromoRefusalPaidLotRequired  ComputePromoRefusal = "paid_lot_required"
	ComputePromoRefusalDailyLimit       ComputePromoRefusal = "daily_limit"
	ComputePromoRefusalBalanceCap       ComputePromoRefusal = "balance_cap"
	ComputePromoRefusalRateLimited      ComputePromoRefusal = "rate_limited"
	// A chargeback suspended the network's compute (§9.11's "no suspension for a chargeback"): the device's
	// compute_balance, the network's balance unable to pay while suspended (a reading the report names).
	ComputePromoRefusalSuspended ComputePromoRefusal = "compute_balance"
)

// Whether the refusal is a failed code, which the day's count of failures takes: an unknown code or an ended one. A
// network's own state refusing a good code is no failure.
func (self ComputePromoRefusal) failedCode() bool {
	return self == ComputePromoRefusalCodeUnknown || self == ComputePromoRefusalCodeEnded
}

var (
	// A code the ledger cannot take: a value past $10, a cap above one without the paid-lot rule, a code not of letters
	// and digits, a past last day, the operator's words missing.
	ErrComputePromoArgs = model.ErrComputePromoArgs
	// The network's failed codes today do not read: the redemption refuses rather than leave guessing uncounted.
	ErrComputePromoUnavailable = errors.New("compute promo: the day's failed codes do not read")
)

// The code folded for its hash: ASCII letters to lowercase. ok is false for a code that is not letters and digits
// within the settings' lengths, which no code is.
func computePromoCodeFold(settings *model.ComputeLedgerSettings, code string) (string, bool) {
	if len(code) < settings.PromoCodeMinCharacterCount || settings.PromoCodeMaxCharacterCount < len(code) {
		return "", false
	}
	folded := make([]byte, len(code))
	for i := 0; i < len(code); i += 1 {
		c := code[i]
		switch {
		case 'a' <= c && c <= 'z', '0' <= c && c <= '9':
			folded[i] = c
		case 'A' <= c && c <= 'Z':
			folded[i] = c + ('a' - 'A')
		default:
			return "", false
		}
	}
	return string(folded), true
}

// The keyed hash of a folded code under the host's promotion key.
func computePromoCodeHash(secrets ComputeLedgerSecrets, folded string) ([]byte, error) {
	key, err := computePromoKey(secrets)
	if err != nil {
		return nil, err
	}
	return computeKeyedHash(key, computePromoCodeDomain, folded), nil
}

// A code of count characters drawn from the alphabet: 5 bits a character from crypto/rand, which 256 divides evenly.
func computePromoCodeDraw(count int) (string, error) {
	draw := make([]byte, count)
	if _, err := rand.Read(draw); err != nil {
		return "", err
	}
	code := make([]byte, count)
	for i, b := range draw {
		code[i] = computePromoCodeAlphabet[int(b)%len(computePromoCodeAlphabet)]
	}
	return string(code), nil
}

// Whether text is an operator's words a code keeps: present, valid UTF-8, no control character, within bound.
func computePromoTextValid(text string, bound int) bool {
	if strings.TrimSpace(text) == "" || bound < len(text) || !utf8.ValidString(text) {
		return false
	}
	for _, r := range text {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// One code an operator makes.
type ComputePromoCreate struct {
	Campaign string
	// At most the settings' $10.
	AmountNanoUsd int64
	// How many networks may redeem it; above one asks for PaidLotRequired.
	RedeemMaxCount int64
	// The last UTC day it redeems: today or later.
	LastDay time.Time
	// A network must hold an unreversed paid lot to redeem it.
	PaidLotRequired bool
	// The operator's own code, 8 to 32 letters and digits; empty draws one of the settings' 16 characters.
	Code string
	// Made for a single network: drawn, never the operator's, and redeemed at most once.
	ForNetwork bool
	// Who made it and why: an operator's name and words about a campaign, never a person's content.
	CreatedBy string
	Reason    string
}

// A code made: its id and the code itself, answered this once and kept nowhere.
type ComputePromoCreated struct {
	CodeId operator.Id
	Code   string
}

// Makes request's code (see the file header). Unset secrets refuse it before anything is written.
func ComputeCreatePromo(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, secrets ComputeLedgerSecrets, request *ComputePromoCreate) (*ComputePromoCreated, error) {
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	now := clock.Now()
	switch {
	case !computePromoTextValid(request.Campaign, settings.PromoTextMaxByteCount) ||
		!computePromoTextValid(request.CreatedBy, settings.PromoTextMaxByteCount) ||
		!computePromoTextValid(request.Reason, settings.PromoTextMaxByteCount):
		return nil, fmt.Errorf("%w: a code names its campaign, its operator and why, each within %d bytes", ErrComputePromoArgs, settings.PromoTextMaxByteCount)
	case request.AmountNanoUsd <= 0 || settings.PromoMaxNanoUsd < request.AmountNanoUsd:
		return nil, fmt.Errorf("%w: a code's value is positive and at most %d nano-USD", ErrComputePromoArgs, settings.PromoMaxNanoUsd)
	case request.RedeemMaxCount <= 0:
		return nil, fmt.Errorf("%w: a code's cap is positive", ErrComputePromoArgs)
	case 1 < request.RedeemMaxCount && !request.PaidLotRequired:
		return nil, fmt.Errorf("%w: a code with a cap above one asks for an unreversed paid lot", ErrComputePromoArgs)
	case request.ForNetwork && (request.RedeemMaxCount != 1 || request.Code != ""):
		return nil, fmt.Errorf("%w: a code made for a single network is drawn and redeems once", ErrComputePromoArgs)
	case model.ComputeUtcDay(request.LastDay).Before(model.ComputeUtcDay(now)):
		return nil, fmt.Errorf("%w: a code's last day is today or later", ErrComputePromoArgs)
	}
	code := request.Code
	if code == "" {
		if code, err = computePromoCodeDraw(settings.PromoNetworkCodeCharacterCount); err != nil {
			return nil, err
		}
	}
	folded, ok := computePromoCodeFold(settings, code)
	if !ok {
		return nil, fmt.Errorf("%w: a code is %d to %d letters and digits", ErrComputePromoArgs, settings.PromoCodeMinCharacterCount, settings.PromoCodeMaxCharacterCount)
	}
	codeHash, err := computePromoCodeHash(secrets, folded)
	if err != nil {
		return nil, err
	}
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	row := &model.ComputePromoCode{
		CodeId:          sidecar.NewId(),
		CodeHash:        codeHash,
		Campaign:        request.Campaign,
		AmountNanoUsd:   request.AmountNanoUsd,
		RedeemMaxCount:  request.RedeemMaxCount,
		LastDay:         model.ComputeUtcDay(request.LastDay),
		PaidLotRequired: request.PaidLotRequired,
		CreatedBy:       request.CreatedBy,
		Reason:          request.Reason,
		CreateTime:      now.UTC(),
	}
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		return model.ComputePromoCodeInsertInTx(env, ctx, tx, row)
	}, operator.DbIsolationReadCommitted)
	if err != nil {
		return nil, err
	}
	return &ComputePromoCreated{CodeId: row.CodeId, Code: code}, nil
}

// One redemption.
type ComputeRedeemRequest struct {
	NetworkId operator.Id
	// The redeeming sidecar's opaque id; nil for the network's own credential, which the row keeps as the nil id.
	SidecarId *operator.Id
	Code      string
}

// What a redemption came to.
type ComputeRedeemAnswer struct {
	// The redemption's lot: credited now, or a retry's of the first redemption.
	Lot *model.ComputeLot
	// This call redeemed it; false for a retry, which credits nothing.
	Redeemed bool
	// Why not, where no lot is answered.
	Refusal ComputePromoRefusal
	// For rate_limited: until the next UTC midnight.
	RetryAfter time.Duration
	// The projection took the account.
	Projected bool
}

// §14.7's count of redemptions and refusals, by outcome: redeemed, retry or the refusal's code, a closed set, never a
// code or a network (I-13).
const computePromoRedemptionsMetric = "urnetwork_compute_promo_redemptions_total"

// The redemption outcomes the count takes beside the refusals.
const (
	computePromoOutcomeRedeemed = "redeemed"
	computePromoOutcomeRetry    = "retry"
)

// Counts one redemption's outcome where the env holds metrics.
func computePromoCount(env operator.Env, answer *ComputeRedeemAnswer) {
	metrics, err := env.Metrics()
	if err != nil {
		return
	}
	outcome := string(answer.Refusal)
	switch {
	case answer.Redeemed:
		outcome = computePromoOutcomeRedeemed
	case answer.Lot != nil:
		outcome = computePromoOutcomeRetry
	}
	metrics.Counter(computePromoRedemptionsMetric, "compute promotion code redemptions and refusals, by outcome", "outcome").Add(1, outcome)
}

// The time from now to the next UTC midnight.
func computeUntilUtcMidnight(now time.Time) time.Duration {
	return model.ComputeUtcDay(now).AddDate(0, 0, 1).Sub(now)
}

// Redeems request's code (see the file header). A refusal is an answer, never an error; an error means the ledger
// could not say, and nothing was credited: unset secrets (ErrComputeLedgerSecretsUnset), or a failure count that does
// not read, which refuses rather than leave guessing unbounded.
func ComputeRedeemPromo(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, secrets ComputeLedgerSecrets, request *ComputeRedeemRequest) (*ComputeRedeemAnswer, error) {
	var zero operator.Id
	if request.NetworkId == zero {
		return nil, fmt.Errorf("%w: a redemption names its network", ErrComputePromoArgs)
	}
	if _, err := computePromoKey(secrets); err != nil {
		return nil, err
	}
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	now := clock.Now()
	failures, err := model.ComputePromoFailures(env, ctx, request.NetworkId, now)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrComputePromoUnavailable, err)
	}
	if int64(settings.PromoFailureDayMaxCount) <= failures {
		answer := &ComputeRedeemAnswer{Refusal: ComputePromoRefusalRateLimited, RetryAfter: computeUntilUtcMidnight(now)}
		computePromoCount(env, answer)
		return answer, nil
	}
	answer, err := computeRedeemPromoOnce(env, ctx, settings, secrets, request, now)
	if err != nil {
		return nil, err
	}
	if answer.Refusal.failedCode() {
		// the day's failures; one that does not count still refuses this code
		model.ComputePromoFailureAdd(env, ctx, request.NetworkId, now, settings.PromoFailureKeyTtl)
	}
	if answer.Redeemed {
		answer.Projected = computeProjectionRefresh(env, ctx, settings, request.NetworkId, now, false)
	}
	computePromoCount(env, answer)
	return answer, nil
}

// The redemption's transaction, under the network's fence: the checks in §9.11's order, then the lot, the redemption
// and the code's count.
func computeRedeemPromoOnce(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, secrets ComputeLedgerSecrets, request *ComputeRedeemRequest, now time.Time) (*ComputeRedeemAnswer, error) {
	folded, ok := computePromoCodeFold(settings, request.Code)
	if !ok {
		return &ComputeRedeemAnswer{Refusal: ComputePromoRefusalCodeUnknown}, nil
	}
	codeHash, err := computePromoCodeHash(secrets, folded)
	if err != nil {
		return nil, err
	}
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	var answer *ComputeRedeemAnswer
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		answer = &ComputeRedeemAnswer{}
		refuse := func(refusal ComputePromoRefusal) error {
			answer.Refusal = refusal
			return nil
		}
		if err := model.ComputeFenceInTx(env, ctx, tx, request.NetworkId); err != nil {
			return err
		}
		code, err := model.ComputePromoCodeByHashInTx(env, ctx, tx, codeHash)
		if err != nil {
			return err
		}
		if code == nil {
			return refuse(ComputePromoRefusalCodeUnknown)
		}
		earlier, err := model.ComputePromoRedemptionInTx(env, ctx, tx, code.CodeId, request.NetworkId)
		if err != nil {
			return err
		}
		if earlier != nil {
			if now.Sub(earlier.RedeemTime) <= settings.PromoRetryWindow {
				// a retry: the first redemption's lot, nothing credited twice
				answer.Lot, err = model.ComputeLotGetInTx(env, ctx, tx, earlier.LotId)
				return err
			}
			return refuse(ComputePromoRefusalCodeRedeemed)
		}
		if code.LastDay.Before(model.ComputeUtcDay(now)) || code.RedeemMaxCount <= code.RedeemCount {
			return refuse(ComputePromoRefusalCodeEnded)
		}
		last, err := model.ComputePromoLastRedemptionInTx(env, ctx, tx, request.NetworkId)
		if err != nil {
			return err
		}
		if last != nil && now.Sub(last.RedeemTime) < settings.PromoNetworkInterval {
			return refuse(ComputePromoRefusalRedeemedRecently)
		}
		suspended, err := model.ComputeChargebackSuspendedInTx(env, ctx, tx, request.NetworkId)
		if err != nil {
			return err
		}
		if suspended {
			return refuse(ComputePromoRefusalSuspended)
		}
		if code.PaidLotRequired {
			paid, err := model.ComputePaidLotsInTx(env, ctx, tx, request.NetworkId)
			if err != nil {
				return err
			}
			if paid.OldestTime == nil {
				return refuse(ComputePromoRefusalPaidLotRequired)
			}
		}
		breaches, err := computeLoadBreachesInTx(env, ctx, tx, settings, &computeLoad{
			networkId: request.NetworkId, amount: code.AmountNanoUsd,
		}, now)
		if err != nil {
			return err
		}
		for _, breach := range breaches {
			if breach.Reason == ComputeLimitBalanceCap {
				return refuse(ComputePromoRefusalBalanceCap)
			}
		}
		if 0 < len(breaches) {
			return refuse(ComputePromoRefusalDailyLimit)
		}
		redemptionId := sidecar.NewId()
		expire := now.Add(settings.PromoLapse)
		credit, err := computeCreditLotInTx(env, ctx, tx, settings, &ComputeCreditRequest{
			NetworkId: request.NetworkId, Kind: model.ComputeLotKindPromotion, Market: model.ComputeMarketPromotion,
			MarketRef: redemptionId.String(), AmountNanoUsd: code.AmountNanoUsd, ExpireTime: &expire,
		}, now)
		if err != nil {
			return err
		}
		if !credit.Credited {
			return fmt.Errorf("compute promo: a new redemption's reference stood")
		}
		sidecarId := operator.Id{}
		if request.SidecarId != nil {
			sidecarId = *request.SidecarId
		}
		err = model.ComputePromoRedemptionInsertInTx(env, ctx, tx, &model.ComputePromoRedemption{
			RedemptionId: redemptionId, CodeId: code.CodeId, NetworkId: request.NetworkId, LotId: credit.Lot.LotId,
			SidecarId: sidecarId, RedeemTime: now.UTC(),
		})
		if err != nil {
			return err
		}
		if err := model.ComputePromoCodeCountInTx(env, ctx, tx, code.CodeId); err != nil {
			return err
		}
		answer.Lot = credit.Lot
		answer.Redeemed = true
		return nil
	}, operator.DbIsolationReadCommitted)
	if err != nil {
		return nil, err
	}
	return answer, nil
}

// What one run of compute_promo_lapse did.
type ComputeLapseResult struct {
	LotCount     int
	NetworkCount int
	// What lapsed, in all.
	LapsedNanoUsd int64
	// Networks whose projection did not take the lapse, marked for a rebuild.
	UnprojectedCount int
}

// Runs one pass of compute_promo_lapse (see the file header): up to the settings' batch of promotional lots past their
// expiry, each network's in one transaction under its fence, then its projection. A network that fails waits for the
// next run, its lots still listed.
func ComputeLapsePromos(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings) (*ComputeLapseResult, error) {
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	now := clock.Now()
	lots, err := model.ComputePromoLapsing(env, ctx, now, settings.PromoLapseBatchCount)
	if err != nil {
		return nil, err
	}
	networkIds := []operator.Id{}
	networkIdLots := map[operator.Id][]*model.ComputeLot{}
	for _, lot := range lots {
		if _, ok := networkIdLots[lot.NetworkId]; !ok {
			networkIds = append(networkIds, lot.NetworkId)
		}
		networkIdLots[lot.NetworkId] = append(networkIdLots[lot.NetworkId], lot)
	}
	result := &ComputeLapseResult{}
	var firstErr error
	for _, networkId := range networkIds {
		lapsed := int64(0)
		count := 0
		err := db.Tx(ctx, func(tx operator.DbTx) error {
			lapsed, count = 0, 0
			if err := model.ComputeFenceInTx(env, ctx, tx, networkId); err != nil {
				return err
			}
			for _, lot := range networkIdLots[networkId] {
				lapsedNow, err := model.ComputeLotLapseInTx(env, ctx, tx, lot.LotId)
				if err != nil {
					return err
				}
				if 0 < lapsedNow {
					lapsed += lapsedNow
					count += 1
				}
			}
			if lapsed == 0 {
				return nil
			}
			if _, err := model.ComputeAccountForUpdateInTx(env, ctx, tx, networkId, now); err != nil {
				return err
			}
			_, err := model.ComputeAccountMoveInTx(env, ctx, tx, networkId, -lapsed, nil, now)
			return err
		}, operator.DbIsolationReadCommitted)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if lapsed == 0 {
			continue
		}
		result.LotCount += count
		result.NetworkCount += 1
		result.LapsedNanoUsd += lapsed
		if !computeProjectionRefresh(env, ctx, settings, networkId, now, true) {
			result.UnprojectedCount += 1
		}
	}
	return result, firstErr
}
