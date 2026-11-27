// computetest.FakeParallel (CTEST-M13-03; DESIGN-COMPUTE §18's web search row, with §21.3 and §21.5): Parallel's
// keyless gateway as the device reaches it, POST /api/search on loopback HTTPS (FakeParallelHost), for SRCH's x402
// client, built from the gateway's live 402s of 2026-11-23 and the documents §21.3 cites, never a recorded answer
// (§21.11):
//
//	unpaid     402 with an x402 v2 offer in a base64 PAYMENT-REQUIRED header and the same JSON body: one accepts entry,
//	           scheme exact, network the chain's, the search's amount, the chain's USDC (EIP-55), a fresh payTo drawn
//	           for this 402 alone and cached PayeeCacheTtl, maxTimeoutSeconds, extra {name, version}; beside it an MPP
//	           Tempo charge challenge in WWW-Authenticate, for the client to ignore
//	paid       the payment read from the first of PaymentHeaders the request carries (PAYMENT-SIGNATURE until
//	           G-SRCH-parallel's load test says otherwise), base64 of x402 v2's PaymentPayload; the facilitator's checks,
//	           as x402's reference verifier makes them: the version, the scheme and network, the offer still cached
//	           (else the payee aged out: a new 402, or PayeeLostStatus), authorization.to the offer's payTo, value the
//	           amount exactly, validAfter not in the future, validBefore at least ValidBeforeBuffer ahead, the EIP-712
//	           signature recovered for real to authorization.from, the payer's balance and the nonce unused on FakeBase;
//	           each refusal a new 402 naming x402's reason, nothing settled
//	settle     transferWithAuthorization submitted to FakeBase from the facilitator's address (Facilitator), before the
//	           search as Parallel's wording suggests (CO-30) unless SettleBeforeSearch is off, x402's default of serving
//	           first; a chain that refuses it answers a 402 naming unexpected_settle_error
//	search     after payment, Parallel's API's own checks (search_queries required, past the fifth dropped, a query of
//	           at most QueryMaxCharacterCount and an objective of ObjectiveMaxCharacterCount, mode turbo, fast, basic or
//	           advanced, fast by default), each refusal a paid 422; then the results, synthetic and built from
//	           Parallel's documented schema (search_id, results with url, title, publish_date and excerpts, warnings,
//	           usage, session_id), and PAYMENT-RESPONSE with the transaction where PaymentResponse says the gateway
//	           sends it
//	limits     RequestsPerMinute per client address on the fake clock, a 429 with Retry-After past it
//	script     Script queues steps a request takes in order (FakeParallelStep): a 429; a settled search whose upstream
//	           fails (CO-30); a settled search whose answer is lost, the connection closed; a stall held at a barrier
//	           until the test releases it or the client gives up; a payee aged out; or results the test chose
//
// Every request is logged as received (Requests), with the fields its body held and any other field's name, its
// connection's number, its payment decoded, its offer and its outcome; every settlement too (Settlements). What
// the gateway does where §21.3 calls it open (the header it reads, whether settlement comes first, whether
// PAYMENT-RESPONSE is sent, what a lost payee answers) is a setting, so a test runs either reading. Unverified against
// the live gateway: G-SRCH-parallel's load test settles each open point (QD-1233). Endpoints the device never calls
// (Extract, Task, Responses, GET /api) answer 404 naming ErrFakeParallelUnserved. Safe for concurrent use.

package computetest

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The gateway's host, and its search path (identifiers).
const (
	FakeParallelHost       = "parallelmpp.example"
	FakeParallelSearchPath = "/api/search"
)

// x402's names (identifiers): its version, the scheme, and the reasons a verification or settlement fails.
const (
	fakeX402Version                  = 2
	fakeX402SchemeExact              = "exact"
	FakeX402InvalidPayload           = "invalid_payload"
	FakeX402InvalidVersion           = "invalid_x402_version"
	FakeX402UnsupportedScheme        = "unsupported_scheme"
	FakeX402InvalidNetwork           = "invalid_network"
	FakeX402InvalidRequirements      = "invalid_payment_requirements"
	FakeX402RecipientMismatch        = "invalid_exact_evm_payload_recipient_mismatch"
	FakeX402InvalidValue             = "invalid_exact_evm_payload_authorization_value"
	FakeX402InvalidValidAfter        = "invalid_exact_evm_payload_authorization_valid_after"
	FakeX402InvalidValidBefore       = "invalid_exact_evm_payload_authorization_valid_before"
	FakeX402InvalidSignature         = "invalid_exact_evm_payload_signature"
	FakeX402InsufficientFunds        = "insufficient_funds"
	FakeX402InvalidTransactionState  = "invalid_transaction_state"
	FakeX402UnexpectedSettleError    = "unexpected_settle_error"
	FakeX402PayeeNotCached           = "Invalid payTo address: not found in server cache"
	fakeParallelUpstreamValidation   = "Upstream validation error"
	fakeParallelUpstreamFailureError = "Upstream connection failure"
)

var (
	// A request the gateway does not serve here: another path or method.
	ErrFakeParallelUnserved = errors.New("computetest: the fake gateway serves POST /api/search alone")
	// Args the fake cannot serve.
	ErrFakeParallelArgs = errors.New("computetest: args the fake gateway cannot serve")
)

// The gateway's settings (QD-702).
type FakeParallelSettings struct {
	// A search's price in USDC's 6 decimals: 10,000, $0.01, as every live 402 offered.
	SearchAmount uint64
	// An offer's maxTimeoutSeconds: 300 s, as every live 402 offered.
	MaxTimeout time.Duration
	// How long an offered payee stays in the gateway's cache: 5 minutes, as Stripe's sample kept its deposit
	// addresses; Parallel's own is unpublished (§21.3's open row).
	PayeeCacheTtl time.Duration
	// How far ahead validBefore must be at verification: 6 s, x402's reference verifier's buffer for block time.
	ValidBeforeBuffer time.Duration
	// Requests a client address may send in RateLimitWindow: 60 a minute, the gateway's documented limit, unpaid 402s
	// counted too (unpublished, a reading).
	RequestsPerMinute int
	RateLimitWindow   time.Duration
	// Parallel's documented search limits: queries past the fifth dropped, each at most 200 characters, and an
	// objective of at most 5,000.
	QueryMaxCount              int
	QueryMaxCharacterCount     int
	ObjectiveMaxCharacterCount int
	// The headers a payment is read from, the first the request carries winning: PAYMENT-SIGNATURE, x402 v2's, as its
	// challenge and Stripe's purl use it; X-Payment, the gateway's own JSON's name, is G-SRCH-parallel's to settle.
	PaymentHeaders []string
	// Settlement before the search runs (Parallel's wording, CO-30), or after a served answer (x402's default flow).
	SettleBeforeSearch bool
	// Whether a paid answer carries PAYMENT-RESPONSE with the settlement's transaction (open in §21.3).
	PaymentResponse bool
	// The status a paid request whose payee left the cache answers: 402, a new challenge, as the design reads it;
	// 500 is what Parallel's engineering post describes.
	PayeeLostStatus int
	// The results a served search answers when a step chooses none: 3.
	DefaultResultCount int
	// The most bytes a request's body may hold: 1 MiB.
	RequestBodyMaxByteCount int64
}

// The gateway's defaults, the only place one is set.
func DefaultFakeParallelSettings() *FakeParallelSettings {
	return &FakeParallelSettings{
		SearchAmount:               10000,
		MaxTimeout:                 300 * time.Second,
		PayeeCacheTtl:              5 * time.Minute,
		ValidBeforeBuffer:          6 * time.Second,
		RequestsPerMinute:          60,
		RateLimitWindow:            time.Minute,
		QueryMaxCount:              5,
		QueryMaxCharacterCount:     200,
		ObjectiveMaxCharacterCount: 5000,
		PaymentHeaders:             []string{"PAYMENT-SIGNATURE"},
		SettleBeforeSearch:         true,
		PaymentResponse:            true,
		PayeeLostStatus:            http.StatusPaymentRequired,
		DefaultResultCount:         3,
		RequestBodyMaxByteCount:    1024 * 1024,
	}
}

// What NewFakeParallel builds on.
type FakeParallelArgs struct {
	// Nil takes DefaultFakeParallelSettings.
	Settings *FakeParallelSettings
	// Nil takes a FakeClock at sidecartest.DefaultClockStart; the chain's clock should be the same.
	Clock sidecar.Clock
	// What payees, ids and the facilitator's key are drawn from; empty takes "computetest".
	Seed string
	// The chain the facilitator settles on. Required.
	Base *FakeBase
}

// What a scripted request comes to (identifiers).
type FakeParallelOutcome string

const (
	// The protocol as documented: a 402 unpaid, a verified payment settled and the search served.
	FakeParallelServe FakeParallelOutcome = "serve"
	// 429 with RetryAfter, nothing verified or settled.
	FakeParallelRateLimited FakeParallelOutcome = "rate_limited"
	// Settled, then the upstream fails (Status, 502 by default): paid for no answer (CO-30).
	FakeParallelUpstreamFailure FakeParallelOutcome = "upstream_failure"
	// Settled, then the answer lost: the connection closes with nothing written.
	FakeParallelLostAnswer FakeParallelOutcome = "lost_answer"
	// Settled, then the answer held at Stall until released (it then leaves) or the client gives up (lost).
	FakeParallelStalled FakeParallelOutcome = "stall"
	// The payment's payee treated as gone from the cache: PayeeLostStatus, nothing settled.
	FakeParallelPayeeAgedOut FakeParallelOutcome = "payee_aged_out"
)

// One result as Parallel's schema writes it.
type FakeParallelResult struct {
	Url         string   `json:"url"`
	Title       string   `json:"title"`
	PublishDate string   `json:"publish_date,omitempty"`
	Excerpts    []string `json:"excerpts"`
}

// A stall: a barrier holding a settled search's answer. Safe for concurrent use.
type FakeParallelStall struct {
	reached     chan struct{}
	released    chan struct{}
	reachedOnce sync.Once
	releaseOnce sync.Once
}

func NewFakeParallelStall() *FakeParallelStall {
	return &FakeParallelStall{reached: make(chan struct{}), released: make(chan struct{})}
}

// Closed once an answer holds at the stall.
func (self *FakeParallelStall) Reached() <-chan struct{} {
	return self.reached
}

// The held answer leaves, now or as one reaches the stall.
func (self *FakeParallelStall) Release() {
	self.releaseOnce.Do(func() {
		close(self.released)
	})
}

// One scripted step.
type FakeParallelStep struct {
	// Empty serves.
	Outcome FakeParallelOutcome
	// The step waits for a request carrying a payment, letting unpaid ones pass by; otherwise any request takes it.
	PaidOnly bool
	// rate_limited: Retry-After, whole seconds; 0 sends 1 s.
	RetryAfter time.Duration
	// upstream_failure: the status, 502 by default (Parallel's other upstream answers are 504 and 422).
	Status int
	// serve: the results, nil drawing DefaultResultCount synthetic ones; and the warnings.
	Results  []*FakeParallelResult
	Warnings []string
	// stall: the barrier; nil holds until the client gives up.
	Stall *FakeParallelStall
}

// An offer a 402 made: the requirement in its accepts list.
type FakeParallelOffer struct {
	Scheme            string            `json:"scheme"`
	Network           string            `json:"network"`
	Amount            string            `json:"amount"`
	Asset             string            `json:"asset"`
	PayTo             string            `json:"payTo"`
	MaxTimeoutSeconds int64             `json:"maxTimeoutSeconds"`
	Extra             map[string]string `json:"extra"`
}

// x402 v2's exact EVM payload as the request carried it.
type fakeX402Authorization struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Value       string `json:"value"`
	ValidAfter  string `json:"validAfter"`
	ValidBefore string `json:"validBefore"`
	Nonce       string `json:"nonce"`
}

type fakeX402PaymentPayload struct {
	X402Version int                `json:"x402Version"`
	Resource    json.RawMessage    `json:"resource,omitempty"`
	Accepted    *FakeParallelOffer `json:"accepted"`
	Payload     *struct {
		Signature     string                 `json:"signature"`
		Authorization *fakeX402Authorization `json:"authorization"`
	} `json:"payload"`
}

// A payment decoded.
type FakeParallelPayment struct {
	// The header that carried it.
	Header        string
	Accepted      *FakeParallelOffer
	Authorization *FakeTransferAuthorization
	Signature     []byte
}

// One settlement the facilitator made.
type FakeParallelSettlement struct {
	At      time.Time
	Receipt *FakeBaseReceipt
	Payment *FakeParallelPayment
}

// One request, as received.
type FakeParallelRequest struct {
	At           time.Time
	ConnectionId uint64
	RemoteAddr   string
	Method       string
	Path         string
	Header       http.Header
	Body         []byte
	// The documented fields the body held, and every other top-level field's name, sorted.
	Objective     string
	Query         string
	SearchQueries []string
	Mode          string
	UnknownFields []string
	// Its payment, decoded; nil unpaid or unreadable.
	Payment *FakeParallelPayment
	// The offer a 402 made it, if one did.
	Offer *FakeParallelOffer
	// The status answered, 0 for an answer lost; x402's reason or the upstream's error where it was refused.
	Status  int
	Refusal string
	Outcome FakeParallelOutcome
	// The settlement it made, if any.
	Settlement *FakeBaseReceipt
}

type fakeParallelPayee struct {
	offer    *FakeParallelOffer
	issuedAt time.Time
}

// See the file header.
type FakeParallel struct {
	settings    *FakeParallelSettings
	clock       sidecar.Clock
	seed        string
	base        *FakeBase
	facilitator *FakeEvmKey
	https       *fakeHttpsServer

	stateLock    sync.Mutex
	payees       map[FakeEvmAddress]*fakeParallelPayee
	nextPayees   []FakeEvmAddress
	payeeCount   uint64
	searchCount  uint64
	steps        []*FakeParallelStep
	requests     []*FakeParallelRequest
	settlements  []*FakeParallelSettlement
	clientRecent map[string][]time.Time
	stalls       []*FakeParallelStall
}

// A gateway listening on loopback at once; Close ends it.
func NewFakeParallel(args *FakeParallelArgs) (*FakeParallel, error) {
	if args == nil || args.Base == nil {
		return nil, fmt.Errorf("%w: no FakeBase", ErrFakeParallelArgs)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultFakeParallelSettings()
	}
	clock := args.Clock
	if clock == nil {
		clock = sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	}
	seed := args.Seed
	if seed == "" {
		seed = "computetest"
	}
	https, err := newFakeHttpsServer(seed + " parallel")
	if err != nil {
		return nil, err
	}
	self := &FakeParallel{
		settings:     settings,
		clock:        clock,
		seed:         seed,
		base:         args.Base,
		facilitator:  NewFakeEvmKey(seed, "parallel facilitator"),
		https:        https,
		payees:       map[FakeEvmAddress]*fakeParallelPayee{},
		clientRecent: map[string][]time.Time{},
	}
	https.handle(FakeParallelHost, http.HandlerFunc(self.serveHttp))
	return self, nil
}

// Releases every stall still holding, then stops the listener.
func (self *FakeParallel) Close() {
	stalls := func() []*FakeParallelStall {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return slices.Clone(self.stalls)
	}()
	for _, stall := range stalls {
		stall.Release()
	}
	self.https.close()
}

func (self *FakeParallel) HttpClient() *http.Client {
	return self.https.httpClient()
}

// Dials the listener for FakeParallelHost, on any port; ErrFakeHostUnserved otherwise.
func (self *FakeParallel) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	return self.https.dialContext(ctx, network, address)
}

func (self *FakeParallel) RootCAs() *x509.CertPool {
	return self.https.authority.rootPool
}

func (self *FakeParallel) SearchUrl() string {
	return "https://" + FakeParallelHost + FakeParallelSearchPath
}

// The facilitator's settlement address, the sender of every settlement it makes.
func (self *FakeParallel) Facilitator() FakeEvmAddress {
	return self.facilitator.Address()
}

// Queues steps the requests take in order (FakeParallelStep's PaidOnly says which).
func (self *FakeParallel) Script(steps ...*FakeParallelStep) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, step := range steps {
		self.steps = append(self.steps, step)
		if step.Stall != nil {
			self.stalls = append(self.stalls, step.Stall)
		}
	}
}

// The next 402 names payee rather than a fresh address: a listed one, or one with a past, for the screen.
func (self *FakeParallel) OfferPayee(payee FakeEvmAddress) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nextPayees = append(self.nextPayees, payee)
}

// Empties the payee cache, as a deploy loses it.
func (self *FakeParallel) ForgetPayees() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	clear(self.payees)
}

// Every request received, in order.
func (self *FakeParallel) Requests() []*FakeParallelRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	requests := []*FakeParallelRequest{}
	for _, request := range self.requests {
		clone := *request
		clone.Header = request.Header.Clone()
		clone.Body = slices.Clone(request.Body)
		requests = append(requests, &clone)
	}
	return requests
}

// Every settlement made, in order.
func (self *FakeParallel) Settlements() []*FakeParallelSettlement {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.settlements)
}

// The offer the next 402 makes, its payee cached.
func (self *FakeParallel) offerWithLock() *FakeParallelOffer {
	var payee FakeEvmAddress
	if len(self.nextPayees) > 0 {
		payee = self.nextPayees[0]
		self.nextPayees = self.nextPayees[1:]
	} else {
		self.payeeCount += 1
		copy(payee[:], fakeBytes(self.seed, fmt.Sprintf("parallel payee %d", self.payeeCount), 20))
	}
	offer := &FakeParallelOffer{
		Scheme:            fakeX402SchemeExact,
		Network:           self.base.Network(),
		Amount:            strconv.FormatUint(self.settings.SearchAmount, 10),
		Asset:             self.base.Usdc().ChecksumHex(),
		PayTo:             payee.Hex(),
		MaxTimeoutSeconds: int64(self.settings.MaxTimeout / time.Second),
		Extra:             map[string]string{"name": FakeBaseUsdcName, "version": FakeBaseUsdcVersion},
	}
	self.payees[payee] = &fakeParallelPayee{offer: offer, issuedAt: self.clock.Now()}
	return offer
}

// The 402: the offer in PAYMENT-REQUIRED and the body, and the MPP challenge beside it.
func (self *FakeParallel) challenge(w http.ResponseWriter, offer *FakeParallelOffer, reason string) {
	errorText := "Payment required"
	if reason != "" {
		errorText = reason
	}
	body, _ := json.Marshal(map[string]any{
		"x402Version": fakeX402Version,
		"error":       errorText,
		"resource": map[string]string{
			"url":         self.SearchUrl(),
			"description": "Parallel /api/search endpoint",
			"mimeType":    "application/json",
		},
		"accepts": []*FakeParallelOffer{offer},
	})
	expires := self.clock.Now().Add(self.settings.MaxTimeout).UTC().Format("2006-01-02T15:04:05.000Z")
	mppRequest, _ := json.Marshal(map[string]any{
		"amount":        offer.Amount,
		"currency":      FakeEvmAddress(fakeBytes(self.seed, "parallel tempo currency", 20)).Hex(),
		"methodDetails": map[string]any{"chainId": 4217},
		"recipient":     FakeEvmAddress(fakeBytes(self.seed, "parallel tempo recipient "+offer.PayTo, 20)).Hex(),
	})
	encode := base64.RawURLEncoding.EncodeToString
	w.Header().Set("PAYMENT-REQUIRED", base64.StdEncoding.EncodeToString(body))
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Payment id="%s", realm="%s", method="tempo", intent="charge", expires="%s", request="%s", opaque="%s"`,
		encode(fakeBytes(self.seed, "parallel mpp id "+offer.PayTo, 32)), FakeParallelHost, expires, encode(mppRequest),
		encode([]byte(`{"_mppx_scope":"POST /api/search"}`))))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusPaymentRequired)
	w.Write(body)
}

// The step a request takes: the first in the queue it may take, or nil to serve.
func (self *FakeParallel) takeStepWithLock(paid bool) *FakeParallelStep {
	for i, step := range self.steps {
		if step.PaidOnly && !paid {
			continue
		}
		self.steps = slices.Delete(self.steps, i, i+1)
		return step
	}
	return nil
}

// Whether a client address is past its rate, counting this request; the wait until it is not.
func (self *FakeParallel) rateLimitedWithLock(client string) (bool, time.Duration) {
	now := self.clock.Now()
	recent := slices.DeleteFunc(self.clientRecent[client], func(at time.Time) bool {
		return !at.After(now.Add(-self.settings.RateLimitWindow))
	})
	if len(recent) >= self.settings.RequestsPerMinute {
		self.clientRecent[client] = recent
		return true, recent[0].Add(self.settings.RateLimitWindow).Sub(now)
	}
	self.clientRecent[client] = append(recent, now)
	return false, 0
}

// Decodes a payment header's value, base64 of x402 v2's PaymentPayload; a reason it cannot be read.
func fakeParallelDecodePayment(header string, value string) (*FakeParallelPayment, *fakeX402PaymentPayload, string) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(value)); err != nil {
			return nil, nil, FakeX402InvalidPayload
		}
	}
	var payload fakeX402PaymentPayload
	if err := json.Unmarshal(raw, &payload); err != nil || payload.Accepted == nil || payload.Payload == nil || payload.Payload.Authorization == nil {
		return nil, nil, FakeX402InvalidPayload
	}
	payment := &FakeParallelPayment{Header: header, Accepted: payload.Accepted}
	authorization := payload.Payload.Authorization
	auth := &FakeTransferAuthorization{Value: new(big.Int)}
	var parseErr error
	if auth.From, parseErr = ParseFakeEvmAddress(authorization.From); parseErr != nil {
		return nil, nil, FakeX402InvalidPayload
	}
	if auth.To, parseErr = ParseFakeEvmAddress(authorization.To); parseErr != nil {
		return nil, nil, FakeX402InvalidPayload
	}
	if _, ok := auth.Value.SetString(authorization.Value, 10); !ok || auth.Value.Sign() < 0 || auth.Value.BitLen() > 256 {
		return nil, nil, FakeX402InvalidPayload
	}
	if auth.ValidAfter, parseErr = strconv.ParseUint(authorization.ValidAfter, 10, 64); parseErr != nil {
		return nil, nil, FakeX402InvalidPayload
	}
	if auth.ValidBefore, parseErr = strconv.ParseUint(authorization.ValidBefore, 10, 64); parseErr != nil {
		return nil, nil, FakeX402InvalidPayload
	}
	nonce, parseErr := fakeEvmParseBytes(authorization.Nonce, 32)
	if parseErr != nil {
		return nil, nil, FakeX402InvalidPayload
	}
	auth.Nonce = [32]byte(nonce)
	signature, parseErr := hex.DecodeString(strings.TrimPrefix(payload.Payload.Signature, "0x"))
	if parseErr != nil {
		return nil, nil, FakeX402InvalidSignature
	}
	payment.Authorization = auth
	payment.Signature = signature
	return payment, &payload, ""
}

// The facilitator's first checks (see the file header's paid row), of the payload and the offer it names: the offer
// cached, or the reason it refuses; and whether the reason is the payee gone from the cache.
func (self *FakeParallel) verifyOfferWithLock(payload *fakeX402PaymentPayload, payment *FakeParallelPayment) (*FakeParallelOffer, string, bool) {
	if payload.X402Version != fakeX402Version {
		return nil, FakeX402InvalidVersion, false
	}
	accepted := payment.Accepted
	if accepted.Scheme != fakeX402SchemeExact {
		return nil, FakeX402UnsupportedScheme, false
	}
	if accepted.Network != self.base.Network() {
		return nil, FakeX402InvalidNetwork, false
	}
	payTo, err := ParseFakeEvmAddress(accepted.PayTo)
	if err != nil {
		return nil, FakeX402InvalidRequirements, false
	}
	cached, ok := self.payees[payTo]
	if !ok || !self.clock.Now().Before(cached.issuedAt.Add(self.settings.PayeeCacheTtl)) {
		delete(self.payees, payTo)
		return nil, FakeX402PayeeNotCached, true
	}
	offer := cached.offer
	if !strings.EqualFold(accepted.Asset, offer.Asset) || accepted.Amount != offer.Amount ||
		accepted.MaxTimeoutSeconds != offer.MaxTimeoutSeconds || accepted.Extra["name"] != offer.Extra["name"] ||
		accepted.Extra["version"] != offer.Extra["version"] {
		return nil, FakeX402InvalidRequirements, false
	}
	return offer, "", false
}

// The facilitator's checks of the authorization against offer, the chain read for the payer's balance and the nonce;
// empty when it verifies, else the reason. Takes no lock of the gateway's.
func (self *FakeParallel) verifyAuthorization(offer *FakeParallelOffer, payment *FakeParallelPayment) string {
	payTo, _ := ParseFakeEvmAddress(offer.PayTo)
	auth := payment.Authorization
	if auth.To != payTo {
		return FakeX402RecipientMismatch
	}
	amount, _ := new(big.Int).SetString(offer.Amount, 10)
	if auth.Value.Cmp(amount) != 0 {
		return FakeX402InvalidValue
	}
	now := uint64(self.clock.Now().Unix())
	if auth.ValidAfter > now {
		return FakeX402InvalidValidAfter
	}
	if auth.ValidBefore < now+uint64(self.settings.ValidBeforeBuffer/time.Second) {
		return FakeX402InvalidValidBefore
	}
	signer, err := FakeRecoverEvmSigner(FakeTransferWithAuthorizationDigest(self.base.UsdcDomain(), auth), payment.Signature)
	if err != nil || signer != auth.From {
		return FakeX402InvalidSignature
	}
	if self.base.UsdcBalance(auth.From).Cmp(auth.Value) < 0 {
		return FakeX402InsufficientFunds
	}
	if self.base.AuthorizationUsed(auth.From, auth.Nonce) {
		return FakeX402InvalidTransactionState
	}
	return ""
}

// The search body's documented fields and the names of any other.
type fakeParallelBody struct {
	objective     string
	query         string
	searchQueries []string
	mode          string
	unknown       []string
}

func fakeParallelReadBody(body []byte) (*fakeParallelBody, bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, false
	}
	parsed := &fakeParallelBody{}
	for name, raw := range fields {
		var err error
		switch name {
		case "objective":
			err = json.Unmarshal(raw, &parsed.objective)
		case "query":
			err = json.Unmarshal(raw, &parsed.query)
		case "search_queries":
			err = json.Unmarshal(raw, &parsed.searchQueries)
		case "mode":
			err = json.Unmarshal(raw, &parsed.mode)
		default:
			parsed.unknown = append(parsed.unknown, name)
		}
		if err != nil {
			return nil, false
		}
	}
	slices.Sort(parsed.unknown)
	return parsed, true
}

// Parallel's API's own refusal of a paid search's body, as a validation error's detail; empty when it is served.
func (self *FakeParallel) searchRefusal(body *fakeParallelBody) string {
	if len(body.searchQueries) == 0 {
		return "search_queries: at least one query is required"
	}
	for _, query := range body.searchQueries[:min(len(body.searchQueries), self.settings.QueryMaxCount)] {
		if query == "" || len([]rune(query)) > self.settings.QueryMaxCharacterCount {
			return "search_queries: a query of 1 to " + strconv.Itoa(self.settings.QueryMaxCharacterCount) + " characters"
		}
	}
	objective := body.objective
	if objective == "" {
		objective = body.query
	}
	if len([]rune(objective)) > self.settings.ObjectiveMaxCharacterCount {
		return "objective: at most " + strconv.Itoa(self.settings.ObjectiveMaxCharacterCount) + " characters"
	}
	switch body.mode {
	case "", "turbo", "fast", "basic", "advanced":
	default:
		return "mode: one of turbo, fast, basic, advanced"
	}
	return ""
}

func (self *FakeParallel) serveHttp(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != FakeParallelSearchPath || r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": ErrFakeParallelUnserved.Error()})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, self.settings.RequestBodyMaxByteCount))
	request := &FakeParallelRequest{
		At:           self.clock.Now(),
		ConnectionId: fakeConnectionId(r.Context()),
		RemoteAddr:   r.RemoteAddr,
		Method:       r.Method,
		Path:         r.URL.Path,
		Header:       r.Header.Clone(),
		Body:         body,
		Outcome:      FakeParallelServe,
	}
	answered := false
	defer func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !answered {
			request.Status = 0
		}
		self.requests = append(self.requests, request)
	}()
	answer := func(status int, payload any) {
		request.Status = status
		answered = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(payload)
	}
	if err != nil {
		answer(http.StatusRequestEntityTooLarge, map[string]string{"error": "Request body too large"})
		return
	}
	parsedBody, readable := fakeParallelReadBody(body)
	if parsedBody != nil {
		request.Objective = parsedBody.objective
		request.Query = parsedBody.query
		request.SearchQueries = parsedBody.searchQueries
		request.Mode = parsedBody.mode
		request.UnknownFields = parsedBody.unknown
	}
	paymentHeader, paymentValue := "", ""
	for _, name := range self.settings.PaymentHeaders {
		if value := r.Header.Get(name); value != "" {
			paymentHeader, paymentValue = name, value
			break
		}
	}
	client, _, _ := net.SplitHostPort(r.RemoteAddr)
	// what the request comes to, decided under the lock: a 429, a 402, a refusal, or a verified payment
	var step *FakeParallelStep
	var challengeOffer *FakeParallelOffer
	var payment *FakeParallelPayment
	var verifiedOffer *FakeParallelOffer
	refusal := ""
	payeeLost := false
	limited := false
	var retryAfter time.Duration
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		step = self.takeStepWithLock(paymentValue != "")
		if step != nil && step.Outcome == FakeParallelRateLimited {
			limited, retryAfter = true, step.RetryAfter
			return
		}
		if over, wait := self.rateLimitedWithLock(client); over {
			limited, retryAfter = true, wait
			return
		}
		if !readable {
			return
		}
		if paymentValue == "" {
			challengeOffer = self.offerWithLock()
			return
		}
		decoded, payload, reason := fakeParallelDecodePayment(paymentHeader, paymentValue)
		if reason != "" {
			refusal = reason
			challengeOffer = self.offerWithLock()
			return
		}
		payment = decoded
		if step != nil && step.Outcome == FakeParallelPayeeAgedOut {
			if payTo, err := ParseFakeEvmAddress(payment.Accepted.PayTo); err == nil {
				delete(self.payees, payTo)
			}
		}
		offer, reason, lost := self.verifyOfferWithLock(payload, payment)
		if reason != "" {
			refusal, payeeLost = reason, lost
			if !lost || self.settings.PayeeLostStatus == http.StatusPaymentRequired {
				challengeOffer = self.offerWithLock()
			}
			return
		}
		verifiedOffer = offer
	}()
	if verifiedOffer != nil {
		// the authorization's checks read the chain, with no lock of the gateway's held
		if reason := self.verifyAuthorization(verifiedOffer, payment); reason != "" {
			refusal = reason
			self.stateLock.Lock()
			challengeOffer = self.offerWithLock()
			self.stateLock.Unlock()
		}
	}
	request.Payment = payment
	if step != nil && step.Outcome != "" {
		request.Outcome = step.Outcome
	}
	switch {
	case limited:
		seconds := int64((retryAfter + time.Second - 1) / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		request.Refusal = "rate_limited"
		answer(http.StatusTooManyRequests, map[string]string{"error": "Rate limit exceeded (" + strconv.Itoa(self.settings.RequestsPerMinute) + " req/min)"})
		return
	case !readable:
		request.Refusal = "invalid_json"
		answer(http.StatusBadRequest, map[string]string{"error": "Invalid JSON body"})
		return
	case refusal != "" && payeeLost && challengeOffer == nil:
		request.Refusal = refusal
		answer(self.settings.PayeeLostStatus, map[string]string{"error": refusal})
		return
	case challengeOffer != nil:
		request.Refusal = refusal
		request.Offer = challengeOffer
		request.Status = http.StatusPaymentRequired
		answered = true
		self.challenge(w, challengeOffer, refusal)
		return
	}
	settle := func() bool {
		receipt, err := self.base.TransferWithAuthorization(self.facilitator.Address(), payment.Authorization, payment.Signature)
		if err != nil {
			request.Refusal = FakeX402UnexpectedSettleError
			self.stateLock.Lock()
			offer := self.offerWithLock()
			self.stateLock.Unlock()
			request.Offer = offer
			request.Status = http.StatusPaymentRequired
			answered = true
			self.challenge(w, offer, FakeX402UnexpectedSettleError)
			return false
		}
		request.Settlement = receipt
		self.stateLock.Lock()
		self.settlements = append(self.settlements, &FakeParallelSettlement{At: self.clock.Now(), Receipt: receipt, Payment: payment})
		self.stateLock.Unlock()
		return true
	}
	settled := false
	if self.settings.SettleBeforeSearch {
		if !settle() {
			return
		}
		settled = true
	}
	outcome := FakeParallelServe
	if step != nil && step.Outcome != "" {
		outcome = step.Outcome
	}
	switch outcome {
	case FakeParallelUpstreamFailure:
		status := step.Status
		if status == 0 {
			status = http.StatusBadGateway
		}
		request.Refusal = fakeParallelUpstreamFailureError
		answer(status, map[string]string{"error": fakeParallelUpstreamFailureError})
		return
	case FakeParallelLostAnswer:
		if !settled && !settle() {
			return
		}
		panic(http.ErrAbortHandler)
	case FakeParallelStalled:
		if !settled && !settle() {
			return
		}
		held := step.Stall
		if held == nil {
			<-r.Context().Done()
			panic(http.ErrAbortHandler)
		}
		held.reachedOnce.Do(func() { close(held.reached) })
		select {
		case <-held.released:
		case <-r.Context().Done():
			panic(http.ErrAbortHandler)
		}
	}
	if validation := self.searchRefusal(parsedBody); validation != "" {
		// paid where settlement came first; under x402's own order a refused search settles nothing
		request.Refusal = fakeParallelUpstreamValidation
		answer(http.StatusUnprocessableEntity, map[string]any{"type": "error", "error": map[string]string{
			"ref_id":  hex.EncodeToString(fakeBytes(self.seed, "parallel ref "+strconv.Itoa(len(body)), 8)),
			"message": fakeParallelUpstreamValidation,
			"detail":  validation,
		}})
		return
	}
	if !settled && !settle() {
		return
	}
	self.serveResults(w, request, step, parsedBody, payment)
	answered = true
}

// A served search's answer, its PAYMENT-RESPONSE where the settings send one.
func (self *FakeParallel) serveResults(w http.ResponseWriter, request *FakeParallelRequest, step *FakeParallelStep, body *fakeParallelBody, payment *FakeParallelPayment) {
	self.stateLock.Lock()
	self.searchCount += 1
	searchNumber := self.searchCount
	self.stateLock.Unlock()
	queries := body.searchQueries[:min(len(body.searchQueries), self.settings.QueryMaxCount)]
	results := []*FakeParallelResult{}
	var warnings any
	if step != nil && step.Results != nil {
		results = step.Results
	} else {
		digest := fakeKeccak([]byte(strings.Join(queries, "\n")))
		for i := 1; i <= self.settings.DefaultResultCount; i += 1 {
			results = append(results, &FakeParallelResult{
				Url:         fmt.Sprintf("https://result-%d.search.example/%s", i, hex.EncodeToString(digest[:6])),
				Title:       fmt.Sprintf("Synthetic result %d", i),
				PublishDate: "2026-01-0" + strconv.Itoa(i%9+1),
				Excerpts:    []string{fmt.Sprintf("Synthetic excerpt %d for the search's queries.", i)},
			})
		}
	}
	if step != nil && step.Warnings != nil {
		warnings = step.Warnings
	}
	if self.settings.PaymentResponse && request.Settlement != nil {
		receipt, _ := json.Marshal(map[string]any{
			"success":     true,
			"transaction": fakeRpcHex(request.Settlement.TxHash[:]),
			"network":     self.base.Network(),
			"payer":       payment.Authorization.From.Hex(),
		})
		w.Header().Set("PAYMENT-RESPONSE", base64.StdEncoding.EncodeToString(receipt))
	}
	request.Status = http.StatusOK
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"search_id":  "search_" + hex.EncodeToString(fakeBytes(self.seed, fmt.Sprintf("parallel search %d", searchNumber), 16)),
		"results":    results,
		"warnings":   warnings,
		"usage":      []map[string]any{{"name": "sku_search", "count": 1}},
		"session_id": "session_" + hex.EncodeToString(fakeBytes(self.seed, fmt.Sprintf("parallel session %d", searchNumber), 16)),
	})
}

// x402 v2's PaymentPayload for auth and its signature under offer, base64 as a payment header carries it: what a
// device's paid retry sends, for a test that pays the fake.
func FakeParallelPaymentHeader(offer *FakeParallelOffer, auth *FakeTransferAuthorization, signature []byte) string {
	payload, _ := json.Marshal(map[string]any{
		"x402Version": fakeX402Version,
		"accepted":    offer,
		"payload": map[string]any{
			"signature": "0x" + hex.EncodeToString(signature),
			"authorization": &fakeX402Authorization{
				From:        auth.From.Hex(),
				To:          auth.To.Hex(),
				Value:       auth.Value.String(),
				ValidAfter:  strconv.FormatUint(auth.ValidAfter, 10),
				ValidBefore: strconv.FormatUint(auth.ValidBefore, 10),
				Nonce:       "0x" + hex.EncodeToString(auth.Nonce[:]),
			},
		},
	})
	return base64.StdEncoding.EncodeToString(payload)
}

// The offer a 402's PAYMENT-REQUIRED header holds.
func FakeParallelReadChallenge(header string) (*FakeParallelOffer, error) {
	raw, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return nil, err
	}
	var challenge struct {
		X402Version int                  `json:"x402Version"`
		Accepts     []*FakeParallelOffer `json:"accepts"`
	}
	if err := json.Unmarshal(raw, &challenge); err != nil {
		return nil, err
	}
	if challenge.X402Version != fakeX402Version || len(challenge.Accepts) != 1 {
		return nil, fmt.Errorf("%w: a challenge of version %d with %d offers", ErrFakeParallelArgs, challenge.X402Version, len(challenge.Accepts))
	}
	return challenge.Accepts[0], nil
}
