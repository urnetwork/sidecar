//go:build !ios_extension && !sidecar_http

package sidecar_test

// The device's x402 client for Parallel's gateway (SRCH-M13-02), on computetest.FakeParallel and FakeBase with a fake
// clock, a loopback dialer and a broker that opens the payee and signs as searchsigner would, with the real seal and
// digest: the fake gateway checks every signature for real and settles it on the fake chain. The answers are built from
// the gateway's documented schema, never recorded ones.

import (
	"bytes"
	"context"
	"crypto/hpke"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/computetest"
)

// The world a search runs in.
type testWebSearchWorld struct {
	t        *testing.T
	clock    *sidecartest.FakeClock
	base     *computetest.FakeBase
	parallel *computetest.FakeParallel
	payer    *computetest.FakeEvmKey
	signer   hpke.PrivateKey
	line     *sidecar.WebSearchPolicyLine
	policy   *testWebSearchPolicy
	broker   *testWebSearchBroker
	dialer   *testWebSearchDialer
	budget   *testWebSearchBudget
	store    *sidecartest.FakeStore
	outcomes *sidecar.WebSearchOutcomeLog
	client   *sidecar.WebSearchClient
	settings *sidecar.WebSearchSettings
}

// What a world is built with beyond its defaults.
type testWebSearchWorldArgs struct {
	parallelSettings *computetest.FakeParallelSettings
	settings         *sidecar.WebSearchSettings
}

func newTestWebSearchWorld(t *testing.T, args *testWebSearchWorldArgs) *testWebSearchWorld {
	t.Helper()
	if args == nil {
		args = &testWebSearchWorldArgs{}
	}
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	base, err := computetest.NewFakeBase(&computetest.FakeBaseArgs{Clock: clock, Seed: "websearch"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(base.Close)
	parallel, err := computetest.NewFakeParallel(&computetest.FakeParallelArgs{Settings: args.parallelSettings, Clock: clock, Seed: "websearch", Base: base})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(parallel.Close)
	payer := computetest.NewFakeEvmKey("websearch", "payer")
	base.Fund(payer.Address(), big.NewInt(1_000_000_000))
	signer := testWebSearchSignerKey(t, "websearch signer")
	line := &sidecar.WebSearchPolicyLine{
		Host:          computetest.FakeParallelHost,
		Network:       base.Network(),
		ChainId:       base.ChainId(),
		Asset:         sidecar.WebSearchAddress(base.Usdc()),
		AssetName:     computetest.FakeBaseUsdcName,
		AssetVersion:  computetest.FakeBaseUsdcVersion,
		CeilingAmount: 15000,
		Payer:         sidecar.WebSearchAddress(payer.Address()),
		SignerKey:     signer.PublicKey(),
	}
	settings := args.settings
	if settings == nil {
		settings = sidecar.DefaultWebSearchSettings()
	}
	world := &testWebSearchWorld{
		t:        t,
		clock:    clock,
		base:     base,
		parallel: parallel,
		payer:    payer,
		signer:   signer,
		line:     line,
		settings: settings,
		store:    sidecartest.NewFakeStore(),
	}
	world.policy = &testWebSearchPolicy{line: line, price: &sidecar.WebSearchPrice{CatalogVersion: 7, NanoUsdPerSearch: 12_000_000}}
	world.broker = &testWebSearchBroker{world: world}
	world.dialer = &testWebSearchDialer{world: world, exits: []string{"exit-a", "exit-b"}}
	world.budget = &testWebSearchBudget{holds: map[sidecar.Id]int64{}}
	world.outcomes, err = sidecar.NewWebSearchOutcomeLog(&sidecar.WebSearchOutcomeLogArgs{Store: world.store.Root(), Settings: settings, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	world.client = world.newClient()
	return world
}

// A client over the world's seams, as a restart builds one.
func (self *testWebSearchWorld) newClient() *sidecar.WebSearchClient {
	client, err := sidecar.NewWebSearchClient(&sidecar.WebSearchClientArgs{
		Settings: self.settings,
		Policy:   self.policy,
		Broker:   self.broker,
		Dialer:   self.dialer,
		Budget:   self.budget,
		Outcomes: self.outcomes,
		Clock:    self.clock,
		RootCAs:  self.parallel.RootCAs(),
		Version:  "2026.11.27-test",
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return client
}

func testWebSearchQuery() *sidecar.WebSearchQuery {
	return &sidecar.WebSearchQuery{Objective: "synthetic objective for a test", Queries: []string{"synthetic test query"}}
}

// The fake policy: a line and a price, or a refusal.
type testWebSearchPolicy struct {
	stateLock sync.Mutex
	line      *sidecar.WebSearchPolicyLine
	price     *sidecar.WebSearchPrice
	lineErr   error
	priceErr  error
	refreshes int
	// the price RefreshCatalog moves to, nil for none
	refreshed *sidecar.WebSearchPrice
}

func (self *testWebSearchPolicy) Line(ctx context.Context) (*sidecar.WebSearchPolicyLine, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.lineErr != nil {
		return nil, self.lineErr
	}
	return self.line, nil
}

func (self *testWebSearchPolicy) Price(ctx context.Context, engine string, mode string) (*sidecar.WebSearchPrice, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.priceErr != nil {
		return nil, self.priceErr
	}
	if engine != sidecar.WebSearchEngineParallel {
		return nil, errors.New("another engine")
	}
	price := *self.price
	return &price, nil
}

func (self *testWebSearchPolicy) RefreshCatalog(ctx context.Context) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refreshes += 1
	if self.refreshed != nil {
		self.price = self.refreshed
	}
	return nil
}

// One tampering of the signer's authorization, for the device's check.
type testWebSearchTamper func(world *testWebSearchWorld, authorization *protocol.ComputeSearchAuthorization) []byte

// The fake broker: it admits, opens the payee with the signer's key as searchsigner would, signs EIP-3009 with the
// payer key for the minute's window, deterministically, and seals the authorization back; scriptable.
type testWebSearchBroker struct {
	world *testWebSearchWorld

	stateLock sync.Mutex
	// each request received, as its deterministic bytes
	requests [][]byte
	// each answer given, its sealed bytes
	answers [][]byte
	// answers to lose after signing, as a lost connection would
	loseCount int
	// a refusal to answer, nil for none
	refusal *sidecar.ComputeServiceError
	// refusals to answer before the rest, in order
	refusals []*sidecar.ComputeServiceError
	tamper   testWebSearchTamper
	reports  []*protocol.SearchOutcomes
	// the nonces the signer issued, which it refuses again under another request
	nonces map[string]string
}

func (self *testWebSearchBroker) Authorize(ctx context.Context, request *protocol.ComputeSearchAuthorizeRequest) (*protocol.ComputeSearchAuthorizeResponse, error) {
	world := self.world
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	self.requests = append(self.requests, encoded)
	if 0 < len(self.refusals) {
		refusal := self.refusals[0]
		self.refusals = self.refusals[1:]
		self.stateLock.Unlock()
		return nil, refusal
	}
	refusal, tamper := self.refusal, self.tamper
	self.stateLock.Unlock()
	if refusal != nil {
		return nil, refusal
	}
	asset, _ := sidecar.WebSearchAddressOf(request.Asset)
	if asset != world.line.Asset || request.Network != world.line.Network || world.line.CeilingAmount < request.Amount {
		return nil, &sidecar.ComputeServiceError{Route: "POST /v1/search/authorize", Status: http.StatusBadRequest, Code: "capacity"}
	}
	binding := &sidecar.WebSearchSealBinding{Amount: request.Amount, Asset: world.line.Asset, Network: world.line.Network}
	payee, answerKey, err := sidecar.WebSearchOpenPayee(world.signer, request.SealedPayee, binding, world.settings)
	if err != nil {
		return nil, &sidecar.ComputeServiceError{Route: "POST /v1/search/authorize", Status: http.StatusBadRequest, Code: "capacity"}
	}
	self.stateLock.Lock()
	if self.nonces == nil {
		self.nonces = map[string]string{}
	}
	key := fmt.Sprintf("%x/%d", request.RequestId, request.Attempt)
	if issued, ok := self.nonces[string(payee.Nonce)]; ok && issued != key {
		self.stateLock.Unlock()
		return nil, &sidecar.ComputeServiceError{Route: "POST /v1/search/authorize", Status: http.StatusConflict, Code: "capacity"}
	}
	self.nonces[string(payee.Nonce)] = key
	self.stateLock.Unlock()
	minuteS := world.clock.Now().Truncate(time.Minute).Unix()
	validAfter, validBefore, err := sidecar.WebSearchWindow(world.settings, minuteS)
	if err != nil {
		return nil, err
	}
	authorization := &protocol.ComputeSearchAuthorization{
		From:         world.line.Payer[:],
		To:           payee.PayTo,
		Value:        request.Amount,
		ValidAfterS:  validAfter,
		ValidBeforeS: validBefore,
		Nonce:        payee.Nonce,
	}
	var signature []byte
	if tamper != nil {
		signature = tamper(world, authorization)
	}
	if signature == nil {
		digest, err := sidecar.WebSearchTransferDigest(world.line.Domain(), authorization)
		if err != nil {
			return nil, err
		}
		signature = world.payer.SignDigest(digest)
	}
	authorization.Signature = signature
	sealed, err := sidecar.WebSearchSealAuthorization(answerKey, authorization)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.answers = append(self.answers, sealed)
	if 0 < self.loseCount {
		self.loseCount -= 1
		return nil, errors.New("planted: the broker's answer was lost")
	}
	return &protocol.ComputeSearchAuthorizeResponse{SealedAuthorization: sealed}, nil
}

func (self *testWebSearchBroker) ReportOutcomes(ctx context.Context, request *protocol.ComputeSearchOutcomesRequest) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.reports = append(self.reports, proto.Clone(request.Outcomes).(*protocol.SearchOutcomes))
	return nil
}

// The requests the broker received, decoded.
func (self *testWebSearchBroker) received(t *testing.T) []*protocol.ComputeSearchAuthorizeRequest {
	t.Helper()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	out := []*protocol.ComputeSearchAuthorizeRequest{}
	for _, encoded := range self.requests {
		request := &protocol.ComputeSearchAuthorizeRequest{}
		if err := proto.Unmarshal(encoded, request); err != nil {
			t.Fatal(err)
		}
		out = append(out, request)
	}
	return out
}

func (self *testWebSearchBroker) requestCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.requests)
}

// The loopback dialer: sessions over the fake gateway's listener, each on an exit, the last avoided where another is.
type testWebSearchDialer struct {
	world *testWebSearchWorld
	exits []string

	stateLock sync.Mutex
	sessions  []*testWebSearchSession
	asked     []*sidecar.WebSearchSessionArgs
	refuse    error
}

type testWebSearchSession struct {
	dialer *testWebSearchDialer
	exit   string

	stateLock sync.Mutex
	dials     []string
	closed    bool
}

func (self *testWebSearchDialer) Session(ctx context.Context, args *sidecar.WebSearchSessionArgs) (sidecar.WebSearchSession, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	asked := *args
	self.asked = append(self.asked, &asked)
	if self.refuse != nil {
		return nil, self.refuse
	}
	exit := self.exits[0]
	for _, candidate := range self.exits {
		if candidate != args.AvoidExit {
			exit = candidate
			break
		}
	}
	session := &testWebSearchSession{dialer: self, exit: exit}
	self.sessions = append(self.sessions, session)
	return session, nil
}

func (self *testWebSearchSession) Exit() string {
	return self.exit
}

func (self *testWebSearchSession) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	self.stateLock.Lock()
	self.dials = append(self.dials, address)
	self.stateLock.Unlock()
	return self.dialer.world.parallel.DialContext(ctx, network, address)
}

func (self *testWebSearchSession) Close() error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.closed = true
	return nil
}

// The fake budgets: each hold, and how it ended.
type testWebSearchBudget struct {
	stateLock sync.Mutex
	holds     map[sidecar.Id]int64
	settled   []int64
	released  int
	refuse    error
	agents    []*sidecar.Id
}

func (self *testWebSearchBudget) Hold(ctx context.Context, holdId sidecar.Id, agentId *sidecar.Id, priceNanoUsd int64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.refuse != nil {
		return self.refuse
	}
	self.holds[holdId] = priceNanoUsd
	self.agents = append(self.agents, agentId)
	return nil
}

func (self *testWebSearchBudget) Settle(holdId sidecar.Id, priceNanoUsd int64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.holds, holdId)
	self.settled = append(self.settled, priceNanoUsd)
	return nil
}

func (self *testWebSearchBudget) Release(holdId sidecar.Id) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.holds, holdId)
	self.released += 1
	return nil
}

// The paid requests the gateway received.
func testWebSearchPaid(requests []*computetest.FakeParallelRequest) []*computetest.FakeParallelRequest {
	paid := []*computetest.FakeParallelRequest{}
	for _, request := range requests {
		if request.Payment != nil {
			paid = append(paid, request)
		}
	}
	return paid
}

// Returns once a timer due at at is pending on clock, or ctx ends: how a test knows the search waits there, with no
// sleep, where other timers come and go.
func testAwaitTimerAt(ctx context.Context, clock *sidecartest.FakeClock, at time.Time) error {
	for {
		pending, added := clock.WatchTimers()
		if slices.ContainsFunc(pending, at.Equal) {
			return nil
		}
		select {
		case <-added:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Runs search on its own goroutine, its answer and error on the channel.
type testWebSearchResult struct {
	answer *sidecar.WebSearchAnswer
	err    error
}

func (self *testWebSearchWorld) searchAsync(ctx context.Context, query *sidecar.WebSearchQuery) <-chan *testWebSearchResult {
	done := make(chan *testWebSearchResult, 1)
	go func() {
		answer, err := self.client.Search(ctx, query)
		done <- &testWebSearchResult{answer: answer, err: err}
	}()
	return done
}

// One search to the gateway: one 402, one authorization, one paid retry, the results parsed and the payment settled
// once on the chain.
func TestWebSearchClientPaysOnce(t *testing.T) {
	world := newTestWebSearchWorld(t, nil)
	agentId := sidecar.NewId()
	query := testWebSearchQuery()
	query.AgentId = &agentId
	journaled := []*sidecar.WebSearchPayment{}
	query.BeforePay = func(payment *sidecar.WebSearchPayment) error {
		journaled = append(journaled, payment)
		return nil
	}
	answer, err := world.client.Search(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	if len(answer.Results) != 3 || answer.Results[0].Url == "" || answer.Results[0].Title == "" || len(answer.Results[0].Excerpts) != 1 {
		t.Fatalf("results %+v", answer.Results)
	}
	requests := world.parallel.Requests()
	if len(requests) != 2 || requests[0].Status != http.StatusPaymentRequired || requests[1].Status != http.StatusOK {
		t.Fatalf("the gateway saw %d requests", len(requests))
	}
	settlements := world.parallel.Settlements()
	if len(settlements) != 1 {
		t.Fatalf("%d settlements", len(settlements))
	}
	if !world.base.AuthorizationUsed(world.payer.Address(), [32]byte(answer.Nonce)) {
		t.Fatal("the chain shows the nonce unused")
	}
	received := world.broker.received(t)
	if len(received) != 1 || received[0].Attempt != 1 || len(received[0].RequestId) != 16 || received[0].Amount != 10000 ||
		received[0].CatalogVersion != 7 || !bytes.Equal(received[0].AgentId, agentId.Bytes()) {
		t.Fatalf("the broker received %v", received)
	}
	if len(journaled) != 1 || !bytes.Equal(journaled[0].Nonce, answer.Nonce) || journaled[0].MinuteS != answer.MinuteS {
		t.Fatalf("journaled %+v", journaled)
	}
	if answer.PriceNanoUsd != 12_000_000 || answer.Amount != 10000 || answer.Mode != sidecar.WebSearchModeFast {
		t.Fatalf("price %d, amount %d, mode %s", answer.PriceNanoUsd, answer.Amount, answer.Mode)
	}
	if len(answer.Transaction) != 32 || !bytes.Equal(answer.Transaction, settlements[0].Receipt.TxHash[:]) {
		t.Fatalf("the transaction %x", answer.Transaction)
	}
	if len(world.budget.settled) != 1 || world.budget.settled[0] != 12_000_000 || world.budget.released != 0 {
		t.Fatalf("the budget settled %v and released %d", world.budget.settled, world.budget.released)
	}
	// the broker saw neither the payee nor the nonce
	for _, encoded := range world.broker.requests {
		offer := requests[0].Offer
		payTo, _ := sidecar.ParseWebSearchAddress(offer.PayTo)
		if bytes.Contains(encoded, payTo[:]) || bytes.Contains(encoded, answer.Nonce) {
			t.Fatal("the broker's request holds the payee or the nonce")
		}
	}
}

// Each offer off the policy or the catalog is refused unpaid, with no byte to the broker: another host, scheme, network,
// asset, EIP-712 name or version, a maxTimeoutSeconds under 120, an amount past the ceiling or the catalog's price.
func TestWebSearchClientRefusesBadOffer(t *testing.T) {
	cases := []struct {
		name     string
		parallel func(settings *computetest.FakeParallelSettings)
		line     func(line *sidecar.WebSearchPolicyLine)
		price    int64
	}{
		{name: "network", line: func(line *sidecar.WebSearchPolicyLine) { line.Network = "eip155:1"; line.ChainId = 1 }},
		{name: "asset", line: func(line *sidecar.WebSearchPolicyLine) { line.Asset[0] ^= 0xff }},
		{name: "name", line: func(line *sidecar.WebSearchPolicyLine) { line.AssetName = "Synthetic Dollar" }},
		{name: "version", line: func(line *sidecar.WebSearchPolicyLine) { line.AssetVersion = "1" }},
		{name: "timeout", parallel: func(settings *computetest.FakeParallelSettings) { settings.MaxTimeout = 119 * time.Second }},
		{name: "ceiling", parallel: func(settings *computetest.FakeParallelSettings) { settings.SearchAmount = 15001 }},
		{name: "catalog", price: 11_900_000},
	}
	for _, c := range cases {
		parallelSettings := computetest.DefaultFakeParallelSettings()
		if c.parallel != nil {
			c.parallel(parallelSettings)
		}
		world := newTestWebSearchWorld(t, &testWebSearchWorldArgs{parallelSettings: parallelSettings})
		if c.line != nil {
			line := *world.line
			c.line(&line)
			world.policy.line = &line
		}
		if c.price != 0 {
			world.policy.price.NanoUsdPerSearch = c.price
		}
		_, err := world.client.Search(context.Background(), testWebSearchQuery())
		if sidecar.WebSearchErrorCode(err) != sidecar.WebSearchCodeBadOffer {
			t.Errorf("%s: %v", c.name, err)
		}
		if world.broker.requestCount() != 0 || len(testWebSearchPaid(world.parallel.Requests())) != 0 {
			t.Errorf("%s: a byte reached the broker or a payment left", c.name)
		}
		if len(world.budget.holds) != 0 {
			t.Errorf("%s: a hold was left open", c.name)
		}
	}
}

// Another payee, value, nonce, window or payer, or a signature that recovers elsewhere, is refused before the paid
// retry: no payment leaves, and the outcome is refused.
func TestWebSearchClientChecksAuthorization(t *testing.T) {
	other := computetest.NewFakeEvmKey("websearch", "another key")
	tampers := map[string]testWebSearchTamper{
		"payee": func(world *testWebSearchWorld, authorization *protocol.ComputeSearchAuthorization) []byte {
			authorization.To = bytes.Repeat([]byte{0x11}, 20)
			return nil
		},
		"value": func(world *testWebSearchWorld, authorization *protocol.ComputeSearchAuthorization) []byte {
			authorization.Value += 1
			return nil
		},
		"nonce": func(world *testWebSearchWorld, authorization *protocol.ComputeSearchAuthorization) []byte {
			authorization.Nonce = bytes.Repeat([]byte{0x22}, 32)
			return nil
		},
		"window": func(world *testWebSearchWorld, authorization *protocol.ComputeSearchAuthorization) []byte {
			authorization.ValidBeforeS += 60
			return nil
		},
		"stale minute": func(world *testWebSearchWorld, authorization *protocol.ComputeSearchAuthorization) []byte {
			authorization.ValidAfterS -= 600
			authorization.ValidBeforeS -= 600
			return nil
		},
		"signer": func(world *testWebSearchWorld, authorization *protocol.ComputeSearchAuthorization) []byte {
			digest, err := sidecar.WebSearchTransferDigest(world.line.Domain(), authorization)
			if err != nil {
				return nil
			}
			return other.SignDigest(digest)
		},
		"payer": func(world *testWebSearchWorld, authorization *protocol.ComputeSearchAuthorization) []byte {
			address := other.Address()
			authorization.From = address[:]
			digest, _ := sidecar.WebSearchTransferDigest(world.line.Domain(), authorization)
			return other.SignDigest(digest)
		},
	}
	for name, tamper := range tampers {
		world := newTestWebSearchWorld(t, nil)
		world.broker.tamper = tamper
		_, err := world.client.Search(context.Background(), testWebSearchQuery())
		if sidecar.WebSearchErrorCode(err) != sidecar.WebSearchCodeRefused {
			t.Errorf("%s: %v", name, err)
		}
		if paid := testWebSearchPaid(world.parallel.Requests()); len(paid) != 0 {
			t.Errorf("%s: %d paid retries left", name, len(paid))
		}
		if outcomes, _ := world.outcomes.Unreported(); outcomes.GetRefused() != 1 {
			t.Errorf("%s: outcomes %v", name, outcomes)
		}
		if world.budget.released != 1 || len(world.budget.settled) != 0 {
			t.Errorf("%s: the hold was not released", name)
		}
	}
}

// The body holds the gateway's documented fields alone, objective left out when empty, and the requests the fixed
// headers alone, the payment's only on the paid retry; a query goes to the policy's host alone.
func TestWebSearchClientBodyAndHeaders(t *testing.T) {
	world := newTestWebSearchWorld(t, nil)
	query := testWebSearchQuery()
	query.Mode = sidecar.WebSearchModeAdvanced
	if _, err := world.client.Search(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	noObjective := &sidecar.WebSearchQuery{Queries: []string{"synthetic first", "synthetic second"}}
	if _, err := world.client.Search(context.Background(), noObjective); err != nil {
		t.Fatal(err)
	}
	requests := world.parallel.Requests()
	if len(requests) != 4 {
		t.Fatalf("%d requests", len(requests))
	}
	allowed := []string{"Content-Type", "Accept-Encoding", "User-Agent", "Content-Length"}
	for i, request := range requests {
		if len(request.UnknownFields) != 0 || request.Query != "" {
			t.Errorf("request %d carried %v and query %q", i, request.UnknownFields, request.Query)
		}
		names := slices.Sorted(func(yield func(string) bool) {
			for name := range request.Header {
				if !yield(name) {
					return
				}
			}
		})
		for _, name := range names {
			if !slices.Contains(allowed, name) && !(request.Payment != nil && name == http.CanonicalHeaderKey(world.settings.PaymentHeader)) {
				t.Errorf("request %d carried header %s", i, name)
			}
		}
		if request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept-Encoding") != "identity" ||
			request.Header.Get("User-Agent") != "ur/2026.11.27-test" {
			t.Errorf("request %d's fixed headers: %v", i, request.Header)
		}
		if (request.Payment != nil) != (i%2 == 1) {
			t.Errorf("request %d's payment: %v", i, request.Payment != nil)
		}
	}
	var first map[string]any
	if err := json.Unmarshal(requests[0].Body, &first); err != nil {
		t.Fatal(err)
	}
	if len(first) != 3 || first["objective"] != query.Objective || first["mode"] != "advanced" {
		t.Errorf("the first body %s", requests[0].Body)
	}
	var second map[string]any
	if err := json.Unmarshal(requests[2].Body, &second); err != nil {
		t.Fatal(err)
	}
	if _, ok := second["objective"]; ok || len(second) != 2 || second["mode"] != "fast" {
		t.Errorf("the second body %s", requests[2].Body)
	}
	if !bytes.Equal(requests[0].Body, requests[1].Body) || !bytes.Equal(requests[2].Body, requests[3].Body) {
		t.Error("a paid retry's body is not its request's")
	}
	for _, session := range world.dialer.sessions {
		for _, dial := range session.dials {
			if dial != computetest.FakeParallelHost+":443" {
				t.Errorf("a dial to %s", dial)
			}
		}
	}
	// a query past the gateway's limits is refused before anything
	for _, planted := range []*sidecar.WebSearchQuery{
		{Queries: nil},
		{Queries: []string{"a", "b", "c", "d", "e", "f"}},
		{Queries: []string{strings.Repeat("x", 201)}},
		{Queries: []string{" "}},
		{Queries: []string{"synthetic"}, Objective: strings.Repeat("o", 5001)},
		{Queries: []string{"synthetic"}, Mode: "news"},
	} {
		if _, err := world.client.Search(context.Background(), planted); sidecar.WebSearchErrorCode(err) != sidecar.WebSearchCodeInvalid {
			t.Errorf("%+v: %v", planted, err)
		}
	}
	if len(world.parallel.Requests()) != 4 {
		t.Error("a refused query reached the gateway")
	}
}

// The unpaid request and its paid retry share one connection, so both leave by one exit.
func TestWebSearchClientOneConnection(t *testing.T) {
	world := newTestWebSearchWorld(t, nil)
	if _, err := world.client.Search(context.Background(), testWebSearchQuery()); err != nil {
		t.Fatal(err)
	}
	requests := world.parallel.Requests()
	if len(requests) != 2 || requests[0].ConnectionId == 0 || requests[0].ConnectionId != requests[1].ConnectionId {
		t.Fatalf("connections %d and %d", requests[0].ConnectionId, requests[1].ConnectionId)
	}
	if len(world.dialer.sessions) != 1 || len(world.dialer.sessions[0].dials) != 1 || !world.dialer.sessions[0].closed {
		t.Fatal("not one session with one dial, closed after")
	}
}

// A second 402 after paying takes attempt 2, a new nonce and its own hold under the same request id; at most 3.
func TestWebSearchClientAttempts(t *testing.T) {
	world := newTestWebSearchWorld(t, nil)
	world.parallel.Script(&computetest.FakeParallelStep{Outcome: computetest.FakeParallelPayeeAgedOut})
	answer, err := world.client.Search(context.Background(), testWebSearchQuery())
	if err != nil {
		t.Fatal(err)
	}
	received := world.broker.received(t)
	if len(received) != 2 || received[0].Attempt != 1 || received[1].Attempt != 2 ||
		!bytes.Equal(received[0].RequestId, received[1].RequestId) || bytes.Equal(received[0].SealedPayee, received[1].SealedPayee) {
		t.Fatalf("the broker received %v", received)
	}
	if answer.Attempt != 2 || len(world.parallel.Settlements()) != 1 {
		t.Fatalf("attempt %d, %d settlements", answer.Attempt, len(world.parallel.Settlements()))
	}
	paid := testWebSearchPaid(world.parallel.Requests())
	if len(paid) != 2 || paid[0].Payment.Authorization.Nonce == paid[1].Payment.Authorization.Nonce {
		t.Fatal("the two attempts did not pay with two nonces")
	}
	if len(world.budget.settled) != 2 {
		t.Fatalf("%d holds settled: each attempt's payment may have settled", len(world.budget.settled))
	}

	// three lost payees: refused after the third attempt, never a fourth
	world = newTestWebSearchWorld(t, nil)
	for range 3 {
		world.parallel.Script(&computetest.FakeParallelStep{Outcome: computetest.FakeParallelPayeeAgedOut})
	}
	if _, err := world.client.Search(context.Background(), testWebSearchQuery()); sidecar.WebSearchErrorCode(err) != sidecar.WebSearchCodeRefused {
		t.Fatalf("three lost payees: %v", err)
	}
	if received := world.broker.received(t); len(received) != 3 || received[2].Attempt != 3 {
		t.Fatalf("the broker received %d requests", len(received))
	}
	if outcomes, _ := world.outcomes.Unreported(); outcomes.GetRefused() != 1 {
		t.Fatalf("outcomes %v", outcomes)
	}
}

// A lost answer from the broker is asked again with the same request id, attempt and sealed bytes, and the signer's
// answer is the same authorization: one payment.
func TestWebSearchClientRetrySameAuthorization(t *testing.T) {
	world := newTestWebSearchWorld(t, nil)
	world.broker.loseCount = 2
	if _, err := world.client.Search(context.Background(), testWebSearchQuery()); err != nil {
		t.Fatal(err)
	}
	if len(world.broker.requests) != 3 {
		t.Fatalf("%d requests", len(world.broker.requests))
	}
	for i := range world.broker.requests[1:] {
		if !bytes.Equal(world.broker.requests[i+1], world.broker.requests[0]) {
			t.Fatal("a retry's bytes are not the first request's")
		}
		if !bytes.Equal(world.broker.answers[i+1], world.broker.answers[0]) {
			t.Fatal("the signer's answers to one request differ")
		}
	}
	if len(world.parallel.Settlements()) != 1 {
		t.Fatal("more than one payment")
	}
	// a broker that never answers: capacity, nothing paid
	world = newTestWebSearchWorld(t, nil)
	world.broker.loseCount = 10
	if _, err := world.client.Search(context.Background(), testWebSearchQuery()); sidecar.WebSearchErrorCode(err) != sidecar.WebSearchCodeCapacity {
		t.Fatalf("a broker that never answers: %v", err)
	}
	if len(world.broker.requests) != world.settings.BrokerRetryCount+1 || len(testWebSearchPaid(world.parallel.Requests())) != 0 {
		t.Fatal("asked past the retries, or paid")
	}
}

// The broker's refusals answer as the search's, nothing paid and the hold released: search_off, insufficient_quota,
// rate_limited with its time, payee_refused, capacity; catalog_stale fetches the catalog and asks once more.
func TestWebSearchClientBrokerRefusals(t *testing.T) {
	for _, code := range []string{"search_off", "insufficient_quota", "rate_limited", "payee_refused", "capacity", "held"} {
		world := newTestWebSearchWorld(t, nil)
		world.broker.refusal = &sidecar.ComputeServiceError{Route: "POST /v1/search/authorize", Status: http.StatusForbidden, Code: code, RetryAfter: 5 * time.Second}
		_, err := world.client.Search(context.Background(), testWebSearchQuery())
		want := code
		if code == "held" {
			want = sidecar.WebSearchCodeCapacity
		}
		var refusal *sidecar.WebSearchError
		if !errors.As(err, &refusal) || refusal.Code != want || refusal.RetryAfter != 5*time.Second {
			t.Errorf("%s: %v", code, err)
		}
		if len(testWebSearchPaid(world.parallel.Requests())) != 0 || world.budget.released != 1 {
			t.Errorf("%s: paid, or the hold kept", code)
		}
	}
	world := newTestWebSearchWorld(t, nil)
	world.broker.refusals = []*sidecar.ComputeServiceError{{Route: "POST /v1/search/authorize", Status: http.StatusConflict, Code: "catalog_stale"}}
	world.policy.refreshed = &sidecar.WebSearchPrice{CatalogVersion: 8, NanoUsdPerSearch: 12_000_000}
	if _, err := world.client.Search(context.Background(), testWebSearchQuery()); err != nil {
		t.Fatal(err)
	}
	received := world.broker.received(t)
	if len(received) != 2 || received[0].CatalogVersion != 7 || received[1].CatalogVersion != 8 || world.policy.refreshes != 1 {
		t.Fatalf("catalog_stale: %d requests, refreshed %d", len(received), world.policy.refreshes)
	}
}

// A 429 waits its Retry-After and goes again through the same exit, never another; past its retries the search is
// refused.
func TestWebSearchClient429SameExit(t *testing.T) {
	world := newTestWebSearchWorld(t, nil)
	world.parallel.Script(&computetest.FakeParallelStep{Outcome: computetest.FakeParallelRateLimited, PaidOnly: true, RetryAfter: 7 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	done := world.searchAsync(ctx, testWebSearchQuery())
	if err := testAwaitTimerAt(ctx, world.clock, world.clock.Now().Add(7*time.Second)); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(7 * time.Second)
	result := <-done
	if result.err != nil {
		t.Fatal(result.err)
	}
	requests := world.parallel.Requests()
	if len(requests) != 3 || requests[1].Status != http.StatusTooManyRequests || requests[2].Status != http.StatusOK {
		t.Fatalf("%d requests", len(requests))
	}
	if len(world.dialer.sessions) != 1 {
		t.Fatalf("%d sessions: the retry moved exits", len(world.dialer.sessions))
	}
	paidHeader := http.CanonicalHeaderKey(world.settings.PaymentHeader)
	if requests[1].Header.Get(paidHeader) == "" || requests[1].Header.Get(paidHeader) != requests[2].Header.Get(paidHeader) || len(world.broker.requests) != 1 {
		t.Fatal("the retry asked for another authorization")
	}
	if requests[0].ConnectionId != requests[1].ConnectionId || requests[1].ConnectionId != requests[2].ConnectionId {
		t.Fatal("the retry left on another connection")
	}

	// past its retries: refused
	world = newTestWebSearchWorld(t, nil)
	for range world.settings.RateLimitedRetryCount + 1 {
		world.parallel.Script(&computetest.FakeParallelStep{Outcome: computetest.FakeParallelRateLimited, PaidOnly: true, RetryAfter: time.Second})
	}
	done = world.searchAsync(ctx, testWebSearchQuery())
	for range world.settings.RateLimitedRetryCount {
		if err := testAwaitTimerAt(ctx, world.clock, world.clock.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		world.clock.Advance(time.Second)
	}
	if result := <-done; sidecar.WebSearchErrorCode(result.err) != sidecar.WebSearchCodeRefused {
		t.Fatalf("past the retries: %v", result.err)
	}
	if outcomes, _ := world.outcomes.Unreported(); outcomes.GetRefused() != 1 {
		t.Fatalf("outcomes %v", outcomes)
	}
}

// Each paid search counts one class: ok, provider_error for an upstream error after settlement, timeout for no answer
// in 30 s on the fake clock, refused for a paid retry the gateway refused.
func TestWebSearchClientOutcomeClasses(t *testing.T) {
	world := newTestWebSearchWorld(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := world.client.Search(ctx, testWebSearchQuery()); err != nil {
		t.Fatal(err)
	}
	world.parallel.Script(&computetest.FakeParallelStep{Outcome: computetest.FakeParallelUpstreamFailure})
	if _, err := world.client.Search(ctx, testWebSearchQuery()); sidecar.WebSearchErrorCode(err) != sidecar.WebSearchCodeProviderError {
		t.Fatalf("an upstream failure: %v", err)
	}
	world.parallel.Script(&computetest.FakeParallelStep{Outcome: computetest.FakeParallelLostAnswer})
	if _, err := world.client.Search(ctx, testWebSearchQuery()); sidecar.WebSearchErrorCode(err) != sidecar.WebSearchCodeProviderError {
		t.Fatalf("a lost answer: %v", err)
	}
	stall := computetest.NewFakeParallelStall()
	world.parallel.Script(&computetest.FakeParallelStep{Outcome: computetest.FakeParallelStalled, Stall: stall})
	done := world.searchAsync(ctx, testWebSearchQuery())
	select {
	case <-stall.Reached():
	case <-ctx.Done():
		t.Fatal("the stall was never reached")
	}
	world.clock.Advance(29 * time.Second)
	select {
	case result := <-done:
		t.Fatalf("answered before 30 s: %v", result.err)
	default:
	}
	world.clock.Advance(time.Second)
	if result := <-done; sidecar.WebSearchErrorCode(result.err) != sidecar.WebSearchCodeTimeout {
		t.Fatalf("a stalled answer: %v", result.err)
	}
	for range 3 {
		world.parallel.Script(&computetest.FakeParallelStep{Outcome: computetest.FakeParallelPayeeAgedOut})
	}
	if _, err := world.client.Search(ctx, testWebSearchQuery()); sidecar.WebSearchErrorCode(err) != sidecar.WebSearchCodeRefused {
		t.Fatalf("a refused paid retry: %v", err)
	}
	outcomes, err := world.outcomes.Unreported()
	if err != nil {
		t.Fatal(err)
	}
	// the first search's ok rode the second's authorization, and so on: what is left is what no later search carried
	reported := &protocol.SearchOutcomes{}
	for _, request := range world.broker.received(t) {
		if request.Outcomes != nil {
			reported.Ok += request.Outcomes.Ok
			reported.ProviderError += request.Outcomes.ProviderError
			reported.Timeout += request.Outcomes.Timeout
			reported.Refused += request.Outcomes.Refused
		}
	}
	total := &protocol.SearchOutcomes{Ok: reported.Ok + outcomes.GetOk(), ProviderError: reported.ProviderError + outcomes.GetProviderError(),
		Timeout: reported.Timeout + outcomes.GetTimeout(), Refused: reported.Refused + outcomes.GetRefused()}
	if !proto.Equal(total, &protocol.SearchOutcomes{Ok: 1, ProviderError: 2, Timeout: 1, Refused: 1}) {
		t.Fatalf("outcomes %v and %v reported", outcomes, reported)
	}
}

// With no search line, or a lapsed ticket, the policy answers search_off, and nothing is sent: no dial, no broker.
func TestWebSearchClientNoSearchLine(t *testing.T) {
	world := newTestWebSearchWorld(t, nil)
	world.policy.lineErr = &sidecar.WebSearchError{Code: sidecar.WebSearchCodeSearchOff, Message: "the signed policy carries no search line"}
	if _, err := world.client.Search(context.Background(), testWebSearchQuery()); sidecar.WebSearchErrorCode(err) != sidecar.WebSearchCodeSearchOff {
		t.Fatalf("no search line: %v", err)
	}
	if len(world.dialer.asked) != 0 || world.broker.requestCount() != 0 || len(world.parallel.Requests()) != 0 || len(world.budget.agents) != 0 {
		t.Fatal("something was sent with no search line")
	}
	// no catalog entry for the mode: search_off the same
	world.policy.lineErr = nil
	world.policy.priceErr = &sidecar.WebSearchError{Code: sidecar.WebSearchCodeSearchOff, Message: "the catalog lists no search/parallel/fast"}
	if _, err := world.client.Search(context.Background(), testWebSearchQuery()); sidecar.WebSearchErrorCode(err) != sidecar.WebSearchCodeSearchOff {
		t.Fatalf("no catalog entry: %v", err)
	}
	if len(world.parallel.Requests()) != 0 {
		t.Fatal("something was sent with no catalog entry")
	}
}

// A lapsed freshness ticket answers search_off through the policy: nothing is sent, and a search goes once a current
// ticket is held again.
func TestWebSearchClientTicketLapsed(t *testing.T) {
	world := newTestWebSearchWorld(t, nil)
	world.policy.lineErr = &sidecar.WebSearchError{Code: sidecar.WebSearchCodeSearchOff, Message: "the compute policy's freshness ticket lapsed"}
	if _, err := world.client.Search(context.Background(), testWebSearchQuery()); sidecar.WebSearchErrorCode(err) != sidecar.WebSearchCodeSearchOff {
		t.Fatalf("a lapsed ticket: %v", err)
	}
	if len(world.parallel.Requests()) != 0 || world.broker.requestCount() != 0 {
		t.Fatal("something was sent under a lapsed ticket")
	}
	world.policy.lineErr = nil
	if _, err := world.client.Search(context.Background(), testWebSearchQuery()); err != nil {
		t.Fatalf("a current ticket again: %v", err)
	}
}

// At most 25 searches a minute from a device: the 26th is rate_limited with when a place frees, before anything is
// sent, and one goes again once the window passes.
func TestWebSearchClientPace(t *testing.T) {
	world := newTestWebSearchWorld(t, nil)
	world.dialer.refuse = errors.New("planted: no egress, so each search ends after its place in the pace")
	for i := range world.settings.DevicePaceCount {
		if _, err := world.client.Search(context.Background(), testWebSearchQuery()); sidecar.WebSearchErrorCode(err) != sidecar.WebSearchCodeUnavailable {
			t.Fatalf("search %d: %v", i, err)
		}
		world.clock.Advance(time.Second)
	}
	var refusal *sidecar.WebSearchError
	if _, err := world.client.Search(context.Background(), testWebSearchQuery()); !errors.As(err, &refusal) || refusal.Code != sidecar.WebSearchCodeRateLimited ||
		refusal.RetryAfter != 35*time.Second {
		t.Fatalf("the 26th: %v", err)
	}
	if len(world.dialer.asked) != world.settings.DevicePaceCount {
		t.Fatal("the 26th asked for egress")
	}
	world.clock.Advance(35 * time.Second)
	if _, err := world.client.Search(context.Background(), testWebSearchQuery()); sidecar.WebSearchErrorCode(err) != sidecar.WebSearchCodeUnavailable {
		t.Fatalf("after the window: %v", err)
	}
}

// Every search asks for auto egress, whatever the network's own egress (a network whose fetch egress is exits searches
// through auto all the same), on an exit other than the last search's where the egress offers one.
func TestWebSearchClientAutoEgress(t *testing.T) {
	world := newTestWebSearchWorld(t, nil)
	for range 3 {
		if _, err := world.client.Search(context.Background(), testWebSearchQuery()); err != nil {
			t.Fatal(err)
		}
	}
	if len(world.dialer.asked) != 3 {
		t.Fatalf("%d sessions asked", len(world.dialer.asked))
	}
	for i, asked := range world.dialer.asked {
		if asked.Egress != sidecar.AclComputeEgressAuto {
			t.Errorf("search %d asked for %q egress", i, asked.Egress)
		}
	}
	if world.dialer.asked[0].AvoidExit != "" || world.dialer.asked[1].AvoidExit != "exit-a" || world.dialer.asked[2].AvoidExit != "exit-b" {
		t.Fatalf("the exits avoided: %q %q %q", world.dialer.asked[0].AvoidExit, world.dialer.asked[1].AvoidExit, world.dialer.asked[2].AvoidExit)
	}
	exits := []string{}
	for _, session := range world.dialer.sessions {
		exits = append(exits, session.exit)
	}
	if !slices.Equal(exits, []string{"exit-a", "exit-b", "exit-a"}) {
		t.Fatalf("exits %v", exits)
	}
	// with no egress the search is unavailable before a byte leaves
	world.dialer.refuse = sidecar.ErrWebSearchNoEgress
	if _, err := world.client.Search(context.Background(), testWebSearchQuery()); sidecar.WebSearchErrorCode(err) != sidecar.WebSearchCodeUnavailable {
		t.Fatalf("no egress: %v", err)
	}
}

// The device's budget check comes first: a search with no room is insufficient_quota before a byte leaves for the
// gateway or the broker.
func TestWebSearchClientBudgetFirst(t *testing.T) {
	world := newTestWebSearchWorld(t, nil)
	world.budget.refuse = errors.New("planted: the agent's day budget is spent")
	if _, err := world.client.Search(context.Background(), testWebSearchQuery()); sidecar.WebSearchErrorCode(err) != sidecar.WebSearchCodeInsufficientQuota {
		t.Fatalf("no room: %v", err)
	}
	if world.broker.requestCount() != 0 || len(world.parallel.Requests()) != 0 || len(world.dialer.asked) != 0 {
		t.Fatal("past the budget, the gateway or the broker was asked")
	}
}
