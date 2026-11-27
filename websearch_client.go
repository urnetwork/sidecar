//go:build !ios_extension && !sidecar_http

// The device's x402 client for Parallel's keyless gateway (DESIGN-COMPUTE §21.3, §21.4, §21.5, §21.8, §21.9, CF-13's
// device half, R-SRCH-3, R-SRCH-4, R-SRCH-7, D-SRCH-2, D-SRCH-3, D-SRCH-9, IC-2, IC-15, compute-11; SRCH-M13-02). One
// search, WebSearchClient.Search:
//
//  1. policy    the newest verified policy's search line under a current freshness ticket, and the catalog's
//     search/parallel/<mode> at its price (WebSearchPolicy); else search_off, nothing sent
//  2. budget    the device's own budget check holds the search's price first (WebSearchBudget, INFER's ledger), since a
//     query the broker then refuses has reached the gateway unpaid: insufficient_quota
//  3. pace      at most DevicePaceCount searches a DevicePaceWindow from this device: rate_limited
//  4. egress    a session on auto egress whatever the network's egress mode (R-SRCH-4), on an exit other than the last
//     search's where the egress offers one (WebSearchDialer): DoH through it, the policy's host dialed pinned, TLS to
//     that host alone, so a query goes nowhere but there; no egress answers unavailable
//  5. request   POST /api/search, its JSON body objective (left out when empty), search_queries and mode alone, never
//     session_id, advanced_settings, a location or a client model, with Content-Type, Accept-Encoding and a
//     User-Agent naming ur and its version, nothing else
//  6. offer     the 402's x402 v2 offer checked against the policy and the catalog (websearch_x402.go): bad_offer, unpaid
//  7. admission a 32-byte nonce and a 16-byte request id drawn; {pay_to, nonce} sealed to searchsigner
//     (websearch_seal.go) and POST compute/v1/search/authorize with this device's unreported outcomes; a lost answer
//     asked again with the same request id, attempt and sealed bytes, which the signer re-signs to the same bytes
//  8. check     the answer opened under the device's own request and held to the same payee and value, its own nonce,
//     the fixed window of a minute near this device's clock, and a signature recovering to the policy's payer;
//     else refused, counted, nothing paid
//  9. paid      before it leaves, the query's BeforePay is told the payment's nonce and minute (the tool journals them);
//     then the same body, on the same connection, with x402 v2's payload base64 in the settings' header
//  10. answer    read within AnswerTimeout of the paid retry leaving and AnswerMaxByteCount: search_id, results (url,
//     title, publish_date, excerpts), warnings, usage, session_id, and PAYMENT-RESPONSE's transaction where sent
//  11. retries   a 402 after paying (the gateway lost its payee) takes the next attempt, a new nonce and its own hold
//     under the same request id, up to AttemptMaxCount; a 429 waits its Retry-After and goes again through the same
//     exit, never another (§21.9), at most RateLimitedRetryCount times
//  12. outcome   every search that reached its paid retry counts one class: ok, provider_error (an error or unreadable
//     answer after payment), timeout (no answer within AnswerTimeout) or refused (the paid retry refused: a second
//     402 past the last attempt, a payment error, a 429 past its retries); and so does an authorization refused at
//     the check
//  13. answer    WebSearchAnswer: the results, the raw answer's SHA-256, the nonce, the minute, the transaction and the
//     price, for the tool's stub
//
// The unpaid request and its paid retry share one connection, so both leave by one exit; one the gateway closes is
// dialed again through the same session. Task, Responses, Extract and the MPP rail are never called (R-SRCH-7). A
// payment that may have settled is never offered against a new 402, and an answer lost after it is paid for (CO-30).
// No query, objective or result reaches a log, a metric or an error.
//
// Safe for concurrent use: the pace and the last exit sit under stateLock; each search keeps its own state.

package sidecar

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/urnetwork/sidecar/protocol"
)

// The codes a search ends with after its payment: its outcome class, which the tool shows, and the one a search that
// never reached the gateway answers.
const (
	WebSearchCodeProviderError = WebSearchOutcomeProviderError
	WebSearchCodeTimeout       = WebSearchOutcomeTimeout
	WebSearchCodeUnavailable   = "unavailable"
)

// One search as the tool or `ur search` asks it.
type WebSearchQuery struct {
	// One sentence on what is wanted; empty leaves it out of the body.
	Objective string
	// One to QueryMaxCount keyword queries.
	Queries []string
	// One of WebSearchModes; empty is fast.
	Mode string
	// The agent the search is charged to (§21.9), nil for none: a terminal search naming no agent.
	AgentId *Id
	// Called once before each paid retry leaves, with the payment the search is about to make; an error stops the
	// search unpaid. Nil calls nothing.
	BeforePay func(payment *WebSearchPayment) error
}

// A payment a search is about to make: what the tool journals so the charge check counts a search whose answer is lost.
type WebSearchPayment struct {
	RequestId []byte
	Attempt   uint32
	Nonce     []byte
	MinuteS   int64
}

// One result, from the gateway's answer's whitelist.
type WebSearchResult struct {
	Url         string
	Title       string
	PublishDate string
	Excerpts    []string
}

// A served search.
type WebSearchAnswer struct {
	Results  []*WebSearchResult
	Warnings []string
	// SHA-256 of the gateway's answer as received.
	AnswerSha256 [sha256.Size]byte
	// The payment that bought it: its nonce, its minute, its request id and attempt, and its transaction where the
	// gateway named one.
	Nonce       []byte
	MinuteS     int64
	RequestId   []byte
	Attempt     uint32
	Transaction []byte
	// The authorization's value in the asset's units, and what the network is charged for it, in nano-USD.
	Amount       uint64
	PriceNanoUsd int64
	Mode         string
}

// What a session is asked for.
type WebSearchSessionArgs struct {
	// Always auto for a search (R-SRCH-4): an exit of the network's own would show Parallel an address of theirs.
	Egress AclComputeEgress
	// The last search's exit, which this one leaves by only where the egress offers no other; empty for none.
	AvoidExit string
}

// The egress one search leaves through (FETCH-M13-01's SidecarEgress in production). Safe for concurrent use.
type WebSearchDialer interface {
	Session(ctx context.Context, args *WebSearchSessionArgs) (WebSearchSession, error)
}

// One search's way out: every dial leaves by one exit.
type WebSearchSession interface {
	// The exit's opaque id.
	Exit() string
	// Resolves address's host by the egress's DoH and dials it pinned through the session's exit.
	DialContext(ctx context.Context, network string, address string) (net.Conn, error)
	Close() error
}

// The device's budgets as a search spends them (§16.4, §21.9; INFER C§6.4's check). Safe for concurrent use.
type WebSearchBudget interface {
	// Holds priceNanoUsd against the budgets a search by agentId spends; an error where one has no room.
	Hold(ctx context.Context, holdId Id, agentId *Id, priceNanoUsd int64) error
	// The hold's payment may have settled: it is spent at priceNanoUsd.
	Settle(holdId Id, priceNanoUsd int64) error
	// Nothing was paid.
	Release(holdId Id) error
}

// What NewWebSearchClient builds on.
type WebSearchClientArgs struct {
	// Nil takes DefaultWebSearchSettings.
	Settings *WebSearchSettings
	// Required.
	Policy WebSearchPolicy
	Broker WebSearchBroker
	Dialer WebSearchDialer
	Budget WebSearchBudget
	// Where outcomes wait to be reported; nil keeps none.
	Outcomes *WebSearchOutcomeLog
	// Nil reads real time.
	Clock Clock
	// Nil logs nothing.
	Log Logger
	// The roots the gateway's certificate chains to; nil for the system's.
	RootCAs *x509.CertPool
	// What the User-Agent names after ur, empty for none.
	Version string
	// Where nonces and request ids are drawn from; nil for crypto/rand.
	Random io.Reader
}

// See the file header.
type WebSearchClient struct {
	settings *WebSearchSettings
	policy   WebSearchPolicy
	broker   WebSearchBroker
	dialer   WebSearchDialer
	budget   WebSearchBudget
	outcomes *WebSearchOutcomeLog
	clock    Clock
	log      Logger
	rootCAs  *x509.CertPool
	version  string
	random   io.Reader

	stateLock sync.Mutex
	paced     []time.Time
	lastExit  string
}

// A client over args.
func NewWebSearchClient(args *WebSearchClientArgs) (*WebSearchClient, error) {
	if args == nil || args.Policy == nil || args.Broker == nil || args.Dialer == nil || args.Budget == nil {
		return nil, errors.New("web search client: a policy, a broker, a dialer and a budget")
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultWebSearchSettings()
	}
	clock := args.Clock
	if clock == nil {
		clock = RealClock{}
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	random := args.Random
	if random == nil {
		random = rand.Reader
	}
	return &WebSearchClient{
		settings: settings,
		policy:   args.Policy,
		broker:   args.Broker,
		dialer:   args.Dialer,
		budget:   args.Budget,
		outcomes: args.Outcomes,
		clock:    clock,
		log:      log,
		rootCAs:  args.RootCAs,
		version:  args.Version,
		random:   random,
	}, nil
}

// The settings the client reads.
func (self *WebSearchClient) Settings() *WebSearchSettings {
	return self.settings
}

// The search body's documented fields alone (§21.5).
type webSearchBody struct {
	Objective     string   `json:"objective,omitempty"`
	SearchQueries []string `json:"search_queries"`
	Mode          string   `json:"mode"`
}

// query's mode, and nil where its fields are within the gateway's documented limits; else invalid_arguments.
func (self *WebSearchClient) checkQuery(query *WebSearchQuery) (string, error) {
	if query == nil {
		return "", webSearchRefusal(WebSearchCodeInvalid, nil, "no query")
	}
	mode := query.Mode
	if mode == "" {
		mode = WebSearchModeFast
	}
	known := false
	for _, candidate := range WebSearchModes {
		known = known || candidate == mode
	}
	if !known {
		return "", webSearchRefusal(WebSearchCodeInvalid, nil, "mode is one of %s", strings.Join(WebSearchModes, ", "))
	}
	if len(query.Queries) < self.settings.QueryMinCount || self.settings.QueryMaxCount < len(query.Queries) {
		return "", webSearchRefusal(WebSearchCodeInvalid, nil, "%d to %d queries", self.settings.QueryMinCount, self.settings.QueryMaxCount)
	}
	for _, text := range query.Queries {
		if strings.TrimSpace(text) == "" || !utf8.ValidString(text) || self.settings.QueryMaxCharacterCount < utf8.RuneCountInString(text) {
			return "", webSearchRefusal(WebSearchCodeInvalid, nil, "each query 1 to %d characters", self.settings.QueryMaxCharacterCount)
		}
	}
	if !utf8.ValidString(query.Objective) || self.settings.ObjectiveMaxCharacterCount < utf8.RuneCountInString(query.Objective) {
		return "", webSearchRefusal(WebSearchCodeInvalid, nil, "an objective of at most %d characters", self.settings.ObjectiveMaxCharacterCount)
	}
	return mode, nil
}

// Takes a place in the device's pace, or answers rate_limited with when one frees.
func (self *WebSearchClient) pace() error {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	kept := self.paced[:0]
	for _, at := range self.paced {
		if now.Before(at.Add(self.settings.DevicePaceWindow)) {
			kept = append(kept, at)
		}
	}
	self.paced = kept
	if self.settings.DevicePaceCount <= len(self.paced) {
		refusal := webSearchRefusal(WebSearchCodeRateLimited, nil, "at most %d searches a %s from this device", self.settings.DevicePaceCount, self.settings.DevicePaceWindow)
		refusal.RetryAfter = self.paced[0].Add(self.settings.DevicePaceWindow).Sub(now)
		return refusal
	}
	self.paced = append(self.paced, now)
	return nil
}

// The last search's exit, which the next avoids where it can.
func (self *WebSearchClient) avoidExit() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.lastExit
}

// Notes the exit a search left by.
func (self *WebSearchClient) setLastExit(exit string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lastExit = exit
}

// n bytes from the client's source.
func (self *WebSearchClient) draw(n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := io.ReadFull(self.random, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Counts one outcome, logging a count that could not be kept.
func (self *WebSearchClient) outcome(class string) {
	if self.outcomes == nil {
		return
	}
	if err := self.outcomes.Add(class); err != nil {
		self.log.Warningf("[websearch]an outcome was not kept: %v", err)
	}
}

// One search (see the file header). A refusal is a *WebSearchError, its code what the search came to.
func (self *WebSearchClient) Search(ctx context.Context, query *WebSearchQuery) (*WebSearchAnswer, error) {
	mode, err := self.checkQuery(query)
	if err != nil {
		return nil, err
	}
	line, err := self.policy.Line(ctx)
	if err != nil {
		return nil, err
	}
	price, err := self.policy.Price(ctx, WebSearchEngineParallel, mode)
	if err != nil {
		return nil, err
	}
	if err := self.pace(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(&webSearchBody{Objective: query.Objective, SearchQueries: query.Queries, Mode: mode})
	if err != nil {
		return nil, webSearchRefusal(WebSearchCodeInvalid, nil, "the body does not encode")
	}
	// the device's own budget check comes before a byte leaves: a query the broker then refuses has reached the gateway
	// unpaid. The first attempt spends this hold; the catalog's price bounds what its offer may cost.
	holdId := NewId()
	if err := self.budget.Hold(ctx, holdId, query.AgentId, price.NanoUsdPerSearch); err != nil {
		return nil, webSearchRefusal(WebSearchCodeInsufficientQuota, err, "%v", err)
	}
	run := &webSearchRun{client: self, query: query, mode: mode, line: line, price: price, body: body, firstHold: &holdId}
	defer run.releaseFirstHold()
	session, err := self.dialer.Session(ctx, &WebSearchSessionArgs{Egress: AclComputeEgressAuto, AvoidExit: self.avoidExit()})
	if err != nil {
		return nil, webSearchRefusal(WebSearchCodeUnavailable, err, "no egress for the search: %v", err)
	}
	defer session.Close()
	self.setLastExit(session.Exit())
	run.session = session
	defer run.closeConnection()
	return run.search(ctx)
}

// One search's state.
type webSearchRun struct {
	client  *WebSearchClient
	query   *WebSearchQuery
	mode    string
	line    *WebSearchPolicyLine
	price   *WebSearchPrice
	session WebSearchSession
	body    []byte

	conn   net.Conn
	reader *bufio.Reader
	// the hold Search took before the search's first byte left, which the first attempt spends; nil once taken
	firstHold *Id
}

// Releases the first hold where no attempt took it: nothing was paid.
func (self *webSearchRun) releaseFirstHold() {
	if self.firstHold == nil {
		return
	}
	if err := self.client.budget.Release(*self.firstHold); err != nil {
		self.client.log.Warningf("[websearch]the device's budget hold did not end: %v", err)
	}
	self.firstHold = nil
}

// A gateway answer as read.
type webSearchReply struct {
	status int
	header http.Header
	body   []byte
}

// Why an exchange read no answer: the deadline, or anything else.
var (
	errWebSearchExchangeTimeout = errors.New("web search: no answer within the timeout")
	errWebSearchAnswerTooLarge  = errors.New("web search: an answer past its cap")
)

// Closes the search's connection, where one is open.
func (self *webSearchRun) closeConnection() {
	if self.conn != nil {
		self.conn.Close()
		self.conn = nil
		self.reader = nil
	}
}

// A connection to the policy's host through the session, TLS to that host alone.
func (self *webSearchRun) connect(ctx context.Context) error {
	raw, err := self.session.DialContext(ctx, "tcp", net.JoinHostPort(self.line.Host, "443"))
	if err != nil {
		return err
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName: self.line.Host,
		RootCAs:    self.client.rootCAs,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	})
	timedOut := atomic.Bool{}
	stop := self.client.clock.AfterFunc(self.client.settings.AnswerTimeout, func() {
		timedOut.Store(true)
		conn.Close()
	})
	defer stop()
	if err := conn.HandshakeContext(ctx); err != nil {
		conn.Close()
		if timedOut.Load() {
			return errWebSearchExchangeTimeout
		}
		return err
	}
	self.conn, self.reader = conn, bufio.NewReader(conn)
	return nil
}

// One request on the search's connection, a new one through the same session where there is none, payment carried
// where it is not empty; the answer read whole within the timeout and the cap.
func (self *webSearchRun) exchange(ctx context.Context, payment string) (*webSearchReply, error) {
	settings := self.client.settings
	if self.conn == nil {
		if err := self.connect(ctx); err != nil {
			return nil, err
		}
	}
	target := &url.URL{Scheme: "https", Host: self.line.Host, Path: webSearchSearchPath}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(self.body))
	if err != nil {
		return nil, err
	}
	userAgent := settings.UserAgent
	if self.client.version != "" {
		userAgent += "/" + self.client.version
	}
	request.Header = http.Header{}
	request.Header.Set("Content-Type", settings.ContentType)
	request.Header.Set("Accept-Encoding", settings.AcceptEncoding)
	request.Header.Set("User-Agent", userAgent)
	if payment != "" {
		request.Header.Set(settings.PaymentHeader, payment)
	}
	conn := self.conn
	timedOut := atomic.Bool{}
	stop := self.client.clock.AfterFunc(settings.AnswerTimeout, func() {
		timedOut.Store(true)
		conn.Close()
	})
	defer stop()
	stopCancel := context.AfterFunc(ctx, func() {
		conn.Close()
	})
	defer stopCancel()
	failed := func(err error) (*webSearchReply, error) {
		self.closeConnection()
		if timedOut.Load() {
			return nil, errWebSearchExchangeTimeout
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if err := request.Write(conn); err != nil {
		return failed(err)
	}
	response, err := http.ReadResponse(self.reader, request)
	if err != nil {
		return failed(err)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(settings.AnswerMaxByteCount)+1))
	response.Body.Close()
	if err != nil {
		return failed(err)
	}
	if settings.AnswerMaxByteCount < len(body) {
		return failed(errWebSearchAnswerTooLarge)
	}
	if strings.EqualFold(response.Header.Get("Content-Encoding"), "gzip") {
		decoded, err := webSearchGunzip(body, settings.AnswerMaxByteCount)
		if err != nil {
			return failed(err)
		}
		body = decoded
	}
	if response.Close {
		// the gateway closes this connection: the next request dials again through the same session
		self.closeConnection()
	}
	return &webSearchReply{status: response.StatusCode, header: response.Header, body: body}, nil
}

// A gzip body decoded within maxByteCount.
func webSearchGunzip(body []byte, maxByteCount int) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	decoded, err := io.ReadAll(io.LimitReader(reader, int64(maxByteCount)+1))
	if err != nil {
		return nil, err
	}
	if maxByteCount < len(decoded) {
		return nil, errWebSearchAnswerTooLarge
	}
	return decoded, nil
}

// How long a 429 asks to wait, within RateLimitedWaitMax: whole seconds, a second where it names none.
func (self *webSearchRun) retryAfter(reply *webSearchReply) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(reply.header.Get("Retry-After")))
	wait := time.Second
	if err == nil && 0 < seconds {
		wait = time.Duration(seconds) * time.Second
	}
	return min(wait, self.client.settings.RateLimitedWaitMax)
}

// Waits wait on the client's clock, or until ctx ends.
func (self *webSearchRun) wait(ctx context.Context, wait time.Duration) error {
	select {
	case <-self.client.clock.After(wait):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// One request and the 429s it meets, each waited and asked again through the same exit, at most
// RateLimitedRetryCount times; the last answer.
func (self *webSearchRun) exchangePaced(ctx context.Context, payment string) (*webSearchReply, error) {
	for retry := 0; ; retry += 1 {
		reply, err := self.exchange(ctx, payment)
		if err != nil || reply.status != http.StatusTooManyRequests || self.client.settings.RateLimitedRetryCount <= retry {
			return reply, err
		}
		if err := self.wait(ctx, self.retryAfter(reply)); err != nil {
			return nil, err
		}
	}
}

// The search (see the file header).
func (self *webSearchRun) search(ctx context.Context) (*WebSearchAnswer, error) {
	settings := self.client.settings
	reply, err := self.exchangePaced(ctx, "")
	if err != nil {
		return nil, webSearchRefusal(WebSearchCodeUnavailable, err, "the gateway did not answer: %v", err)
	}
	switch reply.status {
	case http.StatusPaymentRequired:
	case http.StatusTooManyRequests:
		return nil, webSearchRefusal(WebSearchCodeRateLimited, nil, "the gateway's rate, past %d retries", settings.RateLimitedRetryCount)
	default:
		return nil, webSearchRefusal(WebSearchCodeUnavailable, nil, "the gateway answered %d unpaid", reply.status)
	}
	requestId, err := self.client.draw(settings.RequestIdByteCount)
	if err != nil {
		return nil, err
	}
	for attempt := uint32(1); ; attempt += 1 {
		challenge, err := webSearchReadChallenge(reply.header.Get(webSearchPaymentRequiredHeader), reply.body, settings)
		var offer *webSearchOffer
		if err == nil {
			offer, err = webSearchTakeOffer(challenge, self.line, self.price, settings)
		} else {
			err = webSearchRefusal(WebSearchCodeBadOffer, err, "the challenge does not read")
		}
		if err != nil {
			if 1 < attempt {
				// the paid retry was answered by a 402 the search cannot take
				self.client.outcome(WebSearchOutcomeRefused)
				return nil, webSearchRefusal(WebSearchCodeRefused, err, "the paid retry was refused, and its next offer was not taken")
			}
			return nil, err
		}
		answer, next, err := self.attempt(ctx, requestId, attempt, offer)
		if err != nil || answer != nil {
			return answer, err
		}
		if settings.AttemptMaxCount <= int(attempt) {
			self.client.outcome(WebSearchOutcomeRefused)
			return nil, webSearchRefusal(WebSearchCodeRefused, nil, "the paid retry was refused %d times", attempt)
		}
		reply = next
	}
}

// One attempt: its hold, its authorization and its paid retry. The answer where it was served; else the 402 that asks
// for the next attempt; else the error the search ends with.
func (self *webSearchRun) attempt(ctx context.Context, requestId []byte, attempt uint32, offer *webSearchOffer) (*WebSearchAnswer, *webSearchReply, error) {
	client, settings := self.client, self.client.settings
	retail, ok := webSearchRetailNanoUsd(offer.amount, settings)
	if !ok {
		return nil, nil, webSearchRefusal(WebSearchCodeBadOffer, nil, "the offer's price does not read")
	}
	var holdId Id
	if self.firstHold != nil {
		holdId, self.firstHold = *self.firstHold, nil
	} else {
		holdId = NewId()
		if err := client.budget.Hold(ctx, holdId, self.query.AgentId, retail); err != nil {
			// the paid retry before this attempt was refused, and this one cannot pay
			client.outcome(WebSearchOutcomeRefused)
			return nil, nil, webSearchRefusal(WebSearchCodeInsufficientQuota, err, "%v", err)
		}
	}
	paid := false
	defer func() {
		var err error
		if paid {
			err = client.budget.Settle(holdId, retail)
		} else {
			err = client.budget.Release(holdId)
		}
		if err != nil {
			client.log.Warningf("[websearch]the device's budget hold did not end: %v", err)
		}
	}()
	authorization, nonce, minuteS, err := self.authorize(ctx, requestId, attempt, offer)
	if err != nil {
		return nil, nil, err
	}
	if self.query.BeforePay != nil {
		payment := &WebSearchPayment{RequestId: requestId, Attempt: attempt, Nonce: nonce, MinuteS: minuteS}
		if err := self.query.BeforePay(payment); err != nil {
			return nil, nil, webSearchRefusal(WebSearchCodeRefused, err, "the payment was not journaled, so it did not leave")
		}
	}
	payment, err := webSearchPaymentHeaderValue(offer, authorization)
	if err != nil {
		return nil, nil, err
	}
	paid = true
	reply, err := self.exchangePaced(ctx, payment)
	switch {
	case errors.Is(err, errWebSearchExchangeTimeout):
		client.outcome(WebSearchOutcomeTimeout)
		return nil, nil, webSearchRefusal(WebSearchCodeTimeout, nil, "no answer within %s of paying", settings.AnswerTimeout)
	case err != nil:
		client.outcome(WebSearchOutcomeProviderError)
		return nil, nil, webSearchRefusal(WebSearchCodeProviderError, nil, "the answer was lost after paying")
	case reply.status == http.StatusPaymentRequired:
		return nil, reply, nil
	case reply.status == http.StatusTooManyRequests:
		client.outcome(WebSearchOutcomeRefused)
		return nil, nil, webSearchRefusal(WebSearchCodeRefused, nil, "the paid retry was rate limited past %d retries", settings.RateLimitedRetryCount)
	case reply.status != http.StatusOK:
		client.outcome(WebSearchOutcomeProviderError)
		return nil, nil, webSearchRefusal(WebSearchCodeProviderError, nil, "the gateway answered %d after paying", reply.status)
	}
	answer, err := webSearchReadAnswer(reply.body)
	if err != nil {
		client.outcome(WebSearchOutcomeProviderError)
		return nil, nil, webSearchRefusal(WebSearchCodeProviderError, nil, "the answer does not read")
	}
	client.outcome(WebSearchOutcomeOk)
	answer.AnswerSha256 = sha256.Sum256(reply.body)
	answer.Nonce, answer.MinuteS, answer.RequestId, answer.Attempt = nonce, minuteS, requestId, attempt
	answer.Amount, answer.PriceNanoUsd, answer.Mode = offer.amount, retail, self.mode
	if transaction, ok := webSearchReadPaymentResponse(reply.header.Get(webSearchPaymentResponseHeader), settings); ok {
		answer.Transaction = transaction
	}
	return answer, nil, nil
}

// The attempt's authorization from the broker and the signer, checked: the authorization, its nonce and its minute.
func (self *webSearchRun) authorize(ctx context.Context, requestId []byte, attempt uint32, offer *webSearchOffer) (*protocol.ComputeSearchAuthorization, []byte, int64, error) {
	client, settings := self.client, self.client.settings
	nonce, err := client.draw(settings.NonceByteCount)
	if err != nil {
		return nil, nil, 0, err
	}
	payee := &protocol.SearchPayee{PayTo: offer.payTo[:], Nonce: nonce}
	binding := &WebSearchSealBinding{Amount: offer.amount, Asset: self.line.Asset, Network: self.line.Network}
	sealed, answerKey, err := WebSearchSealPayee(self.line.SignerKey, payee, binding, settings)
	if err != nil {
		return nil, nil, 0, webSearchRefusal(WebSearchCodeSearchOff, err, "the payee does not seal to the policy's signer key")
	}
	var outcomes *protocol.SearchOutcomes
	if client.outcomes != nil {
		if outcomes, err = client.outcomes.Unreported(); err != nil {
			client.log.Warningf("[websearch]the unreported outcomes do not read: %v", err)
			outcomes = nil
		}
	}
	request := &protocol.ComputeSearchAuthorizeRequest{
		CatalogVersion: self.price.CatalogVersion,
		RequestId:      requestId,
		Attempt:        attempt,
		SealedPayee:    sealed,
		Amount:         offer.amount,
		Asset:          self.line.Asset[:],
		Network:        self.line.Network,
		Outcomes:       outcomes,
	}
	if self.query.AgentId != nil {
		request.AgentId = self.query.AgentId.Bytes()
	}
	var response *protocol.ComputeSearchAuthorizeResponse
	staleAsked := false
	for retry := 0; ; retry += 1 {
		response, err = client.broker.Authorize(ctx, request)
		if err == nil {
			break
		}
		if refusal, ok := webSearchBrokerRefusal(err); ok {
			if refusal.Code != WebSearchCodeCatalogStale || staleAsked {
				return nil, nil, 0, refusal
			}
			// a catalog the broker no longer takes: fetched again, the offer held to its price, and asked once more
			staleAsked = true
			if err := client.policy.RefreshCatalog(ctx); err != nil {
				return nil, nil, 0, refusal
			}
			price, err := client.policy.Price(ctx, WebSearchEngineParallel, self.mode)
			if err != nil {
				return nil, nil, 0, err
			}
			if retail, ok := webSearchRetailNanoUsd(offer.amount, settings); !ok || price.NanoUsdPerSearch < retail {
				return nil, nil, 0, webSearchRefusal(WebSearchCodeBadOffer, nil, "the offer passes the catalog's new price")
			}
			self.price = price
			request.CatalogVersion = price.CatalogVersion
			continue
		}
		if ctx.Err() != nil {
			return nil, nil, 0, ctx.Err()
		}
		if settings.BrokerRetryCount <= retry {
			return nil, nil, 0, webSearchRefusal(WebSearchCodeCapacity, err, "the broker did not answer")
		}
	}
	if outcomes != nil {
		if err := client.outcomes.Reported(outcomes); err != nil {
			client.log.Warningf("[websearch]the reported outcomes were not dropped: %v", err)
		}
	}
	authorization, err := WebSearchOpenAuthorization(answerKey, response.GetSealedAuthorization())
	if err != nil {
		client.outcome(WebSearchOutcomeRefused)
		return nil, nil, 0, webSearchRefusal(WebSearchCodeRefused, nil, "the authorization does not open under this request")
	}
	minuteS, err := self.checkAuthorization(authorization, offer, nonce)
	if err != nil {
		client.outcome(WebSearchOutcomeRefused)
		return nil, nil, 0, err
	}
	return authorization, nonce, minuteS, nil
}

// Whether the signer's authorization is the one this attempt asked for (see the file header's check row): its minute,
// or refused.
func (self *webSearchRun) checkAuthorization(authorization *protocol.ComputeSearchAuthorization, offer *webSearchOffer, nonce []byte) (int64, error) {
	settings := self.client.settings
	refuse := func(why string) (int64, error) {
		return 0, webSearchRefusal(WebSearchCodeRefused, nil, "the authorization names %s", why)
	}
	if !bytes.Equal(authorization.GetTo(), offer.payTo[:]) {
		return refuse("another payee")
	}
	if authorization.GetValue() != offer.amount {
		return refuse("another value")
	}
	if !bytes.Equal(authorization.GetNonce(), nonce) {
		return refuse("another nonce")
	}
	if !bytes.Equal(authorization.GetFrom(), self.line.Payer[:]) {
		return refuse("another payer")
	}
	minuteS, ok := WebSearchWindowMinute(settings, authorization.GetValidAfterS(), authorization.GetValidBeforeS())
	if !ok {
		return refuse("no minute's window")
	}
	now := self.client.clock.Now()
	minute := time.Unix(minuteS, 0)
	if minute.Before(now.Add(-settings.WindowSkew)) || now.Add(settings.WindowSkew).Before(minute) ||
		!now.Before(time.Unix(authorization.GetValidBeforeS(), 0)) {
		return refuse("a window away from now")
	}
	digest, err := WebSearchTransferDigest(self.line.Domain(), authorization)
	if err != nil {
		return refuse("a transfer that does not hash")
	}
	signer, err := WebSearchRecoverSigner(digest, authorization.GetSignature())
	if err != nil || signer != self.line.Payer {
		return refuse("a signature that does not recover to the payer")
	}
	return minuteS, nil
}

// The gateway's answer, as its documented schema writes it.
type webSearchGatewayAnswer struct {
	SearchId  string                    `json:"search_id"`
	Results   []*webSearchGatewayResult `json:"results"`
	Warnings  []json.RawMessage         `json:"warnings"`
	Usage     json.RawMessage           `json:"usage"`
	SessionId string                    `json:"session_id"`
}

// One result as the gateway's schema writes it.
type webSearchGatewayResult struct {
	Url         string   `json:"url"`
	Title       string   `json:"title"`
	PublishDate *string  `json:"publish_date"`
	Excerpts    []string `json:"excerpts"`
}

// The whitelist of body: each result whose url is http or https, its title, date and excerpts; each warning's text.
// search_id, usage and session_id are read past and kept nowhere. An answer that is no JSON object, or holds no results
// list, does not read.
func webSearchReadAnswer(body []byte) (*WebSearchAnswer, error) {
	decoded := &webSearchGatewayAnswer{}
	if err := json.Unmarshal(body, decoded); err != nil {
		return nil, err
	}
	if decoded.Results == nil {
		return nil, errors.New("no results")
	}
	answer := &WebSearchAnswer{}
	for _, result := range decoded.Results {
		if result == nil {
			continue
		}
		parsed, err := url.Parse(result.Url)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
			continue
		}
		kept := &WebSearchResult{Url: result.Url, Title: result.Title, Excerpts: result.Excerpts}
		if result.PublishDate != nil {
			kept.PublishDate = *result.PublishDate
		}
		answer.Results = append(answer.Results, kept)
	}
	for _, raw := range decoded.Warnings {
		var text string
		if err := json.Unmarshal(raw, &text); err == nil {
			answer.Warnings = append(answer.Warnings, text)
			continue
		}
		var object struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(raw, &object); err == nil && object.Message != "" {
			answer.Warnings = append(answer.Warnings, object.Message)
		}
	}
	return answer, nil
}

// Sends this device's outcomes once a day where it searched no more (§21.8): nil once nothing is due or the broker
// took them.
func (self *WebSearchClient) ReportOutcomes(ctx context.Context) error {
	if self.outcomes == nil {
		return nil
	}
	due, err := self.outcomes.ReportDue()
	if err != nil || due == nil {
		return err
	}
	if err := self.broker.ReportOutcomes(ctx, &protocol.ComputeSearchOutcomesRequest{Outcomes: due}); err != nil {
		return err
	}
	return self.outcomes.Reported(due)
}

// The daily report's schedule, until ctx ends: each OutcomesReportInterval, a failure tried again after
// OutcomesReportRetryInterval.
func (self *WebSearchClient) run(ctx context.Context) {
	wait := self.settings.OutcomesReportInterval
	for {
		select {
		case <-ctx.Done():
			return
		case <-self.clock.After(wait):
		}
		wait = self.settings.OutcomesReportInterval
		if err := self.ReportOutcomes(ctx); err != nil {
			self.log.Warningf("[websearch]the day's outcomes were not reported: %v", err)
			wait = self.settings.OutcomesReportRetryInterval
		}
	}
}
