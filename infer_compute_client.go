//go:build !ios_extension && !sidecar_http

// The device's client of the compute service (DESIGN-COMPUTE §14.2, §14.3, §6.3, §6.6; INFER-M12-01): one per Sidecar,
// reaching the broker at compute.<root> (InferSettings.ComputeServiceUrl, https alone) with a service token for the
// compute audience (DESIGN §7.8) and the ClientKey's DPoP proof of each request, which the broker's guard checks the
// bearer of today and the proof of once compute-plan-compute-token-dpop's hardening lands (QD-1239). Every compute/v1
// body is deterministic protobuf, every refusal the broker's JSON code (QD-1246). The remote catalog, the TEE and
// direct paths, the evidence tunnel, ENC, BAL and SRCH share it.
//
// Each call: a token for the compute audience, kept by the Sidecar for its life, and a proof signed for the request's
// method and url; a request body at most ComputeServiceRequestMaxByteCount, an answer at most the caller's bound, each
// refused whole rather than cut; a 401 drops the token and asks once more under a new one; a 503 or a connection that
// failed before any answer is asked again up to ComputeServiceRetryCount times, after its Retry-After where the broker
// gave one, at most ComputeServiceRetryAfterMaxDuration, else ComputeServiceRetryInterval; any other refusal goes back
// at once as a *ComputeServiceError naming the route and the broker's code, never anything the request carried.
//
// The broker's clock: every answer the broker writes, refusals included, carries its time in ComputeServiceTimeHeader,
// which the client keeps as an offset from this device's clock, measured at the midpoint of the request's round trip;
// an answer without it falls back on its Date header, to the second. BrokerNow reads it: the direct path's btauth/1
// nonce is proposed from it, since the broker refuses one more than a second from its own clock (§6.6).
//
// Safe for concurrent use: the offset sits under stateLock, and the rest is fixed when the client is built.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
)

// The headers and media types the compute service's two ends name: identifiers of its wire.
const (
	// The broker's clock on every answer, in Unix milliseconds (§6.6's nonces), which computeservice's engine writes.
	ComputeServiceTimeHeader = "Ur-Compute-Time"
	// Every compute/v1 body (QD-1246).
	computeServiceProtobufContentType = "application/x-protobuf"
	// A refusal's body.
	computeServiceJsonContentType = "application/json"
	// The ClientKey's proof of one request (RFC 9449).
	computeServiceDpopHeader = "DPoP"
	// The component's name (compute_sidecar.go).
	computeServiceComponentName = "compute-service"
)

var (
	// The Sidecar is given no compute service url: every remote model, enclave and web search is unavailable, and
	// local inference runs on.
	ErrComputeServiceUnconfigured = errors.New("no compute service url is configured")
	// An answer that is not what its route answers: a body past the caller's bound, or one that does not decode.
	ErrComputeServiceAnswer = errors.New("compute service answer refused")
	// A request the client does not send: a body past ComputeServiceRequestMaxByteCount, or a path that is no
	// compute/v1 route's.
	ErrComputeServiceRequest = errors.New("compute service request refused")
)

// A refusal the broker answered (its ComputeRefusal): the route, the HTTP status, its code and reason words, and when
// to ask again. errors.Is with a *ComputeServiceError matches by code.
type ComputeServiceError struct {
	// The method and path, which hold no id beyond the route's own.
	Route  string
	Status int
	// The broker's code: catalog_stale, capacity, held, insufficient_quota, unauthenticated, scope, unavailable ...
	Code string
	// A word of the code's own set, such as insufficient_quota's balance or budget; empty for none.
	Reason string
	// When to ask again; zero where the broker gave no time.
	RetryAfter time.Duration
}

// See error.
func (self *ComputeServiceError) Error() string {
	text := "compute " + self.Route + ": " + strconv.Itoa(self.Status) + " " + self.Code
	if self.Reason != "" {
		text += " (" + self.Reason + ")"
	}
	return text
}

// A *ComputeServiceError target matches one of its code.
func (self *ComputeServiceError) Is(target error) bool {
	other, ok := target.(*ComputeServiceError)
	return ok && other.Code == self.Code
}

// What a refusal's body holds, as the broker writes it.
type computeServiceRefusalBody struct {
	Code         string `json:"code"`
	Reason       string `json:"reason"`
	RetryAfterMs int64  `json:"retry_after_ms"`
}

// What the client asks of its Sidecar: the compute audience's service token, and the ClientKey's DPoP proof.
type computeServiceCredentials interface {
	// A service token for the compute audience, kept where one is.
	token(ctx context.Context) (string, error)
	// Drops the kept token, which the broker answered 401 to.
	forget()
	// The ClientKey's proof of one request to url with method, bound to accessToken.
	proof(method string, url string, accessToken string) (string, error)
}

// What builds a ComputeServiceClient.
type computeServiceClientArgs struct {
	// The broker's base url, https://<host>[:port], no path; empty for none, every call then refused
	// ErrComputeServiceUnconfigured.
	BaseUrl     string
	Credentials computeServiceCredentials
	Settings    *InferSettings
	// Nil: a client of the standard transport that follows no redirect, since a broker that redirects is not answering.
	HttpClient *http.Client
	// Nil reads real time.
	Clock Clock
	// Nil logs nothing.
	Log Logger
}

// The device's compute service client. See the file header.
type ComputeServiceClient struct {
	base        *url.URL
	credentials computeServiceCredentials
	settings    *InferSettings
	client      *http.Client
	clock       Clock
	log         Logger

	stateLock sync.Mutex
	// the broker's clock less this device's, and whether it was read from ComputeServiceTimeHeader or a Date
	brokerOffset      time.Duration
	brokerOffsetKnown bool
	brokerOffsetExact bool
}

// A client over args. A base url that is not an absolute https url with a host and no user, path, query or fragment
// is refused: the client never sends a token over http.
func newComputeServiceClient(args *computeServiceClientArgs) (*ComputeServiceClient, error) {
	if args == nil || args.Credentials == nil || args.Settings == nil {
		return nil, errors.New("compute service client: credentials and settings")
	}
	var base *url.URL
	if args.BaseUrl != "" {
		parsed, err := url.Parse(args.BaseUrl)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
			(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("compute service client: %w: not an https base url", errServiceUrl)
		}
		parsed.Path = ""
		base = parsed
	}
	client := args.HttpClient
	if client == nil {
		client = &http.Client{
			Transport: &http.Transport{Proxy: nil, ForceAttemptHTTP2: true},
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	clock := args.Clock
	if clock == nil {
		clock = RealClock{}
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	return &ComputeServiceClient{
		base:        base,
		credentials: args.Credentials,
		settings:    args.Settings,
		client:      client,
		clock:       clock,
		log:         log,
	}, nil
}

// GET path, its answer decoded into answer, at most maxByteCount bytes (ComputeServiceAnswerMaxByteCount where
// non-positive). See the file header for the rest.
func (self *ComputeServiceClient) Get(ctx context.Context, path string, answer proto.Message, maxByteCount int) error {
	return self.call(ctx, http.MethodGet, path, nil, nil, answer, maxByteCount)
}

// POST path with request, its answer decoded into answer, nil for one with no body, at most maxByteCount bytes
// (ComputeServiceAnswerMaxByteCount where non-positive).
func (self *ComputeServiceClient) Post(ctx context.Context, path string, request proto.Message, answer proto.Message, maxByteCount int) error {
	return self.call(ctx, http.MethodPost, path, nil, request, answer, maxByteCount)
}

// Post under Idempotency-Key: idempotencyKey, which a route taking one requires (§14.3; the effect key of an approved
// decision): every retry and renewal of the call carries the same key. BAL-M12-16's kind 21 posts this way.
func (self *ComputeServiceClient) PostIdempotent(ctx context.Context, path string, idempotencyKey string, request proto.Message, answer proto.Message, maxByteCount int) error {
	if idempotencyKey == "" {
		return fmt.Errorf("%w: POST %s: no Idempotency-Key", ErrComputeServiceRequest, path)
	}
	return self.call(ctx, http.MethodPost, path, http.Header{"Idempotency-Key": []string{idempotencyKey}}, request, answer, maxByteCount)
}

// The broker's clock now, as the answers so far read it, and whether any answer gave it: false before the first.
func (self *ComputeServiceClient) BrokerNow() (time.Time, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.clock.Now().Add(self.brokerOffset), self.brokerOffsetKnown
}

// One call, its retries and its token's renewal, each attempt carrying header beside the client's own, nil for none.
func (self *ComputeServiceClient) call(ctx context.Context, method string, path string, header http.Header, request proto.Message, answer proto.Message, maxByteCount int) error {
	route := method + " " + path
	if self.base == nil {
		return ErrComputeServiceUnconfigured
	}
	if !strings.HasPrefix(path, "/v1/") || strings.ContainsAny(path, "?#") {
		return fmt.Errorf("%w: %s is no compute/v1 route", ErrComputeServiceRequest, route)
	}
	var body []byte
	if request != nil {
		var err error
		body, err = proto.MarshalOptions{Deterministic: true}.Marshal(request)
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrComputeServiceRequest, route, err)
		}
	}
	if self.settings.ComputeServiceRequestMaxByteCount < len(body) {
		return fmt.Errorf("%w: %s: a body of %d bytes, past %d", ErrComputeServiceRequest, route, len(body), self.settings.ComputeServiceRequestMaxByteCount)
	}
	if maxByteCount <= 0 {
		maxByteCount = self.settings.ComputeServiceAnswerMaxByteCount
	}
	target := *self.base
	target.Path = path
	renewed := false
	for attempt := 0; ; attempt += 1 {
		status, answerBody, answerHeader, err := self.send(ctx, method, target.String(), header, body, maxByteCount)
		if err != nil {
			if attempt < self.settings.ComputeServiceRetryCount && ctx.Err() == nil && !errors.Is(err, ErrComputeServiceAnswer) &&
				!errors.Is(err, errComputeServiceCredentials) {
				if err := self.wait(ctx, 0); err != nil {
					return err
				}
				continue
			}
			return err
		}
		if status == http.StatusOK {
			if answer == nil {
				return nil
			}
			if err := proto.Unmarshal(answerBody, answer); err != nil {
				return fmt.Errorf("%w: %s: %w", ErrComputeServiceAnswer, route, err)
			}
			return nil
		}
		refusal := self.refusal(route, status, answerHeader, answerBody)
		switch {
		case status == http.StatusUnauthorized && !renewed:
			// the token no longer authenticates there: once more under a new one
			self.credentials.forget()
			renewed = true
			continue
		case status == http.StatusServiceUnavailable && attempt < self.settings.ComputeServiceRetryCount:
			if err := self.wait(ctx, refusal.RetryAfter); err != nil {
				return err
			}
			continue
		}
		return refusal
	}
}

// A credential the client could not get: never asked again within the call.
var errComputeServiceCredentials = errors.New("compute service credentials")

// One request with header beside the client's own: its status, its body within maxByteCount, and its headers, or why
// none came back.
func (self *ComputeServiceClient) send(ctx context.Context, method string, target string, header http.Header, body []byte, maxByteCount int) (int, []byte, http.Header, error) {
	accessToken, err := self.credentials.token(ctx)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%w: %w", errComputeServiceCredentials, err)
	}
	proof, err := self.credentials.proof(method, target, accessToken)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%w: %w", errComputeServiceCredentials, err)
	}
	if 0 < self.settings.ComputeServiceRequestTimeout {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, self.settings.ComputeServiceRequestTimeout)
		defer cancel()
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return 0, nil, nil, err
	}
	for name, values := range header {
		for _, value := range values {
			httpRequest.Header.Add(name, value)
		}
	}
	httpRequest.Header.Set("Authorization", "Bearer "+accessToken)
	httpRequest.Header.Set(computeServiceDpopHeader, proof)
	httpRequest.Header.Set("Accept", computeServiceProtobufContentType)
	if body != nil {
		httpRequest.Header.Set("Content-Type", computeServiceProtobufContentType)
	}
	sent := self.clock.Now()
	response, err := self.client.Do(httpRequest)
	if err != nil {
		// the error names the url, which holds no id beyond the route's
		return 0, nil, nil, fmt.Errorf("compute %s %s: %w", method, httpRequest.URL.Path, err)
	}
	defer response.Body.Close()
	self.observeClock(response.Header, sent, self.clock.Now())
	answerBody, err := io.ReadAll(io.LimitReader(response.Body, int64(maxByteCount)+1))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("compute %s %s: the answer was cut: %w", method, httpRequest.URL.Path, err)
	}
	if maxByteCount < len(answerBody) {
		return 0, nil, nil, fmt.Errorf("%w: compute %s %s: past %d bytes", ErrComputeServiceAnswer, method, httpRequest.URL.Path, maxByteCount)
	}
	return response.StatusCode, answerBody, response.Header, nil
}

// The refusal a status and body make: the broker's code and words where its JSON reads, else unavailable for a 5xx
// and the status's own for the rest; RetryAfter from the body, else the Retry-After header.
func (self *ComputeServiceClient) refusal(route string, status int, header http.Header, body []byte) *ComputeServiceError {
	refusal := &ComputeServiceError{Route: route, Status: status}
	parsed := &computeServiceRefusalBody{}
	maxByteCount := self.settings.ComputeServiceRefusalWordMaxByteCount
	if strings.HasPrefix(header.Get("Content-Type"), computeServiceJsonContentType) && json.Unmarshal(body, parsed) == nil &&
		computeServiceCodeWord(parsed.Code, maxByteCount) {
		refusal.Code = parsed.Code
		if computeServiceCodeWord(parsed.Reason, maxByteCount) {
			refusal.Reason = parsed.Reason
		}
		if 0 < parsed.RetryAfterMs {
			refusal.RetryAfter = time.Duration(parsed.RetryAfterMs) * time.Millisecond
		}
	}
	if refusal.Code == "" {
		refusal.Code = "unavailable"
		if status < http.StatusInternalServerError {
			refusal.Code = "status_" + strconv.Itoa(status)
		}
	}
	if refusal.RetryAfter == 0 {
		if seconds, err := strconv.Atoi(header.Get("Retry-After")); err == nil && 0 < seconds {
			refusal.RetryAfter = time.Duration(seconds) * time.Second
		}
	}
	return refusal
}

// Whether word may name a code or reason: lowercase letters, digits and underscores, at most maxByteCount, so nothing
// a broker answers carries text into an error.
func computeServiceCodeWord(word string, maxByteCount int) bool {
	if word == "" || maxByteCount < len(word) {
		return false
	}
	for i := 0; i < len(word); i += 1 {
		c := word[i]
		if !(('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

// Waits before a retry: retryAfter where the broker gave one, at most ComputeServiceRetryAfterMaxDuration, else
// ComputeServiceRetryInterval.
func (self *ComputeServiceClient) wait(ctx context.Context, retryAfter time.Duration) error {
	wait := self.settings.ComputeServiceRetryInterval
	if 0 < retryAfter {
		wait = min(retryAfter, self.settings.ComputeServiceRetryAfterMaxDuration)
	}
	if wait <= 0 {
		return ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-self.clock.After(wait):
		return nil
	}
}

// Keeps the broker's clock an answer gave: ComputeServiceTimeHeader at the round trip's midpoint, else its Date to the
// second, which never replaces an exact reading.
func (self *ComputeServiceClient) observeClock(header http.Header, sent time.Time, received time.Time) {
	midpoint := sent.Add(received.Sub(sent) / 2)
	if milliseconds, err := strconv.ParseInt(header.Get(ComputeServiceTimeHeader), 10, 64); err == nil && 0 < milliseconds {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.brokerOffset = time.UnixMilli(milliseconds).Sub(midpoint)
		self.brokerOffsetKnown = true
		self.brokerOffsetExact = true
		return
	}
	date, err := http.ParseTime(header.Get("Date"))
	if err != nil {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.brokerOffsetExact {
		return
	}
	self.brokerOffset = date.Sub(midpoint)
	self.brokerOffsetKnown = true
}

// Registers the client, which every Sidecar on a compute leg then constructs.
func init() {
	registerComputeComponent(computeServiceComponentName, newSidecarComputeServiceClient, nil)
}

// The client over sidecar's service tokens and DPoP signer and its settings' broker url.
func newSidecarComputeServiceClient(sidecar *Sidecar) (*ComputeServiceClient, error) {
	settings := sidecar.settings.Infer
	if settings == nil {
		settings = DefaultInferSettings()
	}
	return newComputeServiceClient(&computeServiceClientArgs{
		BaseUrl:     settings.ComputeServiceUrl,
		Credentials: &computeServiceSidecarCredentials{sidecar: sidecar, resource: strings.TrimSuffix(settings.ComputeServiceUrl, "/")},
		Settings:    settings,
		Clock:       sidecar.clock,
		Log:         sidecar.log,
	})
}

// This Sidecar's compute service client (§14.2), shared by the remote catalog, the remote paths, the tunnel, enclaves,
// the balance's broker routes and web search, or an error wrapping ErrComputeComponentUnavailable that says why there
// is none.
func (self *Sidecar) ComputeServiceClient() (*ComputeServiceClient, error) {
	return sidecarComputeComponent[ComputeServiceClient](self, computeServiceComponentName)
}

// The client's credentials over a Sidecar: its service token for the broker's url, and its ClientKey's proofs.
type computeServiceSidecarCredentials struct {
	sidecar *Sidecar
	// the broker's url, the token's resource (§7.8)
	resource string
}

// See computeServiceCredentials.
func (self *computeServiceSidecarCredentials) token(ctx context.Context) (string, error) {
	return self.sidecar.ServiceToken(ctx, self.resource, nil)
}

// See computeServiceCredentials.
func (self *computeServiceSidecarCredentials) forget() {
	self.sidecar.ForgetServiceToken(self.resource, nil)
}

// See computeServiceCredentials.
func (self *computeServiceSidecarCredentials) proof(method string, url string, accessToken string) (string, error) {
	signer, err := self.sidecar.DpopSigner()
	if err != nil {
		return "", err
	}
	return signer(method, url, dpopAth(accessToken))
}
