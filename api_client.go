// SidecarApi, §5.4's net/http client of api: enrollment, bind, refresh, the token exchange, and the
// sidecar routes §6-§20 add, on every leg, the page Worker's included. It holds the sidecar's jwt, its
// DPoP signer and its transport, and nothing else of the sidecar. api_routes_core.go holds §5's and
// §7's routes, and each later section adds its own in api_routes_<prefix>.go on sendJson and send.
//
// The transport is the leg's (api_transport_connect.go, api_transport_http.go), always behind
// absoluteUrlTransport, so no request reaches net/http's defaults, which on a connect leg dial
// unbound sockets that can follow a tunnel's default route back into this process and in the page
// Worker send a relative url to the page's own host.
//
// Credentials stay in this process (I-7): an error carries a route's method and path template, its
// status, structured code and retry hint, and never a url, a request or response body, or a token,
// and logs say no more. A redirect is never followed, since following one would repeat a bearer or a
// form holding the subject token to wherever the answer pointed. Every call sends at most one request
// and retries nothing: a proof's jti is single use, so a retry is a new call with a new proof, which
// the caller decides.
//
// SidecarApi is safe for concurrent use. A call reads the token, signer and transport once, when it
// starts, so one that SetByJwt races finishes on the token it began with.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	// The call presents the client's jwt and none is installed. Nothing was sent.
	ErrSidecarApiNoToken = errors.New("sidecar api: no token")
	// The call carries a DPoP proof (§7.4) and no signer is installed. Nothing was sent: a strict_exp
	// refresh without a proof leaves the sidecar unenrolled, never proofless.
	ErrSidecarApiNoDpopSigner = errors.New("sidecar api: no dpop signer")
	// A request would carry an auth key's client-only bundle, or a key enrollment refuses (§7.8).
	// Nothing was sent.
	ErrSidecarApiBundle = errors.New("sidecar api: auth key refused before sending")
	// Arguments the route cannot take. Nothing was sent.
	ErrSidecarApiArgs = errors.New("sidecar api: invalid arguments")
	// An answer that is not the route's shape, or longer than ApiResponseByteCount.
	ErrSidecarApiReply = errors.New("sidecar api: malformed reply")
	// No transport is installed on this connect leg. Nothing was sent.
	errSidecarApiNoTransport = errors.New("sidecar api: no transport")
)

// The structured codes the core acts on. Each is a format value api answers with, in a refusal's
// code or a 200's error object.
const (
	// Refresh's answer after a Postgres restore lacks this sidecar's identity, binding or registration
	// (§5.6, §19.10): re-register and refresh again. It is not a refusal.
	SidecarApiCodeRestoreRequired = "restore_required"
	// A 401's code for a session the server ended, which §18.5 maps to session_ended.
	SidecarApiCodeSessionRevoked = "session_revoked"
	// POST /sidecar/bind's 403 for a revoked sidecar.
	SidecarApiCodeSidecarRevoked = "sidecar_revoked"
	// POST /sidecar/bind's 400 for a bad signature, a malformed body, or a binding that names
	// another client or network than the token's.
	SidecarApiCodeBindingInvalid = "binding_invalid"
	// POST /sidecar/bind's 409 for a generation that is not the newest plus one under the same
	// identity key.
	SidecarApiCodeGenerationConflict = "generation_conflict"
	// POST /sidecar/bind's 409 for a client already bound with other bytes: a client binds once.
	SidecarApiCodeClientBound = "client_bound"
)

// The longest structured code read from an answer. A longer one is not a code.
const sidecarApiMaxCodeByteCount = 64

// A request api answered with a refusal. It carries what the caller acts on and never a url, a body
// or a token (I-7), so it may be logged and shown as it is.
type SidecarApiError struct {
	// The route as its method and path template, such as "GET /sidecar/identity/<sidecar_id>".
	Route string
	// The HTTP status. 200 also stands for any 2xx whose body held an error object, as refresh,
	// auth-client and remove-client answer a refusal.
	Status int
	// The structured code: the body's code, or an RFC 6749 error code, such as restore_required,
	// session_revoked, binding_invalid or invalid_grant. Empty when the answer held none, as a plain
	// text refusal holds none. Only lowercase letters, digits and _ are read as a code, so no text
	// of the server's reaches here.
	Code string
	// How long the server asked the caller to wait: the body's retry_after_ms, else Retry-After's
	// delay-seconds, or its HTTP-date less the api's clock, a date already past asking for no wait.
	// Zero: no hint. Past a uint32 is its largest.
	RetryAfterMs uint32
}

// The route, status and code: nothing the server wrote but its code.
func (self *SidecarApiError) Error() string {
	if self.Code == "" {
		return fmt.Sprintf("sidecar api %s refused: %d", self.Route, self.Status)
	}
	return fmt.Sprintf("sidecar api %s refused: %d %s", self.Route, self.Status, self.Code)
}

// The net/http client of api (§5.4). Construct with newSidecarApi.
type SidecarApi struct {
	settings *SidecarSettings
	log      Logger
	// the clock a Retry-After given as a date is read against; set once, at construction
	now func() time.Time

	stateLock sync.Mutex
	// the authenticated jwt
	byJwt string
	// the ClientKey's proof (§7.4), newDpopSigner's; nil until the core installs one, and then a call
	// that needs a proof is not sent
	dpopSigner func(method string, url string, ath string) (string, error)
	// absoluteUrlTransport over the leg's: a connect leg dials by its client strategy's
	// ConnectSettings().DialContext (connect/net_http.go:777, connect/net.go:232), egress-bound as
	// connect/net_http.go:3663-3668 requires; sidecar_http's is net/http's fetch
	transport http.RoundTripper
}

// A client of api on settings, which must pass validate, so no route builds a url on an empty or
// relative service url. transport carries every request; nil is the leg's default, which on
// sidecar_http is fetch and on a connect leg refuses until the core installs its client strategy's
// with setTransport. Whatever transport is given goes behind absoluteUrlTransport. now is the clock a
// Retry-After given as a date is read against, which a test fixes; nil is real time.
func newSidecarApi(settings *SidecarSettings, transport http.RoundTripper, now func() time.Time) (*SidecarApi, error) {
	if err := settings.validate(); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &SidecarApi{
		settings:  settings,
		log:       loggerOrDefault(settings.Log),
		now:       now,
		transport: wrapSidecarApiTransport(transport),
	}, nil
}

// transport behind absoluteUrlTransport, once, with nil as the leg's default.
func wrapSidecarApiTransport(transport http.RoundTripper) http.RoundTripper {
	if transport == nil {
		transport = defaultSidecarApiTransport()
	}
	if _, ok := transport.(*absoluteUrlTransport); ok {
		return transport
	}
	return &absoluteUrlTransport{transport: transport}
}

// Installs the token every later call presents. The token manager calls it only after persisting
// the token to the keychain (D-CORE-8), and calls in flight keep the token they started with.
func (self *SidecarApi) SetByJwt(byJwt string) {
	testHookSecret("by_client_jwt", []byte(byJwt))
	testHookBarrier("api.set_by_jwt.before", "")
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.byJwt = byJwt
	}()
	testHookBarrier("api.set_by_jwt.after", "")
}

// The installed token, for the token manager's schedule, which reads its claims. Never for a reply,
// a log or an environment (I-7).
func (self *SidecarApi) currentByJwt() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.byJwt
}

// Installs the ClientKey's proof signer, newDpopSigner's. nil removes it, after which no call that
// needs a proof is sent.
func (self *SidecarApi) setDpopSigner(dpopSigner func(method string, url string, ath string) (string, error)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.dpopSigner = dpopSigner
}

// The transport every call goes through, behind absoluteUrlTransport: what another client of a service, such as
// evs's (EvsClientArgs.Transport), dials with, so it binds to the same egress and never reaches net/http's default.
func (self *SidecarApi) Transport() http.RoundTripper {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.transport
}

// Replaces the transport, as a connect leg does with each client strategy's
// (newSidecarApiTransport), and drops the old one's idle connections. nil is the leg's default.
func (self *SidecarApi) setTransport(transport http.RoundTripper) {
	transport = wrapSidecarApiTransport(transport)
	var oldTransport http.RoundTripper
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		oldTransport = self.transport
		self.transport = transport
	}()
	if closer, ok := oldTransport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// Says what it is and nothing it holds, so a %v of it cannot print the token.
func (self *SidecarApi) String() string {
	return "SidecarApi"
}

// As String, for %#v.
func (self *SidecarApi) GoString() string {
	return "SidecarApi"
}

// One request of a route.
type sidecarApiRequest struct {
	// The route's method and path template, for errors and logs: never the url.
	route string
	// A literal naming the route for testHookBarrier's key, such as "refresh".
	operation string
	method    string
	// The absolute url, built on a validated service url.
	url string
	// The body and its type. Empty for none.
	body        []byte
	contentType string
	// Builds the body from the jwt the call presents, in place of body, so a body that carries the
	// token, as the exchange's subject token does, carries the one its proof hashes.
	buildBody func(byJwt string) []byte
	// Presents the jwt as a bearer.
	bearer bool
	// Carries a DPoP proof over the jwt (§7.4).
	dpop bool
}

// Sends request, once, and returns the body of its 2xx answer. A refusal is a *SidecarApiError, and
// a failure before any answer is the transport's error, named by the route and without the url.
func (self *SidecarApi) send(ctx context.Context, request *sidecarApiRequest) ([]byte, error) {
	var byJwt string
	var dpopSigner func(method string, url string, ath string) (string, error)
	var transport http.RoundTripper
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		byJwt = self.byJwt
		dpopSigner = self.dpopSigner
		transport = self.transport
	}()

	if (request.bearer || request.dpop) && byJwt == "" {
		return nil, fmt.Errorf("sidecar api %s: %w", request.route, ErrSidecarApiNoToken)
	}
	proof := ""
	if request.dpop {
		if dpopSigner == nil {
			return nil, fmt.Errorf("sidecar api %s: %w", request.route, ErrSidecarApiNoDpopSigner)
		}
		var err error
		proof, err = dpopSigner(request.method, request.url, dpopAth(byJwt))
		if err != nil {
			return nil, fmt.Errorf("sidecar api %s: %w", request.route, err)
		}
	}

	requestBody := request.body
	if request.buildBody != nil {
		requestBody = request.buildBody(byJwt)
	}
	var body io.Reader
	if requestBody != nil {
		body = bytes.NewReader(requestBody)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, request.method, request.url, body)
	if err != nil {
		// its text would repeat the url
		return nil, fmt.Errorf("sidecar api %s: %w", request.route, ErrSidecarApiArgs)
	}
	httpRequest.Header.Set("Accept", "application/json")
	if request.contentType != "" {
		httpRequest.Header.Set("Content-Type", request.contentType)
	}
	if request.bearer {
		httpRequest.Header.Set("Authorization", "Bearer "+byJwt)
	}
	if proof != "" {
		httpRequest.Header.Set("DPoP", proof)
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(redirect *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	testHookBarrier("api.send.before", request.operation)
	response, err := client.Do(httpRequest)
	testHookBarrier("api.send.after", request.operation)
	if err != nil {
		// net/http's url.Error repeats the url, which may hold an id or a query (I-13)
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return nil, fmt.Errorf("sidecar api %s: %w", request.route, err)
	}
	defer response.Body.Close()

	responseBody, tooLarge, err := readSidecarApiBody(response.Body, self.settings.ApiResponseByteCount)
	if err != nil {
		return nil, fmt.Errorf("sidecar api %s: %w", request.route, err)
	}
	if self.log.V(2).Enabled() {
		self.log.Infof("[api]%s %d\n", request.route, response.StatusCode)
	}
	if response.StatusCode < 200 || 300 <= response.StatusCode {
		return nil, newSidecarApiError(request.route, response, responseBody, self.now)
	}
	if tooLarge {
		return nil, fmt.Errorf("sidecar api %s: %w: past %d bytes", request.route, ErrSidecarApiReply, self.settings.ApiResponseByteCount)
	}
	return responseBody, nil
}

// Sends request with args as its JSON body, when not nil, and decodes the 2xx answer's JSON into
// result, when not nil.
func (self *SidecarApi) sendJson(ctx context.Context, request *sidecarApiRequest, args any, result any) error {
	if args != nil {
		body, err := json.Marshal(args)
		if err != nil {
			return fmt.Errorf("sidecar api %s: %w", request.route, ErrSidecarApiArgs)
		}
		request.body = body
		request.contentType = "application/json"
	}
	responseBody, err := self.send(ctx, request)
	if err != nil {
		return err
	}
	if result == nil {
		return nil
	}
	if err := json.Unmarshal(responseBody, result); err != nil {
		return fmt.Errorf("sidecar api %s: %w", request.route, ErrSidecarApiReply)
	}
	return nil
}

// Up to byteCount bytes of body, and whether there was more, which it leaves unread.
func readSidecarApiBody(body io.Reader, byteCount int64) ([]byte, bool, error) {
	limit := byteCount
	if limit < math.MaxInt64 {
		// one more, to tell a body of exactly byteCount from a longer one
		limit += 1
	}
	responseBody, err := io.ReadAll(io.LimitReader(body, limit))
	if err != nil {
		return nil, false, err
	}
	if byteCount < int64(len(responseBody)) {
		return responseBody[:byteCount], true, nil
	}
	return responseBody, false, nil
}

// Whether code is a structured code and not text: a lowercase letter, then lowercase letters, digits
// and _, as every code api and RFC 6749 define is.
func isSidecarApiCode(code string) bool {
	if code == "" || sidecarApiMaxCodeByteCount < len(code) || code[0] < 'a' || 'z' < code[0] {
		return false
	}
	for i := 1; i < len(code); i += 1 {
		c := code[i]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// The code raw holds when it is a JSON string that isSidecarApiCode takes, else empty.
func sidecarApiCodeOf(raw json.RawMessage) string {
	var code string
	if json.Unmarshal(raw, &code) == nil && isSidecarApiCode(code) {
		return code
	}
	return ""
}

// What a refusal's body may say, in the shapes api answers with: {"error": "<text>", "code":
// "<code>"}, {"error": {"code": "<code>", ...}}, RFC 6749's {"error": "<code>"}, and a QuotaRefusal's
// retry_after_ms (§20.7). Each field is raw, so one of an unexpected type drops only itself, never
// the others beside it.
type sidecarApiErrorBody struct {
	Code         json.RawMessage `json:"code"`
	Error        json.RawMessage `json:"error"`
	RetryAfterMs json.RawMessage `json:"retry_after_ms"`
}

// The refusal a non-2xx answer carries, read from its body and headers: a code only where one is
// well formed, and never the body's text. now is read only for a Retry-After given as a date.
func newSidecarApiError(route string, response *http.Response, body []byte, now func() time.Time) *SidecarApiError {
	apiErr := &SidecarApiError{
		Route:  route,
		Status: response.StatusCode,
	}
	errorBody := &sidecarApiErrorBody{}
	if json.Unmarshal(body, errorBody) == nil {
		apiErr.Code = sidecarApiCodeOf(errorBody.Code)
		if apiErr.Code == "" {
			apiErr.Code = sidecarApiCodeOf(errorBody.Error)
		}
		if apiErr.Code == "" {
			nested := &sidecarApiErrorBody{}
			if json.Unmarshal(errorBody.Error, nested) == nil {
				apiErr.Code = sidecarApiCodeOf(nested.Code)
			}
		}
		var retryAfterMs float64
		if json.Unmarshal(errorBody.RetryAfterMs, &retryAfterMs) == nil {
			apiErr.RetryAfterMs = clampRetryAfterMs(retryAfterMs)
		}
	}
	if apiErr.RetryAfterMs == 0 {
		// RFC 9110 §10.2.3: delay-seconds, which is digits alone, or an HTTP-date in any of its three
		// forms; anything else is no hint
		retryAfter := response.Header.Get("Retry-After")
		if retryAfter != "" && strings.Trim(retryAfter, "0123456789") == "" {
			// digits alone, so the one error is past a uint64, which answers the largest
			seconds, _ := strconv.ParseUint(retryAfter, 10, 64)
			apiErr.RetryAfterMs = clampRetryAfterMs(float64(seconds) * 1000)
		} else if retryTime, err := http.ParseTime(retryAfter); err == nil {
			apiErr.RetryAfterMs = clampRetryAfterMs(float64(retryTime.Sub(now()).Milliseconds()))
		}
	}
	return apiErr
}

// ms as a retry hint: negative and NaN are none, and past a uint32 is its largest.
func clampRetryAfterMs(ms float64) uint32 {
	if !(0 < ms) {
		return 0
	}
	if math.MaxUint32 < ms {
		return math.MaxUint32
	}
	return uint32(ms)
}

// The error object refresh, auth-client and remove-client put in a 200 to refuse.
type sidecarApiResultError struct {
	Message string `json:"message"`
	Code    string `json:"code"`
	// auth-client's limits (connect/api/bringyour.yml's AuthNetworkClientResult)
	ClientLimitExceeded bool `json:"client_limit_exceeded"`
	UpgradeRequired     bool `json:"upgrade_required"`
}

// The refusal a 200's error object makes, with its code, or auth-client's limit as one.
func (self *sidecarApiResultError) apiError(route string) *SidecarApiError {
	code := ""
	switch {
	case isSidecarApiCode(self.Code):
		code = self.Code
	case self.UpgradeRequired:
		code = "upgrade_required"
	case self.ClientLimitExceeded:
		code = "client_limit_exceeded"
	}
	return &SidecarApiError{
		Route:  route,
		Status: http.StatusOK,
		Code:   code,
	}
}
