// The client's transport to evs (§11.20's routes), on every leg: net/http over SidecarApi's transport, which dials by
// the client strategy on a connect leg and is fetch in the page Worker, behind absoluteUrlTransport, so no request
// carries a token anywhere but an absolute evs url (api_transport.go).
//
// Each call presents a service token for evs with the repo scope its route takes (§7.8: repo:<id>:deposit|r|rw|admin),
// from the caller's ServiceToken, which keeps a token at most 10 of its 15 minutes and never across a client
// generation. A token carries one repo scope here, well under the 64 one exchange may ask for. The token goes only
// into the request's Authorization header: never into a url, a reply, an error or a log (I-7). URLs carry opaque ids
// only (I-13), and an error never repeats a url or a body.
//
// Answers map to typed errors: every answer but a 200 is an *EvsError, its code from §11.8's fixed table with
// recorded, retry_after_ms, outcome unknown, the paths a 409 names, needs_format, §20.7's QuotaRefusal and a
// depositor's head, as EvsRefusalReply carries them. A read retries a 429 or a 503 that refuses nothing, after
// retry_after_ms; nothing else retries here, since a push's retries are the push sender's, under its one push id
// (§11.8's retry id row).
//
// The read reply is a stream of u32be(length) | EvsReadFrame (plan-EVS1-format-bytes#8), which EvsReadFrames reads one
// frame at a time, so a reply of 32 MiB of ranges is never held whole (R-EVS-14).
//
// Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The body type of every evs request and answer but a segment PUT's raw bytes.
const evsHttpContentType = "application/x-protobuf"

// The most one read frame takes: an object's 1 MiB slice (EvsReadObject spans frames past it) and room for its
// fields, or a path reply with its proofs, or a statement. A longer one is refused, so evs cannot make a reader
// buffer more.
const evsReadFrameMaxByteCount = 1024*1024 + 64*1024

// The audience prefix and roles of an evs capability scope (§7.8).
const (
	evsScopeRead    = "r"
	evsScopeWrite   = "rw"
	evsScopeAdmin   = "admin"
	evsScopeDeposit = "deposit"
)

var (
	// A method this draft of the client does not build yet: the task that builds it is named in the error, and the
	// call does nothing.
	ErrEvsNotBuilt = errors.New("evs: not built")
	// evs refused the call's token (401): the token exchange's subject is revoked, or the token is past its life.
	ErrEvsUnauthorized = errors.New("evs: token refused")
	// An answer that does not hold §11.20's form: a body that does not parse, a frame past its bound, a stream cut
	// short. Never read as a refusal.
	ErrEvsReplyInvalid = errors.New("evs: reply invalid")
)

// A service token for an audience url with scopes, Sidecar.ServiceToken's shape: for an in-process caller only.
type EvsServiceTokenFunction func(ctx context.Context, resource string, scopes []string) (string, error)

// Every answer of evs's but a 200 (§11.20), as EvsRefusalReply carries it. Its text names the status and code and
// never a path, an id or a token.
type EvsError struct {
	Status int
	Code   protocol.EvsRefusalCode
	// The push, part, seal or lease the answer is about.
	PushId *Id
	// The head's refusal records answered this attempt (§11.8's refuse row): every later attempt of its push id gets
	// the same answer.
	Recorded bool
	// A 429's, or a 503's where it applies; Retry-After's when the body names none.
	RetryAfter time.Duration
	// A 503 {outcome: unknown}: the attempt may yet have committed, which a retry of the same push id resolves.
	OutcomeUnknown bool
	// What a 409 names, in the push's path epoch.
	Paths []EvsTokenPath
	// FORMAT_UNSUPPORTED's needs_format.
	NeedsFormat uint32
	// QUOTA_PAYMENT, QUOTA_LIMIT and RESOURCE_EXHAUSTED past a quota (§20.7).
	Quota *protocol.EvsQuotaRefusal
	// BASE_STALE, or a push's 200, on the caller's own deposit ref (plan-EVS1-deposit-head).
	DepositHead *protocol.EvsDepositHead
}

// The status and code, and whether the refusal was recorded or its outcome is unknown.
func (self *EvsError) Error() string {
	text := fmt.Sprintf("evs refused: %d %s", self.Status, self.Code)
	if self.Recorded {
		text += " (recorded)"
	}
	if self.OutcomeUnknown {
		text += " (outcome unknown)"
	}
	return text
}

// Whether the answer refuses nothing, so the same request may go again after RetryAfter: a 429, or a 503 whose
// outcome is not unknown.
func (self *EvsError) RefusesNothing() bool {
	if self.OutcomeUnknown {
		return false
	}
	return self.Status == http.StatusTooManyRequests || self.Status == http.StatusServiceUnavailable
}

// The *EvsError err holds, and false for any other error.
func EvsErrorOf(err error) (*EvsError, bool) {
	var evsError *EvsError
	if errors.As(err, &evsError) {
		return evsError, true
	}
	return nil, false
}

// Whether err is evs's answer with code.
func IsEvsRefusal(err error, code protocol.EvsRefusalCode) bool {
	evsError, ok := EvsErrorOf(err)
	return ok && evsError.Code == code
}

// One call to evs.
type evsCall struct {
	// The route's template for errors: its method and pattern, which hold no id.
	route  string
	method string
	// After the service url: /evs/v1/..., opaque ids only (I-13).
	path string
	// The repo the token's scope names, and the role the route takes.
	repoId Id
	role   string
	// A protobuf body, or nil for none.
	body proto.Message
	// Raw bytes instead, for a segment PUT.
	rawBody []byte
	// Whether a 429 or a 503 that refuses nothing goes again (reads only).
	retry bool
}

// The client's half of evs's HTTP surface.
type evsHttp struct {
	baseUrl      string
	transport    http.RoundTripper
	serviceToken EvsServiceTokenFunction
	settings     *EvsSettings
	clock        Clock
}

// An id as a route's path and query name it: 32 lowercase hex characters with no dashes, as evs parses them and as
// object keys hold them (plan-EVS1-format-bytes#9).
func evsUrlId(id Id) string {
	return hex.EncodeToString(id[:])
}

// The repo scope one call presents.
func evsRepoScope(repoId Id, role string) string {
	return sidecarExchangeRepoScopePrefix + repoId.String() + ":" + role
}

// Sends call and answers the 200's body, at most limit bytes, or an *EvsError for any other answer.
func (self *evsHttp) do(ctx context.Context, call *evsCall, limit int64) ([]byte, error) {
	response, err := self.send(ctx, call)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: the answer was cut short", ErrEvsReplyInvalid, call.route)
	}
	if limit < int64(len(body)) {
		return nil, fmt.Errorf("%w: %s: an answer past %d bytes", ErrEvsReplyInvalid, call.route, limit)
	}
	return body, nil
}

// Sends call and unmarshals the 200's body into reply, which may be nil for an answer with no body.
func (self *evsHttp) callMessage(ctx context.Context, call *evsCall, reply proto.Message) error {
	body, err := self.do(ctx, call, self.settings.ReplyMaxByteCount)
	if err != nil {
		return err
	}
	if reply == nil {
		return nil
	}
	if err := proto.Unmarshal(body, reply); err != nil {
		return fmt.Errorf("%w: %s: a body that does not parse", ErrEvsReplyInvalid, call.route)
	}
	return nil
}

// Sends call, retrying as call.retry allows, and answers a 200's response with its body unread, or an *EvsError.
// The caller closes the body.
func (self *evsHttp) send(ctx context.Context, call *evsCall) (*http.Response, error) {
	attempts := 1
	if call.retry {
		attempts += self.settings.ReadRetryCount
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt += 1 {
		response, err := self.sendOnce(ctx, call)
		if err == nil {
			return response, nil
		}
		lastErr = err
		evsError, ok := EvsErrorOf(err)
		if !ok || !call.retry || !evsError.RefusesNothing() || attempt+1 == attempts {
			return nil, err
		}
		wait := evsError.RetryAfter
		if wait <= 0 {
			wait = self.settings.ReadRetryWait
		}
		if self.settings.ReadRetryMaxWait < wait {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-self.clock.After(wait):
		}
	}
	return nil, lastErr
}

// One attempt.
func (self *evsHttp) sendOnce(ctx context.Context, call *evsCall) (*http.Response, error) {
	var body []byte
	switch {
	case call.body != nil:
		var err error
		body, err = proto.MarshalOptions{Deterministic: true}.Marshal(call.body)
		if err != nil {
			return nil, fmt.Errorf("evs %s: a body that does not marshal: %w", call.route, err)
		}
	case call.rawBody != nil:
		body = call.rawBody
	}
	token, err := self.serviceToken(ctx, self.baseUrl, []string{evsRepoScope(call.repoId, call.role)})
	if err != nil {
		return nil, fmt.Errorf("evs %s: no service token: %w", call.route, err)
	}
	callCtx, cancel := context.WithCancel(ctx)
	stop := self.clock.AfterFunc(self.settings.RequestTimeout, cancel)
	request, err := http.NewRequestWithContext(callCtx, call.method, self.baseUrl+call.path, bytes.NewReader(body))
	if err != nil {
		stop()
		cancel()
		return nil, fmt.Errorf("evs %s: a request that does not build", call.route)
	}
	if body != nil {
		if call.rawBody != nil {
			request.Header.Set("Content-Type", "application/octet-stream")
		} else {
			request.Header.Set("Content-Type", evsHttpContentType)
		}
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := self.transport.RoundTrip(request)
	if err != nil {
		stop()
		cancel()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// a transport error may hold the url, which holds only ids, but never the token
		return nil, fmt.Errorf("evs %s: %w", call.route, err)
	}
	if response.StatusCode == http.StatusOK {
		// the body's reader ends the deadline once it is closed
		response.Body = &evsHttpBody{ReadCloser: response.Body, done: func() { stop(); cancel() }}
		return response, nil
	}
	defer func() {
		response.Body.Close()
		stop()
		cancel()
	}()
	if response.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("%w: %s", ErrEvsUnauthorized, call.route)
	}
	refusalBody, _ := io.ReadAll(io.LimitReader(response.Body, self.settings.ReplyMaxByteCount))
	return nil, evsErrorOfAnswer(response, refusalBody)
}

// A 200's body, which ends the call's deadline when closed.
type evsHttpBody struct {
	io.ReadCloser
	done func()
}

// Closes the body and ends the call's deadline.
func (self *evsHttpBody) Close() error {
	err := self.ReadCloser.Close()
	self.done()
	return err
}

// The *EvsError a refusal's status and body give. A body that does not parse leaves the code the status's own:
// UNAVAILABLE for a 503, WAIT for a 429, else unspecified, so a proxy's error page is never read as a code.
func evsErrorOfAnswer(response *http.Response, body []byte) *EvsError {
	evsError := &EvsError{Status: response.StatusCode}
	reply := &protocol.EvsRefusalReply{}
	if err := proto.Unmarshal(body, reply); err == nil && len(body) != 0 {
		if status, ok := EvsRefusalStatus(reply.GetCode()); ok && status == response.StatusCode {
			evsError.Code = reply.GetCode()
		}
		if pushId, err := IdFromBytes(reply.GetPushId()); err == nil {
			evsError.PushId = &pushId
		}
		evsError.Recorded = reply.GetRecorded()
		evsError.RetryAfter = time.Duration(reply.GetRetryAfterMs()) * time.Millisecond
		evsError.OutcomeUnknown = reply.GetOutcome() == protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN
		for _, path := range reply.GetPaths() {
			if tokenPath, err := ParseEvsTokenPath(path.GetToken()); err == nil {
				evsError.Paths = append(evsError.Paths, tokenPath)
			}
		}
		evsError.NeedsFormat = reply.GetNeedsFormat()
		evsError.Quota = reply.GetQuota()
		evsError.DepositHead = reply.GetDepositHead()
	}
	if evsError.Code == protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED {
		switch response.StatusCode {
		case http.StatusServiceUnavailable:
			evsError.Code = protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE
		case http.StatusTooManyRequests:
			evsError.Code = protocol.EvsRefusalCode_EVS_REFUSAL_WAIT
		}
	}
	if evsError.RetryAfter <= 0 {
		if seconds, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil && 0 < seconds {
			evsError.RetryAfter = time.Duration(seconds) * time.Second
		}
	}
	return evsError
}

// Reads a read reply's frames one at a time: u32be(length) | EvsReadFrame, each at most evsReadFrameMaxByteCount,
// the last with end set. Not safe for concurrent use.
type EvsReadFrames struct {
	in    io.Reader
	ended bool
}

// Reads frames from in.
func NewEvsReadFrames(in io.Reader) *EvsReadFrames {
	return &EvsReadFrames{in: in}
}

// The next frame. io.EOF once the frame with end set has been read; a stream that stops before it, or a frame
// that does not parse or passes its bound, is ErrEvsReplyInvalid.
func (self *EvsReadFrames) Next() (*protocol.EvsReadFrame, error) {
	if self.ended {
		return nil, io.EOF
	}
	lengthBytes := [4]byte{}
	if _, err := io.ReadFull(self.in, lengthBytes[:]); err != nil {
		return nil, fmt.Errorf("%w: a read reply that ends before its last frame", ErrEvsReplyInvalid)
	}
	length := binary.BigEndian.Uint32(lengthBytes[:])
	if evsReadFrameMaxByteCount < length {
		return nil, fmt.Errorf("%w: a read frame of %d bytes", ErrEvsReplyInvalid, length)
	}
	frameBytes := make([]byte, length)
	if _, err := io.ReadFull(self.in, frameBytes); err != nil {
		return nil, fmt.Errorf("%w: a read frame cut short", ErrEvsReplyInvalid)
	}
	frame := &protocol.EvsReadFrame{}
	if err := proto.Unmarshal(frameBytes, frame); err != nil {
		return nil, fmt.Errorf("%w: a read frame that does not parse", ErrEvsReplyInvalid)
	}
	if frame.GetEnd() {
		self.ended = true
	}
	return frame, nil
}

// One frame's bytes as a read reply carries it, for evs and for tests that stand in for it.
func EncodeEvsReadFrame(frame *protocol.EvsReadFrame) ([]byte, error) {
	frameBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(frame)
	if err != nil {
		return nil, err
	}
	if evsReadFrameMaxByteCount < len(frameBytes) {
		return nil, fmt.Errorf("%w: a read frame of %d bytes", ErrEvsReplyInvalid, len(frameBytes))
	}
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(frameBytes))), frameBytes...), nil
}
