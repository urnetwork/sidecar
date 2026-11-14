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
// depositor's head, as EvsRefusalReply carries them. A 502 or 504 whose body is not an evs refusal is the lb's
// answer, no answer from evs at all, so its outcome is unknown (QD-758): the lb answers a streamed segment PUT whose
// upstream died so, since it cannot send a body it has begun streaming to another block. A read retries a 429 or a
// 503 that refuses nothing, after retry_after_ms; nothing else retries here, since a push's retries are the push
// sender's, under its one push id, and the uploads', each with its same bytes (§11.8's retry id row).
//
// The read reply is a stream of u32be(length) | EvsReadFrame (plan-EVS1-format-bytes#8), which EvsReadFrames reads one
// frame at a time, so a reply of 32 MiB of ranges is never held whole (R-EVS-14), a directory's delta frames folded
// back into its path and an error frame answered as its refusal (QD-662).
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
	// A 503 {outcome: unknown}: the attempt may yet have committed, which a retry of the same push id resolves. So is
	// a 502 or 504 whose body is not an evs refusal, which is the lb's answer and none from evs (QD-758): the push
	// sender and the uploads send that attempt's bytes again, as when nothing answered.
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
//
// A 502 or 504 whose body is not an evs refusal, an EvsRefusalReply naming a code of §11.8's table, is the lb's
// answer and no answer from evs at all (QD-758): nginx's, when the block a request reached died or went silent
// under it and it could not pass the request on, as with a streamed segment PUT once its body has begun, or when
// its tries ran out. Nothing of its body is read, and its outcome is unknown, so retryRefusingNothing sends the same
// bytes again after ReadRetryWait, as for no answer, until §11.8's 200, 409 or 412; a read, which retries no lost
// answer here, takes it as it took one before. An evs refusal a 502 or 504 carries keeps its meaning, as any other
// answer's does.
func evsErrorOfAnswer(response *http.Response, body []byte) *EvsError {
	reply := &protocol.EvsRefusalReply{}
	parsed := len(body) != 0 && proto.Unmarshal(body, reply) == nil
	if response.StatusCode == http.StatusBadGateway || response.StatusCode == http.StatusGatewayTimeout {
		if _, refusal := EvsRefusalStatus(reply.GetCode()); !parsed || !refusal {
			return &EvsError{Status: response.StatusCode, OutcomeUnknown: true}
		}
	}
	evsError := &EvsError{Status: response.StatusCode}
	if parsed {
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

// Reads a read reply's frames one at a time: u32be(length) | EvsReadFrame, each at most the format's
// ReadFrameMaxByteCount, the last with end set. A directory's deltas come one a frame after its path frame, each a
// path frame of its token path with continues set and that delta alone (QD-662), with its delta_proofs entry beside
// it (QD-681), which Next folds back into the path's deltas and delta_proofs, one proof entry a delta, at most
// ReadPathDeltaMaxCount of them, so a caller sees a path in one frame as before; a frame with error set ends the
// reply as that refusal. Not safe for concurrent use.
type EvsReadFrames struct {
	in     io.Reader
	format *EvsFormatSettings
	ended  bool
	// the frame read past a path's last delta frame, or the error met reading it, which the next call returns
	held    *protocol.EvsReadFrame
	heldErr error
}

// Reads frames from in, under the format's bounds.
func NewEvsReadFrames(in io.Reader) *EvsReadFrames {
	return &EvsReadFrames{in: in, format: DefaultEvsFormatSettings()}
}

// The next frame, a path's delta frames folded into it. io.EOF once the frame with end set has been read; a stream
// that stops before it, a frame that does not parse or passes its bound, or a delta frame that does not continue the
// path before it, is ErrEvsReplyInvalid; an error frame is evs's *EvsError, UNAVAILABLE as evs sends it.
func (self *EvsReadFrames) Next() (*protocol.EvsReadFrame, error) {
	frame, err := self.nextFrame()
	if err != nil || frame.GetPath() == nil {
		return frame, err
	}
	path := frame.GetPath()
	if path.GetContinues() {
		return nil, fmt.Errorf("%w: a delta frame with no path before it", ErrEvsReplyInvalid)
	}
	for {
		following, err := self.nextFrame()
		if err != nil {
			// the path stands as far as it came; the error ends the reply at the next call
			self.heldErr = err
			return frame, nil
		}
		if !following.GetPath().GetContinues() {
			self.held = following
			return frame, nil
		}
		delta := following.GetPath()
		if !evsDeltaFrameContinues(path, following) {
			return nil, fmt.Errorf("%w: a delta frame that does not continue the path before it", ErrEvsReplyInvalid)
		}
		if self.format.ReadPathDeltaMaxCount <= len(path.GetDeltas()) {
			return nil, fmt.Errorf("%w: a path of more than %d deltas", ErrEvsReplyInvalid, self.format.ReadPathDeltaMaxCount)
		}
		// one delta_proofs entry a delta, in order: an entry a frame left out is an empty proof, which stands only for
		// an inline statement's delta (QD-681)
		if len(path.GetDeltas()) < len(path.GetDeltaProofs()) {
			return nil, fmt.Errorf("%w: a path of more delta proofs than deltas", ErrEvsReplyInvalid)
		}
		for len(path.GetDeltaProofs()) < len(path.GetDeltas()) {
			path.DeltaProofs = append(path.DeltaProofs, &protocol.EvsDeltaProof{})
		}
		path.Deltas = append(path.Deltas, delta.GetDeltas()...)
		if len(delta.GetDeltaProofs()) == 1 {
			path.DeltaProofs = append(path.DeltaProofs, delta.GetDeltaProofs()[0])
		} else {
			path.DeltaProofs = append(path.DeltaProofs, &protocol.EvsDeltaProof{})
		}
	}
}

// Whether a delta frame continues path: its token path, one delta, at most that delta's one delta_proofs entry, and
// nothing else, so no part of a path but its deltas and their proofs is ever taken from a frame after its own.
func evsDeltaFrameContinues(path *protocol.EvsReadPathReply, frame *protocol.EvsReadFrame) bool {
	delta := frame.GetPath()
	if frame.GetHead() != nil || frame.GetStatement() != nil || frame.GetBehind() != 0 || frame.GetMore() != 0 ||
		frame.GetObject() != nil || frame.GetEnd() || frame.GetError() != nil {
		return false
	}
	if len(delta.GetDeltas()) != 1 || 1 < len(delta.GetDeltaProofs()) || len(delta.GetTokenPath()) != len(path.GetTokenPath()) {
		return false
	}
	for i, token := range delta.GetTokenPath() {
		if !bytes.Equal(token, path.GetTokenPath()[i]) {
			return false
		}
	}
	// what is left once its token path, its delta, that delta's proof and continues are set aside, with no copy of
	// the delta's bytes
	tokenPath, deltas, deltaProofs := delta.TokenPath, delta.Deltas, delta.DeltaProofs
	delta.TokenPath, delta.Deltas, delta.DeltaProofs, delta.Continues = nil, nil, nil, false
	rest := proto.Size(delta)
	delta.TokenPath, delta.Deltas, delta.DeltaProofs, delta.Continues = tokenPath, deltas, deltaProofs, true
	return rest == 0
}

// The next frame as it came. A frame with error set ends the reply: its refusal, with nothing read after it.
func (self *EvsReadFrames) nextFrame() (*protocol.EvsReadFrame, error) {
	if held := self.held; held != nil {
		self.held = nil
		return held, nil
	}
	if err := self.heldErr; err != nil {
		self.heldErr = nil
		return nil, err
	}
	if self.ended {
		return nil, io.EOF
	}
	lengthBytes := [4]byte{}
	if _, err := io.ReadFull(self.in, lengthBytes[:]); err != nil {
		return nil, fmt.Errorf("%w: a read reply that ends before its last frame", ErrEvsReplyInvalid)
	}
	length := binary.BigEndian.Uint32(lengthBytes[:])
	if uint64(self.format.ReadFrameMaxByteCount) < uint64(length) {
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
	if refusal := frame.GetError(); refusal != nil {
		self.ended = true
		return nil, evsErrorOfReadFrame(refusal)
	}
	if frame.GetEnd() {
		self.ended = true
	}
	return frame, nil
}

// The *EvsError an error frame gives: its code where it is one a refusal answers, else UNAVAILABLE, a 503 either way
// that refuses nothing, since the read changed nothing; and its retry delay.
func evsErrorOfReadFrame(refusal *protocol.EvsRefusalReply) *EvsError {
	evsError := &EvsError{
		Status:     http.StatusServiceUnavailable,
		Code:       protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE,
		RetryAfter: time.Duration(refusal.GetRetryAfterMs()) * time.Millisecond,
	}
	if status, ok := EvsRefusalStatus(refusal.GetCode()); ok && status == http.StatusServiceUnavailable {
		evsError.Code = refusal.GetCode()
	}
	return evsError
}

// One frame's bytes as a read reply carries it, for evs and for tests that stand in for it: at most the format's
// ReadFrameMaxByteCount.
func EncodeEvsReadFrame(frame *protocol.EvsReadFrame) ([]byte, error) {
	frameBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(frame)
	if err != nil {
		return nil, err
	}
	if DefaultEvsFormatSettings().ReadFrameMaxByteCount < len(frameBytes) {
		return nil, fmt.Errorf("%w: a read frame of %d bytes", ErrEvsReplyInvalid, len(frameBytes))
	}
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(frameBytes))), frameBytes...), nil
}
