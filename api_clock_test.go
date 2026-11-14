// The api's clock as SidecarApi keeps it (§7.4, QD-757): the offset each answer's Date gives, the iat a
// proof is signed by, and the one request more a proof refused for its iat gets. The api here is in this
// process, on a clock of its own, and holds a proof's iat within §7.4's 60 s of it, answering a proof
// outside it as server's routes do: the exchange 400 invalid_dpop_proof, the strict_exp proof gate 403
// in plain text. Runs on every leg, since it opens nothing.

package sidecar

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"
)

// §7.4's iat window, as server's session.DpopSettings and sidecartest's fake api hold it.
const testApiClockIatWindow = 60 * time.Second

// An api on its own clock and a device whose clock runs deviceOffset from it.
type testApiClockWorld struct {
	t         *testing.T
	api       *SidecarApi
	transport *scriptedApiTransport
	publicKey ed25519.PublicKey

	stateLock sync.Mutex
	// the api's clock
	apiNow time.Time
	// the device's clock less the api's
	deviceOffset time.Duration
	// called as each request arrives, before its answer: how a test moves a clock inside a round trip
	arrive func(requestIndex int)
	// answers a request in place of the api's own answer, when it returns one
	override func(request *http.Request, requestIndex int) *http.Response
	// each proof's claims, in the order the requests came
	proofs []*testDpopClaims
	// leaves Date off every answer, as a page Worker's fetch hides it
	noDate bool
}

func newTestApiClockWorld(t *testing.T, deviceOffset time.Duration) *testApiClockWorld {
	t.Helper()
	world := &testApiClockWorld{
		t:            t,
		apiNow:       time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		deviceOffset: deviceOffset,
	}
	world.transport = &scriptedApiTransport{answer: world.answer}
	api, err := newSidecarApi(validSidecarSettings(), world.transport, world.deviceNow)
	if err != nil {
		t.Fatal(err)
	}
	api.SetByJwt(testByJwt)
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x42
	}
	signer, err := newDpopSigner(seed, world.deviceNow, api.currentApiClockOffset, cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	api.setDpopSigner(signer)
	world.api = api
	world.publicKey = ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return world
}

func (self *testApiClockWorld) deviceNow() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.apiNow.Add(self.deviceOffset)
}

// Moves the api's clock, the device's following at its offset.
func (self *testApiClockWorld) advance(timeout time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.apiNow = self.apiNow.Add(timeout)
}

// Sets the device's clock, as a user or NTP does.
func (self *testApiClockWorld) setDeviceOffset(deviceOffset time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.deviceOffset = deviceOffset
}

// Stamps header with the api's clock, unless the world hides it.
func (self *testApiClockWorld) date(header http.Header, apiNow time.Time) http.Header {
	if !self.noDate {
		header.Set("Date", apiNow.Format(http.TimeFormat))
	}
	return header
}

// The api: a proof whose iat is outside the window is refused as server's routes refuse one, and every
// other request is answered with its route's 200.
func (self *testApiClockWorld) answer(request *http.Request, body []byte) (*http.Response, error) {
	requestIndex := self.transport.requestCount() - 1
	if self.arrive != nil {
		self.arrive(requestIndex)
	}
	self.stateLock.Lock()
	apiNow := self.apiNow
	self.stateLock.Unlock()
	if self.override != nil {
		if response := self.override(request, requestIndex); response != nil {
			return response, nil
		}
	}
	if proof := request.Header.Get("DPoP"); proof != "" {
		claims := verifyTestDpopProof(self.t, proof, self.publicKey)
		self.stateLock.Lock()
		self.proofs = append(self.proofs, claims)
		self.stateLock.Unlock()
		if age := apiNow.Sub(time.Unix(claims.Iat, 0)); age < -testApiClockIatWindow || testApiClockIatWindow < age {
			return self.proofRefusal(request, apiNow), nil
		}
	}
	header := self.date(http.Header{}, apiNow)
	switch request.URL.Path {
	case "/auth/refresh":
		return syntheticResponse(request, 200, `{"by_jwt":"synthetic-refresh-jwt"}`, header), nil
	case "/network/auth-client":
		return syntheticResponse(request, 200, `{"by_client_jwt":"synthetic-child-jwt"}`, header), nil
	case "/oauth/token":
		return syntheticResponse(request, 200, `{"access_token":"synthetic-service-token","expires_in":900}`, header), nil
	}
	return syntheticResponse(request, 200, `{}`, header), nil
}

// How api refuses a proof on request's route.
func (self *testApiClockWorld) proofRefusal(request *http.Request, apiNow time.Time) *http.Response {
	if request.URL.Path == "/oauth/token" {
		return syntheticResponse(request, 400, `{"error":"invalid_dpop_proof","error_description":"The DPoP proof is invalid."}`, self.date(http.Header{}, apiNow))
	}
	header := self.date(http.Header{"Content-Type": {"text/plain"}}, apiNow)
	return syntheticResponse(request, 403, "A sidecar token needs a proof of its client key on this route.\n", header)
}

// One call of each route that carries a proof, by name.
func (self *testApiClockWorld) proofCalls() []struct {
	name string
	call func() error
} {
	ctx := context.Background()
	return []struct {
		name string
		call func() error
	}{
		{name: "GET /auth/refresh", call: func() error {
			_, err := self.api.Refresh(ctx)
			return err
		}},
		{name: "POST /oauth/token", call: func() error {
			_, err := self.api.ExchangeToken(ctx, "https://evs.example", nil)
			return err
		}},
		{name: "POST /network/auth-client", call: func() error {
			_, err := self.api.AuthClient(ctx, &SidecarAuthClientArgs{})
			return err
		}},
	}
}

// The proofs the api has seen.
func (self *testApiClockWorld) seenProofs() []*testDpopClaims {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*testDpopClaims{}, self.proofs...)
}

// Any answer of api's gives its clock: after one, a device 10 min off either way signs iat at the api's
// time, at each route that carries a proof, in one request.
func TestApiClockOffsetIsReadFromAnAnswersDate(t *testing.T) {
	for _, deviceOffset := range []time.Duration{10 * time.Minute, -10 * time.Minute, 0} {
		world := newTestApiClockWorld(t, deviceOffset)
		if offset := world.api.currentApiClockOffset(); offset != 0 {
			t.Fatalf("an offset of %s before any answer", offset)
		}
		// a route with no proof: its answer still carries Date
		if err := world.api.RemoveClient(context.Background(), NewId()); err != nil {
			t.Fatal(err)
		}
		if offset := world.api.currentApiClockOffset(); offset != -deviceOffset {
			t.Errorf("device %s: offset %s", deviceOffset, offset)
		}
		for i, proofCall := range world.proofCalls() {
			world.advance(7 * time.Second)
			before := world.transport.requestCount()
			if err := proofCall.call(); err != nil {
				t.Errorf("device %s, %s: %v", deviceOffset, proofCall.name, err)
			}
			if sent := world.transport.requestCount() - before; sent != 1 {
				t.Errorf("device %s, %s: %d requests", deviceOffset, proofCall.name, sent)
			}
			proofs := world.seenProofs()
			if len(proofs) != i+1 {
				t.Fatalf("device %s, %s: %d proofs", deviceOffset, proofCall.name, len(proofs))
			}
			if iat := proofs[i].Iat; iat != world.apiNow.Unix() {
				t.Errorf("device %s, %s: iat %d, the api's clock reads %d", deviceOffset, proofCall.name, iat, world.apiNow.Unix())
			}
		}
	}
}

// A device 10 min off that has heard nothing from api yet signs its first proof on its own clock, is
// refused for it, reads the api's clock from the refusal and signs once more: two requests, two proofs
// with jtis of their own, the second at the api's time, and the call succeeds.
func TestProofRefusedForIatIsSignedOnceMore(t *testing.T) {
	for _, deviceOffset := range []time.Duration{10 * time.Minute, -10 * time.Minute} {
		for i := range 3 {
			world := newTestApiClockWorld(t, deviceOffset)
			proofCall := world.proofCalls()[i]
			if err := proofCall.call(); err != nil {
				t.Errorf("device %s, %s: %v", deviceOffset, proofCall.name, err)
				continue
			}
			proofs := world.seenProofs()
			if world.transport.requestCount() != 2 || len(proofs) != 2 {
				t.Errorf("device %s, %s: %d requests, %d proofs", deviceOffset, proofCall.name, world.transport.requestCount(), len(proofs))
				continue
			}
			if proofs[0].Iat != world.deviceNow().Unix() || proofs[1].Iat != world.apiNow.Unix() {
				t.Errorf("device %s, %s: iat %d then %d", deviceOffset, proofCall.name, proofs[0].Iat, proofs[1].Iat)
			}
			if proofs[0].Jti == proofs[1].Jti {
				t.Errorf("device %s, %s: the second request repeated the first's jti", deviceOffset, proofCall.name)
			}
			if proofs[0].Htm != proofs[1].Htm || proofs[0].Htu != proofs[1].Htu || proofs[0].Ath != proofs[1].Ath {
				t.Errorf("device %s, %s: the second proof names another request", deviceOffset, proofCall.name)
			}
			// the next call needs no second request
			if err := proofCall.call(); err != nil || world.transport.requestCount() != 3 {
				t.Errorf("device %s, %s: the next call sent %d requests: %v", deviceOffset, proofCall.name, world.transport.requestCount()-2, err)
			}
		}
	}
}

// A device whose clock is set after an offset was read is refused once at its next proof and mended by
// the refusal, as at its first.
func TestProofSignedOnAStaleOffsetIsSignedOnceMore(t *testing.T) {
	world := newTestApiClockWorld(t, 10*time.Minute)
	if _, err := world.api.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	world.setDeviceOffset(0)
	before := world.transport.requestCount()
	if _, err := world.api.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sent := world.transport.requestCount() - before; sent != 2 {
		t.Errorf("%d requests after the clock was set", sent)
	}
	if offset := world.api.currentApiClockOffset(); offset != 0 {
		t.Errorf("offset %s", offset)
	}
}

// A proof refused while the refusal's Date moves the api's clock less than ApiClockRetryShift was not
// refused for its iat: the request is not sent again, and the refusal is the call's.
func TestProofRefusalThatMovesNoClockIsNotSentAgain(t *testing.T) {
	for i := range 3 {
		world := newTestApiClockWorld(t, 10*time.Minute)
		proofCall := world.proofCalls()[i]
		if err := world.api.RemoveClient(context.Background(), NewId()); err != nil {
			t.Fatal(err)
		}
		// the api refuses every proof from here, as it does one by a key it has not bound
		world.override = func(request *http.Request, requestIndex int) *http.Response {
			if request.Header.Get("DPoP") == "" {
				return nil
			}
			return world.proofRefusal(request, world.apiNow)
		}
		before := world.transport.requestCount()
		err := proofCall.call()
		apiErr := &SidecarApiError{}
		if !errors.As(err, &apiErr) || !isSidecarApiProofRefusal(apiErr) {
			t.Errorf("%s: err %v", proofCall.name, err)
		}
		if sent := world.transport.requestCount() - before; sent != 1 {
			t.Errorf("%s: %d requests", proofCall.name, sent)
		}
	}
}

// The shift that sends a request again is ApiClockRetryShift: a clock moved just under it is not, and
// one moved by it is.
func TestProofRefusalIsSentAgainFromTheRetryShift(t *testing.T) {
	for _, c := range []struct {
		shiftLess time.Duration
		sent      int
	}{
		{shiftLess: time.Second, sent: 1},
		{shiftLess: 0, sent: 2},
	} {
		world := newTestApiClockWorld(t, 0)
		if err := world.api.RemoveClient(context.Background(), NewId()); err != nil {
			t.Fatal(err)
		}
		shift := world.api.settings.ApiClockRetryShift - c.shiftLess
		world.setDeviceOffset(-shift)
		// an api that refuses every proof, whatever its iat, so only the clock's move decides
		world.override = func(request *http.Request, requestIndex int) *http.Response {
			if request.Header.Get("DPoP") == "" {
				return nil
			}
			return world.proofRefusal(request, world.apiNow)
		}
		before := world.transport.requestCount()
		if _, err := world.api.Refresh(context.Background()); err == nil {
			t.Errorf("shift %s: no refusal", shift)
		}
		if sent := world.transport.requestCount() - before; sent != c.sent {
			t.Errorf("shift %s: %d requests", shift, sent)
		}
	}
}

// A second refusal stands, however far its Date moves the clock again: never a third request.
func TestProofRefusedTwiceIsNotSentAThirdTime(t *testing.T) {
	for i := range 3 {
		world := newTestApiClockWorld(t, 10*time.Minute)
		proofCall := world.proofCalls()[i]
		// an api whose Date reads another 10 min back at each answer, so every refusal moves the offset
		world.override = func(request *http.Request, requestIndex int) *http.Response {
			return world.proofRefusal(request, world.apiNow.Add(-time.Duration(requestIndex+1)*10*time.Minute))
		}
		err := proofCall.call()
		apiErr := &SidecarApiError{}
		if !errors.As(err, &apiErr) || !isSidecarApiProofRefusal(apiErr) {
			t.Errorf("%s: err %v", proofCall.name, err)
		}
		if count := world.transport.requestCount(); count != 2 {
			t.Errorf("%s: %d requests", proofCall.name, count)
		}
		if offset := world.api.currentApiClockOffset(); offset != -30*time.Minute {
			t.Errorf("%s: offset %s after the second refusal", proofCall.name, offset)
		}
	}
}

// Only a proof's refusal is sent again: any other refusal of a request carrying a proof, a transport
// failure, and a 403 of a request carrying none each stand after one request, though the answer's Date
// moved the clock.
func TestOnlyAProofRefusalIsSentAgain(t *testing.T) {
	for _, c := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "401", status: 401, body: `{"error":"Session request could not be completed.","code":"session_revoked"}`},
		{name: "403 with a code", status: 403, body: `{"error":"Sidecars are in preview.","code":"not_preview"}`},
		{name: "429", status: 429, body: `{}`},
		{name: "500", status: 500, body: `{}`},
		{name: "400 invalid_grant", status: 400, body: `{"error":"invalid_grant"}`},
	} {
		for i := range 3 {
			world := newTestApiClockWorld(t, 10*time.Minute)
			proofCall := world.proofCalls()[i]
			world.override = func(request *http.Request, requestIndex int) *http.Response {
				return syntheticResponse(request, c.status, c.body, world.date(http.Header{}, world.apiNow))
			}
			if err := proofCall.call(); err == nil {
				t.Errorf("%s, %s: no refusal", c.name, proofCall.name)
			}
			if count := world.transport.requestCount(); count != 1 {
				t.Errorf("%s, %s: %d requests", c.name, proofCall.name, count)
			}
			if offset := world.api.currentApiClockOffset(); offset != -10*time.Minute {
				t.Errorf("%s, %s: the refusal's Date left the offset at %s", c.name, proofCall.name, offset)
			}
		}
	}

	// a request with a bearer and no proof, refused 403 in plain text
	world := newTestApiClockWorld(t, 10*time.Minute)
	world.override = func(request *http.Request, requestIndex int) *http.Response {
		return world.proofRefusal(request, world.apiNow)
	}
	if err := world.api.RemoveClient(context.Background(), NewId()); err == nil {
		t.Error("no refusal")
	}
	if count := world.transport.requestCount(); count != 1 {
		t.Errorf("a request with no proof was sent %d times", count)
	}

	// no answer at all
	world = newTestApiClockWorld(t, 10*time.Minute)
	world.transport.answer = func(request *http.Request, body []byte) (*http.Response, error) {
		return nil, errors.New("synthetic transport failure")
	}
	if _, err := world.api.Refresh(context.Background()); err == nil {
		t.Error("no failure")
	}
	if count := world.transport.requestCount(); count != 1 {
		t.Errorf("a failed request was sent %d times", count)
	}
}

// An answer with no Date gives no clock: a device 10 min off stays refused, in one request, and is never
// sent again on a guess.
func TestProofRefusalWithNoDateStands(t *testing.T) {
	for i := range 3 {
		world := newTestApiClockWorld(t, 10*time.Minute)
		world.noDate = true
		proofCall := world.proofCalls()[i]
		err := proofCall.call()
		apiErr := &SidecarApiError{}
		if !errors.As(err, &apiErr) || !isSidecarApiProofRefusal(apiErr) {
			t.Errorf("%s: err %v", proofCall.name, err)
		}
		if count := world.transport.requestCount(); count != 1 {
			t.Errorf("%s: %d requests", proofCall.name, count)
		}
		if offset := world.api.currentApiClockOffset(); offset != 0 {
			t.Errorf("%s: offset %s", proofCall.name, offset)
		}
	}
}

// The reading is the Date less the round trip's midpoint on the device's clock; a round trip past
// ApiClockMaxRoundTrip and a Date that is no HTTP-date each leave the reading before standing, as another
// service's answer does (api_clock_socket_test.go).
func TestApiClockReadingsKeptAndLeft(t *testing.T) {
	world := newTestApiClockWorld(t, 10*time.Minute)
	ctx := context.Background()
	// the round trip takes 4 s, and the api stamps its answer at its end
	world.arrive = func(requestIndex int) {
		world.advance(4 * time.Second)
	}
	if err := world.api.RemoveClient(ctx, NewId()); err != nil {
		t.Fatal(err)
	}
	if offset := world.api.currentApiClockOffset(); offset != -10*time.Minute+2*time.Second {
		t.Errorf("offset %s after a 4 s round trip", offset)
	}
	kept := world.api.currentApiClockOffset()

	// 1 s past the longest round trip kept
	world.arrive = func(requestIndex int) {
		world.advance(world.api.settings.ApiClockMaxRoundTrip + time.Second)
		world.setDeviceOffset(3 * time.Minute)
	}
	if err := world.api.RemoveClient(ctx, NewId()); err != nil {
		t.Fatal(err)
	}
	if offset := world.api.currentApiClockOffset(); offset != kept {
		t.Errorf("a slow answer moved the offset to %s", offset)
	}

	// a Date that is not one
	world.arrive = nil
	world.override = func(request *http.Request, requestIndex int) *http.Response {
		return syntheticResponse(request, 200, `{}`, http.Header{"Date": {"synthetic-not-a-date"}})
	}
	if err := world.api.RemoveClient(ctx, NewId()); err != nil {
		t.Fatal(err)
	}
	if offset := world.api.currentApiClockOffset(); offset != kept {
		t.Errorf("a malformed Date moved the offset to %s", offset)
	}

	// the auth origin's answer gives api's clock as the api origin's does
	world.override = nil
	world.setDeviceOffset(-10 * time.Minute)
	if _, err := world.api.ExchangeToken(ctx, "https://evs.example", nil); err != nil {
		t.Fatal(err)
	}
	if offset := world.api.currentApiClockOffset(); offset != 10*time.Minute {
		t.Errorf("offset %s after the exchange's answer", offset)
	}
}

// A Retry-After given as a date is read against the api's clock, which the same answer's Date gives, so
// a device 10 min off either way waits what api asked.
func TestRetryAfterDateIsReadAgainstTheApisClock(t *testing.T) {
	for _, deviceOffset := range []time.Duration{10 * time.Minute, -10 * time.Minute, 0} {
		world := newTestApiClockWorld(t, deviceOffset)
		world.override = func(request *http.Request, requestIndex int) *http.Response {
			header := world.date(http.Header{}, world.apiNow)
			header.Set("Retry-After", world.apiNow.Add(30*time.Second).Format(http.TimeFormat))
			return syntheticResponse(request, 503, `{}`, header)
		}
		err := world.api.RemoveClient(context.Background(), NewId())
		apiErr := &SidecarApiError{}
		if !errors.As(err, &apiErr) {
			t.Fatalf("device %s: err %v", deviceOffset, err)
		}
		if apiErr.RetryAfterMs != 30000 {
			t.Errorf("device %s: retry after %d ms", deviceOffset, apiErr.RetryAfterMs)
		}
	}
}

// A signer with an offset signs iat at its clock plus the offset, read at each proof; with none, at its
// clock alone.
func TestDpopSignerSignsIatByTheApiClockOffset(t *testing.T) {
	offset := -10 * time.Minute
	signer, err := newDpopSigner(dpopVectorSeed(), fixedDpopClock(1767225600), func() time.Duration { return offset }, cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := ed25519.NewKeyFromSeed(dpopVectorSeed()).Public().(ed25519.PublicKey)
	for _, want := range []int64{1767225600 - 600, 1767225600 + 600} {
		proof, err := signer("GET", "https://api.example/auth/refresh", dpopAth(testByJwt))
		if err != nil {
			t.Fatal(err)
		}
		if iat := verifyTestDpopProof(t, proof, publicKey).Iat; iat != want {
			t.Errorf("iat %d, not %d", iat, want)
		}
		offset = -offset
	}
}
