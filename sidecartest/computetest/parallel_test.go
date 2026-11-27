package computetest

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

const testParallelBody = `{"objective": "synthetic objective", "search_queries": ["synthetic query one", "synthetic query two"], "mode": "fast"}`

type testParallelWorld struct {
	base     *FakeBase
	parallel *FakeParallel
	clock    *sidecartest.FakeClock
	payer    *FakeEvmKey
}

func newTestParallel(t *testing.T, settings *FakeParallelSettings) *testParallelWorld {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	base, err := NewFakeBase(&FakeBaseArgs{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(base.Close)
	parallel, err := NewFakeParallel(&FakeParallelArgs{Settings: settings, Clock: clock, Base: base})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(parallel.Close)
	payer := NewFakeEvmKey("computetest", "test payer")
	base.Fund(payer.Address(), big.NewInt(1000000))
	return &testParallelWorld{base: base, parallel: parallel, clock: clock, payer: payer}
}

// One search request: its status, headers and body; status 0 where the connection closed with no answer.
func (self *testParallelWorld) search(t *testing.T, body string, header map[string]string) (int, http.Header, []byte) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, self.parallel.SearchUrl(), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	for name, value := range header {
		request.Header.Set(name, value)
	}
	response, err := self.parallel.HttpClient().Do(request)
	if err != nil {
		return 0, nil, nil
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, nil, nil
	}
	return response.StatusCode, response.Header, answer
}

// An unpaid search's offer.
func (self *testParallelWorld) offer(t *testing.T) *FakeParallelOffer {
	t.Helper()
	status, header, _ := self.search(t, testParallelBody, nil)
	if status != http.StatusPaymentRequired {
		t.Fatalf("an unpaid search answered %d", status)
	}
	offer, err := FakeParallelReadChallenge(header.Get("PAYMENT-REQUIRED"))
	if err != nil {
		t.Fatal(err)
	}
	return offer
}

// An authorization paying offer from the payer, valid a minute before now to two after, signed by signer.
func (self *testParallelWorld) authorize(t *testing.T, offer *FakeParallelOffer, signer *FakeEvmKey, nonceLabel string) (*FakeTransferAuthorization, []byte) {
	t.Helper()
	payTo, err := ParseFakeEvmAddress(offer.PayTo)
	if err != nil {
		t.Fatal(err)
	}
	amount, _ := new(big.Int).SetString(offer.Amount, 10)
	now := uint64(self.clock.Now().Unix())
	auth := &FakeTransferAuthorization{
		From:        self.payer.Address(),
		To:          payTo,
		Value:       amount,
		ValidAfter:  now - 60,
		ValidBefore: now + 120,
		Nonce:       FakeBaseNonce("computetest", nonceLabel),
	}
	return auth, signer.SignTransferWithAuthorization(self.base.UsdcDomain(), auth)
}

// x402's error in a 402's body.
func testParallelChallengeError(t *testing.T, body []byte) string {
	t.Helper()
	var challenge struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &challenge); err != nil {
		t.Fatalf("not a challenge: %s", body)
	}
	return challenge.Error
}

func TestFakeParallelVerifiesTheAuthorization(t *testing.T) {
	world := newTestParallel(t, nil)
	status, header, body := world.search(t, testParallelBody, nil)
	if status != http.StatusPaymentRequired || !strings.HasPrefix(header.Get("WWW-Authenticate"), "Payment ") ||
		!strings.Contains(header.Get("WWW-Authenticate"), `method="tempo"`) {
		t.Fatalf("an unpaid search answered %d %v", status, header)
	}
	decoded, err := base64.StdEncoding.DecodeString(header.Get("PAYMENT-REQUIRED"))
	if err != nil || strings.TrimSpace(string(decoded)) != strings.TrimSpace(string(body)) {
		t.Fatalf("the header's challenge is not the body's:\n%s\n%s", decoded, body)
	}
	offer, err := FakeParallelReadChallenge(header.Get("PAYMENT-REQUIRED"))
	if err != nil {
		t.Fatal(err)
	}
	if offer.Scheme != "exact" || offer.Network != "eip155:8453" || offer.Amount != "10000" || offer.Asset != world.base.Usdc().ChecksumHex() ||
		offer.MaxTimeoutSeconds != 300 || offer.Extra["name"] != "USD Coin" || offer.Extra["version"] != "2" {
		t.Fatalf("the offer %+v", offer)
	}
	if another := world.offer(t); another.PayTo == offer.PayTo {
		t.Fatalf("two 402s named one payee")
	}
	stranger := NewFakeEvmKey("computetest", "test stranger")
	cases := []struct {
		name   string
		change func(auth *FakeTransferAuthorization)
		signer *FakeEvmKey
		mangle func(signature []byte) []byte
		want   string
	}{
		{name: "signed by another key", signer: stranger, want: FakeX402InvalidSignature},
		{name: "another value", change: func(auth *FakeTransferAuthorization) { auth.Value = big.NewInt(9999) }, want: FakeX402InvalidValue},
		{name: "another payee", change: func(auth *FakeTransferAuthorization) { auth.To = FakeEvmAddress{0xfe, 0x09} }, want: FakeX402RecipientMismatch},
		{name: "a window closing within the buffer", change: func(auth *FakeTransferAuthorization) { auth.ValidBefore = auth.ValidAfter + 63 }, want: FakeX402InvalidValidBefore},
		{name: "a window not yet open", change: func(auth *FakeTransferAuthorization) { auth.ValidAfter += 120 }, want: FakeX402InvalidValidAfter},
		{name: "the high-s twin", mangle: FakeEvmMalleate, want: FakeX402InvalidSignature},
		{name: "v of 29", mangle: func(signature []byte) []byte { return append(append([]byte{}, signature[:64]...), 29) }, want: FakeX402InvalidSignature},
		{name: "a payer with no funds", change: func(auth *FakeTransferAuthorization) { auth.From = stranger.Address() }, signer: stranger, want: FakeX402InsufficientFunds},
	}
	for _, c := range cases {
		offer := world.offer(t)
		auth, _ := world.authorize(t, offer, world.payer, "refused "+c.name)
		if c.change != nil {
			c.change(auth)
		}
		signer := world.payer
		if c.signer != nil {
			signer = c.signer
		}
		signature := signer.SignTransferWithAuthorization(world.base.UsdcDomain(), auth)
		if c.mangle != nil {
			signature = c.mangle(signature)
		}
		status, _, body := world.search(t, testParallelBody, map[string]string{"PAYMENT-SIGNATURE": FakeParallelPaymentHeader(offer, auth, signature)})
		if status != http.StatusPaymentRequired || testParallelChallengeError(t, body) != c.want {
			t.Errorf("%s: answered %d %s, want %s", c.name, status, body, c.want)
		}
		if world.base.AuthorizationUsed(auth.From, auth.Nonce) {
			t.Errorf("%s: settled", c.name)
		}
	}
	if settlements := world.parallel.Settlements(); len(settlements) != 0 {
		t.Fatalf("%d settlements for refused payments", len(settlements))
	}
	// the authorization that verifies is settled from the facilitator's address, then the search is served
	offer = world.offer(t)
	auth, signature := world.authorize(t, offer, world.payer, "paid")
	status, header, body = world.search(t, testParallelBody, map[string]string{"PAYMENT-SIGNATURE": FakeParallelPaymentHeader(offer, auth, signature)})
	if status != http.StatusOK {
		t.Fatalf("a paid search answered %d %s", status, body)
	}
	var answer struct {
		SearchId string                `json:"search_id"`
		Results  []*FakeParallelResult `json:"results"`
		Usage    []map[string]any      `json:"usage"`
	}
	if err := json.Unmarshal(body, &answer); err != nil || !strings.HasPrefix(answer.SearchId, "search_") || len(answer.Results) != 3 || answer.Results[0].Url == "" {
		t.Fatalf("the answer %s", body)
	}
	settlements := world.parallel.Settlements()
	if len(settlements) != 1 || settlements[0].Receipt.From != world.parallel.Facilitator() {
		t.Fatalf("settlements %+v", settlements)
	}
	receipt, _ := base64.StdEncoding.DecodeString(header.Get("PAYMENT-RESPONSE"))
	if !strings.Contains(string(receipt), hex.EncodeToString(settlements[0].Receipt.TxHash[:])) {
		t.Fatalf("PAYMENT-RESPONSE %s", receipt)
	}
	payTo, _ := ParseFakeEvmAddress(offer.PayTo)
	if !world.base.AuthorizationUsed(world.payer.Address(), auth.Nonce) || world.base.UsdcBalance(payTo).Int64() != 10000 {
		t.Fatalf("the settlement is not on the chain")
	}
	// the log holds what was sent: the documented fields and the header that paid
	requests := world.parallel.Requests()
	paid := requests[len(requests)-1]
	if paid.Payment == nil || paid.Payment.Header != "PAYMENT-SIGNATURE" || len(paid.SearchQueries) != 2 || paid.Mode != "fast" ||
		len(paid.UnknownFields) != 0 || paid.Settlement == nil {
		t.Fatalf("the paid request's record %+v", paid)
	}
	// a field the gateway does not document still gets its 402, and the log names it
	if status, _, _ := world.search(t, `{"search_queries": ["synthetic"], "session_id": "synthetic"}`, nil); status != http.StatusPaymentRequired {
		t.Fatalf("an undocumented field answered %d", status)
	}
	requests = world.parallel.Requests()
	if unknown := requests[len(requests)-1].UnknownFields; len(unknown) != 1 || unknown[0] != "session_id" {
		t.Fatalf("unknown fields %v", unknown)
	}
}

func TestFakeParallelSettlesBeforeFailingWhenTold(t *testing.T) {
	world := newTestParallel(t, nil)
	world.parallel.Script(
		&FakeParallelStep{Outcome: FakeParallelUpstreamFailure, PaidOnly: true},
		&FakeParallelStep{Outcome: FakeParallelLostAnswer, PaidOnly: true},
	)
	// the upstream fails after the payment settled: paid for no answer (CO-30)
	offer := world.offer(t)
	auth, signature := world.authorize(t, offer, world.payer, "upstream failure")
	status, _, body := world.search(t, testParallelBody, map[string]string{"PAYMENT-SIGNATURE": FakeParallelPaymentHeader(offer, auth, signature)})
	if status != http.StatusBadGateway || !world.base.AuthorizationUsed(auth.From, auth.Nonce) {
		t.Fatalf("an upstream failure answered %d %s, settled %v", status, body, world.base.AuthorizationUsed(auth.From, auth.Nonce))
	}
	// the answer is lost after the payment settled
	offer = world.offer(t)
	auth, signature = world.authorize(t, offer, world.payer, "lost answer")
	if status, _, _ := world.search(t, testParallelBody, map[string]string{"PAYMENT-SIGNATURE": FakeParallelPaymentHeader(offer, auth, signature)}); status != 0 {
		t.Fatalf("a lost answer reached the client: %d", status)
	}
	if !world.base.AuthorizationUsed(auth.From, auth.Nonce) || len(world.parallel.Settlements()) != 2 {
		t.Fatalf("the lost answer's payment did not settle")
	}
	requests := world.parallel.Requests()
	if last := requests[len(requests)-1]; last.Status != 0 || last.Outcome != FakeParallelLostAnswer || last.Settlement == nil {
		t.Fatalf("the lost answer's record %+v", last)
	}
	// a stall holds a settled answer until released
	stall := NewFakeParallelStall()
	world.parallel.Script(&FakeParallelStep{Outcome: FakeParallelStalled, PaidOnly: true, Stall: stall})
	offer = world.offer(t)
	auth, signature = world.authorize(t, offer, world.payer, "stall")
	done := make(chan int, 1)
	go func() {
		status, _, _ := world.search(t, testParallelBody, map[string]string{"PAYMENT-SIGNATURE": FakeParallelPaymentHeader(offer, auth, signature)})
		done <- status
	}()
	select {
	case <-stall.Reached():
	case <-time.After(30 * time.Second):
		t.Fatalf("the stall was never reached")
	}
	if !world.base.AuthorizationUsed(auth.From, auth.Nonce) {
		t.Fatalf("the stalled search had not settled")
	}
	stall.Release()
	select {
	case status := <-done:
		if status != http.StatusOK {
			t.Fatalf("the released search answered %d", status)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("the released search never answered")
	}
	// under x402's own order, verify, serve, then settle, a failed upstream settles nothing
	settings := DefaultFakeParallelSettings()
	settings.SettleBeforeSearch = false
	after := newTestParallel(t, settings)
	after.parallel.Script(&FakeParallelStep{Outcome: FakeParallelUpstreamFailure, PaidOnly: true, Status: http.StatusGatewayTimeout})
	offer = after.offer(t)
	auth, signature = after.authorize(t, offer, after.payer, "settle after")
	if status, _, _ := after.search(t, testParallelBody, map[string]string{"PAYMENT-SIGNATURE": FakeParallelPaymentHeader(offer, auth, signature)}); status != http.StatusGatewayTimeout {
		t.Fatalf("an upstream timeout answered %d", status)
	}
	if after.base.AuthorizationUsed(auth.From, auth.Nonce) || len(after.parallel.Settlements()) != 0 {
		t.Fatalf("a failed search settled under x402's order")
	}
}

func TestFakeParallelRefusesAReusedNonce(t *testing.T) {
	world := newTestParallel(t, nil)
	offer := world.offer(t)
	auth, signature := world.authorize(t, offer, world.payer, "once")
	header := FakeParallelPaymentHeader(offer, auth, signature)
	if status, _, body := world.search(t, testParallelBody, map[string]string{"PAYMENT-SIGNATURE": header}); status != http.StatusOK {
		t.Fatalf("the first payment answered %d %s", status, body)
	}
	balance := world.base.UsdcBalance(world.payer.Address())
	// the same payment again, its payee still cached
	if status, _, body := world.search(t, testParallelBody, map[string]string{"PAYMENT-SIGNATURE": header}); status != http.StatusPaymentRequired ||
		testParallelChallengeError(t, body) != FakeX402InvalidTransactionState {
		t.Fatalf("a replayed payment answered %d %s", status, body)
	}
	// the same nonce to a new 402's payee, signed afresh
	fresh := world.offer(t)
	reused, _ := world.authorize(t, fresh, world.payer, "once")
	reusedSignature := world.payer.SignTransferWithAuthorization(world.base.UsdcDomain(), reused)
	if status, _, body := world.search(t, testParallelBody, map[string]string{"PAYMENT-SIGNATURE": FakeParallelPaymentHeader(fresh, reused, reusedSignature)}); status != http.StatusPaymentRequired ||
		testParallelChallengeError(t, body) != FakeX402InvalidTransactionState {
		t.Fatalf("a reused nonce answered %d %s", status, body)
	}
	if len(world.parallel.Settlements()) != 1 || world.base.UsdcBalance(world.payer.Address()).Cmp(balance) != 0 {
		t.Fatalf("a reused nonce settled")
	}
}

func TestFakeParallelLimitsAndPayees(t *testing.T) {
	settings := DefaultFakeParallelSettings()
	settings.RequestsPerMinute = 3
	world := newTestParallel(t, settings)
	for range 3 {
		world.offer(t)
	}
	status, header, _ := world.search(t, testParallelBody, nil)
	if status != http.StatusTooManyRequests || header.Get("Retry-After") != "60" {
		t.Fatalf("past the rate answered %d, Retry-After %q", status, header.Get("Retry-After"))
	}
	world.clock.Advance(time.Minute)
	// a payee past the cache's life is gone: a new 402 naming why, nothing settled
	offer := world.offer(t)
	world.clock.Advance(settings.PayeeCacheTtl)
	auth, signature := world.authorize(t, offer, world.payer, "aged out")
	status, _, body := world.search(t, testParallelBody, map[string]string{"PAYMENT-SIGNATURE": FakeParallelPaymentHeader(offer, auth, signature)})
	if status != http.StatusPaymentRequired || testParallelChallengeError(t, body) != FakeX402PayeeNotCached || world.base.AuthorizationUsed(auth.From, auth.Nonce) {
		t.Fatalf("an aged payee answered %d %s", status, body)
	}
	// a scripted 429 and a scripted lost cache
	world.parallel.Script(&FakeParallelStep{Outcome: FakeParallelRateLimited, RetryAfter: 7 * time.Second})
	if status, header, _ := world.search(t, testParallelBody, nil); status != http.StatusTooManyRequests || header.Get("Retry-After") != "7" {
		t.Fatalf("a scripted 429 answered %d", status)
	}
	world.clock.Advance(time.Minute)
	offer = world.offer(t)
	world.parallel.ForgetPayees()
	auth, signature = world.authorize(t, offer, world.payer, "forgotten")
	if status, _, body := world.search(t, testParallelBody, map[string]string{"PAYMENT-SIGNATURE": FakeParallelPaymentHeader(offer, auth, signature)}); status != http.StatusPaymentRequired ||
		testParallelChallengeError(t, body) != FakeX402PayeeNotCached {
		t.Fatalf("a lost cache answered %d %s", status, body)
	}
	// the gateway Parallel's post describes answers 500 there; one reading X-Payment alone ignores PAYMENT-SIGNATURE
	lost := DefaultFakeParallelSettings()
	lost.PayeeLostStatus = http.StatusInternalServerError
	lost.PaymentHeaders = []string{"X-Payment"}
	other := newTestParallel(t, lost)
	offer = other.offer(t)
	auth, signature = other.authorize(t, offer, other.payer, "other header")
	payment := FakeParallelPaymentHeader(offer, auth, signature)
	if status, _, _ := other.search(t, testParallelBody, map[string]string{"PAYMENT-SIGNATURE": payment}); status != http.StatusPaymentRequired {
		t.Fatalf("a payment in an unread header answered %d", status)
	}
	other.parallel.ForgetPayees()
	if status, _, _ := other.search(t, testParallelBody, map[string]string{"X-Payment": payment}); status != http.StatusInternalServerError {
		t.Fatalf("a lost payee on the 500 reading answered %d", status)
	}
	// a paid search Parallel's API refuses is paid for: a 422 after settlement
	world.clock.Advance(time.Minute)
	offer = world.offer(t)
	auth, signature = world.authorize(t, offer, world.payer, "invalid body")
	if status, _, body := world.search(t, `{"objective": "only an objective"}`, map[string]string{"PAYMENT-SIGNATURE": FakeParallelPaymentHeader(offer, auth, signature)}); status != http.StatusUnprocessableEntity ||
		!world.base.AuthorizationUsed(auth.From, auth.Nonce) {
		t.Fatalf("a search without queries answered %d %s", status, body)
	}
	if status, _, _ := world.search(t, `{"search_queries":`, nil); status != http.StatusBadRequest {
		t.Fatalf("unreadable JSON answered %d", status)
	}
}
