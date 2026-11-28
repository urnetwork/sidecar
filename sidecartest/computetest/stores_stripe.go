// computetest.FakeStripe (CTEST-M12-02; DESIGN-COMPUTE §9.5, §9.8, §9.11, §9.12): Stripe's API as BAL's server code
// calls it through stripe-go, on a loopback server at Url, its form-encoded requests answered in Stripe's JSON:
//
//	customers         POST /v1/customers, GET /v1/customers/{id}, GET /v1/customers/search on metadata clauses
//	checkout          POST /v1/checkout/sessions (payment mode: one line's price_data, capture_method,
//	                  setup_future_usage, 3-D Secure, metadata, expires_at), GET by id, GET listed by payment_intent,
//	                  GET its line_items; CompleteCheckout is the person paying on the hosted page with a test card
//	payment intents   GET by id with payment_method and latest_charge expandable; POST create off session with
//	                  confirm (a saved card's threshold top-up, §9.8); capture and cancel; a card's behavior decides
//	                  succeeded, a decline (402 card_declined) or authentication_required (402) off session
//	payment methods   GET with card.fingerprint, the same for one test card across customers and networks (§9.11);
//	                  detach; a card is saved to its customer only when its session asked setup_future_usage
//	refunds           POST create (at most the charge's unrefunded amount), GET listed by payment_intent
//	disputes          Dispute and CloseDispute: a chargeback opened and closed by the test
//
// Every POST honors Idempotency-Key as Stripe does, the same key answering the same response. Every request must
// carry the test API key (ApiKey) as its bearer, else 401. Each change makes the events Stripe would send, queued in
// Events() until the test delivers them, each delivery signed in Stripe-Signature under the endpoint secret
// (WebhookSecret): t=<unix>,v1=<hex HMAC-SHA256 of "<t>.<body>">, timestamped by the signature clock at delivery, as
// Stripe signs each attempt afresh.
//
// Not built (the draft's gaps): subscriptions and invoices (the monthly plan's Checkout in subscription mode, and
// /v1/subscriptions), Stripe Tax's amounts (no tax is added), and the Radar and 3-D Secure outcomes beyond a card's own
// behavior. A request for what it does not build answers 501 computetest_not_built, never a 404 BAL's code would read
// as the object gone, and is kept in NotBuiltRequests (FakeStoreNotBuiltCode).
//
// Safe for concurrent use: one lock guards the state; deliveries and the server's I/O run outside it.

package computetest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// The fake Stripe's settings (QD-702).
type FakeStripeSettings struct {
	// The API version events carry: stripe-go v82.5.1's, which server's go.mod pins.
	ApiVersion string
	// The most objects a list or search answers: 100, Stripe's own bound on limit.
	ListMaxCount int
	// How long a session stays open when its request names no expires_at: 24 hours, Stripe's default.
	SessionLife time.Duration
	// Where a session's hosted page is: a synthetic host.
	CheckoutUrlBase string
}

// The defaults, the only place one is set.
func DefaultFakeStripeSettings() *FakeStripeSettings {
	return &FakeStripeSettings{
		ApiVersion:      "2025-08-27.basil",
		ListMaxCount:    100,
		SessionLife:     24 * time.Hour,
		CheckoutUrlBase: "https://checkout.stripe.example/c/pay/",
	}
}

// What a test card does when charged, as Stripe's test cards behave.
type FakeStripeCardBehavior int

const (
	// Every payment succeeds.
	FakeStripeCardSucceeds FakeStripeCardBehavior = 1
	// Every payment is declined: card_declined, decline_code generic_decline.
	FakeStripeCardDeclines FakeStripeCardBehavior = 2
	// The issuer asks for 3-D Secure: a person passes it on Checkout's page; off session it fails
	// authentication_required.
	FakeStripeCardRequiresAuthentication FakeStripeCardBehavior = 3
)

// A test card: its label names it, so one label is one card, its fingerprint the same wherever it pays.
type FakeStripeCard struct {
	Label    string
	Behavior FakeStripeCardBehavior
}

// A customer.
type fakeStripeCustomer struct {
	id       string
	created  int64
	metadata map[string]string
	deleted  bool
}

// One line of a session.
type fakeStripeLineItem struct {
	id          string
	priceId     string
	product     string
	currency    string
	unitAmount  int64
	quantity    int64
	taxBehavior string
}

// A Checkout session.
type fakeStripeSession struct {
	id                    string
	created               int64
	expiresAt             int64
	mode                  string
	status                string
	paymentStatus         string
	customer              string
	paymentIntent         string
	successUrl            string
	cancelUrl             string
	currency              string
	metadata              map[string]string
	lineItems             []*fakeStripeLineItem
	captureMethod         string
	setupFutureUsage      string
	intentMetadata        map[string]string
	requestThreeDSecure   string
	paymentMethodTypes    []string
	automaticTaxEnabled   bool
	customerUpdateAddress string
}

// A payment method: a test card's.
type fakeStripePaymentMethod struct {
	id          string
	created     int64
	customer    string
	card        *FakeStripeCard
	fingerprint string
	last4       string
}

// A charge.
type fakeStripeCharge struct {
	id             string
	created        int64
	amount         int64
	amountRefunded int64
	captured       bool
	paid           bool
	status         string
	paymentIntent  string
	paymentMethod  string
	customer       string
	disputed       bool
	metadata       map[string]string
}

// A payment intent.
type fakeStripePaymentIntent struct {
	id                 string
	created            int64
	amount             int64
	amountCapturable   int64
	amountReceived     int64
	currency           string
	captureMethod      string
	status             string
	customer           string
	paymentMethod      string
	latestCharge       string
	setupFutureUsage   string
	offSession         bool
	metadata           map[string]string
	cancellationReason string
	lastError          map[string]any
	// whether 3-D Secure ran for it: asked by its session, or by the card's issuer on Checkout's page
	threeDSecure bool
}

// A refund.
type fakeStripeRefund struct {
	id            string
	created       int64
	amount        int64
	charge        string
	paymentIntent string
	reason        string
	metadata      map[string]string
}

// A dispute.
type fakeStripeDispute struct {
	id            string
	created       int64
	amount        int64
	charge        string
	paymentIntent string
	reason        string
	status        string
}

// A POST's answer kept under its Idempotency-Key.
type fakeStripeIdempotent struct {
	status int
	body   []byte
}

// See the file header.
type FakeStripe struct {
	settings       *FakeStoresSettings
	stripe         *FakeStripeSettings
	seed           string
	clock          sidecar.Clock
	signatureClock sidecar.Clock
	apiKey         string
	webhookSecret  string
	server         *httptest.Server
	events         *FakeStoreNotifications
	notBuilt       *fakeStoreNotBuilt

	stateLock        sync.Mutex
	idCount          uint64
	customers        []*fakeStripeCustomer
	sessions         []*fakeStripeSession
	paymentIntents   []*fakeStripePaymentIntent
	paymentMethods   []*fakeStripePaymentMethod
	charges          []*fakeStripeCharge
	refunds          []*fakeStripeRefund
	disputes         []*fakeStripeDispute
	keyIdempotents   map[string]*fakeStripeIdempotent
	requestPathCount map[string]int
}

func newFakeStripe(settings *FakeStoresSettings, seed string, clock sidecar.Clock, signatureClock sidecar.Clock) (*FakeStripe, error) {
	self := &FakeStripe{
		settings:         settings,
		stripe:           settings.Stripe,
		seed:             seed,
		clock:            clock,
		signatureClock:   signatureClock,
		apiKey:           "sk_test_" + hex.EncodeToString(fakeBytes(seed, "stripe api key", 24)),
		webhookSecret:    "whsec_" + hex.EncodeToString(fakeBytes(seed, "stripe webhook secret", 24)),
		events:           newFakeStoreNotifications(settings, clock),
		notBuilt:         newFakeStoreNotBuilt("Stripe"),
		keyIdempotents:   map[string]*fakeStripeIdempotent{},
		requestPathCount: map[string]int{},
	}
	mux := http.NewServeMux()
	routes := map[string]func(writer http.ResponseWriter, request *http.Request, form url.Values) (int, any){
		"POST /v1/customers":                        self.serveCustomerCreate,
		"GET /v1/customers/search":                  self.serveCustomerSearch,
		"GET /v1/customers/{id}":                    self.serveCustomerGet,
		"POST /v1/checkout/sessions":                self.serveSessionCreate,
		"GET /v1/checkout/sessions":                 self.serveSessionList,
		"GET /v1/checkout/sessions/{id}":            self.serveSessionGet,
		"GET /v1/checkout/sessions/{id}/line_items": self.serveSessionLineItems,
		"POST /v1/payment_intents":                  self.servePaymentIntentCreate,
		"GET /v1/payment_intents/{id}":              self.servePaymentIntentGet,
		"POST /v1/payment_intents/{id}/capture":     self.servePaymentIntentCapture,
		"POST /v1/payment_intents/{id}/cancel":      self.servePaymentIntentCancel,
		"GET /v1/payment_methods/{id}":              self.servePaymentMethodGet,
		"POST /v1/payment_methods/{id}/detach":      self.servePaymentMethodDetach,
		"POST /v1/refunds":                          self.serveRefundCreate,
		"GET /v1/refunds":                           self.serveRefundList,
	}
	for pattern, serve := range routes {
		mux.HandleFunc(pattern, self.wrap(pattern, serve))
	}
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		// never Stripe's 404 for an unknown url, which BAL's code reads as the object gone
		self.writeNotBuilt(writer, request, "")
	})
	self.server = newFakeStoreServer(mux)
	return self, nil
}

// Ends the server.
func (self *FakeStripe) Close() {
	self.server.Close()
}

// The API's base URL, which a stripe-go backend takes as its URL.
func (self *FakeStripe) Url() string {
	return self.server.URL
}

// The test API key every request must carry as its bearer.
func (self *FakeStripe) ApiKey() string {
	return self.apiKey
}

// The endpoint secret deliveries are signed under.
func (self *FakeStripe) WebhookSecret() string {
	return self.webhookSecret
}

// The events made, waiting for the test to deliver them.
func (self *FakeStripe) Events() *FakeStoreNotifications {
	return self.events
}

// How many requests the server took for a route's pattern, such as "POST /v1/payment_intents/{id}/capture".
func (self *FakeStripe) RequestCount(pattern string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.requestPathCount[pattern]
}

// A Stripe-Signature header's value for body at t under secret, as Stripe makes it.
func FakeStripeSignature(t time.Time, body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(t.Unix(), 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return fmt.Sprintf("t=%d,v1=%s", t.Unix(), hex.EncodeToString(mac.Sum(nil)))
}

// A new id with Stripe's prefix, synthetic and drawn from the seed in order. Called with the lock.
func (self *FakeStripe) newIdWithLock(prefix string) string {
	self.idCount += 1
	return prefix + "_" + hex.EncodeToString(fakeBytes(self.seed, fmt.Sprintf("stripe id %s %d", prefix, self.idCount), 12))
}

// A card's fingerprint: one per label, whichever customer or network it pays for.
func (self *FakeStripe) fingerprint(card *FakeStripeCard) string {
	return hex.EncodeToString(fakeBytes(self.seed, "stripe card fingerprint "+card.Label, 8))
}

// A card's last four digits, from its label.
func (self *FakeStripe) last4(card *FakeStripeCard) string {
	digits := fakeBytes(self.seed, "stripe card digits "+card.Label, 4)
	return fmt.Sprintf("%d%d%d%d", digits[0]%10, digits[1]%10, digits[2]%10, digits[3]%10)
}

// A Stripe error body.
func fakeStripeErrorBody(errorType string, code string, declineCode string, message string, intent map[string]any) []byte {
	inner := map[string]any{"type": errorType, "message": message}
	if code != "" {
		inner["code"] = code
	}
	if declineCode != "" {
		inner["decline_code"] = declineCode
	}
	if intent != nil {
		inner["payment_intent"] = intent
	}
	body, _ := json.Marshal(map[string]any{"error": inner})
	return body
}

// An error answer.
type fakeStripeErrorAnswer struct {
	body []byte
}

// A served route's answer to what it does not build, such as a Checkout Session in subscription mode: wrap writes it
// through writeNotBuilt and keeps it under no Idempotency-Key, so a retry under the key is answered the same way.
type fakeStripeNotBuiltAnswer struct {
	// what the route does not build, beside its method and path
	detail string
}

// Answers request, which the fake does not serve, 501 computetest_not_built, and keeps it (FakeStoreNotBuiltCode).
func (self *FakeStripe) writeNotBuilt(writer http.ResponseWriter, request *http.Request, detail string) {
	message := self.notBuilt.record(request, detail)
	// stripe-go retries every 5xx but one that says not to
	writer.Header().Set("Stripe-Should-Retry", "false")
	writeFakeStoreJson(writer, http.StatusNotImplemented, fakeStripeErrorBody("api_error", FakeStoreNotBuiltCode, "", message, nil))
}

// The requests the fake did not serve, each "<method> <path>" with what it does not build where a served route
// refused it, oldest first: a test asserts none was made.
func (self *FakeStripe) NotBuiltRequests() []string {
	return self.notBuilt.list()
}

// A route's handler, behind the API key, the body's bound and Idempotency-Key.
func (self *FakeStripe) wrap(pattern string, serve func(writer http.ResponseWriter, request *http.Request, form url.Values) (int, any)) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		self.stateLock.Lock()
		self.requestPathCount[pattern] += 1
		self.stateLock.Unlock()
		if request.Header.Get("Authorization") != "Bearer "+self.apiKey {
			writeFakeStoreJson(writer, http.StatusUnauthorized, fakeStripeErrorBody("invalid_request_error", "", "", "Invalid API Key provided.", nil))
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, self.settings.RequestByteCount+1))
		if err != nil || self.settings.RequestByteCount < int64(len(body)) {
			writeFakeStoreJson(writer, http.StatusBadRequest, fakeStripeErrorBody("invalid_request_error", "", "", "The request's body does not read.", nil))
			return
		}
		form, err := url.ParseQuery(request.URL.RawQuery)
		if err != nil {
			writeFakeStoreJson(writer, http.StatusBadRequest, fakeStripeErrorBody("invalid_request_error", "", "", "The query does not read.", nil))
			return
		}
		if 0 < len(body) {
			bodyForm, err := url.ParseQuery(string(body))
			if err != nil {
				writeFakeStoreJson(writer, http.StatusBadRequest, fakeStripeErrorBody("invalid_request_error", "", "", "The body is not form-encoded.", nil))
				return
			}
			for key, values := range bodyForm {
				form[key] = append(form[key], values...)
			}
		}
		idempotencyKey := ""
		if request.Method == http.MethodPost {
			idempotencyKey = request.Header.Get("Idempotency-Key")
		}
		if idempotencyKey != "" {
			self.stateLock.Lock()
			kept, ok := self.keyIdempotents[pattern+" "+idempotencyKey]
			self.stateLock.Unlock()
			if ok {
				writer.Header().Set("Idempotent-Replayed", "true")
				writeFakeStoreJson(writer, kept.status, kept.body)
				return
			}
		}
		status, answer := serve(writer, request, form)
		if notBuilt, ok := answer.(*fakeStripeNotBuiltAnswer); ok {
			self.writeNotBuilt(writer, request, notBuilt.detail)
			return
		}
		var answerBody []byte
		switch typed := answer.(type) {
		case *fakeStripeErrorAnswer:
			answerBody = typed.body
		default:
			answerBody, err = json.Marshal(answer)
			if err != nil {
				status = http.StatusInternalServerError
				answerBody = fakeStripeErrorBody("api_error", "", "", "The answer does not marshal.", nil)
			}
		}
		if idempotencyKey != "" {
			self.stateLock.Lock()
			self.keyIdempotents[pattern+" "+idempotencyKey] = &fakeStripeIdempotent{status: status, body: answerBody}
			self.stateLock.Unlock()
		}
		writeFakeStoreJson(writer, status, answerBody)
	}
}

// An invalid request's answer.
func fakeStripeInvalid(message string) (int, any) {
	return http.StatusBadRequest, &fakeStripeErrorAnswer{body: fakeStripeErrorBody("invalid_request_error", "parameter_invalid", "", message, nil)}
}

// A missing object's answer.
func fakeStripeMissing(kind string, id string) (int, any) {
	return http.StatusNotFound, &fakeStripeErrorAnswer{body: fakeStripeErrorBody("invalid_request_error", "resource_missing", "", "No such "+kind+": '"+id+"'", nil)}
}

// The form's metadata under prefix: prefix[key]=value.
func fakeStripeMetadata(form url.Values, prefix string) map[string]string {
	metadata := map[string]string{}
	for key, values := range form {
		if strings.HasPrefix(key, prefix+"[") && strings.HasSuffix(key, "]") && 0 < len(values) {
			inner := key[len(prefix)+1 : len(key)-1]
			if !strings.Contains(inner, "[") {
				metadata[inner] = values[0]
			}
		}
	}
	return metadata
}

// Whether the form asks expand of field: expand[]=field or expand[n]=field.
func fakeStripeExpands(form url.Values, field string) bool {
	for key, values := range form {
		if key == "expand[]" || strings.HasPrefix(key, "expand[") {
			if slices.Contains(values, field) {
				return true
			}
		}
	}
	return false
}

// A list's answer.
func fakeStripeList(objects []any, path string) map[string]any {
	return map[string]any{"object": "list", "data": objects, "has_more": false, "url": path}
}

// A form's int64, 0 for none; false where it is set and does not parse.
func fakeStripeInt(form url.Values, key string) (int64, bool) {
	text := form.Get(key)
	if text == "" {
		return 0, true
	}
	value, err := strconv.ParseInt(text, 10, 64)
	return value, err == nil
}

// The form's limit, at most the settings' bound.
func (self *FakeStripe) limit(form url.Values) int {
	limit, ok := fakeStripeInt(form, "limit")
	if !ok || limit <= 0 || int64(self.stripe.ListMaxCount) < limit {
		return self.stripe.ListMaxCount
	}
	return int(limit)
}

// Queues the event of type over object. Called with the lock.
func (self *FakeStripe) emitWithLock(eventType string, object map[string]any) {
	now := self.clock.Now()
	id := self.newIdWithLock("evt")
	body, _ := json.Marshal(map[string]any{
		"id":               id,
		"object":           "event",
		"api_version":      self.stripe.ApiVersion,
		"created":          now.Unix(),
		"data":             map[string]any{"object": object},
		"livemode":         false,
		"pending_webhooks": 1,
		"request":          map[string]any{"id": nil, "idempotency_key": nil},
		"type":             eventType,
	})
	secret := self.webhookSecret
	signatureClock := self.signatureClock
	// queued without the lock's holder waiting on the queue's own
	notification := &FakeStoreNotification{
		Id:     id,
		Type:   eventType,
		Time:   now,
		Body:   body,
		Header: http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		sign: func(at time.Time, body []byte) http.Header {
			return http.Header{"Stripe-Signature": []string{FakeStripeSignature(signatureClock.Now(), body, secret)}}
		},
	}
	self.events.add(notification)
}

// Renders a customer.
func (self *FakeStripe) renderCustomer(customer *fakeStripeCustomer) map[string]any {
	return map[string]any{
		"id":       customer.id,
		"object":   "customer",
		"created":  customer.created,
		"metadata": customer.metadata,
		"deleted":  customer.deleted,
		"livemode": false,
	}
}

func (self *FakeStripe) serveCustomerCreate(writer http.ResponseWriter, request *http.Request, form url.Values) (int, any) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	customer := &fakeStripeCustomer{
		id:       self.newIdWithLock("cus"),
		created:  self.clock.Now().Unix(),
		metadata: fakeStripeMetadata(form, "metadata"),
	}
	self.customers = append(self.customers, customer)
	return http.StatusOK, self.renderCustomer(customer)
}

func (self *FakeStripe) serveCustomerGet(writer http.ResponseWriter, request *http.Request, form url.Values) (int, any) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, customer := range self.customers {
		if customer.id == request.PathValue("id") {
			return http.StatusOK, self.renderCustomer(customer)
		}
	}
	return fakeStripeMissing("customer", request.PathValue("id"))
}

// One clause of a search: metadata['key']:'value'.
var fakeStripeMetadataClause = regexp.MustCompile(`^metadata\['([^']+)'\]:'([^']*)'$`)

func (self *FakeStripe) serveCustomerSearch(writer http.ResponseWriter, request *http.Request, form url.Values) (int, any) {
	clauses := map[string]string{}
	for _, clause := range strings.Split(form.Get("query"), " AND ") {
		match := fakeStripeMetadataClause.FindStringSubmatch(strings.TrimSpace(clause))
		if match == nil {
			return fakeStripeInvalid("The fake searches metadata clauses alone, joined by AND.")
		}
		clauses[match[1]] = match[2]
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	found := []any{}
	for _, customer := range self.customers {
		matches := !customer.deleted
		for key, value := range clauses {
			matches = matches && customer.metadata[key] == value
		}
		if matches && len(found) < self.limit(form) {
			found = append(found, self.renderCustomer(customer))
		}
	}
	return http.StatusOK, map[string]any{"object": "search_result", "data": found, "has_more": false, "next_page": nil, "url": "/v1/customers/search"}
}

// Renders a session.
func (self *FakeStripe) renderSession(session *fakeStripeSession) map[string]any {
	amount := int64(0)
	for _, line := range session.lineItems {
		amount += line.unitAmount * line.quantity
	}
	rendered := map[string]any{
		"id":                  session.id,
		"object":              "checkout.session",
		"created":             session.created,
		"expires_at":          session.expiresAt,
		"mode":                session.mode,
		"status":              session.status,
		"payment_status":      session.paymentStatus,
		"customer":            session.customer,
		"success_url":         session.successUrl,
		"cancel_url":          session.cancelUrl,
		"currency":            session.currency,
		"amount_subtotal":     amount,
		"amount_total":        amount,
		"metadata":            session.metadata,
		"client_reference_id": nil,
		"livemode":            false,
		"payment_intent":      nil,
		"url":                 nil,
	}
	if session.paymentIntent != "" {
		rendered["payment_intent"] = session.paymentIntent
	}
	if session.status == "open" {
		rendered["url"] = self.stripe.CheckoutUrlBase + session.id
	}
	return rendered
}

func (self *FakeStripe) serveSessionCreate(writer http.ResponseWriter, request *http.Request, form url.Values) (int, any) {
	mode := form.Get("mode")
	if mode != "payment" {
		// subscription and setup modes are not built (see the file header), which is no fault of the request
		return http.StatusNotImplemented, &fakeStripeNotBuiltAnswer{detail: "mode " + mode}
	}
	unitAmount, ok := fakeStripeInt(form, "line_items[0][price_data][unit_amount]")
	quantity, quantityOk := fakeStripeInt(form, "line_items[0][quantity]")
	if !ok || !quantityOk || unitAmount <= 0 || quantity <= 0 || form.Get("line_items[1][quantity]") != "" {
		return fakeStripeInvalid("A session sells one line with a price and a quantity.")
	}
	expiresAt, ok := fakeStripeInt(form, "expires_at")
	if !ok {
		return fakeStripeInvalid("expires_at does not read.")
	}
	now := self.clock.Now()
	if expiresAt == 0 {
		expiresAt = now.Add(self.stripe.SessionLife).Unix()
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	customer := form.Get("customer")
	if customer != "" && !slices.ContainsFunc(self.customers, func(stored *fakeStripeCustomer) bool { return stored.id == customer }) {
		return fakeStripeMissing("customer", customer)
	}
	captureMethod := form.Get("payment_intent_data[capture_method]")
	if captureMethod == "" {
		captureMethod = "automatic"
	}
	session := &fakeStripeSession{
		id:                    "cs_test_" + strings.TrimPrefix(self.newIdWithLock("cs"), "cs_"),
		created:               now.Unix(),
		expiresAt:             expiresAt,
		mode:                  mode,
		status:                "open",
		paymentStatus:         "unpaid",
		customer:              customer,
		successUrl:            form.Get("success_url"),
		cancelUrl:             form.Get("cancel_url"),
		currency:              form.Get("line_items[0][price_data][currency]"),
		metadata:              fakeStripeMetadata(form, "metadata"),
		captureMethod:         captureMethod,
		setupFutureUsage:      form.Get("payment_intent_data[setup_future_usage]"),
		intentMetadata:        fakeStripeMetadata(form, "payment_intent_data[metadata]"),
		requestThreeDSecure:   form.Get("payment_method_options[card][request_three_d_secure]"),
		automaticTaxEnabled:   form.Get("automatic_tax[enabled]") == "true",
		customerUpdateAddress: form.Get("customer_update[address]"),
	}
	for key, values := range form {
		if strings.HasPrefix(key, "payment_method_types[") {
			session.paymentMethodTypes = append(session.paymentMethodTypes, values...)
		}
	}
	session.lineItems = []*fakeStripeLineItem{{
		id:          self.newIdWithLock("li"),
		priceId:     self.newIdWithLock("price"),
		product:     form.Get("line_items[0][price_data][product]"),
		currency:    session.currency,
		unitAmount:  unitAmount,
		quantity:    quantity,
		taxBehavior: form.Get("line_items[0][price_data][tax_behavior]"),
	}}
	self.sessions = append(self.sessions, session)
	return http.StatusOK, self.renderSession(session)
}

// The session id names, nil for none. Called with the lock.
func (self *FakeStripe) sessionWithLock(id string) *fakeStripeSession {
	for _, session := range self.sessions {
		if session.id == id {
			return session
		}
	}
	return nil
}

func (self *FakeStripe) serveSessionGet(writer http.ResponseWriter, request *http.Request, form url.Values) (int, any) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	session := self.sessionWithLock(request.PathValue("id"))
	if session == nil {
		return fakeStripeMissing("checkout.session", request.PathValue("id"))
	}
	return http.StatusOK, self.renderSession(session)
}

func (self *FakeStripe) serveSessionList(writer http.ResponseWriter, request *http.Request, form url.Values) (int, any) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	listed := []any{}
	for _, session := range self.sessions {
		if paymentIntent := form.Get("payment_intent"); paymentIntent != "" && session.paymentIntent != paymentIntent {
			continue
		}
		if len(listed) < self.limit(form) {
			listed = append(listed, self.renderSession(session))
		}
	}
	return http.StatusOK, fakeStripeList(listed, "/v1/checkout/sessions")
}

func (self *FakeStripe) serveSessionLineItems(writer http.ResponseWriter, request *http.Request, form url.Values) (int, any) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	session := self.sessionWithLock(request.PathValue("id"))
	if session == nil {
		return fakeStripeMissing("checkout.session", request.PathValue("id"))
	}
	lines := []any{}
	for _, line := range session.lineItems {
		lines = append(lines, map[string]any{
			"id":              line.id,
			"object":          "item",
			"amount_subtotal": line.unitAmount * line.quantity,
			"amount_total":    line.unitAmount * line.quantity,
			"currency":        line.currency,
			"quantity":        line.quantity,
			"price": map[string]any{
				"id":           line.priceId,
				"object":       "price",
				"active":       true,
				"currency":     line.currency,
				"product":      line.product,
				"unit_amount":  line.unitAmount,
				"tax_behavior": line.taxBehavior,
				"type":         "one_time",
				"livemode":     false,
			},
		})
	}
	return http.StatusOK, fakeStripeList(lines, "/v1/checkout/sessions/"+session.id+"/line_items")
}

// Renders a payment method.
func (self *FakeStripe) renderPaymentMethod(method *fakeStripePaymentMethod) map[string]any {
	rendered := map[string]any{
		"id":       method.id,
		"object":   "payment_method",
		"created":  method.created,
		"type":     "card",
		"customer": nil,
		"livemode": false,
		"card": map[string]any{
			"brand":       "visa",
			"last4":       method.last4,
			"fingerprint": method.fingerprint,
			"exp_month":   12,
			"exp_year":    2099,
			"funding":     "credit",
			"country":     "US",
		},
	}
	if method.customer != "" {
		rendered["customer"] = method.customer
	}
	return rendered
}

// Renders a charge.
func (self *FakeStripe) renderCharge(charge *fakeStripeCharge) map[string]any {
	rendered := map[string]any{
		"id":              charge.id,
		"object":          "charge",
		"created":         charge.created,
		"amount":          charge.amount,
		"amount_captured": int64(0),
		"amount_refunded": charge.amountRefunded,
		"captured":        charge.captured,
		"paid":            charge.paid,
		"refunded":        charge.amountRefunded == charge.amount && 0 < charge.amount,
		"status":          charge.status,
		"payment_intent":  charge.paymentIntent,
		"payment_method":  charge.paymentMethod,
		"customer":        nil,
		"disputed":        charge.disputed,
		"currency":        "usd",
		"metadata":        charge.metadata,
		"livemode":        false,
	}
	if charge.captured {
		rendered["amount_captured"] = charge.amount
	}
	if charge.customer != "" {
		rendered["customer"] = charge.customer
	}
	for _, method := range self.paymentMethods {
		if method.id == charge.paymentMethod {
			rendered["payment_method_details"] = map[string]any{
				"type": "card",
				"card": map[string]any{"brand": "visa", "last4": method.last4, "fingerprint": method.fingerprint},
			}
		}
	}
	return rendered
}

// Renders a payment intent, its payment method and latest charge expanded where asked. Called with the lock.
func (self *FakeStripe) renderPaymentIntentWithLock(intent *fakeStripePaymentIntent, expandMethod bool, expandCharge bool) map[string]any {
	rendered := map[string]any{
		"id":                  intent.id,
		"object":              "payment_intent",
		"created":             intent.created,
		"amount":              intent.amount,
		"amount_capturable":   intent.amountCapturable,
		"amount_received":     intent.amountReceived,
		"currency":            intent.currency,
		"capture_method":      intent.captureMethod,
		"status":              intent.status,
		"customer":            nil,
		"payment_method":      nil,
		"latest_charge":       nil,
		"setup_future_usage":  nil,
		"metadata":            intent.metadata,
		"cancellation_reason": nil,
		"last_payment_error":  nil,
		"livemode":            false,
	}
	if intent.customer != "" {
		rendered["customer"] = intent.customer
	}
	if intent.setupFutureUsage != "" {
		rendered["setup_future_usage"] = intent.setupFutureUsage
	}
	if intent.cancellationReason != "" {
		rendered["cancellation_reason"] = intent.cancellationReason
	}
	if intent.lastError != nil {
		rendered["last_payment_error"] = intent.lastError
	}
	if intent.paymentMethod != "" {
		rendered["payment_method"] = intent.paymentMethod
		if expandMethod {
			for _, method := range self.paymentMethods {
				if method.id == intent.paymentMethod {
					rendered["payment_method"] = self.renderPaymentMethod(method)
				}
			}
		}
	}
	if intent.latestCharge != "" {
		rendered["latest_charge"] = intent.latestCharge
		if expandCharge {
			for _, charge := range self.charges {
				if charge.id == intent.latestCharge {
					rendered["latest_charge"] = self.renderCharge(charge)
				}
			}
		}
	}
	return rendered
}

// The payment intent id names, nil for none. Called with the lock.
func (self *FakeStripe) paymentIntentWithLock(id string) *fakeStripePaymentIntent {
	for _, intent := range self.paymentIntents {
		if intent.id == id {
			return intent
		}
	}
	return nil
}

// The charge id names, nil for none. Called with the lock.
func (self *FakeStripe) chargeWithLock(id string) *fakeStripeCharge {
	for _, charge := range self.charges {
		if charge.id == id {
			return charge
		}
	}
	return nil
}

func (self *FakeStripe) servePaymentIntentGet(writer http.ResponseWriter, request *http.Request, form url.Values) (int, any) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	intent := self.paymentIntentWithLock(request.PathValue("id"))
	if intent == nil {
		return fakeStripeMissing("payment_intent", request.PathValue("id"))
	}
	return http.StatusOK, self.renderPaymentIntentWithLock(intent, fakeStripeExpands(form, "payment_method"), fakeStripeExpands(form, "latest_charge"))
}

// Charges intent with method's card now, as a confirmation does: its charge made, captured at once for an automatic
// intent, held for a manual one, its events queued. Answers the card's error, nil where it paid. Called with the lock.
func (self *FakeStripe) confirmWithLock(intent *fakeStripePaymentIntent, method *fakeStripePaymentMethod, offSession bool) map[string]any {
	now := self.clock.Now()
	behavior := method.card.Behavior
	if behavior == FakeStripeCardDeclines || (behavior == FakeStripeCardRequiresAuthentication && offSession) {
		code, declineCode, message := "card_declined", "generic_decline", "Your card was declined."
		if behavior == FakeStripeCardRequiresAuthentication {
			code, declineCode, message = "authentication_required", "authentication_required", "Your card was declined. This transaction requires authentication."
		}
		intent.status = "requires_payment_method"
		intent.lastError = map[string]any{"type": "card_error", "code": code, "decline_code": declineCode, "message": message, "payment_method": self.renderPaymentMethod(method)}
		self.emitWithLock("payment_intent.payment_failed", self.renderPaymentIntentWithLock(intent, false, false))
		return map[string]any{"code": code, "decline_code": declineCode, "message": message}
	}
	charge := &fakeStripeCharge{
		id:            self.newIdWithLock("ch"),
		created:       now.Unix(),
		amount:        intent.amount,
		paid:          true,
		status:        "succeeded",
		paymentIntent: intent.id,
		paymentMethod: method.id,
		customer:      intent.customer,
		metadata:      map[string]string{},
	}
	self.charges = append(self.charges, charge)
	intent.latestCharge = charge.id
	intent.paymentMethod = method.id
	intent.lastError = nil
	if intent.captureMethod == "manual" {
		intent.status = "requires_capture"
		intent.amountCapturable = intent.amount
		self.emitWithLock("charge.succeeded", self.renderCharge(charge))
		self.emitWithLock("payment_intent.amount_capturable_updated", self.renderPaymentIntentWithLock(intent, false, false))
		return nil
	}
	charge.captured = true
	intent.status = "succeeded"
	intent.amountReceived = intent.amount
	self.emitWithLock("charge.succeeded", self.renderCharge(charge))
	self.emitWithLock("payment_intent.succeeded", self.renderPaymentIntentWithLock(intent, false, false))
	return nil
}

// The person pays session on Checkout's hosted page with card: a payment method made for the card, saved to the
// session's customer only where the session asked setup_future_usage, the intent made and confirmed, 3-D Secure run
// where the session or the issuer asks and passed by the person. A declined card leaves the session open and answers
// its error; a paid one completes it and queues checkout.session.completed after the intent's events. Answers the
// intent's id.
func (self *FakeStripe) CompleteCheckout(sessionId string, card *FakeStripeCard) (string, error) {
	if card == nil || card.Label == "" {
		return "", fmt.Errorf("%w: a card needs a label", ErrFakeStoreState)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	session := self.sessionWithLock(sessionId)
	if session == nil {
		return "", ErrFakeStoreUnknown
	}
	if session.status != "open" || self.clock.Now().Unix() >= session.expiresAt {
		return "", fmt.Errorf("%w: the session is %s", ErrFakeStoreState, session.status)
	}
	now := self.clock.Now()
	method := &fakeStripePaymentMethod{
		id:          self.newIdWithLock("pm"),
		created:     now.Unix(),
		card:        &FakeStripeCard{Label: card.Label, Behavior: card.Behavior},
		fingerprint: self.fingerprint(card),
		last4:       self.last4(card),
	}
	if session.setupFutureUsage != "" {
		method.customer = session.customer
	}
	self.paymentMethods = append(self.paymentMethods, method)
	amount := int64(0)
	for _, line := range session.lineItems {
		amount += line.unitAmount * line.quantity
	}
	intent := self.paymentIntentWithLock(session.paymentIntent)
	if intent == nil {
		intent = &fakeStripePaymentIntent{
			id:               self.newIdWithLock("pi"),
			created:          now.Unix(),
			amount:           amount,
			currency:         session.currency,
			captureMethod:    session.captureMethod,
			status:           "requires_payment_method",
			customer:         session.customer,
			setupFutureUsage: session.setupFutureUsage,
			metadata:         session.intentMetadata,
		}
		self.paymentIntents = append(self.paymentIntents, intent)
		session.paymentIntent = intent.id
	}
	intent.threeDSecure = session.requestThreeDSecure == "any" || card.Behavior == FakeStripeCardRequiresAuthentication
	if failure := self.confirmWithLock(intent, method, false); failure != nil {
		return intent.id, fmt.Errorf("%w: %s", ErrFakeStoreState, failure["code"])
	}
	session.status = "complete"
	if intent.status == "succeeded" {
		session.paymentStatus = "paid"
	}
	self.emitWithLock("checkout.session.completed", self.renderSession(session))
	return intent.id, nil
}

// Lets session lapse unpaid, as its expires_at passing does: checkout.session.expired.
func (self *FakeStripe) ExpireCheckout(sessionId string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	session := self.sessionWithLock(sessionId)
	if session == nil {
		return ErrFakeStoreUnknown
	}
	if session.status != "open" {
		return fmt.Errorf("%w: the session is %s", ErrFakeStoreState, session.status)
	}
	session.status = "expired"
	self.emitWithLock("checkout.session.expired", self.renderSession(session))
	return nil
}

// Whether 3-D Secure ran for intentId's payment.
func (self *FakeStripe) ThreeDSecureRan(intentId string) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	intent := self.paymentIntentWithLock(intentId)
	return intent != nil && intent.threeDSecure
}

func (self *FakeStripe) servePaymentIntentCreate(writer http.ResponseWriter, request *http.Request, form url.Values) (int, any) {
	amount, ok := fakeStripeInt(form, "amount")
	if !ok || amount <= 0 || form.Get("currency") == "" {
		return fakeStripeInvalid("An intent needs an amount and a currency.")
	}
	if form.Get("confirm") != "true" || form.Get("off_session") != "true" {
		return fakeStripeInvalid("The fake makes off-session intents confirmed at once alone.")
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	var method *fakeStripePaymentMethod
	for _, stored := range self.paymentMethods {
		if stored.id == form.Get("payment_method") {
			method = stored
		}
	}
	if method == nil {
		return fakeStripeMissing("payment_method", form.Get("payment_method"))
	}
	if method.customer == "" || method.customer != form.Get("customer") {
		return fakeStripeInvalid("The provided PaymentMethod does not belong to the Customer: it was not saved for later use.")
	}
	captureMethod := form.Get("capture_method")
	if captureMethod == "" {
		captureMethod = "automatic"
	}
	intent := &fakeStripePaymentIntent{
		id:            self.newIdWithLock("pi"),
		created:       self.clock.Now().Unix(),
		amount:        amount,
		currency:      form.Get("currency"),
		captureMethod: captureMethod,
		status:        "requires_payment_method",
		customer:      form.Get("customer"),
		offSession:    true,
		metadata:      fakeStripeMetadata(form, "metadata"),
	}
	self.paymentIntents = append(self.paymentIntents, intent)
	if failure := self.confirmWithLock(intent, method, true); failure != nil {
		return http.StatusPaymentRequired, &fakeStripeErrorAnswer{body: fakeStripeErrorBody("card_error", failure["code"].(string), failure["decline_code"].(string), failure["message"].(string), self.renderPaymentIntentWithLock(intent, false, false))}
	}
	return http.StatusOK, self.renderPaymentIntentWithLock(intent, false, false)
}

func (self *FakeStripe) servePaymentIntentCapture(writer http.ResponseWriter, request *http.Request, form url.Values) (int, any) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	intent := self.paymentIntentWithLock(request.PathValue("id"))
	if intent == nil {
		return fakeStripeMissing("payment_intent", request.PathValue("id"))
	}
	if intent.status != "requires_capture" {
		return http.StatusBadRequest, &fakeStripeErrorAnswer{body: fakeStripeErrorBody("invalid_request_error", "payment_intent_unexpected_state", "", "This PaymentIntent could not be captured because it has a status of "+intent.status+".", self.renderPaymentIntentWithLock(intent, false, false))}
	}
	intent.status = "succeeded"
	intent.amountReceived = intent.amountCapturable
	intent.amountCapturable = 0
	if charge := self.chargeWithLock(intent.latestCharge); charge != nil {
		charge.captured = true
		self.emitWithLock("charge.captured", self.renderCharge(charge))
	}
	self.emitWithLock("payment_intent.succeeded", self.renderPaymentIntentWithLock(intent, false, false))
	return http.StatusOK, self.renderPaymentIntentWithLock(intent, false, false)
}

func (self *FakeStripe) servePaymentIntentCancel(writer http.ResponseWriter, request *http.Request, form url.Values) (int, any) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	intent := self.paymentIntentWithLock(request.PathValue("id"))
	if intent == nil {
		return fakeStripeMissing("payment_intent", request.PathValue("id"))
	}
	if intent.status == "succeeded" || intent.status == "canceled" {
		return http.StatusBadRequest, &fakeStripeErrorAnswer{body: fakeStripeErrorBody("invalid_request_error", "payment_intent_unexpected_state", "", "This PaymentIntent could not be canceled because it has a status of "+intent.status+".", self.renderPaymentIntentWithLock(intent, false, false))}
	}
	intent.status = "canceled"
	intent.amountCapturable = 0
	intent.cancellationReason = form.Get("cancellation_reason")
	if intent.cancellationReason == "" {
		intent.cancellationReason = "requested_by_customer"
	}
	self.emitWithLock("payment_intent.canceled", self.renderPaymentIntentWithLock(intent, false, false))
	return http.StatusOK, self.renderPaymentIntentWithLock(intent, false, false)
}

func (self *FakeStripe) servePaymentMethodGet(writer http.ResponseWriter, request *http.Request, form url.Values) (int, any) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, method := range self.paymentMethods {
		if method.id == request.PathValue("id") {
			return http.StatusOK, self.renderPaymentMethod(method)
		}
	}
	return fakeStripeMissing("payment_method", request.PathValue("id"))
}

func (self *FakeStripe) servePaymentMethodDetach(writer http.ResponseWriter, request *http.Request, form url.Values) (int, any) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, method := range self.paymentMethods {
		if method.id == request.PathValue("id") {
			if method.customer == "" {
				return fakeStripeInvalid("The payment method is not attached to a customer.")
			}
			method.customer = ""
			self.emitWithLock("payment_method.detached", self.renderPaymentMethod(method))
			return http.StatusOK, self.renderPaymentMethod(method)
		}
	}
	return fakeStripeMissing("payment_method", request.PathValue("id"))
}

// The payment method intentId was paid with as Stripe holds it, nil for none: whether its card was saved to a
// customer, and its fingerprint.
func (self *FakeStripe) PaymentMethodOf(intentId string) map[string]any {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	intent := self.paymentIntentWithLock(intentId)
	if intent == nil {
		return nil
	}
	for _, method := range self.paymentMethods {
		if method.id == intent.paymentMethod {
			return self.renderPaymentMethod(method)
		}
	}
	return nil
}

// The payment intent as Stripe holds it now, nil for none.
func (self *FakeStripe) PaymentIntent(intentId string) map[string]any {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	intent := self.paymentIntentWithLock(intentId)
	if intent == nil {
		return nil
	}
	return self.renderPaymentIntentWithLock(intent, true, true)
}

// Renders a refund.
func (self *FakeStripe) renderRefund(refund *fakeStripeRefund) map[string]any {
	return map[string]any{
		"id":             refund.id,
		"object":         "refund",
		"created":        refund.created,
		"amount":         refund.amount,
		"charge":         refund.charge,
		"payment_intent": refund.paymentIntent,
		"reason":         refund.reason,
		"status":         "succeeded",
		"currency":       "usd",
		"metadata":       refund.metadata,
	}
}

func (self *FakeStripe) serveRefundCreate(writer http.ResponseWriter, request *http.Request, form url.Values) (int, any) {
	amount, ok := fakeStripeInt(form, "amount")
	if !ok || amount < 0 {
		return fakeStripeInvalid("amount does not read.")
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	intent := self.paymentIntentWithLock(form.Get("payment_intent"))
	if intent == nil {
		return fakeStripeMissing("payment_intent", form.Get("payment_intent"))
	}
	charge := self.chargeWithLock(intent.latestCharge)
	if charge == nil || !charge.captured {
		return fakeStripeInvalid("This PaymentIntent has no captured charge to refund.")
	}
	unrefunded := charge.amount - charge.amountRefunded
	if amount == 0 {
		amount = unrefunded
	}
	if unrefunded < amount || amount == 0 {
		return fakeStripeInvalid(fmt.Sprintf("Refund amount (%d) is greater than unrefunded amount on charge (%d).", amount, unrefunded))
	}
	refund := &fakeStripeRefund{
		id:            self.newIdWithLock("re"),
		created:       self.clock.Now().Unix(),
		amount:        amount,
		charge:        charge.id,
		paymentIntent: intent.id,
		reason:        form.Get("reason"),
		metadata:      fakeStripeMetadata(form, "metadata"),
	}
	self.refunds = append(self.refunds, refund)
	charge.amountRefunded += amount
	self.emitWithLock("refund.created", self.renderRefund(refund))
	self.emitWithLock("charge.refunded", self.renderCharge(charge))
	return http.StatusOK, self.renderRefund(refund)
}

func (self *FakeStripe) serveRefundList(writer http.ResponseWriter, request *http.Request, form url.Values) (int, any) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	listed := []any{}
	for _, refund := range self.refunds {
		if paymentIntent := form.Get("payment_intent"); paymentIntent != "" && refund.paymentIntent != paymentIntent {
			continue
		}
		if len(listed) < self.limit(form) {
			listed = append(listed, self.renderRefund(refund))
		}
	}
	return http.StatusOK, fakeStripeList(listed, "/v1/refunds")
}

// Renders a dispute.
func (self *FakeStripe) renderDispute(dispute *fakeStripeDispute) map[string]any {
	return map[string]any{
		"id":             dispute.id,
		"object":         "dispute",
		"created":        dispute.created,
		"amount":         dispute.amount,
		"charge":         dispute.charge,
		"payment_intent": dispute.paymentIntent,
		"reason":         dispute.reason,
		"status":         dispute.status,
		"currency":       "usd",
		"livemode":       false,
	}
}

// The card holder disputes intentId's charge with their bank, a chargeback: the dispute opened and its funds
// withdrawn, charge.dispute.created and charge.dispute.funds_withdrawn queued. Answers the dispute's id.
func (self *FakeStripe) Dispute(intentId string, reason string) (string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	intent := self.paymentIntentWithLock(intentId)
	if intent == nil {
		return "", ErrFakeStoreUnknown
	}
	charge := self.chargeWithLock(intent.latestCharge)
	if charge == nil || !charge.captured || charge.disputed {
		return "", fmt.Errorf("%w: no captured, undisputed charge", ErrFakeStoreState)
	}
	charge.disputed = true
	dispute := &fakeStripeDispute{
		id:            self.newIdWithLock("dp"),
		created:       self.clock.Now().Unix(),
		amount:        charge.amount - charge.amountRefunded,
		charge:        charge.id,
		paymentIntent: intent.id,
		reason:        reason,
		status:        "needs_response",
	}
	self.disputes = append(self.disputes, dispute)
	self.emitWithLock("charge.dispute.created", self.renderDispute(dispute))
	self.emitWithLock("charge.dispute.funds_withdrawn", self.renderDispute(dispute))
	return dispute.id, nil
}

// Closes disputeId, won or lost: charge.dispute.closed, and charge.dispute.funds_reinstated where won.
func (self *FakeStripe) CloseDispute(disputeId string, won bool) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, dispute := range self.disputes {
		if dispute.id != disputeId {
			continue
		}
		if dispute.status == "won" || dispute.status == "lost" {
			return fmt.Errorf("%w: the dispute is closed", ErrFakeStoreState)
		}
		dispute.status = "lost"
		if won {
			dispute.status = "won"
			self.emitWithLock("charge.dispute.funds_reinstated", self.renderDispute(dispute))
		}
		self.emitWithLock("charge.dispute.closed", self.renderDispute(dispute))
		return nil
	}
	return ErrFakeStoreUnknown
}
