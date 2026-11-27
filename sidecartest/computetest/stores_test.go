package computetest

// CTEST-M12-02's tests: each market's notifications verifying as BAL's server code verifies them (Stripe's signature
// under the test endpoint secret, the App Store's JWS chain to the test root), Play's renewals each carrying a new
// order id under one token, and every market's notifications delivered once, twice, out of order or never as the test
// scripts them. The calls a test makes stand in for BAL's server code, on the wire each market documents.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

// An endpoint that keeps each delivery's body and headers, in arrival order, and answers 200.
type testStoreEndpoint struct {
	server *httptest.Server

	stateLock  sync.Mutex
	bodies     [][]byte
	headerList []http.Header
}

func newTestStoreEndpoint(t *testing.T) *testStoreEndpoint {
	t.Helper()
	endpoint := &testStoreEndpoint{}
	endpoint.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		endpoint.stateLock.Lock()
		endpoint.bodies = append(endpoint.bodies, body)
		endpoint.headerList = append(endpoint.headerList, request.Header.Clone())
		endpoint.stateLock.Unlock()
		writer.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(endpoint.server.Close)
	return endpoint
}

func (self *testStoreEndpoint) received() ([][]byte, []http.Header) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.bodies), slices.Clone(self.headerList)
}

// The three markets on a fake clock, closed at the test's end.
func newTestStores(t *testing.T, seed string) (*FakeStores, *sidecartest.FakeClock) {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	stores, err := NewFakeStores(&FakeStoresArgs{Seed: seed, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stores.Close)
	return stores, clock
}

// One Stripe call, form-encoded as stripe-go sends it, under the test API key: its status and its JSON.
func testStripeCall(t *testing.T, stripe *FakeStripe, method string, path string, form url.Values, idempotencyKey string) (int, map[string]any) {
	t.Helper()
	var body io.Reader
	target := stripe.Url() + path
	if method == http.MethodGet {
		target += "?" + form.Encode()
	} else {
		body = strings.NewReader(form.Encode())
	}
	request, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+stripe.ApiKey())
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	answer := map[string]any{}
	if err := json.NewDecoder(response.Body).Decode(&answer); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, answer
}

// Whether header is a valid Stripe-Signature over body under secret: Stripe's v1 scheme.
func testStripeSignatureValid(header string, body []byte, secret string) bool {
	timestamp := ""
	signatures := []string{}
	for _, pair := range strings.Split(header, ",") {
		name, value, _ := strings.Cut(pair, "=")
		switch name {
		case "t":
			timestamp = value
		case "v1":
			signatures = append(signatures, value)
		}
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "." + string(body)))
	expected := mac.Sum(nil)
	for _, signature := range signatures {
		decoded, err := hex.DecodeString(signature)
		if err == nil && hmac.Equal(decoded, expected) {
			return true
		}
	}
	return false
}

// A compute pack's session as BAL's checkout makes it (server's compute_stripe.go): one line at a dollar a credit,
// captured by hand, metadata on the session and its intent, the card saved where setup is asked.
func testStripeSession(t *testing.T, stripe *FakeStripe, customerId string, setup bool) string {
	t.Helper()
	form := url.Values{
		"mode":                                             {"payment"},
		"customer":                                         {customerId},
		"customer_update[address]":                         {"auto"},
		"automatic_tax[enabled]":                           {"true"},
		"line_items[0][price_data][currency]":              {"usd"},
		"line_items[0][price_data][product]":               {"prod_compute"},
		"line_items[0][price_data][unit_amount]":           {"2500"},
		"line_items[0][price_data][tax_behavior]":          {"exclusive"},
		"line_items[0][quantity]":                          {"1"},
		"payment_method_types[0]":                          {"card"},
		"payment_intent_data[capture_method]":              {"manual"},
		"payment_intent_data[metadata][urnetwork_compute]": {"1"},
		"metadata[urnetwork_compute]":                      {"1"},
		"success_url":                                      {"https://app.example/compute/done"},
		"cancel_url":                                       {"https://app.example/compute/cancel"},
	}
	if setup {
		form.Set("payment_intent_data[setup_future_usage]", "off_session")
	}
	status, session := testStripeCall(t, stripe, http.MethodPost, "/v1/checkout/sessions", form, "")
	if status != http.StatusOK || session["status"] != "open" || !strings.HasPrefix(session["url"].(string), "https://checkout.stripe.example/") {
		t.Fatalf("the session: %d %v", status, session)
	}
	return session["id"].(string)
}

// Every Stripe event is delivered signed under the test endpoint secret, over the exact bytes delivered, and no other
// secret verifies it; a pack bought on Checkout holds its card until captured, saves the card only where setup was
// asked, and pays off session on a saved card only, a card needing authentication or declining answering 402 (§9.5,
// §9.8, §9.11).
func TestFakeStripeWebhooksVerifyUnderTheTestSecret(t *testing.T) {
	stores, _ := newTestStores(t, "stripe")
	stripe := stores.Stripe
	endpoint := newTestStoreEndpoint(t)
	stripe.Events().SetEndpoint(endpoint.server.URL, nil)

	status, customer := testStripeCall(t, stripe, http.MethodPost, "/v1/customers", url.Values{"metadata[compute_network_id]": {"network-a"}, "metadata[compute_member_id]": {"alice"}}, "customer-a-alice")
	if status != http.StatusOK {
		t.Fatalf("the customer: %d %v", status, customer)
	}
	_, again := testStripeCall(t, stripe, http.MethodPost, "/v1/customers", url.Values{"metadata[compute_network_id]": {"network-a"}}, "customer-a-alice")
	if again["id"] != customer["id"] {
		t.Fatalf("one Idempotency-Key made two customers: %v, %v", customer["id"], again["id"])
	}
	_, found := testStripeCall(t, stripe, http.MethodGet, "/v1/customers/search", url.Values{"query": {"metadata['compute_network_id']:'network-a' AND metadata['compute_member_id']:'alice'"}}, "")
	if data := found["data"].([]any); len(data) != 1 || data[0].(map[string]any)["id"] != customer["id"] {
		t.Fatalf("the search found %v", found)
	}
	customerId := customer["id"].(string)

	card := &FakeStripeCard{Label: "alice-visa", Behavior: FakeStripeCardSucceeds}
	sessionId := testStripeSession(t, stripe, customerId, true)
	intentId, err := stripe.CompleteCheckout(sessionId, card)
	if err != nil {
		t.Fatal(err)
	}
	_, intent := testStripeCall(t, stripe, http.MethodGet, "/v1/payment_intents/"+intentId, url.Values{"expand[0]": {"payment_method"}, "expand[1]": {"latest_charge"}}, "")
	method := intent["payment_method"].(map[string]any)
	if intent["status"] != "requires_capture" || method["customer"] != customerId {
		t.Fatalf("a held intent with its card saved: %v", intent)
	}
	fingerprint := method["card"].(map[string]any)["fingerprint"].(string)
	if charge := intent["latest_charge"].(map[string]any); charge["payment_method_details"].(map[string]any)["card"].(map[string]any)["fingerprint"] != fingerprint {
		t.Fatalf("the charge's card differs: %v", charge)
	}
	status, captured := testStripeCall(t, stripe, http.MethodPost, "/v1/payment_intents/"+intentId+"/capture", nil, "capture-"+intentId)
	if status != http.StatusOK || captured["status"] != "succeeded" || captured["amount_received"].(float64) != 2500 {
		t.Fatalf("the capture: %d %v", status, captured)
	}

	// the same card in another network's session, no setup asked: not saved, the same fingerprint
	otherSessionId := testStripeSession(t, stripe, "", false)
	otherIntentId, err := stripe.CompleteCheckout(otherSessionId, card)
	if err != nil {
		t.Fatal(err)
	}
	if other := stripe.PaymentMethodOf(otherIntentId); other["customer"] != nil || other["card"].(map[string]any)["fingerprint"] != fingerprint {
		t.Fatalf("an unsaved card: %v", other)
	}
	if third := stripe.PaymentMethodOf(intentId); third == nil {
		t.Fatal("no payment method")
	}

	// a threshold top-up off session on the saved card, and the refusals a card makes there
	status, offSession := testStripeCall(t, stripe, http.MethodPost, "/v1/payment_intents", url.Values{
		"amount": {"2000"}, "currency": {"usd"}, "customer": {customerId}, "payment_method": {method["id"].(string)},
		"off_session": {"true"}, "confirm": {"true"},
	}, "topup-1")
	if status != http.StatusOK || offSession["status"] != "succeeded" {
		t.Fatalf("an off-session top-up: %d %v", status, offSession)
	}
	for _, c := range []struct {
		card *FakeStripeCard
		code string
	}{
		{card: &FakeStripeCard{Label: "bob-3ds", Behavior: FakeStripeCardRequiresAuthentication}, code: "authentication_required"},
		{card: &FakeStripeCard{Label: "carol-declined", Behavior: FakeStripeCardSucceeds}, code: "card_declined"},
	} {
		savedSessionId := testStripeSession(t, stripe, customerId, true)
		savedIntentId, err := stripe.CompleteCheckout(savedSessionId, c.card)
		if err != nil {
			t.Fatal(err)
		}
		savedMethodId := stripe.PaymentMethodOf(savedIntentId)["id"].(string)
		if c.code == "card_declined" {
			// the card turns bad after it was saved
			func() {
				stripe.stateLock.Lock()
				defer stripe.stateLock.Unlock()
				for _, stored := range stripe.paymentMethods {
					if stored.id == savedMethodId {
						stored.card.Behavior = FakeStripeCardDeclines
					}
				}
			}()
		}
		status, refused := testStripeCall(t, stripe, http.MethodPost, "/v1/payment_intents", url.Values{
			"amount": {"2000"}, "currency": {"usd"}, "customer": {customerId}, "payment_method": {savedMethodId},
			"off_session": {"true"}, "confirm": {"true"},
		}, "")
		errorBody, _ := refused["error"].(map[string]any)
		if status != http.StatusPaymentRequired || errorBody == nil || errorBody["code"] != c.code {
			t.Fatalf("%s: %d %v", c.card.Label, status, refused)
		}
		if c.code == "authentication_required" && !stripe.ThreeDSecureRan(savedIntentId) {
			t.Errorf("%s passed Checkout without 3-D Secure", c.card.Label)
		}
	}
	unsavedMethodId := stripe.PaymentMethodOf(otherIntentId)["id"].(string)
	status, _ = testStripeCall(t, stripe, http.MethodPost, "/v1/payment_intents", url.Values{
		"amount": {"2000"}, "currency": {"usd"}, "customer": {customerId}, "payment_method": {unsavedMethodId},
		"off_session": {"true"}, "confirm": {"true"},
	}, "")
	if status != http.StatusBadRequest {
		t.Fatalf("an off-session charge on a card never saved answered %d", status)
	}

	statuses, err := stripe.Events().DeliverPending(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	bodies, headers := endpoint.received()
	if len(bodies) == 0 || len(bodies) != len(statuses) {
		t.Fatalf("%d deliveries, %d statuses", len(bodies), len(statuses))
	}
	types := []string{}
	for i, body := range bodies {
		signature := headers[i].Get("Stripe-Signature")
		if !testStripeSignatureValid(signature, body, stripe.WebhookSecret()) {
			t.Fatalf("delivery %d does not verify under the test secret", i)
		}
		if testStripeSignatureValid(signature, body, "whsec_another") {
			t.Fatalf("delivery %d verifies under another secret", i)
		}
		if testStripeSignatureValid(signature, append(bytes.Clone(body), ' '), stripe.WebhookSecret()) {
			t.Fatalf("delivery %d verifies over other bytes", i)
		}
		event := map[string]any{}
		if err := json.Unmarshal(body, &event); err != nil {
			t.Fatal(err)
		}
		if event["object"] != "event" || event["api_version"] != DefaultFakeStripeSettings().ApiVersion || event["data"].(map[string]any)["object"] == nil {
			t.Fatalf("an event %v", event)
		}
		types = append(types, event["type"].(string))
	}
	want := []string{"charge.succeeded", "payment_intent.amount_capturable_updated", "checkout.session.completed", "charge.captured", "payment_intent.succeeded"}
	if !slices.Equal(types[:len(want)], want) {
		t.Fatalf("the first events %v, want %v", types[:len(want)], want)
	}

	// a request without the key is refused
	request, _ := http.NewRequest(http.MethodGet, stripe.Url()+"/v1/payment_intents/"+intentId, nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a keyless request answered %d", response.StatusCode)
	}

	// a refund of the unspent part, then a chargeback of the rest
	status, refund := testStripeCall(t, stripe, http.MethodPost, "/v1/refunds", url.Values{"payment_intent": {intentId}, "amount": {"1000"}, "metadata[compute_refund]": {"self_serve"}}, "refund-1")
	if status != http.StatusOK || refund["amount"].(float64) != 1000 {
		t.Fatalf("the refund: %d %v", status, refund)
	}
	status, _ = testStripeCall(t, stripe, http.MethodPost, "/v1/refunds", url.Values{"payment_intent": {intentId}, "amount": {"2000"}}, "")
	if status != http.StatusBadRequest {
		t.Fatalf("a refund past the unrefunded amount answered %d", status)
	}
	if _, err := stripe.Dispute(intentId, "fraudulent"); err != nil {
		t.Fatal(err)
	}
	if stripe.Events().Last("charge.dispute.funds_withdrawn") == nil {
		t.Fatal("a chargeback queued no funds_withdrawn")
	}
}

// Verifies jws as server's verifier does (api/handlers/apple_notification_verifier.go): ES256, three certificates in
// x5c, Apple's policy extensions on the leaf and the intermediate, the chain ending at root and verifying at the
// payload's signedDate, a P-256 leaf whose key verifies the signature. Answers the claims.
func testAppleVerify(t *testing.T, jws string, root *x509.Certificate) (map[string]any, error) {
	t.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not compact")
	}
	headerJson, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	header := struct {
		Alg string   `json:"alg"`
		X5c []string `json:"x5c"`
	}{}
	if err := json.Unmarshal(headerJson, &header); err != nil {
		return nil, err
	}
	if header.Alg != "ES256" || len(header.X5c) != 3 {
		return nil, fmt.Errorf("not ES256 with three certificates")
	}
	certificates := []*x509.Certificate{}
	for _, encoded := range header.X5c {
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, err
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
	}
	hasExtension := func(certificate *x509.Certificate, oid asn1.ObjectIdentifier) bool {
		return slices.ContainsFunc(certificate.Extensions, func(extension pkix.Extension) bool { return extension.Id.Equal(oid) })
	}
	if !hasExtension(certificates[0], FakeAppleLeafPolicyOid) || !hasExtension(certificates[1], FakeAppleIntermediatePolicyOid) {
		return nil, fmt.Errorf("the chain lacks Apple's policy extensions")
	}
	if !bytes.Equal(certificates[2].Raw, root.Raw) {
		return nil, fmt.Errorf("the chain does not end at the pinned root")
	}
	payloadJson, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	claims := map[string]any{}
	if err := json.Unmarshal(payloadJson, &claims); err != nil {
		return nil, err
	}
	signedDate, _ := claims["signedDate"].(float64)
	if signedDate <= 0 {
		return nil, fmt.Errorf("no signed date")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(certificates[1])
	if _, err := certificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: time.UnixMilli(int64(signedDate)), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, err
	}
	key, ok := certificates[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("not a P-256 leaf")
	}
	if _, _, err := fakeJwsVerify(jws, key); err != nil {
		return nil, err
	}
	return claims, nil
}

// A Server API bearer signed with the App Store's test key, as server's appleServerApiToken signs one.
func testAppleBearer(t *testing.T, store *FakeAppStore, bundleId string, now time.Time) string {
	t.Helper()
	keyPem, err := store.ApiKeyPem()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyPem)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	bearer, err := fakeJwsSign(parsed.(*ecdsa.PrivateKey), map[string]any{"kid": store.ApiKeyId(), "typ": "JWT"}, map[string]any{
		"iss": store.IssuerId(), "iat": now.Unix(), "exp": now.Add(30 * time.Minute).Unix(), "aud": "appstoreconnect-v1", "bid": bundleId,
	})
	if err != nil {
		t.Fatal(err)
	}
	return bearer
}

// Every App Store object (the app's report, a notification's payload, the transaction and renewal inside it, a Server
// API answer) is a JWS chaining to the test root with Apple's policy extensions, and none verifies under another
// root; the Server API answers only a bearer of the test key for this app.
func TestFakeAppStoreJwsChainsToTheTestRoot(t *testing.T) {
	stores, clock := newTestStores(t, "apple")
	store := stores.AppStore
	networkId := "0b6d3a10-0000-4000-8000-000000000001"
	consumable, err := store.BuyConsumable(&FakeApplePurchase{ProductId: "compute.credits.25", AppAccountToken: networkId, Payer: "alice-apple", Price: 24990})
	if err != nil {
		t.Fatal(err)
	}
	report, err := store.SignedTransaction(consumable.TransactionId)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := testAppleVerify(t, report, store.RootCertificate())
	if err != nil {
		t.Fatal(err)
	}
	if claims["transactionId"] != consumable.TransactionId || claims["appAccountToken"] != networkId || claims["type"] != FakeAppleTypeConsumable || claims["bundleId"] != DefaultFakeAppStoreSettings().BundleId {
		t.Fatalf("the report's claims %v", claims)
	}

	subscription, err := store.Subscribe(&FakeApplePurchase{ProductId: "compute.monthly.10", SubscriptionGroupId: "compute", AppAccountToken: networkId, Payer: "alice-apple", Price: 11990})
	if err != nil {
		t.Fatal(err)
	}
	notification := store.Notifications().Last("SUBSCRIBED/INITIAL_BUY")
	if notification == nil {
		t.Fatal("no SUBSCRIBED notification")
	}
	signedPayload := struct {
		SignedPayload string `json:"signedPayload"`
	}{}
	if err := json.Unmarshal(notification.Body, &signedPayload); err != nil {
		t.Fatal(err)
	}
	outer, err := testAppleVerify(t, signedPayload.SignedPayload, store.RootCertificate())
	if err != nil {
		t.Fatal(err)
	}
	data := outer["data"].(map[string]any)
	if outer["notificationType"] != "SUBSCRIBED" || outer["subtype"] != "INITIAL_BUY" || outer["version"] != "2.0" || data["bundleId"] != DefaultFakeAppStoreSettings().BundleId {
		t.Fatalf("the notification %v", outer)
	}
	inner, err := testAppleVerify(t, data["signedTransactionInfo"].(string), store.RootCertificate())
	if err != nil || inner["originalTransactionId"] != subscription.OriginalTransactionId {
		t.Fatalf("the transaction inside: %v, %v", inner, err)
	}
	if renewal, err := testAppleVerify(t, data["signedRenewalInfo"].(string), store.RootCertificate()); err != nil || renewal["autoRenewProductId"] != "compute.monthly.10" {
		t.Fatalf("the renewal inside: %v, %v", renewal, err)
	}

	// another seed's root verifies none of it
	otherStores, _ := newTestStores(t, "apple other")
	if _, err := testAppleVerify(t, report, otherStores.AppStore.RootCertificate()); err == nil {
		t.Fatal("the report verified under another root")
	}
	// the same seed and clock make the same bytes
	againReport, err := store.SignedTransaction(consumable.TransactionId)
	if err != nil || againReport != report {
		t.Fatalf("one transaction signed twice differs: %v", err)
	}

	// the Server API, behind the test key's bearer
	call := func(bearer string, path string) (int, map[string]any) {
		request, _ := http.NewRequest(http.MethodGet, store.Url()+path, nil)
		if bearer != "" {
			request.Header.Set("Authorization", "Bearer "+bearer)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		answer := map[string]any{}
		json.NewDecoder(response.Body).Decode(&answer)
		return response.StatusCode, answer
	}
	bearer := testAppleBearer(t, store, DefaultFakeAppStoreSettings().BundleId, clock.Now())
	status, answer := call(bearer, "/inApps/v1/transactions/"+consumable.TransactionId)
	if status != http.StatusOK {
		t.Fatalf("the lookup answered %d %v", status, answer)
	}
	if _, err := testAppleVerify(t, answer["signedTransactionInfo"].(string), store.RootCertificate()); err != nil {
		t.Fatal(err)
	}
	for _, refused := range []string{"", testAppleBearer(t, store, "com.example.another", clock.Now()), testAppleBearer(t, otherStores.AppStore, DefaultFakeAppStoreSettings().BundleId, clock.Now())} {
		if status, _ := call(refused, "/inApps/v1/transactions/"+consumable.TransactionId); status != http.StatusUnauthorized {
			t.Fatalf("a bearer that is not the test key's for this app answered %d", status)
		}
	}
	// an upgrade marks the old period upgraded, and the history shows both, newest first
	clock.Advance(24 * time.Hour)
	upgraded, err := store.Upgrade(subscription.OriginalTransactionId, "compute.monthly.25", 27990)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := call(bearer, "/inApps/v1/transactions/"+upgraded.TransactionId); status != http.StatusUnauthorized {
		t.Fatalf("a bearer past its life answered %d", status)
	}
	bearer = testAppleBearer(t, store, DefaultFakeAppStoreSettings().BundleId, clock.Now())
	status, history := call(bearer, "/inApps/v2/history/"+subscription.TransactionId+"?productType=AUTO_RENEWABLE&sort=DESCENDING")
	signed, _ := history["signedTransactions"].([]any)
	if status != http.StatusOK || len(signed) != 2 {
		t.Fatalf("the history: %d %v", status, history)
	}
	newest, err := testAppleVerify(t, signed[0].(string), store.RootCertificate())
	if err != nil || newest["transactionId"] != upgraded.TransactionId {
		t.Fatalf("the newest: %v, %v", newest, err)
	}
	if oldest, err := testAppleVerify(t, signed[1].(string), store.RootCertificate()); err != nil || oldest["isUpgraded"] != true {
		t.Fatalf("the upgraded period: %v, %v", oldest, err)
	}
}

// One Play call under the test access token: its status and JSON.
func testPlayCall(t *testing.T, play *FakePlay, method string, path string) (int, map[string]any) {
	t.Helper()
	request, err := http.NewRequest(method, play.Url()+"/androidpublisher/v3/applications/"+DefaultFakePlaySettings().PackageName+"/"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+play.AccessToken())
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	answer := map[string]any{}
	json.NewDecoder(response.Body).Decode(&answer)
	return response.StatusCode, answer
}

// A Play subscription keeps one purchase token across its renewals, and each renewal carries an order id of its own,
// the first order's with ..0, ..1, …, which subscriptionsv2 and each push name, so a renewal is credited once by its
// order id (§9.5); a replacement plan is a new token linked to the old; a push's bearer is an id token the fake's
// tokeninfo answers for the publisher and audience; a consumable left unconsumed past three days is voided.
func TestFakePlayRenewalsCarryNewOrderIds(t *testing.T) {
	stores, clock := newTestStores(t, "play")
	play := stores.Play
	networkId := "0b6d3a10-0000-4000-8000-000000000002"
	token, err := play.Subscribe(&FakePlayPurchase{ProductId: "compute.monthly.10", BasePlanId: "monthly", ObfuscatedAccountId: networkId})
	if err != nil {
		t.Fatal(err)
	}
	orderIds := []string{play.LatestOrderId(token)}
	for range 3 {
		orderId, err := play.Renew(token)
		if err != nil {
			t.Fatal(err)
		}
		orderIds = append(orderIds, orderId)
	}
	for i, orderId := range orderIds[1:] {
		if orderId != fmt.Sprintf("%s..%d", orderIds[0], i) {
			t.Fatalf("renewal %d's order id %s", i, orderId)
		}
	}
	if !strings.HasPrefix(orderIds[0], "GPA.3") || len(orderIds[0]) != len("GPA.3xxx-xxxx-xxxx-xxxxx") {
		t.Fatalf("an order id %s", orderIds[0])
	}
	status, subscription := testPlayCall(t, play, http.MethodGet, "purchases/subscriptionsv2/tokens/"+token)
	lineItem := subscription["lineItems"].([]any)[0].(map[string]any)
	if status != http.StatusOK || lineItem["latestSuccessfulOrderId"] != orderIds[3] || subscription["externalAccountIdentifiers"].(map[string]any)["obfuscatedExternalAccountId"] != networkId {
		t.Fatalf("subscriptionsv2: %d %v", status, subscription)
	}
	pushes := play.Notifications().All()
	types := []string{}
	for _, push := range pushes {
		developer, err := FakePlayDeveloperNotification(push.Body)
		if err != nil {
			t.Fatal(err)
		}
		inner := developer["subscriptionNotification"].(map[string]any)
		if inner["purchaseToken"] != token {
			t.Fatalf("a push names %v", inner["purchaseToken"])
		}
		types = append(types, push.Type)
		// the push's bearer is an id token tokeninfo answers as Google's does
		idToken := strings.TrimPrefix(push.Header.Get("Authorization"), "Bearer ")
		response, err := http.Get(play.TokenInfoUrl() + "?id_token=" + url.QueryEscape(idToken))
		if err != nil {
			t.Fatal(err)
		}
		claims := map[string]any{}
		json.NewDecoder(response.Body).Decode(&claims)
		response.Body.Close()
		if response.StatusCode != http.StatusOK || claims["email"] != DefaultFakePlaySettings().PublisherEmail || claims["aud"] != DefaultFakePlaySettings().Audience ||
			claims["email_verified"] != "true" || claims["iss"] != FakePlayIdTokenIssuer {
			t.Fatalf("tokeninfo answered %d %v", response.StatusCode, claims)
		}
	}
	if !slices.Equal(types, []string{"subscriptionNotification.4", "subscriptionNotification.2", "subscriptionNotification.2", "subscriptionNotification.2"}) {
		t.Fatalf("the pushes %v", types)
	}
	if response, err := http.Get(play.TokenInfoUrl() + "?id_token=a.forged.token"); err != nil || response.StatusCode != http.StatusBadRequest {
		t.Fatalf("tokeninfo of a token the fake never issued: %v", err)
	}

	// a replacement plan, its new token linked to the old
	replacement, err := play.Replace(token, &FakePlayPurchase{ProductId: "compute.monthly.25", BasePlanId: "monthly"})
	if err != nil {
		t.Fatal(err)
	}
	_, replaced := testPlayCall(t, play, http.MethodGet, "purchases/subscriptionsv2/tokens/"+replacement)
	if replaced["linkedPurchaseToken"] != token {
		t.Fatalf("the replacement: %v", replaced)
	}
	if _, old := testPlayCall(t, play, http.MethodGet, "purchases/subscriptionsv2/tokens/"+token); old["subscriptionState"] != "SUBSCRIPTION_STATE_EXPIRED" {
		t.Fatalf("the replaced plan: %v", old)
	}
	if _, err := play.Renew(token); err == nil {
		t.Fatal("a replaced plan renewed")
	}

	// consumables: one consumed at once, one left past the three days and voided
	consumed, err := play.BuyConsumable(&FakePlayPurchase{ProductId: "compute.credits.10", ObfuscatedAccountId: networkId})
	if err != nil {
		t.Fatal(err)
	}
	left, err := play.BuyConsumable(&FakePlayPurchase{ProductId: "compute.credits.10", ObfuscatedAccountId: networkId})
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := testPlayCall(t, play, http.MethodPost, "purchases/products/compute.credits.10/tokens/"+consumed+":consume"); status != http.StatusOK {
		t.Fatalf("the consume answered %d", status)
	}
	if status, _ := testPlayCall(t, play, http.MethodPost, "purchases/products/compute.credits.10/tokens/"+consumed+":consume"); status != http.StatusBadRequest {
		t.Fatalf("a second consume answered %d", status)
	}
	clock.Advance(DefaultFakePlaySettings().AcknowledgeWindow - time.Second)
	if voided, err := play.VoidUnacknowledged(); err != nil || len(voided) != 0 {
		t.Fatalf("voided inside the window: %v, %v", voided, err)
	}
	clock.Advance(time.Second)
	voided, err := play.VoidUnacknowledged()
	if err != nil || !slices.Equal(voided, []string{left}) {
		t.Fatalf("voided past the window: %v, %v", voided, err)
	}
	_, list := testPlayCall(t, play, http.MethodGet, "purchases/voidedpurchases")
	if purchases := list["voidedPurchases"].([]any); len(purchases) != 1 || purchases[0].(map[string]any)["purchaseToken"] != left {
		t.Fatalf("voidedpurchases %v", list)
	}
	if status, _ := testPlayCall(t, play, http.MethodPost, "purchases/products/compute.credits.10/tokens/"+left+":consume"); status != http.StatusGone {
		t.Fatalf("a voided purchase consumed: %d", status)
	}
}

// Each market's notifications go where and when the test says: in order, reversed, a second time with the same id
// and bytes (Stripe re-signing each attempt), or never; nothing is delivered until asked.
func TestFakeStoresReplayAndReorderNotifications(t *testing.T) {
	stores, clock := newTestStores(t, "replay")
	ctx := context.Background()

	// Play: three consumables' pushes, reversed, the first again, one dropped
	playEndpoint := newTestStoreEndpoint(t)
	stores.Play.Notifications().SetEndpoint(playEndpoint.server.URL, nil)
	for range 4 {
		if _, err := stores.Play.BuyConsumable(&FakePlayPurchase{ProductId: "compute.credits.10"}); err != nil {
			t.Fatal(err)
		}
	}
	made := stores.Play.Notifications().All()
	if bodies, _ := playEndpoint.received(); len(bodies) != 0 {
		t.Fatal("a push was delivered before the test asked")
	}
	if err := stores.Play.Notifications().Drop(made[3].Id); err != nil {
		t.Fatal(err)
	}
	if _, err := stores.Play.Notifications().DeliverPendingReversed(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := stores.Play.Notifications().Deliver(ctx, made[0].Id); err != nil {
		t.Fatal(err)
	}
	bodies, _ := playEndpoint.received()
	arrived := []string{}
	for _, body := range bodies {
		push := struct {
			Message struct {
				MessageId string `json:"messageId"`
			} `json:"message"`
		}{}
		json.Unmarshal(body, &push)
		arrived = append(arrived, push.Message.MessageId)
	}
	if !slices.Equal(arrived, []string{made[2].Id, made[1].Id, made[0].Id, made[0].Id}) {
		t.Fatalf("arrived %v", arrived)
	}
	if !bytes.Equal(bodies[2], bodies[3]) {
		t.Fatal("a push delivered twice changed its bytes")
	}
	if pending := stores.Play.Notifications().Pending(); len(pending) != 0 {
		t.Fatalf("pending after delivery %v", pending)
	}

	// Stripe: one event twice, the same id and body, each attempt signed afresh at its own time
	stripeEndpoint := newTestStoreEndpoint(t)
	stores.Stripe.Events().SetEndpoint(stripeEndpoint.server.URL, nil)
	sessionId := testStripeSession(t, stores.Stripe, "", false)
	if _, err := stores.Stripe.CompleteCheckout(sessionId, &FakeStripeCard{Label: "dave", Behavior: FakeStripeCardSucceeds}); err != nil {
		t.Fatal(err)
	}
	completed := stores.Stripe.Events().Last("checkout.session.completed")
	if _, err := stores.Stripe.Events().Deliver(ctx, completed.Id); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Minute)
	if _, err := stores.Stripe.Events().Deliver(ctx, completed.Id); err != nil {
		t.Fatal(err)
	}
	stripeBodies, stripeHeaders := stripeEndpoint.received()
	if len(stripeBodies) != 2 || !bytes.Equal(stripeBodies[0], stripeBodies[1]) || stripeHeaders[0].Get("Stripe-Signature") == stripeHeaders[1].Get("Stripe-Signature") {
		t.Fatalf("a redelivery: %d bodies", len(stripeBodies))
	}
	for i := range stripeBodies {
		if !testStripeSignatureValid(stripeHeaders[i].Get("Stripe-Signature"), stripeBodies[i], stores.Stripe.WebhookSecret()) {
			t.Fatalf("attempt %d does not verify", i)
		}
	}
	if got := stores.Stripe.Events().All(); got[slices.IndexFunc(got, func(event *FakeStoreNotification) bool { return event.Id == completed.Id })].DeliveryStatuses[1] != http.StatusOK {
		t.Fatal("the second attempt's answer was not kept")
	}

	// App Store: the app's report races its notification, both naming one transaction, the notification never
	// delivered and the transaction reported again at the next launch until finished
	appleEndpoint := newTestStoreEndpoint(t)
	stores.AppStore.Notifications().SetEndpoint(appleEndpoint.server.URL, nil)
	transaction, err := stores.AppStore.BuyConsumable(&FakeApplePurchase{ProductId: "compute.credits.10", Payer: "erin", Price: 11990})
	if err != nil {
		t.Fatal(err)
	}
	report, err := stores.AppStore.SignedTransaction(transaction.TransactionId)
	if err != nil {
		t.Fatal(err)
	}
	reportClaims, err := testAppleVerify(t, report, stores.AppStore.RootCertificate())
	if err != nil {
		t.Fatal(err)
	}
	notification := stores.AppStore.Notifications().Last("ONE_TIME_CHARGE")
	if err := stores.AppStore.Notifications().Drop(notification.Id); err != nil {
		t.Fatal(err)
	}
	if statuses, err := stores.AppStore.Notifications().DeliverPending(ctx); err != nil || len(statuses) != 0 {
		t.Fatalf("a dropped notification delivered: %v, %v", statuses, err)
	}
	if !slices.Equal(stores.AppStore.Unfinished(), []string{transaction.TransactionId}) {
		t.Fatalf("unfinished %v", stores.AppStore.Unfinished())
	}
	if _, err := stores.AppStore.Notifications().Deliver(ctx, notification.Id); err != nil {
		t.Fatal(err)
	}
	appleBodies, _ := appleEndpoint.received()
	signedPayload := struct {
		SignedPayload string `json:"signedPayload"`
	}{}
	json.Unmarshal(appleBodies[0], &signedPayload)
	outer, err := testAppleVerify(t, signedPayload.SignedPayload, stores.AppStore.RootCertificate())
	if err != nil {
		t.Fatal(err)
	}
	inner, err := testAppleVerify(t, outer["data"].(map[string]any)["signedTransactionInfo"].(string), stores.AppStore.RootCertificate())
	if err != nil || inner["transactionId"] != reportClaims["transactionId"] {
		t.Fatalf("the notification names %v, the report %v", inner["transactionId"], reportClaims["transactionId"])
	}
	if err := stores.AppStore.Finish(transaction.TransactionId); err != nil || len(stores.AppStore.Unfinished()) != 0 {
		t.Fatalf("finished: %v %v", err, stores.AppStore.Unfinished())
	}
}
