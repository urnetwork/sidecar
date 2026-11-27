// computetest.FakePlay (CTEST-M12-02; DESIGN-COMPUTE §9.5, §9.11, §9.12, D-BAL-8): Google Play as BAL's server code
// reads it, the Android Publisher API under /androidpublisher/v3/applications/{packageName}/ on a loopback server:
//
//	consumables    purchases.products get, consume and acknowledge; a purchase neither consumed nor acknowledged
//	               within AcknowledgeWindow (three days) is refunded and voided by Play (VoidUnacknowledged), as
//	               Play does
//	subscriptions  purchases.subscriptionsv2 get and purchases.subscriptions acknowledge; one purchase token across
//	               every renewal, each renewal a new order id (GPA.…..0, ..1, …), the plan's latestSuccessfulOrderId
//	               moving with it; a replacement plan a new token whose linkedPurchaseToken names the old, which
//	               expires
//	voids          purchases.voidedpurchases list, and orders' refund (revoke=true) for a gone network's purchase
//	notifications  real-time developer notifications as Pub/Sub pushes them: {"message": {"data": base64 of the
//	               DeveloperNotification, "messageId", "publishTime"}, "subscription"}, under an Authorization bearer
//	               that is a Google-shaped id token for the publisher's service account and the push's audience, which
//	               the fake's tokeninfo endpoint (GET /tokeninfo?id_token=) answers as Google's does, so server's
//	               playIdTokenClaims can be pointed at it; queued in Notifications() until the test delivers them
//
// Every request to the API must carry the test's access token (AccessToken) as its bearer, else 401, and every id
// (purchase tokens, order ids, message ids) is synthetic, drawn from the seed in order. obfuscatedExternalAccountId is
// what the app set at purchase (the network's id), empty for a purchase that names none.
//
// Safe for concurrent use: one lock guards the state; the server's I/O runs outside it.

package computetest

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// The fake Play's settings (QD-702).
type FakePlaySettings struct {
	// The app's package: synthetic.
	PackageName string
	// A subscription's period, in months.
	SubscriptionPeriodMonths int
	// How long Play waits for a one-time purchase to be consumed or acknowledged before it refunds it: three days.
	AcknowledgeWindow time.Duration
	// The Pub/Sub subscription a push names.
	PubsubSubscription string
	// The service account a push's id token names, and the audience it is for: what server's google.yml webhook
	// block holds, synthetic here.
	PublisherEmail string
	Audience       string
	// How long a push's id token is good for: an hour, as Google's.
	IdTokenLife time.Duration
	// The region a purchase is billed in.
	RegionCode string
}

// The defaults, the only place one is set.
func DefaultFakePlaySettings() *FakePlaySettings {
	return &FakePlaySettings{
		PackageName:              "com.example.urnetwork",
		SubscriptionPeriodMonths: 1,
		AcknowledgeWindow:        3 * 24 * time.Hour,
		PubsubSubscription:       "projects/computetest/subscriptions/play-rtdn",
		PublisherEmail:           "play-rtdn@computetest.iam.example",
		Audience:                 "https://api.example/subscription/play-webhook",
		IdTokenLife:              time.Hour,
		RegionCode:               "US",
	}
}

// The issuer a push's id token names, Google's, which server's push verifier requires (controller's verifyPlayAuth):
// an identifier of Google's token format, never a host the fake reaches.
const FakePlayIdTokenIssuer = "https://accounts.google.com"

// Play's notification types the fake sends (RTDN's): identifiers.
const (
	FakePlayOneTimePurchased       = 1
	FakePlaySubscriptionRenewed    = 2
	FakePlaySubscriptionPurchased  = 4
	FakePlaySubscriptionExpired    = 13
	FakePlaySubscriptionRevoked    = 12
	FakePlayVoidedSubscriptionType = 1
	FakePlayVoidedOneTimeType      = 2
)

// A one-time purchase.
type fakePlayProduct struct {
	token                string
	productId            string
	orderId              string
	purchaseTime         time.Time
	purchaseState        int
	consumptionState     int
	acknowledgementState int
	obfuscatedAccountId  string
	test                 bool
	voided               bool
}

// A subscription purchase, one token across its renewals.
type fakePlaySubscription struct {
	token               string
	productId           string
	basePlanId          string
	startTime           time.Time
	expiryTime          time.Time
	baseOrderId         string
	renewalCount        int
	latestOrderId       string
	state               string
	acknowledged        bool
	obfuscatedAccountId string
	linkedPurchaseToken string
	autoRenew           bool
	test                bool
}

// One voided purchase, as voidedpurchases lists it.
type fakePlayVoided struct {
	token       string
	orderId     string
	productType int
	purchase    time.Time
	voided      time.Time
}

// See the file header.
type FakePlay struct {
	settings      *FakeStoresSettings
	play          *FakePlaySettings
	seed          string
	clock         sidecar.Clock
	accessToken   string
	googleKey     *ecdsa.PrivateKey
	server        *httptest.Server
	notifications *FakeStoreNotifications

	stateLock     sync.Mutex
	idCount       uint64
	products      []*fakePlayProduct
	subscriptions []*fakePlaySubscription
	voided        []*fakePlayVoided
	refunded      map[string]bool
	idTokens      map[string]map[string]any
	consumeCount  int
}

func newFakePlay(settings *FakeStoresSettings, seed string, clock sidecar.Clock) (*FakePlay, error) {
	googleKey, err := fakeP256Key(seed, "play id token")
	if err != nil {
		return nil, err
	}
	self := &FakePlay{
		settings:      settings,
		play:          settings.Play,
		seed:          seed,
		clock:         clock,
		accessToken:   "ya29.computetest-" + fmt.Sprintf("%x", fakeBytes(seed, "play access token", 16)),
		googleKey:     googleKey,
		notifications: newFakeStoreNotifications(settings, clock),
		refunded:      map[string]bool{},
		idTokens:      map[string]map[string]any{},
	}
	mux := http.NewServeMux()
	base := "/androidpublisher/v3/applications/{package}/"
	mux.HandleFunc("GET "+base+"purchases/products/{product}/tokens/{token}", self.authorized(self.serveProductGet))
	mux.HandleFunc("POST "+base+"purchases/products/{product}/tokens/{tokenVerb}", self.authorized(self.serveProductVerb))
	mux.HandleFunc("GET "+base+"purchases/subscriptionsv2/tokens/{token}", self.authorized(self.serveSubscriptionGet))
	mux.HandleFunc("POST "+base+"purchases/subscriptions/{product}/tokens/{tokenVerb}", self.authorized(self.serveSubscriptionVerb))
	mux.HandleFunc("GET "+base+"purchases/voidedpurchases", self.authorized(self.serveVoided))
	mux.HandleFunc("POST "+base+"orders/{orderVerb}", self.authorized(self.serveOrderRefund))
	mux.HandleFunc("GET /tokeninfo", self.serveTokenInfo)
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writeFakePlayError(writer, http.StatusNotFound, "NOT_FOUND", "The fake Play serves no such request.")
	})
	self.server = newFakeStoreServer(mux)
	return self, nil
}

// Ends the server.
func (self *FakePlay) Close() {
	self.server.Close()
}

// The API's base URL, which server's playPublisherApiBaseUrl takes.
func (self *FakePlay) Url() string {
	return self.server.URL
}

// The tokeninfo endpoint's URL, which server's playIdTokenClaims reads instead of Google's.
func (self *FakePlay) TokenInfoUrl() string {
	return self.server.URL + "/tokeninfo"
}

// The test's access token every API request must carry as its bearer.
func (self *FakePlay) AccessToken() string {
	return self.accessToken
}

// The pushes made, waiting for the test to deliver them.
func (self *FakePlay) Notifications() *FakeStoreNotifications {
	return self.notifications
}

// How many consumes Play took.
func (self *FakePlay) ConsumeCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.consumeCount
}

// A Google API error.
func writeFakePlayError(writer http.ResponseWriter, status int, statusText string, message string) {
	body, _ := json.Marshal(map[string]any{"error": map[string]any{"code": status, "message": message, "status": statusText}})
	writeFakeStoreJson(writer, status, body)
}

// An API handler behind the access token, for the fake's package alone.
func (self *FakePlay) authorized(serve func(writer http.ResponseWriter, request *http.Request)) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+self.accessToken {
			writeFakePlayError(writer, http.StatusUnauthorized, "UNAUTHENTICATED", "Request had invalid authentication credentials.")
			return
		}
		if request.PathValue("package") != self.play.PackageName {
			writeFakePlayError(writer, http.StatusNotFound, "NOT_FOUND", "No application was found for the given package name.")
			return
		}
		serve(writer, request)
	}
}

// A new synthetic id of kind, in order. Called with the lock.
func (self *FakePlay) newIdWithLock(kind string) uint64 {
	self.idCount += 1
	return binary.BigEndian.Uint64(fakeBytes(self.seed, fmt.Sprintf("play id %s %d", kind, self.idCount), 8))
}

// A new purchase token. Called with the lock.
func (self *FakePlay) newTokenWithLock() string {
	return fmt.Sprintf("computetest-token.%016x%016x", self.newIdWithLock("token"), self.newIdWithLock("token tail"))
}

// A new order id in Play's form, GPA.3xxx-xxxx-xxxx-xxxxx. Called with the lock.
func (self *FakePlay) newOrderIdWithLock() string {
	digits := fmt.Sprintf("%020d", self.newIdWithLock("order"))
	return "GPA.3" + digits[1:4] + "-" + digits[4:8] + "-" + digits[8:12] + "-" + digits[12:17]
}

// Queues one RTDN over notification, a DeveloperNotification's one-of field set by the caller. Called with the lock.
func (self *FakePlay) pushWithLock(kind string, notificationType int, notification map[string]any) error {
	now := self.clock.Now()
	developer := map[string]any{
		"version":         "1.0",
		"packageName":     self.play.PackageName,
		"eventTimeMillis": strconv.FormatInt(now.UnixMilli(), 10),
	}
	for name, value := range notification {
		developer[name] = value
	}
	data, err := json.Marshal(developer)
	if err != nil {
		return err
	}
	messageId := strconv.FormatUint(self.newIdWithLock("message")%1000000000000000, 10)
	body, err := json.Marshal(map[string]any{
		"message": map[string]any{
			"data":         base64.StdEncoding.EncodeToString(data),
			"messageId":    messageId,
			"message_id":   messageId,
			"publishTime":  now.UTC().Format(time.RFC3339Nano),
			"publish_time": now.UTC().Format(time.RFC3339Nano),
			"attributes":   map[string]string{},
		},
		"subscription": self.play.PubsubSubscription,
	})
	if err != nil {
		return err
	}
	idToken, err := self.idTokenWithLock(now)
	if err != nil {
		return err
	}
	self.notifications.add(&FakeStoreNotification{
		Id:   messageId,
		Type: fmt.Sprintf("%s.%d", kind, notificationType),
		Time: now,
		Body: body,
		Header: http.Header{
			"Content-Type":  []string{"application/json"},
			"Authorization": []string{"Bearer " + idToken},
		},
	})
	return nil
}

// A push's id token: a Google-shaped JWT for the publisher's service account and the push's audience, kept for
// tokeninfo. Called with the lock.
func (self *FakePlay) idTokenWithLock(now time.Time) (string, error) {
	claims := map[string]any{
		"iss":            FakePlayIdTokenIssuer,
		"aud":            self.play.Audience,
		"azp":            self.play.PublisherEmail,
		"email":          self.play.PublisherEmail,
		"email_verified": true,
		"sub":            strconv.FormatUint(self.newIdWithLock("subject")%1000000000000000000, 10),
		"iat":            now.Unix(),
		"exp":            now.Add(self.play.IdTokenLife).Unix(),
	}
	token, err := fakeJwsSign(self.googleKey, map[string]any{"typ": "JWT", "kid": fmt.Sprintf("%x", fakeBytes(self.seed, "play kid", 8))}, claims)
	if err != nil {
		return "", err
	}
	self.idTokens[token] = claims
	return token, nil
}

// GET /tokeninfo?id_token=: the claims of a token the fake issued, live by the fake's clock, every value a string as
// Google's endpoint writes them; 400 invalid_token for any other.
func (self *FakePlay) serveTokenInfo(writer http.ResponseWriter, request *http.Request) {
	token := request.URL.Query().Get("id_token")
	self.stateLock.Lock()
	claims, ok := self.idTokens[token]
	self.stateLock.Unlock()
	if !ok || claims["exp"].(int64) <= self.clock.Now().Unix() {
		body, _ := json.Marshal(map[string]string{"error": "invalid_token", "error_description": "Invalid Value"})
		writeFakeStoreJson(writer, http.StatusBadRequest, body)
		return
	}
	answer := map[string]string{"alg": "ES256", "typ": "JWT"}
	for name, value := range claims {
		answer[name] = fmt.Sprint(value)
	}
	body, _ := json.Marshal(answer)
	writeFakeStoreJson(writer, http.StatusOK, body)
}

// A one-time purchase the person makes.
type FakePlayPurchase struct {
	ProductId string
	// What the app set at purchase: the network's id; empty for none.
	ObfuscatedAccountId string
	// A license tester's purchase: purchaseType 0, and testPurchase on a subscription.
	Test bool
	// A subscription's base plan.
	BasePlanId string
}

// The person buys a consumable: its token and order id, unconsumed and unacknowledged, and ONE_TIME_PRODUCT_PURCHASED
// queued. Answers the purchase token.
func (self *FakePlay) BuyConsumable(purchase *FakePlayPurchase) (string, error) {
	if purchase == nil || purchase.ProductId == "" {
		return "", fmt.Errorf("%w: a purchase names its product", ErrFakeStoreState)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	product := &fakePlayProduct{
		token:               self.newTokenWithLock(),
		productId:           purchase.ProductId,
		orderId:             self.newOrderIdWithLock(),
		purchaseTime:        self.clock.Now(),
		obfuscatedAccountId: purchase.ObfuscatedAccountId,
		test:                purchase.Test,
	}
	self.products = append(self.products, product)
	return product.token, self.pushWithLock("oneTimeProductNotification", FakePlayOneTimePurchased, map[string]any{
		"oneTimeProductNotification": map[string]any{"version": "1.0", "notificationType": FakePlayOneTimePurchased, "purchaseToken": product.token, "sku": product.productId},
	})
}

// The product purchase token names, nil for none. Called with the lock.
func (self *FakePlay) productWithLock(token string) *fakePlayProduct {
	for _, product := range self.products {
		if product.token == token {
			return product
		}
	}
	return nil
}

// The subscription token names, nil for none. Called with the lock.
func (self *FakePlay) subscriptionWithLock(token string) *fakePlaySubscription {
	for _, subscription := range self.subscriptions {
		if subscription.token == token {
			return subscription
		}
	}
	return nil
}

func (self *FakePlay) serveProductGet(writer http.ResponseWriter, request *http.Request) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	product := self.productWithLock(request.PathValue("token"))
	if product == nil || product.productId != request.PathValue("product") {
		writeFakePlayError(writer, http.StatusNotFound, "NOT_FOUND", "The purchase token was not found.")
		return
	}
	answer := map[string]any{
		"kind":                 "androidpublisher#productPurchase",
		"purchaseTimeMillis":   strconv.FormatInt(product.purchaseTime.UnixMilli(), 10),
		"purchaseState":        product.purchaseState,
		"consumptionState":     product.consumptionState,
		"orderId":              product.orderId,
		"acknowledgementState": product.acknowledgementState,
		"purchaseToken":        product.token,
		"productId":            product.productId,
		"quantity":             1,
		"regionCode":           self.play.RegionCode,
	}
	if product.obfuscatedAccountId != "" {
		answer["obfuscatedExternalAccountId"] = product.obfuscatedAccountId
	}
	if product.test {
		answer["purchaseType"] = 0
	}
	body, _ := json.Marshal(answer)
	writeFakeStoreJson(writer, http.StatusOK, body)
}

// POST …/purchases/products/{product}/tokens/{token}:consume or :acknowledge.
func (self *FakePlay) serveProductVerb(writer http.ResponseWriter, request *http.Request) {
	token, verb, ok := strings.Cut(request.PathValue("tokenVerb"), ":")
	if !ok || (verb != "consume" && verb != "acknowledge") {
		writeFakePlayError(writer, http.StatusNotFound, "NOT_FOUND", "No such method.")
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	product := self.productWithLock(token)
	if product == nil || product.productId != request.PathValue("product") || product.voided {
		writeFakePlayError(writer, http.StatusGone, "NOT_FOUND", "The purchase is no longer available.")
		return
	}
	switch verb {
	case "consume":
		if product.consumptionState == 1 {
			writeFakePlayError(writer, http.StatusBadRequest, "FAILED_PRECONDITION", "The product purchase is already consumed.")
			return
		}
		product.consumptionState = 1
		self.consumeCount += 1
	case "acknowledge":
		product.acknowledgementState = 1
	}
	writeFakeStoreJson(writer, http.StatusOK, []byte("{}"))
}

// The person subscribes: a token, its first order id, active and unacknowledged, and SUBSCRIPTION_PURCHASED queued.
// Answers the purchase token.
func (self *FakePlay) Subscribe(purchase *FakePlayPurchase) (string, error) {
	if purchase == nil || purchase.ProductId == "" || purchase.BasePlanId == "" {
		return "", fmt.Errorf("%w: a subscription names its product and base plan", ErrFakeStoreState)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.subscribeWithLock(purchase, "")
}

// A subscription made, replacing linked where it names one. Called with the lock.
func (self *FakePlay) subscribeWithLock(purchase *FakePlayPurchase, linked string) (string, error) {
	now := self.clock.Now()
	orderId := self.newOrderIdWithLock()
	subscription := &fakePlaySubscription{
		token:               self.newTokenWithLock(),
		productId:           purchase.ProductId,
		basePlanId:          purchase.BasePlanId,
		startTime:           now,
		expiryTime:          now.AddDate(0, self.play.SubscriptionPeriodMonths, 0),
		baseOrderId:         orderId,
		latestOrderId:       orderId,
		state:               "SUBSCRIPTION_STATE_ACTIVE",
		obfuscatedAccountId: purchase.ObfuscatedAccountId,
		linkedPurchaseToken: linked,
		autoRenew:           true,
		test:                purchase.Test,
	}
	self.subscriptions = append(self.subscriptions, subscription)
	return subscription.token, self.pushWithLock("subscriptionNotification", FakePlaySubscriptionPurchased, map[string]any{
		"subscriptionNotification": map[string]any{"version": "1.0", "notificationType": FakePlaySubscriptionPurchased, "purchaseToken": subscription.token, "subscriptionId": subscription.productId},
	})
}

// The subscription renews: its token kept, a new order id (the first order's with ..0, ..1, …), its expiry a period
// on, and SUBSCRIPTION_RENEWED queued. Answers the new order id.
func (self *FakePlay) Renew(token string) (string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	subscription := self.subscriptionWithLock(token)
	if subscription == nil {
		return "", ErrFakeStoreUnknown
	}
	if subscription.state != "SUBSCRIPTION_STATE_ACTIVE" || !subscription.autoRenew {
		return "", fmt.Errorf("%w: the subscription is %s", ErrFakeStoreState, subscription.state)
	}
	subscription.latestOrderId = fmt.Sprintf("%s..%d", subscription.baseOrderId, subscription.renewalCount)
	subscription.renewalCount += 1
	subscription.expiryTime = subscription.expiryTime.AddDate(0, self.play.SubscriptionPeriodMonths, 0)
	return subscription.latestOrderId, self.pushWithLock("subscriptionNotification", FakePlaySubscriptionRenewed, map[string]any{
		"subscriptionNotification": map[string]any{"version": "1.0", "notificationType": FakePlaySubscriptionRenewed, "purchaseToken": subscription.token, "subscriptionId": subscription.productId},
	})
}

// The person replaces token's plan with purchase's, at once: a new token whose linkedPurchaseToken names the old, the
// old expired, SUBSCRIPTION_EXPIRED for the old and SUBSCRIPTION_PURCHASED for the new queued. Answers the new token.
func (self *FakePlay) Replace(token string, purchase *FakePlayPurchase) (string, error) {
	if purchase == nil || purchase.ProductId == "" || purchase.BasePlanId == "" {
		return "", fmt.Errorf("%w: a replacement names its product and base plan", ErrFakeStoreState)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	old := self.subscriptionWithLock(token)
	if old == nil {
		return "", ErrFakeStoreUnknown
	}
	if old.state != "SUBSCRIPTION_STATE_ACTIVE" {
		return "", fmt.Errorf("%w: the subscription is %s", ErrFakeStoreState, old.state)
	}
	old.state = "SUBSCRIPTION_STATE_EXPIRED"
	old.autoRenew = false
	if err := self.pushWithLock("subscriptionNotification", FakePlaySubscriptionExpired, map[string]any{
		"subscriptionNotification": map[string]any{"version": "1.0", "notificationType": FakePlaySubscriptionExpired, "purchaseToken": old.token, "subscriptionId": old.productId},
	}); err != nil {
		return "", err
	}
	replacement := *purchase
	if replacement.ObfuscatedAccountId == "" {
		replacement.ObfuscatedAccountId = old.obfuscatedAccountId
	}
	return self.subscribeWithLock(&replacement, old.token)
}

// The subscription's newest order id, empty for none.
func (self *FakePlay) LatestOrderId(token string) string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if subscription := self.subscriptionWithLock(token); subscription != nil {
		return subscription.latestOrderId
	}
	return ""
}

func (self *FakePlay) serveSubscriptionGet(writer http.ResponseWriter, request *http.Request) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	subscription := self.subscriptionWithLock(request.PathValue("token"))
	if subscription == nil {
		writeFakePlayError(writer, http.StatusNotFound, "NOT_FOUND", "The purchase token was not found.")
		return
	}
	acknowledgement := "ACKNOWLEDGEMENT_STATE_PENDING"
	if subscription.acknowledged {
		acknowledgement = "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED"
	}
	answer := map[string]any{
		"kind":                 "androidpublisher#subscriptionPurchaseV2",
		"regionCode":           self.play.RegionCode,
		"startTime":            subscription.startTime.UTC().Format(time.RFC3339Nano),
		"subscriptionState":    subscription.state,
		"latestOrderId":        subscription.latestOrderId,
		"acknowledgementState": acknowledgement,
		"lineItems": []any{map[string]any{
			"productId":               subscription.productId,
			"expiryTime":              subscription.expiryTime.UTC().Format(time.RFC3339Nano),
			"latestSuccessfulOrderId": subscription.latestOrderId,
			"autoRenewingPlan":        map[string]any{"autoRenewEnabled": subscription.autoRenew},
			"offerDetails":            map[string]any{"basePlanId": subscription.basePlanId},
		}},
	}
	if subscription.obfuscatedAccountId != "" {
		answer["externalAccountIdentifiers"] = map[string]any{"obfuscatedExternalAccountId": subscription.obfuscatedAccountId}
	}
	if subscription.linkedPurchaseToken != "" {
		answer["linkedPurchaseToken"] = subscription.linkedPurchaseToken
	}
	if subscription.test {
		answer["testPurchase"] = map[string]any{}
	}
	body, _ := json.Marshal(answer)
	writeFakeStoreJson(writer, http.StatusOK, body)
}

// POST …/purchases/subscriptions/{product}/tokens/{token}:acknowledge.
func (self *FakePlay) serveSubscriptionVerb(writer http.ResponseWriter, request *http.Request) {
	token, verb, ok := strings.Cut(request.PathValue("tokenVerb"), ":")
	if !ok || verb != "acknowledge" {
		writeFakePlayError(writer, http.StatusNotFound, "NOT_FOUND", "No such method.")
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	subscription := self.subscriptionWithLock(token)
	if subscription == nil || subscription.productId != request.PathValue("product") {
		writeFakePlayError(writer, http.StatusNotFound, "NOT_FOUND", "The purchase token was not found.")
		return
	}
	subscription.acknowledged = true
	writeFakeStoreJson(writer, http.StatusOK, []byte("{}"))
}

// Voids one purchase: listed in voidedpurchases and voidedPurchaseNotification queued. Called with the lock.
func (self *FakePlay) voidWithLock(token string, orderId string, productType int, purchaseTime time.Time) error {
	self.voided = append(self.voided, &fakePlayVoided{token: token, orderId: orderId, productType: productType, purchase: purchaseTime, voided: self.clock.Now()})
	// refundType 1, a full refund
	return self.pushWithLock("voidedPurchaseNotification", productType, map[string]any{
		"voidedPurchaseNotification": map[string]any{"purchaseToken": token, "orderId": orderId, "productType": productType, "refundType": 1},
	})
}

// Play refunds a purchase: a consumable by its token, or a subscription's newest order by its token, which is revoked
// (SUBSCRIPTION_REVOKED queued beside the void).
func (self *FakePlay) Void(token string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if product := self.productWithLock(token); product != nil {
		if product.voided {
			return fmt.Errorf("%w: voided already", ErrFakeStoreState)
		}
		product.voided = true
		return self.voidWithLock(product.token, product.orderId, FakePlayVoidedOneTimeType, product.purchaseTime)
	}
	subscription := self.subscriptionWithLock(token)
	if subscription == nil {
		return ErrFakeStoreUnknown
	}
	subscription.state = "SUBSCRIPTION_STATE_EXPIRED"
	subscription.autoRenew = false
	if err := self.pushWithLock("subscriptionNotification", FakePlaySubscriptionRevoked, map[string]any{
		"subscriptionNotification": map[string]any{"version": "1.0", "notificationType": FakePlaySubscriptionRevoked, "purchaseToken": subscription.token, "subscriptionId": subscription.productId},
	}); err != nil {
		return err
	}
	return self.voidWithLock(subscription.token, subscription.latestOrderId, FakePlayVoidedSubscriptionType, subscription.startTime)
}

// What Play does at the acknowledge window: every one-time purchase neither consumed nor acknowledged within
// AcknowledgeWindow of its purchase, by the fake's clock now, is refunded and voided. Answers the tokens voided.
func (self *FakePlay) VoidUnacknowledged() ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	now := self.clock.Now()
	voided := []string{}
	for _, product := range self.products {
		if product.voided || product.consumptionState == 1 || product.acknowledgementState == 1 {
			continue
		}
		if now.Sub(product.purchaseTime) < self.play.AcknowledgeWindow {
			continue
		}
		product.voided = true
		if err := self.voidWithLock(product.token, product.orderId, FakePlayVoidedOneTimeType, product.purchaseTime); err != nil {
			return voided, err
		}
		voided = append(voided, product.token)
	}
	return voided, nil
}

func (self *FakePlay) serveVoided(writer http.ResponseWriter, request *http.Request) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	listed := []any{}
	for _, voided := range self.voided {
		listed = append(listed, map[string]any{
			"kind":               "androidpublisher#voidedPurchase",
			"purchaseToken":      voided.token,
			"orderId":            voided.orderId,
			"purchaseTimeMillis": strconv.FormatInt(voided.purchase.UnixMilli(), 10),
			"voidedTimeMillis":   strconv.FormatInt(voided.voided.UnixMilli(), 10),
			"voidedSource":       1,
			"voidedReason":       0,
		})
	}
	body, _ := json.Marshal(map[string]any{"voidedPurchases": listed})
	writeFakeStoreJson(writer, http.StatusOK, body)
}

// POST …/orders/{orderId}:refund: refunds the order once, a second refund refused.
func (self *FakePlay) serveOrderRefund(writer http.ResponseWriter, request *http.Request) {
	orderId, verb, ok := strings.Cut(request.PathValue("orderVerb"), ":")
	if !ok || verb != "refund" {
		writeFakePlayError(writer, http.StatusNotFound, "NOT_FOUND", "No such method.")
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	known := false
	for _, product := range self.products {
		known = known || product.orderId == orderId
	}
	for _, subscription := range self.subscriptions {
		known = known || subscription.baseOrderId == orderId || subscription.latestOrderId == orderId || strings.HasPrefix(orderId, subscription.baseOrderId+"..")
	}
	if !known {
		writeFakePlayError(writer, http.StatusNotFound, "NOT_FOUND", "The order was not found.")
		return
	}
	if self.refunded[orderId] {
		writeFakePlayError(writer, http.StatusBadRequest, "FAILED_PRECONDITION", "The order is already refunded.")
		return
	}
	self.refunded[orderId] = true
	writeFakeStoreJson(writer, http.StatusOK, []byte("{}"))
}

// Whether orderId was refunded through the orders API.
func (self *FakePlay) Refunded(orderId string) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.refunded[orderId]
}

// The DeveloperNotification a push carries, decoded from its body.
func FakePlayDeveloperNotification(body []byte) (map[string]any, error) {
	push := struct {
		Message struct {
			Data string `json:"data"`
		} `json:"message"`
	}{}
	if err := json.Unmarshal(body, &push); err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.DecodeString(push.Message.Data)
	if err != nil {
		return nil, err
	}
	notification := map[string]any{}
	if err := json.Unmarshal(data, &notification); err != nil {
		return nil, err
	}
	if notification["packageName"] == nil {
		return nil, errors.New("computetest: a push with no package")
	}
	return notification, nil
}
