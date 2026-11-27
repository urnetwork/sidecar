// computetest.FakeAppStore (CTEST-M12-02; DESIGN-COMPUTE §9.5, §9.11, §9.12, D-BAL-8): the App Store as BAL's
// server code reads it, every signed object a compact JWS, ES256 over P-256, whose x5c header holds a three-certificate
// chain under a test root (RootCertificate): the leaf carrying Apple's notification-signing policy extension
// (1.2.840.113635.100.6.11.1) and the intermediate Apple's WWDR one (1.2.840.113635.100.6.2.1), as server's verifier
// (api/handlers/apple_notification_verifier.go) demands. The test root goes into server's pinned roots through its own
// test seam (apple_root_store.go's newAppleRootStore), never a production root.
//
//	purchases     BuyConsumable, Subscribe, Renew, Upgrade (at once, the old transaction marked upgraded),
//	              Downgrade (at the next renewal), Refund: each a transaction the app's StoreKit holds signed
//	              (SignedTransaction, Transaction.jwsRepresentation, the app's report), and the Server Notification V2
//	              the store sends (ONE_TIME_CHARGE, SUBSCRIBED, DID_RENEW, DID_CHANGE_RENEWAL_PREF, REFUND), queued in
//	              Notifications() until the test delivers it as {"signedPayload": …}
//	the app       a transaction stays unfinished until the app calls finish() (Finish), and the app reports each
//	              unfinished transaction again at its next launch (Unfinished)
//	Server API    GET /inApps/v1/transactions/{id}, GET /inApps/v2/history/{id} (by productType and sort, in pages
//	              by revision) and GET /inApps/v1/subscriptions/{id}, each under a bearer JWT the test's in-app
//	              purchase key signs (ApiKeyPem, ApiKeyId, IssuerId): ES256, kid, iss, aud appstoreconnect-v1, bid,
//	              exp, else 401
//
// Each transaction's appAccountToken is what the app set (the network's id), its appTransactionId one per payer label
// (one Apple Account in the app, §9.11's payer), and its ids synthetic. Every signature is RFC 6979's, so one seed and
// one clock make the same bytes.
//
// Safe for concurrent use: one lock guards the state; the server's I/O runs outside it.

package computetest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// The policy extensions Apple's notification chain carries, which server's verifier demands.
var (
	FakeAppleLeafPolicyOid         = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 11, 1}
	FakeAppleIntermediatePolicyOid = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 1}
)

// The fake App Store's settings (QD-702).
type FakeAppStoreSettings struct {
	// The app every transaction and notification names: synthetic.
	BundleId   string
	AppAppleId int64
	// "Production" or "Sandbox", as Apple writes it.
	Environment string
	// A subscription's period, in months: Apple's monthly plans.
	SubscriptionPeriodMonths int
	// The transactions one history page holds: 20, the Server API's.
	HistoryPageCount int
	// How long a Server API bearer may live: Apple refuses one whose exp is more than 60 minutes after its iat.
	BearerMaxLife time.Duration
	// The storefront a purchase is made in.
	Storefront   string
	StorefrontId string
	Currency     string
}

// The defaults, the only place one is set.
func DefaultFakeAppStoreSettings() *FakeAppStoreSettings {
	return &FakeAppStoreSettings{
		BundleId:                 "com.example.urnetwork",
		AppAppleId:               1000000001,
		Environment:              "Production",
		SubscriptionPeriodMonths: 1,
		HistoryPageCount:         20,
		BearerMaxLife:            60 * time.Minute,
		Storefront:               "USA",
		StorefrontId:             "143441",
		Currency:                 "USD",
	}
}

// The transaction types Apple writes: identifiers.
const (
	FakeAppleTypeConsumable   = "Consumable"
	FakeAppleTypeAutoRenewing = "Auto-Renewable Subscription"
)

// A purchase the person makes in the app.
type FakeApplePurchase struct {
	ProductId string
	// The subscription group, for a subscription.
	SubscriptionGroupId string
	// What the app set: the network's id as a UUID string; empty for none, as an offer code redeemed in the store.
	AppAccountToken string
	// The Apple Account in the app that pays, by label: its appTransactionId is one per label.
	Payer string
	// The price in milliunits of the storefront's currency, as Apple writes it: 9990 for 9.99.
	Price int64
}

// One transaction as the store holds it; the claims of its signed payload.
type FakeAppleTransaction struct {
	TransactionId         string
	OriginalTransactionId string
	WebOrderLineItemId    string
	ProductId             string
	SubscriptionGroupId   string
	Type                  string
	PurchaseDate          time.Time
	OriginalPurchaseDate  time.Time
	// The zero time for a consumable.
	ExpiresDate       time.Time
	AppAccountToken   string
	AppTransactionId  string
	TransactionReason string
	Price             int64
	IsUpgraded        bool
	RevocationDate    time.Time
	RevocationReason  int
	Finished          bool
	ownershipType     string
}

// A subscription's renewal state, by its original transaction.
type fakeAppleRenewal struct {
	originalTransactionId string
	productId             string
	autoRenewProductId    string
	autoRenewStatus       int
	appAccountToken       string
	appTransactionId      string
	renewalDate           time.Time
	startDate             time.Time
}

// See the file header.
type FakeAppStore struct {
	settings      *FakeStoresSettings
	apple         *FakeAppStoreSettings
	seed          string
	clock         sidecar.Clock
	root          *x509.Certificate
	intermediate  *x509.Certificate
	leaf          *x509.Certificate
	leafKey       *ecdsa.PrivateKey
	apiKey        *ecdsa.PrivateKey
	apiKeyId      string
	issuerId      string
	server        *httptest.Server
	notifications *FakeStoreNotifications

	stateLock    sync.Mutex
	idCount      uint64
	transactions []*FakeAppleTransaction
	renewals     map[string]*fakeAppleRenewal
}

// A certificate signed by signer's key, or self-signed where parent is nil.
func fakeAppleCertificate(seed string, label string, serial int64, subject string, key *ecdsa.PrivateKey, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, ca bool, policy asn1.ObjectIdentifier) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: subject, Organization: []string{"computetest"}},
		NotBefore:             time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC),
		BasicConstraintsValid: true,
		IsCA:                  ca,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if ca {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	if policy != nil {
		// Apple's policy extensions hold an ASN.1 NULL
		template.ExtraExtensions = []pkix.Extension{{Id: policy, Value: []byte{0x05, 0x00}}}
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(newFakeStream(seed, "apple certificate "+label), template, parent, key.Public(), parentKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func newFakeAppStore(settings *FakeStoresSettings, seed string, clock sidecar.Clock) (*FakeAppStore, error) {
	rootKey, err := fakeP256Key(seed, "apple root")
	if err != nil {
		return nil, err
	}
	intermediateKey, err := fakeP256Key(seed, "apple intermediate")
	if err != nil {
		return nil, err
	}
	leafKey, err := fakeP256Key(seed, "apple leaf")
	if err != nil {
		return nil, err
	}
	apiKey, err := fakeP256Key(seed, "apple api key")
	if err != nil {
		return nil, err
	}
	root, err := fakeAppleCertificate(seed, "root", 1, "computetest App Store test root "+seed, rootKey, nil, nil, true, nil)
	if err != nil {
		return nil, err
	}
	intermediate, err := fakeAppleCertificate(seed, "intermediate", 2, "computetest App Store test intermediate", intermediateKey, root, rootKey, true, FakeAppleIntermediatePolicyOid)
	if err != nil {
		return nil, err
	}
	leaf, err := fakeAppleCertificate(seed, "leaf", 3, "computetest App Store test signing", leafKey, intermediate, intermediateKey, false, FakeAppleLeafPolicyOid)
	if err != nil {
		return nil, err
	}
	self := &FakeAppStore{
		settings:      settings,
		apple:         settings.AppStore,
		seed:          seed,
		clock:         clock,
		root:          root,
		intermediate:  intermediate,
		leaf:          leaf,
		leafKey:       leafKey,
		apiKey:        apiKey,
		apiKeyId:      strings.ToUpper(fmt.Sprintf("%x", fakeBytes(seed, "apple api key id", 5))),
		issuerId:      sidecarIdOf(fakeBytes(seed, "apple issuer id", 16)).String(),
		notifications: newFakeStoreNotifications(settings, clock),
		renewals:      map[string]*fakeAppleRenewal{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /inApps/v1/transactions/{id}", self.authorized(self.serveTransaction))
	mux.HandleFunc("GET /inApps/v2/history/{id}", self.authorized(self.serveHistory))
	mux.HandleFunc("GET /inApps/v1/subscriptions/{id}", self.authorized(self.serveSubscriptions))
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writeFakeAppleError(writer, http.StatusNotFound, 4040000, "The fake App Store serves no such request.")
	})
	self.server = newFakeStoreServer(mux)
	return self, nil
}

// An Id of 16 bytes.
func sidecarIdOf(raw []byte) sidecar.Id {
	id := sidecar.Id{}
	copy(id[:], raw)
	return id
}

// Ends the server.
func (self *FakeAppStore) Close() {
	self.server.Close()
}

// The Server API's base URL, the production or the sandbox base a test points server at.
func (self *FakeAppStore) Url() string {
	return self.server.URL
}

// The test root, which a test pins in server's root store and nowhere else.
func (self *FakeAppStore) RootCertificate() *x509.Certificate {
	return self.root
}

// The test root as PEM, as apple_roots.pem holds Apple's.
func (self *FakeAppStore) RootPem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: self.root.Raw})
}

// The in-app purchase key a Server API bearer is signed with, as a .p8 holds one (PKCS #8, PEM).
func (self *FakeAppStore) ApiKeyPem() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(self.apiKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// The key's id, a bearer's kid.
func (self *FakeAppStore) ApiKeyId() string {
	return self.apiKeyId
}

// The issuer, a bearer's iss.
func (self *FakeAppStore) IssuerId() string {
	return self.issuerId
}

// The notifications made, waiting for the test to deliver them.
func (self *FakeAppStore) Notifications() *FakeStoreNotifications {
	return self.notifications
}

// A compact JWS, ES256, of payload under key, its header's fields beside alg. The signature is RFC 6979's, so the same
// key and payload make the same bytes.
func fakeJwsSign(key *ecdsa.PrivateKey, header map[string]any, payload any) (string, error) {
	fullHeader := map[string]any{"alg": "ES256"}
	for name, value := range header {
		fullHeader[name] = value
	}
	headerJson, err := json.Marshal(fullHeader)
	if err != nil {
		return "", err
	}
	payloadJson, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(headerJson) + "." + base64.RawURLEncoding.EncodeToString(payloadJson)
	digest := sha256.Sum256([]byte(input))
	// a nil reader signs by RFC 6979
	der, err := key.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	signature := struct {
		R, S *big.Int
	}{}
	if _, err := asn1.Unmarshal(der, &signature); err != nil {
		return "", err
	}
	raw := make([]byte, 64)
	signature.R.FillBytes(raw[:32])
	signature.S.FillBytes(raw[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(raw), nil
}

// Verifies a compact JWS's ES256 signature under key and answers its header and payload. No claim is judged.
func fakeJwsVerify(jws string, key *ecdsa.PublicKey) (map[string]any, []byte, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("computetest: not a compact JWS")
	}
	headerJson, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, err
	}
	header := map[string]any{}
	if err := json.Unmarshal(headerJson, &header); err != nil {
		return nil, nil, err
	}
	if header["alg"] != "ES256" {
		return nil, nil, errors.New("computetest: not ES256")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != 64 {
		return nil, nil, errors.New("computetest: the signature does not read")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return nil, nil, errors.New("computetest: the signature does not verify")
	}
	return header, payload, nil
}

// A JWS of payload under the store's leaf, its x5c the chain.
func (self *FakeAppStore) sign(payload any) (string, error) {
	return fakeJwsSign(self.leafKey, map[string]any{"x5c": []string{
		base64.StdEncoding.EncodeToString(self.leaf.Raw),
		base64.StdEncoding.EncodeToString(self.intermediate.Raw),
		base64.StdEncoding.EncodeToString(self.root.Raw),
	}}, payload)
}

// A new decimal id, synthetic and in order. Called with the lock.
func (self *FakeAppStore) newIdWithLock(kind string) string {
	self.idCount += 1
	digits := binary.BigEndian.Uint64(fakeBytes(self.seed, fmt.Sprintf("apple id %s %d", kind, self.idCount), 8)) % 1000000000
	return fmt.Sprintf("20000%02d%09d", self.idCount%100, digits)
}

// The appTransactionId of payer: one per label.
func (self *FakeAppStore) appTransactionId(payer string) string {
	return fmt.Sprintf("70%016d", binary.BigEndian.Uint64(fakeBytes(self.seed, "apple payer "+payer, 8))%10000000000000000)
}

// The transaction's claims, as its signed payload holds them, signed now.
func (self *FakeAppStore) transactionClaims(transaction *FakeAppleTransaction, signedAt time.Time) map[string]any {
	claims := map[string]any{
		"transactionId":         transaction.TransactionId,
		"originalTransactionId": transaction.OriginalTransactionId,
		"bundleId":              self.apple.BundleId,
		"productId":             transaction.ProductId,
		"purchaseDate":          transaction.PurchaseDate.UnixMilli(),
		"originalPurchaseDate":  transaction.OriginalPurchaseDate.UnixMilli(),
		"quantity":              1,
		"type":                  transaction.Type,
		"inAppOwnershipType":    transaction.ownershipType,
		"signedDate":            signedAt.UnixMilli(),
		"environment":           self.apple.Environment,
		"transactionReason":     transaction.TransactionReason,
		"storefront":            self.apple.Storefront,
		"storefrontId":          self.apple.StorefrontId,
		"price":                 transaction.Price,
		"currency":              self.apple.Currency,
		"appTransactionId":      transaction.AppTransactionId,
	}
	if transaction.AppAccountToken != "" {
		claims["appAccountToken"] = transaction.AppAccountToken
	}
	if transaction.Type == FakeAppleTypeAutoRenewing {
		claims["webOrderLineItemId"] = transaction.WebOrderLineItemId
		claims["subscriptionGroupIdentifier"] = transaction.SubscriptionGroupId
		claims["expiresDate"] = transaction.ExpiresDate.UnixMilli()
	}
	if transaction.IsUpgraded {
		claims["isUpgraded"] = true
	}
	if !transaction.RevocationDate.IsZero() {
		claims["revocationDate"] = transaction.RevocationDate.UnixMilli()
		claims["revocationReason"] = transaction.RevocationReason
	}
	return claims
}

// A subscription's renewal claims, signed now.
func (self *FakeAppStore) renewalClaims(renewal *fakeAppleRenewal, signedAt time.Time) map[string]any {
	claims := map[string]any{
		"originalTransactionId":       renewal.originalTransactionId,
		"productId":                   renewal.productId,
		"autoRenewProductId":          renewal.autoRenewProductId,
		"autoRenewStatus":             renewal.autoRenewStatus,
		"signedDate":                  signedAt.UnixMilli(),
		"environment":                 self.apple.Environment,
		"recentSubscriptionStartDate": renewal.startDate.UnixMilli(),
		"renewalDate":                 renewal.renewalDate.UnixMilli(),
		"appTransactionId":            renewal.appTransactionId,
	}
	if renewal.appAccountToken != "" {
		claims["appAccountToken"] = renewal.appAccountToken
	}
	return claims
}

// The transaction id names, nil for none. Called with the lock.
func (self *FakeAppStore) transactionWithLock(transactionId string) *FakeAppleTransaction {
	for _, transaction := range self.transactions {
		if transaction.TransactionId == transactionId {
			return transaction
		}
	}
	return nil
}

// The newest transaction of a subscription, nil for none. Called with the lock.
func (self *FakeAppStore) latestWithLock(originalTransactionId string) *FakeAppleTransaction {
	var latest *FakeAppleTransaction
	for _, transaction := range self.transactions {
		if transaction.OriginalTransactionId == originalTransactionId {
			latest = transaction
		}
	}
	return latest
}

// Queues the notification of notificationType and subtype over transaction and, for a subscription, its renewal.
// Called with the lock.
func (self *FakeAppStore) notifyWithLock(notificationType string, subtype string, transaction *FakeAppleTransaction) error {
	now := self.clock.Now()
	data := map[string]any{
		"appAppleId":    self.apple.AppAppleId,
		"bundleId":      self.apple.BundleId,
		"bundleVersion": "1",
		"environment":   self.apple.Environment,
	}
	signedTransaction, err := self.sign(self.transactionClaims(transaction, now))
	if err != nil {
		return err
	}
	data["signedTransactionInfo"] = signedTransaction
	if renewal, ok := self.renewals[transaction.OriginalTransactionId]; ok {
		signedRenewal, err := self.sign(self.renewalClaims(renewal, now))
		if err != nil {
			return err
		}
		data["signedRenewalInfo"] = signedRenewal
		data["status"] = 1
	}
	self.idCount += 1
	uuid := sidecarIdOf(fakeBytes(self.seed, fmt.Sprintf("apple notification %d", self.idCount), 16)).String()
	payload := map[string]any{
		"notificationType": notificationType,
		"notificationUUID": uuid,
		"data":             data,
		"version":          "2.0",
		"signedDate":       now.UnixMilli(),
	}
	if subtype != "" {
		payload["subtype"] = subtype
	}
	signedPayload, err := self.sign(payload)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{"signedPayload": signedPayload})
	if err != nil {
		return err
	}
	notificationLabel := notificationType
	if subtype != "" {
		notificationLabel += "/" + subtype
	}
	self.notifications.add(&FakeStoreNotification{
		Id:     uuid,
		Type:   notificationLabel,
		Time:   now,
		Body:   body,
		Header: http.Header{"Content-Type": []string{"application/json"}},
	})
	return nil
}

// A copy of transaction for a caller.
func fakeAppleTransactionCopy(transaction *FakeAppleTransaction) *FakeAppleTransaction {
	copied := *transaction
	return &copied
}

// The person buys a consumable: its transaction, unfinished until the app's Finish, and ONE_TIME_CHARGE queued.
func (self *FakeAppStore) BuyConsumable(purchase *FakeApplePurchase) (*FakeAppleTransaction, error) {
	if purchase == nil || purchase.ProductId == "" || purchase.Payer == "" {
		return nil, fmt.Errorf("%w: a purchase names its product and payer", ErrFakeStoreState)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	now := self.clock.Now()
	transactionId := self.newIdWithLock("transaction")
	transaction := &FakeAppleTransaction{
		TransactionId:         transactionId,
		OriginalTransactionId: transactionId,
		ProductId:             purchase.ProductId,
		Type:                  FakeAppleTypeConsumable,
		PurchaseDate:          now,
		OriginalPurchaseDate:  now,
		AppAccountToken:       purchase.AppAccountToken,
		AppTransactionId:      self.appTransactionId(purchase.Payer),
		TransactionReason:     "PURCHASE",
		Price:                 purchase.Price,
		ownershipType:         "PURCHASED",
	}
	self.transactions = append(self.transactions, transaction)
	if err := self.notifyWithLock("ONE_TIME_CHARGE", "", transaction); err != nil {
		return nil, err
	}
	return fakeAppleTransactionCopy(transaction), nil
}

// The person subscribes: the first period's transaction and SUBSCRIBED/INITIAL_BUY queued.
func (self *FakeAppStore) Subscribe(purchase *FakeApplePurchase) (*FakeAppleTransaction, error) {
	if purchase == nil || purchase.ProductId == "" || purchase.Payer == "" || purchase.SubscriptionGroupId == "" {
		return nil, fmt.Errorf("%w: a subscription names its product, group and payer", ErrFakeStoreState)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	now := self.clock.Now()
	transactionId := self.newIdWithLock("transaction")
	transaction := &FakeAppleTransaction{
		TransactionId:         transactionId,
		OriginalTransactionId: transactionId,
		WebOrderLineItemId:    self.newIdWithLock("line"),
		ProductId:             purchase.ProductId,
		SubscriptionGroupId:   purchase.SubscriptionGroupId,
		Type:                  FakeAppleTypeAutoRenewing,
		PurchaseDate:          now,
		OriginalPurchaseDate:  now,
		ExpiresDate:           now.AddDate(0, self.apple.SubscriptionPeriodMonths, 0),
		AppAccountToken:       purchase.AppAccountToken,
		AppTransactionId:      self.appTransactionId(purchase.Payer),
		TransactionReason:     "PURCHASE",
		Price:                 purchase.Price,
		ownershipType:         "PURCHASED",
	}
	self.transactions = append(self.transactions, transaction)
	self.renewals[transactionId] = &fakeAppleRenewal{
		originalTransactionId: transactionId,
		productId:             purchase.ProductId,
		autoRenewProductId:    purchase.ProductId,
		autoRenewStatus:       1,
		appAccountToken:       purchase.AppAccountToken,
		appTransactionId:      transaction.AppTransactionId,
		renewalDate:           transaction.ExpiresDate,
		startDate:             now,
	}
	if err := self.notifyWithLock("SUBSCRIBED", "INITIAL_BUY", transaction); err != nil {
		return nil, err
	}
	return fakeAppleTransactionCopy(transaction), nil
}

// The subscription renews: a new transaction under the same original one, for the plan its renewal names (a
// downgrade takes effect here), from the last period's end, and DID_RENEW queued.
func (self *FakeAppStore) Renew(originalTransactionId string) (*FakeAppleTransaction, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	latest := self.latestWithLock(originalTransactionId)
	renewal, ok := self.renewals[originalTransactionId]
	if latest == nil || !ok {
		return nil, ErrFakeStoreUnknown
	}
	if renewal.autoRenewStatus != 1 {
		return nil, fmt.Errorf("%w: auto-renew is off", ErrFakeStoreState)
	}
	transaction := &FakeAppleTransaction{
		TransactionId:         self.newIdWithLock("transaction"),
		OriginalTransactionId: originalTransactionId,
		WebOrderLineItemId:    self.newIdWithLock("line"),
		ProductId:             renewal.autoRenewProductId,
		SubscriptionGroupId:   latest.SubscriptionGroupId,
		Type:                  FakeAppleTypeAutoRenewing,
		PurchaseDate:          latest.ExpiresDate,
		OriginalPurchaseDate:  latest.OriginalPurchaseDate,
		ExpiresDate:           latest.ExpiresDate.AddDate(0, self.apple.SubscriptionPeriodMonths, 0),
		AppAccountToken:       latest.AppAccountToken,
		AppTransactionId:      latest.AppTransactionId,
		TransactionReason:     "RENEWAL",
		Price:                 latest.Price,
		ownershipType:         "PURCHASED",
	}
	self.transactions = append(self.transactions, transaction)
	renewal.productId = transaction.ProductId
	renewal.renewalDate = transaction.ExpiresDate
	if err := self.notifyWithLock("DID_RENEW", "", transaction); err != nil {
		return nil, err
	}
	return fakeAppleTransactionCopy(transaction), nil
}

// The person upgrades to productId, which takes effect at once: the current period's transaction marked upgraded,
// a new one for the new plan from now, price as given, and DID_CHANGE_RENEWAL_PREF/UPGRADE queued.
func (self *FakeAppStore) Upgrade(originalTransactionId string, productId string, price int64) (*FakeAppleTransaction, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	latest := self.latestWithLock(originalTransactionId)
	renewal, ok := self.renewals[originalTransactionId]
	if latest == nil || !ok {
		return nil, ErrFakeStoreUnknown
	}
	now := self.clock.Now()
	latest.IsUpgraded = true
	transaction := &FakeAppleTransaction{
		TransactionId:         self.newIdWithLock("transaction"),
		OriginalTransactionId: originalTransactionId,
		WebOrderLineItemId:    self.newIdWithLock("line"),
		ProductId:             productId,
		SubscriptionGroupId:   latest.SubscriptionGroupId,
		Type:                  FakeAppleTypeAutoRenewing,
		PurchaseDate:          now,
		OriginalPurchaseDate:  latest.OriginalPurchaseDate,
		ExpiresDate:           now.AddDate(0, self.apple.SubscriptionPeriodMonths, 0),
		AppAccountToken:       latest.AppAccountToken,
		AppTransactionId:      latest.AppTransactionId,
		TransactionReason:     "PURCHASE",
		Price:                 price,
		ownershipType:         "PURCHASED",
	}
	self.transactions = append(self.transactions, transaction)
	renewal.productId, renewal.autoRenewProductId = productId, productId
	renewal.renewalDate = transaction.ExpiresDate
	if err := self.notifyWithLock("DID_CHANGE_RENEWAL_PREF", "UPGRADE", transaction); err != nil {
		return nil, err
	}
	return fakeAppleTransactionCopy(transaction), nil
}

// The person downgrades to productId, which takes effect at the next renewal: DID_CHANGE_RENEWAL_PREF/DOWNGRADE
// queued over the current period's transaction, no new one.
func (self *FakeAppStore) Downgrade(originalTransactionId string, productId string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	latest := self.latestWithLock(originalTransactionId)
	renewal, ok := self.renewals[originalTransactionId]
	if latest == nil || !ok {
		return ErrFakeStoreUnknown
	}
	renewal.autoRenewProductId = productId
	return self.notifyWithLock("DID_CHANGE_RENEWAL_PREF", "DOWNGRADE", latest)
}

// Apple refunds transactionId: its revocation date set, REFUND queued.
func (self *FakeAppStore) Refund(transactionId string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	transaction := self.transactionWithLock(transactionId)
	if transaction == nil {
		return ErrFakeStoreUnknown
	}
	if !transaction.RevocationDate.IsZero() {
		return fmt.Errorf("%w: refunded already", ErrFakeStoreState)
	}
	transaction.RevocationDate = self.clock.Now()
	// 0 for a refund for another reason, as Apple writes it
	transaction.RevocationReason = 0
	return self.notifyWithLock("REFUND", "", transaction)
}

// The app's StoreKit report of transactionId, Transaction.jwsRepresentation, signed now.
func (self *FakeAppStore) SignedTransaction(transactionId string) (string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	transaction := self.transactionWithLock(transactionId)
	if transaction == nil {
		return "", ErrFakeStoreUnknown
	}
	return self.sign(self.transactionClaims(transaction, self.clock.Now()))
}

// The app calls finish() on transactionId, as it does once the server answered credited.
func (self *FakeAppStore) Finish(transactionId string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	transaction := self.transactionWithLock(transactionId)
	if transaction == nil {
		return ErrFakeStoreUnknown
	}
	transaction.Finished = true
	return nil
}

// The transactions the app has not finished, oldest first: what StoreKit hands the app again at its next launch, for
// it to report again.
func (self *FakeAppStore) Unfinished() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	unfinished := []string{}
	for _, transaction := range self.transactions {
		if !transaction.Finished {
			unfinished = append(unfinished, transaction.TransactionId)
		}
	}
	return unfinished
}

// The transaction as the store holds it, nil for none.
func (self *FakeAppStore) Transaction(transactionId string) *FakeAppleTransaction {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	transaction := self.transactionWithLock(transactionId)
	if transaction == nil {
		return nil
	}
	return fakeAppleTransactionCopy(transaction)
}

// An App Store Server API error.
func writeFakeAppleError(writer http.ResponseWriter, status int, code int64, message string) {
	body, _ := json.Marshal(map[string]any{"errorCode": code, "errorMessage": message})
	writeFakeStoreJson(writer, status, body)
}

// A Server API handler behind the bearer (see the file header).
func (self *FakeAppStore) authorized(serve func(writer http.ResponseWriter, request *http.Request)) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		bearer, ok := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
		if !ok || self.checkBearer(bearer) != nil {
			writeFakeAppleError(writer, http.StatusUnauthorized, 4010000, "Unauthenticated")
			return
		}
		serve(writer, request)
	}
}

// Whether bearer is a token the test's key signed for this app, live now.
func (self *FakeAppStore) checkBearer(bearer string) error {
	header, payloadJson, err := fakeJwsVerify(bearer, &self.apiKey.PublicKey)
	if err != nil {
		return err
	}
	if header["kid"] != self.apiKeyId {
		return errors.New("computetest: another key's bearer")
	}
	claims := struct {
		Iss string `json:"iss"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		Aud string `json:"aud"`
		Bid string `json:"bid"`
	}{}
	if err := json.Unmarshal(payloadJson, &claims); err != nil {
		return err
	}
	if claims.Iss != self.issuerId || claims.Aud != "appstoreconnect-v1" || claims.Bid != self.apple.BundleId {
		return errors.New("computetest: a bearer for another issuer, audience or app")
	}
	if claims.Exp <= self.clock.Now().Unix() || self.apple.BearerMaxLife < time.Duration(claims.Exp-claims.Iat)*time.Second {
		return errors.New("computetest: a bearer past its life")
	}
	return nil
}

func (self *FakeAppStore) serveTransaction(writer http.ResponseWriter, request *http.Request) {
	signed, err := self.SignedTransaction(request.PathValue("id"))
	if err != nil {
		writeFakeAppleError(writer, http.StatusNotFound, 4040010, "Transaction id not found.")
		return
	}
	body, _ := json.Marshal(map[string]string{"signedTransactionInfo": signed})
	writeFakeStoreJson(writer, http.StatusOK, body)
}

// The transactions of the subscription or purchase transactionId belongs to, as productType and sort ask, in pages of
// the settings' count, the revision the index of the next page.
func (self *FakeAppStore) serveHistory(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	transaction := self.transactionWithLock(request.PathValue("id"))
	if transaction == nil {
		writeFakeAppleError(writer, http.StatusNotFound, 4040010, "Transaction id not found.")
		return
	}
	productTypes := map[string]string{"AUTO_RENEWABLE": FakeAppleTypeAutoRenewing, "CONSUMABLE": FakeAppleTypeConsumable}
	chain := []*FakeAppleTransaction{}
	for _, stored := range self.transactions {
		if stored.AppTransactionId != transaction.AppTransactionId {
			continue
		}
		if productType := query.Get("productType"); productType != "" && productTypes[productType] != stored.Type {
			continue
		}
		chain = append(chain, stored)
	}
	if query.Get("sort") == "DESCENDING" {
		slices.Reverse(chain)
	}
	start := 0
	if revision := query.Get("revision"); revision != "" {
		parsed, err := strconv.Atoi(revision)
		if err != nil || parsed < 0 || len(chain) < parsed {
			writeFakeAppleError(writer, http.StatusBadRequest, 4000005, "Invalid revision.")
			return
		}
		start = parsed
	}
	end := min(len(chain), start+self.apple.HistoryPageCount)
	now := self.clock.Now()
	signed := []string{}
	for _, stored := range chain[start:end] {
		jws, err := self.sign(self.transactionClaims(stored, now))
		if err != nil {
			writeFakeAppleError(writer, http.StatusInternalServerError, 5000000, "The fake could not sign.")
			return
		}
		signed = append(signed, jws)
	}
	body, _ := json.Marshal(map[string]any{
		"signedTransactions": signed,
		"revision":           strconv.Itoa(end),
		"hasMore":            end < len(chain),
		"bundleId":           self.apple.BundleId,
		"appAppleId":         self.apple.AppAppleId,
		"environment":        self.apple.Environment,
	})
	writeFakeStoreJson(writer, http.StatusOK, body)
}

// The statuses of the subscription transactionId belongs to: its group, its newest transaction and its renewal.
func (self *FakeAppStore) serveSubscriptions(writer http.ResponseWriter, request *http.Request) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	transaction := self.transactionWithLock(request.PathValue("id"))
	if transaction == nil || transaction.Type != FakeAppleTypeAutoRenewing {
		writeFakeAppleError(writer, http.StatusNotFound, 4040010, "Transaction id not found.")
		return
	}
	latest := self.latestWithLock(transaction.OriginalTransactionId)
	renewal := self.renewals[transaction.OriginalTransactionId]
	now := self.clock.Now()
	signedTransaction, err := self.sign(self.transactionClaims(latest, now))
	if err != nil {
		writeFakeAppleError(writer, http.StatusInternalServerError, 5000000, "The fake could not sign.")
		return
	}
	signedRenewal, err := self.sign(self.renewalClaims(renewal, now))
	if err != nil {
		writeFakeAppleError(writer, http.StatusInternalServerError, 5000000, "The fake could not sign.")
		return
	}
	// 1 active, 2 expired, 5 revoked, as Apple numbers them
	status := 1
	switch {
	case !latest.RevocationDate.IsZero():
		status = 5
	case !now.Before(latest.ExpiresDate):
		status = 2
	}
	body, _ := json.Marshal(map[string]any{
		"environment": self.apple.Environment,
		"bundleId":    self.apple.BundleId,
		"appAppleId":  self.apple.AppAppleId,
		"data": []any{map[string]any{
			"subscriptionGroupIdentifier": latest.SubscriptionGroupId,
			"lastTransactions": []any{map[string]any{
				"status":                status,
				"originalTransactionId": latest.OriginalTransactionId,
				"signedTransactionInfo": signedTransaction,
				"signedRenewalInfo":     signedRenewal,
			}},
		}},
	})
	writeFakeStoreJson(writer, http.StatusOK, body)
}
