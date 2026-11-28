// computetest.FakeStores (CTEST-M12-02; DESIGN-COMPUTE §9.5, §9.8, §9.11, §9.12 and §18's ledger row): the three
// markets compute credit is bought in, as HTTP fakes BAL's server code talks to in tests, each on its own loopback
// server with the roots and secrets the test installs, every id synthetic and drawn from the seed:
//
//	FakeStripe     stores_stripe.go: Stripe's API for Customers, Checkout Sessions, PaymentIntents (on and off session,
//	               captured by hand or at once, with authentication_required and declines), PaymentMethods with card
//	               fingerprints, Refunds and disputes, and webhook events signed under a test endpoint secret
//	FakeAppStore   stores_apple.go: the App Store Server API's transaction lookups and history, and Server
//	               Notifications V2, every signed object a JWS under a test root chain carrying Apple's certificate
//	               policy extensions; consumables, subscriptions, renewals, upgrades, downgrades and refunds, and the
//	               app's queue of transactions it has not finished
//	FakePlay       stores_play.go: the Android Publisher API's purchases.products get, consume and acknowledge,
//	               purchases.subscriptionsv2 get, voided purchases and order refunds; real-time developer
//	               notifications pushed as Pub/Sub does, under an id token its tokeninfo endpoint answers; a new order id
//	               at each renewal, replacement plans and the three days after which Play refunds a purchase never
//	               consumed or acknowledged
//
// Each market's notifications wait in its own FakeStoreNotifications until the test delivers them: once, twice, out of
// order or never, to the endpoint it set, so §18's ledger cases are scripted rather than raced (a report racing its
// notification, a renewal credited once by its order id, four plan changes in a sitting, a consumable consumed within
// three days, a chargeback). Nothing sleeps: each fake reads the injected clock.
//
// A request for what a market does not build answers 501 with a named code, never a store's 404 that BAL's code would
// read as the object gone, and is kept for a test to assert none was made (FakeStoreNotBuiltCode, NotBuiltRequests).
//
// The fakes speak only HTTP on loopback. The App Store's test root goes into server's pinned roots through its own
// test seam (api/handlers/apple_root_store.go), never a production root; no production build trusts any key here.
//
// Safe for concurrent use.

package computetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

var (
	// A notification id the queue does not hold.
	ErrFakeStoreNotificationUnknown = errors.New("computetest: the store holds no such notification")
	// A delivery with no endpoint set.
	ErrFakeStoreNoEndpoint = errors.New("computetest: no endpoint to deliver the store's notifications to")
	// A test asked a store for a purchase, customer, token or transaction it does not hold.
	ErrFakeStoreUnknown = errors.New("computetest: the fake store holds no such object")
	// A test asked a store for what its state forbids: capturing a canceled payment, renewing a replaced plan.
	ErrFakeStoreState = errors.New("computetest: the fake store's state forbids that")
)

// The markets: identifiers.
const (
	FakeMarketStripe   = "stripe"
	FakeMarketAppStore = "app_store"
	FakeMarketPlay     = "play"
)

// What a market answers a request it does not serve. A fake fails a call it was not scripted for with a named error,
// never a default answer, and a store's own 404 would be one: BAL's code reads a 404 as the object gone (server's
// computeStripeGone, and computePlayGone with Play's 400 and 410), so an unbuilt route would pass for a subscription
// already canceled. Each market answers 501 in its own error shape naming this code, a status none of BAL's clients
// retries (Stripe's carries Stripe-Should-Retry false, which stripe-go honors before its retry on 5xx), and keeps the
// request for a test to assert none was made (NotBuiltRequests). A served route's own miss, such as an unknown
// customer or purchase token, is still that store's 404. Identifiers.
const (
	// Stripe's error code, and the start of the App Store's errorMessage and of Play's message.
	FakeStoreNotBuiltCode = "computetest_not_built"
	// The App Store's errorCode, in Apple's form of the status then an index.
	FakeAppStoreNotBuiltErrorCode = 5010000
)

// The three markets' settings (QD-702).
type FakeStoresSettings struct {
	Stripe   *FakeStripeSettings
	AppStore *FakeAppStoreSettings
	Play     *FakePlaySettings
	// The most bytes of a request body any market reads: 1 MiB, past every request BAL's code sends.
	RequestByteCount int64
	// The most bytes of an endpoint's answer a delivery reads back: 64 KiB.
	DeliveryAnswerByteCount int64
	// How long one delivery waits for its endpoint: 30 seconds, a guard on a test's own server, never a proof.
	DeliveryTimeout time.Duration
}

// The defaults, the only place one is set.
func DefaultFakeStoresSettings() *FakeStoresSettings {
	return &FakeStoresSettings{
		Stripe:                  DefaultFakeStripeSettings(),
		AppStore:                DefaultFakeAppStoreSettings(),
		Play:                    DefaultFakePlaySettings(),
		RequestByteCount:        1024 * 1024,
		DeliveryAnswerByteCount: 64 * 1024,
		DeliveryTimeout:         30 * time.Second,
	}
}

// What NewFakeStores builds on.
type FakeStoresArgs struct {
	// Nil takes DefaultFakeStoresSettings; a nil market's field, that market's defaults.
	Settings *FakeStoresSettings
	// Where every id, key and secret is drawn from; empty takes "stores".
	Seed string
	// Nil takes a FakeClock at sidecartest.DefaultClockStart.
	Clock sidecar.Clock
	// What a Stripe webhook's Stripe-Signature is timestamped by. stripe-go judges that time against the wall clock
	// within its 5-minute tolerance, so a test that delivers to stripe-go on a fake clock far from real time gives real
	// time here. Nil takes Clock.
	SignatureClock sidecar.Clock
}

// The three markets (see the file header).
type FakeStores struct {
	Stripe   *FakeStripe
	AppStore *FakeAppStore
	Play     *FakePlay
}

// Starts the three markets, each serving at once; Close ends them.
func NewFakeStores(args *FakeStoresArgs) (*FakeStores, error) {
	if args == nil {
		args = &FakeStoresArgs{}
	}
	settings := DefaultFakeStoresSettings()
	if args.Settings != nil {
		copied := *args.Settings
		if copied.Stripe == nil {
			copied.Stripe = settings.Stripe
		}
		if copied.AppStore == nil {
			copied.AppStore = settings.AppStore
		}
		if copied.Play == nil {
			copied.Play = settings.Play
		}
		settings = &copied
	}
	seed := args.Seed
	if seed == "" {
		seed = "stores"
	}
	clock := args.Clock
	if clock == nil {
		clock = sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	}
	signatureClock := args.SignatureClock
	if signatureClock == nil {
		signatureClock = clock
	}
	stores := &FakeStores{}
	var err error
	if stores.Stripe, err = newFakeStripe(settings, seed, clock, signatureClock); err != nil {
		return nil, err
	}
	if stores.AppStore, err = newFakeAppStore(settings, seed, clock); err != nil {
		stores.Close()
		return nil, err
	}
	if stores.Play, err = newFakePlay(settings, seed, clock); err != nil {
		stores.Close()
		return nil, err
	}
	return stores, nil
}

// Ends every market's server.
func (self *FakeStores) Close() {
	if self.Stripe != nil {
		self.Stripe.Close()
	}
	if self.AppStore != nil {
		self.AppStore.Close()
	}
	if self.Play != nil {
		self.Play.Close()
	}
}

// A loopback HTTP server for one market's handler, its error log discarded.
func newFakeStoreServer(handler http.Handler) *httptest.Server {
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Start()
	return server
}

// One notification a market made, as it would send it: its body and headers, and every delivery of it.
type FakeStoreNotification struct {
	// The market's own id for it: a Stripe event's, an App Store notification's UUID, a Pub/Sub message's.
	Id string
	// The event's or notification's type, as the market names it: payment_intent.succeeded, DID_RENEW, 2.
	Type string
	// When the market made it, by the fake's clock.
	Time time.Time
	// What a delivery POSTs.
	Body []byte
	// The headers a delivery sends beside the body; a header a market signs per delivery (Stripe's) is made at each
	// delivery instead (sign).
	Header http.Header
	// Each delivery's answer status, in order; 0 for one that reached no endpoint.
	DeliveryStatuses []int

	// signs one delivery: the headers to add, made at that delivery
	sign func(at time.Time, body []byte) http.Header
	// set by Drop: never delivered
	dropped bool
}

// A market's notifications, held until the test delivers them (see the file header). Safe for concurrent use.
type FakeStoreNotifications struct {
	settings *FakeStoresSettings
	clock    sidecar.Clock

	stateLock     sync.Mutex
	notifications []*FakeStoreNotification
	endpoint      string
	client        *http.Client
}

func newFakeStoreNotifications(settings *FakeStoresSettings, clock sidecar.Clock) *FakeStoreNotifications {
	return &FakeStoreNotifications{settings: settings, clock: clock, client: &http.Client{Timeout: settings.DeliveryTimeout}}
}

// Sets where deliveries go: a URL the test's server or server's webhook route answers at, and the client that reaches
// it, nil for a plain one.
func (self *FakeStoreNotifications) SetEndpoint(url string, client *http.Client) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.endpoint = url
	if client != nil {
		self.client = client
	}
}

// Queues notification, undelivered.
func (self *FakeStoreNotifications) add(notification *FakeStoreNotification) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.notifications = append(self.notifications, notification)
}

// A copy of notification for a caller.
func fakeStoreNotificationCopy(notification *FakeStoreNotification) *FakeStoreNotification {
	copied := *notification
	copied.Body = bytes.Clone(notification.Body)
	copied.Header = notification.Header.Clone()
	copied.DeliveryStatuses = slices.Clone(notification.DeliveryStatuses)
	copied.sign = nil
	return &copied
}

// Every notification made, in the order made, copies.
func (self *FakeStoreNotifications) All() []*FakeStoreNotification {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	all := make([]*FakeStoreNotification, 0, len(self.notifications))
	for _, notification := range self.notifications {
		all = append(all, fakeStoreNotificationCopy(notification))
	}
	return all
}

// The notifications never delivered and not dropped, in the order made.
func (self *FakeStoreNotifications) Pending() []*FakeStoreNotification {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	pending := []*FakeStoreNotification{}
	for _, notification := range self.notifications {
		if len(notification.DeliveryStatuses) == 0 && !notification.dropped {
			pending = append(pending, fakeStoreNotificationCopy(notification))
		}
	}
	return pending
}

// The newest notification of type, nil for none.
func (self *FakeStoreNotifications) Last(notificationType string) *FakeStoreNotification {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for i := len(self.notifications) - 1; 0 <= i; i -= 1 {
		if self.notifications[i].Type == notificationType {
			return fakeStoreNotificationCopy(self.notifications[i])
		}
	}
	return nil
}

// Marks id never to be delivered, as a market that gave up does.
func (self *FakeStoreNotifications) Drop(id string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, notification := range self.notifications {
		if notification.Id == id {
			notification.dropped = true
			return nil
		}
	}
	return ErrFakeStoreNotificationUnknown
}

// Delivers id once more, whether delivered before or not, and answers the endpoint's status: a market's retry, or a
// first delivery. A dropped notification is delivered too, since the test asked for it by id.
func (self *FakeStoreNotifications) Deliver(ctx context.Context, id string) (int, error) {
	notification, endpoint, client, err := func() (*FakeStoreNotification, string, *http.Client, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, notification := range self.notifications {
			if notification.Id == id {
				return notification, self.endpoint, self.client, nil
			}
		}
		return nil, "", nil, ErrFakeStoreNotificationUnknown
	}()
	if err != nil {
		return 0, err
	}
	if endpoint == "" {
		return 0, ErrFakeStoreNoEndpoint
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(notification.Body))
	if err != nil {
		return 0, err
	}
	for name, values := range notification.Header {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	if notification.sign != nil {
		for name, values := range notification.sign(self.clock.Now(), notification.Body) {
			for _, value := range values {
				request.Header.Set(name, value)
			}
		}
	}
	status := 0
	response, err := client.Do(request)
	if err == nil {
		io.Copy(io.Discard, io.LimitReader(response.Body, self.settings.DeliveryAnswerByteCount))
		response.Body.Close()
		status = response.StatusCode
	}
	self.stateLock.Lock()
	notification.DeliveryStatuses = append(notification.DeliveryStatuses, status)
	self.stateLock.Unlock()
	if err != nil {
		return 0, fmt.Errorf("computetest: delivering %s: %w", id, err)
	}
	return status, nil
}

// Delivers every pending notification once, oldest first, and answers their statuses in that order.
func (self *FakeStoreNotifications) DeliverPending(ctx context.Context) ([]int, error) {
	statuses := []int{}
	for _, notification := range self.Pending() {
		status, err := self.Deliver(ctx, notification.Id)
		if err != nil {
			return statuses, err
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

// Delivers every pending notification once, newest first: the out-of-order delivery a market makes no promise
// against.
func (self *FakeStoreNotifications) DeliverPendingReversed(ctx context.Context) ([]int, error) {
	pending := self.Pending()
	slices.Reverse(pending)
	statuses := []int{}
	for _, notification := range pending {
		status, err := self.Deliver(ctx, notification.Id)
		if err != nil {
			return statuses, err
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

// The requests one market did not serve (see FakeStoreNotBuiltCode), each "<method> <path>", with what a served route
// does not build after it, in arrival order. Safe for concurrent use.
type fakeStoreNotBuilt struct {
	// the market as its message names it
	market string

	stateLock sync.Mutex
	requests  []string
}

func newFakeStoreNotBuilt(market string) *fakeStoreNotBuilt {
	return &fakeStoreNotBuilt{market: market}
}

// Keeps request, and answers the message its 501 carries: the code, the market and what was asked. detail names what
// a served route does not build (a mode, a method), empty where the route itself is not served.
func (self *fakeStoreNotBuilt) record(request *http.Request, detail string) string {
	asked := request.Method + " " + request.URL.Path
	if detail != "" {
		asked += " (" + detail + ")"
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.requests = append(self.requests, asked)
	}()
	return FakeStoreNotBuiltCode + ": the fake " + self.market + " serves no " + asked
}

// The requests kept, oldest first.
func (self *fakeStoreNotBuilt) list() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.requests)
}

// An HTTP status and a JSON body, as each market answers.
func writeFakeStoreJson(writer http.ResponseWriter, status int, body []byte) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	writer.Write(body)
}
