//go:build !sidecar_http && !js && !ios_extension

package sidecar

// §15.5's MTA-STS on the receiver (MAIL-M8-08; §22.5's §13 row with TLS-M8-02): the policy body is a valid RFC 8461
// policy whose id is the one §12.7's _mta-sts carries, an alias gets its own mx, a burner host, a scope's and another
// network's get none, and the component serves it as its receiver's system publish only while the receiver listens
// and the device holds a §13 certificate, never on the self-signed leaf alone, ending it with the listen grant.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// RFC 8461 §3.2's grammar, term by term: a version, a mode, a max_age and at least one mx, the version first.
var (
	testMtaStsVersionTerm = regexp.MustCompile(`^version[ \t]*:[ \t]*STSv1$`)
	testMtaStsModeTerm    = regexp.MustCompile(`^mode[ \t]*:[ \t]*(testing|enforce|none)$`)
	testMtaStsMaxAgeTerm  = regexp.MustCompile(`^max_age[ \t]*:[ \t]*([0-9]{1,10})$`)
	testMtaStsMxTerm      = regexp.MustCompile(`^mx[ \t]*:[ \t]*((\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?)$`)
)

// The policy's fields when body is a valid RFC 8461 §3.2 policy, else an error naming what is not.
func testParseMtaStsPolicy(body string) (mode string, maxAge int, mxs []string, err error) {
	terms := strings.Split(strings.TrimSuffix(body, "\r\n"), "\r\n")
	if len(terms) == 0 || !testMtaStsVersionTerm.MatchString(terms[0]) {
		return "", 0, nil, errors.New("the first term is no version: STSv1")
	}
	modes := 0
	maxAges := 0
	for _, term := range terms[1:] {
		switch {
		case testMtaStsModeTerm.MatchString(term):
			mode = testMtaStsModeTerm.FindStringSubmatch(term)[1]
			modes += 1
		case testMtaStsMaxAgeTerm.MatchString(term):
			maxAge, err = strconv.Atoi(testMtaStsMaxAgeTerm.FindStringSubmatch(term)[1])
			if err != nil || 31557600 < maxAge {
				return "", 0, nil, errors.New("max_age past RFC 8461 §3.2's bound")
			}
			maxAges += 1
		case testMtaStsMxTerm.MatchString(term):
			mxs = append(mxs, testMtaStsMxTerm.FindStringSubmatch(term)[1])
		default:
			return "", 0, nil, errors.New("a term of no RFC 8461 shape: " + term)
		}
	}
	if modes != 1 || maxAges != 1 || (mode != "none" && len(mxs) == 0) {
		return "", 0, nil, errors.New("not exactly one mode and one max_age, or no mx")
	}
	return mode, maxAge, mxs, nil
}

// The test network's zones: label acme under root.example, and an alias.
func testMtaStsZones() []string {
	return []string{"acme.root.example", "acme-alias.root.example"}
}

// A GET of host's policy path through handler.
func testMtaStsGet(handler http.Handler, method string, host string, path string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://"+host+path, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// The body is a valid RFC 8461 policy, mode enforce, max_age a week, mx the zone's mail host, served as text/plain;
// and its id is the one the dns writer puts in _mta-sts, since both compute it from MtaStsPolicy's text.
func TestMailMtaStsHandlerServesAValidPolicy(t *testing.T) {
	handler := NewMailMtaStsHandler(testMtaStsZones, nil)
	recorder := testMtaStsGet(handler, http.MethodGet, "mta-sts.acme.root.example", "/.well-known/mta-sts.txt")
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "text/plain" {
		t.Fatalf("answered %d %q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
	body := recorder.Body.String()
	mode, maxAge, mxs, err := testParseMtaStsPolicy(body)
	if err != nil {
		t.Fatalf("%v in %q", err, body)
	}
	if mode != "enforce" || maxAge != 7*24*3600 || len(mxs) != 1 || mxs[0] != "mx.acme.root.example" {
		t.Errorf("mode %s, max_age %d, mx %v", mode, maxAge, mxs)
	}
	if want := MtaStsPolicyId(MtaStsPolicy("mx.acme.root.example.", nil), nil); MtaStsPolicyId(body, nil) != want {
		t.Errorf("the served policy's id %s is not _mta-sts's %s", MtaStsPolicyId(body, nil), want)
	}
	if length := recorder.Header().Get("Content-Length"); length != strconv.Itoa(len(body)) {
		t.Errorf("Content-Length %s for %d bytes", length, len(body))
	}
	// a host header with a port and another case names the same zone
	if recorder := testMtaStsGet(handler, http.MethodGet, "MTA-STS.Acme.Root.Example:443", "/.well-known/mta-sts.txt"); recorder.Body.String() != body {
		t.Errorf("a cased host with its port answered %d %q", recorder.Code, recorder.Body.String())
	}
	head := testMtaStsGet(handler, http.MethodHead, "mta-sts.acme.root.example", "/.well-known/mta-sts.txt")
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Errorf("HEAD answered %d with %d bytes", head.Code, head.Body.Len())
	}
	// and a sending sidecar's own reader (§14.4's TL2) takes it as enforcing for the mail host and nothing else
	policy, err := ParseSmtpMtaStsPolicy([]byte(body))
	if err != nil || !policy.Enforced() || !policy.MatchesMx("mx.acme.root.example") || policy.MatchesMx("otter-4821.acme.root.example") {
		t.Errorf("the sender's reader took %+v, %v", policy, err)
	}
}

// The alias's policy names the alias's own mail host, which its MX names and the receivers' certificate covers.
func TestMailMtaStsHandlerServesTheAliasItsOwnMx(t *testing.T) {
	handler := NewMailMtaStsHandler(testMtaStsZones, nil)
	recorder := testMtaStsGet(handler, http.MethodGet, "mta-sts.acme-alias.root.example", "/.well-known/mta-sts.txt")
	_, _, mxs, err := testParseMtaStsPolicy(recorder.Body.String())
	if err != nil || len(mxs) != 1 || mxs[0] != "mx.acme-alias.root.example" {
		t.Errorf("the alias got %v, %v", mxs, err)
	}
}

// A burner host gets no policy (RFC 8461 §3.4: senders never take a parent zone's, so burners rely on DANE), nor does a
// Team scope's, another network's or the bare zone; another path is 404 and another method 405.
func TestMailMtaStsHandlerServesNoBurnerOrOtherHost(t *testing.T) {
	handler := NewMailMtaStsHandler(testMtaStsZones, nil)
	for _, host := range []string{
		"mta-sts.otter-4821.acme.root.example",
		"mta-sts.sales.acme.root.example",
		"mta-sts.other.root.example",
		"acme.root.example",
		"mta-sts.root.example",
		"",
	} {
		if recorder := testMtaStsGet(handler, http.MethodGet, host, "/.well-known/mta-sts.txt"); recorder.Code != http.StatusNotFound {
			t.Errorf("%q answered %d", host, recorder.Code)
		}
	}
	if recorder := testMtaStsGet(handler, http.MethodGet, "mta-sts.acme.root.example", "/.well-known/mta-sts"); recorder.Code != http.StatusNotFound {
		t.Errorf("another path answered %d", recorder.Code)
	}
	if recorder := testMtaStsGet(handler, http.MethodPost, "mta-sts.acme.root.example", "/.well-known/mta-sts.txt"); recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST answered %d", recorder.Code)
	}
}

// A system publish standing in for Sidecar.ServeTlsSystemPublish: whether the device is certified, each publish
// served, and each close.
type testMailMtaStsPublisher struct {
	certified atomic.Bool
	serveErr  atomic.Pointer[error]

	stateLock   sync.Mutex
	serverNames []string
	handlers    []http.Handler
	closeCount  int
}

func (self *testMailMtaStsPublisher) Certified(serverName string) bool {
	self.stateLock.Lock()
	self.serverNames = append(self.serverNames, serverName)
	self.stateLock.Unlock()
	return self.certified.Load()
}

func (self *testMailMtaStsPublisher) Serve(ctx context.Context, handler http.Handler) (io.Closer, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.handlers = append(self.handlers, handler)
	if err := self.serveErr.Load(); err != nil {
		return nil, *err
	}
	return testMailMtaStsCloser(func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closeCount += 1
	}), nil
}

// Publishes served and closes, so far.
func (self *testMailMtaStsPublisher) counts() (serveCount int, closeCount int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.handlers), self.closeCount
}

type testMailMtaStsCloser func()

func (self testMailMtaStsCloser) Close() error {
	self()
	return nil
}

// The component's world: mail on, a receiver it starts over the receiver test world while granted, and the publisher.
type testMailMtaStsWorld struct {
	world     *mailClientTestWorld
	receivers *mailReceiverTestWorld
	publisher *testMailMtaStsPublisher
	granted   atomic.Bool
	run       *mailComponentRun
	binding   *MailBinding
}

func newTestMailMtaStsWorld(t *testing.T) *testMailMtaStsWorld {
	t.Helper()
	self := &testMailMtaStsWorld{
		world:     newMailClientTestWorld(t),
		receivers: newMailReceiverTestWorld(t, nil),
		publisher: &testMailMtaStsPublisher{},
	}
	self.granted.Store(true)
	self.world.client.componentSeams = &mailComponentSeams{
		mayReceive: self.granted.Load,
		factory: func(args *mailReceiverFactoryArgs) (*MailReceiver, func(), error) {
			return self.receivers.newReceiver(nil), func() {}, nil
		},
		mtaSts: self.publisher,
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	self.run = &mailComponentRun{ctx: ctx, cancel: cancel}
	binding, _, err := self.world.client.bound()
	if err != nil {
		t.Fatal(err)
	}
	self.binding = binding
	return self
}

// One of the component's passes: the receiver's, then the publish's.
func (self *testMailMtaStsWorld) pass() {
	self.world.client.passReceive(self.run, self.binding)
	self.world.client.passMtaSts(self.run, self.binding)
}

// Nothing serves while mail is off or the receiver holds only its self-signed leaf; once the device holds a §13
// certificate for mta-sts.<label>.<root> one publish serves, on a handler answering the network's policy, and a later
// pass serves no second one.
func TestMailComponentServesMtaStsOnlyOnceCertified(t *testing.T) {
	world := newTestMailMtaStsWorld(t)
	world.pass()
	if serveCount, _ := world.publisher.counts(); serveCount != 0 {
		t.Fatal("a publish with mail off")
	}
	world.world.enable()
	world.world.client.passReceive(world.run, world.binding)
	// the listen holds once the receiver posts its key, which it does only while it holds the registration
	world.receivers.publisher.awaitCount(1)
	world.world.client.passMtaSts(world.run, world.binding)
	if serveCount, _ := world.publisher.counts(); serveCount != 0 {
		t.Fatal("a receiver holding only its self-signed certificate served the policy")
	}
	world.publisher.stateLock.Lock()
	serverNames := append([]string{}, world.publisher.serverNames...)
	world.publisher.stateLock.Unlock()
	if len(serverNames) == 0 || serverNames[len(serverNames)-1] != "mta-sts.acme.root.example" {
		t.Errorf("certification asked of %v", serverNames)
	}

	world.publisher.certified.Store(true)
	world.pass()
	world.pass()
	serveCount, closeCount := world.publisher.counts()
	if serveCount != 1 || closeCount != 0 || !world.world.client.mtaStsServing(world.run) {
		t.Fatalf("certified: %d served, %d closed", serveCount, closeCount)
	}
	world.publisher.stateLock.Lock()
	handler := world.publisher.handlers[0]
	world.publisher.stateLock.Unlock()
	recorder := testMtaStsGet(handler, http.MethodGet, "mta-sts.acme.root.example", "/.well-known/mta-sts.txt")
	if recorder.Code != http.StatusOK || recorder.Body.String() != MtaStsPolicy("mx.acme.root.example", nil) {
		t.Errorf("the served handler answered %d %q", recorder.Code, recorder.Body.String())
	}
}

// A revoked listen grant ends serving: the receiver stops and its publish closes with it. Mail turning off does too.
func TestMailComponentEndsMtaStsWithTheListenGrant(t *testing.T) {
	world := newTestMailMtaStsWorld(t)
	world.publisher.certified.Store(true)
	world.world.enable()
	world.world.client.passReceive(world.run, world.binding)
	// the listen holds once the receiver posts its key, which it does only while it holds the registration
	world.receivers.publisher.awaitCount(1)
	world.world.client.passMtaSts(world.run, world.binding)
	if serveCount, _ := world.publisher.counts(); serveCount != 1 {
		t.Fatalf("%d served", serveCount)
	}
	world.granted.Store(false)
	world.pass()
	if _, closeCount := world.publisher.counts(); closeCount != 1 || world.world.client.mtaStsServing(world.run) {
		t.Errorf("the revoked grant left the publish: %d closed", closeCount)
	}
	world.pass()
	if serveCount, _ := world.publisher.counts(); serveCount != 1 {
		t.Errorf("served again with no grant: %d", serveCount)
	}
}

// A publish the sockets service refuses, an unverified network's above all, is tried again only after RetryInterval.
func TestMailComponentRetriesARefusedMtaStsOnlyAfterItsInterval(t *testing.T) {
	world := newTestMailMtaStsWorld(t)
	world.publisher.certified.Store(true)
	refused := error(&SocketCodeError{Err: ErrSocketDenied})
	world.publisher.serveErr.Store(&refused)
	world.world.enable()
	world.world.client.passReceive(world.run, world.binding)
	// the listen holds once the receiver posts its key, which it does only while it holds the registration
	world.receivers.publisher.awaitCount(1)
	before := time.Now()
	world.world.client.passMtaSts(world.run, world.binding)
	world.world.client.passMtaSts(world.run, world.binding)
	if serveCount, _ := world.publisher.counts(); serveCount != 1 {
		t.Fatalf("a refused publish was tried %d times at once", serveCount)
	}
	retryTime := func() time.Time {
		world.world.client.stateLock.Lock()
		defer world.world.client.stateLock.Unlock()
		return world.run.mtaStsRetryTime
	}()
	if retryTime.Before(before.Add(DefaultMailMtaStsSettings().RetryInterval)) {
		t.Errorf("the retry is at %v, before the interval from %v", retryTime, before)
	}
	// the interval passed
	func() {
		world.world.client.stateLock.Lock()
		defer world.world.client.stateLock.Unlock()
		world.run.mtaStsRetryTime = time.Time{}
	}()
	world.publisher.serveErr.Store(nil)
	world.world.client.passMtaSts(world.run, world.binding)
	if serveCount, _ := world.publisher.counts(); serveCount != 2 || !world.world.client.mtaStsServing(world.run) {
		t.Errorf("after the interval: %d tries", serveCount)
	}
}
