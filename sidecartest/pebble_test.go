// The harness's hold on a request to an authorization whose challenge Pebble is validating, which keeps
// Pebble's own lock leak from wedging it (pebble.go's header), and the bounds on its waits. Tip-check
// at sidecar be60f4c3 hung two hours on that wedge: certs' order of a set deactivated an authorization
// mid-validation when dns refused the next name's write. Every wait here has its test's deadline, and
// the order the race needs is forced with held lookups and the hold's own signal, never a sleep.

package sidecartest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mholt/acmez/v3/acme"
)

// An account on pebble, and a pending order for name with its one authorization's dns-01 challenge.
func testPebbleChallenge(t *testing.T, ctx context.Context, pebble *Pebble, name string) (*acme.Client, acme.Account, acme.Authorization, acme.Challenge) {
	t.Helper()
	client := &acme.Client{Directory: pebble.DirectoryUrl, HTTPClient: pebble.HttpClient}
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	account, err := client.NewAccount(ctx, acme.Account{PrivateKey: accountKey, TermsOfServiceAgreed: true})
	if err != nil {
		t.Fatal(err)
	}
	order, err := client.NewOrder(ctx, account, acme.Order{Identifiers: []acme.Identifier{{Type: "dns", Value: name}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(order.Authorizations) != 1 {
		t.Fatalf("authorizations %v", order.Authorizations)
	}
	authz, err := client.GetAuthorization(ctx, account, order.Authorizations[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, challenge := range authz.Challenges {
		if challenge.Type == acme.ChallengeTypeDNS01 {
			return client, account, authz, challenge
		}
	}
	t.Fatalf("Pebble offered no dns-01 challenge: %+v", authz.Challenges)
	return nil, acme.Account{}, acme.Authorization{}, acme.Challenge{}
}

// A deactivation that arrives while the authorization's challenge is under validation, as acmez's
// cleanup sends one when a later authorization's solver fails, waits until the validation authority
// has finished; Pebble then deactivates the authorization and still takes orders. Without the hold,
// Pebble deactivates it while the authority's lookup is held, the authority then waits forever with the
// authorization's lock held, and the next newOrder never answers: this test's deadline fails it in
// seconds, and the test's end names Pebble's wedged goroutines.
func TestPebbleHoldsADeactivationUntilItsChallengeIsValidated(t *testing.T) {
	settings := DefaultPebbleSettings()
	settings.NonceRejectPercent = 0
	pebble := StartPebble(t, settings)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client, account, authz, challenge := testPebbleChallenge(t, ctx, pebble, "held.pebble.example")

	arrived, release := pebble.HoldLookups(t)
	if _, err := client.InitiateChallenge(ctx, account, challenge); err != nil {
		t.Fatal(err)
	}
	select {
	case <-arrived:
	case <-ctx.Done():
		t.Fatal("Pebble's validation authority never looked the challenge up")
	}

	deactivated := make(chan error, 1)
	go func() {
		_, err := client.DeactivateAuthorization(ctx, account, authz.Location)
		deactivated <- err
	}()
	held := false
	answered := false
	var deactivateErr error
	select {
	case <-pebble.AuthorizationHeld():
		held = true
	case deactivateErr = <-deactivated:
		answered = true
	case <-ctx.Done():
		t.Fatal("the deactivation was neither held nor answered")
	}
	release()
	if !held {
		t.Errorf("Pebble deactivated the authorization while its challenge was under validation: %v", deactivateErr)
	}
	if !answered {
		select {
		case deactivateErr = <-deactivated:
		case <-ctx.Done():
			t.Fatal("the held deactivation never reached Pebble once the validation ended")
		}
	}
	if deactivateErr != nil {
		t.Fatal(deactivateErr)
	}

	// a newOrder reads every authorization's lock, the deactivated one's among them
	if _, err := client.NewOrder(ctx, account, acme.Order{Identifiers: []acme.Identifier{{Type: "dns", Value: "next.pebble.example"}}}); err != nil {
		t.Fatalf("Pebble took no order after the deactivation: %v", err)
	}
	ended, err := client.GetAuthorization(ctx, account, authz.Location)
	if err != nil {
		t.Fatal(err)
	}
	if ended.Status != acme.StatusDeactivated {
		t.Fatalf("the authorization ended %s", ended.Status)
	}
}

// What a test's end reports of a Pebble, which the Pebble's own test reads in place of failing.
type testPebbleTb struct {
	testing.TB

	stateLock sync.Mutex
	errors    []string
	cleanups  []func()
}

func (self *testPebbleTb) Error(args ...any) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.errors = append(self.errors, fmt.Sprint(args...))
}

func (self *testPebbleTb) Errorf(format string, args ...any) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.errors = append(self.errors, fmt.Sprintf(format, args...))
}

func (self *testPebbleTb) Cleanup(cleanup func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.cleanups = append(self.cleanups, cleanup)
}

// Runs the cleanups, last first, as the test's end does, and returns what they reported.
func (self *testPebbleTb) end() []string {
	cleanups := func() []func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		cleanups := self.cleanups
		self.cleanups = nil
		return cleanups
	}()
	for index := len(cleanups) - 1; 0 <= index; index -= 1 {
		cleanups[index]()
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.errors...)
}

// A request on an authorization still held at ValidationWaitTimeout is answered 503 and fails the test
// at its end, rather than reach a Pebble that would wedge on it. The authority's lookup is held until
// the test's end, so no hold can end before its timeout; acmez sends a POST answered 5xx three times,
// and each is held and answered alike.
func TestPebbleAnswersAHeldRequest503AtItsTimeout(t *testing.T) {
	pebbleTb := &testPebbleTb{TB: t}
	t.Cleanup(func() {
		pebbleTb.end()
	})
	settings := DefaultPebbleSettings()
	settings.NonceRejectPercent = 0
	settings.ValidationWaitTimeout = 50 * time.Millisecond
	pebble := StartPebble(pebbleTb, settings)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client, account, authz, challenge := testPebbleChallenge(t, ctx, pebble, "timeout.pebble.example")
	challengeId := path.Base(challenge.URL)

	arrived, _ := pebble.HoldLookups(pebbleTb)
	if _, err := client.InitiateChallenge(ctx, account, challenge); err != nil {
		t.Fatal(err)
	}
	select {
	case <-arrived:
	case <-ctx.Done():
		t.Fatal("Pebble's validation authority never looked the challenge up")
	}
	_, err := client.DeactivateAuthorization(ctx, account, authz.Location)
	var problem acme.Problem
	if !errors.As(err, &problem) || problem.Status != http.StatusServiceUnavailable || !strings.Contains(problem.Detail, challengeId) {
		t.Fatalf("the held deactivation answered %v", err)
	}
	select {
	case <-pebble.AuthorizationHeld():
	default:
		t.Fatal("the deactivation was answered with no hold")
	}

	reported := pebbleTb.end()
	if len(reported) == 0 {
		t.Fatal("the test's end reported nothing of the held deactivation")
	}
	for _, report := range reported {
		if !strings.Contains(report, challengeId) || !strings.Contains(report, "answered 503") {
			t.Fatalf("the test's end reported %q", reported)
		}
	}
}

// The test's end waits CloseTimeout for Pebble's requests and then fails the test, rather than wait
// on a request that never ends, as every request on a wedged Pebble does.
func TestPebbleCloseFailsTheTestOnARequestThatNeverEnds(t *testing.T) {
	entered := make(chan struct{})
	leave := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(entered)
		// a wedged Pebble's handler, which no closed connection or ended test lets go
		<-leave
	}))
	server.StartTLS()
	defer close(leave)
	settings := DefaultPebbleSettings()
	settings.CloseTimeout = 50 * time.Millisecond
	pebble := &Pebble{settings: settings, closing: make(chan struct{})}

	requested := make(chan error, 1)
	go func() {
		response, err := server.Client().Get(server.URL)
		if err == nil {
			response.Body.Close()
		}
		requested <- err
	}()
	select {
	case <-entered:
	case <-time.After(20 * time.Second):
		t.Fatal("the request never reached the server")
	}

	pebbleTb := &testPebbleTb{TB: t}
	pebble.close(pebbleTb, server)
	reported := pebbleTb.end()
	if len(reported) != 1 || !strings.Contains(reported[0], "had not ended") {
		t.Fatalf("the close reported %q", reported)
	}
	select {
	case err := <-requested:
		if err == nil {
			t.Fatal("a request on a closed connection was answered")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the closed connection never failed its request")
	}
}
