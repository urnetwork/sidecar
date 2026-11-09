package dnsservice_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/dnsservice"
)

// A writer answering what a test tells it, and keeping what it was asked.
type fakeChallengeWriter struct {
	stateLock sync.Mutex
	err       error
	serial    uint64
	calls     []fakeChallengeCall
}

type fakeChallengeCall struct {
	root   string
	name   string
	values []string
	ttl    uint32
}

func (self *fakeChallengeWriter) PutChallenge(ctx context.Context, root string, name string, values []string, ttl uint32) (uint64, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls = append(self.calls, fakeChallengeCall{root: root, name: name, values: values, ttl: ttl})
	return self.serial, self.err
}

func challengeTestBody(t testing.TB, name string, values ...string) string {
	t.Helper()
	body, err := json.Marshal(&dnsservice.DnsChallengeRequest{Name: name, Values: values})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// certs' write answers the serial it took, with the root and dns.yml's challenge TTL passed down.
func TestDnsChallengeAnswersTheSerial(t *testing.T) {
	writer := &fakeChallengeWriter{serial: 42}
	api := newTestApi(t, func(deps *dnsservice.DnsApiDeps) { deps.Challenges = writer })
	recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsAcmeChallengePath, dnsservice.DnsCallerCerts, challengeTestBody(t, "abcdefghij.zone.example.", "one", "two")))
	if recorder.Code != http.StatusOK {
		t.Fatalf("%d %s", recorder.Code, recorder.Body.String())
	}
	answer := &dnsservice.DnsChallengeAnswer{}
	if err := json.Unmarshal(recorder.Body.Bytes(), answer); err != nil || answer.Serial != 42 {
		t.Fatalf("answer %s, %v", recorder.Body.String(), err)
	}
	if len(writer.calls) != 1 || writer.calls[0].root != "zone.example." || writer.calls[0].ttl != api.settings.Ttl.Challenge || len(writer.calls[0].values) != 2 {
		t.Fatalf("calls %+v", writer.calls)
	}
}

// Only certs writes challenges (D-DNS-8): an edge's bearer, and no bearer, are 403 and reach no writer.
func TestDnsChallengeRefusesAnyoneButCerts(t *testing.T) {
	writer := &fakeChallengeWriter{serial: 1}
	api := newTestApi(t, func(deps *dnsservice.DnsApiDeps) { deps.Challenges = writer })
	for _, class := range []dnsservice.DnsCallerClass{dnsservice.DnsCallerEdge, ""} {
		recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsAcmeChallengePath, class, challengeTestBody(t, "abcdefghij.zone.example.", "one")))
		if recorder.Code != http.StatusForbidden {
			t.Errorf("%q: %d", class, recorder.Code)
		}
	}
	if len(writer.calls) != 0 {
		t.Fatalf("a refused caller reached the writer: %+v", writer.calls)
	}
}

// Each of the writer's refusals answers as certs reads it: a restore 503 with Retry-After, a refused
// name or values 400, the hourly cap 429, a removal of nothing the serial zero. A block with no writer
// answers 503, and writes: false refuses before the writer.
func TestDnsChallengeMapsRefusals(t *testing.T) {
	writer := &fakeChallengeWriter{}
	api := newTestApi(t, func(deps *dnsservice.DnsApiDeps) { deps.Challenges = writer })
	cases := []struct {
		err  error
		code int
	}{
		{err: dnsservice.ErrDnsRestoring, code: http.StatusServiceUnavailable},
		{err: dnsservice.ErrDnsChallengeRefused, code: http.StatusBadRequest},
		{err: dnsservice.ErrDnsChallengeRate, code: http.StatusTooManyRequests},
		{err: dnsservice.ErrDnsWriteEmpty, code: http.StatusOK},
		{err: errors.New("a store that failed"), code: http.StatusServiceUnavailable},
	}
	for _, c := range cases {
		writer.stateLock.Lock()
		writer.err = c.err
		writer.stateLock.Unlock()
		recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsAcmeChallengePath, dnsservice.DnsCallerCerts, challengeTestBody(t, "abcdefghij.zone.example.", "one")))
		if recorder.Code != c.code {
			t.Errorf("%v: %d", c.err, recorder.Code)
		}
		if c.code == http.StatusServiceUnavailable && recorder.Header().Get("Retry-After") == "" {
			t.Errorf("%v: no Retry-After", c.err)
		}
	}

	none := newTestApi(t, nil)
	if recorder := none.serve(none.request(http.MethodPost, dnsservice.DnsAcmeChallengePath, dnsservice.DnsCallerCerts, challengeTestBody(t, "abcdefghij.zone.example.", "one"))); recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("no writer: %d", recorder.Code)
	}

	if err := api.host.Gates.Set("sidecar:\n  dns: {enabled: true, writes: false}\n"); err != nil {
		t.Fatal(err)
	}
	before := len(writer.calls)
	if recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsAcmeChallengePath, dnsservice.DnsCallerCerts, challengeTestBody(t, "abcdefghij.zone.example.", "one"))); recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("writes off: %d", recorder.Code)
	}
	if len(writer.calls) != before {
		t.Error("writes off reached the writer")
	}
}

// A body that is not a challenge, or names a root the block does not serve, is 400.
func TestDnsChallengeRefusesMalformedBodies(t *testing.T) {
	writer := &fakeChallengeWriter{}
	api := newTestApi(t, func(deps *dnsservice.DnsApiDeps) { deps.Challenges = writer })
	for _, body := range []string{"not json", "{}", `{"root": "other.example.", "name": "abcdefghij.other.example."}`} {
		if recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsAcmeChallengePath, dnsservice.DnsCallerCerts, body)); recorder.Code != http.StatusBadRequest {
			t.Errorf("%q: %d", body, recorder.Code)
		}
	}
	if len(writer.calls) != 0 {
		t.Fatalf("calls %+v", writer.calls)
	}
}
