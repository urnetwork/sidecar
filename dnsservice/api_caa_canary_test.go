package dnsservice_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"

	"github.com/urnetwork/sidecar/dnsservice"
)

// POST caa-canary (api_caa_canary.go; DNS-M6-05): the canary's exact form, its nonce answered with the serial;
// a delete; each refusal the writer names mapped to its answer, lint_refused and busy apart as the probe needs;
// a set no canary may hold refused before the writer; only certs' bearer, and the gate's writes: false.

// One owner a strong-mode custom host maps to.
const caaCanaryTestOwner = "shop.net1." + edgeTestRoot

// A writer that records each call and answers what the test sets.
type fakeCaaCanaryWriter struct {
	stateLock sync.Mutex
	puts      []*dnsservice.DnsCaaCanaryPut
	deletes   []string
	putErr    error
	deleteErr error
	serial    uint64
}

func (self *fakeCaaCanaryWriter) PutCaaCanary(ctx context.Context, root string, put *dnsservice.DnsCaaCanaryPut) (uint64, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.putErr != nil {
		return 0, self.putErr
	}
	self.puts = append(self.puts, put)
	self.serial += 1
	return self.serial, nil
}

func (self *fakeCaaCanaryWriter) DeleteCaaCanary(ctx context.Context, root string, owner string) (uint64, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.deleteErr != nil {
		return 0, self.deleteErr
	}
	self.deletes = append(self.deletes, owner)
	self.serial += 1
	return self.serial, nil
}

func newTestCaaCanaryApi(t testing.TB) (*testApi, *fakeCaaCanaryWriter) {
	t.Helper()
	writer := &fakeCaaCanaryWriter{}
	api := newTestApi(t, func(deps *dnsservice.DnsApiDeps) { deps.CaaCanaries = writer })
	return api, writer
}

func caaCanaryTestBody(owner string, caa []string, replaces string) string {
	body, _ := json.Marshal(&dnsservice.DnsCaaCanaryRequest{Owner: owner, Caa: caa, Replaces: replaces})
	return string(body)
}

// The customer's pin a test copies.
var caaCanaryTestPin = []string{`0 issue "ca.example; accounturi=https://ca.example/acct/42"`}

// A publish writes the effective set plus 0 urcanary "<nonce>", TTL ttl.canary, and answers the serial with the
// 128-bit nonce, a fresh one each publish; a replacing publish names the canary it replaces.
func TestDnsCaaCanaryPublishesTheCanarysExactForm(t *testing.T) {
	api, writer := newTestCaaCanaryApi(t)
	recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsCaaCanaryPath, dnsservice.DnsCallerCerts, caaCanaryTestBody(caaCanaryTestOwner, caaCanaryTestPin, "")))
	if recorder.Code != http.StatusOK {
		t.Fatalf("%d %s", recorder.Code, recorder.Body.String())
	}
	answer := &dnsservice.DnsCaaCanaryAnswer{}
	if err := json.Unmarshal(recorder.Body.Bytes(), answer); err != nil || answer.Serial != 1 || len(answer.Nonce) != 32 {
		t.Fatalf("answer %+v %v", answer, err)
	}
	put := writer.puts[0]
	want := []string{caaCanaryTestPin[0], fmt.Sprintf(`0 urcanary "%s"`, answer.Nonce)}
	if put.Owner != caaCanaryTestOwner || put.Nonce != answer.Nonce || put.Ttl != api.settings.Ttl.Canary || strings.Join(put.Rdata, "|") != strings.Join(want, "|") {
		t.Fatalf("put %+v", put)
	}
	// the RRset parses as CAA, the canary non-critical
	set := &dnsservice.DnsRecordSet{Owner: put.Owner, Type: dns.TypeCAA, Ttl: put.Ttl, Kind: dnsservice.DnsRecordKindCanary, Rdata: put.Rdata}
	records, err := set.Records()
	if err != nil {
		t.Fatal(err)
	}
	if canary := records[1].(*dns.CAA); canary.Flag != 0 || canary.Tag != dnsservice.DnsCaaCanaryTag || canary.Value != answer.Nonce {
		t.Fatalf("canary %v", canary)
	}
	if nonce := dnsservice.DnsCaaCanaryNonce(put.Rdata); nonce != answer.Nonce {
		t.Fatalf("the nonce read back is %q", nonce)
	}
	again := api.serve(api.request(http.MethodPost, dnsservice.DnsCaaCanaryPath, dnsservice.DnsCallerCerts, caaCanaryTestBody(caaCanaryTestOwner, caaCanaryTestPin, answer.Nonce)))
	second := &dnsservice.DnsCaaCanaryAnswer{}
	if err := json.Unmarshal(again.Body.Bytes(), second); err != nil || again.Code != http.StatusOK || second.Nonce == answer.Nonce || second.Serial != 2 {
		t.Fatalf("a replacing publish: %d %+v", again.Code, second)
	}
	if writer.puts[1].Replaces != answer.Nonce {
		t.Fatalf("replaces %q", writer.puts[1].Replaces)
	}
}

// A delete takes the canary out and answers its serial; a delete of nothing answers serial zero.
func TestDnsCaaCanaryDeletes(t *testing.T) {
	api, writer := newTestCaaCanaryApi(t)
	body, _ := json.Marshal(&dnsservice.DnsCaaCanaryRequest{Owner: caaCanaryTestOwner, Delete: true})
	recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsCaaCanaryPath, dnsservice.DnsCallerCerts, string(body)))
	if recorder.Code != http.StatusOK || len(writer.deletes) != 1 || writer.deletes[0] != caaCanaryTestOwner {
		t.Fatalf("%d %v", recorder.Code, writer.deletes)
	}
	writer.deleteErr = fmt.Errorf("%w: gone", dnsservice.ErrDnsWriteEmpty)
	recorder = api.serve(api.request(http.MethodPost, dnsservice.DnsCaaCanaryPath, dnsservice.DnsCallerCerts, string(body)))
	answer := &dnsservice.DnsCaaCanaryAnswer{}
	if err := json.Unmarshal(recorder.Body.Bytes(), answer); err != nil || recorder.Code != http.StatusOK || answer.Serial != 0 {
		t.Fatalf("a delete of nothing: %d %+v", recorder.Code, answer)
	}
}

// Each refusal of the writer as the route answers it: a CNAME at the owner 409 lint_refused, the probe's
// failing verdict; another probe's canary 409 busy; an owner no custom host maps to, an @ among them, 400; a
// restore 503 with Retry-After.
func TestDnsCaaCanaryAnswersEachRefusal(t *testing.T) {
	api, writer := newTestCaaCanaryApi(t)
	cases := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "a cname", err: fmt.Errorf("%w: cname", dnsservice.ErrDnsCaaCanaryLint), status: http.StatusConflict, code: dnsservice.DnsCaaCanaryCodeLintRefused},
		{name: "busy", err: fmt.Errorf("%w: another", dnsservice.ErrDnsCaaCanaryBusy), status: http.StatusConflict, code: dnsservice.DnsCaaCanaryCodeBusy},
		{name: "an apex", err: fmt.Errorf("%w: apex", dnsservice.ErrDnsCaaCanaryRefused), status: http.StatusBadRequest},
		{name: "restoring", err: dnsservice.ErrDnsRestoring, status: http.StatusServiceUnavailable},
		{name: "a failure", err: errors.New("down"), status: http.StatusServiceUnavailable},
	}
	for _, c := range cases {
		writer.putErr = c.err
		recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsCaaCanaryPath, dnsservice.DnsCallerCerts, caaCanaryTestBody(caaCanaryTestOwner, caaCanaryTestPin, "")))
		if recorder.Code != c.status {
			t.Errorf("%s: %d", c.name, recorder.Code)
			continue
		}
		if c.code != "" {
			refusal := &dnsservice.DnsCaaCanaryRefusal{}
			if err := json.Unmarshal(recorder.Body.Bytes(), refusal); err != nil || refusal.Code != c.code {
				t.Errorf("%s: %q %v", c.name, recorder.Body.String(), err)
			}
		}
		if c.status == http.StatusServiceUnavailable && recorder.Header().Get("Retry-After") == "" {
			t.Errorf("%s: no Retry-After", c.name)
		}
	}
	if refused := api.host.Metrics.Value("urnetwork_dns_caa_canaries_total", "lint_refused"); refused != 1 {
		t.Errorf("lint_refused counted %v", refused)
	}
}

// Refused before the writer: no record, a record that is no CAA, the urcanary tag itself, a record twice, more
// than record_max_count, an owner outside the root or at it, a replaces that is no nonce, and a delete naming a
// record; and nothing reaches the writer.
func TestDnsCaaCanaryRefusesASetNoCanaryMayHold(t *testing.T) {
	api, writer := newTestCaaCanaryApi(t)
	tooMany := []string{}
	for index := range api.settings.CaaCanary.RecordMaxCount + 1 {
		tooMany = append(tooMany, fmt.Sprintf(`0 issue "ca%d.example"`, index))
	}
	deleteWithRecord, _ := json.Marshal(&dnsservice.DnsCaaCanaryRequest{Owner: caaCanaryTestOwner, Caa: caaCanaryTestPin, Delete: true})
	bodies := []string{
		caaCanaryTestBody(caaCanaryTestOwner, nil, ""),
		caaCanaryTestBody(caaCanaryTestOwner, []string{"not a caa"}, ""),
		caaCanaryTestBody(caaCanaryTestOwner, []string{`0 urcanary "x"`}, ""),
		caaCanaryTestBody(caaCanaryTestOwner, []string{caaCanaryTestPin[0], caaCanaryTestPin[0]}, ""),
		caaCanaryTestBody(caaCanaryTestOwner, tooMany, ""),
		caaCanaryTestBody("shop.other.example.", caaCanaryTestPin, ""),
		caaCanaryTestBody(edgeTestRoot, caaCanaryTestPin, ""),
		caaCanaryTestBody(caaCanaryTestOwner, caaCanaryTestPin, "not-a-nonce"),
		string(deleteWithRecord),
		`{"owner":`,
	}
	for _, body := range bodies {
		if recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsCaaCanaryPath, dnsservice.DnsCallerCerts, body)); recorder.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", body, recorder.Code)
		}
	}
	if len(writer.puts) != 0 || len(writer.deletes) != 0 {
		t.Fatalf("the writer was called: %d %d", len(writer.puts), len(writer.deletes))
	}
}

// Only certs' bearer reaches the route, and the gate's writes: false refuses it; a block with no writer answers
// 503.
func TestDnsCaaCanaryTakesOnlyCertsAndAnOpenGate(t *testing.T) {
	api, writer := newTestCaaCanaryApi(t)
	body := caaCanaryTestBody(caaCanaryTestOwner, caaCanaryTestPin, "")
	for _, class := range []dnsservice.DnsCallerClass{dnsservice.DnsCallerEdge, dnsservice.DnsCallerMonitor, ""} {
		if recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsCaaCanaryPath, class, body)); recorder.Code != http.StatusForbidden {
			t.Errorf("%q: %d", class, recorder.Code)
		}
	}
	if err := api.host.Gates.Set("sidecar:\n  dns: {enabled: true, writes: false}\n"); err != nil {
		t.Fatal(err)
	}
	if recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsCaaCanaryPath, dnsservice.DnsCallerCerts, body)); recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("writes off: %d", recorder.Code)
	}
	if len(writer.puts) != 0 {
		t.Fatal("a refused request reached the writer")
	}
	none := newTestApi(t, nil)
	if recorder := none.serve(none.request(http.MethodPost, dnsservice.DnsCaaCanaryPath, dnsservice.DnsCallerCerts, body)); recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("no writer: %d", recorder.Code)
	}
}
