// The network mail key's checks and the block's source over api's route (plan-SMTP-report-seal-key; §14.8, §15.8,
// D-KEYS-17), on a mail repo keyed at FakeGkm: the key is the newest generation's drop key and seals a copy only its
// readers open; a removal the newest does not cover stops the seal until a rotation covers it, so a removed reader
// opens no later copy; a lapsed key, a GenRotate the state's devices did not sign and another repo's ladder seal
// nothing; a state behind the generation waits; and the source tells a key, none, or nothing from api's answer.

package smtpedgeservice_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// A mail repo keyed at generation 1, and a context for the test.
func newReportKeyFixture(t *testing.T) (context.Context, *sidecartest.SmtpReportKeyFixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	keys, err := sidecartest.NewSmtpReportKeyFixture(ctx, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, keys
}

// api's checks of gkm's whole answer at view and the fixture's now.
func checkReportKey(t *testing.T, ctx context.Context, keys *sidecartest.SmtpReportKeyFixture, view sidecar.GkmAuthView) (*smtpedgeservice.SmtpReportSealKey, error) {
	t.Helper()
	reply, err := keys.DropKeyReply(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	return smtpedgeservice.CheckSmtpReportSealKey(view, keys.RepoId, reply, keys.Clock.Now(), sidecar.DefaultGkmSettings().DropKeyLifetime)
}

// The drop key's public half of a generation, the newest for 0.
func reportDropPublicKey(t *testing.T, ctx context.Context, keys *sidecartest.SmtpReportKeyFixture, generation uint64) []byte {
	t.Helper()
	privateKey, err := keys.DropPrivateKey(ctx, generation)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey.PublicKey().Bytes()
}

func TestReportSealKeyIsTheNewestGenerationsDropKey(t *testing.T) {
	ctx, keys := newReportKeyFixture(t)
	key, err := checkReportKey(t, ctx, keys, keys.View())
	if err != nil {
		t.Fatal(err)
	}
	if key.RepoId != keys.RepoId || key.Generation != 1 || !bytes.Equal(key.PublicKey, reportDropPublicKey(t, ctx, keys, 1)) {
		t.Fatalf("generation %d's key, not generation 1's drop key", key.Generation)
	}
	if !key.NotAfter.Equal(keys.Clock.Now().Add(sidecar.DefaultGkmSettings().DropKeyLifetime).Truncate(time.Millisecond)) {
		t.Fatalf("not after %v", key.NotAfter)
	}
	// a rotation: the answer holds both, and the newest is sealed to
	keys.Clock.Advance(time.Minute)
	if err := keys.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	key, err = checkReportKey(t, ctx, keys, keys.View())
	if err != nil {
		t.Fatal(err)
	}
	if key.Generation != 2 || !bytes.Equal(key.PublicKey, reportDropPublicKey(t, ctx, keys, 2)) || bytes.Equal(key.PublicKey, reportDropPublicKey(t, ctx, keys, 1)) {
		t.Fatalf("generation %d's key after a rotation", key.Generation)
	}
	// an answer of the newest alone, as a since past its parent asks, has no parent to chain it on and seals nothing
	reply, err := keys.DropKeyReply(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := smtpedgeservice.CheckSmtpReportSealKey(keys.View(), keys.RepoId, reply, keys.Clock.Now(), sidecar.DefaultGkmSettings().DropKeyLifetime); !errors.Is(err, smtpedgeservice.ErrSmtpReportKeyNone) {
		t.Fatalf("a generation past 1 with no parent to chain on: %v", err)
	}
}

func TestReportSealKeyStopsAtARemovalItsGenerationDoesNotCover(t *testing.T) {
	ctx, keys := newReportKeyFixture(t)
	key, err := checkReportKey(t, ctx, keys, keys.View())
	if err != nil {
		t.Fatal(err)
	}
	// a reader removed: holders_shrunk_at passes generation 1's pin, so neither the cached key nor gkm's answer seals
	keys.Clock.Advance(time.Minute)
	view := keys.Shrink()
	if err := key.Check(view, keys.Clock.Now()); !errors.Is(err, smtpedgeservice.ErrSmtpReportKeyNone) {
		t.Fatalf("a cached key past a removal it does not cover: %v", err)
	}
	if _, err := checkReportKey(t, ctx, keys, view); !errors.Is(err, smtpedgeservice.ErrSmtpReportKeyNone) {
		t.Fatalf("gkm's newest past a removal it does not cover: %v", err)
	}
	// the writer's rotation from that state covers it, cause REMOVE
	if err := keys.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	key, err = checkReportKey(t, ctx, keys, view)
	if err != nil {
		t.Fatal(err)
	}
	if key.Generation != 2 || !bytes.Equal(key.PublicKey, reportDropPublicKey(t, ctx, keys, 2)) {
		t.Fatalf("generation %d after the covering rotation", key.Generation)
	}
}

func TestReportSealKeyRefusesALapsedDropKey(t *testing.T) {
	ctx, keys := newReportKeyFixture(t)
	key, err := checkReportKey(t, ctx, keys, keys.View())
	if err != nil {
		t.Fatal(err)
	}
	keys.Clock.AdvanceTo(key.NotAfter.Add(-time.Millisecond))
	if err := key.Check(keys.View(), keys.Clock.Now()); err != nil {
		t.Fatalf("a key a millisecond before its expiry: %v", err)
	}
	keys.Clock.AdvanceTo(key.NotAfter)
	if err := key.Check(keys.View(), keys.Clock.Now()); !errors.Is(err, smtpedgeservice.ErrSmtpReportKeyNone) {
		t.Fatalf("a key at its expiry: %v", err)
	}
	if _, err := checkReportKey(t, ctx, keys, keys.View()); !errors.Is(err, smtpedgeservice.ErrSmtpReportKeyNone) {
		t.Fatalf("gkm's newest at its expiry: %v", err)
	}
}

func TestReportSealKeyRefusesAGenRotateTheStatesDevicesDidNotSign(t *testing.T) {
	ctx, keys := newReportKeyFixture(t)
	reply, err := keys.DropKeyReply(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	check := func(signed *bridge.Signed) error {
		_, err := smtpedgeservice.CheckSmtpReportSealKey(keys.View(), keys.RepoId, &protocol.GkmGenerationsReply{Generations: []*bridge.Signed{signed}}, keys.Clock.Now(), sidecar.DefaultGkmSettings().DropKeyLifetime)
		return err
	}
	// a drop key of a server's making in place of the device's, the signature left as it was
	rotate := &protocol.GenRotate{}
	if err := proto.Unmarshal(reply.GetGenerations()[0].GetBody(), rotate); err != nil {
		t.Fatal(err)
	}
	stranger, err := sidecartest.NewSmtpReportKeyFixture(ctx, keys.Clock, nil)
	if err != nil {
		t.Fatal(err)
	}
	rotate.DropPublicKey = reportDropPublicKey(t, ctx, stranger, 1)
	swapped := proto.Clone(reply.GetGenerations()[0]).(*bridge.Signed)
	swappedBody, err := proto.MarshalOptions{Deterministic: true}.Marshal(rotate)
	if err != nil {
		t.Fatal(err)
	}
	swapped.Body = swappedBody
	if err := check(swapped); !errors.Is(err, smtpedgeservice.ErrSmtpReportKeyNone) {
		t.Fatalf("a GenRotate whose drop key was swapped: %v", err)
	}
	// the same statement signed anew by a sidecar the state never admitted
	signer := sidecartest.NewFakeGkmSigner()
	resigned, err := signer.Sign("gen-rotate", bridge.SignedType_SIGNED_GEN_ROTATE, swapped.GetBody(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := check(resigned); !errors.Is(err, smtpedgeservice.ErrSmtpReportKeyNone) {
		t.Fatalf("a GenRotate an unadmitted sidecar signed: %v", err)
	}
	// and the device's own, untouched, verifies
	if err := check(reply.GetGenerations()[0]); err != nil {
		t.Fatalf("the device's own GenRotate: %v", err)
	}
}

func TestReportSealKeyRefusesAnotherReposLadder(t *testing.T) {
	ctx, keys := newReportKeyFixture(t)
	reply, err := keys.DropKeyReply(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := smtpedgeservice.CheckSmtpReportSealKey(keys.View(), sidecar.NewId(), reply, keys.Clock.Now(), sidecar.DefaultGkmSettings().DropKeyLifetime); !errors.Is(err, smtpedgeservice.ErrSmtpReportKeyNone) {
		t.Fatalf("another repo's generations: %v", err)
	}
	// generations that do not rise
	keys.Clock.Advance(time.Minute)
	if err := keys.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	reply, err = keys.DropKeyReply(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	reversed := &protocol.GkmGenerationsReply{Generations: []*bridge.Signed{reply.GetGenerations()[1], reply.GetGenerations()[0]}}
	if _, err := smtpedgeservice.CheckSmtpReportSealKey(keys.View(), keys.RepoId, reversed, keys.Clock.Now(), sidecar.DefaultGkmSettings().DropKeyLifetime); !errors.Is(err, smtpedgeservice.ErrSmtpReportKeyNone) {
		t.Fatalf("generations out of order: %v", err)
	}
	// gkm serving nothing
	if _, err := smtpedgeservice.CheckSmtpReportSealKey(keys.View(), keys.RepoId, &protocol.GkmGenerationsReply{}, keys.Clock.Now(), sidecar.DefaultGkmSettings().DropKeyLifetime); !errors.Is(err, smtpedgeservice.ErrSmtpReportKeyNone) {
		t.Fatalf("no generation: %v", err)
	}
}

func TestReportSealKeyWaitsForAStateBehindTheGeneration(t *testing.T) {
	ctx, keys := newReportKeyFixture(t)
	keys.Clock.Advance(time.Minute)
	keys.Shrink()
	if err := keys.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	// a verifier still at position 1, below generation 2's pin
	if _, err := checkReportKey(t, ctx, keys, keys.ViewAt(1)); !errors.Is(err, smtpedgeservice.ErrSmtpReportKeyUnavailable) {
		t.Fatalf("a state behind the newest generation: %v", err)
	}
	if _, err := checkReportKey(t, ctx, keys, nil); !errors.Is(err, smtpedgeservice.ErrSmtpReportKeyUnavailable) {
		t.Fatalf("no state: %v", err)
	}
	// a generation whose time is past this clock's allowance waits too
	key, err := checkReportKey(t, ctx, keys, keys.View())
	if err != nil {
		t.Fatal(err)
	}
	reply, err := keys.DropKeyReply(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := smtpedgeservice.CheckSmtpReportSealKey(keys.View(), keys.RepoId, reply, key.Time.Add(-time.Hour), sidecar.DefaultGkmSettings().DropKeyLifetime); !errors.Is(err, smtpedgeservice.ErrSmtpReportKeyUnavailable) {
		t.Fatalf("a generation from this clock's future: %v", err)
	}
}

// api's report-key route over a fixture for networkId, as api answers it with no cache: gkm's whole answer checked at
// the fixture's newest state, on bearer alone. Counts its calls.
type reportKeyApi struct {
	server *httptest.Server
	calls  atomic.Int64
}

func newReportKeyApi(t *testing.T, keys *sidecartest.SmtpReportKeyFixture, networkId sidecar.Id, bearer string) *reportKeyApi {
	t.Helper()
	self := &reportKeyApi{}
	self.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		self.calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+bearer {
			http.Error(w, "", http.StatusForbidden)
			return
		}
		answer := smtpedgeservice.NewSmtpReportKeyReply(nil)
		if r.URL.Path == smtpedgeservice.SmtpReportKeyGatePath+networkId.String() {
			reply, err := keys.DropKeyReply(r.Context(), 0)
			if err != nil {
				http.Error(w, "", http.StatusServiceUnavailable)
				return
			}
			key, err := smtpedgeservice.CheckSmtpReportSealKey(keys.View(), keys.RepoId, reply, keys.Clock.Now(), sidecar.DefaultGkmSettings().DropKeyLifetime)
			switch {
			case errors.Is(err, smtpedgeservice.ErrSmtpReportKeyUnavailable):
				http.Error(w, "", http.StatusServiceUnavailable)
				return
			case err == nil:
				answer = smtpedgeservice.NewSmtpReportKeyReply(key)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(answer)
	}))
	t.Cleanup(self.server.Close)
	return self
}

// The block's source on api at apiUrl.
func newReportKeyGateSource(t *testing.T, apiUrl string, bearer string, clock sidecar.Clock) *smtpedgeservice.SmtpReportKeyGateSource {
	t.Helper()
	source, err := smtpedgeservice.NewSmtpReportKeyGateSource(&smtpedgeservice.SmtpReportKeyGateSourceArgs{ApiUrl: apiUrl, Bearer: bearer, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func TestReportIntakeSealsToTheNetworkMailKeyThroughApisRoute(t *testing.T) {
	ctx, keys := newReportKeyFixture(t)
	ti := newTestIntake(t, false)
	networkId := sidecar.NewId()
	api := newReportKeyApi(t, keys, networkId, "platform-bearer")
	source := newReportKeyGateSource(t, api.server.URL, "platform-bearer", keys.Clock)
	intake, err := smtpedgeservice.NewSmtpReportIntake(ti.host.ServiceHost(), ti.store, &smtpedgeservice.SmtpReportIntakeDeps{
		Tokens: ti.tokens, Labels: ti.labels, Keys: source, Txt: ti.txt, Sink: ti.sink, Log: ti.log,
	}, testSettings())
	if err != nil {
		t.Fatal(err)
	}
	recipient := ti.tokens.Add(networkId) + "@rpt.report.example"
	accept := func(reportId string) ([]byte, *smtpedgeservice.SmtpComplaint) {
		t.Helper()
		raw := dmarcAggregate(ti.reporterKey, recipient, "reporter.example", reportId, intakeDmarcRecords())
		before := len(ti.store.Complaints())
		outcome, err := intake.Accept(ctx, &smtpedgeservice.SmtpReportMessage{Recipient: recipient, ArrivalTime: ti.arrival, Raw: raw})
		if err != nil || outcome != smtpedgeservice.SmtpReportOutcomeCounted {
			t.Fatalf("%s: %s %v", reportId, outcome, err)
		}
		complaints := ti.store.Complaints()
		if len(complaints) == before {
			return raw, nil
		}
		return raw, complaints[len(complaints)-1]
	}

	// sealed to generation 1's drop key, which its readers' device opens
	raw, home := accept("report-k1")
	if home == nil || home.Type != smtpedgeservice.SmtpComplaintTypeRua || home.NetworkId != networkId {
		t.Fatalf("no sealed copy: %+v", home)
	}
	firstKey, err := keys.DropPrivateKey(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := smtpedgeservice.OpenSealedReport(firstKey, networkId, ti.arrival, home.SealedReport)
	if err != nil || !bytes.Equal(opened, raw) {
		t.Fatalf("the copy does not open under the network mail key: %v", err)
	}
	if opened, err := sidecartest.OpenSmtpSealedReportFixture(firstKey, networkId, ti.arrival, home.SealedReport); err != nil || !bytes.Equal(opened, raw) {
		t.Fatalf("the copy does not open under the fixture's reading of the format: %v", err)
	}

	// a removal generation 1 does not cover: the next report's counts are kept and its raw bytes dropped unread
	keys.Clock.Advance(time.Minute)
	keys.Shrink()
	if _, home := accept("report-k2"); home != nil {
		t.Fatal("a copy sealed past a removal the key does not cover")
	}
	if len(ti.store.Aggregates()) != 2 {
		t.Fatal("the uncovered report's counts were not kept")
	}

	// the covering rotation: sealed to generation 2's key, which generation 1's does not open
	if err := keys.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	raw, home = accept("report-k3")
	if home == nil {
		t.Fatal("no copy after the covering rotation")
	}
	secondKey, err := keys.DropPrivateKey(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := smtpedgeservice.OpenSealedReport(secondKey, networkId, ti.arrival, home.SealedReport); err != nil || !bytes.Equal(opened, raw) {
		t.Fatalf("the copy does not open under generation 2's key: %v", err)
	}
	if _, err := smtpedgeservice.OpenSealedReport(firstKey, networkId, ti.arrival, home.SealedReport); !errors.Is(err, smtpedgeservice.ErrSmtpSealedReportOpen) {
		t.Fatal("a removed reader's generation opens a later copy")
	}
	if api.calls.Load() != 3 {
		t.Fatalf("%d reads of api's route for three reports", api.calls.Load())
	}

	// api not telling now: the report is asked again, and nothing is stored
	api.server.Close()
	before := len(ti.store.Aggregates())
	rawLater := dmarcAggregate(ti.reporterKey, recipient, "reporter.example", "report-k4", intakeDmarcRecords())
	if _, err := intake.Accept(ctx, &smtpedgeservice.SmtpReportMessage{Recipient: recipient, ArrivalTime: ti.arrival, Raw: rawLater}); err == nil {
		t.Fatal("a report taken while api did not answer")
	}
	if len(ti.store.Aggregates()) != before {
		t.Fatal("a report counted while its key could not be read")
	}
}

func TestReportKeyGateSourceReadsApisAnswer(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	networkId := sidecar.NewId()
	ctx, keys := newReportKeyFixture(t)
	publicKey := reportDropPublicKey(t, ctx, keys, 1)
	var answer atomic.Pointer[string]
	var seenPath atomic.Pointer[string]
	var seenBearer atomic.Pointer[string]
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, bearer := r.URL.Path, r.Header.Get("Authorization")
		seenPath.Store(&path)
		seenBearer.Store(&bearer)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(*answer.Load()))
	}))
	defer server.Close()
	source := newReportKeyGateSource(t, server.URL, "platform-bearer", clock)
	set := func(reply *smtpedgeservice.SmtpReportKeyReply) {
		body, err := json.Marshal(reply)
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		answer.Store(&text)
	}

	notAfter := clock.Now().Add(time.Hour)
	set(&smtpedgeservice.SmtpReportKeyReply{PublicKey: publicKey, Generation: 1, NotAfterMs: notAfter.UnixMilli()})
	key, err := source.ReportSealKey(ctx, networkId)
	if err != nil || !bytes.Equal(key, publicKey) {
		t.Fatalf("a key: %v", err)
	}
	if *seenPath.Load() != smtpedgeservice.SmtpReportKeyGatePath+networkId.String() || *seenBearer.Load() != "Bearer platform-bearer" {
		t.Fatalf("asked %s", *seenPath.Load())
	}
	// none
	set(smtpedgeservice.NewSmtpReportKeyReply(nil))
	if key, err := source.ReportSealKey(ctx, networkId); err != nil || key != nil {
		t.Fatalf("none: %v", err)
	}
	// a key that lapsed after api answered is none
	clock.AdvanceTo(notAfter)
	set(&smtpedgeservice.SmtpReportKeyReply{PublicKey: publicKey, Generation: 1, NotAfterMs: notAfter.UnixMilli()})
	if key, err := source.ReportSealKey(ctx, networkId); err != nil || key != nil {
		t.Fatalf("a lapsed key: %v", err)
	}
}

func TestReportKeyGateSourceTellsNothingFromARefusalOrABadAnswer(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	ctx, keys := newReportKeyFixture(t)
	publicKey := reportDropPublicKey(t, ctx, keys, 1)
	notAfterMs := clock.Now().Add(time.Hour).UnixMilli()
	reply := func(value *smtpedgeservice.SmtpReportKeyReply) string {
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	redirected := atomic.Bool{}
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			redirected.Store(true)
		}
	}))
	defer elsewhere.Close()
	cases := []struct {
		name   string
		status int
		body   string
		header map[string]string
	}{
		{name: "unavailable", status: http.StatusServiceUnavailable},
		{name: "refused", status: http.StatusForbidden},
		{name: "redirect", status: http.StatusFound, header: map[string]string{"Location": elsewhere.URL}},
		{name: "not json", status: http.StatusOK, body: "<html>"},
		{name: "a field beyond the format", status: http.StatusOK, body: `{"public_key":"","repo_id":"x"}`},
		{name: "a second value", status: http.StatusOK, body: reply(&smtpedgeservice.SmtpReportKeyReply{}) + "{}"},
		{name: "none naming a generation", status: http.StatusOK, body: reply(&smtpedgeservice.SmtpReportKeyReply{Generation: 3})},
		{name: "a key with no expiry", status: http.StatusOK, body: reply(&smtpedgeservice.SmtpReportKeyReply{PublicKey: publicKey, Generation: 1})},
		{name: "no X-Wing key", status: http.StatusOK, body: reply(&smtpedgeservice.SmtpReportKeyReply{PublicKey: publicKey[:100], Generation: 1, NotAfterMs: notAfterMs})},
		{name: "past the bound", status: http.StatusOK, body: `{"public_key":"` + strings.Repeat("A", 9*1024) + `"}`},
	}
	for _, c := range cases {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for name, value := range c.header {
				w.Header().Set(name, value)
			}
			w.WriteHeader(c.status)
			w.Write([]byte(c.body))
		}))
		source := newReportKeyGateSource(t, server.URL, "platform-bearer", clock)
		key, err := source.ReportSealKey(ctx, sidecar.NewId())
		server.Close()
		if !errors.Is(err, smtpedgeservice.ErrSmtpReportKeyUnavailable) || key != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if err != nil && strings.Contains(err.Error(), "platform-bearer") {
			t.Errorf("%s: the error names the bearer", c.name)
		}
	}
	if redirected.Load() {
		t.Fatal("the bearer followed a redirect")
	}
	for _, args := range []*smtpedgeservice.SmtpReportKeyGateSourceArgs{
		{ApiUrl: "https://api.example", Bearer: ""},
		{ApiUrl: "https://api.example/", Bearer: "b"},
		{ApiUrl: "ftp://api.example", Bearer: "b"},
		{ApiUrl: "https://api.example", Bearer: "b", Settings: &smtpedgeservice.SmtpReportKeyGateSettings{}},
	} {
		if _, err := smtpedgeservice.NewSmtpReportKeyGateSource(args); err == nil {
			t.Errorf("a source of %+v", args)
		}
	}
}
