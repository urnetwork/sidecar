//go:build sidecar_testhooks

// §22.8's clocks ±10 min (TEST-M2-16), two of its three clauses; the ticket's runs in the root, where the listener's
// registrar is (socket_listen_skew_test.go).
//
// A push's time bound (§11.8's 5b), on the evs world: a writer and a reader whose clocks each run 10 min fast, 10 min
// slow or true, against evs on the shared clock, which chrony holds within 50 ms of UTC (§19.6). Every pairing commits,
// the reader verifies what the writer wrote, and no device alarms, since 5b's bound takes a time_ms within 10 min either
// way. Past the bound nothing commits and nothing is silent: a writer 1 s past it behind is refused TIME_STALE, recorded,
// at each rebuild its client makes under a fresh push id, and then waits once the head's refusal records are full; one
// 1 s past it ahead gets 429 TIME_AHEAD, which refuses nothing, until its retries run out. The schedules hold no barrier,
// but the world's rows build with sidecar_testhooks, and so does this.
//
// A token (§7.4, §7.8; QD-757): a strict_exp sidecar, enrolled and bound, whose clock runs 10 min fast, 10 min slow or
// true, against the api on the shared clock, which holds a DPoP proof's iat within 60 s of its own. At each pairing the
// sidecar exchanges at POST /oauth/token, renews at GET /auth/refresh and mints a child at POST /network/auth-client,
// each proof signed by the api's clock as the api's answers give it, and a service token is never kept past its expiry
// at its audience. The sidecar runs as a daemon does, on no schedule's baton, so this clause is a test of its own
// beside the schedules, as FS-97's device is.

package fault

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Runs build's schedule for pairing on a Net of its own, failing t with the pairing and the trace.
func runClockSkewPairing(t *testing.T, pairing *ClockSkewPairing, build func(net *Net, pairing *ClockSkewPairing) *Schedule) {
	t.Helper()
	net := sidecartest.NewNet(t.Context(), sidecartest.DefaultNetSettings())
	defer net.Close()
	if result := Run(t.Context(), build(net, pairing), net); result.Err != nil {
		t.Errorf("pairing %s: %s", pairing, result)
	}
}

// writerA writes and overwrites a path on its clock and the reader verifies each version on its own: the repo is set up
// on the shared clock, and only then are the device clocks offset.
func clockSkewPushSchedule(net *Net, pairing *ClockSkewPairing) *Schedule {
	world := NewEvsWorld(net, nil)
	steps := []*Step{{Actor: "writerA", Action: world.Setup}}
	steps = append(steps, ClockSkewSteps(pairing)...)
	steps = append(steps,
		&Step{Actor: "writerA", Action: world.Write("writerA", "skew.txt", EvsWorldContent("skew first", 300))},
		&Step{Actor: "reader", Action: world.Verify("reader", "skew.txt")},
		&Step{Actor: "writerA", Action: world.Write("writerA", "skew.txt", EvsWorldContent("skew second", 300))},
		&Step{Actor: "reader", Action: world.Verify("reader", "skew.txt")},
		&Step{Actor: "check", Action: world.ExpectCommitted("writerA", "skew.txt")},
	)
	return &Schedule{Id: "skew push " + pairing.String(), Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2}}
}

func TestClockSkewPushTimeBoundHoldsInEveryPairing(t *testing.T) {
	skew, err := NewClockSkew(nil, "writerA", "reader")
	if err != nil {
		t.Fatal(err)
	}
	pairings := skew.Pairings()
	if len(pairings) != 9 || !pairings[0].Unskewed() {
		t.Fatalf("pairings %v", pairings)
	}
	for _, pairing := range pairings {
		runClockSkewPairing(t, pairing, clockSkewPushSchedule)
	}
}

// A writer whose clock is offset past 5b's bound: its write commits nothing, every answer it got is an explicit one
// naming the bound, code (TIME_STALE behind, which records each statement's refusal and has the client rebuild under a
// new push id, TIME_AHEAD ahead, which refuses nothing and has it retry the same bytes), or a 429 that refuses nothing
// once the head's refusal records are full, and the head does not move.
func clockSkewPastTheBoundSchedule(net *Net, offset time.Duration) *Schedule {
	world := NewEvsWorld(net, nil)
	code := protocol.EvsRefusalCode_EVS_REFUSAL_TIME_AHEAD
	status := http.StatusTooManyRequests
	if offset < 0 {
		code = protocol.EvsRefusalCode_EVS_REFUSAL_TIME_STALE
		status = http.StatusConflict
	}
	// the head and writerA's pushes before the skewed write
	headVersion := uint64(0)
	pushCount := 0
	readHead := func(ctx context.Context) (uint64, error) {
		head, err := world.Head(ctx)
		if err != nil || head == nil {
			return 0, err
		}
		return head.GetVersion(), nil
	}
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "kept.txt", EvsWorldContent("skew kept", 300))},
		{Actor: "check", Action: world.Expect("the head before the skewed write", func(ctx context.Context) error {
			version, err := readHead(ctx)
			headVersion = version
			pushCount = len(world.DevicePushes("writerA"))
			return err
		})},
		{Actor: "writerA", ClockOffset: offset},
		{Actor: "writerA", Action: world.WriteAny("writerA", "skewed.txt", EvsWorldContent("skew past the bound", 300))},
		{Actor: "check", Action: world.Expect("the skewed write committed nothing, and its answers name the bound", func(ctx context.Context) error {
			world.stateLock.Lock()
			writes := world.pathWrites["skewed.txt"]
			world.stateLock.Unlock()
			if len(writes) != 1 {
				return fmt.Errorf("the ledger holds %d writes of the skewed path", len(writes))
			}
			if writes[0].state == evsWorldWriteCommitted {
				return fmt.Errorf("the skewed write committed at v%d", writes[0].version)
			}
			if _, ok := sidecar.EvsErrorOf(writes[0].err); !ok {
				return fmt.Errorf("the skewed write ended %v, not an answer of evs's", writes[0].err)
			}
			namedCount := 0
			for _, push := range world.DevicePushes("writerA")[pushCount:] {
				for _, answer := range push.Answers {
					switch {
					case answer.Status == http.StatusOK:
						return fmt.Errorf("an answer %s committed a statement past the bound", answer)
					case answer.Status == status && answer.Code == code:
						namedCount += 1
					case answer.Status == http.StatusTooManyRequests:
						// the head's refusal records are full: a wait that refuses nothing
					default:
						return fmt.Errorf("an answer %s that names neither the bound nor a wait", answer)
					}
				}
			}
			if namedCount == 0 {
				return fmt.Errorf("no answer was %d %s", status, code)
			}
			return nil
		})},
		{Actor: "check", Action: world.Expect("the head did not move", func(ctx context.Context) error {
			version, err := readHead(ctx)
			if err != nil {
				return err
			}
			if version != headVersion {
				return fmt.Errorf("the head moved from v%d to v%d", headVersion, version)
			}
			return nil
		})},
		{Actor: "reader", Action: world.Verify("reader", "kept.txt")},
	}
	return &Schedule{Id: fmt.Sprintf("skew push past the bound %s", offset), Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2}}
}

func TestClockSkewPushPastTheBoundCommitsNothing(t *testing.T) {
	bound := DefaultClockSkewSettings().Skew
	for _, offset := range []time.Duration{-(bound + time.Second), bound + time.Second} {
		net := sidecartest.NewNet(t.Context(), sidecartest.DefaultNetSettings())
		result := Run(t.Context(), clockSkewPastTheBoundSchedule(net, offset), net)
		net.Close()
		if result.Err != nil {
			t.Errorf("offset %s: %s", offset, result)
		}
	}
}

// How long, in real time, one pairing's sidecar may take over any one wait: only a failure's bound, since connect's
// timers are real (X9).
const clockSkewTokenTimeout = 30 * time.Second

// Hands a sidecar's own api client to the test, as each of its components gets it (SidecarEnv.SidecarApi): the client
// that holds the generation's token and signs the ClientKey's proofs.
type clockSkewTokenComponent struct {
	stateLock sync.Mutex
	api       *sidecar.SidecarApi
	attached  chan struct{}
}

func (self *clockSkewTokenComponent) Name() string {
	return "skew-token-test"
}

func (self *clockSkewTokenComponent) Attach(env *sidecar.SidecarEnv) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.api = env.SidecarApi
	select {
	case <-self.attached:
	default:
		close(self.attached)
	}
	return nil
}

func (self *clockSkewTokenComponent) Close() {
}

// The newest generation's api client.
func (self *clockSkewTokenComponent) sidecarApi() *sidecar.SidecarApi {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.api
}

// One pairing of the token clause, on a Net of its own, closed before the next pairing's: laptop enrolls and binds on
// the shared clock, restarts on its pairing's, and then goes to each route that carries a proof. An error names what
// did not hold.
func runClockSkewTokenPairing(ctx context.Context, pairing *ClockSkewPairing) error {
	net := sidecartest.NewNet(ctx, sidecartest.DefaultNetSettings())
	defer net.Close()
	await := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(ctx, clockSkewTokenTimeout)
	}

	laptop, err := net.AddSidecar("laptop", nil)
	if err != nil {
		return err
	}
	laptop.Settings.Clock = pairing.Clock(net.Clock(), "laptop")
	if err := laptop.Restart(); err != nil {
		return err
	}
	onlineCtx, onlineCancel := await()
	defer onlineCancel()
	if err := laptop.AwaitState(onlineCtx, sidecar.SidecarStateOnline); err != nil {
		return fmt.Errorf("not Online on its own clock: %w", err)
	}
	component := &clockSkewTokenComponent{attached: make(chan struct{})}
	if _, err := laptop.Sidecar().AddComponent(component); err != nil {
		return err
	}
	select {
	case <-component.attached:
	case <-onlineCtx.Done():
		return fmt.Errorf("no generation attached the component")
	}
	record, ok := laptop.NetworkRecord()
	if !ok {
		return fmt.Errorf("no network record")
	}
	api := laptop.Api
	generation := laptop.Sidecar().Status().Generation

	// POST /oauth/token: a service token evs takes on the shared clock, kept to the end of its cache life and no longer
	serviceToken := func(what string) (string, error) {
		tokenCtx, tokenCancel := await()
		defer tokenCancel()
		accessToken, err := laptop.Sidecar().ServiceToken(tokenCtx, laptop.Settings.EvsUrl, nil)
		if err != nil {
			return "", fmt.Errorf("%s: %w", what, err)
		}
		principal, err := net.Fakes().Authenticator.Authenticate(tokenCtx, "evs", accessToken)
		if err != nil {
			return "", fmt.Errorf("%s: evs refuses the token the sidecar handed out: %w", what, err)
		}
		if !net.Clock().Now().Before(principal.ExpiresAt) {
			return "", fmt.Errorf("%s: a token past its expiry", what)
		}
		return accessToken, nil
	}
	first, err := serviceToken("the first exchange")
	if err != nil {
		return err
	}
	cacheTimeout := laptop.Settings.TokenRefreshSettings.ServiceTokenCacheTimeout
	net.Clock().Advance(cacheTimeout - time.Second)
	if cached, err := serviceToken("the token at the end of its cache life"); err != nil {
		return err
	} else if cached != first {
		return fmt.Errorf("a new service token inside the first one's cache life")
	}
	net.Clock().Advance(2 * time.Second)
	if next, err := serviceToken("the exchange after the cache life"); err != nil {
		return err
	} else if next == first {
		return fmt.Errorf("the first service token was kept past its cache life")
	}

	// GET /auth/refresh: the core's own refresher, at connect's report of a refused credential
	net.Clock().Advance(time.Hour)
	tokenCount := api.ClientTokenCount(record.ClientId)
	laptop.CloseAuthorization()
	deadline := time.After(clockSkewTokenTimeout)
	for renewed := false; !renewed; {
		// subscribed before the read, so a mint between them wakes the wait
		_, minted := api.Mints()
		if tokenCount < api.ClientTokenCount(record.ClientId) {
			renewed = true
			continue
		}
		select {
		case <-minted:
		case <-deadline:
			return fmt.Errorf("the api minted no renewed client token: GET /auth/refresh served %d requests", api.RouteCount("GET /auth/refresh"))
		}
	}
	if issuedAt, _, ok := api.NewestClientToken(record.ClientId); !ok || !issuedAt.Equal(net.Clock().Now()) {
		return fmt.Errorf("the renewed client token was issued at %s, not now on the api's clock", issuedAt)
	}

	// POST /network/auth-client: a child of the sidecar's own client, by its api client's proof
	mintCtx, mintCancel := await()
	defer mintCancel()
	sourceClientId := record.ClientId
	minted, err := component.sidecarApi().AuthClient(mintCtx, &sidecar.SidecarAuthClientArgs{
		SourceClientId:   &sourceClientId,
		DeviceSpec:       "synthetic",
		DeclaresNoEgress: true,
	})
	if err != nil {
		return fmt.Errorf("the child's mint: %w", err)
	}
	if _, childId, _, ok := api.TokenClient(minted.ByClientJwt); !ok || childId != minted.ClientId || childId == record.ClientId || !minted.StrictExp {
		return fmt.Errorf("the child's token names %s (%t), strict_exp %t", childId, ok, minted.StrictExp)
	}

	if status := laptop.Sidecar().Status(); status.State != sidecar.SidecarStateOnline || status.Generation != generation {
		return fmt.Errorf("the sidecar ended %s at generation %d", status.State, status.Generation)
	}
	return nil
}

// Whichever way the sidecar's clock runs, it exchanges, renews and mints under the api's 60 s window, the unskewed
// twin beside the two skewed pairings.
func TestClockSkewTokenRoutesHoldInEveryPairing(t *testing.T) {
	skew, err := NewClockSkew(nil, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if window := sidecartest.DefaultFakeApiSettings().DpopIatWindow; skew.Skew() <= window {
		t.Fatalf("a skew of %s fits the DPoP window of %s, so no pairing proves anything", skew.Skew(), window)
	}
	pairings := skew.Pairings()
	if len(pairings) != 3 || !pairings[0].Unskewed() {
		t.Fatalf("pairings %v", pairings)
	}
	for _, pairing := range pairings {
		if err := runClockSkewTokenPairing(t.Context(), pairing); err != nil {
			t.Errorf("pairing %s: %v", pairing, err)
		}
	}
}
