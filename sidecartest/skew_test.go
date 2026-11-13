// §22.8's clocks ±10 min on a token (TEST-M2-16; §7.4, §7.8): a sidecar whose clock runs 10 min fast, 10 min slow or
// true, against the Net's api on the shared clock. A service token is kept for at most ServiceTokenCacheTimeout of the
// sidecar's own time and its expires_in, both lengths rather than times, so whichever way its clock runs it never
// presents one its audience finds expired, and it trades for a new one at the end of each cache life. The exchange
// and the client token's renewal prove the ClientKey by DPoP, whose iat §7.4 holds within ±60 s of the api's clock:
// the sidecar signs iat by the api's clock, which each of api's answers gives it in its Date (QD-757), so a sidecar
// 10 min off exchanges and renews under that window as the unskewed twin does. The window itself stands: a client
// that cannot read the api's clock stays refused (the root's TestSkewedSidecarApiWithNoDateStaysRefused), and a proof
// replayed is refused (TestSkewedSidecarApiExchangesWithTheFakeApi).
//
// A push's time bound runs on the evs world (fault/skew_test.go), where the token clause's three routes also run as
// one row, and a ticket on the listener's registrar and admission in the root (socket_listen_skew_test.go).

package sidecartest

import (
	"context"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// How long, in real time, a sidecar here may take to come back Online: only a failure's bound, since connect's timers
// are real (X9).
const testSkewOnlineTimeout = 30 * time.Second

// A Net whose api holds a DPoP iat within production's window, §7.4's 60 s, and a sidecar enrolled on it at the shared
// clock and then restarted on its pairing's clock, Online. The caller closes the Net, before the next pairing's, since
// a sidecar_testhooks build holds one Net at a time.
func newTestSkewSidecar(t *testing.T, skew *ClockSkew, pairing *ClockSkewPairing) (*Net, *TestSidecar) {
	t.Helper()
	if window := DefaultFakeApiSettings().DpopIatWindow; skew.Skew() <= window {
		t.Fatalf("a skew of %s fits the DPoP window of %s, so this pairing proves nothing", skew.Skew(), window)
	}
	net := NewNet(t.Context(), nil)
	testSidecar, err := net.AddSidecar("laptop", nil)
	if err != nil {
		net.Close()
		t.Fatal(err)
	}
	testSidecar.Settings.Clock = pairing.Clock(net.Clock(), "laptop")
	if err := testSidecar.Restart(); err != nil {
		net.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), testSkewOnlineTimeout)
	defer cancel()
	if err := testSidecar.AwaitState(ctx, sidecar.SidecarStateOnline); err != nil {
		net.Close()
		t.Fatalf("pairing %s: %v", pairing, err)
	}
	return net, testSidecar
}

// Whichever way the sidecar's clock runs, every service token it hands its components verifies at evs on the shared
// clock, the cached one up to the end of its cache life, and the one after it is new: each exchange is taken under
// the api's 60 s window.
func TestClockSkewServiceTokenExpiryHolds(t *testing.T) {
	skew, err := NewClockSkew(nil, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	for _, pairing := range skew.Pairings() {
		func() {
			net, testSidecar := newTestSkewSidecar(t, skew, pairing)
			defer net.Close()
			running := testSidecar.Sidecar()
			cacheTimeout := testSidecar.Settings.TokenRefreshSettings.ServiceTokenCacheTimeout
			if cacheTimeout <= time.Second {
				t.Fatalf("a cache timeout of %s leaves nothing to step through", cacheTimeout)
			}
			token := func(what string) string {
				t.Helper()
				accessToken, err := running.ServiceToken(t.Context(), testSidecar.Settings.EvsUrl, nil)
				if err != nil {
					t.Fatalf("pairing %s, %s: %v", pairing, what, err)
				}
				principal, err := net.Fakes().Authenticator.Authenticate(t.Context(), "evs", accessToken)
				if err != nil {
					t.Errorf("pairing %s, %s: evs refuses the token the sidecar handed out: %v", pairing, what, err)
				} else if principal.ExpiresAt.Sub(net.Clock().Now()) <= 0 {
					t.Errorf("pairing %s, %s: a token past its expiry", pairing, what)
				}
				return accessToken
			}
			first := token("the first token")
			net.Clock().Advance(cacheTimeout - time.Second)
			if cached := token("the token at the end of its cache life"); cached != first {
				t.Errorf("pairing %s: a new token inside the first one's cache life", pairing)
			}
			net.Clock().Advance(2 * time.Second)
			if next := token("the token after its cache life"); next == first {
				t.Errorf("pairing %s: the first token was kept past its cache life", pairing)
			}
		}()
	}
}

// Whichever way the sidecar's clock runs, it renews its client token at GET /auth/refresh under the api's 60 s
// window, when connect reports its credential refused and again after: the api mints each one, the sidecar stays
// Online on its generation, and the token it then exchanges with is the renewed one.
func TestClockSkewClientTokenRenews(t *testing.T) {
	skew, err := NewClockSkew(nil, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	for _, pairing := range skew.Pairings() {
		func() {
			net, testSidecar := newTestSkewSidecar(t, skew, pairing)
			defer net.Close()
			record, ok := testSidecar.NetworkRecord()
			if !ok {
				t.Fatalf("pairing %s: no network record", pairing)
			}
			api := testSidecar.Api
			generation := testSidecar.Sidecar().Status().Generation
			for i := range 2 {
				net.Clock().Advance(time.Hour)
				count := api.ClientTokenCount(record.ClientId)
				testSidecar.CloseAuthorization()
				if !testSkewAwaitClientTokenCount(api, record.ClientId, count+1) {
					t.Errorf("pairing %s, renewal %d: the api minted %d tokens for the client, not %d", pairing, i, api.ClientTokenCount(record.ClientId), count+1)
					return
				}
				if issuedAt, _, ok := api.NewestClientToken(record.ClientId); !ok || !issuedAt.Equal(net.Clock().Now()) {
					t.Errorf("pairing %s, renewal %d: the newest token was issued at %s", pairing, i, issuedAt)
				}
			}
			if status := testSidecar.Sidecar().Status(); status.State != sidecar.SidecarStateOnline || status.Generation != generation {
				t.Errorf("pairing %s: status %+v after the renewals", pairing, status)
			}
			if _, err := testSidecar.Sidecar().ServiceToken(t.Context(), testSidecar.Settings.EvsUrl, nil); err != nil {
				t.Errorf("pairing %s: the exchange after the renewals: %v", pairing, err)
			}
		}()
	}
}

// Waits until api has minted the client count tokens in all, false when it has not within testSkewOnlineTimeout.
func testSkewAwaitClientTokenCount(api *FakeApi, clientId sidecar.Id, count int) bool {
	deadline := time.After(testSkewOnlineTimeout)
	for {
		// subscribed before the read, so a mint between them wakes the wait
		_, minted := api.Mints()
		if count <= api.ClientTokenCount(clientId) {
			return true
		}
		select {
		case <-minted:
		case <-deadline:
			return false
		}
	}
}

// The pairings of a row: every actor at each of -skew, 0 and +skew, the unskewed twin first, and each pairing's clocks
// on the shared one.
func TestClockSkewPairingsCoverEveryOffset(t *testing.T) {
	skew, err := NewClockSkew(nil, "dialer", "listener")
	if err != nil {
		t.Fatal(err)
	}
	pairings := skew.Pairings()
	if len(pairings) != 9 || !pairings[0].Unskewed() || len(skew.SkewedPairings()) != 8 {
		t.Fatalf("%d pairings, %d skewed", len(pairings), len(skew.SkewedPairings()))
	}
	seen := map[[2]time.Duration]bool{}
	for _, pairing := range pairings {
		key := [2]time.Duration{pairing.Offset("dialer"), pairing.Offset("listener")}
		if seen[key] {
			t.Errorf("pairing %s twice", pairing)
		}
		seen[key] = true
		for _, actor := range skew.Actors {
			if offset := pairing.Offset(actor); offset != 0 && offset != skew.Skew() && offset != -skew.Skew() {
				t.Errorf("pairing %s offsets %s by %s", pairing, actor, offset)
			}
		}
	}
	if gap := pairings[len(pairings)-1].Gap("dialer", "listener"); gap != 0 {
		t.Errorf("the last pairing's gap is %s", gap)
	}
	widest := time.Duration(0)
	for _, pairing := range pairings {
		widest = max(widest, pairing.Gap("dialer", "listener"))
	}
	if widest != 2*skew.Skew() {
		t.Errorf("the widest gap is %s, not twice the skew", widest)
	}
	clock := NewFakeClock(DefaultClockStart())
	for _, pairing := range pairings {
		if got := pairing.Clock(clock, "listener").Now().Sub(clock.Now()); got != pairing.Offset("listener") {
			t.Errorf("pairing %s: the listener's clock reads %s off", pairing, got)
		}
	}
	if _, err := NewClockSkew(nil, "dialer", "dialer"); err == nil {
		t.Error("a row naming an actor twice")
	}
	if _, err := NewClockSkew(&ClockSkewSettings{Skew: 0}, "dialer"); err == nil {
		t.Error("a row with no skew")
	}
}
