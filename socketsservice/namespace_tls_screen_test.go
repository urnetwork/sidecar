// tls/'s screen row as ABUSE-M5-08 feeds it (§21.6, QD-188, QD-235): a host sent to review stays refused at each
// heartbeat with no read of the facts, so a re-check issues no query, and a reviewer's screen_allow, once it reaches
// the facts at their next read, lets the same registration pass.

package socketsservice_test

import (
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/socketsservice"
)

// A brand-plus-keyword host is refused through its review, every heartbeat inside FactsRefreshInterval answering
// from memory with the facts read once; the read after the interval carries the reviewer's allow, and the host
// passes from the heartbeat after it lands. A host the allow does not name stays refused.
func TestTlsListenScreenReadsNoQueryPerHeartbeat(t *testing.T) {
	scene := newTestTlsListenScene(t, nil)
	scene.setName("tls/443/apple-login")
	if err := scene.validate(); !errors.Is(err, socketsservice.ErrSocketListenRefused) {
		t.Fatalf("a host held for review answered %v", err)
	}
	if reads := scene.source.reads(); reads != 1 {
		t.Fatalf("%d reads to screen once", reads)
	}
	settings := socketsservice.DefaultTlsNamespaceSettings()
	// §9.5's heartbeats re-run the check: each answers from the held verdict, and none reads the facts
	heartbeatCount := 10
	for range heartbeatCount {
		scene.clock.Advance(settings.FactsRefreshInterval / time.Duration(heartbeatCount+1))
		if err := scene.hooks.ValidateListen(scene.ctx, scene.check); !errors.Is(err, socketsservice.ErrSocketListenRefused) {
			t.Fatalf("a heartbeat answered %v", err)
		}
	}
	if reads := scene.source.reads(); reads != 1 {
		t.Fatalf("%d reads across the heartbeats", reads)
	}

	// the reviewer's screen_allow reaches the facts: the next read carries it, the old verdict serving until it lands
	allowed := *scene.facts
	allowed.ScreenAllowedHosts = []string{"apple-login"}
	scene.source.set(scene.networkId, &allowed)
	scene.clock.Advance(settings.FactsRefreshInterval)
	if err := scene.hooks.ValidateListen(scene.ctx, scene.check); !errors.Is(err, socketsservice.ErrSocketListenRefused) {
		t.Fatalf("before the read landed answered %v", err)
	}
	scene.awaitLoads(2)
	if err := scene.hooks.ValidateListen(scene.ctx, scene.check); err != nil {
		t.Fatalf("the allowed host refused: %v", err)
	}
	if reads := scene.source.reads(); reads != 2 {
		t.Fatalf("%d reads after the refresh", reads)
	}
	// the allow names one host of the network
	scene.setName("tls/443/apple-support")
	if err := scene.hooks.ValidateListen(scene.ctx, scene.check); !errors.Is(err, socketsservice.ErrSocketListenRefused) {
		t.Fatalf("a host the allow does not name answered %v", err)
	}
	if verdict := sidecar.ScreenHost("apple-login", &sidecar.ScreenFacts{ReviewAllowed: true}); verdict != sidecar.ScreenVerdictAllow {
		t.Fatalf("the pure screen answered %v for an allowed host", verdict)
	}
}
