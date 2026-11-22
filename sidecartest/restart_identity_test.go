// A sidecar daemon restarted under its kept generation (§5.5, §5.9), the daemon's half of what QD-1174 settled for edges
// (TestEdgeClientPoolRestartedInPlaceReachesItsListenerAgain): the restarted Sidecar's client comes back under the
// same client id, as the generation its keychain keeps names it, while a peer that served it keeps its send sequence to
// that id and the contract that sequence holds, HMAC'd with the daemon's earlier Network provide key and committed to
// its earlier sequence certificate. A daemon that keeps its connect identity with the generation presents both again,
// so the peer's contract verifies and the restarted daemon's stream to the peer carries bytes both ways within
// RecoveryTimeout. One that drew fresh ones refuses the contract, and the peer's answers wait on its AckTimeout,
// connect's 60 s. A new generation, a new client, draws a connect identity of its own.
//
// The issuer commits each contract to its destination's certificate (Net.CommitSequenceCertificates), so the peer
// checks the certificate the restarted daemon presents, as it does on a platform. Real connect clients keep real
// timers, so the bounds are real time, each one a broken run's, never a sleep.
//
// The restarted daemon opens the stream, as the restarted edge does in the edge's test, so its own first sends start
// the pair's new TLS session. A restarted daemon that waits, its peer opening first over its stale session, is reached
// only after about two minutes here, kept identity or not: the peer's re-handshake with the restarted responder fails
// with a bad record MAC until connect's timeouts end the session. That is connect's per-peer session, not the contracts,
// and question daemon-restart-identity-passive-restart-handshake raises it.

package sidecartest

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
)

// The restart tests' bounds (QD-702).
type restartIdentitySettings struct {
	// How soon after the restarted daemon starts its stream must carry the peer's bytes back: above a resend of the
	// peer's held item, which backs off to connect's MaxResendInterval (8 s), and well below the AckTimeout (60 s) a
	// stale contract waits on.
	RecoveryTimeout time.Duration
	// Each step before the restart, and each wait for a state, a broken run's bound.
	StepTimeout time.Duration
	// The peer's stream target.
	Target string
}

func defaultRestartIdentitySettings() *restartIdentitySettings {
	return &restartIdentitySettings{
		RecoveryTimeout: 20 * time.Second,
		StepTimeout:     45 * time.Second,
		Target:          "restart-identity",
	}
}

// What a generation's client presents to its peers: its client id, its provide secret keys by mode and its sequence
// certificate.
type restartIdentityMaterial struct {
	clientId          connect.Id
	provideSecretKeys map[connectprotocol.ProvideMode][]byte
	tlsCertificatePem []byte
}

// The material of testSidecar's newest client.
func restartIdentityOf(t *testing.T, testSidecar *TestSidecar) *restartIdentityMaterial {
	t.Helper()
	netClient := testSidecar.Client()
	if netClient == nil {
		t.Fatalf("%s has no client", testSidecar.Name)
	}
	material := &restartIdentityMaterial{
		clientId:          netClient.ClientId,
		provideSecretKeys: netClient.Client.ContractManager().GetProvideSecretKeys(),
	}
	if manager := netClient.Client.EncryptionSessionManager(); manager != nil {
		material.tlsCertificatePem = manager.ProvideTlsCertificatePem()
	}
	if len(material.tlsCertificatePem) == 0 {
		t.Fatalf("%s's client presents no sequence certificate", testSidecar.Name)
	}
	if len(material.provideSecretKeys[connectprotocol.ProvideMode_Network]) == 0 {
		t.Fatalf("%s's client holds no Network provide key", testSidecar.Name)
	}
	return material
}

// Whether two clients present the same connect identity: the same certificate and the same key for every mode the
// first holds.
func (self *restartIdentityMaterial) same(other *restartIdentityMaterial) bool {
	if !bytes.Equal(self.tlsCertificatePem, other.tlsCertificatePem) {
		return false
	}
	for mode, key := range self.provideSecretKeys {
		if !bytes.Equal(key, other.provideSecretKeys[mode]) {
			return false
		}
	}
	return true
}

// Whether two clients share nothing of a connect identity: another certificate and another key for every mode both
// hold.
func (self *restartIdentityMaterial) disjoint(other *restartIdentityMaterial) bool {
	if bytes.Equal(self.tlsCertificatePem, other.tlsCertificatePem) {
		return false
	}
	for mode, key := range self.provideSecretKeys {
		if otherKey, ok := other.provideSecretKeys[mode]; ok && bytes.Equal(key, otherKey) {
			return false
		}
	}
	return true
}

// Opens a stream from opener's dispatcher to the target on peerId and waits for the peer's accept, both within ctx.
func restartIdentityOpen(t *testing.T, ctx context.Context, opener *SubprotocolSidecar, peerId connect.Id, target string, incomings <-chan *sidecar.StreamIncoming) (*sidecar.SubprotocolStream, *sidecar.StreamIncoming) {
	t.Helper()
	stream, err := opener.Subprotocol().OpenStream(ctx, sidecar.Id(peerId), &sidecar.StreamOpenRequest{Target: target})
	if err != nil {
		t.Fatalf("%s's open: %v", opener.Name, err)
	}
	select {
	case incoming := <-incomings:
		return stream, incoming
	case <-ctx.Done():
		t.Fatal("the peer never saw the open")
		return nil, nil
	}
}

// Reads exactly len(want) bytes from stream by deadline and fails unless they are want.
func restartIdentityRead(t *testing.T, stream *sidecar.SubprotocolStream, deadline time.Time, want string, what string) {
	t.Helper()
	if err := stream.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(stream, got); err != nil || string(got) != want {
		t.Fatalf("%s read %q, %v", what, got, err)
	}
}

// Stops subprotocolSidecar as a killed daemon is, runs whileStopped, then starts it again on its durable state alone,
// puts authority back as the network's verified state and the dispatcher's component back on it, as a daemon's host
// does at every start, and waits for the restarted generation's dispatcher. Answers when the start began.
func restartSubprotocolSidecar(t *testing.T, net *Net, subprotocolSidecar *SubprotocolSidecar, authority *FakeAuthority, whileStopped func()) time.Time {
	t.Helper()
	subprotocolSidecar.stop()
	whileStopped()
	attached := make(chan struct{})
	func() {
		subprotocolSidecar.stateLock.Lock()
		defer subprotocolSidecar.stateLock.Unlock()
		subprotocolSidecar.subprotocol = nil
		subprotocolSidecar.attached = attached
	}()
	startTime := time.Now()
	if err := subprotocolSidecar.start(); err != nil {
		t.Fatal(err)
	}
	running := subprotocolSidecar.Sidecar()
	running.InstallAuthority(authority)
	if _, err := running.AddComponent(&subprotocolComponent{owner: subprotocolSidecar}); err != nil {
		t.Fatal(err)
	}
	attachTimeout := net.settings.SubprotocolAttachTimeout
	if attachTimeout <= 0 {
		attachTimeout = DefaultNetSettings().SubprotocolAttachTimeout
	}
	select {
	case <-attached:
	case <-time.After(attachTimeout):
		t.Fatalf("%s: no dispatcher attached after the restart", subprotocolSidecar.Name)
	}
	return startTime
}

// The daemon closes mid-stream, as a crash or a SIGTERM ends it, and starts again on its durable state, so its client
// is the same generation's under the same id. The peer's last write before the restart is still waiting for its ack,
// so the peer's send sequence to that id lives through the restart with the contract it holds, as a live peer's does.
// The restarted daemon's stream to the peer opens, and carries bytes both ways, within RecoveryTimeout, and its client
// presents the provide keys and the sequence certificate it had.
func TestRestartedSidecarIsReachedAtOnceUnderItsKeptGeneration(t *testing.T) {
	settings := defaultRestartIdentitySettings()
	net := newTestNet(t)
	net.CommitSequenceCertificates()
	sidecars, authority, err := net.AddSubprotocolSidecars("daemon", "peer")
	if err != nil {
		t.Fatal(err)
	}
	daemon, peer := sidecars[0], sidecars[1]
	daemonClientId := daemon.ClientId()
	generation := daemon.Sidecar().Status().Generation
	incomings := make(chan *sidecar.StreamIncoming, 8)
	remove, err := peer.Subprotocol().Listen(settings.Target, func(ctx context.Context, incoming *sidecar.StreamIncoming) error {
		incomings <- incoming
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remove)

	stepCtx, cancelStep := context.WithTimeout(t.Context(), settings.StepTimeout)
	defer cancelStep()
	stream, incoming := restartIdentityOpen(t, stepCtx, daemon, peer.ClientId(), settings.Target, incomings)
	if _, err := incoming.Stream.Write([]byte("before")); err != nil {
		t.Fatal(err)
	}
	restartIdentityRead(t, stream, time.Now().Add(settings.StepTimeout), "before", "the daemon before the restart")
	before := restartIdentityOf(t, daemon.TestSidecar)

	// the daemon goes away mid-stream; the peer's next write waits for an ack the old process never sends
	restartTime := restartSubprotocolSidecar(t, net, daemon, authority, func() {
		if _, err := incoming.Stream.Write([]byte("held")); err != nil {
			t.Fatal(err)
		}
	})
	if daemon.ClientId() != daemonClientId || daemon.Sidecar().Status().Generation != generation {
		t.Fatal("the restarted daemon runs another generation")
	}
	recoveryCtx, cancelRecovery := context.WithDeadline(t.Context(), restartTime.Add(settings.RecoveryTimeout))
	defer cancelRecovery()
	restartedStream, restartedIncoming := restartIdentityOpen(t, recoveryCtx, daemon, peer.ClientId(), settings.Target, incomings)
	if _, err := restartedIncoming.Stream.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	restartIdentityRead(t, restartedStream, restartTime.Add(settings.RecoveryTimeout), "after", "the restarted daemon")
	if _, err := restartedStream.Write([]byte("daemon")); err != nil {
		t.Fatal(err)
	}
	restartIdentityRead(t, restartedIncoming.Stream, restartTime.Add(settings.RecoveryTimeout), "daemon", "the peer after the restart")
	t.Logf("the restarted daemon's stream carried bytes both ways %s after its start", time.Since(restartTime))

	after := restartIdentityOf(t, daemon.TestSidecar)
	if after.clientId != before.clientId || !before.same(after) || !after.same(before) {
		t.Error("the restarted generation's client presents another connect identity")
	}
	for _, mode := range []connectprotocol.ProvideMode{connectprotocol.ProvideMode_Service, connectprotocol.ProvideMode_FriendsAndFamily} {
		if len(after.provideSecretKeys[mode]) == 0 {
			t.Errorf("the restarted client holds no kept %s key for a hold to provide", mode)
		}
	}
}

// A refused refresh ends generation 1, and the person's re-enrollment binds generation 2, a new client: its connect
// identity is its own, sharing no key or certificate with generation 1's, and a restart under generation 2 keeps it.
// The refusal comes before any restart: the fake clock keeps a stopped refresher's timer pending, which the refresh
// point's wait could take for the running one's.
func TestNewSidecarGenerationDrawsAFreshConnectIdentity(t *testing.T) {
	settings := defaultRestartIdentitySettings()
	net := newTestNet(t)
	ctx, cancel := context.WithTimeout(t.Context(), settings.StepTimeout)
	defer cancel()
	daemon := addCoreSidecar(t, net, "daemon")
	first := restartIdentityOf(t, daemon)

	record := coreNetworkRecord(t, daemon)
	daemon.Api.RefuseRefresh(record.ClientId)
	advancePastRefreshPoint(t, net, daemon, record.ClientId)
	if err := daemon.AwaitStateReason(ctx, sidecar.SidecarStateUnenrolled, sidecar.SidecarReasonRefused); err != nil {
		t.Fatal(err)
	}
	if err := daemon.Enroll(ctx, record.NetworkId); err != nil {
		t.Fatal(err)
	}
	if err := daemon.AwaitState(ctx, sidecar.SidecarStateOnline); err != nil {
		t.Fatal(err)
	}
	if generation := daemon.Sidecar().Status().Generation; generation != 2 {
		t.Fatalf("generation %d", generation)
	}
	second := restartIdentityOf(t, daemon)
	if second.clientId == first.clientId || !first.disjoint(second) {
		t.Fatal("generation 2's client presents generation 1's connect identity")
	}

	if err := daemon.Restart(); err != nil {
		t.Fatal(err)
	}
	if err := daemon.AwaitState(ctx, sidecar.SidecarStateOnline); err != nil {
		t.Fatal(err)
	}
	if restarted := restartIdentityOf(t, daemon); restarted.clientId != second.clientId || !second.same(restarted) {
		t.Fatal("a restart under generation 2 drew another connect identity")
	}
	requireS1Clean(t, net)
}
