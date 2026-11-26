// A sidecar daemon restarted under its kept generation and held between its client's becoming reachable and the
// Sidecar's own steps after the open: the daemon's half of the edge's
// TestEdgeClientPoolRestartedInPlaceTakesItsListenersContractAtOnce. A peer that served the daemon keeps its send
// sequence to the daemon's client id and the contract it holds, for Network and HMAC'd with the daemon's earlier
// Network provide key, and connect verifies a contract only under a mode its receiver provides. A generation asks its
// platform for Network, its dispatcher's own mode, from the start (SidecarPlatformClientArgs.ProvideModes), and the
// platform readies the client with it before anything can reach the client (ApplyProvide), so the first copy of the
// peer's contract that reaches the restarted client verifies with nothing from the Sidecar after the open. A
// generation that provided Network only once its platform client was open, as before 2026-11-26, would refuse that
// copy, and connect would drop the peer's sequence until the client's modes changed, which the held window keeps from
// happening. The Net's platform gives a client the modes its opener asked for and no other, as connect's platform does
// (netExchange.addReadiedClient), so such a generation's client would be handed over providing nothing.
//
// The peer's frames reach the restarted client only once the hold listens for them: the Net partitions the pair across
// the restart and the hold lifts the partition once its callback is on. A held client, which sends nothing, hears the
// peer's backlog at the peer's own resends, so the hold is bounded as the backlog's resend is, by RecoveryTimeout.

package sidecartest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
)

// The Net's platform for a restarted sidecar, handing the Sidecar the first client it opens only once hold has
// returned for it: the window between that client's becoming reachable and the generation's own steps after the open,
// held open as long as hold takes. Every later client is handed over at once. The Net's api transport is kept, which
// the Sidecar sends its api requests through (sidecar.SidecarApiPlatform).
type restartHeldPlatform struct {
	*netSidecarPlatform
	// never fails the open: a hold that finds something wrong reports it and still hands the client over, so the
	// restart goes on to its dispatcher and the test fails on what the hold found rather than at the attach's bound
	hold func(client *sidecar.SidecarPlatformClient)

	stateLock sync.Mutex
	held      bool
}

// The Net's client, the first one handed over only once hold has returned for it. See sidecar.SidecarPlatform.
func (self *restartHeldPlatform) OpenClient(ctx context.Context, args *sidecar.SidecarPlatformClientArgs) (*sidecar.SidecarPlatformClient, error) {
	client, err := self.netSidecarPlatform.OpenClient(ctx, args)
	if err != nil {
		return nil, err
	}
	first := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		first := !self.held
		self.held = true
		return first
	}()
	if first {
		self.hold(client)
	}
	return client, nil
}

// What a hold found, and when the peer's backlog reached the held client.
type restartHeldVerdict struct {
	err         error
	backlogTime time.Time
}

// The daemon closes mid-stream and starts again on its durable state, so its client is the same generation's under
// the same id, while the peer's last write waits for an ack the old process never sends. The restarted daemon's
// platform hands its generation the client only once the peer's backlog, that write, has reached the client, which
// takes the peer's Network contract with nothing from the Sidecar after the open: the client is handed over providing
// Network and nothing else, under the generation's kept key, and the peer's frames come in. Then the restarted daemon's
// own stream to the peer opens and carries bytes both ways within RecoveryTimeout.
func TestRestartedSidecarTakesItsPeersNetworkContractAtOnce(t *testing.T) {
	settings := defaultRestartIdentitySettings()
	net := newTestNet(t)
	if attachTimeout := net.settings.SubprotocolAttachTimeout; attachTimeout <= settings.RecoveryTimeout {
		// so a hold that runs to its bound is reported as itself, before the attach's wait gives up
		t.Fatalf("the dispatcher's attach timeout, %v, does not outlast the hold's bound, %v", attachTimeout, settings.RecoveryTimeout)
	}
	net.CommitSequenceCertificates()
	sidecars, authority, err := net.AddSubprotocolSidecars("daemon", "peer")
	if err != nil {
		t.Fatal(err)
	}
	daemon, peer := sidecars[0], sidecars[1]
	daemonClientId, peerClientId := daemon.ClientId(), peer.ClientId()
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
	stream, incoming := restartIdentityOpen(t, stepCtx, daemon, peerClientId, settings.Target, incomings)
	if _, err := incoming.Stream.Write([]byte("before")); err != nil {
		t.Fatal(err)
	}
	restartIdentityRead(t, stream, time.Now().Add(settings.StepTimeout), "before", "the daemon before the restart")
	networkKey := restartIdentityOf(t, daemon.TestSidecar).provideSecretKeys[connectprotocol.ProvideMode_Network]
	network := map[connectprotocol.ProvideMode]bool{connectprotocol.ProvideMode_Network: true}

	// sent once, before the hold hands the client over, so it is there once the dispatcher has attached
	verdicts := make(chan restartHeldVerdict, 1)
	hold := func(holdCtx context.Context, client *sidecar.SidecarPlatformClient) restartHeldVerdict {
		// the peer's frames reach the client again however the hold ends
		defer net.SetLink(peerClientId, daemonClientId, nil)
		contractManager := client.Client.ContractManager()
		key, ok := contractManager.GetProvideSecretKey(connectprotocol.ProvideMode_Network)
		if modes := contractManager.GetProvideModes(); !maps.Equal(modes, network) || !ok || !bytes.Equal(key, networkKey) {
			return restartHeldVerdict{err: fmt.Errorf("the restarted client was handed over providing %v, under its kept Network key: %t", modes, ok && bytes.Equal(key, networkKey))}
		}
		// a frame of the subprotocol is delivered only from a sequence whose contract verified, and only once the
		// client's new session with the peer has opened it
		backlog := make(chan time.Time, 1)
		remove, err := client.Client.AddSubprotocolRawCallback(sidecar.SubprotocolId, func(source connect.TransferPath, subprotocolId connect.SubprotocolId, messageBytes []byte, from connect.Peer) {
			if source.SourceId == peerClientId {
				select {
				case backlog <- time.Now():
				default:
				}
			}
		})
		if err != nil {
			return restartHeldVerdict{err: err}
		}
		defer remove()
		net.SetLink(peerClientId, daemonClientId, nil)
		select {
		case backlogTime := <-backlog:
			return restartHeldVerdict{backlogTime: backlogTime}
		case <-holdCtx.Done():
			return restartHeldVerdict{err: errors.New("the peer's backlog never reached the restarted client")}
		}
	}

	restartTime := restartSubprotocolSidecar(t, net, daemon, authority, func() {
		// the daemon went away mid-stream; the peer's next write waits for an ack the old process never sends
		if _, err := incoming.Stream.Write([]byte("held")); err != nil {
			t.Fatal(err)
		}
		// nothing of the peer's reaches the restarted client before the hold listens for it
		net.SetLink(peerClientId, daemonClientId, &LinkConditions{Partition: true})
		holdCtx, cancelHold := context.WithTimeout(t.Context(), settings.RecoveryTimeout)
		t.Cleanup(cancelHold)
		daemon.Settings.Connect.Platform = &restartHeldPlatform{
			netSidecarPlatform: daemon.platform,
			hold: func(client *sidecar.SidecarPlatformClient) {
				verdicts <- hold(holdCtx, client)
			},
		}
	})
	select {
	case verdict := <-verdicts:
		if verdict.err != nil {
			t.Fatal(verdict.err)
		}
		t.Logf("the peer's backlog reached the held restarted client %s after its start", verdict.backlogTime.Sub(restartTime))
	default:
		t.Fatal("the restarted generation's client was never held")
	}
	if daemon.ClientId() != daemonClientId || daemon.Sidecar().Status().Generation != generation {
		t.Fatal("the restarted daemon runs another generation")
	}

	recoveryTime := time.Now()
	recoveryCtx, cancelRecovery := context.WithDeadline(t.Context(), recoveryTime.Add(settings.RecoveryTimeout))
	defer cancelRecovery()
	restartedStream, restartedIncoming := restartIdentityOpen(t, recoveryCtx, daemon, peerClientId, settings.Target, incomings)
	if _, err := restartedIncoming.Stream.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	restartIdentityRead(t, restartedStream, recoveryTime.Add(settings.RecoveryTimeout), "after", "the restarted daemon")
	if _, err := restartedStream.Write([]byte("daemon")); err != nil {
		t.Fatal(err)
	}
	restartIdentityRead(t, restartedIncoming.Stream, recoveryTime.Add(settings.RecoveryTimeout), "daemon", "the peer after the restart")
	t.Logf("the restarted daemon's stream carried bytes both ways %s after the hold", time.Since(recoveryTime))
}
