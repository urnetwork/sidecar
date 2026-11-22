//go:build !sidecar_http && !ios_extension && !js

// An edge restarted in place on sidecartest's Net (QD-1174, §13.6): EdgeClientPool's client comes back under the same
// client id, as api's derivation gives it, while a listener that served it keeps its send sequence to that id and the
// contract it holds. The Net's issuer signs each contract with the destination's live provide key, as CreateContract
// does, so the listener's contract is the old process's. A restarted pool whose client presents the same connect
// identity, which its source's seed derives (host_edge_identity.go), verifies that contract, and its next stream to the
// listener carries bytes both ways within RecoveryTimeout. A pool that drew a fresh identity refuses the contract, and
// the listener's answers wait on its AckTimeout, connect's 60 s, which is the blogger case's two-minute outage in small.
//
// Real connect clients keep real timers, so the bounds are real time, each one a broken run's, never a sleep.

package sidecar_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The restart test's bounds (QD-702).
type edgeRestartNetSettings struct {
	// How soon after the restarted pool is made its stream must carry the listener's bytes back: above a resend of the
	// listener's held item, which backs off to connect's MaxResendInterval (8 s), and well below the AckTimeout (60 s)
	// a stale contract waits on.
	RecoveryTimeout time.Duration
	// Each step before the restart, a broken run's bound.
	StepTimeout time.Duration
	// The listener's target, a tls/ name as a registration names it.
	Target string
}

func defaultEdgeRestartNetSettings() *edgeRestartNetSettings {
	return &edgeRestartNetSettings{
		RecoveryTimeout: 20 * time.Second,
		StepTimeout:     45 * time.Second,
		Target:          "tls/443/blog",
	}
}

// Opens a stream from the pool's first client to the listener and waits for the listener's accept, both within ctx.
func edgeRestartOpen(t *testing.T, ctx context.Context, pool *sidecar.EdgeClientPool, listenerId connect.Id, target string, incomings <-chan *sidecar.StreamIncoming) (*sidecar.SubprotocolStream, *sidecar.StreamIncoming) {
	t.Helper()
	stream, err := pool.Clients()[0].Subprotocol.OpenStream(ctx, sidecar.Id(listenerId), &sidecar.StreamOpenRequest{Target: target})
	if err != nil {
		t.Fatalf("the edge's open: %v", err)
	}
	select {
	case incoming := <-incomings:
		return stream, incoming
	case <-ctx.Done():
		t.Fatal("the listener never saw the open")
		return nil, nil
	}
}

// Reads exactly len(want) bytes from stream by deadline and fails unless they are want.
func edgeRestartRead(t *testing.T, stream *sidecar.SubprotocolStream, deadline time.Time, want string, what string) {
	t.Helper()
	if err := stream.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(stream, got); err != nil || string(got) != want {
		t.Fatalf("%s read %q, %v", what, got, err)
	}
}

// The edge's pool closes mid-stream, as a crash or a deploy's SIGTERM ends it, and is made again on the same source, so
// its client has the same id. The listener's last write before the restart is still waiting for its ack, so its send
// sequence to that id lives through the restart with the old process's contract, as a live listener's does. The
// restarted client's stream to the listener opens, and carries bytes both ways, within RecoveryTimeout.
func TestEdgeClientPoolRestartedInPlaceReachesItsListenerAgain(t *testing.T) {
	settings := defaultEdgeRestartNetSettings()
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	sidecars, _, err := net.AddSubprotocolSidecars("listener")
	if err != nil {
		t.Fatal(err)
	}
	listener := sidecars[0]
	listenerClientId := listener.ClientId()
	// a tls/ registration's hold: the listener provides Service while it listens (§6.10.1 item 2)
	release, err := listener.Subprotocol().HoldProvideMode(connectprotocol.ProvideMode_Service)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	incomings := make(chan *sidecar.StreamIncoming, 8)
	remove, err := listener.Subprotocol().Listen(settings.Target, func(ctx context.Context, incoming *sidecar.StreamIncoming) error {
		if !incoming.Edge {
			return &sidecar.StreamRejectError{}
		}
		incomings <- incoming
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remove)

	args, err := net.EdgeClientPoolArgs(sidecar.NewId())
	if err != nil {
		t.Fatal(err)
	}
	args.Settings = sidecar.DefaultEdgeClientPoolSettings()
	args.Settings.ClientCount = 1
	pool, err := sidecar.NewEdgeClientPool(t.Context(), args)
	if err != nil {
		t.Fatal(err)
	}
	edgeClientId := connect.Id(pool.Clients()[0].ClientId)
	// Service both ways, CreateContract's decision for a Find-recorded pair (§6.10.1 item 3)
	net.SetContractProvideMode(listenerClientId, edgeClientId, connectprotocol.ProvideMode_Service)
	net.SetContractProvideMode(edgeClientId, listenerClientId, connectprotocol.ProvideMode_Service)

	stepCtx, cancelStep := context.WithTimeout(t.Context(), settings.StepTimeout)
	defer cancelStep()
	stream, incoming := edgeRestartOpen(t, stepCtx, pool, listenerClientId, settings.Target, incomings)
	if _, err := incoming.Stream.Write([]byte("before")); err != nil {
		t.Fatal(err)
	}
	edgeRestartRead(t, stream, time.Now().Add(settings.StepTimeout), "before", "the edge before the restart")

	// the edge goes away mid-stream; the listener's next write waits for an ack that the old process never sends
	pool.Close()
	if _, err := incoming.Stream.Write([]byte("held")); err != nil {
		t.Fatal(err)
	}

	restartTime := time.Now()
	restarted, err := sidecar.NewEdgeClientPool(t.Context(), args)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.Close)
	if connect.Id(restarted.Clients()[0].ClientId) != edgeClientId {
		t.Fatal("the restarted pool's client took another id")
	}
	recoveryCtx, cancelRecovery := context.WithDeadline(t.Context(), restartTime.Add(settings.RecoveryTimeout))
	defer cancelRecovery()
	restartedStream, restartedIncoming := edgeRestartOpen(t, recoveryCtx, restarted, listenerClientId, settings.Target, incomings)
	if _, err := restartedIncoming.Stream.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	edgeRestartRead(t, restartedStream, restartTime.Add(settings.RecoveryTimeout), "after", "the restarted edge")
	if _, err := restartedStream.Write([]byte("visitor")); err != nil {
		t.Fatal(err)
	}
	edgeRestartRead(t, restartedIncoming.Stream, restartTime.Add(settings.RecoveryTimeout), "visitor", "the listener after the restart")
	t.Logf("the restarted edge's stream carried bytes both ways %s after the restart", time.Since(restartTime))
}
