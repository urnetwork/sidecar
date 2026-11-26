//go:build !sidecar_http && !ios_extension && !js

// An edge restarted in place on sidecartest's Net (QD-1174, §13.6): EdgeClientPool's client comes back under the same
// client id, as api's derivation gives it, while a listener that served it keeps its send sequence to that id and the
// contract it holds. The Net's issuer signs each contract with the destination's live provide key, as CreateContract
// does, so the listener's contract is the old process's. A restarted pool whose client presents the same connect
// identity, which its source's seed derives (host_edge_identity.go), verifies that contract, and its next stream to the
// listener carries bytes both ways. A pool that drew a fresh identity, or another provide key alone, refuses that
// contract, and its stream to the listener never opens: neither had an answer within 150 s, past connect's 60 s
// AckTimeout, which is the blogger case's two-minute outage.
//
// What the restarted stream waits for is connect's restart path, on connect's real timers: the restarted client's new
// session with the listener, and the listener's writes of what it holds to the id. Since QD-1232 (owner decision 730,
// connect 0c25db80 and 7cc26e9a) the listener takes the restarted client's first Packs while the worker of its old
// sequence exits, and the restarted client says it has delivered nothing of the listener's sequence, so the listener
// writes what it lacks at once, rather than at resends backed off from its rtt toward MaxResendInterval (8 s). Since
// connect 634825b4, 1c3ee536 and c9105b02 the encryption layer on that path waits for no resend either: the listener
// opens the restarted client's first sealed Pack as soon as it holds the client's identity proof, a new session seals
// nothing before the peer can open it, and what the listener sealed under the old session is sealed again under the
// new one as soon as the restarted client seals under it. Since connect 7ef220fd, 8b49af6a, 668988dc and 30597f8c the
// listener takes the restarted client's nack, or its handshake on a carrier that replaced a live one, as the loss of
// its session: it writes again at once what went out in plaintext, heads each sequence the client lost with its whole
// contract rather than waiting to be asked for it, and seals again under the new session once that session seals.
//
// The listener's contract to the id is for Service, under the slot's Service key, and connect verifies a contract only
// under a mode its receiver provides. The restarted client provides Service under that key from before it can receive
// (SidecarPlatformClientArgs.ApplyProvide), so the first copy of the contract that reaches it verifies. Before, the
// pool set Service only once its platform client was open, while the Net already delivered to it: a head that reached
// it first was refused, which left the listener's sequence dropped until the restarted open had no answer at the edge's
// 15 s DefaultCallTimeout, in about one run in 6,400, and, from connect ccf9e38a, which hears the sequence again once
// the client's modes change, until the listener's next copy, one resend of about 0.6 s, in about one run in 1,400.
// TestEdgeClientPoolRestartedInPlaceTakesItsListenersContractAtOnce holds that window open.
//
// The edge's dispatcher reads the Net's clock, as the listener's does, and nothing here moves it: no deadline of a
// dispatcher's, its DefaultCallTimeout, a read's or its keepalive's, ends a wait that connect has yet to answer, as the
// edge's 15 s DefaultCallTimeout did in listen-expires' landcheck (2026-11-23). Each wait ends on its event, the open's
// answer or the bytes, or at its step's bound, a broken run's, in real time.

package sidecar_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The restart tests' bounds (QD-702), each in real time and each a broken run's.
type edgeRestartNetSettings struct {
	// How long after the restart the restarted pool's stream has to open and carry bytes both ways: the edge dialer's
	// AcceptTimeout, 5 s (D-SOCK-6), after which a ticket's open goes to the backup, so a run past it is one whose first
	// visitor stream a production edge would have sent elsewhere, the failure QD-1232 fixed. Connect's restart path took
	// 2.4, 4.8, 10.6 or 18.6 s before that fix, as one or another of the listener's resends reached the restarted client,
	// in 190 runs at load 37 to 84. Since, over 18,360 runs at load 12 to 37 and 12,800 beside 28 CPU burners, it took
	// 22 ms at the median and under 0.1 s at the 99th percentile, but one resend timer, up to 0.68 s, in about one run in
	// a hundred, from races in connect's encryption layer. Since connect c9105b02 it took 15 ms at the median and 0.11 s
	// at the 99th percentile, and past 0.5 s in none of 6,400 runs at load 37 to 40, one of 6,399 beside 28 CPU burners
	// and none of 320 under the race detector, where the build before took it in 45, 86 and, earlier, 6 of 320
	// (2026-11-24). In about one run in 6,400, with those fixes and without, the restarted open had no answer at the
	// edge's DefaultCallTimeout, which connect-restart-latency-followups traced to the refused contract the file header
	// describes. Each pool keeps the edge's own DefaultCallTimeout, 15 s, past this bound: an open hands connect what its
	// own deadline leaves, which on a clock nothing moves is all of it, and connect holds the open's send that long, in
	// real time, for the restarted client's session, so only this bound ends a broken run.
	RecoveryTimeout time.Duration
	// Each step before the restart.
	StepTimeout time.Duration
	// The listener's target, a tls/ name as a registration names it.
	Target string
}

func defaultEdgeRestartNetSettings() *edgeRestartNetSettings {
	return &edgeRestartNetSettings{
		RecoveryTimeout: sidecar.DefaultSocketEdgeDialSettings().AcceptTimeout,
		StepTimeout:     45 * time.Second,
		Target:          "tls/443/blog",
	}
}

// A context that ends timeout from now, in real time, and carries no deadline: a dispatcher reads a context's deadline
// on its own clock, which here is the Net's, so the bound reaches it only as the context's end.
func edgeRestartBound(t *testing.T, timeout time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	t.Cleanup(cancel)
	return edgeRestartBoundContext{Context: ctx}
}

// A context without its deadline (edgeRestartBound).
type edgeRestartBoundContext struct {
	context.Context
}

// None, so a dispatcher on the Net's clock does not read a real-time deadline against it.
func (self edgeRestartBoundContext) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

// Opens a stream from the pool's first client to the listener and waits for the listener's accept, both until ctx ends.
func edgeRestartOpen(t *testing.T, ctx context.Context, pool *sidecar.EdgeClientPool, listenerId connect.Id, target string, incomings <-chan *sidecar.StreamIncoming) (*sidecar.SubprotocolStream, *sidecar.StreamIncoming) {
	t.Helper()
	stream, err := pool.Clients()[0].Subprotocol.OpenStream(ctx, sidecar.Id(listenerId), &sidecar.StreamOpenRequest{Target: target})
	if err != nil {
		t.Fatalf("the edge's open: %v (its bound: %v)", err, ctx.Err())
	}
	select {
	case incoming := <-incomings:
		return stream, incoming
	case <-ctx.Done():
		t.Fatal("the listener never saw the open")
		return nil, nil
	}
}

// Reads exactly len(want) bytes from stream and fails unless they are want. The read ends with its bytes, or when ctx
// ends, which passes the stream's read deadline on whichever clock its dispatcher reads.
func edgeRestartRead(t *testing.T, ctx context.Context, stream *sidecar.SubprotocolStream, want string, what string) {
	t.Helper()
	stop := context.AfterFunc(ctx, func() {
		// before every clock here
		stream.SetReadDeadline(time.Unix(0, 0))
	})
	defer stop()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(stream, got); err != nil || string(got) != want {
		t.Fatalf("%s read %q, %v (its bound: %v)", what, got, err, ctx.Err())
	}
}

// A listener on the Net, providing Service and listening on the target for edges, and an edge pool of one client, the
// two providing Service to each other, whose stream to the listener has carried bytes: what a restart test restarts
// the pool from.
type edgeRestartNet struct {
	settings         *edgeRestartNetSettings
	listenerClientId connect.Id
	// each stream the listener accepts, in order
	incomings <-chan *sidecar.StreamIncoming
	// what the pool was made on, which a restart makes it again on
	args         *sidecar.EdgeClientPoolArgs
	edgeClientId connect.Id
	pool         *sidecar.EdgeClientPool
	// the listener's end of the pool's stream
	incoming *sidecar.StreamIncoming
}

func newEdgeRestartNet(t *testing.T, settings *edgeRestartNetSettings) *edgeRestartNet {
	t.Helper()
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
	if args.Settings.Protocol.DefaultCallTimeout <= settings.RecoveryTimeout {
		t.Fatalf("the edge's DefaultCallTimeout, %v, does not outlast the restarted open's bound, %v", args.Settings.Protocol.DefaultCallTimeout, settings.RecoveryTimeout)
	}
	// the Net's clock, as the listener's dispatcher reads it, which nothing here moves (the file header)
	args.Clock = net.Clock()
	pool, err := sidecar.NewEdgeClientPool(t.Context(), args)
	if err != nil {
		t.Fatal(err)
	}
	edgeClientId := connect.Id(pool.Clients()[0].ClientId)
	// Service both ways, CreateContract's decision for a Find-recorded pair (§6.10.1 item 3)
	net.SetContractProvideMode(listenerClientId, edgeClientId, connectprotocol.ProvideMode_Service)
	net.SetContractProvideMode(edgeClientId, listenerClientId, connectprotocol.ProvideMode_Service)

	stepCtx := edgeRestartBound(t, settings.StepTimeout)
	stream, incoming := edgeRestartOpen(t, stepCtx, pool, listenerClientId, settings.Target, incomings)
	if _, err := incoming.Stream.Write([]byte("before")); err != nil {
		t.Fatal(err)
	}
	edgeRestartRead(t, stepCtx, stream, "before", "the edge before the restart")
	return &edgeRestartNet{
		settings:         settings,
		listenerClientId: listenerClientId,
		incomings:        incomings,
		args:             args,
		edgeClientId:     edgeClientId,
		pool:             pool,
		incoming:         incoming,
	}
}

// The edge goes away mid-stream, as a crash or a deploy's SIGTERM ends it, and the listener writes to it: the write
// waits for an ack that the old process never sends, so the listener's send sequence to the id lives through the
// restart with the old process's contract, as a live listener's does.
func (self *edgeRestartNet) closeMidStream(t *testing.T) {
	t.Helper()
	self.pool.Close()
	if _, err := self.incoming.Stream.Write([]byte("held")); err != nil {
		t.Fatal(err)
	}
}

// The restarted pool's client has the old one's id, and its stream to the listener opens and carries bytes both ways,
// each within ctx.
func (self *edgeRestartNet) reachAgain(t *testing.T, ctx context.Context, restarted *sidecar.EdgeClientPool) {
	t.Helper()
	if connect.Id(restarted.Clients()[0].ClientId) != self.edgeClientId {
		t.Fatal("the restarted pool's client took another id")
	}
	restartedStream, restartedIncoming := edgeRestartOpen(t, ctx, restarted, self.listenerClientId, self.settings.Target, self.incomings)
	if _, err := restartedIncoming.Stream.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	edgeRestartRead(t, ctx, restartedStream, "after", "the restarted edge")
	if _, err := restartedStream.Write([]byte("visitor")); err != nil {
		t.Fatal(err)
	}
	edgeRestartRead(t, ctx, restartedIncoming.Stream, "visitor", "the listener after the restart")
}

// The edge's pool closes mid-stream and is made again on the same source, so its client has the same id. The restarted
// client's stream to the listener opens, and carries bytes both ways, within RecoveryTimeout.
func TestEdgeClientPoolRestartedInPlaceReachesItsListenerAgain(t *testing.T) {
	settings := defaultEdgeRestartNetSettings()
	restart := newEdgeRestartNet(t, settings)
	restart.closeMidStream(t)

	restartTime := time.Now()
	recoveryCtx := edgeRestartBound(t, settings.RecoveryTimeout)
	restarted, err := sidecar.NewEdgeClientPool(t.Context(), restart.args)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.Close)
	restart.reachAgain(t, recoveryCtx, restarted)
	t.Logf("the restarted edge's stream carried bytes both ways %s after the restart", time.Since(restartTime))
}

// A platform that hands the pool each client it opens only once hold has returned for it: the window between a
// client's becoming reachable and the pool's own steps after the open, held open as long as hold takes. An error from
// hold fails the open, and the client is closed.
type edgeRestartHoldPlatform struct {
	platform sidecar.SidecarPlatform
	hold     func(client *sidecar.SidecarPlatformClient) error
}

func (self *edgeRestartHoldPlatform) OpenClient(ctx context.Context, args *sidecar.SidecarPlatformClientArgs) (*sidecar.SidecarPlatformClient, error) {
	client, err := self.platform.OpenClient(ctx, args)
	if err != nil {
		return nil, err
	}
	if err := self.hold(client); err != nil {
		return nil, errors.Join(err, client.CloseAndWait(ctx))
	}
	return client, nil
}

// The restarted pool's platform hands it its client only once the listener's backlog, the write held across the
// restart, has reached the client, so nothing the pool does after the open is something the client's taking of the
// listener's contract waits for. The Net delivers to the client from within the open, and the client already provides
// Service there, under the slot's key the listener's contract was signed with, so the first copy of that contract
// verifies and the backlog comes in. A client that provided Service only once the pool had it open would refuse that
// copy, and connect would drop the listener's sequence until the client's modes changed, which the held window keeps
// from happening: its backlog would never arrive. Then the restarted client's own stream to the listener opens and
// carries bytes both ways within RecoveryTimeout. The hold is a step, bounded as one: a client that sends nothing, as
// a held one does, hears the listener's backlog only at the listener's own resends, which on connect's restart path
// took up to 1.2 s here, where the pool's first open would have had the listener write it at once.
func TestEdgeClientPoolRestartedInPlaceTakesItsListenersContractAtOnce(t *testing.T) {
	settings := defaultEdgeRestartNetSettings()
	restart := newEdgeRestartNet(t, settings)
	restart.closeMidStream(t)

	holdCtx := edgeRestartBound(t, settings.StepTimeout)
	// why the hold failed the open, which the pool's error leaves out; read once NewEdgeClientPool has returned
	var holdErr error
	restartedArgs := *restart.args
	restartedArgs.Platform = &edgeRestartHoldPlatform{
		platform: restart.args.Platform,
		hold: func(client *sidecar.SidecarPlatformClient) (err error) {
			defer func() {
				holdErr = err
			}()
			if modes := client.Client.ContractManager().GetProvideModes(); len(modes) != 1 || !modes[connectprotocol.ProvideMode_Service] {
				return fmt.Errorf("the restarted client was handed over providing %v", modes)
			}
			// a frame of the subprotocol is delivered only from a sequence whose contract verified, and only once the
			// client's new session with the listener has opened it
			backlog := make(chan struct{})
			var backlogOnce sync.Once
			remove, err := client.Client.AddSubprotocolRawCallback(sidecar.SubprotocolId, func(source connect.TransferPath, subprotocolId connect.SubprotocolId, messageBytes []byte, peer connect.Peer) {
				if source.SourceId == restart.listenerClientId {
					backlogOnce.Do(func() {
						close(backlog)
					})
				}
			})
			if err != nil {
				return err
			}
			defer remove()
			select {
			case <-backlog:
				return nil
			case <-holdCtx.Done():
				return errors.New("the listener's backlog never reached the restarted client")
			}
		},
	}
	restarted, err := sidecar.NewEdgeClientPool(t.Context(), &restartedArgs)
	if err != nil {
		t.Fatalf("%v: %v", err, holdErr)
	}
	t.Cleanup(restarted.Close)
	restart.reachAgain(t, edgeRestartBound(t, settings.RecoveryTimeout), restarted)
}
