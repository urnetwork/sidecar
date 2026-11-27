//go:build !sidecar_http && !js && !ios_extension

// The root's waits that end with their context (clock-select-ctx-sweep, after tls-wait-ctx-shape). Go's select takes
// any of its ready cases at random, so a loop that selects on a context's end beside a clock's timer ran one more pass
// after the end whenever both were ready at once and the timer's case won. Each loop here did something outward on
// that pass: the TLS front's probe dialed its target and set the listener's serving, its update loop sent the
// registration an update, a CT pass on an ended context read the names and marked the watch degraded, the rpc send
// loop handed connect the envelope again, and the mail receiver listened again, setting its status from the listen,
// or ran a key pass that publishes, serves, rotates and retires. Each now answers the end once its context has ended,
// whatever else was ready, and asks the clock for nothing then.
//
// The proof is tls-wait-ctx-shape's clock (tlsWaitEndingClock), which ends the context as a wait's timer fires, so both
// cases are ready when select runs, over 64 rounds, which leave the old coin no chance (at most (1/2)^64) to pass. More
// of the root's cases are in clock_select_ctx_sweep_more_test.go and clock_select_ctx_sweep_rest_test.go (whose clock
// fires the waits AfterFunc sets too), IMAP IDLE's in clock_select_ctx_sweep_imap_test.go, the device role's in
// device/clock_select_ctx_sweep_test.go, the engines' in each engine's clock_select_ctx_sweep_test.go, the config
// writer's in clock_select_ctx_sweep_external_test.go, the certificate manager's Close in
// clock_select_ctx_sweep_hooks_test.go, and the later pass's in clock_select_ctx_sweep_later_test.go,
// clock_select_ctx_sweep_later_external_test.go and gkmservice's and evsservice's clock_select_ctx_sweep_later_test.go.
//
// The sweep's account of the other selects on a context's end beside a clock's timer, or beside a wake a clock's
// AfterFunc pokes, in the repository's non-test files, by where each step past the end goes. Its second scan followed
// each timer through the variable it was set in, which found the selects whose timer's name says nothing of one.
//
// Left as they are, the step past the end harmless:
//
//	every case ends the wait, or the timer's answers the call: the drains (daemon_socket.go's, dnsservice's api and
//	  edge, evsservice/engine.go's two, gkmservice's, computeservice's waitInFlight, socket_listen.go's,
//	  socket_platform_listen.go's, smtpedgeservice's drainConnections, tlsedgeservice's Drain, evsservice/purge.go's
//	  Drain, mxedgeservice's Drain); the answers (daemon_events.go next, daemon_search_budget.go Admit,
//	  harness_daemon.go's events, harness_ui.go Ask, mail_local_credential.go Check, pushservice's long poll,
//	  stream_open.go OpenStream, rpc_call.go awaitPending, whose DEADLINE_EXCEEDED for CANCELLED comes only at the
//	  call's own deadline, where the peer's timeout_ms ends the handler as Cancel would,
//	  bridge_discovery_component.go handleWatch, search_limits.go admit, search_remote_search.go ask, search_more.go's
//	  progress, evs_local_lock.go lockIn, dnsservice's journalAnswer, customHostMapAnswer and readyAnswer, and
//	  computeservice/engine_stream.go run, whose comment goes to a request already ended); the clock contexts
//	  (rpc_headcheck.go clockContext, stream_peer.go clockContextUntil); and those that already answer the end after
//	  their select (api_service_token_retry.go, tls_custom_domain.go wait, gkm_rekey.go take, the CT watch's and the
//	  certificate manager's loops)
//	no context case, or no timer: enclave_container.go kill, infer_engine_process.go Generate,
//	  smtpedgeservice/connection.go watch, mxedgeservice/splice.go run, gkm_recovery.go followRecoveryBinding,
//	  mcp/resources.go run, device/bridge_reach.go runReach, tlsedgeservice/splice.go admitChunk and splice (its done is
//	  the copies'), pushservice's wake sender dispatcher, socketsservice's runRemovals
//	the step past the end checks the context first: acl_gate.go's loader, evsservice/purge.go run (next answers
//	  stop), bridge_forward.go's Forwarder run (the loop's top reads the hint and checks the context before any step,
//	  and a request is handed only while the loop lives, onRun selecting on the same end), socket_registrar.go run
//	  (the loop's top), search_member_host.go run (open refuses an ended host), acl_contract.go run (loadHeads),
//	  sidecar_core.go run, envelope_reassembly.go run (its expire gives back reservations, and close waits for it),
//	  cli/daemon_desktop_tls.go's two loops, mail_direct.go runAssigned and bridge_discovery_component.go watch (each
//	  loop's condition; a watch's call answers the dead context before its Hello), push_state.go pushFeed.run's retry
//	  and its refetch's wait (the refetch's error on an ended context returns), dnsservice/probe.go Prober.run (its
//	  probes take the dead context, and a round on an ended context records and publishes nothing), cli/relay.go
//	  reconnect (the loop's top), cli/discovery_gather_darwin.go Gather's two waits (the loop's condition), and
//	  cli/tun_device.go runSync (sync refuses an ended tun before it sets the device)
//	the step past the end is a call that takes the dead context, which refuses it before any I/O (net/http checks it
//	  before dialing; the stores, Redis, gkm and evs take it), with nothing local, durable or seen by another reader
//	  first: attest_policy_fetch.go run, compute_client.go run (both selects), config_client.go run,
//	  evs_component.go's mapper (TickMapper's first I/O is the head's read), mail_config.go run (Sync's fresh read,
//	  after which the loop returns), infer_cache_secret.go enclaveWait (before its read the poll drops only the sync
//	  it holds in memory, which costs the next call a read and changes no answer), smtp_prover_host.go Run (the
//	  prover's PrepareKeys refuses it first), dns_hint.go runHints, dns_label_refresh.go run, acl_follow.go's ack,
//	  daemon_socket.go probe (net.Dialer), evs_client.go awaitFirstGeneration, evs_deposit.go waitDropKey,
//	  evs_drop_preview.go, evs_epoch_read.go, evs_http.go send, evs_repo.go callLifecycle, evs_reseed.go,
//	  evs_upload.go retryRefusingNothing, gkm_api.go do, gkm_hints.go run (its handlers take the dead context),
//	  record_evs.go post, record_vault.go awaitVault, mail_config_write.go createRecord, mail_send_result.go
//	  runSendWatch, mail_component_receive.go's zone wait, record_approval_state.go Run, push_poll.go run and
//	  runCoreSync (an answer it keeps is read by no one: currentCore answers nil once the generation has ended),
//	  harness_retry.go waitUntil, infer_compute_client.go wait, infer_download.go's waits,
//	  model/compute_model_mirror.go readChunk, host_edge_clients.go refreshAuth, sidecar_generation_http.go's two,
//	  certsservice's caaWait and solver wait, dnsservice/feed.go parkUntil, evsservice's budget_client.go runWeights,
//	  quota_gate.go, hdd_admission.go, budget_loop.go and hdd_loop.go Run (a lease's take fails on it, and what a
//	  failed take forgets is the holding the end's release gives up), collect_markers.go Collect, marker.go
//	  waitOverMarker, drop_job.go dropPace, epoch_copy.go pace, push_commit.go takeOver, outcome.go, refuse.go and
//	  quota_read_gate.go Wait, gkmservice's listNetworks, mxedgeservice's direct_mx.go, records.go and listings.go
//	  runs and its wake hold's dial, smtp_outcome.go progress, smtpedgeservice's send_log.go, breaker.go and
//	  sending_set.go runs, pushservice's wake_enqueue.go, wake_sender.go runClaimer and wait (runReader's loop checks
//	  the context, and submit's vendor send takes it, the attempt counted), publisher.go's coalescing and idle waits
//	  and backoff (Redis takes it, a failure counted, and the run's top then ends the run), socketsservice's
//	  gate_projection.go, over_limit.go, removeClient, runKills and runSweeps, tlsedgeservice's records.go run,
//	  runVisitorKeys and runNames, smtpproof's probe pace and key waits, and the ur commands' waits
//	  (cli/cmd_bridge.go, cmd_compute.go, cmd_login_device.go, commands.go connectDaemon); and the engines' readiness
//	  probes (dnsservice/api.go, evsservice/engine.go, gkmservice's, mxedge's, smtpedge's and sockets' runs), whose
//	  store read on the dead context can mark the stores unreachable only for an engine that has ended, which serves
//	  nothing after
//	the end closes what the retry would use, the race an accept or read in flight at the end has: mxedgeservice's
//	  Serve, dnsservice/edge.go's readPackets and Serve, tlsedgeservice's PROXY listener, and cli's mDNS queries
//	the same step the end takes anyway: support_log.go run (the end's case flushes), tls_reach_receipt.go run (close
//	  writes what the loop has not), bridge_daemon_forward.go's UDP sweep (it closes conns the end closes), daemon.go
//	  idle (only Close), keys_instance.go run (the auto-lock it was due), acl_gate.go run (the epoch and dirty marks;
//	  no loader loads past the end), bridge_discovery_component.go viewer (its end withdraws every host and rebuilds
//	  the view), bridge_share.go run (a wake its timer gives only ends a share, which releases the holds the end's
//	  teardown releases), socketsservice/ticket_keys.go run (a reread of the key file into the view of an engine that
//	  has ended), cli/tun_device.go runLocal (a read past the end hands the bridge addresses that the tun's close,
//	  which waits for the loop, then puts back to unknown), and dnsservice/feed.go's snapshot writer (a flush past the
//	  end writes what FeedLoop.Close flushes once the loops end)
//	test support and upstream: sidecartest's fakes and drivers, built into no release leg, and third_party's
//	  go-sev-guest and go-tdx-guest, kept as upstream ships them
//
// Fixed in the sweep's second sitting, each with its case: the bridge component's catch-up alarm, compile timer and
// binding fetcher (which its Close now joins), discovery's host loop, remote serving's follow, the directory client's
// Run, device.Bridge's run and its link manager's, the evs receive queue and sync engine, the index schedule, the mail
// component's generation, IMAP IDLE, mail ingest's passes, the head check's rounds and fetch follow-up, the
// scim_signer component, the SMTP outbox, the share loader, the stream keepalive, and in the ur daemon the shared
// blocks' judgment, which now waits on the daemon's clock, and the cap on the core's clock checks
// (cli/clock_select_ctx_sweep_test.go).
//
// Fixed in the later pass (clock-sweep-later-pass), each with its case: the agents' inbox watch and status writer, a
// creation's wait for the path epoch, gkm's waits and the team directory's unhinted wait, the prefix repair, the evs
// subscriber's rounds and its lease's retry, the key upkeep's passes and ReaderKey retries, the usage batcher, the
// record writer, remote search's follow, the search sync's rounds, the config follower's anchor and member record
// retries, the socket component's config follow, the support client's loop, gkm's reconciler, and evsservice's write
// budget ticks, drop pace and orphan GC pace; and the Forwarder's wait, which now waits for its time itself (QD-1425).
//
// Left for a later pass, the step past the end outward or durable and its fix not built here:
//
//	whose file brings a settings migration with it (QD-702): rpc_headcheck_stop.go run, whose alarm owner decision
//	  129 fixes outside settings, beside a document bound and witness_bound_hours' range
//	outward past the end, with no clock seam a fake clock drives (real time): the ur daemon's discovery proxies
//	  (cli/discovery_proxy_darwin.go's and discovery_proxy_mdns.go's runs), whose registration, apply or announce past
//	  the end goes to mDNSResponder or the LAN, and cli's darwin and mDNS gatherers (discovery_gather_darwin.go's
//	  gatherOn and discovery_gather_mdns.go's Gather), whose report past the end the daemon may take; the core lane's
//	  darwin-discovery-test-bound holds their tests
//	written after the sweep's scan, in a file the later pass did not hold: agents_person.go's AgentPersonWatch.run,
//	  the inbox watch's shape, whose pass past the end can notify the person's view

package sidecar

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// Where the sweep's clocks stand.
func clockSelectTestStart() time.Time {
	return time.Date(2026, time.November, 26, 9, 0, 0, 0, time.UTC)
}

// A TlsFront under ctx on the front tests' fakes and clock, its target dialed by dial (the default dialer when nil),
// and its registration's lists sent by updateTls (none when nil). It is closed when the test ends.
func newClockSelectTestFront(
	t *testing.T,
	ctx context.Context,
	clock Clock,
	settings *TlsFrontSettings,
	dial func(ctx context.Context) (net.Conn, error),
	updateTls func(update *TlsFrontUpdate) error,
) *TlsFront {
	t.Helper()
	front, err := NewTlsFront(ctx, &TlsFrontArgs{
		Settings: settings,
		Target: &TlsFrontTarget{
			Name:         tlsFrontTestName,
			ServerNames:  []string{tlsFrontTestServerName},
			AppMode:      "http",
			LocalAddress: "127.0.0.1:8080",
		},
		Listener:  newTlsFrontTestListener(NewId()),
		NetworkId: NewId(),
		SidecarId: NewId(),
		Policy:    newTlsFrontTestPolicy(),
		Certificate: func(serverName string) (*tls.Certificate, error) {
			return nil, errors.New("no certificate in this test")
		},
		Secrets: newTlsFrontTestSecrets(),
		Limits: func(ctx context.Context) (*QuotaLimits, error) {
			return &QuotaLimits{Tier: "pro"}, nil
		},
		DialTarget: dial,
		UpdateTls:  updateTls,
		Clock:      clock,
		Log:        NewNoopLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		front.Close()
	})
	return front
}

// The front's probe makes no probe once the front has ended: an end landing as a wait after the first probe fires ends
// the loop with that probe its last, whether the wait was the probe's least spacing (the first) or the rest of its
// interval (the second), in each of 64 rounds, and an end at the first asks the clock for no second wait; a front whose
// context ended before it began probes nothing and asks the clock for nothing. A loop that took the timer's case dialed
// the target again on the dead front and set the listener's serving from that dial.
func TestTlsFrontProbeMakesNoProbeAfterTheFrontEnds(t *testing.T) {
	settings := DefaultTlsFrontSettings()
	// the dials the front's probe made before its loop returned
	run := func(ctx context.Context, clock *tlsWaitEndingClock) int64 {
		dialCount := &atomic.Int64{}
		front := newClockSelectTestFront(t, ctx, clock, settings, func(ctx context.Context) (net.Conn, error) {
			dialCount.Add(1)
			return nil, errors.New("the target refuses")
		}, nil)
		clock.open()
		clock.awaitDone(t, front.probeDone, "the probe loop")
		return dialCount.Load()
	}
	for round := range 64 {
		for _, endIndex := range []int{1, 2} {
			ctx, cancel := context.WithCancel(context.Background())
			// the probe's waits are the front's only ones
			clock := newTlsWaitEndingClock(t, clockSelectTestStart(), 0)
			clock.arm(endIndex, cancel)
			if dials := run(ctx, clock); dials != 1 || clock.waits() != endIndex {
				t.Fatalf("round %d, ending at wait %d: %d dials and %d waits, want 1 dial and %d waits", round, endIndex, dials, clock.waits(), endIndex)
			}
			cancel()
		}
	}
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	clock := newTlsWaitEndingClock(t, clockSelectTestStart(), 0)
	if dials := run(ended, clock); dials != 0 || clock.asks() != 0 {
		t.Fatalf("a front ended before it began: %d dials and %d waits", dials, clock.asks())
	}
}

// The front's update loop sends nothing once the front has ended: with every send refused, each look waits
// TargetProbeMinInterval to try again, and an end landing as the second wait fires ends the loop after the two sends
// before it, in each of 64 rounds; a front whose context ended before it began sends nothing and asks the clock for
// nothing. A loop that took the timer's case sent the registration another update for the dead front.
func TestTlsFrontUpdatesSendNothingAfterTheFrontEnds(t *testing.T) {
	settings := DefaultTlsFrontSettings()
	// no probe, so the update loop's are the front's only waits
	settings.TargetProbeInterval = 0
	// the sends the update loop made before it returned
	run := func(ctx context.Context, clock *tlsWaitEndingClock) int64 {
		sendCount := &atomic.Int64{}
		front := newClockSelectTestFront(t, ctx, clock, settings, nil, func(update *TlsFrontUpdate) error {
			sendCount.Add(1)
			return errors.New("the registration refuses")
		})
		clock.open()
		clock.awaitDone(t, front.updatesDone, "the update loop")
		return sendCount.Load()
	}
	for round := range 64 {
		ctx, cancel := context.WithCancel(context.Background())
		clock := newTlsWaitEndingClock(t, clockSelectTestStart(), settings.TargetProbeMinInterval)
		clock.arm(2, cancel)
		if sends := run(ctx, clock); sends != 2 || clock.waits() != 2 {
			t.Fatalf("round %d: %d sends and %d waits, want 2 of each", round, sends, clock.waits())
		}
		cancel()
	}
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	clock := newTlsWaitEndingClock(t, clockSelectTestStart(), 0)
	if sends := run(ended, clock); sends != 0 || clock.asks() != 0 {
		t.Fatalf("a front ended before it began: %d sends and %d waits", sends, clock.asks())
	}
}

// A CT pass on a context that has ended runs none: with the names refused, a pass that ran would mark the watch
// degraded, and one on an ended context leaves the status as the live pass before it left it, raises nothing, and
// answers the alarms standing.
func TestTlsCtWatchPassOnAnEndedContextRunsNone(t *testing.T) {
	fixture := newTlsCtFixture(t)
	standing := fixture.pass()
	if fixture.watch.Degraded() {
		t.Fatal("the live pass was degraded")
	}
	events := len(fixture.eventsSoFar())
	fixture.set(func() {
		fixture.namesErr = errors.New("the names are refused")
	})
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	if answered := fixture.watch.Pass(ended); answered != standing || fixture.watch.Degraded() || len(fixture.eventsSoFar()) != events {
		t.Fatalf("a pass on an ended context: %d alarms (%d standing), degraded %t, %d events (%d before)",
			answered, standing, fixture.watch.Degraded(), len(fixture.eventsSoFar()), events)
	}
	// the same refusal on a live context is degraded, so the names were the pass's to read
	if fixture.pass(); !fixture.watch.Degraded() {
		t.Fatal("a live pass with the names refused was not degraded")
	}
}

// The rpc send loop hands connect nothing more once the call's context or the dispatcher has ended: a send connect
// refuses waits CallSendRetryInterval, and an end landing as that pause's timer fires ends the call after the one
// send, CANCELLED for the call's context and errSubprotocolClosed for the dispatcher's, in each of 64 rounds, asking
// the clock for no second pause. A loop that took the timer's case sent the envelope again after the end.
func TestSubprotocolSendEnvelopesUntilSendsNothingAfterTheEnd(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	// the sends one call made and its answer
	run := func(endCall bool) (int64, error, *tlsWaitEndingClock) {
		clock := newTlsWaitEndingClock(t, clockSelectTestStart(), settings.CallSendRetryInterval)
		subprotocolCtx, subprotocolCancel := context.WithCancel(context.Background())
		defer subprotocolCancel()
		callCtx, callCancel := context.WithCancel(context.Background())
		defer callCancel()
		sendCount := &atomic.Int64{}
		// what the send loop reads of a dispatcher: its context, settings, clock, counts and connect's send, which
		// refuses every envelope at once
		subprotocol := &Subprotocol{
			ctx:      subprotocolCtx,
			settings: settings,
			clock:    clock,
			send: func(destinationId connect.Id, envelope *protocol.Envelope, ack connect.AckFunction, timeout time.Duration, opts ...any) (bool, error) {
				sendCount.Add(1)
				return false, nil
			},
		}
		end := callCancel
		if !endCall {
			end = subprotocolCancel
		}
		clock.arm(1, end)
		clock.open()
		envelopes := []*protocol.Envelope{{Version: WireVersionMajor, Type: uint32(testCallType), RequestId: 7}}
		err := subprotocol.sendEnvelopesUntil(callCtx, connect.NewId(), envelopes, ignoreSubprotocolAck, clock.Now().Add(time.Minute), 7, func(before bool) {})
		return sendCount.Load(), err, clock
	}
	for round := range 64 {
		sends, err, clock := run(true)
		if code, _ := SubprotocolErrorCode(err); code != protocol.ErrorCode_ERR_CANCELLED || sends != 1 || clock.waits() != 1 {
			t.Fatalf("round %d, the call's end: %v after %d sends and %d pauses, want CANCELLED after 1 of each", round, err, sends, clock.waits())
		}
		sends, err, clock = run(false)
		if !errors.Is(err, errSubprotocolClosed) || sends != 1 || clock.waits() != 1 {
			t.Fatalf("round %d, the dispatcher's end: %v after %d sends and %d pauses, want it closed after 1 of each", round, err, sends, clock.waits())
		}
	}
}

// The mail receiver asks for no listen once its context has ended: with every listen refused, each waits
// ListenRetryInterval to ask again, and an end landing as the second wait fires ends the loop after the two listens
// before it, Start's and the first wait's, in each of 64 rounds, the status keeping the refusal it showed. A loop that
// took the timer's case listened again on the dead context and set the status from that listen.
func TestMailReceiverListensNoMoreAfterItsContextEnds(t *testing.T) {
	refused := errors.New("the listen is refused")
	for round := range 64 {
		world := newMailReceiverTestWorld(t, nil)
		world.listenAnswers = []func() (MailReceiverListener, error){
			func() (MailReceiverListener, error) { return nil, refused },
		}
		clock := newTlsWaitEndingClock(t, world.clock.Now(), DefaultMailReceiverSettings().ListenRetryInterval)
		receiver := world.newReceiver(func(args *MailReceiverArgs) {
			args.Clock = clock
		})
		clock.arm(2, world.cancel)
		if err := world.start(); !errors.Is(err, refused) {
			t.Fatalf("round %d: the first listen answered %v", round, err)
		}
		clock.open()
		clock.awaitDone(t, receiver.done, "the receiver's loop")
		if calls, _ := world.listenCalls.Get(); calls != 2 || clock.waits() != 2 {
			t.Fatalf("round %d: %d listens and %d waits, want 2 of each", round, calls, clock.waits())
		}
		if problem := receiver.Status().Problem; problem != "listen: "+refused.Error() {
			t.Fatalf("round %d: the status reads %q", round, problem)
		}
	}
}

// The mail receiver makes no key pass once its context has ended: serving a listen, it passes at once and then at
// each wait its pass sets, and an end landing as the second wait fires ends the key loop after the two passes before
// it, in each of 64 rounds, and the receiver's loop with it, asking the clock for nothing more. A loop that took the
// timer's case ran a pass on the dead context, which publishes, serves, rotates and retires.
func TestMailReceiverMakesNoKeyPassAfterItsContextEnds(t *testing.T) {
	for round := range 64 {
		world := newMailReceiverTestWorld(t, nil)
		// every wait the receiver asks: the key loop's while it serves, and the listen loop's after
		clock := newTlsWaitEndingClock(t, world.clock.Now(), 0)
		passCount := &atomic.Int64{}
		receiver := world.newReceiver(func(args *MailReceiverArgs) {
			args.Clock = clock
			// each pass reads the names first, after its records
			args.Names = func(ctx context.Context) ([]string, error) {
				passCount.Add(1)
				return slices.Clone(testMailReceiverNames), nil
			}
		})
		clock.arm(2, world.cancel)
		if err := world.start(); err != nil {
			t.Fatalf("round %d: the first listen answered %v", round, err)
		}
		clock.open()
		clock.awaitDone(t, receiver.done, "the receiver's loop")
		if passes := passCount.Load(); passes != 2 || clock.waits() != 2 {
			t.Fatalf("round %d: %d key passes and %d waits, want 2 of each", round, passes, clock.waits())
		}
	}
}
