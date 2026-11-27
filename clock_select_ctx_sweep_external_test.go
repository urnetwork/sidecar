//go:build !ios_extension && !sidecar_http && !js

// The config writer's waits end with their context (clock-select-ctx-sweep): SaveBridgeBlock's retry and the fold
// loop's delay each selected on a context's end beside a clock's timer and went on whenever select took the timer as
// the context ended, so a retry planned, pushed and could sign a head on the dead context, and the fold loop signed
// a fold's base and handed it to the publisher. Each now answers the end whatever else was ready. The proof is
// sidecartest.EndingClock, which ends the context as a wait's timer fires, over 64 rounds; the world is the config
// writer tests' (config_writer_test.go, bridge_block_resign_carry_test.go).

package sidecar_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A desktop writer of net's under the world's context, as testCarryNet.busyWriter makes one, on clock, its tries
// waiting the default BridgeBlockRetryWait, at most attempts of them.
func clockSelectBusyWriter(net *testCarryNet, busy *testCarryBusyRef, clock *sidecartest.EndingClock, attempts int) *sidecar.ConfigWriter {
	world := net.world
	world.t.Helper()
	client := world.client()
	world.caughtUp(client)
	settings := sidecar.DefaultConfigWriterSettings()
	settings.Clock = clock
	settings.Random = func() float64 { return 0 }
	settings.BridgeBlockRandom = testBlockNoDraw()
	settings.BridgeBlockAttemptCount = attempts
	settings.Log = sidecar.NewNoopLogger()
	busy.ConfigHeadRef = world.heads.For(net.desktop.sidecarId, net.desktop.key)
	writer, err := sidecar.NewConfigWriter(world.ctx, &sidecar.ConfigWriterArgs{
		SidecarId:   net.desktop.sidecarId,
		Sign:        net.desktop.sign(),
		Client:      client,
		Heads:       busy,
		Publisher:   world.publisher(),
		Settings:    settings,
		BridgeBlock: sidecar.WithBridgeBlock,
	})
	if err != nil {
		world.t.Fatal(err)
	}
	world.t.Cleanup(func() {
		clock.Open()
		writer.Close()
	})
	return writer
}

// SaveBridgeBlock tries nothing more once its context has ended: with gkm answering 503 to every prepare, each try
// waits BridgeBlockRetryWait, and a cancel landing as the first wait fires ends the save with the context's error
// after the one prepare, in each of 64 rounds. A loop that took the timer's case planned the block's head again on the
// dead context, and asked gkm to prepare it.
func TestSaveBridgeBlockTriesNothingAfterItsContextEnds(t *testing.T) {
	net := newTestCarryNet(t)
	retryWait := sidecar.DefaultConfigWriterSettings().BridgeBlockRetryWait
	for round := range 64 {
		busy := &testCarryBusyRef{unavailable: 5}
		clock := sidecartest.NewEndingClock(net.world.clock.Now(), sidecartest.EndingClockCounts(retryWait))
		writer := clockSelectBusyWriter(net, busy, clock, 3)
		ctx, cancel := context.WithCancel(net.world.ctx)
		clock.Arm(1, cancel)
		clock.Open()
		pin, err := writer.SaveBridgeBlock(ctx)
		cancel()
		if !errors.Is(err, context.Canceled) || pin != nil || busy.prepares != 1 || clock.Waits() != 1 {
			t.Fatalf("round %d: %v, %v after %d prepares and %d waits, want the cancel after 1 of each", round, pin, err, busy.prepares, clock.Waits())
		}
	}
}

// The fold loop publishes nothing once the writer has ended: a writer offline past FoldAge folds at start after its
// random delay, and an end landing as that delay's timer fires ends the loop with no base handed to the publisher, in
// each of 64 rounds. A loop that took the timer's case planned and signed the fold's base on the dead context and
// handed it on.
func TestTheFoldLoopPublishesNothingAfterTheWriterEnds(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	if _, err := world.admitMember("a"); err != nil {
		t.Fatal(err)
	}
	settings := sidecar.DefaultConfigWriterSettings()
	// Random's 0.5 of FoldDelayMax, the loop's one wait of this length
	delay := time.Duration(0.5 * float64(settings.FoldDelayMax))
	for round := range 64 {
		client := world.client()
		world.caughtUp(client)
		clock := sidecartest.NewEndingClock(world.clock.Now().Add(settings.FoldAge+time.Hour), sidecartest.EndingClockCounts(delay))
		publishCount := &atomic.Int64{}
		publisher := &sidecartest.FakeApiConfigPublisher{
			Api:       world.api,
			NetworkId: world.networkId,
			Before: func(ctx context.Context) {
				publishCount.Add(1)
			},
		}
		ctx, cancel := context.WithCancel(world.ctx)
		writerSettings := sidecar.DefaultConfigWriterSettings()
		writerSettings.Clock = clock
		writerSettings.Random = func() float64 { return 0.5 }
		writerSettings.Log = sidecar.NewNoopLogger()
		clock.Arm(1, cancel)
		writer, err := sidecar.NewConfigWriter(ctx, &sidecar.ConfigWriterArgs{
			SidecarId: world.owner.sidecarId,
			Sign:      world.owner.sign(),
			Client:    client,
			Heads:     world.heads.For(world.owner.sidecarId, world.owner.key),
			Publisher: publisher,
			Settings:  writerSettings,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(writer.Close)
		clock.Open()
		select {
		case <-sidecar.ConfigWriterRunDone(writer):
		case <-time.After(30 * time.Second):
			t.Fatalf("round %d: the fold loop did not end within 30s of its context", round)
		}
		cancel()
		if publishes := publishCount.Load(); publishes != 0 || clock.Waits() != 1 {
			t.Fatalf("round %d: %d bases published and %d delays waited, want none and 1", round, publishes, clock.Waits())
		}
	}
}
