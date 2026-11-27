//go:build !sidecar_http && !js && !ios_extension

// The team directory's unhinted wait ends with its context (clock-sweep-later-pass; clock_select_ctx_sweep_test.go
// holds the account). A writer whose push the gate refused waits its random time before it rotates alone, and that
// wait selected on the context's end beside its timer: whenever select took the timer as the context ended it answered
// nil, and EnsureWritable went on into the rotation on the dead context, which the world's gkm, heeding no context,
// let through to its claim and its wraps. It now answers the end whatever else was ready. The proof is
// sidecartest.EndingClock, which ends the context as the wait's timer fires, over 64 rounds; the world is the directory
// tests' (gkm_directory_test.go).

package sidecar_test

import (
	"context"
	"crypto/hpke"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A client for flow's device on clock, over its keychain and gkm as its restart makes one on the world's clock.
func clockSweepLaterGkmClient(t *testing.T, flow *gkmFlowDevice, clock sidecar.Clock) *sidecar.GkmGroupClient {
	t.Helper()
	world := flow.world
	args := &sidecar.GkmGroupClientArgs{
		SidecarId: flow.id,
		Api:       flow.api,
		Sign:      flow.signer.Sign,
		Secrets:   flow.secrets,
		ReaderPrivateKey: func(keySha256 []byte) (hpke.PrivateKey, error) {
			privateKey, ok := flow.readerPrivateKeys[string(keySha256)]
			if !ok {
				return nil, sidecar.ErrGkmKeyMissing
			}
			return privateKey, nil
		},
		ReaderKeySha256: func() []byte { return flow.readerKeySha256 },
		RecoveryKey: func(memberId sidecar.Id) (*sidecar.GkmRecoveryKey, error) {
			return world.recoveryKeys[memberId], nil
		},
		ReaderRepoIds: func() []sidecar.Id { return []sidecar.Id{world.repoId} },
		Alarm:         func(alarm *sidecar.GkmAlarm) {},
		SealAllowed:   func(groupId sidecar.Id) error { return nil },
		ReportFork:    func(fork sidecar.HeadFork) {},
		HoldsState:    func() bool { return true },
		Jitter:        func(max time.Duration) time.Duration { return min(world.jitter, max) },
		Settings:      world.settings,
		Clock:         clock,
	}
	if len(flow.row.GetTagIds()) == 0 {
		args.Mls = flow.mls
	}
	client, err := sidecar.NewGkmGroupClient(args)
	if err != nil {
		t.Fatal(err)
	}
	if tip := world.log.Tip(); tip != nil {
		client.AuthAdvanced(tip)
	}
	return client
}

// An unhinted directory writer's wait answers its context's end: with x revoked and the gate closed, b's push waits
// its random time before rotating alone, and an end landing as that wait's timer fires answers the context's error with
// nothing claimed or uploaded at gkm, in each of 64 rounds, each round's client a restart of b's on its own clock. A
// wait that took the timer's case answered nil, and b went on to rotate on the dead context, which the world's gkm let
// through to its claim and its wraps.
func TestDirectoryRotateWaitAnswersTheEndOfItsContext(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_DIRECTORY)
	world.revoke(world.x)
	world.stateFor()
	b := world.flows[world.b]
	world.jitter = 4 * time.Second
	for round := range 64 {
		clock := sidecartest.NewEndingClock(world.clock.Now(), sidecartest.EndingClockCounts(world.jitter))
		client := clockSweepLaterGkmClient(t, b, clock)
		ctx, cancel := context.WithCancel(world.ctx)
		clock.Arm(1, cancel)
		clock.Open()
		key, err := client.EnsureWritable(ctx, world.repoId)
		cancel()
		if !errors.Is(err, context.Canceled) || key != nil || clock.Waits() != 1 {
			t.Fatalf("round %d: the push answered %v after %d waits, want canceled after 1", round, err, clock.Waits())
		}
		if claims, uploads := world.store.callCount("ClaimGeneration"), world.store.callCount("UploadWraps"); claims != 0 || uploads != 0 {
			t.Fatalf("round %d: gkm took %d claims and %d uploads past the end", round, claims, uploads)
		}
	}
}
