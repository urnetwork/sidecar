//go:build sidecar_testhooks

// Open through the real hooks: a key is a reader's when its own actor created, derived or unwrapped it, as
// testHookSecret reports, so an oracle opens exactly what that reader could.

package fault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The writer opens the generation it made; a reader that held nothing does not; and a reader that holds only a
// later generation opens the earlier one down the ladder, as a current reader does.
func TestStoreViewOpensOnlyWhatItsReaderHeld(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	fixture := NewStoreViewFixture()
	schedule := &Schedule{
		Id: "held",
		Steps: []*Step{
			{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
				return fixture.Write(ctx, net)
			}},
			{Actor: "rotatorC", Action: func(ctx context.Context, net *Net) error {
				holders := sha256.Sum256([]byte("the holders after"))
				_, rotate, err := fixture.RepoKey.NextGeneration(&sidecar.GkmGenerationArgs{
					Cause:         sidecar.GkmCauseRequest,
					Auth:          &bridge.AuthPin{Version: 2, Chain: bytes.Repeat([]byte{8}, 32)},
					Time:          net.Clock().Now(),
					HoldersSha256: holders[:],
				})
				if err != nil {
					return err
				}
				signedBytes, err := StoreViewFixtureGeneration(rotate)
				if err != nil {
					return err
				}
				first, err := net.Host().Blobs.FirstCluster()
				if err != nil {
					return err
				}
				_, err = first.PutIfNoneMatch(ctx, sidecar.GkmGenerationPath(fixture.GroupId, 2), signedBytes, nil)
				return err
			}},
		},
	}
	if result := Run(t.Context(), schedule, net); result.Err != nil {
		t.Fatalf("%s", result)
	}
	view := NewStoreView(net, nil)
	ladder, err := view.Generations(t.Context(), fixture.GroupId)
	if err != nil || len(ladder) != 2 {
		t.Fatalf("the ladder: %v, %v", ladder, err)
	}
	key, err := view.Open("writerA", ladder, 1)
	if err != nil || !bytes.Equal(key.Commitment(), fixture.RepoKey.Commitment()) {
		t.Fatalf("the writer's own generation: %v, %v", key, err)
	}
	if _, err := view.Open("readerB", ladder, 1); !errors.Is(err, ErrStoreViewNotHeld) {
		t.Fatalf("a reader that held nothing: %v", err)
	}
	if _, err := view.Open("writerA", ladder, 2); !errors.Is(err, ErrStoreViewNotHeld) {
		t.Fatalf("the writer opened a generation made after it: %v", err)
	}
	down, err := view.Open("rotatorC", ladder, 1)
	if err != nil || !bytes.Equal(down.Commitment(), fixture.RepoKey.Commitment()) || down.Generation() != 1 {
		t.Fatalf("the rotator down its ladder: %v, %v", down, err)
	}
	if !slices.Contains(view.HeldSecrets().Actors(), "writerA") || !slices.Contains(view.HeldSecrets().Actors(), "rotatorC") {
		t.Fatalf("held by %v", view.HeldSecrets().Actors())
	}
}
