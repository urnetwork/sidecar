package gkmschedule

// A creation's readers woken by their STAGED deliveries in KeyDelivery mode (v0, owner decision 610; gkmservice's
// wraps.go): gkm wakes the recipient of a STAGED ReaderWrap of a generation it already holds, KF1's generation 1, since
// that recipient follows no topic of a group it has not seen.

import (
	"context"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
)

// A creation's readers are woken by their STAGED deliveries: a reader that synced as the RepoCreate reached it, before
// the repo was placed, and found nothing, takes generation 1 at gkm's pending hint once KF1's deliveries stand, with no
// sync of its own after the creation.
func TestCreationWakesItsReadersAtTheirStagedDeliveries(t *testing.T) {
	world := NewFsKeysWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	ctx, cancel := context.WithTimeout(world.Ctx, 30*time.Second)
	t.Cleanup(cancel)
	world.Ctx = ctx
	world.Reconfigure(func(settings *gkmservice.GkmServiceSettings) { settings.DraftMls = false })
	writer := world.AddMember("writer", false)
	reader := world.AddMember("reader", true)
	world.Grant(true, writer)
	world.Grant(false, reader)
	world.Creator(writer)
	world.Advance()
	world.Publish()
	readerHints := attachPendingHints(t, world, reader)
	// the RepoCreate reached the reader ahead of the placement: its sync finds no group
	if err := reader.Client.SyncRepo(world.Ctx, world.RepoId); err == nil {
		if held, _ := reader.Client.RepoKeyHeld(world.RepoId); held {
			t.Fatal("the reader held a key before the creation")
		}
	}
	first := world.Create(writer)
	if !world.WrapRecipients(1)[reader.SidecarId()] {
		t.Fatal("the creation staged no wrap to the reader")
	}
	relayLateDeliveryHint(t, readerHints, world.AwaitHint(reader, world.pendingHint))
	awaitHoldsFirst(t, world, reader, first)
}
