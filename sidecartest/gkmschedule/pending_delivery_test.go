package gkmschedule

// KeyDelivery's pending hint and late delivery (v0, owner decision 610) on T2's world, each device's hint intake
// attached and each hint relayed as the exchange's publisher would: the pending hint's granting device first (§10.6's
// pending changes row, §10.7's KF2 and KF3, DESIGN-DETAILS 6.2.4's may(c)), every other holder after PendingCommitDelay
// and in its place when it is offline; the deliver row's refetch and second try after a 409 (6.2.4); and the first
// wrap the signer of an admission writes at the admission (§7.9's wrapped row).

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
)

// gkm's pending hint about the world's group on the per-client topic, as its reconciler sends it at a holder change
// (gkmservice's hintPending).
func pendingAboutTheGroup(world *FsKeysWorld) *FsKeysHint {
	return &FsKeysHint{
		Topic:   sidecar.PushTopicGkm,
		Version: uint64(world.Clock.Now().UnixMicro()),
		Hint:    &protocol.GkmHint{Kind: protocol.GkmHintKind_GKM_HINT_PENDING, GroupId: world.GroupId.Bytes()},
	}
}

// The device's POSTs to gkm's wraps route from now on, counted, and a channel told of each.
func watchWrapUploads(device *FsKeysDevice) (*sync.Mutex, *int, chan struct{}) {
	lock := &sync.Mutex{}
	count := 0
	posted := make(chan struct{}, 16)
	device.Transport.Before = func(request *http.Request) FsKeysFault {
		if request.Method == http.MethodPost && strings.Contains(request.URL.Path, "/wraps/") {
			lock.Lock()
			count += 1
			lock.Unlock()
			select {
			case posted <- struct{}{}:
			default:
			}
		}
		return FsKeysFaultNone
	}
	return lock, &count, posted
}

// Waits until a timer is set on the world's clock at exactly at: the device's wait has begun, with nothing slept.
func awaitTimerAt(t *testing.T, world *FsKeysWorld, at time.Time) {
	t.Helper()
	for {
		pending, added := world.Clock.WatchTimers()
		for _, timer := range pending {
			if timer.Equal(at) {
				return
			}
		}
		select {
		case <-added:
		case <-world.Ctx.Done():
			t.Fatalf("no wait set for %s", at)
		}
	}
}

// On the pending hint gkm sends a repo's writers at a grant, the granting device, the RepoGrant's signer, delivers at
// once, and the other writer does not within PendingCommitDelay; once the delay has passed, the other's PUT meets the
// granting device's delivery, which stands. The same with the granter the reader's admission's signer and the grant
// unsigned by it.
func TestPendingHintGrantingDeviceDeliversFirst(t *testing.T) {
	for _, admitted := range []bool{false, true} {
		pending := newPendingDeliveryWorld(t, admitted, true)
		world := pending.world
		granterHints := attachPendingHints(t, world, pending.granter)
		otherHints := attachPendingHints(t, world, pending.other)
		readerHints := attachPendingHints(t, world, pending.reader)
		otherLock, otherUploads, otherPosted := watchWrapUploads(pending.other)
		otherCount := func() int {
			otherLock.Lock()
			defer otherLock.Unlock()
			return *otherUploads
		}
		hintedAt := world.Clock.Now()
		hint := pendingAboutTheGroup(world)
		relayLateDeliveryHint(t, granterHints, hint)
		relayLateDeliveryHint(t, otherHints, hint)

		// the granting device's delivery wakes the reader, which takes it, no clock moved
		relayLateDeliveryHint(t, readerHints, world.AwaitHint(pending.reader, world.pendingHint))
		awaitHoldsFirst(t, world, pending.reader, pending.first)
		if signer := deliverySigner(t, world, pending.reader); signer == nil || *signer != pending.granter.SidecarId() {
			t.Fatalf("admitted %t: the reader's delivery is not the granting device's", admitted)
		}
		// the other writer waits PendingCommitDelay, its jitter none
		delay := sidecar.DefaultGkmSettings().PendingCommitDelay
		awaitTimerAt(t, world, hintedAt.Add(delay))
		world.Clock.Advance(delay - time.Millisecond)
		if count := otherCount(); count != 0 {
			t.Fatalf("admitted %t: the other writer uploaded %d deliveries within PendingCommitDelay", admitted, count)
		}
		world.Clock.Advance(time.Millisecond)
		select {
		case <-otherPosted:
		case <-world.Ctx.Done():
			t.Fatalf("admitted %t: the other writer never answered after its delay", admitted)
		}
		if signer := deliverySigner(t, world, pending.reader); signer == nil || *signer != pending.granter.SidecarId() {
			t.Fatalf("admitted %t: the granting device's delivery did not stand", admitted)
		}
	}
}

// With the granting device offline, its intake hearing nothing, the other writer delivers once PendingCommitDelay has
// passed, and not before, and the reader takes its delivery.
func TestPendingHintOtherHolderDeliversAfterTheDelayWithTheGrantingDeviceOffline(t *testing.T) {
	pending := newPendingDeliveryWorld(t, false, true)
	world := pending.world
	otherHints := attachPendingHints(t, world, pending.other)
	readerHints := attachPendingHints(t, world, pending.reader)
	hintedAt := world.Clock.Now()
	relayLateDeliveryHint(t, otherHints, pendingAboutTheGroup(world))
	delay := sidecar.DefaultGkmSettings().PendingCommitDelay
	awaitTimerAt(t, world, hintedAt.Add(delay))
	world.Clock.Advance(delay - time.Millisecond)
	if world.WrapRecipients(1)[pending.reader.SidecarId()] {
		t.Fatal("a delivery to the reader stands within PendingCommitDelay")
	}
	world.Clock.Advance(time.Millisecond)
	relayLateDeliveryHint(t, readerHints, world.AwaitHint(pending.reader, world.pendingHint))
	awaitHoldsFirst(t, world, pending.reader, pending.first)
	if signer := deliverySigner(t, world, pending.reader); signer == nil || *signer != pending.other.SidecarId() {
		t.Fatal("the reader's delivery is not the other writer's")
	}
}

// A late delivery right after the repo's activation that gkm answers 409, the instance that judged it still holding
// repo/ keying in its cache (RepoKeyingCacheTtl, the 5 s production had before gkm-repo-create-race): the deliverer
// refetches gen/ and its row, reads the recipient's key again, and tries once more, which reaches another instance
// behind the lb whose read follows the activation, and lands.
func TestLateDeliveryConflictJustAfterActivationIsRetriedOnceAndLands(t *testing.T) {
	world := NewFsKeysWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	ctx, cancel := context.WithTimeout(world.Ctx, 30*time.Second)
	t.Cleanup(cancel)
	world.Ctx = ctx
	world.Reconfigure(func(settings *gkmservice.GkmServiceSettings) {
		settings.DraftMls = false
		settings.RepoCacheTtl = 5 * time.Second
		settings.RepoKeyingCacheTtl = 5 * time.Second
	})
	writer := world.AddMember("writer", false)
	world.Grant(true, writer)
	world.Creator(writer)
	world.Advance()
	world.Publish()
	first := world.Create(writer)
	reader := world.AddMember("reader", true)
	world.GrantBy(writer, false, reader)
	world.Advance()
	reader.PublishReaderKey()
	readerHints := attachPendingHints(t, world, reader)

	paths := []string{}
	posts := 0
	writer.Transport.Before = func(request *http.Request) FsKeysFault {
		paths = append(paths, request.Method+" "+request.URL.Path)
		if request.Method == http.MethodPost && strings.Contains(request.URL.Path, "/wraps/") {
			posts += 1
			if posts == 2 {
				// the retry reaches another gkm instance, whose repo/ read follows the activation
				world.RestartEngine()
			}
		}
		return FsKeysFaultNone
	}
	if err := writer.Client.DeliverLate(world.Ctx, world.RepoId, fsKeysRecipient(reader.SidecarId())); err != nil {
		t.Fatal(err)
	}
	if posts != 2 {
		t.Fatalf("the deliverer sent %d deliveries, not the 409's and its retry", posts)
	}
	// between the two, the refetch: gen/ and the recipient's key read again
	firstPost, secondPost := -1, -1
	for index, path := range paths {
		if strings.HasPrefix(path, "POST ") && strings.Contains(path, "/wraps/") {
			if firstPost < 0 {
				firstPost = index
			} else {
				secondPost = index
			}
		}
	}
	refetchedGen, refetchedKey := false, false
	for _, path := range paths[firstPost+1 : secondPost] {
		refetchedGen = refetchedGen || strings.HasPrefix(path, "GET ") && strings.HasSuffix(path, "/gen")
		refetchedKey = refetchedKey || strings.HasPrefix(path, "GET /gkm/reader-key/")
	}
	if !refetchedGen || !refetchedKey {
		t.Fatalf("the retry refetched gen/ %t and the key %t: %v", refetchedGen, refetchedKey, paths)
	}
	relayLateDeliveryHint(t, readerHints, world.AwaitHint(reader, world.pendingHint))
	awaitHoldsFirst(t, world, reader, first)
}

// The signer of an admission writes the new device's first wrap of the config when its state shows the admission
// (§7.9's wrapped row): a member device that writes no config signs the joiner's admission, and at the state that
// admits it, with the joiner's ReaderKey up and no ask of the joiner's, gkm holds the signer's delivery of the config to
// it, which the joiner opens.
func TestAdmissionSignerWritesTheFirstWrapAtTheAdmission(t *testing.T) {
	late := newLateDeliveryWorld(t, func(late *lateDeliveryWorld) {
		late.joiner.row.AdmissionSigners = [][]byte{late.other.SidecarId().Bytes()}
		late.other.Offline = true
	})
	world := late.world
	attachPendingHints(t, world, late.other)
	uploads := countWrapUploads(late.other)
	// the signer's follower reaches the admission once the joiner's ReaderKey is up
	late.other.Offline = false
	late.other.Take(late.admission)
	joinerHints := attachPendingHints(t, world, late.joiner)
	relayLateDeliveryHint(t, joinerHints, world.AwaitHint(late.joiner, late.configPending))
	if uploads.Load() == 0 {
		t.Fatal("the signer uploaded no first wrap")
	}
	late.joinerTakesItsAdmission()
	late.awaitJoinerHoldsTheConfig(t)
}
