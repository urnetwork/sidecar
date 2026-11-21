package gkmschedule

// A joining device's config key in KeyDelivery mode (v0, owner decision 610; §10.6's late wraps row, KF2's wrapped
// row, §5.6's reads row), on T2's world with every device's hint intake attached and each hint relayed as the
// exchange's publisher would: the joiner's first ask raises wrap-pending on the config writers' per-client topic and no
// other holder's, the writer answers it with a LATE delivery and the joiner holds the config's generation, with no
// rotation and no time passing; a writer offline at that hint delivers at its next resync instead, and once a
// generation; and a self-admitted device, whose admission a member device that writes no config signed, is answered
// by that signer, at its resync with no config writer online, and at once on the widened ask's hint.

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
)

// A KeyDelivery world with its config repo formed by writer, the one config writer, and other, a member device
// that writes no config and holds the config's generation 1 by its STAGED wrap; the joiner, a member device admitted
// at the state returned, whose ReaderKey stands at gkm and which has taken no state yet.
type lateDeliveryWorld struct {
	world     *FsKeysWorld
	writer    *FsKeysDevice
	other     *FsKeysDevice
	joiner    *FsKeysDevice
	first     *sidecar.EvsRepoKey
	admission sidecar.GkmAuthView
}

func newLateDeliveryWorld(t *testing.T, admitJoiner func(late *lateDeliveryWorld)) *lateDeliveryWorld {
	world := NewFsKeysWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	ctx, cancel := context.WithTimeout(world.Ctx, 30*time.Second)
	t.Cleanup(cancel)
	world.Ctx = ctx
	world.Reconfigure(func(settings *gkmservice.GkmServiceSettings) { settings.DraftMls = false })
	self := &lateDeliveryWorld{world: world}
	self.writer = world.AddMember("writer", false)
	self.other = world.AddMember("other", false)
	world.ConfigWriters(self.writer)
	world.Advance()
	world.Publish()
	self.first = world.CreateConfig(self.writer)
	if !world.WrapRecipientsIn(world.ConfigGroupId, 1)[self.other.SidecarId()] {
		t.Fatal("the config's creation staged no wrap to the other device")
	}
	// the other device holds the config's key, as every standing device's follower does
	world.Again("the other device's config key", func() error {
		_, err := self.other.Client.CurrentRepoKey(world.Ctx, world.ConfigRepoId)
		return err
	})
	self.joiner = world.AddMember("joiner", false)
	if admitJoiner != nil {
		admitJoiner(self)
	}
	self.joiner.Offline = true
	self.admission = world.Advance()
	self.joiner.PublishReaderKey()
	return self
}

// The device's hint intake, attached to its key client until the test ends.
func (self *lateDeliveryWorld) attach(t *testing.T, device *FsKeysDevice) *sidecar.GkmHints {
	t.Helper()
	hints, err := sidecar.NewGkmHints(self.world.Ctx, &sidecar.GkmHintsArgs{Clock: self.world.Clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hints.Close)
	device.Client.AttachHints(self.world.Ctx, hints)
	return hints
}

// Hands a hint gkm sent the device's client to its intake, as the publisher would.
func relayLateDeliveryHint(t *testing.T, hints *sidecar.GkmHints, hint *FsKeysHint) {
	t.Helper()
	body, err := proto.Marshal(hint.Hint)
	if err != nil {
		t.Fatal(err)
	}
	hints.Receive(sidecar.PushNotice{Topic: hint.Topic, Version: hint.Version, Kind: uint32(protocol.MessageType_GKM_HINT), Hint: body})
}

// The joiner takes its admission's state, as its log applier hands it: its key client asks for the config's first
// wrap, finding none.
func (self *lateDeliveryWorld) joinerTakesItsAdmission() {
	self.joiner.Offline = false
	self.joiner.Take(self.admission)
}

// A wrap-pending hint naming the joiner in the config's group.
func (self *lateDeliveryWorld) wrapPendingForJoiner(hint *FsKeysHint) bool {
	return hint.Topic == sidecar.PushTopicGkm && hint.Hint.GetKind() == protocol.GkmHintKind_GKM_HINT_WRAP_PENDING &&
		bytes.Equal(hint.Hint.GetGroupId(), self.world.ConfigGroupId.Bytes()) && string(hint.Hint.GetRecipient()) == fsKeysRecipient(self.joiner.SidecarId())
}

// A pending hint about the config's group.
func (self *lateDeliveryWorld) configPending(hint *FsKeysHint) bool {
	return hint.Topic == sidecar.PushTopicGkm && hint.Hint.GetKind() == protocol.GkmHintKind_GKM_HINT_PENDING &&
		bytes.Equal(hint.Hint.GetGroupId(), self.world.ConfigGroupId.Bytes())
}

// Waits until the joiner's keychain holds a generation of the config repo, then checks it is the creation's
// generation 1, with no rotation since.
func (self *lateDeliveryWorld) awaitJoinerHoldsTheConfig(t *testing.T) {
	t.Helper()
	world := self.world
	for {
		held, changed := self.joiner.Client.RepoKeyHeld(world.ConfigRepoId)
		if held {
			break
		}
		select {
		case <-changed:
		case <-world.Ctx.Done():
			t.Fatal("the joiner never held the config's generation")
		}
	}
	key, err := self.joiner.Client.CurrentRepoKey(world.Ctx, world.ConfigRepoId)
	if err != nil || key.Generation() != 1 || !bytes.Equal(key.Commitment(), self.first.Commitment()) {
		t.Fatalf("the joiner's config key: %v", err)
	}
	if count := world.GenerationCountIn(world.ConfigGroupId); count != 1 {
		t.Fatalf("the config group holds %d generations: the join rotated", count)
	}
}

// Counts the device's POSTs to gkm's wraps route from now on.
func countWrapUploads(device *FsKeysDevice) *atomic.Int64 {
	count := &atomic.Int64{}
	device.Transport.Before = func(request *http.Request) FsKeysFault {
		if request.Method == http.MethodPost && strings.Contains(request.URL.Path, "/wraps/") {
			count.Add(1)
		}
		return FsKeysFaultNone
	}
	return count
}

// The joiner's first ask is answered within the late ask's interval: the writer it hints delivers at once, gkm's
// pending hint wakes the joiner, and the joiner holds the config's generation 1 with no rotation and no clock moved.
func TestJoiningDeviceTakesTheConfigGenerationWithinTheLateAskInterval(t *testing.T) {
	late := newLateDeliveryWorld(t, nil)
	world := late.world
	writerHints := late.attach(t, late.writer)
	joinerHints := late.attach(t, late.joiner)
	askedAt := world.Clock.Now()
	late.joinerTakesItsAdmission()
	relayLateDeliveryHint(t, writerHints, world.AwaitHint(late.writer, late.wrapPendingForJoiner))
	relayLateDeliveryHint(t, joinerHints, world.AwaitHint(late.joiner, late.configPending))
	late.awaitJoinerHoldsTheConfig(t)
	if elapsed := world.Clock.Now().Sub(askedAt); sidecar.DefaultGkmSettings().LateAskInterval <= elapsed {
		t.Fatalf("the join took %s, past the late ask's interval", elapsed)
	}
	if !world.WrapRecipientsIn(world.ConfigGroupId, 1)[late.joiner.SidecarId()] {
		t.Fatal("gkm holds no delivery of the config to the joiner")
	}
}

// The ask's wrap-pending reaches the config's writer and no other client: not the other holder's, which writes no
// config, and not the joiner's own.
func TestLateAskWrapPendingReachesTheConfigWriterAlone(t *testing.T) {
	late := newLateDeliveryWorld(t, nil)
	world := late.world
	late.attach(t, late.joiner)
	late.joinerTakesItsAdmission()
	hint := world.AwaitHint(late.writer, late.wrapPendingForJoiner)
	if hint.Hint.GetEpoch() != 0 {
		t.Errorf("a KeyDelivery hint names epoch %d", hint.Hint.GetEpoch())
	}
	if err := world.Engine.AwaitHints(world.Ctx); err != nil {
		t.Fatal(err)
	}
	for _, device := range []*FsKeysDevice{late.other, late.joiner} {
		if slices.ContainsFunc(world.Hints(device), func(hint *FsKeysHint) bool {
			return hint.Hint.GetKind() == protocol.GkmHintKind_GKM_HINT_WRAP_PENDING
		}) {
			t.Errorf("%s's client was told a wrap-pending", device.Label)
		}
	}
}

// A writer offline when the joiner's ask hinted it misses the hint; back, it takes the newest state, and its next
// resync writes the joiner's LATE delivery, whose pending hint wakes the joiner. A later sync PUTs nothing more for
// the joiner: the keychain records it answered for this generation.
func TestHolderOfflineAtTheHintDeliversAtItsNextResync(t *testing.T) {
	late := newLateDeliveryWorld(t, func(late *lateDeliveryWorld) {
		late.writer.Offline = true
	})
	world := late.world
	if !late.writer.Offline {
		t.Fatal("the writer was not offline at the admission")
	}
	writerHints := late.attach(t, late.writer)
	joinerHints := late.attach(t, late.joiner)
	late.joinerTakesItsAdmission()
	// the hint went to the writer's client, whose intake, offline, never heard it
	world.AwaitHint(late.writer, late.wrapPendingForJoiner)
	if err := world.Engine.AwaitHints(world.Ctx); err != nil {
		t.Fatal(err)
	}
	if held, _ := late.joiner.Client.RepoKeyHeld(world.ConfigRepoId); held {
		t.Fatal("the joiner holds the config with no delivery")
	}
	uploads := countWrapUploads(late.writer)
	late.writer.Offline = false
	late.writer.Take(late.admission)
	writerHints.Resync()
	relayLateDeliveryHint(t, joinerHints, world.AwaitHint(late.joiner, late.configPending))
	late.awaitJoinerHoldsTheConfig(t)
	if uploads.Load() == 0 {
		t.Fatal("the joiner's delivery came from no upload of the writer's")
	}
	// the next sync answers the joiner no more
	before := uploads.Load()
	if err := late.writer.Client.SyncRepo(world.Ctx, world.ConfigRepoId); err != nil {
		t.Fatal(err)
	}
	if after := uploads.Load(); after != before {
		t.Fatalf("a later sync uploaded %d more deliveries", after-before)
	}
	// and the other holder, which writes no config and signed no admission, answers nothing at its own
	otherUploads := countWrapUploads(late.other)
	if err := late.other.Client.SyncRepo(world.Ctx, world.ConfigRepoId); err != nil {
		t.Fatal(err)
	}
	if otherUploads.Load() != 0 {
		t.Fatalf("the other holder uploaded %d deliveries", otherUploads.Load())
	}
}

// The same resync once the claim's state is older than what the devices retain, their previous base past it: the
// writer tells the joiner from its row, admitted past the claim's position, and the other device, admitted before it,
// from its own, and delivers to the joiner alone.
func TestResyncAnswersAJoinerPastTheClaimsRetainedState(t *testing.T) {
	late := newLateDeliveryWorld(t, nil)
	world := late.world
	claim := world.GenerationIn(world.ConfigGroupId, 1)
	if late.admission.Pin().GetVersion() <= claim.Rotate.GetAuth().GetVersion() {
		t.Fatal("the joiner was admitted at the claim's position")
	}
	world.Retain(late.admission.Pin().GetVersion())
	if _, err := late.admission.At(claim.Rotate.GetAuth()); !errors.Is(err, sidecar.ErrGkmAuthNotRetained) {
		t.Fatalf("the claim's state is still retained: %v", err)
	}
	writerHints := late.attach(t, late.writer)
	joinerHints := late.attach(t, late.joiner)
	late.joinerTakesItsAdmission()
	// the writer's intake never hears the ask's hint
	world.AwaitHint(late.writer, late.wrapPendingForJoiner)
	uploads := countWrapUploads(late.writer)
	writerHints.Resync()
	relayLateDeliveryHint(t, joinerHints, world.AwaitHint(late.joiner, late.configPending))
	late.awaitJoinerHoldsTheConfig(t)
	if count := uploads.Load(); count != 1 {
		t.Fatalf("the writer uploaded %d deliveries, want the joiner's alone", count)
	}
}

// A self-admitted device (§5.6's reads row): the other device, which writes no config, signed the joiner's admission.
// With the config's writer offline, the signer answers the joiner at its resync; and where it learns of the ask by its
// hint, the ask's widening to the joiner's member's devices past 15 minutes, it delivers at once as the granting
// device, with no wait of its own.
func TestSelfAdmittedDeviceTakesTheConfigFromItsSigner(t *testing.T) {
	admittedBy := func(late *lateDeliveryWorld) {
		late.joiner.row.AdmissionSigners = [][]byte{late.other.SidecarId().Bytes()}
		late.writer.Offline = true
	}

	// at the signer's resync
	late := newLateDeliveryWorld(t, admittedBy)
	world := late.world
	otherHints := late.attach(t, late.other)
	joinerHints := late.attach(t, late.joiner)
	late.joinerTakesItsAdmission()
	world.AwaitHint(late.writer, late.wrapPendingForJoiner)
	otherHints.Resync()
	relayLateDeliveryHint(t, joinerHints, world.AwaitHint(late.joiner, late.configPending))
	late.awaitJoinerHoldsTheConfig(t)

	// on the widened ask's hint, at once: the signer's own jittered waits never end on this clock, which only the
	// widening moves
	late = newLateDeliveryWorld(t, admittedBy)
	world = late.world
	late.other.Jitter = func(max time.Duration) time.Duration { return max }
	late.other.Restart()
	otherHints = late.attach(t, late.other)
	joinerHints = late.attach(t, late.joiner)
	late.joinerTakesItsAdmission()
	world.AwaitHint(late.writer, late.wrapPendingForJoiner)
	if err := world.Engine.AwaitHints(world.Ctx); err != nil {
		t.Fatal(err)
	}
	world.Clock.Advance(gkmservice.DefaultGkmServiceSettings().LateAskWidenAge)
	// the joiner asks again, its first ask's since carried, and gkm widens the hint to the joiner's member's devices
	if _, err := late.joiner.Client.CurrentRepoKey(world.Ctx, world.ConfigRepoId); err == nil {
		t.Fatal("the joiner read the config before any delivery")
	}
	widened := world.AwaitHint(late.other, late.wrapPendingForJoiner)
	signedAt := world.Clock.Now()
	relayLateDeliveryHint(t, otherHints, widened)
	relayLateDeliveryHint(t, joinerHints, world.AwaitHint(late.joiner, late.configPending))
	late.awaitJoinerHoldsTheConfig(t)
	if !world.Clock.Now().Equal(signedAt) {
		t.Fatal("the granting device's delivery waited on the clock")
	}
}
