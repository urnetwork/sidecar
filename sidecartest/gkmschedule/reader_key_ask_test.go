package gkmschedule

// A KeyDelivery reader gkm serves no ReaderKey for (v0, owner decision 610; DESIGN-DETAILS 6.2.4's asker row: a device
// none of whose keys opens anything publishes a fresh ReaderKey first), on T2's world with each device's hint intake
// attached and each hint relayed as the exchange's publisher would: a network's first device whose upkeep's first
// upload went before gkm loaded its network, and which then reads a group repo a RepoGrant to its member lets it read,
// as the e2e mail case's owner devices did. Here too are the KeyDelivery helpers the pending and creation cases share:
// a repo the granter formed and a reader it grants, a device's attached intake, the wait for a held generation and the
// signer of a stored delivery.

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A KeyDelivery world whose repo the granter formed, a writer, beside other, a writer that holds generation 1 by its
// STAGED wrap; reader, a read_only member device granted read at grant, after the claim, by the granter's RepoGrant,
// or with admitted by the granter's admission of it and an unsigned grant, holding the state but no hint intake yet.
type pendingDeliveryWorld struct {
	world   *FsKeysWorld
	granter *FsKeysDevice
	other   *FsKeysDevice
	reader  *FsKeysDevice
	first   *sidecar.EvsRepoKey
	grant   sidecar.GkmAuthView
}

func newPendingDeliveryWorld(t *testing.T, admitted bool, publish bool) *pendingDeliveryWorld {
	world := NewFsKeysWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	ctx, cancel := context.WithTimeout(world.Ctx, 30*time.Second)
	t.Cleanup(cancel)
	world.Ctx = ctx
	world.Reconfigure(func(settings *gkmservice.GkmServiceSettings) { settings.DraftMls = false })
	self := &pendingDeliveryWorld{world: world}
	self.granter = world.AddMember("granter", false)
	self.other = world.AddMember("other", false)
	world.Grant(true, self.granter, self.other)
	world.Creator(self.granter)
	world.Advance()
	world.Publish()
	self.first = world.Create(self.granter)
	if !world.WrapRecipients(1)[self.other.SidecarId()] {
		t.Fatal("the creation staged no wrap to the other writer")
	}
	// the other writer holds generation 1, as its creation's wake has it take
	world.Again("the other writer's key", func() error {
		_, err := self.other.Client.CurrentRepoKey(world.Ctx, world.RepoId)
		return err
	})
	self.reader = world.AddMember("reader", true)
	if admitted {
		self.reader.row.AdmissionSigners = [][]byte{self.granter.SidecarId().Bytes()}
		world.Grant(false, self.reader)
	} else {
		world.GrantBy(self.granter, false, self.reader)
	}
	self.grant = world.Advance()
	if publish {
		self.reader.PublishReaderKey()
	}
	return self
}

// The device's hint intake, attached to its key client until the test ends.
func attachPendingHints(t *testing.T, world *FsKeysWorld, device *FsKeysDevice) *sidecar.GkmHints {
	t.Helper()
	hints, err := sidecar.NewGkmHints(world.Ctx, &sidecar.GkmHintsArgs{Clock: world.Clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hints.Close)
	device.Client.AttachHints(world.Ctx, hints)
	return hints
}

// Waits until the device's keychain holds a generation of the repo, then checks it is the creation's generation 1.
func awaitHoldsFirst(t *testing.T, world *FsKeysWorld, device *FsKeysDevice, first *sidecar.EvsRepoKey) {
	t.Helper()
	for {
		held, changed := device.Client.RepoKeyHeld(world.RepoId)
		if held {
			break
		}
		select {
		case <-changed:
		case <-world.Ctx.Done():
			t.Fatalf("%s never held the repo's generation", device.Label)
		}
	}
	key, err := device.Client.CurrentRepoKey(world.Ctx, world.RepoId)
	if err != nil || key.Generation() != 1 || !bytes.Equal(key.Commitment(), first.Commitment()) {
		t.Fatalf("%s's key: %v", device.Label, err)
	}
}

// The signer of the delivery gkm holds of generation 1 to device, nil for none.
func deliverySigner(t *testing.T, world *FsKeysWorld, device *FsKeysDevice) *sidecar.Id {
	t.Helper()
	recipient := "/" + fsKeysRecipient(device.SidecarId()) + "/"
	for key, body := range world.objects(gkmservice.GkmWrapGenerationPrefix(world.GroupId, 1)) {
		if !strings.Contains(key, recipient) {
			continue
		}
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(body, signed); err != nil {
			t.Fatalf("a stored delivery: %v", err)
		}
		delivery, err := sidecar.ParseGkmDelivery(signed, sidecar.GkmWrapTypeReader, sidecar.GkmIdentityKeys(world.Log.Tip()))
		if err != nil {
			t.Fatalf("a stored delivery: %v", err)
		}
		return &delivery.SignerId
	}
	return nil
}

// A reader gkm serves no ReaderKey for, its upkeep's first upload refused as gkm refuses one before it has loaded the
// network's state: its first ask, at the grant, sends no want, since nothing could be sealed to it, and has the upkeep
// publish its ReaderKey, whose upload resyncs its intake; the ask that follows reaches the granter, which delivers at
// once, and the reader holds generation 1 with no clock moved, so within the late ask's interval.
func TestReaderWithNoReaderKeyPublishesOneAtItsFirstAsk(t *testing.T) {
	pending := newPendingDeliveryWorld(t, false, false)
	world := pending.world
	reader := pending.reader
	transportLock := sync.Mutex{}
	refusing := true
	wantsWithoutKey := 0
	var upkeep *sidecar.GkmUpkeep
	reader.Transport.Respond = func(request *http.Request) *http.Response {
		transportLock.Lock()
		defer transportLock.Unlock()
		if refusing && request.Method == http.MethodPost && request.URL.Path == "/gkm/reader-key" {
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: http.Header{}, Body: http.NoBody, Request: request}
		}
		if request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/wraps/") && request.URL.Query().Get("want") != "" && upkeep != nil &&
			upkeep.CurrentReaderKeySha256() == nil {
			wantsWithoutKey += 1
		}
		return nil
	}
	readerHints, err := sidecar.NewGkmHints(world.Ctx, &sidecar.GkmHintsArgs{Clock: world.Clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(readerHints.Close)
	func() {
		transportLock.Lock()
		defer transportLock.Unlock()
		upkeep = reader.StartUpkeep(readerHints)
	}()
	for {
		count, changed := upkeep.Passes()
		if 1 <= count {
			break
		}
		select {
		case <-changed:
		case <-world.Ctx.Done():
			t.Fatal("the upkeep's first pass never ended")
		}
	}
	if upkeep.CurrentReaderKeySha256() != nil {
		t.Fatal("a refused upload left a current ReaderKey")
	}
	func() {
		transportLock.Lock()
		defer transportLock.Unlock()
		refusing = false
	}()
	granterHints := attachPendingHints(t, world, pending.granter)
	reader.Client.AttachHints(world.Ctx, readerHints)
	// the grant's sync: the first wrap is asked for, and with no ReaderKey the upkeep is asked to publish one
	if err := reader.Client.SyncRepo(world.Ctx, world.RepoId); err == nil {
		t.Fatal("the reader synced a key before any delivery")
	}
	ask := world.AwaitHint(pending.granter, func(hint *FsKeysHint) bool {
		return hint.Hint.GetKind() == protocol.GkmHintKind_GKM_HINT_WRAP_PENDING && bytes.Equal(hint.Hint.GetGroupId(), world.GroupId.Bytes()) &&
			string(hint.Hint.GetRecipient()) == fsKeysRecipient(reader.SidecarId())
	})
	relayLateDeliveryHint(t, granterHints, ask)
	relayLateDeliveryHint(t, readerHints, world.AwaitHint(reader, world.pendingHint))
	awaitHoldsFirst(t, world, reader, pending.first)
	if signer := deliverySigner(t, world, reader); signer == nil || *signer != pending.granter.SidecarId() {
		t.Fatal("the reader's delivery is not the granter's")
	}
	transportLock.Lock()
	defer transportLock.Unlock()
	if wantsWithoutKey != 0 {
		t.Fatalf("the reader asked %d times with no ReaderKey at gkm", wantsWithoutKey)
	}
}
