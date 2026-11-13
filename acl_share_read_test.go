//go:build !ios_extension

// FS-30's acl side: an EvsShare's subject reads an owner-bound repo only once its read receipt has landed, its author
// offline; a deposit refused fails the read closed; a share past its expires refuses the read with nothing filed; the
// repo's writer reads with no receipt; and each read is judged at its own time on the installed state.

package sidecar

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A vault of one member: its consented laptop writes it, a friend reads it by an EvsShare that ends an hour after
// aclTestNow, and an engine for each.
type aclShareReadWorld struct {
	fixture  *aclTestFixture
	vaultId  Id
	laptop   Id
	friend   Id
	expires  time.Time
	engines  map[Id]*AclEngine
	clock    *aclShareReadClock
	receipts []aclShareReadReceipt
	// what the deposit answers
	depositErr error
}

// One receipt the fake evs committed, in order.
type aclShareReadReceipt struct {
	repoId    Id
	refId     Id
	objectIds [][]byte
}

// A clock a test moves.
type aclShareReadClock struct {
	now time.Time
}

func (self *aclShareReadClock) Now() time.Time {
	return self.now
}

func (self *aclShareReadClock) After(timeout time.Duration) <-chan time.Time {
	fired := make(chan time.Time, 1)
	fired <- self.now.Add(timeout)
	return fired
}

func (self *aclShareReadClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return func() bool { return false }
}

func newAclShareReadWorld(t *testing.T) *aclShareReadWorld {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	other := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	laptop := fixture.invitedDevice(owner)
	friend := fixture.invitedDevice(other)
	vaultId, vault := fixture.repo(protocol.RepoKind_REPO_KIND_VAULT, owner)
	vault.ConsentedSidecarIds = [][]byte{laptop.Bytes()}
	expires := aclTestNow.Add(time.Hour)
	vault.Shares = []*protocol.AclRepoShareRow{{Subject: friend.Bytes(), Signer: laptop.Bytes(), At: fixture.next(), Expires: expires.UnixMilli()}}
	world := &aclShareReadWorld{
		fixture: fixture,
		vaultId: vaultId,
		laptop:  laptop,
		friend:  friend,
		expires: expires,
		engines: map[Id]*AclEngine{},
		clock:   &aclShareReadClock{now: aclTestNow},
	}
	state := fixture.state(t)
	for _, sidecarId := range []Id{laptop, friend} {
		engine := NewAclEngine(sidecarId, nil, nil, nil)
		if err := engine.Install(state, nil); err != nil {
			t.Fatal(err)
		}
		world.engines[sidecarId] = engine
	}
	return world
}

// The deposit a fake evs answers: it commits the receipt, durably here, before it returns, or refuses.
func (self *aclShareReadWorld) deposit(ctx context.Context, repoId Id, refId Id, objectIds [][]byte) error {
	if self.depositErr != nil {
		return self.depositErr
	}
	self.receipts = append(self.receipts, aclShareReadReceipt{repoId: repoId, refId: refId, objectIds: objectIds})
	return nil
}

// One read through the gate, then its decryption, which looks for its own receipt first: the order the read path keeps.
// Whether it decrypted.
func (self *aclShareReadWorld) read(t *testing.T, reader Id, refId Id) (bool, error) {
	gate := NewAclShareReadGate(self.engines[reader], self.clock, self.deposit)
	objectIds := [][]byte{[]byte("segment"), []byte("slot")}
	if err := gate(context.Background(), self.vaultId, refId, objectIds); err != nil {
		return false, err
	}
	read := self.engines[reader].ReadRequiresReceipt(self.vaultId, self.clock.Now())
	if read.RequiresReceipt {
		found := false
		for _, receipt := range self.receipts {
			found = found || (receipt.repoId == self.vaultId && receipt.refId == refId && len(receipt.objectIds) == len(objectIds))
		}
		if !found {
			t.Fatalf("decrypting before the receipt landed")
		}
	}
	return true, nil
}

// The share's subject reads with a receipt, landed before anything is decrypted, with the vault's owner offline: no
// call reaches its devices, only evs.
func TestAclShareReadLandsAReceiptFirst(t *testing.T) {
	world := newAclShareReadWorld(t)
	read := world.engines[world.friend].ReadRequiresReceipt(world.vaultId, world.clock.Now())
	if !read.Allowed || !read.RequiresReceipt || read.Reason != AclReasonEvsShare {
		t.Fatalf("the share's read: %+v", read)
	}
	refId := NewId()
	if decrypted, err := world.read(t, world.friend, refId); !decrypted || err != nil {
		t.Fatalf("the share's read: %t %v", decrypted, err)
	}
	if len(world.receipts) != 1 || world.receipts[0].refId != refId {
		t.Fatalf("receipts %+v", world.receipts)
	}
	if decrypted, err := world.read(t, world.friend, refId); !decrypted || err != nil || len(world.receipts) != 2 {
		t.Fatalf("a second read deposits again: %t %v, %d receipts", decrypted, err, len(world.receipts))
	}
}

// A deposit evs refuses fails the read closed: nothing is decrypted.
func TestAclShareReadFailsClosedWithoutItsReceipt(t *testing.T) {
	world := newAclShareReadWorld(t)
	world.depositErr = errors.New("synthetic: the deposit's 429")
	decrypted, err := world.read(t, world.friend, NewId())
	if decrypted || !errors.Is(err, ErrEvsReceiptGate) {
		t.Fatalf("a refused deposit: %t %v", decrypted, err)
	}
	gate := NewAclShareReadGate(world.engines[world.friend], world.clock, nil)
	if err := gate(context.Background(), world.vaultId, NewId(), nil); !errors.Is(err, ErrEvsReceiptGate) {
		t.Errorf("no depositor: %v", err)
	}
}

// Past the share's expires, and its skew, the read is refused before any deposit, so nothing is filed though no device
// was online to file anything; a read inside the skew still deposits.
func TestAclShareReadEndsAtItsExpiresWithNothingFiled(t *testing.T) {
	world := newAclShareReadWorld(t)
	world.clock.now = world.expires.Add(30 * time.Second)
	if decrypted, err := world.read(t, world.friend, NewId()); !decrypted || err != nil || len(world.receipts) != 1 {
		t.Fatalf("a read inside the skew: %t %v", decrypted, err)
	}
	world.clock.now = world.expires.Add(2 * DefaultAclEngineSettings().ClockSkew)
	decrypted, err := world.read(t, world.friend, NewId())
	if decrypted || !errors.Is(err, ErrAclShareReadRefused) {
		t.Fatalf("a read past the share: %t %v", decrypted, err)
	}
	if len(world.receipts) != 1 {
		t.Errorf("a read past the share filed a receipt: %d", len(world.receipts))
	}
	if read := world.engines[world.friend].ReadRequiresReceipt(world.vaultId, world.clock.Now()); read.Allowed || read.Reason != AclReasonNoGrant {
		t.Errorf("the expired share: %+v", read)
	}
}

// The vault's writer reads with no receipt; a sidecar that reads nothing there is refused, and an engine with no state
// refuses every read.
func TestAclShareReadWriterNeedsNoReceipt(t *testing.T) {
	world := newAclShareReadWorld(t)
	read := world.engines[world.laptop].ReadRequiresReceipt(world.vaultId, world.clock.Now())
	if !read.Allowed || read.RequiresReceipt {
		t.Fatalf("the writer's read: %+v", read)
	}
	if decrypted, err := world.read(t, world.laptop, NewId()); !decrypted || err != nil || len(world.receipts) != 0 {
		t.Fatalf("the writer's read: %t %v, %d receipts", decrypted, err, len(world.receipts))
	}
	stranger := NewAclEngine(NewId(), nil, nil, nil)
	if read := stranger.ReadRequiresReceipt(world.vaultId, world.clock.Now()); read.Allowed || read.Reason != AclReasonNoState {
		t.Errorf("an engine with no state: %+v", read)
	}
	if err := stranger.Install(world.fixture.state(t), nil); err != nil {
		t.Fatal(err)
	}
	if read := stranger.ReadRequiresReceipt(world.vaultId, world.clock.Now()); read.Allowed {
		t.Errorf("an unadmitted sidecar reads: %+v", read)
	}
	if err := NewAclShareReadGate(nil, world.clock, world.deposit)(context.Background(), world.vaultId, NewId(), nil); !errors.Is(err, ErrAclShareReadRefused) {
		t.Errorf("a gate with no engine: %v", err)
	}
}
