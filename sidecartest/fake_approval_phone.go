// T4's phone as approval requests reach it (MCP-M8-01, CTXH-M11-07; §16.6's flow, §11.10, §18.7, WK4; DESIGN-COMPUTE
// §24.7, D-CTXH-10), until SDK-M8-15's surrogate cells: one phone sidecar's sidecar.ApprovalPhoneLeaser over the repos
// a test has it follow, each commit a test or an ApprovalWorldLog makes standing for one push at evs:
//
//   - leases as evs keeps them (§11.10's lease and renew rows), each a prefix of one ref, a whole ref or every ref of a
//     repo, lapsing LeaseExpiry after its last renewal on the clock: a Lease of one it holds renews it, a release drops
//     that one callback, and the lease goes with its last; Kill drops every callback, as a process's end does, and
//     leaves each lease at evs until it lapses, where Standing lists it and Drop deletes it;
//   - matching (§11.10's match row): a commit's changed paths match a lease of their repo on every ref, and a lease on
//     their ref whose prefix and a changed path are on one branch of the tree, the whole ref's included;
//   - hints and wakes: a commit that matches a live lease is one hint, topic evs:<repo_id> carrying the repo's push
//     sequence, as §6.8 sends one per matching client. A process holding a callback on a matching lease takes it over
//     connect, and its stack acks it, so §18.7's sender drops the wake (step 4's ack rule); with none, §18.7 makes the
//     hint one wake, whose payload pushservice builds: the topic's class and that version, naming nothing else (WK4).
//
// So a session push, a stream push of the vault's record that no phone's notice lease matches, wakes a phone only
// through a whole-vault lease, an older release's, which the phone drops at its next renew.
//
// Safe for concurrent use.

package sidecartest

import (
	"encoding/hex"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/pushservice"
)

type FakeApprovalPhoneSettings struct {
	// A lease lapses this long after its last renewal: 7 d (§11.10's renew row).
	LeaseExpiry time.Duration
}

func DefaultFakeApprovalPhoneSettings() *FakeApprovalPhoneSettings {
	return &FakeApprovalPhoneSettings{
		LeaseExpiry: 7 * 24 * time.Hour,
	}
}

// What the phone saw, by kind.
type FakeApprovalPhoneCounts struct {
	// Leases taken where none stood or one had lapsed, renewed, released with their last callback, and dropped standing.
	LeasesTaken    int
	LeasesRenewed  int
	LeasesReleased int
	LeasesDropped  int
	// Hints a live process took over connect, which wake nothing.
	Hints int
}

// One wake §18.7 sent the phone.
type FakeApprovalWake struct {
	// The payload pushservice builds: the topic's class and its version.
	Payload pushservice.WakePayload
	// APNs' body for it, which is all a vendor carries.
	Body []byte
	// FCM's message for it, to a synthetic token.
	FcmMessage []byte
	// On the phone's clock.
	At time.Time
}

// One lease the phone holds as evs keeps it.
type FakeApprovalPhoneLease struct {
	Lease     sidecar.ApprovalPhoneLease
	RenewedAt time.Time
	// Not lapsed at the clock now.
	Live bool
	// Callbacks of a live process on it.
	Holders int
}

type fakeApprovalPhoneLease struct {
	renewedAt time.Time
	callbacks map[uint64]func(lease sidecar.ApprovalPhoneLease)
}

// The ref a record stream push lands on, as Follow models it: no phone leases it but by a lease on every ref.
const fakeApprovalPhoneStreamRef = "ur/record"

// One phone's reach to its approval logs. NewFakeApprovalPhone makes one.
type FakeApprovalPhone struct {
	clock    sidecar.Clock
	settings *FakeApprovalPhoneSettings

	stateLock    sync.Mutex
	leases       map[sidecar.ApprovalPhoneLease]*fakeApprovalPhoneLease
	nextCallback uint64
	wakes        []*FakeApprovalWake
	counts       FakeApprovalPhoneCounts
}

var _ sidecar.ApprovalPhoneLeaser = (*FakeApprovalPhone)(nil)

// A phone on clock; settings may be nil, for the defaults.
func NewFakeApprovalPhone(clock sidecar.Clock, settings *FakeApprovalPhoneSettings) *FakeApprovalPhone {
	if settings == nil {
		settings = DefaultFakeApprovalPhoneSettings()
	}
	return &FakeApprovalPhone{
		clock:    clock,
		settings: settings,
		leases:   map[sidecar.ApprovalPhoneLease]*fakeApprovalPhoneLease{},
	}
}

// Follows log's pushes as stream pushes of the repo logId at evs, on a writer's owned ref under e/: each matches the
// phone's leases on every ref of logId alone, until the answer stops it.
func (self *FakeApprovalPhone) Follow(logId sidecar.Id, log *ApprovalWorldLog) func() {
	return log.AddCommitListener(func(sequence uint64) {
		self.Commit(logId, fakeApprovalPhoneStreamRef, []string{"e/"}, sequence)
	})
}

// Follows log's requests, decisions and cancels as the notices their writers write at a/<approval_id> on the main ref
// of the vault vaultId (record_approval_notice.go): each a commit of its own, until the answer stops it.
func (self *FakeApprovalPhone) FollowNotices(vaultId sidecar.Id, log *ApprovalWorldLog) func() {
	return log.AddNoticeListener(func(approvalId sidecar.Id, sequence uint64) {
		self.Commit(vaultId, "", []string{FakeApprovalNoticePath(approvalId)}, sequence)
	})
}

// a/<approval_id>, as record_approval_notice.go names a notice: the id in 32 lowercase hex.
func FakeApprovalNoticePath(approvalId sidecar.Id) string {
	return "a/" + hex.EncodeToString(approvalId[:])
}

// Takes or renews the phone's lease, as one POST /evs/v1/subscriptions does, and adds callback to it.
func (self *FakeApprovalPhone) Lease(lease sidecar.ApprovalPhoneLease, callback func(lease sidecar.ApprovalPhoneLease)) (func(), error) {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	held, ok := self.leases[lease]
	switch {
	case !ok:
		held = &fakeApprovalPhoneLease{callbacks: map[uint64]func(lease sidecar.ApprovalPhoneLease){}}
		self.leases[lease] = held
		self.counts.LeasesTaken += 1
	case now.Before(held.renewedAt.Add(self.settings.LeaseExpiry)):
		self.counts.LeasesRenewed += 1
	default:
		// lapsed: evs takes it as a new lease
		self.counts.LeasesTaken += 1
	}
	held.renewedAt = now
	self.nextCallback += 1
	callbackId := self.nextCallback
	held.callbacks[callbackId] = callback
	return func() { self.release(lease, callbackId) }, nil
}

// Drops one callback, and the lease with its last, as DELETE /evs/v1/subscriptions does once nothing shares it.
func (self *FakeApprovalPhone) release(lease sidecar.ApprovalPhoneLease, callbackId uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	held, ok := self.leases[lease]
	if !ok {
		return
	}
	if _, ok := held.callbacks[callbackId]; !ok {
		return
	}
	delete(held.callbacks, callbackId)
	if len(held.callbacks) == 0 {
		delete(self.leases, lease)
		self.counts.LeasesReleased += 1
	}
}

// The leases on repoId that no live callback holds, lapsed ones left out: what an earlier process left standing.
func (self *FakeApprovalPhone) Standing(repoId sidecar.Id) ([]sidecar.ApprovalPhoneLease, error) {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	standing := []sidecar.ApprovalPhoneLease{}
	for lease, held := range self.leases {
		if lease.RepoId == repoId && len(held.callbacks) == 0 && now.Before(held.renewedAt.Add(self.settings.LeaseExpiry)) {
			standing = append(standing, lease)
		}
	}
	return standing, nil
}

// Deletes a lease at evs, whatever its callbacks.
func (self *FakeApprovalPhone) Drop(lease sidecar.ApprovalPhoneLease) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, ok := self.leases[lease]; ok {
		delete(self.leases, lease)
		self.counts.LeasesDropped += 1
	}
	return nil
}

// The phone's process ends: every callback goes, and evs keeps each lease until it lapses, so wakes come.
func (self *FakeApprovalPhone) Kill() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, held := range self.leases {
		held.callbacks = map[uint64]func(lease sidecar.ApprovalPhoneLease){}
	}
}

// Whether a lease matches a commit to ref of its repo that changed paths (§11.10's match row).
func fakeApprovalPhoneMatches(lease sidecar.ApprovalPhoneLease, ref string, paths []string) bool {
	if lease.EveryRef {
		return true
	}
	if lease.Ref != ref {
		return false
	}
	if lease.Prefix == "" {
		return true
	}
	for _, path := range paths {
		if strings.HasPrefix(path, lease.Prefix) || strings.HasPrefix(lease.Prefix, strings.TrimSuffix(path, "/")+"/") {
			return true
		}
	}
	return false
}

// One commit to ref of repoId that changed paths, the repo's push sequence then: one hint to a live process holding a
// matching lease, or one wake with none; nothing past a lease's lapse. Callbacks run with no lock held.
func (self *FakeApprovalPhone) Commit(repoId sidecar.Id, ref string, paths []string, sequence uint64) {
	now := self.clock.Now()
	callbacks := func() []func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		matched := []sidecar.ApprovalPhoneLease{}
		held := false
		for lease, entry := range self.leases {
			if lease.RepoId != repoId || !now.Before(entry.renewedAt.Add(self.settings.LeaseExpiry)) || !fakeApprovalPhoneMatches(lease, ref, paths) {
				continue
			}
			matched = append(matched, lease)
			held = held || 0 < len(entry.callbacks)
		}
		if len(matched) == 0 {
			return nil
		}
		if !held {
			class, wakes := pushservice.WakeTopicClass(sidecar.PushTopicEvs(repoId))
			if wakes {
				payload := pushservice.WakePayload{TopicClass: class, Version: sequence}
				self.wakes = append(self.wakes, &FakeApprovalWake{
					Payload:    payload,
					Body:       pushservice.ApnsWakeBody(&payload),
					FcmMessage: pushservice.FcmWakeMessage("fake-approval-phone-token", &payload),
					At:         now,
				})
			}
			return nil
		}
		self.counts.Hints += 1
		slices.SortFunc(matched, fakeApprovalPhoneLeaseCmp)
		callbacks := []func(){}
		for _, lease := range matched {
			entry := self.leases[lease]
			for _, callbackId := range slices.Sorted(maps.Keys(entry.callbacks)) {
				callback := entry.callbacks[callbackId]
				callbacks = append(callbacks, func() { callback(lease) })
			}
		}
		return callbacks
	}()
	for _, callback := range callbacks {
		callback()
	}
}

// Every wake so far, in order.
func (self *FakeApprovalPhone) Wakes() []*FakeApprovalWake {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.wakes)
}

// The calls so far.
func (self *FakeApprovalPhone) Counts() FakeApprovalPhoneCounts {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.counts
}

// The order Leases lists in: by repo, every ref first, then ref and prefix.
func fakeApprovalPhoneLeaseCmp(a sidecar.ApprovalPhoneLease, b sidecar.ApprovalPhoneLease) int {
	if c := a.RepoId.Cmp(b.RepoId); c != 0 {
		return c
	}
	if a.EveryRef != b.EveryRef {
		if a.EveryRef {
			return -1
		}
		return 1
	}
	if c := strings.Compare(a.Ref, b.Ref); c != 0 {
		return c
	}
	return strings.Compare(a.Prefix, b.Prefix)
}

// The leases evs holds for this phone, lapsed ones included until a release or a drop removes them, in order.
func (self *FakeApprovalPhone) Leases() []FakeApprovalPhoneLease {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	leases := []FakeApprovalPhoneLease{}
	for _, lease := range slices.SortedFunc(maps.Keys(self.leases), fakeApprovalPhoneLeaseCmp) {
		held := self.leases[lease]
		leases = append(leases, FakeApprovalPhoneLease{
			Lease:     lease,
			RenewedAt: held.renewedAt,
			Live:      now.Before(held.renewedAt.Add(self.settings.LeaseExpiry)),
			Holders:   len(held.callbacks),
		})
	}
	return leases
}
