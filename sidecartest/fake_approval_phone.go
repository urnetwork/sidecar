// T4's phone as approval requests reach it (MCP-M8-01; §16.6's flow, §11.10, §18.7, WK4), until SDK-M8-15's surrogate
// cells: one phone sidecar's sidecar.ApprovalPhoneLeaser over the approval logs a test has it follow, an
// ApprovalWorldLog standing for each log's pushes at evs:
//
//   - leases as evs keeps them, one per log this phone holds, each lapsing LeaseExpiry after its last renewal on the
//     clock (§11.10's renew row): a Lease of a log it holds renews it, a release drops that one callback, and the
//     lease goes with its last; Kill drops every callback, as a process's end does, and leaves each lease at evs until
//     it lapses;
//   - hints and wakes: each commit to a followed log under a live lease is one hint, topic evs:<log_id> carrying the
//     log's push sequence. A process holding a callback on the lease takes the hint over connect, and its stack acks
//     it, so §18.7's sender drops the wake (step 4's ack rule); with none, §18.7 makes the hint one wake, whose payload
//     pushservice builds: the topic's class and that version, naming nothing else (WK4).
//
// Safe for concurrent use.

package sidecartest

import (
	"maps"
	"slices"
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
	// Leases taken where none stood or one had lapsed, renewed, and released.
	LeasesTaken    int
	LeasesRenewed  int
	LeasesReleased int
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
	LogId     sidecar.Id
	RenewedAt time.Time
	// Not lapsed at the clock now.
	Live bool
	// Callbacks of a live process on it.
	Holders int
}

type fakeApprovalPhoneLease struct {
	renewedAt time.Time
	callbacks map[uint64]func(logId sidecar.Id)
}

// One phone's reach to its approval logs. NewFakeApprovalPhone makes one.
type FakeApprovalPhone struct {
	clock    sidecar.Clock
	settings *FakeApprovalPhoneSettings

	stateLock    sync.Mutex
	leases       map[sidecar.Id]*fakeApprovalPhoneLease
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
		leases:   map[sidecar.Id]*fakeApprovalPhoneLease{},
	}
}

// Follows log as the repo logId at evs: each commit to it hints the phone's lease on logId while that lease is live,
// until the answer stops it.
func (self *FakeApprovalPhone) Follow(logId sidecar.Id, log *ApprovalWorldLog) func() {
	return log.AddCommitListener(func(sequence uint64) {
		self.hint(logId, sequence)
	})
}

// Takes or renews the phone's lease on logId, as one POST /evs/v1/subscriptions does, and adds callback to it.
func (self *FakeApprovalPhone) Lease(logId sidecar.Id, callback func(logId sidecar.Id)) (func(), error) {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	lease, held := self.leases[logId]
	switch {
	case !held:
		lease = &fakeApprovalPhoneLease{callbacks: map[uint64]func(logId sidecar.Id){}}
		self.leases[logId] = lease
		self.counts.LeasesTaken += 1
	case now.Before(lease.renewedAt.Add(self.settings.LeaseExpiry)):
		self.counts.LeasesRenewed += 1
	default:
		// lapsed: evs takes it as a new lease
		self.counts.LeasesTaken += 1
	}
	lease.renewedAt = now
	self.nextCallback += 1
	callbackId := self.nextCallback
	lease.callbacks[callbackId] = callback
	return func() { self.release(logId, callbackId) }, nil
}

// Drops one callback, and the lease with its last, as DELETE /evs/v1/subscriptions does once nothing shares it.
func (self *FakeApprovalPhone) release(logId sidecar.Id, callbackId uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	lease, ok := self.leases[logId]
	if !ok {
		return
	}
	if _, ok := lease.callbacks[callbackId]; !ok {
		return
	}
	delete(lease.callbacks, callbackId)
	if len(lease.callbacks) == 0 {
		delete(self.leases, logId)
		self.counts.LeasesReleased += 1
	}
}

// The phone's process ends: every callback goes, and evs keeps each lease until it lapses, so wakes come.
func (self *FakeApprovalPhone) Kill() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, lease := range self.leases {
		lease.callbacks = map[uint64]func(logId sidecar.Id){}
	}
}

// One commit to logId at sequence: the hint to a live process, or one wake with none; nothing past the lease's lapse.
// Callbacks run with no lock held.
func (self *FakeApprovalPhone) hint(logId sidecar.Id, sequence uint64) {
	now := self.clock.Now()
	callbacks := func() []func(logId sidecar.Id) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		lease, ok := self.leases[logId]
		if !ok || !now.Before(lease.renewedAt.Add(self.settings.LeaseExpiry)) {
			return nil
		}
		if len(lease.callbacks) == 0 {
			class, wakes := pushservice.WakeTopicClass(sidecar.PushTopicEvs(logId))
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
		callbacks := []func(logId sidecar.Id){}
		for _, callbackId := range slices.Sorted(maps.Keys(lease.callbacks)) {
			callbacks = append(callbacks, lease.callbacks[callbackId])
		}
		return callbacks
	}()
	for _, callback := range callbacks {
		callback(logId)
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

// The leases evs holds for this phone, lapsed ones included until a release drops them, in log order.
func (self *FakeApprovalPhone) Leases() []FakeApprovalPhoneLease {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	leases := []FakeApprovalPhoneLease{}
	for _, logId := range slices.SortedFunc(maps.Keys(self.leases), sidecar.Id.Cmp) {
		lease := self.leases[logId]
		leases = append(leases, FakeApprovalPhoneLease{
			LogId:     logId,
			RenewedAt: lease.renewedAt,
			Live:      now.Before(lease.renewedAt.Add(self.settings.LeaseExpiry)),
			Holders:   len(lease.callbacks),
		})
	}
	return leases
}
