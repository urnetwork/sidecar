//go:build !ios_extension

// §16.6's host table for apps (MCP-M8-01; D-MCP-14, D-MCP-19, D-SDK-9, I-8, FS-124), beside MCP-M3-07's approver side
// (record_approval_decide.go), which applies it:
//
//	host        what an approver's device signs, and on which channel
//	  daemon      ur daemon: ur approve <id> confirmed on /dev/tty signs other sidecars' requests by device, and this
//	              sidecar's own by presence through the daemon's prompt; harness_ok's decisions are the gate's
//	              (record_harness.go). The approver side's default
//	  app local   an iOS or Android app in local mode (SidecarApprovals): others' requests by device, its own by
//	              presence through the app's SidecarPresenceSigner
//	  app remote  a desktop app in remote mode, over its daemon's app methods (daemon_approvals_app.go): other sidecars'
//	              requests by device, after the app's confirmation; never the daemon's own, which it lists with no
//	              decision, for ur approve or the daemon's prompt (D-SDK-9)
//	  nothing     a page Worker, quick burner, tagged, ephemeral or cloud sidecar: no host of it signs, as the
//	              approver's standing refuses every device that is not approval-capable (D-MCP-14)
//	templates   an app's Decide carries no uses (§18.5), and a template's approval takes 2 or more (D-MCP-11), so an
//	            app host lists a template request with deny alone; ur approve --uses approves one. QD-1010 gives the
//	            request the uses its agent asks for, which an app then approves as shown; until that lands, deny alone
//	log         InstallApproverLog: the approval logs the approver side reads in place of its record's, on a host
//	            whose record has no streams bound yet (RECORD-M3-12's binding has no composition), and in tests
//	phone       an ApprovalRequest reaches a phone by its evs hint, else §18.7's wake (§16.6's flow): an app host
//	            in local mode binds ApprovalPhone, which leases each approval log this device reads, whole, so a
//	            request's push, its decision's and its cancel's hint it while the app runs and wake it, topic class
//	            evs and a version alone (WK4), while it does not. The host runs Resync at each of its resyncs (its
//	            open, each wake, each hint, hourly while open), which renews a lease once ApprovalPhoneLeaseRenewAge
//	            old, reads the logs and raises approval_pending once for each request newly waiting for this
//	            device's decision, so SidecarApprovals' listener reads GetPending again. Close releases nothing:
//	            evs keeps each lease until it lapses, so a closed app is still woken, and the next process takes them
//	            again. A device that is no approval-capable device of its member leases nothing and raises nothing.
//	            No app host binds it yet: its leaser over EvsRepo.Subscribe and a record with its streams bound are
//	            RECORD-M3-12's binding, which no composition makes, so until then no approval wakes a phone, the
//	            closed direction, and an open app hears a request at SidecarApprovals' refresh
//
// The phone's leases name whole logs, so every push to a log wakes it, a capture's too: §18.7's per-client coalescing
// and the vendors' caps bound the wakes, and a wake spent on another push still brings the phone to its resync, which
// reads the requests that wait.
//
// Nothing here creates, derives or unwraps a key. Safe for concurrent use. On every leg but the ios_extension legs.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar/protocol"
)

// Which row of §16.6's host table an approver's device decides as (see the file's comment). The zero value is the
// daemon's, the approver side's default.
type ApprovalHost int

const (
	// ur daemon: ur approve <id> on /dev/tty, its own agents' requests by the daemon's prompt.
	ApprovalHostDaemon ApprovalHost = iota
	// An iOS or Android app in local mode.
	ApprovalHostAppLocal
	// A desktop app in remote mode, over its daemon's app methods.
	ApprovalHostAppRemote
)

var (
	// A remote-mode app signs no decision on its daemon's own request (D-SDK-9): the member's presence key does, by ur
	// approve or the daemon's prompt.
	ErrApprovalRemoteOwnRequest = fmt.Errorf("%w: a remote-mode app signs no decision on its daemon's own request, which the member's presence key approves by ur approve or the daemon's prompt", ErrSidecarApprovalNotEligible)
	// The phone's approval part was closed.
	ErrApprovalPhoneClosed = errors.New("the phone's approval part is closed")
)

// The channel host signs a request on, own being this sidecar's own request: device for another sidecar's; for its own,
// presence where host takes it, else none, as for a host this table does not know.
func ApprovalHostChannel(host ApprovalHost, own bool) protocol.ApprovalChannel {
	switch host {
	case ApprovalHostDaemon, ApprovalHostAppLocal:
		if own {
			return protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE
		}
		return protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE
	case ApprovalHostAppRemote:
		if own {
			return protocol.ApprovalChannel_APPROVAL_CHANNEL_UNSPECIFIED
		}
		return protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE
	}
	return protocol.ApprovalChannel_APPROVAL_CHANNEL_UNSPECIFIED
}

// A channel's name as ur and the apps show it: device, presence or harness; empty for none.
func approvalChannelName(channel protocol.ApprovalChannel) string {
	switch channel {
	case protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE:
		return "device"
	case protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE:
		return "presence"
	case protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS:
		return "harness"
	}
	return ""
}

// Whether host is an app's, whose Decide carries no uses.
func approvalHostApp(host ApprovalHost) bool {
	return host == ApprovalHostAppLocal || host == ApprovalHostAppRemote
}

// What host may answer a request it signs on a channel: approve and deny; deny alone for a template on an app host,
// which cannot give the template's uses (the file's templates row).
func approvalHostDecisions(host ApprovalHost, request *StoredApprovalRequest) []string {
	if approvalHostApp(host) && request.Action.Action.GetScope() {
		return []string{SidecarDecisionDeny}
	}
	return []string{SidecarDecisionApprove, SidecarDecisionDeny}
}

// The same approver side, deciding as host's row of the table. The receiver is not changed.
func (self *ApprovalApprover) ForHost(host ApprovalHost) *ApprovalApprover {
	return &ApprovalApprover{sidecar: self.sidecar, log: self.log, details: self.details, sockets: self.sockets, host: host}
}

// The row this approver side decides as.
func (self *ApprovalApprover) Host() ApprovalHost {
	return self.host
}

// An app host's approval parts on its Sidecar, made on first use: the installed log, and the phone part.
type sidecarApprovalApps struct {
	stateLock sync.Mutex
	log       ApproverLog
	// raised at each install and removal, so a removal of a log another install replaced does nothing
	changes uint64
	phone   *ApprovalPhone
}

// This Sidecar's approval parts.
func (self *Sidecar) approvalAppsState() *sidecarApprovalApps {
	if apps, ok := self.approvalApps.Load().(*sidecarApprovalApps); ok {
		return apps
	}
	self.approvalApps.CompareAndSwap(nil, &sidecarApprovalApps{})
	return self.approvalApps.Load().(*sidecarApprovalApps)
}

// Installs log as the approval logs this sidecar's approver side reads (ApprovalApprover), in place of its record's
// approvals, replacing any before; the answer removes it if it is still the installed one. A host whose record has no
// streams bound lists no request without one; a test installs its world's log.
func (self *Sidecar) InstallApproverLog(log ApproverLog) func() {
	apps := self.approvalAppsState()
	change := func() uint64 {
		apps.stateLock.Lock()
		defer apps.stateLock.Unlock()
		apps.log = log
		apps.changes += 1
		return apps.changes
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			apps.stateLock.Lock()
			defer apps.stateLock.Unlock()
			if apps.changes == change {
				apps.log = nil
				apps.changes += 1
			}
		})
	}
}

// The log InstallApproverLog installed, nil for none.
func (self *Sidecar) installedApproverLog() ApproverLog {
	apps := self.approvalAppsState()
	apps.stateLock.Lock()
	defer apps.stateLock.Unlock()
	return apps.log
}

// What a phone's approval part leases each approval log through (§11.10's lease row): the whole log, a hint calling
// callback, with no lock held, at each commit to it, until release, which drops this callback, and the lease with its
// last. Leasing a log already leased renews it. evs keeps a lease until it lapses unrenewed, whether or not a process
// holds a callback on it, and hints the client then by §18.7's wake. RECORD-M3-12's binding serves it over
// EvsRepo.Subscribe; sidecartest's FakeApprovalPhone is T4's surrogate. Safe for concurrent use.
type ApprovalPhoneLeaser interface {
	Lease(logId Id, callback func(logId Id)) (release func(), err error)
}

// What a phone's approval part is bound with.
type ApprovalPhoneArgs struct {
	Leaser ApprovalPhoneLeaser
	// The approval logs to lease; nil for the ones the approver side's log reads (the author's vault, and the team
	// record where this device reads it).
	Logs func() ([]Id, error)
	// Called with no lock held at each hint, so the app host runs Resync; nil for none. It runs on the leaser's
	// goroutine, which a hint's reader shares, so it must not block: the host runs Resync on its own.
	Hinted func()
}

// What one Resync did.
type ApprovalPhoneResynced struct {
	// Leases taken where this process held none, renewed once ApprovalPhoneLeaseRenewAge old, and released.
	LeasesTaken    int
	LeasesRenewed  int
	LeasesReleased int
	// The logs leased now, sorted.
	Leased []Id
	// The requests waiting for this device's decision now, in the order the approver side lists them.
	Pending []Id
	// The requests of Pending newly waiting, for each of which approval_pending was raised.
	Raised []Id
	// Logs a hint, a lapse or a first lease made due since the last Resync, all read now, sorted.
	Due []Id
}

// One lease this process holds on a log.
type approvalPhoneLease struct {
	release        func()
	leasedAtMillis int64
}

// An app host's phone part for approvals: see the file's comment. Safe for concurrent use.
type ApprovalPhone struct {
	sidecar *Sidecar
	args    *ApprovalPhoneArgs

	// one Resync at a time
	writeLock sync.Mutex

	stateLock sync.Mutex
	leases    map[Id]*approvalPhoneLease
	// logs to read at the next Resync: hinted, first taken, or lapsed
	due map[Id]bool
	// the requests approval_pending was raised for, while they wait
	raised map[Id]bool
	closed bool
}

// Binds this sidecar's phone part for approvals, which an app host in local mode calls once: from then on Resync
// leases its approval logs. Binding again replaces the args of the part already bound, which keeps its leases.
func (self *Sidecar) BindApprovalPhone(args *ApprovalPhoneArgs) (*ApprovalPhone, error) {
	if args == nil || args.Leaser == nil {
		return nil, errors.New("a phone's approval part leases through a leaser")
	}
	argsCopy := *args
	apps := self.approvalAppsState()
	apps.stateLock.Lock()
	defer apps.stateLock.Unlock()
	if apps.phone != nil && !apps.phone.isClosed() {
		apps.phone.setArgs(&argsCopy)
		return apps.phone, nil
	}
	apps.phone = &ApprovalPhone{
		sidecar: self,
		args:    &argsCopy,
		leases:  map[Id]*approvalPhoneLease{},
		due:     map[Id]bool{},
		raised:  map[Id]bool{},
	}
	return apps.phone, nil
}

// This sidecar's phone part for approvals, nil until BindApprovalPhone or once closed: a desktop's has none.
func (self *Sidecar) ApprovalPhone() *ApprovalPhone {
	apps := self.approvalAppsState()
	apps.stateLock.Lock()
	defer apps.stateLock.Unlock()
	if apps.phone == nil || apps.phone.isClosed() {
		return nil
	}
	return apps.phone
}

// Replaces the args a later Resync and hint read.
func (self *ApprovalPhone) setArgs(args *ApprovalPhoneArgs) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.args = args
}

// The args bound last.
func (self *ApprovalPhone) currentArgs() *ApprovalPhoneArgs {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.args
}

// Whether Close ended this part.
func (self *ApprovalPhone) isClosed() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.closed
}

// The callback of the lease on logId: marks it due and cues the app host.
func (self *ApprovalPhone) hintFunc(logId Id) func(logId Id) {
	return func(Id) {
		hinted := func() func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.closed {
				return nil
			}
			self.due[logId] = true
			return self.args.Hinted
		}()
		if hinted != nil {
			hinted()
		}
	}
}

// Renews the phone's leases, reads its approval logs and raises approval_pending once for each request newly waiting
// for this device's decision (the file's phone row). A device that is no approval-capable device of its member
// releases every lease and raises nothing. A lease that could not be taken is taken at the next Resync.
func (self *ApprovalPhone) Resync(ctx context.Context) (*ApprovalPhoneResynced, error) {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	if self.isClosed() {
		return nil, ErrApprovalPhoneClosed
	}
	args := self.currentArgs()
	resynced := &ApprovalPhoneResynced{}
	approver, err := self.sidecar.ApprovalApprover()
	if err != nil {
		return nil, err
	}
	approver = approver.ForHost(ApprovalHostAppLocal)
	wanted := map[Id]bool{}
	if _, _, _, err := approver.standing(); err == nil {
		logs := args.Logs
		if logs == nil {
			logs = approver.log.approvalLogs
		}
		logIds, err := logs()
		if err != nil {
			return nil, err
		}
		for _, logId := range logIds {
			wanted[logId] = true
		}
	} else if !errors.Is(err, ErrSidecarApprovalNotEligible) {
		return nil, err
	}
	self.holdLeases(args.Leaser, wanted, resynced)

	items, err := approver.Pending(ctx)
	if err != nil {
		return nil, err
	}
	pending := map[Id]*SidecarRequestItem{}
	for _, item := range items {
		if item.Render == nil || len(item.Decisions) == 0 {
			continue
		}
		resynced.Pending = append(resynced.Pending, item.ApprovalId)
		pending[item.ApprovalId] = item
	}
	raise := func() []*SidecarRequestItem {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return nil
		}
		for approvalId := range self.raised {
			if pending[approvalId] == nil {
				delete(self.raised, approvalId)
			}
		}
		raise := []*SidecarRequestItem{}
		for _, approvalId := range resynced.Pending {
			if !self.raised[approvalId] {
				self.raised[approvalId] = true
				raise = append(raise, pending[approvalId])
			}
		}
		resynced.Due = slices.SortedFunc(maps.Keys(self.due), Id.Cmp)
		self.due = map[Id]bool{}
		resynced.Leased = slices.SortedFunc(maps.Keys(self.leases), Id.Cmp)
		return raise
	}()
	for _, item := range raise {
		approvalId := item.ApprovalId
		event := SidecarEvent{Kind: SidecarEventApprovalPending, ApprovalId: &approvalId}
		if requesterId := item.Render.RequesterSidecarId; requesterId != (Id{}) {
			event.SidecarId = &requesterId
		}
		self.sidecar.emitEvent(event)
		resynced.Raised = append(resynced.Raised, approvalId)
	}
	return resynced, nil
}

// Holds wanted and releases the rest. A lease is taken again before the one it renews goes, so evs holds it
// throughout. One this process did not hold, or held ApprovalPhoneLeaseExpiry, had lapsed or never stood, so its log is
// due, what changed meanwhile being unknown.
func (self *ApprovalPhone) holdLeases(leaser ApprovalPhoneLeaser, wanted map[Id]bool, resynced *ApprovalPhoneResynced) {
	settings := self.sidecar.settings.Mcp
	nowMillis := self.sidecar.clock.Now().UnixMilli()
	renewAge := settings.ApprovalPhoneLeaseRenewAge.Milliseconds()
	expiry := settings.ApprovalPhoneLeaseExpiry.Milliseconds()
	releases := []func(){}
	takes := []Id{}
	lapsed := map[Id]bool{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for logId, lease := range self.leases {
			if !wanted[logId] {
				releases = append(releases, lease.release)
				delete(self.leases, logId)
			}
		}
		for logId := range wanted {
			lease, held := self.leases[logId]
			switch {
			case !held:
				takes = append(takes, logId)
				lapsed[logId] = true
			case lease.leasedAtMillis+renewAge <= nowMillis:
				takes = append(takes, logId)
				lapsed[logId] = lease.leasedAtMillis+expiry <= nowMillis
			}
		}
	}()
	for _, release := range releases {
		release()
		resynced.LeasesReleased += 1
	}
	slices.SortFunc(takes, Id.Cmp)
	for _, logId := range takes {
		release, err := leaser.Lease(logId, self.hintFunc(logId))
		if err != nil {
			// taken at the next resync
			continue
		}
		old, kept := func() (*approvalPhoneLease, bool) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.closed {
				return nil, false
			}
			old := self.leases[logId]
			self.leases[logId] = &approvalPhoneLease{release: release, leasedAtMillis: nowMillis}
			if lapsed[logId] {
				self.due[logId] = true
			}
			return old, true
		}()
		if !kept {
			release()
			continue
		}
		if old != nil {
			old.release()
			resynced.LeasesRenewed += 1
		} else {
			resynced.LeasesTaken += 1
		}
	}
}

// The logs this process leases, sorted.
func (self *ApprovalPhone) Leased() []Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.SortedFunc(maps.Keys(self.leases), Id.Cmp)
}

// Ends this process's part: nothing more is read, raised or leased, and no lease is released, so evs keeps each until
// it lapses and a closed app is still woken; the next process binds a part that takes them again.
func (self *ApprovalPhone) Close() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.closed = true
	self.leases = map[Id]*approvalPhoneLease{}
	self.due = map[Id]bool{}
	self.raised = map[Id]bool{}
}
