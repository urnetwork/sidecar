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
//	templates   an app's Decide carries no uses (§18.5), and a template's approval takes 2 or more (D-MCP-11): the
//	            request names the uses its agent asks for (QD-1010; ApprovalRequest.uses, version 2's), which the
//	            render shows and an app approves as shown. A version-1 template's request names no count, so an app
//	            host lists it with deny alone, and ur approve --uses approves it
//	log         InstallApproverLog: the approval logs the approver side reads in place of its record's, on a host
//	            whose record has no streams bound yet (RECORD-M3-12's binding has no composition), and in tests
//	phone       an ApprovalRequest reaches a phone by its notice's evs hint, else §18.7's wake (§16.6's flow): an app
//	            host in local mode binds ApprovalPhone, which leases a/ on the main ref of each vault it follows, where
//	            each request's notice sits (record_approval_notice.go), and the inbox prefixes SKILL names (§20.7),
//	            never the whole vault, so a request's notice and its rewrite or removal at a decision or cancel hint it
//	            while the app runs and wake it, topic class evs and a version alone (WK4), while it does not, and a
//	            session push, which every model call makes, wakes it never (owner decision 573's remedy, D-CTXH-10;
//	            CTXH-M11-07). The team record, which holds no session entry (I-20), is leased whole where this device
//	            reads it, since a request routed there has no notice in a vault an admin reads. The host runs Resync at
//	            each of its resyncs (its open, each wake, each hint, hourly while open), which renews a lease once
//	            ApprovalPhoneLeaseRenewAge old, drops at evs each lease standing there that no process holds and this
//	            release does not want, an older release's whole-vault lease among them, reads the logs and raises
//	            approval_pending once for each request newly waiting for this device's decision, so SidecarApprovals'
//	            listener reads GetPending again; a notice is a hint alone, read from the log, and one no request entry
//	            backs is ignored and alarmed. Close releases nothing: evs keeps each lease until it lapses, so a closed
//	            app is still woken, and the next process takes them again. A device that is no approval-capable device
//	            of its member leases nothing and raises nothing. No app host binds it yet: its leaser over
//	            EvsRepo.Subscribe and a record with its streams bound are RECORD-M3-12's binding, which no composition
//	            makes, so until then no approval wakes a phone, the closed direction, and an open app hears a request
//	            at SidecarApprovals' refresh
//
// An approver log that does not say which of its logs is a vault, one a test installs, is leased whole, as every log
// was before M11 (QD-1009's interim, which D-CTXH-10 ends for the record's own log).
//
// Nothing here creates, derives or unwraps a key. Safe for concurrent use. On every leg but the ios_extension legs.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
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

// What host may answer a request it signs on a channel: approve and deny; deny alone on an app host for a request
// that names no count of uses, a version-1 template's, which the app cannot give (the file's templates row).
func approvalHostDecisions(host ApprovalHost, request *StoredApprovalRequest) []string {
	if _, named := request.Uses(); approvalHostApp(host) && !named {
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

// One lease a phone's approval part holds at evs (§11.10's lease row): a prefix of one ref of a repo, a whole ref, or
// every ref of a repo, a whole log. Comparable, so it keys the part's maps.
type ApprovalPhoneLease struct {
	RepoId Id
	// Every ref of the repo, the whole log: the team record's lease, and an older release's of a vault, which this
	// release drops at its next renew. Ref and Prefix are empty then.
	EveryRef bool
	// The ref's name, "" for main.
	Ref string
	// A directory prefix with its trailing slash, "" for the whole ref.
	Prefix string
}

// The order the part lists its leases in: by repo, then every ref first, then ref and prefix.
func approvalPhoneLeaseCmp(a ApprovalPhoneLease, b ApprovalPhoneLease) int {
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

// The lease of a vault's notices: a/ on its main ref (record_approval_notice.go).
func approvalPhoneNoticeLease(vaultId Id) ApprovalPhoneLease {
	return ApprovalPhoneLease{RepoId: vaultId, Prefix: approvalNoticePrefix()}
}

// One approval log a phone follows.
type ApprovalPhoneLog struct {
	LogId Id
	// A member's vault, whose session entries push at every model call: its a/ notices are leased, never the whole
	// log. Else the team record, which holds no session entry (I-20), leased whole.
	Vault bool
}

// What a phone's approval part leases through (§11.10's lease row): a lease, a hint calling callback, with no lock
// held, at each commit that changes a path under it, until release, which drops this callback, and the lease with its
// last. Leasing again renews it. evs keeps a lease until it lapses unrenewed, whether or not a process holds a
// callback on it, and hints the client then by §18.7's wake. RECORD-M3-12's binding serves it over EvsRepo.Subscribe;
// sidecartest's FakeApprovalPhone is T4's surrogate. Safe for concurrent use.
type ApprovalPhoneLeaser interface {
	Lease(lease ApprovalPhoneLease, callback func(lease ApprovalPhoneLease)) (release func(), err error)
	// The leases evs holds for this client on repoId on which this process holds no callback: what an earlier
	// process, of this release or an older one, left standing. A leaser that keeps none answers none.
	Standing(repoId Id) ([]ApprovalPhoneLease, error)
	// Deletes a standing lease at evs, as DELETE /evs/v1/subscriptions does.
	Drop(lease ApprovalPhoneLease) error
}

// What a phone's approval part is bound with.
type ApprovalPhoneArgs struct {
	Leaser ApprovalPhoneLeaser
	// The approval logs to follow; nil for the ones the approver side's log reads (the author's vault, and the team
	// record where this device reads it).
	Logs func() ([]ApprovalPhoneLog, error)
	// The inbox prefixes to lease beside the notices, SKILL's (§20.7: agents:inbox/ and agent/<name>:inbox/ of the
	// person's agents); nil for none, until SKILL's agents client names them.
	Inboxes func() ([]ApprovalPhoneLease, error)
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
	// Leases standing at evs that no process held and this release does not want, dropped there: an older release's
	// whole-vault lease among them.
	LeasesDropped int
	// The leases held now, sorted.
	Leased []ApprovalPhoneLease
	// The requests waiting for this device's decision now, in the order the approver side lists them.
	Pending []Id
	// The requests of Pending newly waiting, for each of which approval_pending was raised.
	Raised []Id
	// Leases a hint, a lapse or a first lease made due since the last Resync, all read now, sorted.
	Due []ApprovalPhoneLease
	// Notices under a/ that no request entry backs, ignored and alarmed.
	NoticesIgnored int
}

// One lease this process holds.
type approvalPhoneLease struct {
	release        func()
	leasedAtMillis int64
}

// An approver log that says which of its logs is a vault: the record's own (RecordApprovals).
type approvalPhoneLogSource interface {
	approvalPhoneLogs() ([]ApprovalPhoneLog, error)
}

// An approver log that checks a vault's notices against its requests: the record's own, once its notices part is made.
type approvalPhoneNoticeChecker interface {
	CheckNotices(ctx context.Context, vaultId Id) (*ApprovalNoticesChecked, error)
}

// An app host's phone part for approvals: see the file's comment. Safe for concurrent use.
type ApprovalPhone struct {
	sidecar *Sidecar
	args    *ApprovalPhoneArgs

	// one Resync at a time
	writeLock sync.Mutex

	stateLock sync.Mutex
	leases    map[ApprovalPhoneLease]*approvalPhoneLease
	// leases to read at the next Resync: hinted, first taken, or lapsed
	due map[ApprovalPhoneLease]bool
	// the requests approval_pending was raised for, while they wait
	raised map[Id]bool
	closed bool
}

// Binds this sidecar's phone part for approvals, which an app host in local mode calls once: from then on Resync
// leases its approval logs' notices. Binding again replaces the args of the part already bound, which keeps its
// leases.
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
		leases:  map[ApprovalPhoneLease]*approvalPhoneLease{},
		due:     map[ApprovalPhoneLease]bool{},
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

// The callback of lease: marks it due and cues the app host.
func (self *ApprovalPhone) hintFunc(lease ApprovalPhoneLease) func(lease ApprovalPhoneLease) {
	return func(ApprovalPhoneLease) {
		hinted := func() func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.closed {
				return nil
			}
			self.due[lease] = true
			return self.args.Hinted
		}()
		if hinted != nil {
			hinted()
		}
	}
}

// The logs this part follows and the leases they call for (the file's phone row): a vault's a/ notices, the team
// record whole, an unclassified log whole, and the inbox prefixes.
func (self *ApprovalPhone) wantedLeases(args *ApprovalPhoneArgs, approver *ApprovalApprover) (map[ApprovalPhoneLease]bool, []Id, error) {
	logs := args.Logs
	if logs == nil {
		if source, ok := approver.log.(approvalPhoneLogSource); ok {
			logs = source.approvalPhoneLogs
		} else {
			logs = func() ([]ApprovalPhoneLog, error) {
				logIds, err := approver.log.approvalLogs()
				if err != nil {
					return nil, err
				}
				phoneLogs := []ApprovalPhoneLog{}
				for _, logId := range logIds {
					phoneLogs = append(phoneLogs, ApprovalPhoneLog{LogId: logId})
				}
				return phoneLogs, nil
			}
		}
	}
	phoneLogs, err := logs()
	if err != nil {
		return nil, nil, err
	}
	wanted := map[ApprovalPhoneLease]bool{}
	vaultIds := []Id{}
	for _, log := range phoneLogs {
		if log.Vault {
			wanted[approvalPhoneNoticeLease(log.LogId)] = true
			vaultIds = append(vaultIds, log.LogId)
		} else {
			wanted[ApprovalPhoneLease{RepoId: log.LogId, EveryRef: true}] = true
		}
	}
	if args.Inboxes != nil {
		inboxes, err := args.Inboxes()
		if err != nil {
			return nil, nil, err
		}
		for _, lease := range inboxes {
			wanted[lease] = true
		}
	}
	slices.SortFunc(vaultIds, Id.Cmp)
	return wanted, vaultIds, nil
}

// Renews the phone's leases, drops what an earlier process left standing that this release does not want, reads its
// approval logs and raises approval_pending once for each request newly waiting for this device's decision (the file's
// phone row), then checks each due vault's notices against its log. A device that is no approval-capable device of
// its member releases every lease and raises nothing. A lease that could not be taken is taken at the next Resync.
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
	wanted := map[ApprovalPhoneLease]bool{}
	vaultIds := []Id{}
	if _, _, _, err := approver.standing(); err == nil {
		wanted, vaultIds, err = self.wantedLeases(args, approver)
		if err != nil {
			return nil, err
		}
	} else if !errors.Is(err, ErrSidecarApprovalNotEligible) {
		return nil, err
	}
	self.holdLeases(args.Leaser, wanted, resynced)

	// what is due now is read now; a hint during the reads stays due for the next Resync
	due := func() map[ApprovalPhoneLease]bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		due := self.due
		self.due = map[ApprovalPhoneLease]bool{}
		return due
	}()
	keepDue := func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return
		}
		for lease := range due {
			self.due[lease] = true
		}
	}
	items, err := approver.Pending(ctx)
	if err != nil {
		keepDue()
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
	if checker, ok := approver.log.(approvalPhoneNoticeChecker); ok {
		for _, vaultId := range vaultIds {
			if !due[approvalPhoneNoticeLease(vaultId)] {
				continue
			}
			checked, err := checker.CheckNotices(ctx, vaultId)
			if errors.Is(err, ErrApprovalNoticeUnbound) {
				continue
			}
			if err != nil {
				keepDue()
				return nil, err
			}
			resynced.NoticesIgnored += len(checked.Ignored)
		}
	}
	resynced.Due = slices.SortedFunc(maps.Keys(due), approvalPhoneLeaseCmp)
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
		resynced.Leased = slices.SortedFunc(maps.Keys(self.leases), approvalPhoneLeaseCmp)
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

// Holds wanted and releases the rest, then drops at evs each lease standing on a repo this part follows that no
// process holds and wanted does not name: an older release's whole-vault lease is dropped here, at the renew pass, and
// never renewed. A lease is taken again before the one it renews goes, so evs holds it throughout. One this process did
// not hold, or held ApprovalPhoneLeaseExpiry, had lapsed or never stood, so its lease is due, what changed meanwhile
// being unknown.
func (self *ApprovalPhone) holdLeases(leaser ApprovalPhoneLeaser, wanted map[ApprovalPhoneLease]bool, resynced *ApprovalPhoneResynced) {
	settings := self.sidecar.settings.Mcp
	nowMillis := self.sidecar.clock.Now().UnixMilli()
	renewAge := settings.ApprovalPhoneLeaseRenewAge.Milliseconds()
	expiry := settings.ApprovalPhoneLeaseExpiry.Milliseconds()
	releases := []func(){}
	takes := []ApprovalPhoneLease{}
	lapsed := map[ApprovalPhoneLease]bool{}
	repoIds := map[Id]bool{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for lease, held := range self.leases {
			repoIds[lease.RepoId] = true
			if !wanted[lease] {
				releases = append(releases, held.release)
				delete(self.leases, lease)
			}
		}
		for lease := range wanted {
			repoIds[lease.RepoId] = true
			held, ok := self.leases[lease]
			switch {
			case !ok:
				takes = append(takes, lease)
				lapsed[lease] = true
			case held.leasedAtMillis+renewAge <= nowMillis:
				takes = append(takes, lease)
				lapsed[lease] = held.leasedAtMillis+expiry <= nowMillis
			}
		}
	}()
	for _, release := range releases {
		release()
		resynced.LeasesReleased += 1
	}
	slices.SortFunc(takes, approvalPhoneLeaseCmp)
	for _, lease := range takes {
		release, err := leaser.Lease(lease, self.hintFunc(lease))
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
			old := self.leases[lease]
			self.leases[lease] = &approvalPhoneLease{release: release, leasedAtMillis: nowMillis}
			if lapsed[lease] {
				self.due[lease] = true
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
	for _, repoId := range slices.SortedFunc(maps.Keys(repoIds), Id.Cmp) {
		standing, err := leaser.Standing(repoId)
		if err != nil {
			// read again at the next resync
			continue
		}
		for _, lease := range standing {
			if wanted[lease] {
				continue
			}
			if err := leaser.Drop(lease); err == nil {
				resynced.LeasesDropped += 1
			}
		}
	}
}

// The leases this process holds, sorted.
func (self *ApprovalPhone) Leased() []ApprovalPhoneLease {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.SortedFunc(maps.Keys(self.leases), approvalPhoneLeaseCmp)
}

// Ends this process's part: nothing more is read, raised or leased, and no lease is released, so evs keeps each until
// it lapses and a closed app is still woken; the next process binds a part that takes them again.
func (self *ApprovalPhone) Close() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.closed = true
	self.leases = map[ApprovalPhoneLease]*approvalPhoneLease{}
	self.due = map[ApprovalPhoneLease]bool{}
	self.raised = map[Id]bool{}
}
