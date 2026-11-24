//go:build !sidecar_http && !ios_extension

// The mail component's group repos (§15.7's group mail and ingest, R-MAIL-5, D-MAIL-6; MAIL-M7-15): a writer of a
// group repo ingests its deposits once, into the group's own ref, and a member's device that reads it adds only a
// reference to each of its messages in the member's own mailbox.
//
//	roles     each look reads the group and admin addresses of the signed mailcfg and, at the installed state, what
//	          this device does for each group repo that stands with the inbox marker its address's kind names: it
//	          ingests a repo it reads and writes, and adds its member's r/ references where the address lists the
//	          member, the device reads the repo and it writes the member's mailbox (mailGroupRoles)
//	watch     each group repo with a role runs on a goroutine of its own while the generation lives (mailGroupInbox),
//	          holding a subscription to the repo's refs as the mailbox's ingestor holds one to the mailbox's
//	          (MailIngestor.Run), so each change a hint brings wakes a pass over that group alone: a group's message
//	          is ingested and referenced at its hint (§15.7: "on a §11 hint, any reader takes the deposits"), where it
//	          waited for the component's next look before, CheckInterval at worst. The subscription is taken at the
//	          goroutine's first pass, before the pass reads the repo, and one evs refused is asked for again at each
//	          later pass until one stands, so a refusal at a bad moment does not leave the group to the looks for the
//	          generation's life
//	pass      a group's pass reads its roles afresh and touches the repo only where they still hold: its ingest
//	          first, then its member's references, so a message the ingest wrote is referenced in the same pass, and
//	          references it added or removed drop the mailbox view's kept months and raise IDLE's hint
//	bounds    a group's passes are MinPassInterval apart at least, and one that failed, that could not tell its roles,
//	          or that left a deposit whose pin this device's state has yet to reach, goes again after RetryInterval,
//	          as the mailbox's ingestor's do (MailIngestSettings, mailRunPasses), so a burst of hints is one pass; at
//	          most GroupWatchMaxCount groups have a place to subscribe from, the first by id, and one without takes
//	          one once there is room
//	fallback  the component's look, every CheckInterval and at each change it hears of, wakes every group's
//	          goroutine it did not just start, so a hint that never came is caught there, as is every change of a
//	          group past GroupWatchMaxCount or whose subscription evs has refused so far
//
// A group's goroutine ends with its roles, with a binding of another EvsClient or engine, whose look starts the group
// afresh, and with the generation, whose end joins it. Its ingestor is built again for each binding the component
// binds, so the ingest's callbacks read what the latest look bound, as an ingestor built at each look did.
//
// connect legs only, as the component is. Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// What this device does for one group repo at one state.
type mailGroupRole struct {
	// It reads and writes the repo: it ingests the repo's deposits, as MailIngestAuthority.Ingests gates them.
	ingest bool
	// The repo's address lists its member, it reads the repo and it writes the member's mailbox: it adds the
	// member's references to the repo's messages (MailGroupRefs).
	reference bool
}

// One group repo's goroutine on this device: see the file header. The component's look makes and ends it.
type mailGroupInbox struct {
	groupId Id
	// the binding's EvsClient and engine it was made over
	evs    *EvsClient
	engine *AclEngine
	// whether it has one of GroupWatchMaxCount's places, so it subscribes to the repo's refs
	watched bool
	ctx     context.Context
	cancel  context.CancelFunc
	// one pending wake
	wake chan struct{}
	// closed once its goroutine has ended
	done chan struct{}

	// Touched only by its goroutine.
	// what ends its subscription to the repo's refs, nil while none stands
	stopWatch func()
	// the ingestor, and the binding it was built over
	ingestor        *MailIngestor
	ingestorBinding *MailBinding
	// the member's references, and the mailbox they go to, which their checkpoints belong to
	refs          *MailGroupRefs
	refsMailboxId Id
}

// Asks the group's goroutine for a pass soon. Never blocks.
func (self *mailGroupInbox) Wake() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// Whether its goroutine has ended.
func (self *mailGroupInbox) ended() bool {
	select {
	case <-self.done:
		return true
	default:
		return false
	}
}

// What this device does for each group repo at the installed state, from the signed mailcfg's group and admin
// addresses, and the member's mailbox its references go to, the zero id for none. False where that cannot be told
// now: mailcfg not read, a binding other than binding bound, or the state moving under the look, each of which
// leaves things as they stand. True with no roles where the state marks no repo an inbox.
func (self *MailClient) mailGroupRoles(ctx context.Context, binding *MailBinding) (map[Id]mailGroupRole, Id, bool) {
	state := binding.Engine.State()
	if state == nil || !slices.ContainsFunc(state.Rows().GetRepos(), AclRepoIsInbox) {
		return map[Id]mailGroupRole{}, Id{}, true
	}
	config, err := self.syncedConfig(ctx)
	if err != nil {
		return nil, Id{}, false
	}
	addresses, err := config.Addresses()
	if err != nil {
		return nil, Id{}, false
	}
	active, _, err := self.bound()
	if err != nil || active.Engine != binding.Engine || active.Evs != binding.Evs {
		return nil, Id{}, false
	}
	memberId, member := mailMemberOf(state, self.sidecarId)
	mailboxId, _ := self.mailboxId()
	subject := AclSidecarSubject(self.sidecarId)
	now := self.clock.Now()
	mailboxWritable := member && mailboxId != (Id{}) && state.EvsAccess(subject, mailboxId, AclTokenAudienceEvs, now).Rights.Has(AclEvsWrite)
	roles := map[Id]mailGroupRole{}
	for _, address := range addresses {
		if !address.Known || (address.Kind != protocol.MailAddressKind_MAIL_ADDRESS_GROUP && address.Kind != protocol.MailAddressKind_MAIL_ADDRESS_ADMIN) {
			continue
		}
		groupId := address.MailboxRepoId
		row := state.Repo(groupId)
		inbox := protocol.RepoInbox_REPO_INBOX_GROUP
		if address.Kind == protocol.MailAddressKind_MAIL_ADDRESS_ADMIN {
			inbox = protocol.RepoInbox_REPO_INBOX_ADMIN
		}
		if row.GetInbox() != inbox || !mailRepoStands(row) {
			continue
		}
		rights := state.EvsAccess(subject, groupId, AclTokenAudienceEvs, now).Rights
		role := roles[groupId]
		role.ingest = role.ingest || rights.Has(AclEvsRead|AclEvsWrite)
		role.reference = role.reference || mailboxWritable && rights.Has(AclEvsRead) && slices.Contains(address.MemberIds, memberId)
		if role.ingest || role.reference {
			roles[groupId] = role
		}
	}
	if binding.Engine.State() != state {
		// the next look reads the state that replaced it
		return nil, Id{}, false
	}
	return roles, mailboxId, true
}

// The component's look at the group repos: each group with a role gets its goroutine, started where none runs and
// making its first pass at its start, and every other one is woken, the hints' fallback; one whose group has no role
// left, made over another binding's EvsClient or engine, or that has ended, is ended and joined, and the group then
// started afresh. One without a place to subscribe from is started again with one once fewer than GroupWatchMaxCount
// have one.
func (self *MailClient) passGroupInboxes(run *mailComponentRun, binding *MailBinding) {
	roles, _, ok := self.mailGroupRoles(run.ctx, binding)
	if !ok || run.ctx.Err() != nil {
		return
	}
	groupIds := slices.SortedFunc(maps.Keys(roles), func(a Id, b Id) int { return a.Cmp(b) })
	ended, started, woken := func() ([]*mailGroupInbox, []*mailGroupInbox, []*mailGroupInbox) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		ended := []*mailGroupInbox{}
		for groupId, inbox := range run.groupInboxes {
			if _, ok := roles[groupId]; !ok || inbox.evs != binding.Evs || inbox.engine != binding.Engine || inbox.ended() {
				ended = append(ended, inbox)
				delete(run.groupInboxes, groupId)
			}
		}
		if run.groupInboxes == nil {
			run.groupInboxes = map[Id]*mailGroupInbox{}
		}
		watchedCount := 0
		for _, inbox := range run.groupInboxes {
			if inbox.watched {
				watchedCount += 1
			}
		}
		started, woken := []*mailGroupInbox{}, []*mailGroupInbox{}
		for _, groupId := range groupIds {
			inbox := run.groupInboxes[groupId]
			if inbox != nil && !inbox.watched && watchedCount < self.settings.GroupWatchMaxCount {
				// room for its subscription now
				ended = append(ended, inbox)
				inbox = nil
			}
			if inbox != nil {
				woken = append(woken, inbox)
				continue
			}
			ctx, cancel := context.WithCancel(run.ctx)
			inbox = &mailGroupInbox{
				groupId: groupId,
				evs:     binding.Evs,
				engine:  binding.Engine,
				watched: watchedCount < self.settings.GroupWatchMaxCount,
				ctx:     ctx,
				cancel:  cancel,
				wake:    make(chan struct{}, 1),
				done:    make(chan struct{}),
			}
			if inbox.watched {
				watchedCount += 1
			}
			run.groupInboxes[groupId] = inbox
			started = append(started, inbox)
		}
		return ended, started, woken
	}()
	// one goroutine a group at a time: the ended are joined before any starts
	for _, inbox := range ended {
		inbox.cancel()
		<-inbox.done
	}
	for _, inbox := range started {
		go self.runGroupInbox(run, inbox)
	}
	for _, inbox := range woken {
		inbox.Wake()
	}
}

// Ends every group's goroutine of run and joins them.
func (self *MailClient) stopGroupInboxes(run *mailComponentRun) {
	inboxes := func() []*mailGroupInbox {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		inboxes := slices.Collect(maps.Values(run.groupInboxes))
		run.groupInboxes = nil
		return inboxes
	}()
	for _, inbox := range inboxes {
		inbox.cancel()
	}
	for _, inbox := range inboxes {
		<-inbox.done
	}
}

// One group's passes until its goroutine is ended: mailRunPasses over passGroupInbox at MinPassInterval's gap, each
// change of the repo's refs waking it once its subscription stands, which ends with the goroutine.
func (self *MailClient) runGroupInbox(run *mailComponentRun, inbox *mailGroupInbox) {
	defer close(inbox.done)
	defer func() {
		if inbox.stopWatch != nil {
			inbox.stopWatch()
			inbox.stopWatch = nil
		}
	}()
	mailRunPasses(inbox.ctx, self.clock, self.settings.Ingest.MinPassInterval, inbox.wake, func() time.Duration {
		return self.passGroupInbox(run, inbox)
	})
}

// One pass over the group alone: its subscription taken where it has a place and none stands, its roles read afresh
// at the installed state, then its ingest where it ingests and its member's references where it references, each
// failure logged. Answers mailRunPasses' wait: after a step that failed, roles that could not be told or a deposit
// left pending, the ingest's retry wait, as the mailbox's ingestor waits; otherwise none, the hints and the
// component's looks bringing the next.
func (self *MailClient) passGroupInbox(run *mailComponentRun, inbox *mailGroupInbox) time.Duration {
	ctx := inbox.ctx
	binding, parts, err := self.bound()
	if err != nil || binding.Evs != inbox.evs || binding.Engine != inbox.engine {
		// another binding's: the component's next look ends this goroutine
		return 0
	}
	if inbox.watched && inbox.stopWatch == nil {
		// before the pass reads the repo, so a change it misses brings the next pass; one evs refused is asked for
		// again at the next pass, which the component's next look brings at the latest
		stop, err := parts.watch(ctx, inbox.groupId, inbox.Wake)
		switch {
		case err == nil:
			inbox.stopWatch = stop
		case ctx.Err() != nil:
			return 0
		default:
			self.log.Warningf("[mail]group %s: no watch yet, its passes come at the component's looks until one stands: %v", inbox.groupId, err)
		}
	}
	roles, mailboxId, ok := self.mailGroupRoles(ctx, binding)
	if ctx.Err() != nil {
		return 0
	}
	if !ok {
		// mailcfg unread, or the binding or the state moving under the read: tried again as a failed ingest is, so
		// the change a hint brought waits for no look
		return self.settings.Ingest.retryWait()
	}
	role := roles[inbox.groupId]
	retry := false
	if role.ingest {
		if inbox.ingestor == nil || inbox.ingestorBinding != binding {
			inbox.ingestor, err = parts.ingestor(inbox.groupId, self.ingestArgs(run, binding))
			inbox.ingestorBinding = binding
			if err != nil {
				inbox.ingestor = nil
				self.log.Warningf("[mail]group ingest %s: %v", inbox.groupId, err)
				retry = true
			}
		}
		if inbox.ingestor != nil {
			pass, err := inbox.ingestor.Ingest(ctx)
			switch {
			case ctx.Err() != nil:
				return 0
			case err != nil:
				if !errors.Is(err, ErrMailNotIngester) {
					self.log.Warningf("[mail]group ingest %s: %v", inbox.groupId, err)
				}
				retry = true
			case 0 < pass.Pending:
				// a deposit whose pin this device's state has yet to reach, which no hint announces
				retry = true
			}
		}
	}
	if role.reference {
		if inbox.refs == nil || inbox.refsMailboxId != mailboxId {
			inbox.refs, err = parts.groupRefs(inbox.groupId, mailboxId)
			inbox.refsMailboxId = mailboxId
			if err != nil {
				inbox.refs = nil
				self.log.Warningf("[mail]group references %s: %v", inbox.groupId, err)
				retry = true
			}
		}
		if inbox.refs != nil {
			result, err := inbox.refs.Sync(ctx)
			if 0 < result.Added || 0 < result.Dropped {
				self.invalidateReferences(mailboxId)
			}
			if err != nil && ctx.Err() == nil {
				self.log.Warningf("[mail]group references %s: %v", inbox.groupId, err)
				retry = true
			}
		}
	}
	if retry {
		return self.settings.Ingest.retryWait()
	}
	return 0
}

// Drops the view's kept months of mailboxId, where a group's pass added or removed r/ references, so the next list
// reads them afresh, and raises IDLE's hint, as a message ingest writes does (invalidateMonth).
func (self *MailClient) invalidateReferences(mailboxId Id) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if view := self.views[mailboxId]; view != nil {
			view.Invalidate()
		}
	}()
	self.invalidateSearchJoin()
	// a reference written here is IDLE's hint (mail_imap.go)
	self.imapHints.Update(func(revision uint64) uint64 { return revision + 1 })
}
