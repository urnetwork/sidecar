//go:build !ios_extension

package sidecar

import (
	"context"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
)

// The active member mailbox must be bound to the same enrolled EVS client. Resolving the join opens no remote view.
func (self *memberSearchSource) mailJoin() *MailSearchJoin {
	mail, _ := self.host.running.mail.Load().(*MailClient)
	if mail == nil {
		return nil
	}
	binding, _, err := mail.bound()
	if err != nil || binding.Evs != self.evs {
		return nil
	}
	join, err := mail.searchJoin()
	if err != nil {
		return nil
	}
	return join
}

// The whole table of the mailbox and its referenced groups, or no view until a background or mail sync has read it.
func (self *memberSearchSource) heldMail(repo Id) func() bool {
	join := self.mailJoin()
	if join == nil {
		return nil
	}
	held := join.pinRepo(repo)
	if held == nil {
		return nil
	}
	return func() bool { return self.mailJoin() == join && held() }
}

// A cursor's immutable binding to the mailbox table that admitted its repo.
func (join *MailSearchJoin) pinRepo(repo Id) func() bool {
	join.stateLock.Lock()
	current := join.synced && !join.stale && join.clock.Now().Sub(join.syncedAt) < join.settings.RefreshInterval &&
		(join.reader.args.MailboxId == repo || slices.Contains(join.groupIds, repo))
	revision := join.revision
	join.stateLock.Unlock()
	if !current {
		return nil
	}
	return func() bool {
		join.stateLock.Lock()
		defer join.stateLock.Unlock()
		return join.revision == revision && join.synced && !join.stale && join.clock.Now().Sub(join.syncedAt) < join.settings.RefreshInterval
	}
}

// Search joins only the current bound member's flags and reads them from RAM.
func (self *memberSearchSource) MailFlags(ctx context.Context, repo Id, month MailYearMonth, message Id) (*SearchMailFlags, bool, error) {
	join := self.mailJoin()
	if join == nil || !join.fresh() {
		return nil, false, nil
	}
	return join.MailFlags(ctx, repo, month, message)
}

// A background window, timer or explicit sync may refresh mail's f/, i/ and r/ once, independently of typed text.
func (self *SearchEngine) refreshScope(ctx context.Context, requested *Id) error {
	if source, ok := self.args.Scope.(*memberSearchSource); ok {
		state := source.state()
		if state == nil {
			return ErrSidecarSearchUnavailable
		}
		if requested == nil || state.Repo(*requested).GetKind() == protocol.RepoKind_REPO_KIND_MAILBOX || AclRepoIsInbox(state.Repo(*requested)) {
			if join := source.mailJoin(); join != nil {
				if err := join.Sync(ctx); err != nil {
					// An incomplete member flag table keeps its repos out; a failure does not strand unrelated files.
					if ctx.Err() != nil {
						return ctx.Err()
					}
					if requested != nil {
						return err
					}
				}
			}
		}
	}
	_, err := self.args.Scope.Repos(ctx)
	return err
}
