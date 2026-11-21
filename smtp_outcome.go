//go:build !sidecar_http && !ios_extension

// One Send's outcomes as or/ holds them (§14.5's outcomes, §15.7's or/, plan-SMTP-small-readings#10;
// SMTP-M9-08): one SmtpDomainOutcome a recipient domain, in the order the domains first appear, kept outcomes
// beside new ones. The board writes them whole to or/<h>/<effect_key> through SmtpMailbox.WriteOutcomes, queued
// as each domain starts and each result as it comes, and while a send runs it rewrites them every
// OutboxProgressInterval with fresh times for the queued ones, so another prover host can see this one is alive
// and takes over only after OutboxTakeoverTimeout with no change (D-SMTP-18).
//
// Once the Send ends, each domain whose outcome differs from or/'s earlier one raises SidecarEvent mail_send,
// naming the message's send id (§18.5's GetSendResult reads the outcomes it names). A time alone is no change.
//
// Safe for concurrent use: the progress goroutine and the Send write through one lock.

package sidecar

import (
	"context"
	"slices"
	"sync"

	"google.golang.org/protobuf/proto"
)

// Whether two outcomes say the same thing, their times aside.
func smtpOutcomeSame(a *SmtpDomainOutcome, b *SmtpDomainOutcome) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Domain == b.Domain && a.Outcome == b.Outcome && a.Mode == b.Mode && a.ByteCount == b.ByteCount &&
		a.CapByteCount == b.CapByteCount && a.ReplyCode == b.ReplyCode && a.RetryAfter == b.RetryAfter && a.TlsLevel == b.TlsLevel
}

// A copy of an outcome, which the caller may change.
func smtpOutcomeCopy(outcome *SmtpDomainOutcome) *SmtpDomainOutcome {
	if outcome == nil {
		return nil
	}
	copied := *outcome
	copied.progress = proto.CloneOf(outcome.progress)
	return &copied
}

// One Send's outcomes.
type smtpOutcomeBoard struct {
	sender    *SmtpSender
	effectKey []byte
	sendId    Id

	// orders every write to or/, and is never taken under stateLock
	writeLock sync.Mutex

	stateLock sync.Mutex
	domains   []string
	outcomes  map[string]*SmtpDomainOutcome
	// domains whose outcome differs from the earlier one or/ held
	changed map[string]bool
}

// Adds domain to the board's order the first time it is named.
func (self *smtpOutcomeBoard) nameWithLock(domain string) {
	if self.outcomes == nil {
		self.outcomes = map[string]*SmtpDomainOutcome{}
		self.changed = map[string]bool{}
	}
	if !slices.Contains(self.domains, domain) {
		self.domains = append(self.domains, domain)
	}
}

// An earlier outcome kept as it is.
func (self *smtpOutcomeBoard) keep(earlier *SmtpDomainOutcome) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nameWithLock(earlier.Domain)
	self.outcomes[earlier.Domain] = smtpOutcomeCopy(earlier)
}

// A domain's new outcome, and whether it changed from earlier.
func (self *smtpOutcomeBoard) set(outcome *SmtpDomainOutcome, earlier *SmtpDomainOutcome) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nameWithLock(outcome.Domain)
	self.outcomes[outcome.Domain] = smtpOutcomeCopy(outcome)
	self.changed[outcome.Domain] = !smtpOutcomeSame(outcome, earlier)
}

// A copy of a domain's outcome.
func (self *smtpOutcomeBoard) of(domain string) *SmtpDomainOutcome {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return smtpOutcomeCopy(self.outcomes[domain])
}

// Every outcome, in order, copied.
func (self *smtpOutcomeBoard) snapshotWithLock() []*SmtpDomainOutcome {
	outcomes := make([]*SmtpDomainOutcome, 0, len(self.domains))
	for _, domain := range self.domains {
		outcomes = append(outcomes, smtpOutcomeCopy(self.outcomes[domain]))
	}
	return outcomes
}

// Replaces or/ with the board's outcomes. refreshQueued first moves each queued outcome's time to now.
func (self *smtpOutcomeBoard) writeOutcomes(ctx context.Context, refreshQueued bool) error {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	outcomes := func() []*SmtpDomainOutcome {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if refreshQueued {
			now := self.sender.clock.Now()
			for _, outcome := range self.outcomes {
				if outcome.Outcome == SmtpOutcomeQueued {
					outcome.UpdateTime = now
				}
			}
		}
		return self.snapshotWithLock()
	}()
	return self.sender.args.Mailbox.WriteOutcomes(ctx, self.effectKey, outcomes)
}

// Replaces or/ with the board's outcomes as they stand.
func (self *smtpOutcomeBoard) write(ctx context.Context) error {
	return self.writeOutcomes(ctx, false)
}

// Rewrites or/ every OutboxProgressInterval until stop, which returns once no rewrite runs.
func (self *smtpOutcomeBoard) progress(ctx context.Context) (stop func()) {
	progressCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-progressCtx.Done():
				return
			case <-self.sender.clock.After(self.sender.settings.OutboxProgressInterval):
			}
			if err := self.writeOutcomes(progressCtx, true); err != nil && self.sender.log.V(1).Enabled() {
				self.sender.log.Infof("[smtp]send progress was not written: %v\n", err)
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// Raises mail_send once for each domain whose outcome changed, in order.
func (self *smtpOutcomeBoard) emitChanged() {
	if self.sender.args.Events == nil || self.sendId == (Id{}) {
		return
	}
	changedCount := func() int {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		count := 0
		for _, domain := range self.domains {
			if self.changed[domain] {
				count += 1
			}
		}
		return count
	}()
	for range changedCount {
		sendId := self.sendId
		self.sender.args.Events(SidecarEvent{Kind: SidecarEventMailSend, SendId: &sendId})
	}
}
