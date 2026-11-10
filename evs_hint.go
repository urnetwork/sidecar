// §11.10's hints and resets on the client (EVS1-M2-27): what the subscriber (evs_subscribe.go) does with a hint on
// evs:<repo_id> and a reset's notice, beside EvsClient.ReceiveHint's hinted version, which sends the next read past
// evs's head cache.
//
//	one past    a hint whose push sequence is one past the repo's last names the only commit between, so only its ref
//	            is read
//	skip        a hint further on, or the first since the start, sends the client to the window: every subscribed ref
//	            of the repo is read, each read bringing every statement after its pin
//	fall        a sequence at or below the last is a gap, after Redis lost the family or a master changed, never an
//	            alarm: every subscribed ref is read, and the new sequence adopted
//	reset       a reset notice that moved the repo's topic catches the repo up at once, fresh
//	incomplete  NoteIncompleteReset: a full resync of every subscribed repo, which a background daemon first delays by
//	            a random 0-10 min, so a resident's restart does not bring every daemon at once
//
// Each only queues reads and wakes the rounds; none waits, as a hint's subscriber must not (PROTO-M1-06). A hint names
// no path and carries no authority: a read verifies whatever it finds.
//
// On every leg. Safe for concurrent use.

package sidecar

// A hint's push sequence and the ref its EvsHeadChanged names: see the file header.
func (self *evsSubscriber) noteHint(repoId Id, sequence uint64, refId Id) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		held, known := self.repoSequences[repoId]
		self.repoSequences[repoId] = sequence
		if !self.followsWithLock(repoId) {
			return
		}
		if known && sequence == held+1 {
			self.queueSyncWithLock(repoId, &refId, false, self.client.clock.Now())
			return
		}
		self.queueSyncWithLock(repoId, nil, false, self.client.clock.Now())
	}()
	self.wakeRounds()
}

// A reset's notice for repoId's topic at version: see the file header.
func (self *evsSubscriber) noteResync(repoId Id, version uint64) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		// the reset is the new baseline, whatever it shows
		self.repoSequences[repoId] = version
		if self.followsWithLock(repoId) {
			self.queueSyncWithLock(repoId, nil, true, self.client.clock.Now())
		}
	}()
	self.wakeRounds()
}

// See NoteIncompleteReset.
func (self *evsSubscriber) noteIncompleteReset() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		wait := self.random(self.client.settings.SubscribeResetMaxWait)
		if !self.client.settings.SubscribeBackground {
			wait = 0
		}
		at := self.client.clock.Now().Add(wait)
		if self.resetResyncAt.IsZero() || at.Before(self.resetResyncAt) {
			self.resetResyncAt = at
		}
	}()
	self.wakeRounds()
}

// A reset's notice that evs:<repo_id> moved without a hint (§6.8's PushReset, a versions refetch, a clock's fall), at
// the version it shows: the repo's subscribed refs are read at once, fresh. It never blocks.
func (self *EvsClient) ReceiveResync(repoId Id, version uint64) {
	self.subscriber.noteResync(repoId, version)
}

// A reset the push client could not complete: every subscribed repo is read again, a background daemon first waiting
// a random time below SubscribeResetMaxWait (§11.10's gap row). It never blocks.
func (self *EvsClient) NoteIncompleteReset() {
	self.subscriber.noteIncompleteReset()
}
