//go:build !ios_extension

// A format-1 ingest writes the file ref, while an ERASE destroys keys on the erasure ref.
// Their commits have no common CAS. A signed mail ERASE therefore remains a tombstone after
// completion: another admin can recover a late body's new slots from its verified history,
// and finish the i/ and search-index rewrites under the same erasure id after either device stops.

package sidecar

import (
	"context"
	"errors"
	"slices"
)

// An ERASE whose keys were gone and whose message note never committed.
var errMailEraseUncommitted = errors.New("mail erasure did not commit its message note")

// Every key any authenticated ERASE already destroyed, including another admin's.
func mailErasedKeys(erasures []*EvsErasure) map[EvsErasedKey]bool {
	keys := map[EvsErasedKey]bool{}
	for _, erasure := range erasures {
		for _, key := range erasure.destroyedKeys() {
			keys[*key] = true
		}
	}
	return keys
}

// Later notes can extend the document-version and chunk bounds of the same message.
func mailMergeErasedMessages(messages []mailErasedMessage, more []mailErasedMessage) []mailErasedMessage {
	for _, message := range more {
		position := slices.IndexFunc(messages, func(prior mailErasedMessage) bool {
			return prior.Month == message.Month && prior.MessageId == message.MessageId
		})
		if position < 0 {
			messages = append(messages, message)
			continue
		}
		messages[position].Version = max(messages[position].Version, message.Version)
		messages[position].ChunkCount = max(messages[position].ChunkCount, message.ChunkCount)
	}
	return messages
}

// Reconciles every authenticated m/ history against the keys already destroyed. A body that
// appeared after inventory reopens the erasure, even if its deposit-only ERASE said complete.
// The original note survives any interruption before the new ERASE. Afterwards that ERASE's
// note carries the actual version for the index rewrite and the ordinary parts recovery.
func (self *MailEraser) eraseLateBodies(ctx context.Context, erasureId Id, messages []mailErasedMessage, erasedKeys map[EvsErasedKey]bool, index *mailEraseIndex, complete bool) ([]mailErasedMessage, bool, bool, error) {
	var keys []*EvsErasedKey
	var late []mailErasedMessage
	for _, message := range messages {
		path := MailMessagePath(message.Month, message.MessageId)
		held, version, err := self.pathKeysAt(ctx, path)
		if err != nil {
			return nil, false, false, err
		}
		start := len(keys)
		for _, key := range held {
			if !erasedKeys[*key] {
				keys = append(keys, key)
			}
		}
		if len(keys) == start {
			continue
		}
		if index != nil && message.ChunkCount != 0 {
			// The signed deposit note bounded every chunk of this message. Its
			// actual creation version may exceed the estimate at the first CUT.
			message.Version = max(message.Version, version)
		} else if index != nil {
			message.Version, message.ChunkCount, err = self.documentOf(ctx, index, path, version, 0)
			if err != nil {
				return nil, false, false, err
			}
		}
		late = append(late, message)
	}
	if len(late) == 0 {
		return messages, complete, false, nil
	}
	messages = mailMergeErasedMessages(messages, late)
	if index != nil {
		if _, err := self.cut(ctx, index, erasureId, messages); err != nil {
			return nil, false, false, err
		}
		complete = false
	} else if complete {
		// If no derived rows remain, this destructive ERASE itself can end a format-1
		// erasure. That format has no completion-only ERASE.
		segments, err := self.segmentsListing(ctx, messages)
		if err != nil {
			return nil, false, false, err
		}
		complete = len(segments) == 0
	}
	testHookBarrier("mail.erase.late.before", "")
	err := self.store.Erase(ctx, &EvsEraseArgs{
		ErasureId: erasureId, Keys: keys, Complete: complete, Note: mailErasureNote(late, nil),
	})
	testHookBarrier("mail.erase.late.after", "")
	if err != nil {
		return nil, false, false, err
	}
	// NOTHING_TO_ERASE also answers success. Verify the keys on the committed ref
	// before declaring a body destroyed or moving on to its derived copies.
	read, err := self.store.Erasures(ctx, 0)
	if err != nil {
		return nil, false, false, err
	}
	verified := mailErasedKeys(read)
	for _, key := range keys {
		if !verified[*key] {
			return nil, false, false, errMailEraseUncommitted
		}
		erasedKeys[*key] = true
	}
	return messages, complete && mailErasureComplete(read, erasureId), true, nil
}

// An admin's ingest loop is woken by either ref and also runs at startup and on its timer.
// An already consumed deposit and a formerly completed erasure both remain discoverable.
func (self *MailIngestor) reconcileErased(ctx context.Context) error {
	if self.eraser == nil || !self.eraser.allowed() || !self.erased.hasMessages() {
		return nil
	}
	var mainVersion, erasureVersion uint64
	if source, ok := self.repo.(*mailIngestEvsRepo); ok {
		refId, err := source.repo.resolveRefId(ctx, nil, nil)
		if err != nil {
			return err
		}
		head, err := source.repo.readHeadAlone(ctx, refId, true)
		if err != nil {
			return err
		}
		mainVersion = head.Version
		self.erased.stateLock.Lock()
		erasureVersion = self.erased.through
		self.erased.stateLock.Unlock()
		if mainVersion == self.reconciledMain && erasureVersion == self.reconciledErasure {
			return nil
		}
	}
	steps, err := self.eraser.Resume(ctx)
	if err == nil && !slices.ContainsFunc(steps, func(step *MailErasure) bool { return step.State != MailErasureDone }) {
		self.reconciledMain, self.reconciledErasure = mainVersion, erasureVersion
	}
	return err
}

// The same current, verified repo-admin check EVS applies to ERASE and CLOSURE.
func (self *mailIngestEvsRepo) Erases(repoId Id, sidecarId Id) bool {
	if repoId != self.repo.repoId {
		return false
	}
	state, err := self.repo.client.verifier.config()
	if err != nil {
		return false
	}
	row := state.Repo(repoId)
	return row != nil && evsRepoAdmin(state, row, sidecarId)
}
