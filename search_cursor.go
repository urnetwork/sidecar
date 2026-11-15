//go:build !ios_extension

// Search's cursors (§16.10's pages row; §22.6's cursor target; R-CORE-18, I-13; SEARCH-M10-26): opaque,
// session-bound, in memory, and never persisted. A cursor names one search's stream, which pins the snapshots read at
// the search's start, and yields phase 1's ranked hits, then phase 2's. It lasts Search.CursorTimeout idle; a session
// holds at most Search.SessionCursorCount, the oldest dropped; an erasure, a CUT, a drop or a lost read in its scope
// ends it (its snapshot's Ended), and an ended cursor answers ErrSearchCursorExpired, so no page returns what the index
// no longer holds.
//
// A token is 16 random bytes and the first 16 bytes of HMAC-SHA256 under a key the engine draws at its start and keeps
// in memory, over a label, the session and those bytes: a forged token, a token of another session or another engine
// lifetime, and a malformed one answer ErrSearchCursorInvalid, without saying whether a cursor of that id exists. No
// token, query or hit is logged. Safe for concurrent use.

package sidecar

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"slices"
	"sync"
	"time"
)

// A cursor token's parts: its id and its tag.
const (
	searchCursorIdByteCount  = 16
	searchCursorTagByteCount = 16
	searchCursorLabel        = "UR search cursor 1"
)

// The engine's cursors.
type searchCursorTable struct {
	settings *SidecarSearchSettings
	clock    Clock
	key      []byte

	stateLock sync.Mutex
	cursors   map[[searchCursorIdByteCount]byte]*searchCursor
}

// One open cursor.
type searchCursor struct {
	id       [searchCursorIdByteCount]byte
	session  Id
	stream   *searchEngineStream
	openedAt time.Time
	usedAt   time.Time
}

// A table with a fresh key.
func newSearchCursorTable(settings *SidecarSearchSettings, clock Clock) (*searchCursorTable, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &searchCursorTable{settings: settings, clock: clock, key: key, cursors: map[[searchCursorIdByteCount]byte]*searchCursor{}}, nil
}

// The tag of id for session.
func (self *searchCursorTable) tag(session Id, id [searchCursorIdByteCount]byte) []byte {
	mac := hmac.New(sha256.New, self.key)
	mac.Write([]byte(searchCursorLabel))
	mac.Write(session.Bytes())
	mac.Write(id[:])
	return mac.Sum(nil)[:searchCursorTagByteCount]
}

// Opens a cursor of session over stream, dropping the session's oldest past Search.SessionCursorCount; answers its
// token.
func (self *searchCursorTable) open(session Id, stream *searchEngineStream) (string, error) {
	id := [searchCursorIdByteCount]byte{}
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	now := self.clock.Now()
	dropped := func() []*searchCursor {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.cursors[id] = &searchCursor{id: id, session: session, stream: stream, openedAt: now, usedAt: now}
		held := []*searchCursor{}
		for _, cursor := range self.cursors {
			if cursor.session == session {
				held = append(held, cursor)
			}
		}
		dropped := []*searchCursor{}
		if count := self.settings.SessionCursorCount; count < len(held) {
			slices.SortFunc(held, func(a *searchCursor, b *searchCursor) int { return a.usedAt.Compare(b.usedAt) })
			for _, cursor := range held[:len(held)-count] {
				delete(self.cursors, cursor.id)
				dropped = append(dropped, cursor)
			}
		}
		return dropped
	}()
	for _, cursor := range dropped {
		cursor.stream.Close()
	}
	token := append(id[:], self.tag(session, id)...)
	return base64.RawURLEncoding.EncodeToString(token), nil
}

// The stream of session's cursor token: ErrSearchCursorInvalid for a token this session cannot hold, and
// ErrSearchCursorExpired for one idle past Search.CursorTimeout, dropped, or ended by its scope.
func (self *searchCursorTable) take(session Id, token string) (*searchEngineStream, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != searchCursorIdByteCount+searchCursorTagByteCount {
		return nil, ErrSearchCursorInvalid
	}
	id := [searchCursorIdByteCount]byte(raw[:searchCursorIdByteCount])
	if !hmac.Equal(raw[searchCursorIdByteCount:], self.tag(session, id)) {
		return nil, ErrSearchCursorInvalid
	}
	now := self.clock.Now()
	cursor, expired := func() (*searchCursor, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		cursor := self.cursors[id]
		if cursor == nil {
			return nil, true
		}
		if now.Sub(cursor.usedAt) > self.settings.CursorTimeout || cursor.stream.ended() {
			delete(self.cursors, id)
			return cursor, true
		}
		cursor.usedAt = now
		return cursor, false
	}()
	if expired {
		if cursor != nil {
			cursor.stream.Close()
		}
		return nil, ErrSearchCursorExpired
	}
	return cursor.stream, nil
}

// Ends every cursor idle past Search.CursorTimeout or ended by its scope.
func (self *searchCursorTable) sweep() {
	now := self.clock.Now()
	ended := func() []*searchCursor {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		ended := []*searchCursor{}
		for id, cursor := range self.cursors {
			if now.Sub(cursor.usedAt) > self.settings.CursorTimeout || cursor.stream.ended() {
				delete(self.cursors, id)
				ended = append(ended, cursor)
			}
		}
		return ended
	}()
	for _, cursor := range ended {
		cursor.stream.Close()
	}
}

// Ends every cursor: the engine closes.
func (self *searchCursorTable) closeAll() {
	ended := func() []*searchCursor {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		ended := []*searchCursor{}
		for id, cursor := range self.cursors {
			delete(self.cursors, id)
			ended = append(ended, cursor)
		}
		return ended
	}()
	for _, cursor := range ended {
		cursor.stream.Close()
	}
}
