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
	"cmp"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"slices"
	"sync"
	"time"
)

// A cursor token's parts: its id and its tag; and the label a hit id's MAC starts with.
const (
	searchCursorIdByteCount  = 16
	searchCursorTagByteCount = 16
	searchCursorLabel        = "UR search cursor 1"
	searchHitIdLabel         = "UR search hit 1"
)

// A hit id no live cursor of the session gave: forged, another session's, or its cursor gone.
var ErrSearchHitUnknown = errors.New("search: the hit is none a live cursor of this session gave")

// What a hit id opens (§16.10's open row): for the session whose cursor gave it, while that cursor lives.
type SearchHitRef struct {
	RepoId Id
	RefId  Id
	// The path, or a derived document's registered name.
	Path    string
	Version uint64
	DocKey  [indexIdByteCount]byte
	DocKind int
}

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
	// The hits its pages gave, by hit id, which open while it lives; the oldest forgotten first past a caller's bound.
	hits     map[string]*SearchHitRef
	hitOrder []string
	// Its search completed and its stream closed (finish): no page is left, and its hit ids open until it idles out.
	finished bool
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
		// the session's other cursors, the oldest used first, the oldest opened first among those used at one instant: the
		// one just opened is never among those dropped, though a clock that has not moved since the others opened ties
		// it with every one of them
		held := []*searchCursor{}
		for _, cursor := range self.cursors {
			if cursor.session == session {
				held = append(held, cursor)
			}
		}
		self.cursors[id] = &searchCursor{id: id, session: session, stream: stream, openedAt: now, usedAt: now}
		dropped := []*searchCursor{}
		if count := self.settings.SessionCursorCount; count < len(held)+1 {
			slices.SortFunc(held, func(a *searchCursor, b *searchCursor) int {
				return cmp.Or(a.usedAt.Compare(b.usedAt), a.openedAt.Compare(b.openedAt))
			})
			for _, cursor := range held[:min(len(held), len(held)+1-count)] {
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

// The cursor id of session's token, false for a token the session cannot hold: forged, another session's, or
// malformed.
func (self *searchCursorTable) cursorId(session Id, token string) ([searchCursorIdByteCount]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != searchCursorIdByteCount+searchCursorTagByteCount {
		return [searchCursorIdByteCount]byte{}, false
	}
	id := [searchCursorIdByteCount]byte(raw[:searchCursorIdByteCount])
	if !hmac.Equal(raw[searchCursorIdByteCount:], self.tag(session, id)) {
		return [searchCursorIdByteCount]byte{}, false
	}
	return id, true
}

// The stream of session's cursor token: ErrSearchCursorInvalid for a token this session cannot hold, and
// ErrSearchCursorExpired for one idle past Search.CursorTimeout, dropped, or ended by its scope.
func (self *searchCursorTable) take(session Id, token string) (*searchEngineStream, error) {
	id, ok := self.cursorId(session, token)
	if !ok {
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
		if now.Sub(cursor.usedAt) > self.settings.CursorTimeout || !cursor.finished && cursor.stream.ended() {
			delete(self.cursors, id)
			return cursor, true
		}
		if cursor.finished {
			// its search completed: no page is left
			return nil, true
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

// The hit id of hit for session: opaque, the same each time this engine gives that version of that document in that
// session, and no other session's (§16.10's hit_id). A stub's is its whole hit's.
func (self *searchCursorTable) hitId(session Id, hit *SearchHit) string {
	mac := hmac.New(sha256.New, self.key)
	mac.Write([]byte(searchHitIdLabel))
	mac.Write(session.Bytes())
	mac.Write(hit.Repo.Bytes())
	mac.Write(hit.Ref.Bytes())
	mac.Write(hit.DocKey[:])
	mac.Write(binary.BigEndian.AppendUint64(nil, hit.Version))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:searchCursorTagByteCount])
}

// Notes the hits a call of session gave on its cursor token, whole, so their ids open while the cursor lives: at most
// maxCount a cursor, the oldest forgotten first. A token the session cannot hold, or a cursor gone, notes nothing.
func (self *searchCursorTable) noteHits(session Id, token string, hits []SearchHit, maxCount int) {
	id, ok := self.cursorId(session, token)
	if !ok || len(hits) == 0 {
		return
	}
	hitIds := make([]string, 0, len(hits))
	for index := range hits {
		hitIds = append(hitIds, self.hitId(session, &hits[index]))
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	cursor := self.cursors[id]
	if cursor == nil {
		return
	}
	if cursor.hits == nil {
		cursor.hits = map[string]*SearchHitRef{}
	}
	for index, hitId := range hitIds {
		hit := &hits[index]
		if _, held := cursor.hits[hitId]; !held {
			cursor.hitOrder = append(cursor.hitOrder, hitId)
		}
		cursor.hits[hitId] = &SearchHitRef{
			RepoId: hit.Repo, RefId: hit.Ref, Path: hit.Path, Version: hit.Version, DocKey: hit.DocKey, DocKind: hit.DocKind,
		}
	}
	for maxCount < len(cursor.hitOrder) {
		delete(cursor.hits, cursor.hitOrder[0])
		cursor.hitOrder = cursor.hitOrder[1:]
	}
}

// Ends the search of session's token as complete: its stream closes, and the cursor stays, finished, its hit ids
// opening until it idles past Search.CursorTimeout or is dropped; a page of it answers ErrSearchCursorExpired. A token
// the session cannot hold finishes nothing.
func (self *searchCursorTable) finish(session Id, token string) {
	id, ok := self.cursorId(session, token)
	if !ok {
		return
	}
	stream := func() *searchEngineStream {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		cursor := self.cursors[id]
		if cursor == nil {
			return nil
		}
		cursor.finished = true
		return cursor.stream
	}()
	if stream != nil {
		stream.Close()
	}
}

// What session's hit id names, while a live cursor of the session holds it; ErrSearchHitUnknown otherwise.
func (self *searchCursorTable) openHit(session Id, hitId string) (*SearchHitRef, error) {
	self.sweep()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, cursor := range self.cursors {
		if cursor.session != session {
			continue
		}
		if ref, ok := cursor.hits[hitId]; ok {
			opened := *ref
			return &opened, nil
		}
	}
	return nil, ErrSearchHitUnknown
}

// Ends every cursor idle past Search.CursorTimeout or ended by its scope.
func (self *searchCursorTable) sweep() {
	now := self.clock.Now()
	ended := func() []*searchCursor {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		ended := []*searchCursor{}
		for id, cursor := range self.cursors {
			if now.Sub(cursor.usedAt) > self.settings.CursorTimeout || !cursor.finished && cursor.stream.ended() {
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

// Ends every cursor of session, its hit ids with them: the session ended (D-MCP-25), so nothing it opened stays.
func (self *searchCursorTable) endSession(session Id) {
	ended := func() []*searchCursor {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		ended := []*searchCursor{}
		for id, cursor := range self.cursors {
			if cursor.session == session {
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
