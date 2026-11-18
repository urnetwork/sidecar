// A listed version's state on a reader, and the checked DROP bodies a device keeps (§11.7's states row, §11.9's
// dropped and drop_pending rows; D-EVS-63, FI-27, FS-89; DESIGN-DETAILS 10.2.3's storage paragraph; EVS2-M10-22).
//
//	states   a version a checked DROP covers is drop_pending before the body's not_before_ms by this device's clock:
//	         readable, shown "drop pending until <time>"; dropped from then on, or at any 404 of its content, or where
//	         evs withheld its entry version: nothing fetched or shown, a read answering EVS_DROPPED (ErrEvsDropped; MCP
//	         FAILED_PRECONDITION), history keeping its version, time, signer, entry hash and, where served, padded size,
//	         and no alarm. evs's clock decides drop_pending against dropped on the wire; this device's decides what it
//	         shows
//	bodies   each checked body is kept sealed on the device's store by (repo, ref, drop id) with the DROP's ref version
//	         where the reader placed it, at most DropBodyKeepByteCount a client, least recently used out, so later
//	         reads name it in held_drops (at most HeldDropMaxCount versions a read) and evs sends none of them again.
//	         A body is written to the store as it is checked and read back from it, never held in RAM past its check
//	         (QD-641)
//
// The state is on every leg, so the reader's checks (evs_drop_verify.go) leave it on a verified path; the store's index
// is kept in memory and the bodies on storage, so a restarted device fetches each body once more. Safe for concurrent
// use.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"
)

var (
	// A read of a version a drop took (§11.7's states row): nothing is fetched or shown. EVS_DROPPED; MCP answers it
	// FAILED_PRECONDITION (§16).
	ErrEvsDropped = errors.New("evs: EVS_DROPPED: a version whose history was dropped")
	// A reply named a drop whose body it left out, past its byte bound, and this device holds none: the path is read
	// again, the body first (DESIGN-DETAILS 10.2.3's reply size).
	errEvsDropBodyMissing = errors.New("evs: a drop's body the reply left out")
)

// History's and List's states of a version a checked DROP covers (§18.5's History): kept and collected are the others.
const (
	EvsVersionStateDropPending = "drop_pending"
	EvsVersionStateDropped     = "dropped"
)

// What a reader found of a version a checked DROP covers.
type EvsDropState struct {
	DropId Id
	// The DROP's ref version, 0 where this device could not place its statement (a pending drop's statement evs sent
	// alone, below the walk).
	DropVersion uint64
	// The DROP's signer, a repo admin at its auth pin.
	SignerSidecarId Id
	// The body's not_before_ms: drop_pending before it by this device's clock.
	NotBefore time.Time
	// evs withheld the version's entry version, as it does for a dropped version whose chain names an inline record
	// (§11.9's serve row): nothing of it can be read, and the verified path's Entry holds only its number and push.
	Withheld bool
}

// Whether the version reads as dropped at now: its window passed, or evs withheld its entry version. False for nil.
func (self *EvsDropState) Dropped(now time.Time) bool {
	return self != nil && (self.Withheld || !now.Before(self.NotBefore))
}

// The state History shows at now, "" for nil.
func (self *EvsDropState) Name(now time.Time) string {
	switch {
	case self == nil:
		return ""
	case self.Dropped(now):
		return EvsVersionStateDropped
	}
	return EvsVersionStateDropPending
}

// The drop's id, zero for nil.
func evsDropIdOf(state *EvsDropState) Id {
	if state == nil {
		return Id{}
	}
	return state.DropId
}

// The drop's window's end, zero for nil.
func evsDropNotBeforeOf(state *EvsDropState) time.Time {
	if state == nil {
		return time.Time{}
	}
	return state.NotBefore
}

// The checked DROP bodies a client keeps: see the file header.
type evsDropBodies struct {
	store SidecarStore
	limit int64

	stateLock sync.Mutex
	// least recently used first
	held      []*evsDropHeldBody
	byteCount int64
}

// One body kept: whose it is, its DROP's ref version and statement where known, and where its bytes are.
type evsDropHeldBody struct {
	repoId    Id
	refId     Id
	dropId    Id
	version   uint64
	statement []byte
	byteCount int64
	name      string
}

// A store of checked bodies under store, at most limit bytes of them.
func newEvsDropBodies(store SidecarStore, limit int64) *evsDropBodies {
	return &evsDropBodies{store: store, limit: limit}
}

// The store file of a body.
func evsDropBodyName(repoId Id, refId Id, dropId Id) string {
	return fmt.Sprintf("evs-drop-%s-%s-%s", repoId, refId, dropId)
}

// Keeps a checked body of the drop dropId on refId, with its DROP's statement and ref version where known, writing
// it sealed to the store and dropping the least recently used past the bound. A body larger than the bound is not
// kept.
func (self *evsDropBodies) put(repoId Id, refId Id, dropId Id, version uint64, statement []byte, body []byte) error {
	if self.limit < int64(len(body)) {
		return nil
	}
	name := evsDropBodyName(repoId, refId, dropId)
	writer, err := self.store.Create(name)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(body); err != nil {
		return err
	}
	if err := writer.Commit(); err != nil {
		return err
	}
	evicted := []string{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.held = slices.DeleteFunc(self.held, func(held *evsDropHeldBody) bool {
			if held.name == name {
				self.byteCount -= held.byteCount
				return true
			}
			return false
		})
		self.held = append(self.held, &evsDropHeldBody{
			repoId: repoId, refId: refId, dropId: dropId, version: version, statement: bytes.Clone(statement),
			byteCount: int64(len(body)), name: name,
		})
		self.byteCount += int64(len(body))
		for self.limit < self.byteCount && 1 < len(self.held) {
			oldest := self.held[0]
			self.held = self.held[1:]
			self.byteCount -= oldest.byteCount
			evicted = append(evicted, oldest.name)
		}
	}()
	errs := []error{}
	for _, name := range evicted {
		errs = append(errs, self.store.Remove(name))
	}
	return errors.Join(errs...)
}

// The kept body of the drop dropId on refId, its version and statement, read back from the store and marked used;
// false for none.
func (self *evsDropBodies) get(repoId Id, refId Id, dropId Id) ([]byte, uint64, []byte, bool, error) {
	held := func() *evsDropHeldBody {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for i, held := range self.held {
			if held.repoId == repoId && held.refId == refId && held.dropId == dropId {
				self.held = append(slices.Delete(self.held, i, i+1), held)
				return held
			}
		}
		return nil
	}()
	if held == nil {
		return nil, 0, nil, false, nil
	}
	reader, err := self.store.Open(held.name)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		self.forget(held.name)
		return nil, 0, nil, false, nil
	}
	if err != nil {
		return nil, 0, nil, false, err
	}
	defer reader.Close()
	body, err := io.ReadAll(io.LimitReader(reader, held.byteCount+1))
	if err != nil {
		return nil, 0, nil, false, err
	}
	if int64(len(body)) != held.byteCount {
		self.forget(held.name)
		return nil, 0, nil, false, nil
	}
	return body, held.version, held.statement, true, nil
}

// Forgets a kept body whose file is gone or changed.
func (self *evsDropBodies) forget(name string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.held = slices.DeleteFunc(self.held, func(held *evsDropHeldBody) bool {
		if held.name == name {
			self.byteCount -= held.byteCount
			return true
		}
		return false
	})
}

// The ref versions of the kept bodies on refId whose version is known, newest first, at most count: a read's
// held_drops.
func (self *evsDropBodies) heldVersions(repoId Id, refId Id, count int) []uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	versions := []uint64{}
	for i := len(self.held) - 1; 0 <= i && len(versions) < count; i -= 1 {
		held := self.held[i]
		if held.repoId == repoId && held.refId == refId && held.version != 0 && !slices.Contains(versions, held.version) {
			versions = append(versions, held.version)
		}
	}
	return versions
}

// Each kept body on refId: its drop id and version, for the reader's cancel check and an executed drop's apply.
func (self *evsDropBodies) list(repoId Id, refId Id) []*evsDropHeldBody {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	listed := []*evsDropHeldBody{}
	for _, held := range self.held {
		if held.repoId == repoId && held.refId == refId {
			listed = append(listed, held)
		}
	}
	return listed
}
