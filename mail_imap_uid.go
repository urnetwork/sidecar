//go:build !ios_extension

// IMAP's UIDs for a mailbox's folders (RFC 9051 §2.3.1.1, D-MAIL-11; MAIL-M8-06): local and monotonic per
// folder, since evs ids are not 32-bit numbers. Each folder's state is one file in the mail component's
// sealed directory (§5.9), under imap/: its UIDVALIDITY, the next UID, and the UID each message holds there.
// A message keeps its UID while it stays in the folder; one that leaves gives its UID up for good, and comes
// back under a new one, so a UID is never reused within a UIDVALIDITY.
//
// UIDVALIDITY rises only when a folder's state is lost: a folder with no file, or one that does not decode,
// starts over above every validity this device has issued (imap/validity, which outlives a folder's file),
// and at least at the clock's second, so a store lost whole still rises past what a client cached. Every
// assignment reaches the disk before a session reports it, so a kill never hands one UID to two messages.
//
// Erasure leaves tombstones (imap/tombstones): a message purged here never takes a UID again, whatever a
// stale list still shows, since its keys are gone and a client's copy is beyond recall (§2.18).
//
// Safe for concurrent use.

package sidecar

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"slices"
	"sync"
)

// The files under the component's imap/ directory.
const (
	mailImapUidFileSuffix     = ".uids"
	mailImapValidityFileName  = "validity"
	mailImapTombstoneFileName = "tombstones"
)

// One message as a folder's UIDs name it: its repo and its id, and the month its m/ file is under, which a read
// needs and the UIDs do not, since an id names one message in a repo.
type MailImapKey struct {
	RepoId Id
	Month  MailYearMonth
	Id     Id
}

// The key's text in a UID or tombstone file: repo and id.
func (self MailImapKey) text() string {
	return self.RepoId.String() + "/" + self.Id.String()
}

// One folder's UID state as its file holds it.
type mailImapFolderFile struct {
	Validity uint32            `json:"validity"`
	Next     uint32            `json:"next"`
	Uids     map[string]uint32 `json:"uids"`
}

// What the tombstone file holds: the keys purged, oldest first.
type mailImapTombstoneFile struct {
	Keys []string `json:"keys"`
}

// The UIDs of every folder, loaded as each is first asked for.
type mailImapUids struct {
	store    SidecarStore
	clock    Clock
	settings *MailImapSettings

	stateLock  sync.Mutex
	folders    map[string]*mailImapFolderFile
	tombstones map[string]bool
	// oldest first, so the oldest goes past TombstoneMaxCount
	tombstoneOrder  []string
	tombstoneLoaded bool
}

func newMailImapUids(store SidecarStore, clock Clock, settings *MailImapSettings) *mailImapUids {
	return &mailImapUids{
		store:      store,
		clock:      clock,
		settings:   settings,
		folders:    map[string]*mailImapFolderFile{},
		tombstones: map[string]bool{},
	}
}

// A folder's file name: a hash of its name, since a label may hold any character.
func mailImapUidFileName(folder string) string {
	sum := sha256.Sum256([]byte(folder))
	return hex.EncodeToString(sum[:16]) + mailImapUidFileSuffix
}

// Reads name's JSON into into, false when the file is absent or does not decode.
func (self *mailImapUids) readWithLock(name string, into any) (bool, error) {
	reader, err := self.store.Open(name)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, int64(self.settings.UidFileMaxByteCount)+1))
	if errors.Is(err, ErrSidecarStoreFailed) {
		// a cut or tampered file is a lost one
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if self.settings.UidFileMaxByteCount < len(data) || json.Unmarshal(data, into) != nil {
		return false, nil
	}
	return true, nil
}

// Writes value as name's whole content, on the disk when it returns.
func (self *mailImapUids) writeWithLock(name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	writer, err := self.store.Create(name)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}

// A new validity: above every one this device issued, and at least the clock's second.
func (self *mailImapUids) issueValidityWithLock() (uint32, error) {
	var last uint32
	if _, err := self.readWithLock(mailImapValidityFileName, &last); err != nil {
		return 0, err
	}
	validity := max(last+1, uint32(min(max(self.clock.Now().Unix(), 1), int64(^uint32(0)))))
	if validity == 0 {
		validity = 1
	}
	if err := self.writeWithLock(mailImapValidityFileName, validity); err != nil {
		return 0, err
	}
	testHookBarrier("mail.imap.validity", "")
	return validity, nil
}

// The folder's state, loaded or started over.
func (self *mailImapUids) folderWithLock(folder string) (*mailImapFolderFile, error) {
	if state, ok := self.folders[folder]; ok {
		return state, nil
	}
	state := &mailImapFolderFile{}
	found, err := self.readWithLock(mailImapUidFileName(folder), state)
	if err != nil {
		return nil, err
	}
	if !found || state.Validity == 0 || state.Next == 0 || state.Uids == nil {
		validity, err := self.issueValidityWithLock()
		if err != nil {
			return nil, err
		}
		state = &mailImapFolderFile{Validity: validity, Next: 1, Uids: map[string]uint32{}}
		if err := self.writeWithLock(mailImapUidFileName(folder), state); err != nil {
			return nil, err
		}
	}
	self.folders[folder] = state
	return state, nil
}

// Loads the tombstones once.
func (self *mailImapUids) loadTombstonesWithLock() error {
	if self.tombstoneLoaded {
		return nil
	}
	file := &mailImapTombstoneFile{}
	if _, err := self.readWithLock(mailImapTombstoneFileName, file); err != nil {
		return err
	}
	for _, key := range file.Keys {
		if !self.tombstones[key] {
			self.tombstones[key] = true
			self.tombstoneOrder = append(self.tombstoneOrder, key)
		}
	}
	self.tombstoneLoaded = true
	return nil
}

// What one folder's assignment answered.
type mailImapAssignment struct {
	Validity uint32
	Next     uint32
	// each key's UID, in keys' order; 0 for a tombstoned key, which takes none
	Uids []uint32
}

// Gives every key of the folder's present messages its UID: the one it holds, or the next for one new to
// the folder, in keys' order, which the caller makes oldest first. A key the folder held and keys leaves
// loses its UID. Tombstoned keys take none. The state is on the disk before this returns.
func (self *mailImapUids) Assign(folder string, keys []MailImapKey) (*mailImapAssignment, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := self.loadTombstonesWithLock(); err != nil {
		return nil, err
	}
	state, err := self.folderWithLock(folder)
	if err != nil {
		return nil, err
	}
	next := &mailImapFolderFile{Validity: state.Validity, Next: state.Next, Uids: make(map[string]uint32, len(keys))}
	assignment := &mailImapAssignment{Validity: state.Validity, Uids: make([]uint32, len(keys))}
	for index, key := range keys {
		text := key.text()
		if self.tombstones[text] {
			continue
		}
		uid, ok := state.Uids[text]
		if !ok {
			if next.Next == ^uint32(0) {
				return nil, ErrMailImapUidsExhausted
			}
			uid = next.Next
			next.Next += 1
		}
		next.Uids[text] = uid
		assignment.Uids[index] = uid
	}
	assignment.Next = next.Next
	if next.Next != state.Next || !maps.Equal(next.Uids, state.Uids) {
		testHookBarrier("mail.imap.uids.before", "")
		if err := self.writeWithLock(mailImapUidFileName(folder), next); err != nil {
			return nil, err
		}
		testHookBarrier("mail.imap.uids.after", "")
		self.folders[folder] = next
	}
	return assignment, nil
}

// Tombstones keys and takes them out of every folder loaded: they never take a UID again. On the disk when
// it returns.
func (self *mailImapUids) Purge(keys []MailImapKey) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := self.loadTombstonesWithLock(); err != nil {
		return err
	}
	for _, key := range keys {
		text := key.text()
		if !self.tombstones[text] {
			self.tombstones[text] = true
			self.tombstoneOrder = append(self.tombstoneOrder, text)
		}
	}
	for len(self.tombstoneOrder) > self.settings.TombstoneMaxCount {
		delete(self.tombstones, self.tombstoneOrder[0])
		self.tombstoneOrder = self.tombstoneOrder[1:]
	}
	if err := self.writeWithLock(mailImapTombstoneFileName, &mailImapTombstoneFile{Keys: slices.Clone(self.tombstoneOrder)}); err != nil {
		return err
	}
	for folder, state := range self.folders {
		changed := false
		for _, key := range keys {
			if _, ok := state.Uids[key.text()]; ok {
				delete(state.Uids, key.text())
				changed = true
			}
		}
		if changed {
			if err := self.writeWithLock(mailImapUidFileName(folder), state); err != nil {
				return err
			}
		}
	}
	return nil
}

// Whether key was purged here.
func (self *mailImapUids) Tombstoned(key MailImapKey) (bool, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := self.loadTombstonesWithLock(); err != nil {
		return false, err
	}
	return self.tombstones[key.text()], nil
}
