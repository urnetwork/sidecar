// §5.9's directory/: the team directory's copy on this device, file class search (RECORD-M6-13). It keeps what the
// syncs fetched, so a restart reads nothing again, and what the next sync starts from:
//
//	state                 the directory it is of, the push sequence the last sync ended at, the UTC day of the last
//	                      full listing, and the version this device holds of the cards ref, the erasure ref and each
//	                      stream
//	s/<writer>/<version>  one committed push of a writer's stream, as the read carried it
//	k/<slot>              that push's slot object's live rows, keys which never leave this store but to the reader
//	c/<path>              each file of the cards ref, as its newest statement left it: notices at M6, cards and repo
//	                      files from format 2
//	read/                 RECORD-M3-03's reader's pins of the directory's chains
//
// A version is kept before its stream's position moves, and the state is written last, so a kill leaves at most
// versions a later sync fetches and writes again alike. Everything goes at once on a lost read or a different
// directory (Reset). Phones keep it in memory while the view is open: their store is a memory one. Never a query, a
// hit or a view (owner decision 171).
//
// Ids in names are 32 lowercase hex characters (plan-RECORD-stream-names #2). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The store's names and its documents' version, format values of its own state.
const (
	directoryStoreStateName    = "state"
	directoryStoreStreamPrefix = "s/"
	directoryStoreSlotPrefix   = "k/"
	directoryStoreCardPrefix   = "c/"
	directoryStoreVersion      = 1
	// The component's directory and its file class (§5.9).
	directoryComponentName = "directory"
	directoryFileClass     = "search"
)

// A store file does not decode: never read as empty, which would let the copy wind back.
var ErrDirectoryStoreCorrupt = errors.New("directory store corrupt")

// Where the next sync starts.
type DirectoryStoreState struct {
	// The directory this copy is of.
	DirectoryId Id
	// The push sequence the last sync's listing ended at, the next moved_after, and whether one did.
	Sequence      uint64
	SequenceKnown bool
	// The UTC day, days since 1970, of the last listing of every ref.
	FullListingDay int64
	CardsVersion   uint64
	ErasureVersion uint64
	// Each writer's stream as far as this copy holds it.
	StreamVersions map[Id]uint64
}

// A copy.
func (self *DirectoryStoreState) clone() *DirectoryStoreState {
	cloned := *self
	cloned.StreamVersions = maps.Clone(self.StreamVersions)
	if cloned.StreamVersions == nil {
		cloned.StreamVersions = map[Id]uint64{}
	}
	return &cloned
}

// The state file's document.
type directoryStateDocument struct {
	Version        int               `json:"version"`
	DirectoryId    Id                `json:"directory_id"`
	Sequence       uint64            `json:"sequence"`
	SequenceKnown  bool              `json:"sequence_known"`
	FullListingDay int64             `json:"full_listing_day"`
	CardsVersion   uint64            `json:"cards_version"`
	ErasureVersion uint64            `json:"erasure_version"`
	StreamVersions map[string]uint64 `json:"stream_versions"`
}

// A kept push's document.
type directoryVersionDocument struct {
	Version     int                      `json:"version"`
	PushVersion uint64                   `json:"push_version"`
	PushId      Id                       `json:"push_id"`
	TimeMillis  int64                    `json:"time_millis"`
	PinVersion  uint64                   `json:"pin_version"`
	PinChain    []byte                   `json:"pin_chain"`
	SlotId      Id                       `json:"slot_id"`
	Entries     []directoryEntryDocument `json:"entries"`
}

// One entry file a kept push created.
type directoryEntryDocument struct {
	Path  string `json:"path"`
	Entry []byte `json:"entry"`
}

// A kept slot's document.
type directorySlotDocument struct {
	Version int                     `json:"version"`
	SlotId  Id                      `json:"slot_id"`
	Rows    []directorySlotRowEntry `json:"rows"`
}

// One row of a kept slot.
type directorySlotRowEntry struct {
	KeyIndex uint32 `json:"key_index"`
	Row      []byte `json:"row"`
}

// A kept cards ref file's document.
type directoryCardDocument struct {
	Version         int    `json:"version"`
	Path            string `json:"path"`
	PathVersion     uint64 `json:"path_version"`
	Content         []byte `json:"content"`
	PushVersion     uint64 `json:"push_version"`
	SignerSidecarId Id     `json:"signer_sidecar_id"`
	PinVersion      uint64 `json:"pin_version"`
	PinChain        []byte `json:"pin_chain"`
	TimeMillis      int64  `json:"time_millis"`
}

// The directory's copy over a sealed directory of its own.
type DirectoryStore struct {
	store SidecarStore

	stateLock sync.Mutex
	loaded    bool
	state     *DirectoryStoreState
	cards     map[string]*DirectoryCardFile
}

// A copy over store, which is §5.9's directory/ under file class search, or a memory store on a phone.
func NewDirectoryStore(store SidecarStore) *DirectoryStore {
	return &DirectoryStore{store: store, state: &DirectoryStoreState{StreamVersions: map[Id]uint64{}}, cards: map[string]*DirectoryCardFile{}}
}

// Reads one file's bytes, nil for none.
func (self *DirectoryStore) readFile(name string) ([]byte, error) {
	reader, err := self.store.Open(name)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	content := bytes.Buffer{}
	if _, err := content.ReadFrom(reader); err != nil {
		return nil, err
	}
	return content.Bytes(), nil
}

// Writes one document whole.
func (self *DirectoryStore) writeDocument(name string, document any) error {
	content, err := json.Marshal(document)
	if err != nil {
		return err
	}
	writer, err := self.store.Create(name)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(content); err != nil {
		return err
	}
	return writer.Commit()
}

// Reads the state once and the cards ref's files, resetting a copy of another directory.
func (self *DirectoryStore) Load(directoryId Id) error {
	self.stateLock.Lock()
	loaded, held := self.loaded, self.state.DirectoryId
	self.stateLock.Unlock()
	if loaded && held == directoryId {
		return nil
	}
	content, err := self.readFile(directoryStoreStateName)
	if err != nil {
		return err
	}
	state := &DirectoryStoreState{DirectoryId: directoryId, StreamVersions: map[Id]uint64{}}
	if content != nil {
		document := &directoryStateDocument{}
		if err := recordChainDecode(content, document); err != nil || document.Version != directoryStoreVersion {
			return fmt.Errorf("%w: the state", ErrDirectoryStoreCorrupt)
		}
		if document.DirectoryId != directoryId {
			// a copy of another directory: nothing of it stands for this one
			if err := self.Reset(); err != nil {
				return err
			}
			return self.Load(directoryId)
		}
		state.Sequence, state.SequenceKnown, state.FullListingDay = document.Sequence, document.SequenceKnown, document.FullListingDay
		state.CardsVersion, state.ErasureVersion = document.CardsVersion, document.ErasureVersion
		for writerText, version := range document.StreamVersions {
			writerId, err := directoryParseIdText(writerText)
			if err != nil {
				return fmt.Errorf("%w: a stream's writer", ErrDirectoryStoreCorrupt)
			}
			state.StreamVersions[writerId] = version
		}
	}
	cards := map[string]*DirectoryCardFile{}
	entries, err := self.store.List(directoryStoreCardPrefix)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		content, err := self.readFile(entry.Name)
		if err != nil {
			return err
		}
		document := &directoryCardDocument{}
		if content == nil || recordChainDecode(content, document) != nil || document.Version != directoryStoreVersion ||
			directoryStoreCardPrefix+document.Path != entry.Name {
			return fmt.Errorf("%w: a cards ref file", ErrDirectoryStoreCorrupt)
		}
		cards[document.Path] = &DirectoryCardFile{
			Path: document.Path, Version: document.PathVersion, Content: document.Content, PushVersion: document.PushVersion,
			SignerSidecarId: document.SignerSidecarId, AuthPin: &bridge.AuthPin{Version: document.PinVersion, Chain: document.PinChain},
			TimeMillis: document.TimeMillis,
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.state = state
	self.cards = cards
	self.loaded = true
	return nil
}

// 32 lowercase hex characters as an id.
func directoryParseIdText(text string) (Id, error) {
	if len(text) != 2*len(Id{}) || strings.ToLower(text) != text {
		return Id{}, fmt.Errorf("an id of %d characters", len(text))
	}
	return aclParseHexId(text)
}

// A copy of the state.
func (self *DirectoryStore) State() *DirectoryStoreState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.state.clone()
}

// Writes state as the state file, then keeps it.
func (self *DirectoryStore) writeState(state *DirectoryStoreState) error {
	document := &directoryStateDocument{
		Version: directoryStoreVersion, DirectoryId: state.DirectoryId, Sequence: state.Sequence, SequenceKnown: state.SequenceKnown,
		FullListingDay: state.FullListingDay, CardsVersion: state.CardsVersion, ErasureVersion: state.ErasureVersion,
		StreamVersions: map[string]uint64{},
	}
	for writerId, version := range state.StreamVersions {
		document.StreamVersions[recordChainIdText(writerId)] = version
	}
	if err := self.writeDocument(directoryStoreStateName, document); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.state = state.clone()
	return nil
}

// Applies one page of the cards ref's changes: each file written or removed as its statement left it, then the
// ref's position. A path no directory file takes is not kept.
func (self *DirectoryStore) ApplyCards(changes *DirectoryCardsChanges) error {
	if changes == nil {
		return nil
	}
	state := self.State()
	for _, file := range changes.Files {
		if file == nil || !directoryCardPathKept(file.Path) || file.PushVersion <= state.CardsVersion {
			continue
		}
		name := directoryStoreCardPrefix + file.Path
		if file.Removed {
			if err := self.store.Remove(name); err != nil {
				return err
			}
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				delete(self.cards, file.Path)
			}()
			continue
		}
		document := &directoryCardDocument{
			Version: directoryStoreVersion, Path: file.Path, PathVersion: file.Version, Content: file.Content,
			PushVersion: file.PushVersion, SignerSidecarId: file.SignerSidecarId, PinVersion: file.AuthPin.GetVersion(),
			PinChain: file.AuthPin.GetChain(), TimeMillis: file.TimeMillis,
		}
		if err := self.writeDocument(name, document); err != nil {
			return err
		}
		kept := *file
		kept.Content = bytes.Clone(file.Content)
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.cards[file.Path] = &kept
		}()
	}
	if changes.ThroughVersion <= state.CardsVersion {
		return nil
	}
	state.CardsVersion = changes.ThroughVersion
	return self.writeState(state)
}

// The cards ref's files this copy holds, in path order. Copies.
func (self *DirectoryStore) Cards() []*DirectoryCardFile {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	files := make([]*DirectoryCardFile, 0, len(self.cards))
	for _, file := range self.cards {
		copied := *file
		copied.Content = bytes.Clone(file.Content)
		files = append(files, &copied)
	}
	slices.SortFunc(files, func(a *DirectoryCardFile, b *DirectoryCardFile) int { return strings.Compare(a.Path, b.Path) })
	return files
}

// The name of a kept push.
func directoryStoreVersionName(writerSidecarId Id, version uint64) string {
	return fmt.Sprintf("%s%s/%020d", directoryStoreStreamPrefix, recordChainIdText(writerSidecarId), version)
}

// Keeps a stream's versions past what this copy holds, in order and with no gap, each with its slot, then the
// stream's position. A version out of order stops there, keeping what came before it.
func (self *DirectoryStore) AppendStream(writerSidecarId Id, versions []*DirectoryStreamVersion) error {
	state := self.State()
	held := state.StreamVersions[writerSidecarId]
	reached := held
	for _, version := range versions {
		if version == nil || version.Version == nil || version.Version.Version <= reached {
			continue
		}
		if version.Version.Version != reached+1 {
			break
		}
		recordVersion := version.Version
		document := &directoryVersionDocument{
			Version: directoryStoreVersion, PushVersion: recordVersion.Version, PushId: recordVersion.PushId,
			TimeMillis: recordVersion.TimeMillis, PinVersion: recordVersion.AuthPin.GetVersion(), PinChain: recordVersion.AuthPin.GetChain(),
			SlotId: recordVersion.SlotId,
		}
		for _, entry := range recordVersion.Entries {
			document.Entries = append(document.Entries, directoryEntryDocument{Path: entry.Path, Entry: entry.Entry})
		}
		if version.Slot != nil {
			slot := &directorySlotDocument{Version: directoryStoreVersion, SlotId: recordVersion.SlotId}
			for _, row := range version.Slot.Rows {
				slot.Rows = append(slot.Rows, directorySlotRowEntry{KeyIndex: row.KeyIndex, Row: row.Row})
			}
			if err := self.writeDocument(directoryStoreSlotPrefix+recordChainIdText(recordVersion.SlotId), slot); err != nil {
				return err
			}
		}
		if err := self.writeDocument(directoryStoreVersionName(writerSidecarId, recordVersion.Version), document); err != nil {
			return err
		}
		reached = recordVersion.Version
	}
	if reached == held {
		return nil
	}
	state.StreamVersions[writerSidecarId] = reached
	return self.writeState(state)
}

// A stream's kept versions after afterVersion, oldest first.
func (self *DirectoryStore) StreamVersions(writerSidecarId Id, afterVersion uint64) ([]*DirectoryStreamVersion, error) {
	prefix := directoryStoreStreamPrefix + recordChainIdText(writerSidecarId) + "/"
	entries, err := self.store.List(prefix)
	if err != nil {
		return nil, err
	}
	versions := []*DirectoryStreamVersion{}
	for _, entry := range entries {
		number, err := strconv.ParseUint(strings.TrimPrefix(entry.Name, prefix), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: a kept push's name", ErrDirectoryStoreCorrupt)
		}
		if number <= afterVersion {
			continue
		}
		content, err := self.readFile(entry.Name)
		if err != nil {
			return nil, err
		}
		document := &directoryVersionDocument{}
		if content == nil || recordChainDecode(content, document) != nil || document.Version != directoryStoreVersion || document.PushVersion != number {
			return nil, fmt.Errorf("%w: a kept push", ErrDirectoryStoreCorrupt)
		}
		version := &RecordStreamVersion{
			Version: document.PushVersion, PushId: document.PushId, TimeMillis: document.TimeMillis,
			AuthPin: &bridge.AuthPin{Version: document.PinVersion, Chain: document.PinChain}, SlotId: document.SlotId,
		}
		for _, entry := range document.Entries {
			version.Entries = append(version.Entries, &RecordStreamEntry{Path: entry.Path, Entry: entry.Entry})
		}
		versions = append(versions, &DirectoryStreamVersion{Version: version})
	}
	return versions, nil
}

// A kept slot's live rows, nil for a slot this copy never kept.
func (self *DirectoryStore) Slot(slotId Id) (*RecordSlot, error) {
	content, err := self.readFile(directoryStoreSlotPrefix + recordChainIdText(slotId))
	if err != nil || content == nil {
		return nil, err
	}
	document := &directorySlotDocument{}
	if recordChainDecode(content, document) != nil || document.Version != directoryStoreVersion || document.SlotId != slotId {
		return nil, fmt.Errorf("%w: a kept slot", ErrDirectoryStoreCorrupt)
	}
	slot := &RecordSlot{SlotId: slotId}
	for _, row := range document.Rows {
		slot.Rows = append(slot.Rows, &RecordSlotRow{KeyIndex: row.KeyIndex, Row: row.Row})
	}
	return slot, nil
}

// Notes the erasure ref's version the reader read through.
func (self *DirectoryStore) NoteErasureVersion(version uint64) error {
	state := self.State()
	if version <= state.ErasureVersion {
		return nil
	}
	state.ErasureVersion = version
	return self.writeState(state)
}

// Ends a sync: the listing's sequence is the next moved_after, and a full listing's day is kept.
func (self *DirectoryStore) FinishSync(sequence uint64, full bool, day int64) error {
	state := self.State()
	state.Sequence, state.SequenceKnown = sequence, true
	if full {
		state.FullListingDay = day
	}
	return self.writeState(state)
}

// Deletes every file of the copy, the reader's pins included, and forgets what it held: a lost read, or a copy of
// another directory (§5.9).
func (self *DirectoryStore) Reset() error {
	entries, err := self.store.List("")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := self.store.Remove(entry.Name); err != nil {
			return err
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.loaded = false
	self.state = &DirectoryStoreState{StreamVersions: map[Id]uint64{}}
	self.cards = map[string]*DirectoryCardFile{}
	return nil
}

// Whether the copy holds no file.
func (self *DirectoryStore) Empty() (bool, error) {
	entries, err := self.store.List("")
	if err != nil {
		return false, err
	}
	return len(entries) == 0, nil
}
