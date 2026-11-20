//go:build !ios_extension

// RECORD-M10-02's cards (§16.11's ref cards block and its card, caps, path rules and repair rows; D-MCP-28,
// I-EVS-14, FI-25, FS-84): from the directory's format 2 a sidecar's live items ride one file, its card at
// d/<h>/<sid> on the shared cards ref, in place of announce entries in its stream. RECORD-M10-03 moves daemons onto
// it; here a card is written when asked, and every card and repo file the copy holds (directory_repo_file.go) is
// judged by its path's rules and folded.
//
//	card    a Signed DirectoryCard, by the sidecar's identity key under purpose directory, SIGNED_DIRECTORY_CARD:
//	        network_id, its own sidecar_id, seq, at (§7.9's pin as written), written_millis, at most 16 items, at most
//	        one worker item first and then runs, in at most 16,188 B (QD-858), and version 1; the whole Signed at most
//	        16 KiB, eight steps, which every card within its items' bytes fits, and past which a writer puts none and
//	        a reader parses none
//	write   WriteCard puts the items it is given, less those that show no more: a withdrawal, which a card says by
//	        leaving the item out, an ended or handed-off item 24 h after its renewal, an active one past its stale 24 h.
//	        Each passes DirectoryCheckItem with this sidecar as who; past a cap the writer refuses
//	        (ErrDirectoryCardOverCap) and signs nothing. seq is one above the last this device wrote or this copy
//	        accepted at the path, journaled before the put so a kill never reuses one. The put names the newest version
//	        this device knows at its path, its own last put where the copy has not read it back, so a removal that came
//	        after it fails the put rather than going unread; a path conflict syncs once and puts again from the version
//	        read. One write carries every item, so one write renews every moving run
//	version each item rides the card at its writer's version, which a content change raises and a renewal keeps, plus
//	        this device's raise, 0 until another signer first removes its path. The first card it writes once its copy
//	        shows such a removal at the path's newest version, read at its sync whatever the path rules make of it (a
//	        directory admin's moderation, which its moderation notice shows, a cleanup once it was revoked, a breach),
//	        is a return: the raise grows so that every item comes back above the tombstone the removal's push wrote for
//	        it, one above the version the removal took, which wins a tie, so by two for an item carried unchanged, with
//	        no content change (§16.11's versions and closure rows, owner decision 645). The raise is journaled with the
//	        seq, before the put, and never falls, so later cards carry their items on the raised line: a renewal keeps
//	        its version and a content change still raises it. Items read back from the card this device put last (the
//	        format 2 carrier's seed, the repair) go back to their writers' versions first (cardWrittenItems)
//	binding the DirectoryCards binding writes d/ and r/ as the directory's reserved writer (EvsReservedDirectory,
//	        versionless from format 2) and seals each file padded to FileStepByteCount steps, so a card's size shows at
//	        most whether its sidecar has more than about two runs; the plaintext is the Signed's own bytes
//	read    a d/ version counts only by its push's signer and auth pin (I-EVS-14): written by <sid> alone, whose Signed
//	        signs it and names the path's sidecar and this network, seq above the last version this copy accepted
//	        there, at within 4,096 positions of the reader's state with its signer standing at at, and within its caps;
//	        or pushed by a directory admin at its push's pin, an erasure's CLOSURE (closurePush; RECORD-M10-05), which
//	        counts only as <sid>'s own Signed card: the bytes this copy accepted last, taken again in silence, or a
//	        version it never accepted, held to every rule above but the pusher's;
//	        removed by <sid>, by any writer once <sid> is revoked or reaped, or by a directory admin, whose moderation
//	        alarms <sid>'s member's own devices. Any other version is ignored with an alarm, once, and the reader goes
//	        on showing the version it accepted last (§16.11's repair row), which a/<path> in the copy keeps across
//	        restarts
//	fold    each accepted card's items fold beside M6's announce entries under directory_rules.go's card rules, the
//	        card's at standing for a push pin and its push's time_ms for an entry's
//
// Barriers: directory.card.before and .after around a card's put, keyed by the sidecar's id, with no lock held. Safe for
// concurrent use. Locks: a part's writeLock, then its stateLock; no lock is held across a sync or a call into the state.

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The purpose a card and a repo file are signed under (§6.9).
const DirectorySignedPurpose = "directory"

// DirectoryCard.version, the one this build writes and reads.
const directoryCardFormatVersion = 1

// DirectoryCard.items' field number, whose tag and length count toward the items' bytes.
const directoryCardItemsField protowire.Number = 6

// The copy's names for what this device accepted and wrote, and their documents' version: format values of its own
// state.
const (
	directoryAcceptedPrefix       = "a/"
	directoryAcceptedVersion      = 1
	directoryCardWrittenName      = "card"
	directoryCardWrittenKept      = 1
	directoryCardSettingsPartName = "card settings"
	directoryCardWriterPart       = "card writer"
)

// The domains of the leaves a file's items fold under, apart from every entry's (RFC 9162's 0x00 prefix).
const (
	directoryCardItemLeafDomain = "urnetwork-sidecar-v1/directory-card-item"
	directoryRepoFileLeafDomain = "urnetwork-sidecar-v1/directory-repo-file"
)

var (
	// A card past its caps: more than its items, a second worker item or a worker item after a run, or its items past
	// their bytes, refused before anything is signed; or its Signed past the card file's bytes, signed and never put.
	ErrDirectoryCardOverCap = errors.New("directory card over its caps")
	// The client has no signer or no network bound (DirectoryClientArgs.Sign and NetworkId): nothing was signed.
	ErrDirectoryCardUnbound = errors.New("directory card writer unbound")
	// This sidecar does not stand to write in the directory at the state now (§16.11's card row): readers would ignore
	// its card, so nothing was signed.
	ErrDirectoryCardStanding = errors.New("directory card: this sidecar does not stand to write")
)

// What cards and repo files hold at most and how they are stored and judged. Their defaults are §16.11's values,
// which every reader and writer share, so a deployment changes none on one side alone.
type DirectoryCardSettings struct {
	// A card's items: 16.
	ItemCount int
	// Worker items among them, first: 1.
	WorkerItemCount int
	// The items' bytes, each item's field tag and length included: 16,188 B (QD-858, amending QD-834's 16,192), the
	// most at which every Signed card fits CardFileByteCount.
	ItemsByteCount int
	// A card file's bytes, the Signed and all, past which a writer puts none and a reader parses none: 16 KiB, §20.4's
	// directory_card_bytes, eight steps. A card whose items are within ItemsByteCount fits it whatever its seq, its
	// position and its written_millis: the card's and the Signed's own fields take at most 196 B, with those three
	// varints at their widest. The bound stands on its own on both sides, so settings that raise ItemsByteCount alone
	// still put and parse no larger file.
	CardFileByteCount int
	// A repo file's bytes: 4 KiB.
	RepoFileByteCount int
	// The step cards and repo files are stored padded to: 2 KiB.
	FileStepByteCount int
	// A card's at within this many positions of the reader's state, and a repo file's within this many before its
	// push's auth pin: 4,096.
	PinPositionCount uint64
	// An ended or handed-off item stays on its card this long from its renewal: 24 h.
	EndedKeepTime time.Duration
	// An active item past its expires_millis stays on its card this long, shown stale: 24 h.
	StaleShowTime time.Duration
}

// The defaults, a fresh value each call.
func DefaultDirectoryCardSettings() *DirectoryCardSettings {
	return &DirectoryCardSettings{
		ItemCount:         DirectoryCardItemCount,
		WorkerItemCount:   1,
		ItemsByteCount:    16188,
		CardFileByteCount: 16 * 1024,
		RepoFileByteCount: DirectoryRepoFileByteCount,
		FileStepByteCount: DirectoryFileStepByteCount,
		PinPositionCount:  DirectoryPinPositionCount,
		EndedKeepTime:     DirectoryEndedKeepTime,
		StaleShowTime:     DirectoryStaleShowTime,
	}
}

// The size a file of byteCount is stored at: the next whole step.
func (self *DirectoryCardSettings) StoredByteCount(byteCount int) int {
	step := max(self.FileStepByteCount, 1)
	return max(1, (byteCount+step-1)/step) * step
}

// A card file as stored.
type StoredDirectoryCard struct {
	Card   *protocol.DirectoryCard
	Signed *bridge.Signed
	// As received, never re-encoded.
	Bytes []byte
}

// Whether pin is a pin at all: a position and a 32 B chain value.
func directoryPinValid(pin *bridge.AuthPin) bool {
	return pin != nil && 0 < pin.GetVersion() && len(pin.GetChain()) == sha256.Size
}

// The bytes a card's items take in it, each item's tag and length included.
func directoryCardItemsByteCount(items []*protocol.Announcement) int {
	byteCount := 0
	for _, item := range items {
		byteCount += protowire.SizeTag(directoryCardItemsField) + protowire.SizeBytes(proto.Size(item))
	}
	return byteCount
}

// The Signed a card or repo file carries, from content within maxByteCount, of signedType, signed by an identity key:
// a 16 B signer_id, a 64 B signature, and neither a key_id nor WebAuthn evidence.
func directoryDecodeSignedFile(name string, content []byte, maxByteCount int, signedType bridge.SignedType) (*bridge.Signed, error) {
	if err := directoryBound(name, content, maxByteCount); err != nil {
		return nil, err
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(content, signed); err != nil {
		return nil, directoryRefusal("%s that does not parse: %v", name, err)
	}
	switch {
	case signed.GetType() != uint32(signedType):
		return nil, directoryRefusal("%s of signed type %#x", name, signed.GetType())
	case !directoryIdValid(signed.GetSignerId(), false):
		return nil, directoryRefusal("%s with a signer_id of %d bytes", name, len(signed.GetSignerId()))
	case len(signed.GetKeyId()) != 0, signed.GetWebauthn() != nil:
		return nil, directoryRefusal("%s signed by another key than an identity key", name)
	case len(signed.GetSignature()) != 64:
		return nil, directoryRefusal("%s with a signature of %d bytes", name, len(signed.GetSignature()))
	}
	return signed, nil
}

// A card file's content, d/<h>/<sid>: within CardFileByteCount, a Signed of type SIGNED_DIRECTORY_CARD by an identity
// key, whose body parses as a DirectoryCard that passes DirectoryCheckCard. Who signed it, against the path and the
// card's sidecar_id, and the signature itself are the reader's to judge, under the key its state holds.
func DirectoryDecodeCard(content []byte, settings *DirectoryCardSettings) (*StoredDirectoryCard, error) {
	if settings == nil {
		settings = DefaultDirectoryCardSettings()
	}
	signed, err := directoryDecodeSignedFile("a card", content, settings.CardFileByteCount, bridge.SignedType_SIGNED_DIRECTORY_CARD)
	if err != nil {
		return nil, err
	}
	card := &protocol.DirectoryCard{}
	if err := proto.Unmarshal(signed.GetBody(), card); err != nil {
		return nil, directoryRefusal("a card body that does not parse: %v", err)
	}
	if err := DirectoryCheckCard(card, settings); err != nil {
		return nil, err
	}
	return &StoredDirectoryCard{Card: card, Signed: signed, Bytes: bytes.Clone(content)}, nil
}

// Holds a card to §16.11's card and caps rows and directory.proto's form: its ids, a seq and written time, a pin, the
// version this build reads, and its items: at most ItemCount in at most ItemsByteCount, at most WorkerItemCount worker
// items and those first, then runs, no repo item, no two with one announcement_id, each passing DirectoryCheckItem with
// the card's sidecar as who. A writer refuses what this refuses before it signs; a reader ignores the version and
// alarms over_cap.
func DirectoryCheckCard(card *protocol.DirectoryCard, settings *DirectoryCardSettings) error {
	if card == nil {
		return directoryRefusal("no card")
	}
	if settings == nil {
		settings = DefaultDirectoryCardSettings()
	}
	switch {
	case !directoryIdValid(card.GetNetworkId(), false), !directoryIdValid(card.GetSidecarId(), false):
		return directoryRefusal("a card with a network_id of %d bytes and a sidecar_id of %d", len(card.GetNetworkId()), len(card.GetSidecarId()))
	case card.GetSeq() == 0:
		return directoryRefusal("a card at seq 0")
	case !directoryPinValid(card.GetAt()):
		return directoryRefusal("a card with no pin")
	case card.GetWrittenMillis() <= 0:
		return directoryRefusal("a card written at %d", card.GetWrittenMillis())
	case card.GetVersion() != directoryCardFormatVersion:
		return directoryRefusal("a card of version %d", card.GetVersion())
	}
	items := card.GetItems()
	if settings.ItemCount < len(items) {
		return directoryRefusal("a card of %d items", len(items))
	}
	if byteCount := directoryCardItemsByteCount(items); settings.ItemsByteCount < byteCount {
		return directoryRefusal("a card's items of %d bytes", byteCount)
	}
	workerCount := 0
	seen := map[Id]bool{}
	for index, item := range items {
		if err := DirectoryCheckItem(item); err != nil {
			return err
		}
		switch DirectoryAnnouncementKind(item.GetKind()) {
		case DirectoryAnnouncementKindWorker:
			workerCount += 1
			if index != workerCount-1 {
				return directoryRefusal("a card's worker item after a run")
			}
		case DirectoryAnnouncementKindRun:
		default:
			return directoryRefusal("a card holding an item of kind %d", item.GetKind())
		}
		if !bytes.Equal(item.GetWho().GetSidecarId(), card.GetSidecarId()) {
			return directoryRefusal("a card holding another sidecar's item")
		}
		announcementId := recordIdOf(item.GetAnnouncementId())
		if seen[announcementId] {
			return directoryRefusal("a card holding one announcement twice")
		}
		seen[announcementId] = true
	}
	if settings.WorkerItemCount < workerCount {
		return directoryRefusal("a card of %d worker items", workerCount)
	}
	return nil
}

// The sidecar a d/<h>/<sid> path names, false for any other path.
func directoryCardPathSidecar(path string) (Id, bool) {
	parts := strings.Split(path, "/")
	if len(parts) != 3 || parts[0] != "d" {
		return Id{}, false
	}
	sidecarId, err := directoryParseIdText(parts[2])
	if err != nil || DirectoryCardPath(sidecarId) != path {
		return Id{}, false
	}
	return sidecarId, true
}

// The repo an r/<h>/<repo> path names, false for any other path.
func directoryRepoPathRepo(path string) (Id, bool) {
	parts := strings.Split(path, "/")
	if len(parts) != 3 || parts[0] != "r" {
		return Id{}, false
	}
	repoId, err := directoryParseIdText(parts[2])
	if err != nil || DirectoryRepoPath(repoId) != path {
		return Id{}, false
	}
	return repoId, true
}

// One card or repo file version this copy accepted, kept at a/<path>.
type directoryAcceptedFile struct {
	file *DirectoryCardFile
	// the file's seq, kept through a removal, which the next version rises above
	seq  uint64
	card *StoredDirectoryCard
	repo *StoredDirectoryRepoFile
	// taken from an erasure's CLOSURE, a directory admin's push that rewrites the file in place under a fresh key
	// (closurePush): its push carries no index entry of the file's
	closure bool
}

// The document a/<path> holds.
type directoryAcceptedDocument struct {
	Version         int    `json:"version"`
	Path            string `json:"path"`
	PathVersion     uint64 `json:"path_version"`
	Removed         bool   `json:"removed,omitempty"`
	Content         []byte `json:"content,omitempty"`
	PushVersion     uint64 `json:"push_version"`
	SignerSidecarId Id     `json:"signer_sidecar_id"`
	PinVersion      uint64 `json:"pin_version"`
	PinChain        []byte `json:"pin_chain"`
	TimeMillis      int64  `json:"time_millis"`
	Seq             uint64 `json:"seq"`
}

// How a reader took one file version.
type directoryFileVerdict int

const (
	directoryFileAccepted directoryFileVerdict = iota + 1
	// Not judged yet: a pin ahead of the reader's state, or no state, key or network to judge by. Neither taken nor
	// alarmed; judged again at the next sync.
	directoryFilePending
	directoryFileRefused
)

// One alarm a file version raised, raised once.
type directoryFileAlarmKey struct {
	path        string
	pushVersion uint64
	reason      SidecarRecordAlarm
}

// The copy's judging of the cards ref's d/ and r/ files, held with the fold it feeds.
type directoryFiles struct {
	client *DirectoryClient

	stateLock sync.Mutex
	loaded    bool
	accepted  map[string]*directoryAcceptedFile
	// the push version of the newest file judged at each path, and whether it was refused: a breach its rightful
	// writer repairs
	judged  map[string]uint64
	refused map[string]bool
	alarmed map[directoryFileAlarmKey]bool
}

// The files state of fold, which goes with it at a lost read or another directory.
func (self *DirectoryClient) filesOf(fold *DirectoryFold) *directoryFiles {
	fold.stateLock.Lock()
	defer fold.stateLock.Unlock()
	files, _ := fold.fileState.(*directoryFiles)
	if files == nil {
		files = &directoryFiles{
			client:   self,
			accepted: map[string]*directoryAcceptedFile{},
			judged:   map[string]uint64{},
			refused:  map[string]bool{},
			alarmed:  map[directoryFileAlarmKey]bool{},
		}
		fold.fileState = files
	}
	return files
}

// The files state of the directory this client reads now.
func (self *DirectoryClient) files() *directoryFiles {
	return self.filesOf(self.currentFold())
}

// The card settings part.
type directoryCardSettingsPart struct {
	stateLock sync.Mutex
	settings  *DirectoryCardSettings
}

// Sets what cards and repo files are held to; nil keeps the current settings.
func (self *DirectoryClient) SetCardSettings(settings *DirectoryCardSettings) {
	if settings == nil {
		return
	}
	part := self.part(directoryCardSettingsPartName, func() any { return &directoryCardSettingsPart{settings: DefaultDirectoryCardSettings()} }).(*directoryCardSettingsPart)
	part.stateLock.Lock()
	defer part.stateLock.Unlock()
	part.settings = settings
}

// What cards and repo files are held to now.
func (self *DirectoryClient) cardSettings() *DirectoryCardSettings {
	part := self.part(directoryCardSettingsPartName, func() any { return &directoryCardSettingsPart{settings: DefaultDirectoryCardSettings()} }).(*directoryCardSettingsPart)
	part.stateLock.Lock()
	defer part.stateLock.Unlock()
	return part.settings
}

// Reads what this copy accepted, once, decoding each by settings.
func (self *directoryFiles) loadWithLock(settings *DirectoryCardSettings) error {
	if self.loaded {
		return nil
	}
	store := self.client.store
	entries, err := store.store.List(directoryAcceptedPrefix)
	if err != nil {
		return err
	}
	accepted := map[string]*directoryAcceptedFile{}
	for _, entry := range entries {
		content, err := store.readFile(entry.Name)
		if err != nil {
			return err
		}
		document := &directoryAcceptedDocument{}
		if content == nil || json.Unmarshal(content, document) != nil || document.Version != directoryAcceptedVersion ||
			directoryAcceptedPrefix+document.Path != entry.Name {
			return fmt.Errorf("%w: an accepted file", ErrDirectoryStoreCorrupt)
		}
		file := &DirectoryCardFile{
			Path: document.Path, Version: document.PathVersion, Removed: document.Removed, Content: document.Content,
			PushVersion: document.PushVersion, SignerSidecarId: document.SignerSidecarId,
			AuthPin: &bridge.AuthPin{Version: document.PinVersion, Chain: document.PinChain}, TimeMillis: document.TimeMillis,
		}
		taken := &directoryAcceptedFile{file: file, seq: document.Seq}
		if !file.Removed {
			// what was accepted decodes again by the same rules, or the copy is not what it kept
			if _, ok := directoryCardPathSidecar(file.Path); ok {
				if taken.card, err = DirectoryDecodeCard(file.Content, settings); err != nil {
					return fmt.Errorf("%w: an accepted card", ErrDirectoryStoreCorrupt)
				}
			} else if taken.repo, err = DirectoryDecodeRepoFile(file.Content, settings); err != nil {
				return fmt.Errorf("%w: an accepted repo file", ErrDirectoryStoreCorrupt)
			}
		}
		accepted[file.Path] = taken
	}
	self.accepted = accepted
	for path, taken := range accepted {
		// what was accepted is judged already: a restart takes it again as it stands, never as its own replay
		self.judged[path] = max(self.judged[path], taken.file.PushVersion)
	}
	self.loaded = true
	return nil
}

// Keeps taken as the path's accepted version, in the store first.
func (self *directoryFiles) accept(taken *directoryAcceptedFile) error {
	file := taken.file
	document := &directoryAcceptedDocument{
		Version: directoryAcceptedVersion, Path: file.Path, PathVersion: file.Version, Removed: file.Removed, PushVersion: file.PushVersion,
		SignerSidecarId: file.SignerSidecarId, PinVersion: file.AuthPin.GetVersion(), PinChain: file.AuthPin.GetChain(),
		TimeMillis: file.TimeMillis, Seq: taken.seq,
	}
	if !file.Removed {
		document.Content = file.Content
	}
	if err := self.client.store.writeDocument(directoryAcceptedPrefix+file.Path, document); err != nil {
		return err
	}
	previous := func() *directoryAcceptedFile {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		previous := self.accepted[file.Path]
		self.accepted[file.Path] = taken
		return previous
	}()
	if !taken.closure {
		// the index entries the version's push carries, for the reader's own derivation of its writer's head
		// (directory_index.go)
		self.client.indexAccepted(previous, taken)
	}
	return nil
}

// Whether file's push, by another sidecar than its path's rightful writer, is a directory admin's at its push's pin: an
// erasure's CLOSURE, which rewrites a card or a repo file in place under a fresh key and signs nothing of its own
// (§16.11's readers row, §11.12's versionless row; RECORD-M10-05). The file it carries is still judged as its rightful
// writer's, whose signature it must hold, so an admin's push shows nothing that writer did not sign. The second answer
// is true where the pin is ahead of the reader's state, and the version waits.
func (self *directoryFiles) closurePush(auth DirectoryAuthView, file *DirectoryCardFile) (bool, bool) {
	at := auth
	judged, err := auth.At(file.AuthPin)
	switch {
	case err == nil:
		at = judged
	case errors.Is(err, ErrDirectoryAuthAhead), errors.Is(err, ErrDirectoryAuthUnavailable):
		return false, true
	case !errors.Is(err, ErrDirectoryAuthNotRetained):
		// a pin off the reader's chain
		return false, false
	}
	admins, err := at.DirectoryAdmins(at.Pin())
	return err == nil && slices.Contains(admins, file.SignerSidecarId), false
}

// The version this copy accepted last at file's path, taken again where file is a CLOSURE's rewrite of its very
// bytes: the content's own push still stands for its pin and its time, the rewrite's for the path's version, its push
// and its signer. Nil where the copy accepted other bytes, a removal or nothing.
func (self *directoryFiles) closureOfAccepted(file *DirectoryCardFile) *directoryAcceptedFile {
	accepted := self.acceptedAt(file.Path)
	if accepted == nil || accepted.file.Removed || !bytes.Equal(accepted.file.Content, file.Content) {
		return nil
	}
	closed := *accepted.file
	closed.Version = file.Version
	closed.PushVersion = file.PushVersion
	closed.SignerSidecarId = file.SignerSidecarId
	return &directoryAcceptedFile{file: &closed, seq: accepted.seq, card: accepted.card, repo: accepted.repo, closure: true}
}

// The version this copy accepted last at path, nil for none.
func (self *directoryFiles) acceptedAt(path string) *directoryAcceptedFile {
	settings := self.client.cardSettings()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := self.loadWithLock(settings); err != nil {
		return nil
	}
	return self.accepted[path]
}

// Whether the newest version this copy judged at path was refused: a breach, which its rightful writer repairs.
func (self *directoryFiles) breached(path string) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.refused[path]
}

// The seq a version at path must rise above: the last accepted there, 0 for none.
func (self *directoryFiles) seqAt(path string) uint64 {
	if accepted := self.acceptedAt(path); accepted != nil {
		return accepted.seq
	}
	return 0
}

// What one judgement found, with the alarm a refusal raises: none for a version that broke no rule but counts for
// nothing.
type directoryFileJudgement struct {
	verdict directoryFileVerdict
	alarm   SidecarRecordAlarm
	// the sidecar the alarm names: the push's signer unless set
	alarmSidecarId *Id
	taken          *directoryAcceptedFile
}

// A refusal raising alarm.
func directoryFileRefusal(alarm SidecarRecordAlarm) directoryFileJudgement {
	return directoryFileJudgement{verdict: directoryFileRefused, alarm: alarm}
}

// Raises judgement's alarm for file, once a path, version and reason.
func (self *directoryFiles) alarm(file *DirectoryCardFile, judgement directoryFileJudgement) {
	if judgement.alarm == "" {
		return
	}
	key := directoryFileAlarmKey{path: file.Path, pushVersion: file.PushVersion, reason: judgement.alarm}
	raise := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.alarmed[key] {
			return false
		}
		self.alarmed[key] = true
		return true
	}()
	if !raise {
		return
	}
	sidecarId := file.SignerSidecarId
	if judgement.alarmSidecarId != nil {
		sidecarId = *judgement.alarmSidecarId
	}
	directoryId, _ := self.client.DirectoryId()
	self.client.raise(judgement.alarm, directoryId, &sidecarId)
}

// Judges each d/ and r/ file the copy holds that this copy has not judged yet, keeping what it accepts and alarming
// what it refuses, and answers the versions every accepted file holds, for the fold: see the file's header.
func (self *directoryFiles) judge(fold *DirectoryFold) []*directoryVersion {
	settings := self.client.cardSettings()
	if err := func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.loadWithLock(settings)
	}(); err != nil {
		self.client.log.Warningf("[directory]the accepted files do not read: %s", err)
		return nil
	}
	client := self.client
	auth := client.auth()
	recordAuth := client.recordAuth()
	nowMillis := client.clock.Now().UnixMilli()
	judge := &directoryJudge{fold: fold, auth: auth, readerPin: auth.Pin(), nowMillis: nowMillis, standingNow: map[Id]DirectoryStanding{}}
	for _, file := range client.store.Cards() {
		_, card := directoryCardPathSidecar(file.Path)
		_, repo := directoryRepoPathRepo(file.Path)
		if !card && !repo {
			continue
		}
		judgedVersion := func() uint64 {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.judged[file.Path]
		}()
		if file.PushVersion <= judgedVersion {
			continue
		}
		var judgement directoryFileJudgement
		switch {
		case card && file.Removed:
			judgement = self.judgeCardRemoval(auth, file)
		case card:
			judgement = self.judgeCard(auth, recordAuth, file)
		case file.Removed:
			judgement = self.judgeRepoFileRemoval(auth, file)
		default:
			judgement = self.judgeRepoFile(auth, recordAuth, judge, file)
		}
		if judgement.verdict == directoryFilePending {
			continue
		}
		if judgement.verdict == directoryFileAccepted {
			if err := self.accept(judgement.taken); err != nil {
				client.log.Warningf("[directory]an accepted file was not kept: %s", err)
				continue
			}
		}
		self.alarm(file, judgement)
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.judged[file.Path] = file.PushVersion
			self.refused[file.Path] = judgement.verdict == directoryFileRefused
		}()
	}
	for _, alarm := range judge.alarms {
		if fold.alarm != nil {
			fold.alarm(alarm)
		}
	}
	versions := []*directoryVersion{}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	paths := make([]string, 0, len(self.accepted))
	for path := range self.accepted {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	for _, path := range paths {
		taken := self.accepted[path]
		switch {
		case taken.file.Removed:
		case taken.card != nil:
			versions = append(versions, directoryCardVersions(taken)...)
		case taken.repo != nil:
			versions = append(versions, directoryRepoFileVersion(taken))
		}
	}
	return versions
}

// The leaf one of a card's items folds under: the card's bytes and the item's place in it, apart from every entry's.
func directoryCardItemLeaf(content []byte, index int) [sha256.Size]byte {
	hash := sha256.New()
	hash.Write([]byte(directoryCardItemLeafDomain))
	hash.Write([]byte{0})
	hash.Write(content)
	hash.Write(binary.BigEndian.AppendUint32(nil, uint32(index)))
	var leaf [sha256.Size]byte
	hash.Sum(leaf[:0])
	return leaf
}

// An accepted card's items as the fold holds versions: each the card's sidecar's, at the card's seq, its at standing
// for a push pin and its push's time_ms for an entry's.
func directoryCardVersions(taken *directoryAcceptedFile) []*directoryVersion {
	card := taken.card.Card
	writerId := recordIdOf(card.GetSidecarId())
	at := card.GetAt()
	versions := []*directoryVersion{}
	for index, item := range card.GetItems() {
		kind := DirectoryAnnouncementKind(item.GetKind())
		versions = append(versions, &directoryVersion{
			key:            DirectoryItemKey{Kind: kind, WriterSidecarId: writerId, AnnouncementId: recordIdOf(item.GetAnnouncementId())},
			leaf:           directoryCardItemLeaf(taken.card.Bytes, index),
			writerId:       writerId,
			seq:            card.GetSeq(),
			pushPin:        &bridge.AuthPin{Version: at.GetVersion(), Chain: bytes.Clone(at.GetChain())},
			pushTimeMillis: taken.file.TimeMillis,
			item:           item,
		})
	}
	return versions
}

// Whether item shows yet at nowMillis, so that a card holds it: never a withdrawal, which a card says by leaving the
// item out; an ended or handed-off item for EndedKeepTime from its renewal; an active one until StaleShowTime past its
// expiry.
func (self *DirectoryCardSettings) shows(item *protocol.Announcement, nowMillis int64) bool {
	switch DirectoryAnnouncementState(item.GetState()) {
	case DirectoryAnnouncementStateActive:
		return nowMillis < item.GetExpiresMillis()+self.StaleShowTime.Milliseconds()
	case DirectoryAnnouncementStateEnded, DirectoryAnnouncementStateHandedOff:
		return nowMillis < item.GetRenewedMillis()+self.EndedKeepTime.Milliseconds()
	}
	return false
}

// A d/ path's written version by §16.11's path rules and card row: see the file's header's read row.
func (self *directoryFiles) judgeCard(auth DirectoryAuthView, recordAuth RecordAuthView, file *DirectoryCardFile) directoryFileJudgement {
	sidecarId, _ := directoryCardPathSidecar(file.Path)
	closure := false
	if file.SignerSidecarId != sidecarId {
		// pushed by another sidecar than the path's: only a directory admin's CLOSURE of the sidecar's own card counts
		closurePush, pending := self.closurePush(auth, file)
		switch {
		case pending:
			return directoryFileJudgement{verdict: directoryFilePending}
		case !closurePush:
			return directoryFileRefusal(SidecarRecordAlarmPathRule)
		}
		if taken := self.closureOfAccepted(file); taken != nil {
			return directoryFileJudgement{verdict: directoryFileAccepted, taken: taken}
		}
		// a rewrite of a version this copy never accepted: judged below as the sidecar's card
		closure = true
	}
	settings := self.client.cardSettings()
	stored, err := DirectoryDecodeCard(file.Content, settings)
	if err != nil {
		return directoryFileRefusal(SidecarRecordAlarmOverCap)
	}
	card := stored.Card
	if recordIdOf(card.GetSidecarId()) != sidecarId || recordIdOf(stored.Signed.GetSignerId()) != sidecarId {
		// naming, or signed by, another sidecar than the path's
		return directoryFileRefusal(SidecarRecordAlarmPathRule)
	}
	networkId := self.client.networkId
	if networkId == (Id{}) {
		return directoryFileJudgement{verdict: directoryFilePending}
	}
	if recordIdOf(card.GetNetworkId()) != networkId {
		return directoryFileRefusal(SidecarRecordAlarmBadEntry)
	}
	readerPin := auth.Pin()
	if readerPin == nil || readerPin.GetVersion() < card.GetAt().GetVersion() {
		return directoryFileJudgement{verdict: directoryFilePending}
	}
	key := recordAuth.IdentityKey(sidecarId)
	if len(key) == 0 || bridge.VerifySigned(stored.Signed, DirectorySignedPurpose, bridge.SignedType_SIGNED_DIRECTORY_CARD, bridge.SignedKeyAlgEd25519, key) != nil {
		return directoryFileRefusal(SidecarRecordAlarmBadEntry)
	}
	if card.GetSeq() <= self.seqAt(file.Path) {
		// not above the last version this copy accepted: a replay or a rollback
		return directoryFileRefusal(SidecarRecordAlarmBadEntry)
	}
	if settings.PinPositionCount < readerPin.GetVersion()-card.GetAt().GetVersion() {
		// an auth pin out of range
		return directoryFileRefusal(SidecarRecordAlarmBadEntry)
	}
	standing, err := auth.SignerStanding(sidecarId, card.GetAt())
	switch {
	case errors.Is(err, ErrDirectoryAuthAhead), errors.Is(err, ErrDirectoryAuthUnavailable):
		return directoryFileJudgement{verdict: directoryFilePending}
	case err != nil:
		return directoryFileRefusal(SidecarRecordAlarmBadEntry)
	case standing == DirectoryStandingUnconsented:
		return directoryFileRefusal(SidecarRecordAlarmParkedWriter)
	case standing != DirectoryStandingStanding:
		return directoryFileRefusal(SidecarRecordAlarmBadEntry)
	}
	return directoryFileJudgement{verdict: directoryFileAccepted, taken: &directoryAcceptedFile{file: file, seq: card.GetSeq(), card: stored, closure: closure}}
}

// A d/ path's removal by its path rule: by <sid>; by any writer once <sid> is revoked or reaped; by a directory admin,
// a moderation that alarms <sid>'s member's own devices. Any other is a breach.
func (self *directoryFiles) judgeCardRemoval(auth DirectoryAuthView, file *DirectoryCardFile) directoryFileJudgement {
	sidecarId, _ := directoryCardPathSidecar(file.Path)
	removerId := file.SignerSidecarId
	removed := &directoryAcceptedFile{file: file, seq: self.seqAt(file.Path)}
	if removerId == sidecarId {
		return directoryFileJudgement{verdict: directoryFileAccepted, taken: removed}
	}
	// judged at the removal's push pin; one past what the state retains, at the state now
	at := auth
	judged, err := auth.At(file.AuthPin)
	switch {
	case err == nil:
		at = judged
	case errors.Is(err, ErrDirectoryAuthAhead), errors.Is(err, ErrDirectoryAuthUnavailable):
		return directoryFileJudgement{verdict: directoryFilePending}
	case !errors.Is(err, ErrDirectoryAuthNotRetained):
		// a pin off the reader's chain
		return directoryFileRefusal(SidecarRecordAlarmPathRule)
	}
	switch standing, _ := at.SignerStanding(sidecarId, at.Pin()); standing {
	case DirectoryStandingRevoked, DirectoryStandingExpired:
		return directoryFileJudgement{verdict: directoryFileAccepted, taken: removed}
	}
	if auth.Masked(sidecarId) {
		return directoryFileJudgement{verdict: directoryFileAccepted, taken: removed}
	}
	admins, err := at.DirectoryAdmins(at.Pin())
	if err == nil && slices.Contains(admins, removerId) {
		judgement := directoryFileJudgement{verdict: directoryFileAccepted, taken: removed}
		ownMember, ownOk := auth.MemberOf(self.client.sidecarId)
		cardMember, cardOk := DirectoryWhoMember(auth, sidecarId)
		if ownOk && cardOk && ownMember == cardMember {
			// the moderated sidecar's member's devices hear of it
			judgement.alarm = SidecarRecordAlarmModeration
			judgement.alarmSidecarId = &sidecarId
		}
		return judgement
	}
	return directoryFileRefusal(SidecarRecordAlarmPathRule)
}

// The cards ref's file at path as this copy holds it: its version, 0 where the path holds none or a removal, which is
// what a path CAS write from it names.
func (self *DirectoryClient) cardPathVersion(path string) uint64 {
	if file := self.cardPathFile(path); file != nil && !file.Removed {
		return file.Version
	}
	return 0
}

// The newest version this copy holds at path, a removal among them; nil where it holds none.
func (self *DirectoryClient) cardPathFile(path string) *DirectoryCardFile {
	for _, file := range self.store.Cards() {
		if file.Path == path {
			return file
		}
	}
	return nil
}

// The push version of newest, the newest version a copy holds at sidecarId's card path, where it is a removal another
// signer pushed, whatever the path rules made of it: see the file's header's version row. 0 for the sidecar's own
// removal, a file, or nothing there.
func directoryCardForeignRemoval(newest *DirectoryCardFile, sidecarId Id) uint64 {
	if newest == nil || !newest.Removed || newest.SignerSidecarId == sidecarId {
		return 0
	}
	return newest.PushVersion
}

// The path version a card put names, the newest this device knows at its path: 0 over a removal by another signer no
// card of its stands over yet (over), whose return the put is; the copy's newest where it holds one past this device's
// last put, 0 for a removal; else the version this device put last, though its copy has not read it back. Never 0
// merely because the copy holds nothing or an older removal: a create-only put passes over any removal (EvsPathWrite's
// IfVersion), so a removal that came after this device's last put would go unread and its return unmade.
func directoryCardIfVersion(newest *DirectoryCardFile, written *directoryCardWrittenDocument, over bool) uint64 {
	switch {
	case over:
		return 0
	case newest != nil && written.PathVersion < newest.Version && newest.Removed:
		return 0
	case newest != nil && written.PathVersion < newest.Version:
		return newest.Version
	}
	return written.PathVersion
}

// What WriteCard puts.
type DirectoryCardWriteArgs struct {
	// This sidecar's items as they stand: its worker item, if it announces one, and its runs, each at its writer's
	// version, which a content change raises, and renewed as the caller renewed it. The card carries each at that
	// version plus this device's raise (the file's header's version row). Those that show no more are left off the
	// card.
	Items []*protocol.Announcement
}

// What a card write put.
type DirectoryCardWritten struct {
	Path        string
	Seq         uint64
	PathVersion uint64
	// The items the card holds, worker first, at the versions it carries them at: their writers' plus the raise.
	Items []*protocol.Announcement
	// The Signed's bytes, and the size the binding stores them at, a whole number of steps.
	ByteCount       int
	StoredByteCount int
}

// The card this device last put, and the seq and the raise it journaled before its newest put (the file's header's
// version row).
type directoryCardWrittenDocument struct {
	Version     int    `json:"version"`
	Seq         uint64 `json:"seq"`
	Content     []byte `json:"content,omitempty"`
	PathVersion uint64 `json:"path_version,omitempty"`
	// What every item's version on a card stands above its writer's, the sum of every return's rise; it never falls.
	Raise uint64 `json:"raise,omitempty"`
	// Raise as it stood when Content was put, so an item read back from Content returns to its writer's version.
	ContentRaise uint64 `json:"content_raise,omitempty"`
	// The push version of the newest removal of the path by another signer that Raise has risen for, journaled with
	// it, so a put that fails, or a kill after the journal, raises it no further for that removal.
	RaisedFor uint64 `json:"raised_for,omitempty"`
	// The push version of the newest removal of the path by another signer that a card of this device was put over,
	// kept after the put: until then the put names the removal, and after it the version it put (cardIfVersion).
	PutOver uint64 `json:"put_over,omitempty"`
}

// The card this document keeps as put last, nil before the first put or where its content does not parse as sidecarId's
// card. The bytes this device signed and put, so read as they are.
func (self *directoryCardWrittenDocument) card(sidecarId Id) *protocol.DirectoryCard {
	if len(self.Content) == 0 {
		return nil
	}
	signed := &bridge.Signed{}
	card := &protocol.DirectoryCard{}
	if proto.Unmarshal(self.Content, signed) != nil || proto.Unmarshal(signed.GetBody(), card) != nil ||
		!bytes.Equal(card.GetSidecarId(), sidecarId[:]) {
		return nil
	}
	return card
}

// items, read from a card put at raise, at their writers' versions: each version less raise, and at least 1.
func directoryCardHandedItems(items []*protocol.Announcement, raise uint64) []*protocol.Announcement {
	handed := make([]*protocol.Announcement, 0, len(items))
	for _, item := range items {
		item = proto.Clone(item).(*protocol.Announcement)
		item.Version = max(item.GetVersion(), raise+1) - raise
		handed = append(handed, item)
	}
	return handed
}

// The items of the card this device put last, each at its writer's version, for a writer that hands them to WriteCard
// again; none before its first put.
func (self *DirectoryClient) cardWrittenItems() ([]*protocol.Announcement, error) {
	written, err := self.readCardWritten()
	if err != nil {
		return nil, err
	}
	return directoryCardHandedItems(written.card(self.sidecarId).GetItems(), written.ContentRaise), nil
}

// How far a return raises the line under items, at their writers' versions, as written stands before it. The removal's
// push tombstoned each active item of the card it took one above that card's version of it (directoryIndexCardChange),
// and a tombstone wins a tie (searchVersionSupersedes), so an item carried unchanged comes back two above: the least
// rise, which also covers a card put whose document was not kept before a kill, since a writer's versions only rise.
// More where an item stands below the version the card put last held it at.
func directoryCardReturnRaise(items []*protocol.Announcement, written *directoryCardWrittenDocument, sidecarId Id) uint64 {
	// the removal's tombstone stands one above the version it took, and the item comes back one above the tombstone
	tombstone, above := uint64(1), uint64(1)
	rise := tombstone + above
	took := map[Id]uint64{}
	for _, item := range written.card(sidecarId).GetItems() {
		took[recordIdOf(item.GetAnnouncementId())] = item.GetVersion()
	}
	for _, item := range items {
		version, ok := took[recordIdOf(item.GetAnnouncementId())]
		if carried := item.GetVersion() + written.Raise; ok && carried+rise < version+tombstone+above {
			rise = version + tombstone + above - carried
		}
	}
	return rise
}

// items at their writers' versions as a card carries them: each raised by raise.
func directoryCardCarried(items []*protocol.Announcement, raise uint64) []*protocol.Announcement {
	carried := make([]*protocol.Announcement, 0, len(items))
	for _, item := range items {
		item = proto.Clone(item).(*protocol.Announcement)
		item.Version += raise
		carried = append(carried, item)
	}
	return carried
}

// The client's card writer.
type directoryCardWriter struct {
	// one card write at a time
	writeLock sync.Mutex
}

// The client's card writer part.
func (self *DirectoryClient) cardWriter() *directoryCardWriter {
	return self.part(directoryCardWriterPart, func() any { return &directoryCardWriter{} }).(*directoryCardWriter)
}

// The card document this device keeps, empty before its first put.
func (self *DirectoryClient) readCardWritten() (*directoryCardWrittenDocument, error) {
	content, err := self.store.readFile(directoryCardWrittenName)
	if err != nil {
		return nil, err
	}
	document := &directoryCardWrittenDocument{Version: directoryCardWrittenKept}
	if content == nil {
		return document, nil
	}
	if err := json.Unmarshal(content, document); err != nil || document.Version != directoryCardWrittenKept {
		return nil, fmt.Errorf("%w: the card written", ErrDirectoryStoreCorrupt)
	}
	return document, nil
}

// The items a card holds from items at nowMillis: those that still show, checked as this sidecar's, the worker item
// first and the runs by start then id; ErrDirectoryCardOverCap past a cap.
func (self *DirectoryClient) cardItems(items []*protocol.Announcement, settings *DirectoryCardSettings, nowMillis int64) ([]*protocol.Announcement, error) {
	held := []*protocol.Announcement{}
	for _, item := range items {
		if item == nil || !settings.shows(item, nowMillis) {
			continue
		}
		if err := DirectoryCheckItem(item); err != nil {
			return nil, err
		}
		switch DirectoryAnnouncementKind(item.GetKind()) {
		case DirectoryAnnouncementKindRun, DirectoryAnnouncementKindWorker:
		default:
			return nil, fmt.Errorf("%w: a card holds runs and a worker item, not kind %d", ErrDirectoryFormatInvalid, item.GetKind())
		}
		if !bytes.Equal(item.GetWho().GetSidecarId(), self.sidecarId[:]) {
			return nil, fmt.Errorf("%w: a card holds its own sidecar's items", ErrDirectoryFormatInvalid)
		}
		held = append(held, proto.Clone(item).(*protocol.Announcement))
	}
	slices.SortStableFunc(held, func(a *protocol.Announcement, b *protocol.Announcement) int {
		worker := func(item *protocol.Announcement) int {
			if DirectoryAnnouncementKind(item.GetKind()) == DirectoryAnnouncementKindWorker {
				return 0
			}
			return 1
		}
		return cmp.Or(
			cmp.Compare(worker(a), worker(b)),
			cmp.Compare(a.GetStartedMillis(), b.GetStartedMillis()),
			bytes.Compare(a.GetAnnouncementId(), b.GetAnnouncementId()),
		)
	})
	if err := settings.checkWrittenItems(held); err != nil {
		return nil, err
	}
	return held, nil
}

// ErrDirectoryCardOverCap where a writer's items pass a card's caps: more than ItemCount, more than WorkerItemCount
// worker items, or past ItemsByteCount.
func (self *DirectoryCardSettings) checkWrittenItems(items []*protocol.Announcement) error {
	workerCount := 0
	for _, item := range items {
		if DirectoryAnnouncementKind(item.GetKind()) == DirectoryAnnouncementKindWorker {
			workerCount += 1
		}
	}
	switch byteCount := directoryCardItemsByteCount(items); {
	case self.ItemCount < len(items):
		return fmt.Errorf("%w: %d items, past %d", ErrDirectoryCardOverCap, len(items), self.ItemCount)
	case self.WorkerItemCount < workerCount:
		return fmt.Errorf("%w: %d worker items", ErrDirectoryCardOverCap, workerCount)
	case self.ItemsByteCount < byteCount:
		return fmt.Errorf("%w: items of %d bytes, past %d", ErrDirectoryCardOverCap, byteCount, self.ItemsByteCount)
	}
	return nil
}

// Puts this sidecar's card with args' items: see the file's header's write row. A read_only client, one with no
// signer or network bound, and one whose sidecar does not stand to write in the directory now refuse, signing nothing.
func (self *DirectoryClient) WriteCard(ctx context.Context, args *DirectoryCardWriteArgs) (*DirectoryCardWritten, error) {
	if args == nil {
		args = &DirectoryCardWriteArgs{}
	}
	if self.readOnly {
		return nil, ErrDirectoryReadOnly
	}
	if self.sign == nil || self.networkId == (Id{}) {
		return nil, ErrDirectoryCardUnbound
	}
	if _, ok := self.DirectoryId(); !ok {
		return nil, ErrDirectoryNone
	}
	settings := self.cardSettings()
	items, err := self.cardItems(args.Items, settings, self.clock.Now().UnixMilli())
	if err != nil {
		return nil, err
	}
	writer := self.cardWriter()
	writer.writeLock.Lock()
	defer writer.writeLock.Unlock()
	return self.putCard(ctx, items, settings)
}

// Signs and puts a card of items, at their writers' versions, at a seq above every one written or accepted and on this
// device's raise, a return raising it first (the file's header's version row), journaling the seq and the raise first;
// a path conflict syncs once and puts again. The caller holds the card writer's writeLock.
func (self *DirectoryClient) putCard(ctx context.Context, items []*protocol.Announcement, settings *DirectoryCardSettings) (*DirectoryCardWritten, error) {
	path := DirectoryCardPath(self.sidecarId)
	written, err := self.readCardWritten()
	if err != nil {
		return nil, err
	}
	hookKey := recordChainIdText(self.sidecarId)
	for attempt := 0; ; attempt += 1 {
		seq := max(written.Seq, self.files().seqAt(path)) + 1
		written.Seq = seq
		pathFile := self.cardPathFile(path)
		// a removal of the path by another signer that no card of this device stands over yet
		removal := directoryCardForeignRemoval(pathFile, self.sidecarId)
		over := written.PutOver < removal
		if over && written.RaisedFor < removal {
			// the first card since another signer removed the path: every item comes back above the removal's tombstones
			written.Raise += directoryCardReturnRaise(items, written, self.sidecarId)
			written.RaisedFor = removal
		}
		carried := directoryCardCarried(items, written.Raise)
		if err := settings.checkWrittenItems(carried); err != nil {
			return nil, err
		}
		// the seq and the raise are kept before anything carries them, so a kill after the put never puts the seq again,
		// and every card after a return carries its raise
		if err := self.store.writeDocument(directoryCardWrittenName, written); err != nil {
			return nil, err
		}
		auth := self.auth()
		pin := auth.Pin()
		if !directoryPinValid(pin) {
			return nil, ErrDirectoryAuthUnavailable
		}
		standing, err := auth.SignerStanding(self.sidecarId, pin)
		if err != nil {
			return nil, err
		}
		if standing != DirectoryStandingStanding {
			return nil, fmt.Errorf("%w: %s", ErrDirectoryCardStanding, standing)
		}
		card := &protocol.DirectoryCard{
			NetworkId:     self.networkId.Bytes(),
			SidecarId:     self.sidecarId.Bytes(),
			Seq:           seq,
			At:            &bridge.AuthPin{Version: pin.GetVersion(), Chain: bytes.Clone(pin.GetChain())},
			WrittenMillis: self.clock.Now().UnixMilli(),
			Items:         carried,
			Version:       directoryCardFormatVersion,
		}
		if err := DirectoryCheckCard(card, settings); err != nil {
			return nil, err
		}
		body, err := proto.MarshalOptions{Deterministic: true}.Marshal(card)
		if err != nil {
			return nil, err
		}
		signed, err := self.sign(DirectorySignedPurpose, bridge.SignedType_SIGNED_DIRECTORY_CARD, body, nil)
		if err != nil {
			return nil, fmt.Errorf("directory card: sign: %w", err)
		}
		content, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
		if err != nil {
			return nil, err
		}
		if settings.CardFileByteCount < len(content) {
			return nil, fmt.Errorf("%w: a card of %d bytes", ErrDirectoryCardOverCap, len(content))
		}
		ifVersion := directoryCardIfVersion(pathFile, written, over)
		testHookBarrier("directory.card.before", hookKey)
		pathVersion, err := self.PutCard(ctx, &DirectoryCardWrite{
			PushId: NewId(), Path: path, IfVersion: ifVersion, Content: content, AuthPin: card.GetAt(),
		})
		testHookBarrier("directory.card.after", hookKey)
		if err != nil && directoryPathConflict(err) && attempt == 0 {
			// another version landed since the copy read the path: read it and put again from there
			if err := self.Sync(ctx); err != nil {
				return nil, err
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		written.Content = content
		written.PathVersion = pathVersion
		written.ContentRaise = written.Raise
		if over {
			written.PutOver = removal
		}
		if err := self.store.writeDocument(directoryCardWrittenName, written); err != nil {
			return nil, err
		}
		return &DirectoryCardWritten{
			Path: path, Seq: seq, PathVersion: pathVersion, Items: carried, ByteCount: len(content),
			StoredByteCount: settings.StoredByteCount(len(content)),
		}, nil
	}
}

// The versions every accepted card and repo file holds, for the fold, judging what is new first; set for every leg
// that links this file.
func init() {
	directoryFoldFiles = func(client *DirectoryClient, fold *DirectoryFold) []*directoryVersion {
		// whatever a sync judges, the loop's next pass repairs (directory_repair.go)
		client.repairs()
		return client.filesOf(fold).judge(fold)
	}
}
