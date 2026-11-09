// The posture's transitions: what each call verifies, in what order, and how it commits (posture.go's machine,
// posture_store.go's records, posture_verify.go's checks).
//
// A call works on a copy of what is held, verifies entries onto it in log order, writes its new records under a
// generation no committed manifest names, then the manifest, and only then publishes. So a call that fails, or a kill
// at any step, leaves the posture and its store as they were, and nothing is in force that a restart would not
// restore. A restart verifies what it restores: the base by §7.9's keyless rule under a config writer in its own rows,
// the rows by their hash, the entries since by their chain to the pin, the state's pin on that chain and its
// has_document against the rows, before any packet.
//
// Called only with the posture's operationLock held, which is what every *WithLock and postureOperation method
// assumes.

package device

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The base a posture's rows and pin rest on, with what memory keeps of its rows: has_document, the AdminSet's members
// and the config writers' keys.
type postureBase struct {
	entryBytes       []byte
	entry            *bridge.AuthEntry
	header           *bridge.ProjectionHeader
	chain            [postureDigestByteCount]byte
	rowsRecord       string
	rowsSha256       [postureDigestByteCount]byte
	hasDocument      bool
	adminMemberRoles map[[postureIdByteCount]byte]bridge.MemberRole
	writers          map[[postureIdByteCount]byte]*postureSidecarRow
}

// What a posture holds once its store holds anything. Each call that changes it builds a new one: nothing here is
// changed in place once published.
type postureHeld struct {
	stored            uint64
	generation        uint64
	networkId         []byte
	anchor            []byte
	sidecarId         []byte
	identityPublicKey []byte
	documentSeenAt    uint64
	shareCerts        []postureShareCert

	// enforcing only
	pinN          uint64
	pinChain      [postureDigestByteCount]byte
	base          *postureBase
	entriesRecord string
	entriesSha256 []byte
	entriesCount  uint64
	stateRecord   string
	stateSha256   []byte
	bridgeState   *bridge.BridgeState
	overlay       []PostureOverlayEntry
}

// A copy whose slices may be replaced, never written into.
func (self *postureHeld) clone() *postureHeld {
	held := *self
	held.shareCerts = slices.Clone(self.shareCerts)
	held.overlay = slices.Clone(self.overlay)
	return &held
}

// §17.8's state. Enforcing is doc unless the base's rows say has_document = false and the base sits above the latch.
func (self *postureHeld) postureState() PostureState {
	if self == nil {
		return PostureLegacy
	}
	switch self.stored {
	case postureStoredLegacy:
		return PostureLegacy
	case postureStoredEnforcing:
		if self.base.hasDocument || self.base.entry.GetN() <= self.documentSeenAt {
			return PostureEnforcingDocument
		}
		return PostureEnforcingNoDocument
	default:
		return PosturePending
	}
}

// The state's pin, 0 before a state.
func (self *postureHeld) statePinN() uint64 {
	if self.bridgeState == nil {
		return 0
	}
	return self.bridgeState.GetAuth().GetVersion()
}

// What is in force, without this call's alarms.
func (self *postureHeld) decision() PostureDecision {
	decision := PostureDecision{State: self.postureState()}
	if decision.State.Enforcing() {
		decision.BridgeState = self.bridgeState
		decision.Overlay = slices.Clone(self.overlay)
		decision.Pin = &bridge.AuthPin{Version: self.pinN, Chain: bytes.Clone(self.pinChain[:])}
	}
	return decision
}

// The manifest that records it.
func (self *postureHeld) manifest() *postureManifest {
	manifest := &postureManifest{
		generation:        self.generation,
		stored:            self.stored,
		networkId:         self.networkId,
		anchor:            self.anchor,
		sidecarId:         self.sidecarId,
		identityPublicKey: self.identityPublicKey,
		documentSeenAt:    self.documentSeenAt,
		shareCerts:        self.shareCerts,
	}
	if self.stored == postureStoredEnforcing {
		manifest.pinN = self.pinN
		manifest.pinChain = self.pinChain[:]
		manifest.baseEntry = self.base.entryBytes
		manifest.rowsRecord = self.base.rowsRecord
		manifest.rowsSha256 = self.base.rowsSha256[:]
		manifest.entriesRecord = self.entriesRecord
		manifest.entriesSha256 = self.entriesSha256
		manifest.entriesCount = self.entriesCount
		manifest.stateRecord = self.stateRecord
		manifest.stateSha256 = self.stateSha256
		manifest.overlay = self.overlay
	}
	return manifest
}

// The records a committed manifest names, its own name included.
func (self *postureHeld) recordNames() map[string]bool {
	names := map[string]bool{postureManifestName: true}
	if self.stored == postureStoredEnforcing {
		for _, name := range []string{self.base.rowsRecord, self.entriesRecord, self.stateRecord} {
			if name != "" {
				names[name] = true
			}
		}
	}
	return names
}

// Replaces what is held and in force, and returns the decision with alarms, under stateLock.
func (self *Posture) publishWithLock(held *postureHeld, alarms []PostureAlarm, changed bool) PostureDecision {
	self.held = held
	decision := PostureDecision{State: PostureLegacy}
	if held != nil {
		decision = held.decision()
	}
	decision.Alarms = alarms
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !changed {
		changed = decision.State != self.decision.State || decision.BridgeState != self.decision.BridgeState ||
			!slices.EqualFunc(decision.Overlay, self.decision.Overlay, postureOverlayEntryEqual)
	}
	decision.Changed = changed
	self.decision = decision
	return decision
}

// Whether two overlay entries say the same.
func postureOverlayEntryEqual(a PostureOverlayEntry, b PostureOverlayEntry) bool {
	return a.Kind == b.Kind && a.N == b.N && bytes.Equal(a.Id, b.Id) && bytes.Equal(a.SuspendId, b.SuspendId) &&
		a.WithdrawMode == b.WithdrawMode && a.Covered == b.Covered && a.suspendClass == b.suspendClass
}

// The decision with nothing changed and these alarms, and the error to return with it.
func (self *Posture) refuseWithLock(alarms []PostureAlarm, err error) (PostureDecision, error) {
	decision := self.publishWithLock(self.held, alarms, false)
	return decision, err
}

// An alarm and its error, for a refusal.
func postureAlarmOf(kind PostureAlarmKind, n uint64, err error) PostureAlarm {
	return PostureAlarm{Kind: kind, N: n, Reason: err.Error()}
}

// Reads the whole record, at most maxByteCount bytes, with its SHA-256.
func (self *Posture) readRecord(name string, maxByteCount int) ([]byte, [postureDigestByteCount]byte, error) {
	reader, err := self.store.Open(name)
	if err != nil {
		return nil, [postureDigestByteCount]byte{}, err
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, int64(maxByteCount)+1))
	if err != nil {
		return nil, [postureDigestByteCount]byte{}, postureStoreFault(err)
	}
	if maxByteCount < len(content) {
		return nil, [postureDigestByteCount]byte{}, fmt.Errorf("%w: a record over its bound", ErrPostureStoreFailed)
	}
	return content, sha256.Sum256(content), nil
}

// What a held state is when the store does not verify: pending, keeping what the manifest says of the anchor, the ids,
// the latch and the share certificates, so a next state can restore enforcement and never a lower one.
func postureHeldUnverified(manifest *postureManifest) *postureHeld {
	held := &postureHeld{stored: postureStoredPending}
	if manifest != nil {
		held.generation = manifest.generation
		if len(manifest.networkId) == postureIdByteCount && len(manifest.anchor) == postureDigestByteCount {
			held.networkId = manifest.networkId
			held.anchor = manifest.anchor
			if len(manifest.sidecarId) == postureIdByteCount && len(manifest.identityPublicKey) == ed25519.PublicKeySize {
				held.sidecarId = manifest.sidecarId
				held.identityPublicKey = manifest.identityPublicKey
			}
		}
		held.documentSeenAt = manifest.documentSeenAt
		held.shareCerts = manifest.shareCerts
	}
	return held
}

// Restores from the store (NewPosture). Nothing stored is legacy; anything stored that cannot be read or does not
// verify is pending with an alarm, never legacy.
func (self *Posture) load() (*postureHeld, []PostureAlarm) {
	unreadable := func(err error) (*postureHeld, []PostureAlarm) {
		return postureHeldUnverified(nil), []PostureAlarm{postureAlarmOf(PostureAlarmStoreUnreadable, 0, err)}
	}
	if self.store == nil {
		return unreadable(fmt.Errorf("%w: no store", ErrPostureStoreFailed))
	}
	names, err := self.store.List()
	if err != nil {
		return unreadable(err)
	}
	manifestBytes, _, err := self.readRecord(postureManifestName, self.settings.ManifestMaxByteCount)
	if errors.Is(err, ErrPostureStoreAbsent) {
		if len(names) == 0 {
			return nil, nil
		}
		// a commit writes the manifest first and removes last, so records with no manifest were never a posture's
		// own: read them as a store that does not verify
		held := postureHeldUnverified(nil)
		return held, []PostureAlarm{{Kind: PostureAlarmStoreUnverified, Reason: "records with no manifest"}}
	}
	if err != nil {
		return unreadable(err)
	}
	manifest, err := decodePostureManifest(manifestBytes)
	if err != nil {
		return unreadable(err)
	}
	var held *postureHeld
	switch manifest.stored {
	case postureStoredLegacy:
		held = &postureHeld{stored: postureStoredLegacy, generation: manifest.generation}
	case postureStoredPending:
		held = postureHeldUnverified(manifest)
		if held.networkId == nil {
			return held, []PostureAlarm{{Kind: PostureAlarmStoreUnverified, Reason: "a pending manifest with no anchor"}}
		}
	case postureStoredEnforcing:
		held, err = self.verifyStored(manifest)
		if err != nil {
			return postureHeldUnverified(manifest), []PostureAlarm{postureAlarmOf(PostureAlarmStoreUnverified, manifest.pinN, err)}
		}
	default:
		return unreadable(fmt.Errorf("%w: manifest state %d", ErrPostureStoreFailed, manifest.stored))
	}
	self.removeGarbage(held, names)
	return held, nil
}

// Removes each listed record held does not name: what a commit superseded, or a killed call left. Best effort, since
// a record left over is only space, and the next commit tries again.
func (self *Posture) removeGarbage(held *postureHeld, names []string) {
	keep := held.recordNames()
	for _, name := range names {
		if !keep[name] {
			self.store.Remove(name)
		}
	}
}

// Verifies an enforcing manifest's records offline (the file's comment) and returns what they hold.
func (self *Posture) verifyStored(manifest *postureManifest) (*postureHeld, error) {
	failed := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrPostureRefused, fmt.Sprintf(format, a...))
	}
	if len(manifest.networkId) != postureIdByteCount || len(manifest.anchor) != postureDigestByteCount ||
		len(manifest.pinChain) != postureDigestByteCount || len(manifest.rowsSha256) != postureDigestByteCount ||
		manifest.rowsRecord == "" || manifest.stateRecord == "" || len(manifest.stateSha256) != postureDigestByteCount {
		return nil, failed("an enforcing manifest missing a field")
	}
	held := postureHeldUnverified(manifest)
	if held.networkId == nil {
		return nil, failed("an enforcing manifest with no anchor")
	}
	held.stored = postureStoredEnforcing

	parsed, err := parsePostureEntry(manifest.baseEntry, manifest.networkId, self.settings.EntryMaxByteCount)
	if err != nil {
		return nil, err
	}
	if parsed.entry.GetKind() != bridge.AuthEntryKindBase {
		return nil, failed("a base of kind %d", parsed.entry.GetKind())
	}
	base, err := self.readBase(parsed, manifest.rowsRecord, nil, manifest.anchor)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(base.rowsSha256[:], manifest.rowsSha256) {
		return nil, failed("rows other than the manifest names")
	}
	held.base = base

	stateBytes, stateSha256, err := self.readRecord(manifest.stateRecord, self.settings.StateMaxByteCount)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(stateSha256[:], manifest.stateSha256) {
		return nil, failed("a state other than the manifest names")
	}
	state := &bridge.BridgeState{}
	if err := proto.Unmarshal(stateBytes, state); err != nil {
		return nil, failed("a state that does not decode")
	}
	if !bytes.Equal(state.GetGenesisSha256(), manifest.anchor) || len(state.GetAuth().GetChain()) != postureDigestByteCount {
		return nil, failed("a state for another anchor")
	}
	held.bridgeState = state
	held.stateRecord = manifest.stateRecord
	held.stateSha256 = manifest.stateSha256
	statePinN := state.GetAuth().GetVersion()

	// the entries since the base, each chained onto the one before, the state's pin on that chain
	held.pinN, held.pinChain = base.entry.GetN(), base.chain
	statePinChecked := statePinN < base.entry.GetN()
	checkStatePin := func() {
		if held.pinN == statePinN {
			statePinChecked = bytes.Equal(held.pinChain[:], state.GetAuth().GetChain())
		}
	}
	checkStatePin()
	if manifest.entriesCount == 0 {
		if manifest.entriesRecord != "" || len(manifest.entriesSha256) != 0 {
			return nil, failed("an entries record with no entries")
		}
	} else {
		if manifest.entriesRecord == "" || len(manifest.entriesSha256) != postureDigestByteCount ||
			uint64(self.settings.EntriesMaxCount) < manifest.entriesCount {
			return nil, failed("entries the manifest does not bound")
		}
		count := uint64(0)
		entriesSha256, err := self.readEntries(manifest.entriesRecord, func(entryBytes []byte) error {
			parsed, err := parsePostureEntry(entryBytes, manifest.networkId, self.settings.EntryMaxByteCount)
			if err != nil {
				return err
			}
			if parsed.entry.GetN() != held.pinN+1 || !bytes.Equal(parsed.entry.GetPrevChain(), held.pinChain[:]) {
				return failed("entries that do not chain from the base")
			}
			if parsed.entry.GetKind() == bridge.AuthEntryKindBase {
				return failed("a second base among the entries since the base")
			}
			count += 1
			held.pinN, held.pinChain = parsed.entry.GetN(), parsed.chain
			checkStatePin()
			return nil
		})
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(entriesSha256[:], manifest.entriesSha256) || count != manifest.entriesCount {
			return nil, failed("entries other than the manifest names")
		}
		held.entriesRecord = manifest.entriesRecord
		held.entriesSha256 = manifest.entriesSha256
		held.entriesCount = count
	}
	if held.pinN != manifest.pinN || !bytes.Equal(held.pinChain[:], manifest.pinChain) {
		return nil, failed("entries that end off the pin")
	}
	if !statePinChecked || held.pinN < statePinN {
		return nil, failed("a state whose pin is off the verified chain")
	}
	if base.entry.GetN() <= statePinN && state.GetHasDocument() != base.hasDocument {
		return nil, failed("a state whose has_document is not its rows'")
	}
	// an entry past the pin is one a resync below it kept, which stands until a state passes it
	for _, entry := range manifest.overlay {
		if entry.N <= statePinN {
			return nil, failed("an overlay entry at or before the state's pin")
		}
	}
	if uint64(self.settings.OverlayMaxCount) < uint64(len(manifest.overlay)) {
		return nil, failed("an overlay past its bound")
	}
	held.overlay = manifest.overlay
	return held, nil
}

// Streams an entries record, calling visit with each entry, and returns the record's SHA-256.
func (self *Posture) readEntries(name string, visit func(entryBytes []byte) error) ([postureDigestByteCount]byte, error) {
	reader, err := self.store.Open(name)
	if err != nil {
		return [postureDigestByteCount]byte{}, err
	}
	defer reader.Close()
	hash := sha256.New()
	buffered := bufio.NewReaderSize(io.TeeReader(reader, hash), self.settings.ReadByteCount)
	entryBuffer := []byte{}
	for {
		length, err := binary.ReadUvarint(buffered)
		if err == io.EOF {
			break
		}
		if err != nil {
			return [postureDigestByteCount]byte{}, postureStreamError(err, fmt.Errorf("%w: an entries record that does not decode", ErrPostureStoreFailed))
		}
		if uint64(self.settings.EntryMaxByteCount) < length {
			return [postureDigestByteCount]byte{}, fmt.Errorf("%w: a stored entry over its bound", ErrPostureStoreFailed)
		}
		if uint64(cap(entryBuffer)) < length {
			entryBuffer = make([]byte, length)
		}
		entryBytes := entryBuffer[:length]
		if _, err := io.ReadFull(buffered, entryBytes); err != nil {
			return [postureDigestByteCount]byte{}, fmt.Errorf("%w: an entries record that ends inside an entry", ErrPostureStoreFailed)
		}
		if err := visit(entryBytes); err != nil {
			return [postureDigestByteCount]byte{}, err
		}
	}
	return [postureDigestByteCount]byte(hash.Sum(nil)), nil
}

// Reads a stored base's rows twice, hashing, then for the config writers, and checks the base under its signer. With
// previous nil, the first base a posture takes or restores, its signer must be a config writer in its own rows, as a
// new device's start reads it (§7.9's retention row); otherwise previous's writers judge it, a writer at S(n-1).
// anchor is A_0, which base 1's prev_chain must be.
func (self *Posture) readBase(parsed *postureEntry, rowsRecord string, previous *postureBase, anchor []byte) (*postureBase, error) {
	_, header, signerId, err := parsePostureBase(parsed.entry)
	if err != nil {
		return nil, err
	}
	if parsed.entry.GetN() == 1 && !bytes.Equal(parsed.entry.GetPrevChain(), anchor) {
		return nil, fmt.Errorf("%w: base 1 does not chain from the anchor", ErrPostureRefused)
	}
	openRows := func() (*postureRowsScan, error) {
		reader, err := self.store.Open(rowsRecord)
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return scanPostureRows(reader, self.settings, nil)
	}
	scan, err := openRows()
	if err != nil {
		return nil, err
	}
	reader, err := self.store.Open(rowsRecord)
	if err != nil {
		return nil, err
	}
	writers, err := readPostureWriters(reader, self.settings, scan.sha256, scan.adminMemberRoles)
	reader.Close()
	if err != nil {
		return nil, err
	}
	judges := writers
	var previousHeader *bridge.ProjectionHeader
	if previous != nil {
		judges = previous.writers
		previousHeader = previous.header
	}
	writer := judges[signerId]
	if writer == nil || !writer.standingAt(parsed.entry.GetTimeMs()) {
		return nil, fmt.Errorf("%w: a base by no config writer", ErrPostureRefused)
	}
	if _, err := bridge.VerifyBaseKeylessDigest(parsed.entry, writer.identityPublicKey, scan.sha256[:], scan.byteCount, previousHeader); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPostureRefused, err)
	}
	return &postureBase{
		entryBytes:       bytes.Clone(parsed.bytes),
		entry:            parsed.entry,
		header:           header,
		chain:            parsed.chain,
		rowsRecord:       rowsRecord,
		rowsSha256:       scan.sha256,
		hasDocument:      scan.hasDocument,
		adminMemberRoles: scan.adminMemberRoles,
		writers:          writers,
	}, nil
}

// One call's work: what it started from, what it has verified onto a copy, and what it has written.
type postureOperation struct {
	posture *Posture
	from    *postureHeld
	next    *postureHeld
	// the generation this call's records go under
	generation uint64
	// entries after next's base verified by this call, to follow the stored ones, or alone once rebased
	newEntries [][]byte
	rebased    bool
	// the state's bytes to write, nil when unchanged
	stateBytes []byte
	// records this call wrote that the next manifest may not name
	written []string
	// a manifest write was tried, after which its records may be named and are left for the next commit
	manifestTried bool
	alarms        []PostureAlarm
	wiped         bool
	// sidecar rows found in next's base's rows in this call, and every id looked for
	rowsFound map[[postureIdByteCount]byte]*postureSidecarRow
	lookedUp  map[[postureIdByteCount]byte]bool
}

// An operation on a copy of what is held.
func (self *Posture) newOperation() *postureOperation {
	operation := &postureOperation{
		posture:   self,
		from:      self.held,
		rowsFound: map[[postureIdByteCount]byte]*postureSidecarRow{},
		lookedUp:  map[[postureIdByteCount]byte]bool{},
	}
	if self.held != nil {
		operation.next = self.held.clone()
		operation.generation = self.held.generation + 1
	} else {
		operation.next = &postureHeld{stored: postureStoredLegacy}
		operation.generation = 1
	}
	return operation
}

// Records an alarm.
func (self *postureOperation) alarm(kind PostureAlarmKind, n uint64, err error) {
	self.alarms = append(self.alarms, postureAlarmOf(kind, n, err))
}

// Streams a base's rows from openRows into a new record, hashing and reading has_document as they pass, then checks
// the base against them: from previous's config writers, or with previous nil its own. Nothing of the rows stays in
// memory but has_document and the writers' keys.
func (self *postureOperation) takeBase(parsed *postureEntry, openRows func(rowsSha256 []byte) (io.ReadCloser, error), previous *postureBase) (*postureBase, error) {
	signed, header, signerId, err := parsePostureBase(parsed.entry)
	if err != nil {
		return nil, err
	}
	if previous != nil {
		// fail before 4 MiB stream when the signer is no writer at S(n-1) or its signature does not verify
		writer := previous.writers[signerId]
		if writer == nil || !writer.standingAt(parsed.entry.GetTimeMs()) || postureOverlayRevokes(self.next.overlay, writer) {
			return nil, fmt.Errorf("%w: a base by no config writer", ErrPostureRefused)
		}
		if err := bridge.VerifySigned(signed, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_PROJECTION_HEADER,
			bridge.SignedKeyAlgEd25519, writer.identityPublicKey); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrPostureRefused, err)
		}
	}
	if openRows == nil {
		return nil, fmt.Errorf("%w: a base with no rows to read", ErrPostureRefused)
	}
	source, err := openRows(header.GetRowsSha256())
	if err != nil {
		return nil, fmt.Errorf("%w: its rows: %w", ErrPostureRefused, err)
	}
	defer source.Close()
	rowsRecord := fmt.Sprintf("rows-%d-%d", self.generation, parsed.entry.GetN())
	self.written = append(self.written, rowsRecord)
	err = self.posture.store.Write(rowsRecord, func(writer io.Writer) error {
		_, err := scanPostureRows(io.TeeReader(source, writer), self.posture.settings, nil)
		return err
	})
	if err != nil {
		return nil, err
	}
	base, err := self.posture.readBase(parsed, rowsRecord, previous, self.next.anchor)
	if err != nil {
		return nil, err
	}
	return base, nil
}

// How entries count: under a state, which vouches for its own entries, statements count by their chain alone;
// between states, the six this role applies are verified and change the overlay.
type postureMode int

const (
	postureModeState postureMode = iota
	postureModeDeltas
)

// Verifies entries onto next in order, each chained from next's pin, and returns how many it took and what stopped
// it. A statement that fails to verify is not applied and alarms, and the chain goes on past it, as at every reader
// (§7.9); an entry that does not chain or decode, or a base that does not verify, stops it there.
func (self *postureOperation) applyEntries(log *PostureLog, entries [][]byte, mode postureMode) (int, error) {
	next := self.next
	settings := self.posture.settings
	// the ids every statement here needs rows for, read in one pass of the rows when first needed
	batchIds := map[[postureIdByteCount]byte]bool{}
	if mode == postureModeDeltas {
		for _, entryBytes := range entries {
			entry := &bridge.AuthEntry{}
			if proto.Unmarshal(entryBytes, entry) != nil || entry.GetKind() != bridge.AuthEntryKindStatement {
				continue
			}
			if statement, err := parsePostureStatement(entry); err == nil && statement != nil {
				for _, id := range statement.rowIds() {
					batchIds[id] = true
				}
			}
		}
	}
	for index, entryBytes := range entries {
		parsed, err := parsePostureEntry(entryBytes, next.networkId, settings.EntryMaxByteCount)
		if err != nil {
			self.alarm(PostureAlarmMalformed, next.pinN+1, err)
			return index, err
		}
		entry := parsed.entry
		if entry.GetN() != next.pinN+1 || !bytes.Equal(entry.GetPrevChain(), next.pinChain[:]) {
			err := fmt.Errorf("%w: entry %d does not chain from the pin at %d", ErrPostureRefused, entry.GetN(), next.pinN)
			kind := PostureAlarmChainBreak
			if entry.GetN() <= next.pinN {
				kind = PostureAlarmLowerPin
			}
			self.alarm(kind, entry.GetN(), err)
			return index, err
		}
		if uint64(settings.EntriesMaxCount) <= self.entriesCount() && entry.GetKind() != bridge.AuthEntryKindBase {
			err := fmt.Errorf("%w: past the %d entries kept since a base", ErrPostureRefused, settings.EntriesMaxCount)
			self.alarm(PostureAlarmMalformed, entry.GetN(), err)
			return index, err
		}
		switch entry.GetKind() {
		case bridge.AuthEntryKindBase:
			base, err := self.takeBase(parsed, log.OpenRows, next.base)
			if err != nil {
				self.alarm(PostureAlarmBaseRefused, entry.GetN(), err)
				return index, err
			}
			next.base = base
			self.rebased = true
			self.newEntries = nil
			self.rowsFound = map[[postureIdByteCount]byte]*postureSidecarRow{}
			self.lookedUp = map[[postureIdByteCount]byte]bool{}
		case bridge.AuthEntryKindStatement:
			if mode == postureModeDeltas {
				if err := self.applyStatement(parsed, batchIds); err != nil {
					return index, err
				}
				if self.wiped {
					return index + 1, nil
				}
			}
			self.newEntries = append(self.newEntries, bytes.Clone(entryBytes))
		case bridge.AuthEntryKindTick:
			self.newEntries = append(self.newEntries, bytes.Clone(entryBytes))
		}
		next.pinN, next.pinChain = entry.GetN(), parsed.chain
		if next.base.hasDocument {
			next.documentSeenAt = entry.GetN()
		}
	}
	return len(entries), nil
}

// The entries since next's base, counting this call's.
func (self *postureOperation) entriesCount() uint64 {
	if self.rebased {
		return uint64(len(self.newEntries))
	}
	return self.next.entriesCount + uint64(len(self.newEntries))
}

// Verifies one statement entry between states and applies what it does: the sidecar's own sign-out wipes, the six
// statements this role applies change the overlay, and any other is followed by its chain alone. A statement that
// fails to verify alarms and is not applied; only a fault that stops the call is an error.
func (self *postureOperation) applyStatement(parsed *postureEntry, batchIds map[[postureIdByteCount]byte]bool) error {
	next := self.next
	entry := parsed.entry
	statement, err := parsePostureStatement(entry)
	if err != nil {
		self.alarm(PostureAlarmStatementRefused, entry.GetN(), err)
		return nil
	}
	if statement == nil {
		return nil
	}
	if statement.ownSignOut(next.networkId, next.sidecarId, next.identityPublicKey) {
		self.wiped = true
		return nil
	}
	need := statement.rowIds()
	missing := false
	for _, id := range need {
		if !self.lookedUp[id] {
			missing = true
		}
	}
	if missing {
		ids := map[[postureIdByteCount]byte]bool{}
		for id := range batchIds {
			if !self.lookedUp[id] {
				ids[id] = true
			}
		}
		for _, id := range need {
			ids[id] = true
		}
		reader, err := self.posture.store.Open(next.base.rowsRecord)
		if err != nil {
			self.alarm(PostureAlarmStoreUnreadable, entry.GetN(), err)
			return err
		}
		found, err := readPostureSidecars(reader, self.posture.settings, next.base.rowsSha256, ids)
		reader.Close()
		if err != nil {
			self.alarm(PostureAlarmStoreUnverified, entry.GetN(), err)
			return err
		}
		for id := range ids {
			self.lookedUp[id] = true
		}
		for id, row := range found {
			self.rowsFound[id] = row
		}
	}
	peers := &posturePeers{rows: self.rowsFound, adminMemberRoles: next.base.adminMemberRoles, overlay: next.overlay}
	effect, err := verifyPostureStatement(statement, entry.GetN(), entry.GetTimeMs(), next.networkId, peers)
	if err != nil {
		self.alarm(PostureAlarmStatementRefused, entry.GetN(), err)
		return nil
	}
	if effect.add != nil {
		// a statement delivered again, as after a resync, adds nothing
		if slices.ContainsFunc(next.overlay, func(overlayEntry PostureOverlayEntry) bool {
			return postureOverlayEntryEqual(overlayEntry, *effect.add)
		}) {
			return nil
		}
		if self.posture.settings.OverlayMaxCount <= len(next.overlay) {
			err := fmt.Errorf("%w: past the %d overlay entries held between states", ErrPostureRefused, self.posture.settings.OverlayMaxCount)
			self.alarm(PostureAlarmMalformed, entry.GetN(), err)
			return err
		}
		next.overlay = append(next.overlay, *effect.add)
		return nil
	}
	lifted := slices.IndexFunc(next.overlay, func(overlayEntry PostureOverlayEntry) bool {
		return overlayEntry.Kind == PostureOverlaySuspend && bytes.Equal(overlayEntry.Id, effect.liftSubject) &&
			bytes.Equal(overlayEntry.SuspendId, effect.liftId) && overlayEntry.suspendClass <= effect.liftClass
	})
	if lifted < 0 {
		// lifts only a suspend this posture holds between states; one in the state waits for the next state
		return nil
	}
	next.overlay = slices.Delete(next.overlay, lifted, lifted+1)
	return nil
}

// Writes this call's records, then the manifest, the one point the call takes effect, then removes what the manifest
// no longer names. On an error nothing new is in force and the store still opens to what it held.
func (self *postureOperation) commit() error {
	next := self.next
	store := self.posture.store
	if next.stored == postureStoredEnforcing && (self.rebased || 0 < len(self.newEntries)) {
		count := self.entriesCount()
		if count == 0 {
			next.entriesRecord, next.entriesSha256, next.entriesCount = "", nil, 0
		} else {
			name := postureRecordName("entries", self.generation)
			self.written = append(self.written, name)
			hash := sha256.New()
			err := store.Write(name, func(writer io.Writer) error {
				hashed := io.MultiWriter(writer, hash)
				if !self.rebased && self.from != nil && self.from.entriesRecord != "" {
					// the stored entries, checked as they are copied, then this call's
					storedSha256, err := self.posture.readEntries(self.from.entriesRecord, func(entryBytes []byte) error {
						return writePostureEntry(hashed, entryBytes)
					})
					if err != nil {
						return err
					}
					if !bytes.Equal(storedSha256[:], self.from.entriesSha256) {
						return fmt.Errorf("%w: stored entries changed", ErrPostureStoreFailed)
					}
				}
				for _, entryBytes := range self.newEntries {
					if err := writePostureEntry(hashed, entryBytes); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return err
			}
			next.entriesRecord, next.entriesSha256, next.entriesCount = name, hash.Sum(nil), count
		}
	}
	if self.stateBytes != nil {
		name := postureRecordName("state", self.generation)
		self.written = append(self.written, name)
		if err := store.Write(name, func(writer io.Writer) error {
			_, err := writer.Write(self.stateBytes)
			return err
		}); err != nil {
			return err
		}
		stateSha256 := sha256.Sum256(self.stateBytes)
		next.stateRecord, next.stateSha256 = name, stateSha256[:]
	}
	next.generation = self.generation
	manifestBytes := next.manifest().encode()
	testHookBarrier("posture.commit.before", "")
	self.manifestTried = true
	if err := store.Write(postureManifestName, func(writer io.Writer) error {
		_, err := writer.Write(manifestBytes)
		return err
	}); err != nil {
		return err
	}
	testHookBarrier("posture.commit.after", "")
	if names, err := store.List(); err == nil {
		self.posture.removeGarbage(next, names)
	}
	return nil
}

// Drops the records this call wrote that no manifest names, after a refusal. Best effort, and nothing once a manifest
// write was tried, which may have named them.
func (self *postureOperation) discard() {
	if self.manifestTried {
		return
	}
	for _, name := range self.written {
		self.posture.store.Remove(name)
	}
}

// Appends one entry to an entries record: its length, then its bytes.
func writePostureEntry(writer io.Writer, entryBytes []byte) error {
	if _, err := writer.Write(protowire.AppendVarint(nil, uint64(len(entryBytes)))); err != nil {
		return err
	}
	_, err := writer.Write(entryBytes)
	return err
}

// Commits, and publishes on success; on a store fault, alarms and leaves what was in force.
func (self *postureOperation) finish(callErr error) (PostureDecision, error) {
	if err := self.commit(); err != nil {
		self.discard()
		self.alarm(PostureAlarmStoreFailed, self.next.pinN, err)
		decision, _ := self.posture.refuseWithLock(self.alarms, nil)
		return decision, fmt.Errorf("%w: %w", ErrPostureStore, err)
	}
	return self.posture.publishWithLock(self.next, self.alarms, false), callErr
}

// Wipes the posture back to legacy: a legacy manifest first, so a kill after it leaves legacy, then every other
// record.
func (self *postureOperation) wipe() (PostureDecision, error) {
	self.next = &postureHeld{stored: postureStoredLegacy}
	self.newEntries, self.rebased, self.stateBytes = nil, false, nil
	return self.finish(nil)
}

// SetPending's work.
func (self *Posture) setPendingWithLock(pending *bridge.Pending) (PostureDecision, error) {
	operation := self.newOperation()
	refuse := func(kind PostureAlarmKind, err error) (PostureDecision, error) {
		operation.alarm(kind, 0, err)
		return self.refuseWithLock(operation.alarms, err)
	}
	if pending == nil || len(pending.GetNetworkId()) != postureIdByteCount || len(pending.GetGenesisSha256()) != postureDigestByteCount {
		return refuse(PostureAlarmMalformed, fmt.Errorf("%w: a Pending with no network or anchor", ErrPostureRefused))
	}
	hasIds := len(pending.GetSidecarId()) != 0 || len(pending.GetIdentityPublicKey()) != 0
	if hasIds && (len(pending.GetSidecarId()) != postureIdByteCount || len(pending.GetIdentityPublicKey()) != ed25519.PublicKeySize) {
		return refuse(PostureAlarmMalformed, fmt.Errorf("%w: a Pending with a malformed id or key", ErrPostureRefused))
	}
	next := operation.next
	sameNetwork := bytes.Equal(next.networkId, pending.GetNetworkId())
	sameAnchor := sameNetwork && bytes.Equal(next.anchor, pending.GetGenesisSha256())
	switch next.stored {
	case postureStoredEnforcing:
		if !sameAnchor {
			return refuse(PostureAlarmAnchor, fmt.Errorf("%w: a Pending for another network or anchor while enforcing", ErrPostureRefused))
		}
		if !hasIds || (bytes.Equal(next.sidecarId, pending.GetSidecarId()) && bytes.Equal(next.identityPublicKey, pending.GetIdentityPublicKey())) {
			return self.refuseWithLock(nil, nil)
		}
		// a new enrollment's id and key, after an admin's revocation: no state changes
		next.sidecarId, next.identityPublicKey = bytes.Clone(pending.GetSidecarId()), bytes.Clone(pending.GetIdentityPublicKey())
		return operation.finish(nil)
	case postureStoredPending:
		if next.networkId != nil && !sameNetwork {
			return refuse(PostureAlarmAnchor, fmt.Errorf("%w: a Pending for another network", ErrPostureRefused))
		}
	}
	held := &postureHeld{
		stored:         postureStoredPending,
		networkId:      bytes.Clone(pending.GetNetworkId()),
		anchor:         bytes.Clone(pending.GetGenesisSha256()),
		documentSeenAt: next.documentSeenAt,
		shareCerts:     next.shareCerts,
	}
	if hasIds {
		held.sidecarId, held.identityPublicKey = bytes.Clone(pending.GetSidecarId()), bytes.Clone(pending.GetIdentityPublicKey())
	}
	operation.next = held
	return operation.finish(nil)
}

// SetState's work.
func (self *Posture) setStateWithLock(state *bridge.BridgeState, log *PostureLog) (PostureDecision, error) {
	operation := self.newOperation()
	refuse := func(kind PostureAlarmKind, n uint64, err error) (PostureDecision, error) {
		if kind != "" {
			operation.alarm(kind, n, err)
		}
		operation.discard()
		return self.refuseWithLock(operation.alarms, err)
	}
	next := operation.next
	if next.stored == postureStoredLegacy {
		return refuse("", 0, ErrPostureLegacy)
	}
	if next.networkId == nil {
		return refuse(PostureAlarmAnchor, 0, fmt.Errorf("%w: no anchor to verify a state against", ErrPostureRefused))
	}
	if state == nil || len(state.GetAuth().GetChain()) != postureDigestByteCount || state.GetAuth().GetVersion() == 0 {
		return refuse(PostureAlarmMalformed, 0, fmt.Errorf("%w: a state with no pin", ErrPostureRefused))
	}
	statePinN := state.GetAuth().GetVersion()
	if !bytes.Equal(state.GetGenesisSha256(), next.anchor) {
		return refuse(PostureAlarmAnchor, statePinN, fmt.Errorf("%w: a state for another anchor", ErrPostureRefused))
	}
	stateBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(state)
	if err != nil || self.settings.StateMaxByteCount < len(stateBytes) {
		return refuse(PostureAlarmMalformed, statePinN, fmt.Errorf("%w: a state past its bound", ErrPostureRefused))
	}
	if log == nil {
		log = &PostureLog{}
	}
	enforcing := next.stored == postureStoredEnforcing
	if enforcing && statePinN < next.statePinN() {
		return refuse(PostureAlarmLowerPin, statePinN, fmt.Errorf("%w: a state below the last one", ErrPostureRefused))
	}

	// a log that starts at a base re-anchors on it, as the first state does: the sidecar role holds its state's
	// newest base, and a state on it resyncs a posture whose deltas missed a fold or followed a chain the state's is not
	logStartsAtBase := false
	if 0 < len(log.Entries) {
		entry := &bridge.AuthEntry{}
		logStartsAtBase = proto.Unmarshal(log.Entries[0], entry) == nil && entry.GetKind() == bridge.AuthEntryKindBase
	}
	reanchor := !enforcing
	switch {
	case enforcing && statePinN <= next.pinN:
		// at or below the posture's pin: on the chain the posture verified, at or after the base whose rows say what
		// its has_document must be, it needs no log; otherwise only its own base can vouch for it
		if statePinN < next.base.entry.GetN() {
			if !logStartsAtBase {
				return refuse("", statePinN, fmt.Errorf("%w: a state older than the base the posture holds", ErrPostureRefused))
			}
			reanchor = true
			break
		}
		onChain, err := self.chainAt(next, statePinN)
		if err != nil {
			operation.alarm(PostureAlarmStoreUnverified, statePinN, err)
			return refuse("", statePinN, err)
		}
		if !bytes.Equal(onChain[:], state.GetAuth().GetChain()) {
			err := fmt.Errorf("%w: a state off the chain the deltas verified", ErrPostureRefused)
			if !logStartsAtBase {
				return refuse(PostureAlarmChainBreak, statePinN, err)
			}
			operation.alarm(PostureAlarmChainBreak, statePinN, err)
			reanchor = true
		}
	case enforcing && 0 < len(log.Entries) && postureEntryChainsFrom(log.Entries[0], next):
		if _, err := operation.applyEntries(log, log.Entries, postureModeState); err != nil {
			return refuse("", statePinN, err)
		}
	default:
		reanchor = true
	}
	if reanchor {
		// from pending, or a re-anchor on the state's newest base
		previousPinN, previousPinChain := next.pinN, next.pinChain
		if len(log.Entries) == 0 {
			return refuse(PostureAlarmChainBreak, statePinN, fmt.Errorf("%w: a state with no base to vouch for it", ErrPostureRefused))
		}
		parsed, err := parsePostureEntry(log.Entries[0], next.networkId, self.settings.EntryMaxByteCount)
		if err != nil {
			return refuse(PostureAlarmMalformed, 0, err)
		}
		if parsed.entry.GetKind() != bridge.AuthEntryKindBase {
			return refuse(PostureAlarmChainBreak, parsed.entry.GetN(), fmt.Errorf("%w: a state's log that neither chains from the pin nor starts at a base", ErrPostureRefused))
		}
		base, err := operation.takeBase(parsed, log.OpenRows, nil)
		if err != nil {
			return refuse(PostureAlarmBaseRefused, parsed.entry.GetN(), err)
		}
		next.stored = postureStoredEnforcing
		next.base = base
		next.pinN, next.pinChain = base.entry.GetN(), base.chain
		operation.rebased = true
		operation.newEntries = nil
		if base.hasDocument {
			next.documentSeenAt = max(next.documentSeenAt, base.entry.GetN())
		}
		if _, err := operation.applyEntries(log, log.Entries[1:], postureModeState); err != nil {
			return refuse("", statePinN, err)
		}
		if enforcing && previousPinN <= next.pinN && next.pinN == statePinN {
			// the state's log reaches past what the deltas verified: where it covers the old pin, it must agree
			if onChain, err := operation.chainOfLog(log, previousPinN); err == nil && onChain != previousPinChain {
				operation.alarm(PostureAlarmChainBreak, previousPinN, fmt.Errorf("%w: the deltas' chain is not the state's", ErrPostureRefused))
			}
		}
	}
	if reanchor || statePinN > operation.from.pinN {
		if next.pinN != statePinN || !bytes.Equal(next.pinChain[:], state.GetAuth().GetChain()) {
			return refuse(PostureAlarmChainBreak, statePinN, fmt.Errorf("%w: a state whose log does not end at its pin", ErrPostureRefused))
		}
	}
	// an unsigned has_document changes nothing: the state must say what its verified rows say
	if state.GetHasDocument() != next.base.hasDocument {
		return refuse(PostureAlarmDocument, statePinN, fmt.Errorf("%w: a state whose has_document is not its rows'", ErrPostureRefused))
	}
	next.stored = postureStoredEnforcing
	next.bridgeState = state
	operation.stateBytes = stateBytes
	// the state confirms or reverses everything at or before its pin; what a resync below the pin leaves past it
	// stands, the stricter, until a state passes it
	next.overlay = slices.DeleteFunc(next.overlay, func(entry PostureOverlayEntry) bool {
		return entry.N <= statePinN
	})
	return operation.finish(nil)
}

// Whether entry bytes chain from held's pin.
func postureEntryChainsFrom(entryBytes []byte, held *postureHeld) bool {
	entry := &bridge.AuthEntry{}
	if proto.Unmarshal(entryBytes, entry) != nil {
		return false
	}
	return held.stored == postureStoredEnforcing && entry.GetN() == held.pinN+1 && bytes.Equal(entry.GetPrevChain(), held.pinChain[:])
}

// A_n at n, between held's base and its pin, from what the store keeps.
func (self *Posture) chainAt(held *postureHeld, n uint64) ([postureDigestByteCount]byte, error) {
	switch {
	case n == held.pinN:
		return held.pinChain, nil
	case n == held.base.entry.GetN():
		return held.base.chain, nil
	case held.entriesRecord == "":
		return [postureDigestByteCount]byte{}, fmt.Errorf("%w: no entry at %d", ErrPostureRefused, n)
	}
	found := [postureDigestByteCount]byte{}
	ok := false
	_, err := self.readEntries(held.entriesRecord, func(entryBytes []byte) error {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			return fmt.Errorf("%w: a stored entry that does not decode", ErrPostureStoreFailed)
		}
		if entry.GetN() == n {
			chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
			if err != nil {
				return err
			}
			found, ok = chain, true
		}
		return nil
	})
	if err != nil {
		return [postureDigestByteCount]byte{}, err
	}
	if !ok {
		return [postureDigestByteCount]byte{}, fmt.Errorf("%w: no entry at %d", ErrPostureRefused, n)
	}
	return found, nil
}

// A_n at n in a state's log, which applyEntries has verified, or an error when the log does not reach n.
func (self *postureOperation) chainOfLog(log *PostureLog, n uint64) ([postureDigestByteCount]byte, error) {
	for _, entryBytes := range log.Entries {
		entry := &bridge.AuthEntry{}
		if proto.Unmarshal(entryBytes, entry) != nil {
			continue
		}
		if entry.GetN() == n {
			return bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
		}
	}
	return [postureDigestByteCount]byte{}, fmt.Errorf("%w: the log does not reach %d", ErrPostureRefused, n)
}

// ApplyDeltas' work.
func (self *Posture) applyDeltasWithLock(log *PostureLog) (PostureDecision, error) {
	operation := self.newOperation()
	next := operation.next
	if next.stored == postureStoredLegacy {
		return self.refuseWithLock(nil, ErrPostureLegacy)
	}
	if log == nil || len(log.Entries) == 0 {
		return self.refuseWithLock(nil, nil)
	}
	if next.stored == postureStoredPending {
		// no pin to chain from: the sidecar's own sign-out alone (plan-SDK-pending-sidecar-id)
		refused := fmt.Errorf("%w: in pending only this sidecar's own sign-out applies", ErrPostureRefused)
		if len(log.Entries) != 1 || next.networkId == nil {
			operation.alarm(PostureAlarmStatementRefused, 0, refused)
			return self.refuseWithLock(operation.alarms, refused)
		}
		parsed, err := parsePostureEntry(log.Entries[0], next.networkId, self.settings.EntryMaxByteCount)
		if err != nil || parsed.entry.GetKind() != bridge.AuthEntryKindStatement {
			operation.alarm(PostureAlarmStatementRefused, 0, refused)
			return self.refuseWithLock(operation.alarms, refused)
		}
		statement, err := parsePostureStatement(parsed.entry)
		if err != nil || statement == nil || !statement.ownSignOut(next.networkId, next.sidecarId, next.identityPublicKey) {
			operation.alarm(PostureAlarmStatementRefused, parsed.entry.GetN(), refused)
			return self.refuseWithLock(operation.alarms, refused)
		}
		return operation.wipe()
	}
	taken, err := operation.applyEntries(log, log.Entries, postureModeDeltas)
	if operation.wiped {
		return operation.wipe()
	}
	if taken == 0 {
		operation.discard()
		return self.refuseWithLock(operation.alarms, err)
	}
	// what verified before the refusal stays applied
	return operation.finish(err)
}

// RaiseShareCert's work.
func (self *Posture) raiseShareCertWithLock(shareId []byte, generation uint64, signedCert []byte) error {
	if len(shareId) == 0 || len(signedCert) == 0 {
		return fmt.Errorf("%w: a share certificate with no share or bytes", ErrPostureRefused)
	}
	operation := self.newOperation()
	next := operation.next
	if next.stored != postureStoredEnforcing {
		return fmt.Errorf("%w: only an enforcing posture keeps share certificates", ErrPostureRefused)
	}
	index := slices.IndexFunc(next.shareCerts, func(shareCert postureShareCert) bool {
		return bytes.Equal(shareCert.shareId, shareId)
	})
	shareCert := postureShareCert{shareId: bytes.Clone(shareId), generation: generation, cert: bytes.Clone(signedCert)}
	switch {
	case 0 <= index && generation < next.shareCerts[index].generation:
		return fmt.Errorf("%w: a share certificate below the newest kept", ErrPostureRefused)
	case 0 <= index && generation == next.shareCerts[index].generation:
		return nil
	case 0 <= index:
		next.shareCerts[index] = shareCert
	case self.settings.ShareCertMaxCount <= len(next.shareCerts):
		return fmt.Errorf("%w: past the %d share certificates kept", ErrPostureRefused, self.settings.ShareCertMaxCount)
	default:
		next.shareCerts = append(next.shareCerts, shareCert)
		slices.SortFunc(next.shareCerts, func(a postureShareCert, b postureShareCert) int {
			return bytes.Compare(a.shareId, b.shareId)
		})
	}
	_, err := operation.finish(nil)
	return err
}
