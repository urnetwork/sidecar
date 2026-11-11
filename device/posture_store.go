// Where a posture persists (§18.6's stored row, §17.8's persist row, DESIGN-DETAILS 4.2.2): the VPN component's own
// container, never an app group, under fwd/<network_id hex>/posture/, so PostureStore is an interface,
// NewFilePostureStore the inner store this package brings, and NewSealedPostureStore (posture_seal.go) the wrapper that
// seals every record under the component's forwarding root key.
//
// A posture is a few records. The manifest, "posture", names the rest and is written last, so its rename is the one
// point at which a new posture takes effect: rows-<g>, entries-<g> and state-<g> are written first under a generation
// no committed manifest names, and a record a committed manifest no longer names is garbage, removed after the commit.
// A kill at any step leaves the manifest before or after, each naming records that are whole.
//
// The manifest is this package's own format, protobuf's wire format written field by field in number order with
// nothing zero written, so its bytes are a function of what it holds on every leg (testdata/device/):
//
//	1 version (1)  2 generation  3 state (0 pending, 1 legacy, 2 enforcing)  4 network_id  5 anchor
//	6 sidecar_id  7 identity_public_key  8 pin's n  9 pin's chain  10 the base's AuthEntry, verbatim
//	11 rows record  12 rows_sha256  13 entries record  14 entries record's SHA-256  15 entries' count
//	16 state record  17 state record's SHA-256  18 document_seen_at
//	19 share certificate, repeated: 1 share_id  2 generation  3 Signed ShareCert, verbatim
//	20 overlay entry, repeated, oldest first: 1 kind  2 n  3 id  4 suspend_id  5 withdraw mode  6 covered (1)
//	   7 a ForwardSupersede's delegation_id
//	21 waiting entry, repeated, in position order: 1 n  2 through n, where not n  3 first seen, ms since the epoch
//	   as protobuf's int64 varint
//	22 fork (1)
//
// The overlay and Waiting are kept as derived, not derived again on a restart: a delta base between states replaces
// the rows a statement before it was checked by, and every entry of it was verified when it arrived (posture.go), and
// a waiting entry's first sight is what its clock runs from, so a restart does not reset it.
//
// entries-<g> holds the entries since the base, each a varint length then its AuthEntry, verbatim. state-<g> holds
// the BridgeState in force, deterministically encoded. rows-<g> holds the base's ProjectionRows, verbatim.

package device

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Nothing is stored under the name. Only this means that: a fault is never this, so a store that exists but cannot be
// read never reads as a device that never enrolled, which would reopen the LAN (§18.6, DP1).
var ErrPostureStoreAbsent = errors.New("no posture record")

// A record's bytes, or the store under them, failed: a read, a decode or a write.
var ErrPostureStoreFailed = errors.New("posture store failed")

// One network's posture records. Safe for concurrent use.
type PostureStore interface {
	// Streams the record. ErrPostureStoreAbsent, bare or wrapped, only when no such record exists: any other error
	// says the record may be there and could not be read.
	Open(name string) (io.ReadCloser, error)
	// Replaces the record with what write writes, whole and durably: when this returns nil a power cut keeps the new
	// record, and on any error, write's included, the old record stands untouched.
	Write(name string, write func(writer io.Writer) error) error
	// Takes the record away. Absent is not an error.
	Remove(name string) error
	// The names of the records held, sorted. A write in progress is never listed.
	List() ([]string, error)
}

// The manifest's name, which every commit writes last.
const postureManifestName = "posture"

// What a record's name may be: lowercase letters, digits and dashes, starting with a letter or digit.
var postureRecordNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// The manifest format's values.
const (
	postureManifestVersion = 1

	postureStoredPending   = 0
	postureStoredLegacy    = 1
	postureStoredEnforcing = 2
)

// The manifest's field numbers, in the order they are written.
const (
	postureFieldVersion protowire.Number = iota + 1
	postureFieldGeneration
	postureFieldState
	postureFieldNetworkId
	postureFieldAnchor
	postureFieldSidecarId
	postureFieldIdentityPublicKey
	postureFieldPinN
	postureFieldPinChain
	postureFieldBaseEntry
	postureFieldRowsRecord
	postureFieldRowsSha256
	postureFieldEntriesRecord
	postureFieldEntriesSha256
	postureFieldEntriesCount
	postureFieldStateRecord
	postureFieldStateSha256
	postureFieldDocumentSeenAt
	postureFieldShareCert
	postureFieldOverlay
	postureFieldWaiting
	postureFieldFork
)

// A share certificate's field numbers inside its manifest field.
const (
	postureShareFieldShareId protowire.Number = iota + 1
	postureShareFieldGeneration
	postureShareFieldCert
)

// An overlay entry's field numbers inside its manifest field.
const (
	postureOverlayFieldKind protowire.Number = iota + 1
	postureOverlayFieldN
	postureOverlayFieldId
	postureOverlayFieldSuspendId
	postureOverlayFieldWithdrawMode
	postureOverlayFieldCovered
	postureOverlayFieldDelegationId
)

// A waiting entry's field numbers inside its manifest field.
const (
	postureWaitingFieldN protowire.Number = iota + 1
	postureWaitingFieldThroughN
	postureWaitingFieldFirstSeen
)

// The newest verified ShareCert of a share this host serves (§17.9), kept so a restart refuses one below it.
type postureShareCert struct {
	shareId    []byte
	generation uint64
	cert       []byte
}

// What a committed manifest says.
type postureManifest struct {
	generation        uint64
	stored            uint64
	networkId         []byte
	anchor            []byte
	sidecarId         []byte
	identityPublicKey []byte
	pinN              uint64
	pinChain          []byte
	baseEntry         []byte
	rowsRecord        string
	rowsSha256        []byte
	entriesRecord     string
	entriesSha256     []byte
	entriesCount      uint64
	stateRecord       string
	stateSha256       []byte
	documentSeenAt    uint64
	shareCerts        []postureShareCert
	overlay           []PostureOverlayEntry
	waiting           []PostureWaitingEntry
	fork              bool
}

// The manifest's bytes, every field in number order and none that is zero.
func (self *postureManifest) encode() []byte {
	encoded := []byte{}
	appendUint := func(number protowire.Number, value uint64) {
		if value != 0 {
			encoded = protowire.AppendTag(encoded, number, protowire.VarintType)
			encoded = protowire.AppendVarint(encoded, value)
		}
	}
	appendBytes := func(number protowire.Number, value []byte) {
		if len(value) != 0 {
			encoded = protowire.AppendTag(encoded, number, protowire.BytesType)
			encoded = protowire.AppendBytes(encoded, value)
		}
	}
	appendUint(postureFieldVersion, postureManifestVersion)
	appendUint(postureFieldGeneration, self.generation)
	appendUint(postureFieldState, self.stored)
	appendBytes(postureFieldNetworkId, self.networkId)
	appendBytes(postureFieldAnchor, self.anchor)
	appendBytes(postureFieldSidecarId, self.sidecarId)
	appendBytes(postureFieldIdentityPublicKey, self.identityPublicKey)
	appendUint(postureFieldPinN, self.pinN)
	appendBytes(postureFieldPinChain, self.pinChain)
	appendBytes(postureFieldBaseEntry, self.baseEntry)
	appendBytes(postureFieldRowsRecord, []byte(self.rowsRecord))
	appendBytes(postureFieldRowsSha256, self.rowsSha256)
	appendBytes(postureFieldEntriesRecord, []byte(self.entriesRecord))
	appendBytes(postureFieldEntriesSha256, self.entriesSha256)
	appendUint(postureFieldEntriesCount, self.entriesCount)
	appendBytes(postureFieldStateRecord, []byte(self.stateRecord))
	appendBytes(postureFieldStateSha256, self.stateSha256)
	appendUint(postureFieldDocumentSeenAt, self.documentSeenAt)
	for _, shareCert := range self.shareCerts {
		share := []byte{}
		share = protowire.AppendTag(share, postureShareFieldShareId, protowire.BytesType)
		share = protowire.AppendBytes(share, shareCert.shareId)
		if shareCert.generation != 0 {
			share = protowire.AppendTag(share, postureShareFieldGeneration, protowire.VarintType)
			share = protowire.AppendVarint(share, shareCert.generation)
		}
		share = protowire.AppendTag(share, postureShareFieldCert, protowire.BytesType)
		share = protowire.AppendBytes(share, shareCert.cert)
		encoded = protowire.AppendTag(encoded, postureFieldShareCert, protowire.BytesType)
		encoded = protowire.AppendBytes(encoded, share)
	}
	for _, entry := range self.overlay {
		encoded = protowire.AppendTag(encoded, postureFieldOverlay, protowire.BytesType)
		encoded = protowire.AppendBytes(encoded, encodePostureOverlayEntry(&entry))
	}
	for _, entry := range self.waiting {
		waiting := protowire.AppendVarint(protowire.AppendTag(nil, postureWaitingFieldN, protowire.VarintType), entry.N)
		if entry.ThroughN != entry.N {
			waiting = protowire.AppendTag(waiting, postureWaitingFieldThroughN, protowire.VarintType)
			waiting = protowire.AppendVarint(waiting, entry.ThroughN)
		}
		if firstSeenMs := entry.FirstSeen.UnixMilli(); firstSeenMs != 0 {
			waiting = protowire.AppendTag(waiting, postureWaitingFieldFirstSeen, protowire.VarintType)
			waiting = protowire.AppendVarint(waiting, uint64(firstSeenMs))
		}
		encoded = protowire.AppendTag(encoded, postureFieldWaiting, protowire.BytesType)
		encoded = protowire.AppendBytes(encoded, waiting)
	}
	if self.fork {
		appendUint(postureFieldFork, 1)
	}
	return encoded
}

// One overlay entry's bytes, every field in number order and none that is zero.
func encodePostureOverlayEntry(entry *PostureOverlayEntry) []byte {
	encoded := []byte{}
	appendUint := func(number protowire.Number, value uint64) {
		if value != 0 {
			encoded = protowire.AppendTag(encoded, number, protowire.VarintType)
			encoded = protowire.AppendVarint(encoded, value)
		}
	}
	appendBytes := func(number protowire.Number, value []byte) {
		if len(value) != 0 {
			encoded = protowire.AppendTag(encoded, number, protowire.BytesType)
			encoded = protowire.AppendBytes(encoded, value)
		}
	}
	appendUint(postureOverlayFieldKind, uint64(entry.Kind))
	appendUint(postureOverlayFieldN, entry.N)
	appendBytes(postureOverlayFieldId, entry.Id)
	appendBytes(postureOverlayFieldSuspendId, entry.SuspendId)
	appendUint(postureOverlayFieldWithdrawMode, uint64(entry.WithdrawMode))
	if entry.Covered {
		appendUint(postureOverlayFieldCovered, 1)
	}
	appendBytes(postureOverlayFieldDelegationId, entry.DelegationId)
	return encoded
}

// One overlay entry's fields, each at most once and in order, of a kind this package writes, with what that kind
// carries: a Suspend its suspend_id, a DelegationRevoke a delegation_id as its id, a ForwardSupersede a sidecar_id as
// its id and the newer delegation_id.
func decodePostureOverlayEntry(encoded []byte) (*PostureOverlayEntry, error) {
	entry := &PostureOverlayEntry{}
	failed := fmt.Errorf("%w: manifest overlay entry does not decode", ErrPostureStoreFailed)
	last := protowire.Number(0)
	for 0 < len(encoded) {
		number, wireType, tagLength := protowire.ConsumeTag(encoded)
		if tagLength < 0 || number <= last {
			return nil, failed
		}
		last = number
		encoded = encoded[tagLength:]
		switch number {
		case postureOverlayFieldKind, postureOverlayFieldN, postureOverlayFieldWithdrawMode, postureOverlayFieldCovered:
			if wireType != protowire.VarintType {
				return nil, failed
			}
			value, length := protowire.ConsumeVarint(encoded)
			if length < 0 || (number != postureOverlayFieldN && 1<<16 < value) {
				return nil, failed
			}
			encoded = encoded[length:]
			switch number {
			case postureOverlayFieldKind:
				entry.Kind = PostureOverlayKind(value)
			case postureOverlayFieldN:
				entry.N = value
			case postureOverlayFieldWithdrawMode:
				entry.WithdrawMode = bridge.BridgeWithdrawMode(value)
			case postureOverlayFieldCovered:
				entry.Covered = value == 1
			}
		case postureOverlayFieldId, postureOverlayFieldSuspendId, postureOverlayFieldDelegationId:
			if wireType != protowire.BytesType {
				return nil, failed
			}
			value, length := protowire.ConsumeBytes(encoded)
			if length < 0 {
				return nil, failed
			}
			encoded = encoded[length:]
			switch number {
			case postureOverlayFieldId:
				entry.Id = bytes.Clone(value)
			case postureOverlayFieldSuspendId:
				entry.SuspendId = bytes.Clone(value)
			case postureOverlayFieldDelegationId:
				entry.DelegationId = bytes.Clone(value)
			}
		default:
			return nil, failed
		}
	}
	if entry.Kind < PostureOverlaySidecarRevoke || PostureOverlayForwardSupersede < entry.Kind || entry.N == 0 || len(entry.Id) == 0 {
		return nil, failed
	}
	if (entry.Kind == PostureOverlaySuspend) != (len(entry.SuspendId) != 0) {
		return nil, failed
	}
	if (entry.Kind == PostureOverlayForwardSupersede) != (len(entry.DelegationId) != 0) {
		return nil, failed
	}
	switch entry.Kind {
	case PostureOverlayDelegationRevoke:
		if len(entry.Id) != postureDelegationIdByteCount {
			return nil, failed
		}
	case PostureOverlayForwardSupersede:
		if len(entry.Id) != postureIdByteCount || len(entry.DelegationId) != postureDelegationIdByteCount {
			return nil, failed
		}
	}
	return entry, nil
}

// One waiting entry's fields, each at most once and in order: a position, through one at or past it, and a first
// sight.
func decodePostureWaitingEntry(encoded []byte) (*PostureWaitingEntry, error) {
	failed := fmt.Errorf("%w: manifest waiting entry does not decode", ErrPostureStoreFailed)
	values := map[protowire.Number]uint64{}
	last := protowire.Number(0)
	for 0 < len(encoded) {
		number, wireType, tagLength := protowire.ConsumeTag(encoded)
		if tagLength < 0 || number <= last || wireType != protowire.VarintType ||
			(number != postureWaitingFieldN && number != postureWaitingFieldThroughN && number != postureWaitingFieldFirstSeen) {
			return nil, failed
		}
		last = number
		encoded = encoded[tagLength:]
		value, length := protowire.ConsumeVarint(encoded)
		if length < 0 {
			return nil, failed
		}
		encoded = encoded[length:]
		values[number] = value
	}
	entry := &PostureWaitingEntry{
		N:         values[postureWaitingFieldN],
		ThroughN:  values[postureWaitingFieldN],
		FirstSeen: time.UnixMilli(int64(values[postureWaitingFieldFirstSeen])),
	}
	if throughN, ok := values[postureWaitingFieldThroughN]; ok {
		if throughN <= entry.N {
			return nil, failed
		}
		entry.ThroughN = throughN
	}
	if entry.N == 0 {
		return nil, failed
	}
	return entry, nil
}

// Reads a manifest strictly: version 1, every field of its type, in number order, once, nothing else, and every
// record name a record name. Anything else is ErrPostureStoreFailed, which a posture reads as unreadable, never absent.
func decodePostureManifest(encoded []byte) (*postureManifest, error) {
	manifest := &postureManifest{}
	failed := func(format string, a ...any) error {
		return fmt.Errorf("%w: manifest %s", ErrPostureStoreFailed, fmt.Sprintf(format, a...))
	}
	last := protowire.Number(0)
	version := uint64(0)
	for 0 < len(encoded) {
		number, wireType, tagLength := protowire.ConsumeTag(encoded)
		if tagLength < 0 {
			return nil, failed("tag does not decode")
		}
		encoded = encoded[tagLength:]
		if number < last || (number == last && number != postureFieldShareCert && number != postureFieldOverlay &&
			number != postureFieldWaiting) {
			return nil, failed("field %d out of order", number)
		}
		last = number
		switch number {
		case postureFieldVersion, postureFieldGeneration, postureFieldState, postureFieldPinN, postureFieldEntriesCount,
			postureFieldDocumentSeenAt, postureFieldFork:
			if wireType != protowire.VarintType {
				return nil, failed("field %d of wire type %d", number, wireType)
			}
			value, length := protowire.ConsumeVarint(encoded)
			if length < 0 {
				return nil, failed("field %d does not decode", number)
			}
			encoded = encoded[length:]
			switch number {
			case postureFieldVersion:
				version = value
			case postureFieldGeneration:
				manifest.generation = value
			case postureFieldState:
				manifest.stored = value
			case postureFieldPinN:
				manifest.pinN = value
			case postureFieldEntriesCount:
				manifest.entriesCount = value
			case postureFieldDocumentSeenAt:
				manifest.documentSeenAt = value
			case postureFieldFork:
				if value != 1 {
					return nil, failed("fork %d", value)
				}
				manifest.fork = true
			}
		case postureFieldNetworkId, postureFieldAnchor, postureFieldSidecarId, postureFieldIdentityPublicKey,
			postureFieldPinChain, postureFieldBaseEntry, postureFieldRowsRecord, postureFieldRowsSha256,
			postureFieldEntriesRecord, postureFieldEntriesSha256, postureFieldStateRecord, postureFieldStateSha256,
			postureFieldShareCert, postureFieldOverlay, postureFieldWaiting:
			if wireType != protowire.BytesType {
				return nil, failed("field %d of wire type %d", number, wireType)
			}
			value, length := protowire.ConsumeBytes(encoded)
			if length < 0 {
				return nil, failed("field %d does not decode", number)
			}
			encoded = encoded[length:]
			value = bytes.Clone(value)
			switch number {
			case postureFieldNetworkId:
				manifest.networkId = value
			case postureFieldAnchor:
				manifest.anchor = value
			case postureFieldSidecarId:
				manifest.sidecarId = value
			case postureFieldIdentityPublicKey:
				manifest.identityPublicKey = value
			case postureFieldPinChain:
				manifest.pinChain = value
			case postureFieldBaseEntry:
				manifest.baseEntry = value
			case postureFieldRowsRecord:
				manifest.rowsRecord = string(value)
			case postureFieldRowsSha256:
				manifest.rowsSha256 = value
			case postureFieldEntriesRecord:
				manifest.entriesRecord = string(value)
			case postureFieldEntriesSha256:
				manifest.entriesSha256 = value
			case postureFieldStateRecord:
				manifest.stateRecord = string(value)
			case postureFieldStateSha256:
				manifest.stateSha256 = value
			case postureFieldShareCert:
				shareCert, err := decodePostureShareCert(value)
				if err != nil {
					return nil, err
				}
				manifest.shareCerts = append(manifest.shareCerts, *shareCert)
			case postureFieldOverlay:
				entry, err := decodePostureOverlayEntry(value)
				if err != nil {
					return nil, err
				}
				manifest.overlay = append(manifest.overlay, *entry)
			case postureFieldWaiting:
				entry, err := decodePostureWaitingEntry(value)
				if err != nil {
					return nil, err
				}
				manifest.waiting = append(manifest.waiting, *entry)
			}
		default:
			return nil, failed("unknown field %d", number)
		}
	}
	if version != postureManifestVersion {
		return nil, failed("version %d", version)
	}
	for _, name := range []string{manifest.rowsRecord, manifest.entriesRecord, manifest.stateRecord} {
		if name != "" && !postureRecordNamePattern.MatchString(name) {
			return nil, failed("names a record outside the store")
		}
	}
	return manifest, nil
}

// One share certificate's fields, each once and in order.
func decodePostureShareCert(encoded []byte) (*postureShareCert, error) {
	shareCert := &postureShareCert{}
	failed := fmt.Errorf("%w: manifest share certificate does not decode", ErrPostureStoreFailed)
	last := protowire.Number(0)
	for 0 < len(encoded) {
		number, wireType, tagLength := protowire.ConsumeTag(encoded)
		if tagLength < 0 || number <= last {
			return nil, failed
		}
		last = number
		encoded = encoded[tagLength:]
		switch {
		case number == postureShareFieldGeneration && wireType == protowire.VarintType:
			value, length := protowire.ConsumeVarint(encoded)
			if length < 0 {
				return nil, failed
			}
			shareCert.generation = value
			encoded = encoded[length:]
		case (number == postureShareFieldShareId || number == postureShareFieldCert) && wireType == protowire.BytesType:
			value, length := protowire.ConsumeBytes(encoded)
			if length < 0 {
				return nil, failed
			}
			if number == postureShareFieldShareId {
				shareCert.shareId = bytes.Clone(value)
			} else {
				shareCert.cert = bytes.Clone(value)
			}
			encoded = encoded[length:]
		default:
			return nil, failed
		}
	}
	if len(shareCert.shareId) == 0 || len(shareCert.cert) == 0 {
		return nil, failed
	}
	return shareCert, nil
}

// A record's name for a generation, such as rows-7.
func postureRecordName(kind string, generation uint64) string {
	return fmt.Sprintf("%s-%d", kind, generation)
}

// Files in one directory, one per record (NewFilePostureStore). Writes go to the file as the caller makes them, so a
// caller that writes in small pieces buffers them first.
type filePostureStore struct {
	directoryPath string
}

// The prefix a write's temp file takes, which List never shows and NewFilePostureStore sweeps.
const filePostureTempPrefix = ".write-"

// A store of one file per record in directoryPath, which it makes, 0700, at its first write. A write is a temp file
// in the same directory, written, fsynced and closed, then renamed over the record, then the directory fsynced, so a
// kill leaves the old record or the new one (§22.9's no torn writes). Opening sweeps what a killed write left.
//
// Use one directory per network, in the VPN component's own container: never an app group, and never the sidecar
// role's state directory (DESIGN-DETAILS 4.2.2). NewSealedPostureStore wraps it there.
func NewFilePostureStore(directoryPath string) (PostureStore, error) {
	if directoryPath == "" {
		return nil, fmt.Errorf("%w: no directory", ErrPostureStoreFailed)
	}
	self := &filePostureStore{directoryPath: directoryPath}
	entries, err := os.ReadDir(directoryPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, postureStoreFault(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), filePostureTempPrefix) {
			if err := os.Remove(filepath.Join(directoryPath, entry.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, postureStoreFault(err)
			}
		}
	}
	return self, nil
}

// The record's path, or an error for a name outside the store.
func (self *filePostureStore) path(name string) (string, error) {
	if !postureRecordNamePattern.MatchString(name) {
		return "", fmt.Errorf("%w: a record name outside the store", ErrPostureStoreFailed)
	}
	return filepath.Join(self.directoryPath, name), nil
}

// Answers ErrPostureStoreAbsent only for a file that is not there.
func (self *filePostureStore) Open(name string) (io.ReadCloser, error) {
	path, err := self.path(name)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrPostureStoreAbsent
	}
	if err != nil {
		return nil, postureStoreFault(err)
	}
	return &filePostureReader{file: file}, nil
}

// Temp file, write, fsync, close, rename, fsync the directory, with a barrier around the fsync and the rename.
func (self *filePostureStore) Write(name string, write func(writer io.Writer) error) (returnErr error) {
	path, err := self.path(name)
	if err != nil {
		return err
	}
	if err := self.makeDirectory(); err != nil {
		return err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return postureStoreFault(err)
	}
	tempPath := filepath.Join(self.directoryPath, filePostureTempPrefix+hex.EncodeToString(suffix))
	file, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return postureStoreFault(err)
	}
	renamed := false
	defer func() {
		if !renamed {
			file.Close()
			os.Remove(tempPath)
		}
	}()
	if err := write(&filePostureWriter{file: file}); err != nil {
		return err
	}
	testHookBarrier("posture_store.sync.before", name)
	if err := file.Sync(); err != nil {
		return postureStoreFault(err)
	}
	testHookBarrier("posture_store.sync.after", name)
	// windows renames no open file
	if err := file.Close(); err != nil {
		return postureStoreFault(err)
	}
	testHookBarrier("posture_store.rename.before", name)
	if err := os.Rename(tempPath, path); err != nil {
		return postureStoreFault(err)
	}
	renamed = true
	testHookBarrier("posture_store.rename.after", name)
	return syncPostureDirectory(self.directoryPath)
}

// Removes the file, then makes the removal durable.
func (self *filePostureStore) Remove(name string) error {
	path, err := self.path(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return postureStoreFault(err)
	}
	return syncPostureDirectory(self.directoryPath)
}

// Every record name in the directory, temp files and other files left out. A directory not yet made holds none.
func (self *filePostureStore) List() ([]string, error) {
	entries, err := os.ReadDir(self.directoryPath)
	if errors.Is(err, fs.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, postureStoreFault(err)
	}
	names := []string{}
	for _, entry := range entries {
		if entry.Type().IsRegular() && postureRecordNamePattern.MatchString(entry.Name()) {
			names = append(names, entry.Name())
		}
	}
	slices.Sort(names)
	return names, nil
}

// Makes the directory, 0700, and makes its entry durable in its parent.
func (self *filePostureStore) makeDirectory() error {
	info, err := os.Stat(self.directoryPath)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%w: the store's path is not a directory", ErrPostureStoreFailed)
		}
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return postureStoreFault(err)
	}
	if err := os.MkdirAll(self.directoryPath, 0o700); err != nil {
		return postureStoreFault(err)
	}
	return syncPostureDirectory(filepath.Dir(self.directoryPath))
}

// fsyncs a directory. Windows opens no directory for fsync, and NTFS journals the rename itself.
func syncPostureDirectory(directoryPath string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(directoryPath)
	if err != nil {
		return postureStoreFault(err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return postureStoreFault(err)
	}
	return nil
}

// A store's error as a failure with only its bare cause, since an os error carries its path (I-13).
func postureStoreFault(err error) error {
	if errors.Is(err, ErrPostureStoreAbsent) || errors.Is(err, ErrPostureStoreFailed) {
		return err
	}
	for cause := errors.Unwrap(err); cause != nil; cause = errors.Unwrap(err) {
		err = cause
	}
	return fmt.Errorf("%w: %v", ErrPostureStoreFailed, err)
}

// A record on its way to the disk, whose errors lose their path.
type filePostureWriter struct {
	file *os.File
}

// Appends p.
func (self *filePostureWriter) Write(p []byte) (int, error) {
	n, err := self.file.Write(p)
	if err != nil {
		return n, postureStoreFault(err)
	}
	return n, nil
}

// A record open for reading, whose errors lose their path.
type filePostureReader struct {
	file *os.File
}

// Passes an end of file through as it is.
func (self *filePostureReader) Read(p []byte) (int, error) {
	n, err := self.file.Read(p)
	if err != nil && err != io.EOF {
		return n, postureStoreFault(err)
	}
	return n, err
}

// Closes the file.
func (self *filePostureReader) Close() error {
	return self.file.Close()
}
