// The bridge ledger (DESIGN-DETAILS 12.2.2 and 12.2.3, QD-667 and QD-668): what every sealed bridge body means at
// one pin, judged where its entry lands and frozen into the config head at the fold.
//
//	judge     JudgeBridgeBody, the log's BridgeBodyJudge (ConfigLogSettings), runs for each BridgeRoute and
//	          BridgeMap filing as its entry takes effect, with the state the entry lands on: S(k-1) when it is judged,
//	          R_b(k-1) when a base b re-applies it. Its verdict (Standing, Approved with its facts, Refused, Unopened
//	          with its generation) rides the BridgeLogStatement the state's fold holds, as SignerAdmin does. A keyless
//	          verifier installs none and judges nothing.
//	rows      the head's bridge/ledger/ files: a manifest of the files and their hashes, and rows by kind, which a
//	          writer freezes at each fold and every full reader standing under the previous base checks
//	          (bridge_ledger_fold.go). Read one row at a time through BridgeLedgerFileReader, which hashes the bytes
//	          it read against the manifest
//	ledger    OpenBridgeLedger: the rows, then the state's unfolded statements in log order, each by the landed
//	          body-level rules (bridge_statement_rules.go) and its verdict
//
// So a ledger is a function of the newest base's head and rows, the entries since its fold with their verdicts and the
// generation keys, and of nothing a reader remembers (LedgerEqual).
//
// testHookSecret runs where a body's key derives, inside OpenConfigBody. A judge is safe for concurrent use when its
// RepoKeyAt and ReadHead are, since a StateAt rebuild re-applies entries on any goroutine. On every leg, with no
// connect import.

package sidecar

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

const (
	// BridgeLedgerManifest.format.
	bridgeLedgerFormat = 1
	// The shard widths a manifest may name.
	bridgeLedgerShardBitsNarrow = 8
	bridgeLedgerShardBitsWide   = 16
)

var (
	// A head's ledger files are not a ledger: a manifest that does not parse or does not match the files, a file whose
	// bytes do not hash to the manifest's, or a row that does not parse.
	ErrBridgeLedgerMalformed = errors.New("bridge ledger malformed")
	// The opened bodies of the unfolded statements pass BridgeLedgerSettings.UnfoldedBodyMaxByteCount: the reader
	// alarms ledger_over_budget and keeps what it held.
	ErrBridgeLedgerOverBudget = errors.New("bridge ledger over budget")
)

// Tunables of reading and folding a ledger. A verdict rides on AddressTombstoneTimeout, DrainMaximum, BodyListMaxCount
// and SiteIdMaxByteCount, and the manifest's hashes on RuleShardRowCount, so every reader of a network reads their
// defaults, which are the protocol's values, and only a test changes them.
type BridgeLedgerSettings struct {
	// A ledger file is read this many bytes at a time, and no row is longer: 64 KiB, against the rows' 3 KB at most.
	// Non-positive is the default.
	ChunkByteCount int
	// The most bytes the unfolded statements' opened bodies may hold at one reader: 4 MiB, against a few KB in
	// practice. Past it the open refuses with ErrBridgeLedgerOverBudget. Non-positive bounds nothing.
	UnfoldedBodyMaxByteCount int
	// The rule rows past which the rule shards widen from 8 to 16 bits: 262,144. Every writer and checker of a
	// network reads the default, since the shard width is part of what the manifest hashes; a test lowers it.
	RuleShardRowCount int
	// How long a released overlay address routes to no new holder, by the log's time (§17.4, I-14): 30 days.
	// Non-positive is the default.
	AddressTombstoneTimeout time.Duration
	// The longest drain a route's or map's drain_seconds may name (§17.8's disposition): 3,600 s. Non-positive is the
	// default.
	DrainMaximum time.Duration
	// The most prefixes one BridgeRoute advertises, port ranges one BridgeMap names, or exits one BridgeEgress lists:
	// 64. Non-positive is the default.
	BodyListMaxCount int
	// The longest site_id a BridgeRoute names: 32 bytes. Non-positive is the default.
	SiteIdMaxByteCount int
}

// DESIGN-DETAILS 12.2.2's values, with §17.4's and §17.8's limits.
func DefaultBridgeLedgerSettings() *BridgeLedgerSettings {
	return &BridgeLedgerSettings{
		ChunkByteCount:           64 * 1024,
		UnfoldedBodyMaxByteCount: 4 * 1024 * 1024,
		RuleShardRowCount:        262144,
		AddressTombstoneTimeout:  30 * 24 * time.Hour,
		DrainMaximum:             time.Hour,
		BodyListMaxCount:         64,
		SiteIdMaxByteCount:       32,
	}
}

// The settings as a ledger reads them: a copy, each field that takes a default where it is non-positive given it. Nil
// is the defaults. The caller's settings are never changed.
func bridgeLedgerSettingsOrDefault(settings *BridgeLedgerSettings) *BridgeLedgerSettings {
	defaults := DefaultBridgeLedgerSettings()
	if settings == nil {
		return defaults
	}
	read := *settings
	if read.AddressTombstoneTimeout <= 0 {
		read.AddressTombstoneTimeout = defaults.AddressTombstoneTimeout
	}
	if read.DrainMaximum <= 0 {
		read.DrainMaximum = defaults.DrainMaximum
	}
	if read.BodyListMaxCount <= 0 {
		read.BodyListMaxCount = defaults.BodyListMaxCount
	}
	if read.SiteIdMaxByteCount <= 0 {
		read.SiteIdMaxByteCount = defaults.SiteIdMaxByteCount
	}
	return &read
}

// What a judge made of one route's or map's body where its entry landed.
type BridgeBodyVerdictKind int

const (
	// The body opened and carries no approval: active only where a standing grant covers it, which the compile
	// holds to §8's rules.
	BridgeBodyStanding BridgeBodyVerdictKind = iota + 1
	// The body opened and its approval verified: Facts.
	BridgeBodyApproved
	// The seal or padding failed, the body carries a field this build cannot name, or its approval did not verify:
	// Reason. A seal that failed is the reader's alarm.
	BridgeBodyRefused
	// The body's generation is not held: Generation. The id is held and nothing is active.
	BridgeBodyUnopened
)

// One judge's verdict on a body.
type BridgeBodyVerdict struct {
	Kind BridgeBodyVerdictKind
	// Approved's.
	Facts *BridgeApprovalFacts
	// Refused's.
	Reason error
	// Unopened's.
	Generation uint64
}

// What judges bridge bodies at a reader holding config keys: ConfigLogSettings.BridgeBodyJudge, nil at every keyless
// verifier, which then judges no body (DESIGN-DETAILS 12.2.3).
type BridgeBodyJudge struct {
	// The generation keys the reader holds: nil for a generation it lacks, whose bodies are then Unopened. Nil holds
	// none.
	RepoKeyAt func(generation uint64) *EvsRepoKey
	// The config head a base names, read as the rows source reads it for the head check: the head at configVersion
	// whose chain value is configHeadSha256. The fold check reads the previous base's head through it. Nil checks
	// no fold, as a forwarding role's judge, which takes the head's rows (DESIGN-DETAILS 4.2.1).
	ReadHead func(configVersion uint64, configHeadSha256 []byte) (*ConfigHead, error)
	// Nil is the defaults.
	Settings *BridgeLedgerSettings

	// how an approval verifies; nil is the receiver state's CheckBridgeApproval (tests set it)
	checkApproval BridgeApprovalCheck
}

// Verifies the BridgeApproval a rule's body carries, for the statement that filed it and its opened body, a
// *bridge.BridgeRouteBody or *bridge.BridgeMapBody, on before, the state the entry lands on. An error voids the rule.
type BridgeApprovalCheck func(before *ConfigState, statement *BridgeLogStatement, body proto.Message, approval *bridge.BridgeApproval) (*BridgeApprovalFacts, error)

// The judge's generation keys, none for nil.
func (self *BridgeBodyJudge) repoKeyAt() func(generation uint64) *EvsRepoKey {
	if self == nil || self.RepoKeyAt == nil {
		return func(generation uint64) *EvsRepoKey { return nil }
	}
	return self.RepoKeyAt
}

// DESIGN-DETAILS 12.2.3's JudgeBridgeBody: opens a route's or map's sealed body with the judge's keys and verifies its
// approval on before, the state the entry lands on. A statement that files no rule has no verdict, nil.
func (self *BridgeBodyJudge) Judge(before *ConfigState, statement *BridgeLogStatement) *BridgeBodyVerdict {
	var body proto.Message
	switch statement.SignedType {
	case bridge.SignedType_SIGNED_BRIDGE_ROUTE:
		body = &bridge.BridgeRouteBody{}
	case bridge.SignedType_SIGNED_BRIDGE_MAP:
		body = &bridge.BridgeMapBody{}
	default:
		return nil
	}
	generation, err := OpenConfigBody(statement.SealedBody, statement.Seal, self.repoKeyAt(), body)
	if errors.Is(err, ErrConfigSealGenerationMissing) {
		return &BridgeBodyVerdict{Kind: BridgeBodyUnopened, Generation: generation}
	}
	if err != nil {
		return &BridgeBodyVerdict{Kind: BridgeBodyRefused, Reason: err}
	}
	if len(body.ProtoReflect().GetUnknown()) != 0 {
		return &BridgeBodyVerdict{Kind: BridgeBodyRefused, Reason: errors.New("the body carries a field this build cannot name")}
	}
	var approval *bridge.BridgeApproval
	switch typed := body.(type) {
	case *bridge.BridgeRouteBody:
		approval = typed.GetApproval()
	case *bridge.BridgeMapBody:
		approval = typed.GetApproval()
	}
	if approval == nil {
		return &BridgeBodyVerdict{Kind: BridgeBodyStanding}
	}
	check := self.checkApproval
	if check == nil {
		check = func(before *ConfigState, statement *BridgeLogStatement, body proto.Message, approval *bridge.BridgeApproval) (*BridgeApprovalFacts, error) {
			return before.CheckBridgeApproval(statement, body, approval)
		}
	}
	facts, err := check(before, statement, body, approval)
	if err != nil {
		return &BridgeBodyVerdict{Kind: BridgeBodyRefused, Reason: err}
	}
	if facts == nil {
		return &BridgeBodyVerdict{Kind: BridgeBodyRefused, Reason: errors.New("an approval check that answered nothing")}
	}
	return &BridgeBodyVerdict{Kind: BridgeBodyApproved, Facts: facts}
}

// The judge this state's log installs, nil for none.
func (self *ConfigState) bridgeBodyJudge() *BridgeBodyJudge {
	if self.history == nil || self.history.settings == nil {
		return nil
	}
	return self.history.settings.BridgeBodyJudge
}

// The state an entry at n lands on, as the judge reads it: state's rows, which hold nothing of the entry yet, at
// (n-1, A_{n-1}) and the entry's time, as a base's re-application builds R_b(n-1).
func bridgeStateBefore(state *ConfigState, n uint64, timeMs int64) *ConfigState {
	before := configCopyState(state)
	if chain, ok := state.chainAt(n - 1); ok && 0 < n {
		before.n, before.chain = n-1, chain
	}
	before.timeMs = timeMs
	return before
}

// The path of the rule shard a rule id falls in at a shard width.
func BridgeLedgerRulesPath(ruleId []byte, shardBits uint32) string {
	if shardBits == bridgeLedgerShardBitsWide && 2 <= len(ruleId) {
		return ConfigHeadBridgeLedgerRulesPrefix + hex.EncodeToString(ruleId[:1]) + "/" + hex.EncodeToString(ruleId[1:2])
	}
	if len(ruleId) == 0 {
		return ConfigHeadBridgeLedgerRulesPrefix + "00"
	}
	return ConfigHeadBridgeLedgerRulesPrefix + hex.EncodeToString(ruleId[:1])
}

// Whether a path is the ledger's, the manifest included.
func bridgeLedgerPath(path string) bool {
	return strings.HasPrefix(path, "bridge/ledger/")
}

// Rows in file order, one decoded at a time, so no file is decoded whole. Next answers io.EOF at the end, once the
// bytes read hash to the manifest's sha256 and the rows number its row_count; anything else is
// ErrBridgeLedgerMalformed. For one goroutine.
type BridgeLedgerFileReader interface {
	Next() (proto.Message, error)
	Close()
}

// The folded rows a ledger opens over: a config head's bridge/ledger/ files, which BRIDGE-M4-16's compile also reads
// through LedgerFile, or none.
type BridgeLedgerRows interface {
	// The manifest, nil for a head that holds none: an empty ledger at FoldedThrough.
	Manifest() *protocol.BridgeLedgerManifest
	// The position the rows hold every bridge statement through: the manifest's, else the head's fold.
	FoldedThrough() uint64
	// A reader of one file the manifest names, nil and no error for one it does not name.
	LedgerFile(path string) (BridgeLedgerFileReader, error)
}

// One ledger file's rows read from its bytes as a stream: one length-delimited row of field 1 at a time, its bytes
// hashed as they are read.
type bridgeLedgerStreamReader struct {
	source       *bufio.Reader
	digest       hash.Hash
	wantSha256   []byte
	wantRowCount uint64
	rowCount     uint64
	maxRowBytes  int
	newRow       func() proto.Message
	done         bool
}

// A reader of a file's bytes as the manifest names it: its hash, its row count and a fresh row of its kind.
func newBridgeLedgerStreamReader(source io.Reader, file *protocol.BridgeLedgerFile, newRow func() proto.Message, settings *BridgeLedgerSettings) *bridgeLedgerStreamReader {
	digest := sha256.New()
	chunkByteCount := settings.ChunkByteCount
	if chunkByteCount <= 0 {
		chunkByteCount = DefaultBridgeLedgerSettings().ChunkByteCount
	}
	return &bridgeLedgerStreamReader{
		source:       bufio.NewReaderSize(io.TeeReader(source, digest), chunkByteCount),
		digest:       digest,
		wantSha256:   file.GetSha256(),
		wantRowCount: file.GetRowCount(),
		maxRowBytes:  chunkByteCount,
		newRow:       newRow,
	}
}

// The next row, io.EOF at a clean end whose hash and count the manifest names.
func (self *bridgeLedgerStreamReader) Next() (proto.Message, error) {
	if self.done {
		return nil, io.EOF
	}
	tag, err := binary.ReadUvarint(self.source)
	if errors.Is(err, io.EOF) {
		self.done = true
		if !bytes.Equal(self.digest.Sum(nil), self.wantSha256) {
			return nil, fmt.Errorf("%w: a file whose bytes are not the manifest's", ErrBridgeLedgerMalformed)
		}
		if self.rowCount != self.wantRowCount {
			return nil, fmt.Errorf("%w: %d rows, the manifest %d", ErrBridgeLedgerMalformed, self.rowCount, self.wantRowCount)
		}
		return nil, io.EOF
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBridgeLedgerMalformed, err)
	}
	if tag != uint64(protowire.EncodeTag(1, protowire.BytesType)) {
		return nil, fmt.Errorf("%w: a field this build cannot name", ErrBridgeLedgerMalformed)
	}
	length, err := binary.ReadUvarint(self.source)
	if err != nil || uint64(self.maxRowBytes) < length {
		return nil, fmt.Errorf("%w: a row of %d bytes", ErrBridgeLedgerMalformed, length)
	}
	rowBytes := make([]byte, length)
	if _, err := io.ReadFull(self.source, rowBytes); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBridgeLedgerMalformed, err)
	}
	row := self.newRow()
	if err := proto.Unmarshal(rowBytes, row); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBridgeLedgerMalformed, err)
	}
	if bridgeLedgerUnknownFields(row) {
		return nil, fmt.Errorf("%w: a row with a field this build cannot name", ErrBridgeLedgerMalformed)
	}
	self.rowCount += 1
	return row, nil
}

// Nothing to release: the bytes are the head's.
func (self *bridgeLedgerStreamReader) Close() {
}

// Whether a message or any message it holds carries a field this build cannot name.
func bridgeLedgerUnknownFields(message proto.Message) bool {
	unknown := false
	var walk func(message proto.Message)
	walk = func(message proto.Message) {
		reflected := message.ProtoReflect()
		if len(reflected.GetUnknown()) != 0 {
			unknown = true
			return
		}
		for i := range reflected.Descriptor().Fields().Len() {
			field := reflected.Descriptor().Fields().Get(i)
			if field.Message() == nil || !reflected.Has(field) {
				continue
			}
			if field.IsList() {
				list := reflected.Get(field).List()
				for j := range list.Len() {
					walk(list.Get(j).Message().Interface())
				}
				continue
			}
			walk(reflected.Get(field).Message().Interface())
		}
	}
	walk(message)
	return unknown
}

// A fresh row of the kind a ledger path holds, nil for a path that holds none.
func bridgeLedgerRowOf(path string) func() proto.Message {
	switch {
	case path == ConfigHeadBridgeLedgerAddressesPath:
		return func() proto.Message { return &protocol.BridgeLedgerAddressRow{} }
	case path == ConfigHeadBridgeLedgerEgressPath:
		return func() proto.Message { return &protocol.BridgeLedgerEgressRow{} }
	case path == ConfigHeadBridgeLedgerAliasesPath:
		return func() proto.Message { return &protocol.BridgeLedgerAliasRow{} }
	case strings.HasPrefix(path, ConfigHeadBridgeLedgerRulesPrefix):
		return func() proto.Message { return &protocol.BridgeLedgerRuleRow{} }
	}
	return nil
}

// A config head's ledger files, checked against its manifest.
type bridgeLedgerHeadRows struct {
	head          *ConfigHead
	manifest      *protocol.BridgeLedgerManifest
	files         map[string]*protocol.BridgeLedgerFile
	foldedThrough uint64
	settings      *BridgeLedgerSettings
}

// The head's ledger as a row source: its manifest parses strictly, names format 1, the head's fold, a shard width of
// 8 or 16 and its files in path order, each a ledger path of that width with a 32-byte hash and rows; and the head
// holds exactly those files. A head with no manifest holds no ledger file, and is an empty ledger at its fold. A nil
// head is the empty ledger before any fold. The files' bytes are hashed as they are read.
func NewBridgeLedgerHeadRows(head *ConfigHead, settings *BridgeLedgerSettings) (BridgeLedgerRows, error) {
	settings = bridgeLedgerSettingsOrDefault(settings)
	rows := &bridgeLedgerHeadRows{head: head, files: map[string]*protocol.BridgeLedgerFile{}, settings: settings}
	if head == nil {
		return rows, nil
	}
	rows.foldedThrough = head.FoldedThrough()
	held := []string{}
	for _, path := range head.Paths() {
		if bridgeLedgerPath(path) && path != ConfigHeadBridgeLedgerManifestPath {
			held = append(held, path)
		}
	}
	manifestBytes := head.File(ConfigHeadBridgeLedgerManifestPath)
	if manifestBytes == nil {
		if len(held) != 0 {
			return nil, fmt.Errorf("%w: ledger files and no manifest", ErrBridgeLedgerMalformed)
		}
		return rows, nil
	}
	manifest := &protocol.BridgeLedgerManifest{}
	if err := proto.Unmarshal(manifestBytes, manifest); err != nil {
		return nil, fmt.Errorf("%w: manifest: %w", ErrBridgeLedgerMalformed, err)
	}
	switch {
	case bridgeLedgerUnknownFields(manifest):
		return nil, fmt.Errorf("%w: a manifest with a field this build cannot name", ErrBridgeLedgerMalformed)
	case manifest.GetFormat() != bridgeLedgerFormat:
		return nil, fmt.Errorf("%w: format %d", ErrBridgeLedgerMalformed, manifest.GetFormat())
	case manifest.GetFoldedThrough() != head.FoldedThrough():
		return nil, fmt.Errorf("%w: a manifest through %d in a head folded through %d", ErrBridgeLedgerMalformed, manifest.GetFoldedThrough(), head.FoldedThrough())
	case manifest.GetRuleShardBits() != bridgeLedgerShardBitsNarrow && manifest.GetRuleShardBits() != bridgeLedgerShardBitsWide:
		return nil, fmt.Errorf("%w: rule shards of %d bits", ErrBridgeLedgerMalformed, manifest.GetRuleShardBits())
	}
	named := []string{}
	for i, file := range manifest.GetFiles() {
		path := file.GetPath()
		if 0 < i && path <= manifest.GetFiles()[i-1].GetPath() {
			return nil, fmt.Errorf("%w: files out of path order", ErrBridgeLedgerMalformed)
		}
		if bridgeLedgerRowOf(path) == nil || !configHeadPathKnown(path) || len(file.GetSha256()) != sha256.Size || file.GetRowCount() == 0 {
			return nil, fmt.Errorf("%w: a file %q the manifest cannot name", ErrBridgeLedgerMalformed, path)
		}
		if shard, ok := strings.CutPrefix(path, ConfigHeadBridgeLedgerRulesPrefix); ok && strings.Contains(shard, "/") != (manifest.GetRuleShardBits() == bridgeLedgerShardBitsWide) {
			return nil, fmt.Errorf("%w: a rule shard %q of another width", ErrBridgeLedgerMalformed, path)
		}
		named = append(named, path)
		rows.files[path] = file
	}
	if !slices.Equal(named, held) {
		return nil, fmt.Errorf("%w: the head holds files the manifest does not name, or lacks one it does", ErrBridgeLedgerMalformed)
	}
	rows.manifest = manifest
	return rows, nil
}

// The manifest, nil for none.
func (self *bridgeLedgerHeadRows) Manifest() *protocol.BridgeLedgerManifest {
	return self.manifest
}

// The manifest's fold, else the head's.
func (self *bridgeLedgerHeadRows) FoldedThrough() uint64 {
	return self.foldedThrough
}

// A stream over one file the manifest names.
func (self *bridgeLedgerHeadRows) LedgerFile(path string) (BridgeLedgerFileReader, error) {
	file := self.files[path]
	if file == nil {
		return nil, nil
	}
	return newBridgeLedgerStreamReader(bytes.NewReader(self.head.files[path]), file, bridgeLedgerRowOf(path), self.settings), nil
}

// Every row of every file the manifest names, in path order and file order, one decoded at a time.
func bridgeLedgerEachRow(rows BridgeLedgerRows, each func(path string, row proto.Message) error) error {
	manifest := rows.Manifest()
	if manifest == nil {
		return nil
	}
	for _, file := range manifest.GetFiles() {
		reader, err := rows.LedgerFile(file.GetPath())
		if err != nil {
			return err
		}
		if reader == nil {
			return fmt.Errorf("%w: no reader of %q", ErrBridgeLedgerMalformed, file.GetPath())
		}
		err = func() error {
			defer reader.Close()
			for {
				row, err := reader.Next()
				if errors.Is(err, io.EOF) {
					return nil
				}
				if err != nil {
					return err
				}
				if err := each(file.GetPath(), row); err != nil {
					return err
				}
			}
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// Takes a head's ledger rows into the ledger, each file in its one order, refusing rows no writer folds: a key out of
// order or repeated, an id of the wrong size, a disposition with a body it never carries or without one it always
// does, a body this build cannot read whole, or an alias's release, which BRIDGE-M6-03 builds.
func (self *BridgeLedger) loadRows(rows BridgeLedgerRows) error {
	shardBits := uint32(bridgeLedgerShardBitsNarrow)
	if manifest := rows.Manifest(); manifest != nil {
		shardBits = manifest.GetRuleShardBits()
	}
	previousPath := ""
	var previousKey []byte
	return bridgeLedgerEachRow(rows, func(path string, row proto.Message) error {
		var key []byte
		var err error
		switch typed := row.(type) {
		case *protocol.BridgeLedgerAddressRow:
			key = binary.BigEndian.AppendUint32(nil, typed.GetHostBits())
			err = self.loadAddressRow(typed)
		case *protocol.BridgeLedgerRuleRow:
			key = typed.GetRuleId()
			if BridgeLedgerRulesPath(key, shardBits) != path {
				err = errors.New("a rule in another rule's shard")
			} else {
				err = self.loadRuleRow(typed)
			}
		case *protocol.BridgeLedgerEgressRow:
			key = typed.GetSubject()
			err = self.loadEgressRow(typed)
		case *protocol.BridgeLedgerAliasRow:
			key = binary.BigEndian.AppendUint32(bytes.Clone(typed.GetBody().GetShareId()), typed.GetBody().GetTargetIndex())
			err = self.loadAliasRow(typed)
		default:
			err = errors.New("a row of no ledger file")
		}
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrBridgeLedgerMalformed, path, err)
		}
		// rule shards sort by the id's leading bytes, so one order runs across them
		ruleShard := func(path string) bool { return strings.HasPrefix(path, ConfigHeadBridgeLedgerRulesPrefix) }
		if path != previousPath && !(ruleShard(path) && ruleShard(previousPath)) {
			previousKey = nil
		}
		if previousKey != nil && 0 <= bytes.Compare(previousKey, key) {
			return fmt.Errorf("%w: %s: rows out of their one order", ErrBridgeLedgerMalformed, path)
		}
		previousPath, previousKey = path, key
		return nil
	})
}

// One address row: a host's live address, or a tombstone with its release.
func (self *BridgeLedger) loadAddressRow(row *protocol.BridgeLedgerAddressRow) error {
	sidecarId, err := IdFromBytes(row.GetSidecarId())
	if err != nil {
		return err
	}
	hostBits := row.GetHostBits()
	switch {
	case !bridgeHostBitsValid(hostBits):
		return fmt.Errorf("host bits %#x", hostBits)
	case row.GetClaimedAt() == 0 || (row.GetReleasedAt() != 0 && row.GetReleasedAt() < row.GetClaimedAt()):
		return errors.New("a claim or release out of place")
	case row.GetReleasedAt() == 0 && row.GetReleasedMs() != 0:
		return errors.New("a release time with no release")
	}
	address := &BridgeLedgerAddress{SidecarId: sidecarId, HostBits: hostBits, ClaimedAt: row.GetClaimedAt()}
	if row.GetReleasedAt() != 0 {
		address.folded = &bridgeRelease{n: row.GetReleasedAt(), timeMs: row.GetReleasedMs(), timeMsKnown: true}
	} else if self.bySidecar[sidecarId] != nil {
		return errors.New("two live addresses for one sidecar")
	}
	self.holdAddress(address)
	return nil
}

// The withdrawal a rule row carries, nil for none.
func bridgeLedgerWithdrawalOfRow(row *protocol.BridgeLedgerRuleRow) (*BridgeLedgerWithdrawal, error) {
	if row.GetWithdrawnAt() == 0 {
		if row.GetWithdrawnMs() != 0 || len(row.GetWithdrawnBy()) != 0 || row.GetWithdrawnByAdmin() || row.GetWithdrawMode() != 0 {
			return nil, errors.New("withdrawal fields with no withdrawal")
		}
		return nil, nil
	}
	signer, err := IdFromBytes(row.GetWithdrawnBy())
	if err != nil {
		return nil, err
	}
	if row.GetWithdrawMode() != bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET && row.GetWithdrawMode() != bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN {
		return nil, fmt.Errorf("withdraw mode %d", row.GetWithdrawMode())
	}
	return &BridgeLedgerWithdrawal{
		At: row.GetWithdrawnAt(), TimeMs: row.GetWithdrawnMs(), Mode: row.GetWithdrawMode(), Signer: signer, SignerAdmin: row.GetWithdrawnByAdmin(),
	}, nil
}

// One rule row: a reservation, or a route or map with its disposition, body and approval.
func (self *BridgeLedger) loadRuleRow(row *protocol.BridgeLedgerRuleRow) error {
	if len(row.GetRuleId()) != bridgeRuleIdByteCount {
		return fmt.Errorf("a rule id of %d bytes", len(row.GetRuleId()))
	}
	withdrawal, err := bridgeLedgerWithdrawalOfRow(row)
	if err != nil {
		return err
	}
	key := string(row.GetRuleId())
	if row.GetDisposition() == protocol.BridgeLedgerDisposition_BRIDGE_LEDGER_DISPOSITION_RESERVED {
		if withdrawal == nil || row.GetSignedType() != 0 || len(row.GetOwner()) != 0 || row.GetRoute() != nil || row.GetMap() != nil ||
			row.GetFirstAt() != 0 || len(row.GetApprovalId()) != 0 || row.GetRetainUntilMs() != 0 {
			return errors.New("a reservation with a filing's fields")
		}
		self.reserved[key] = withdrawal
		return nil
	}
	signedType := bridge.SignedType(row.GetSignedType())
	if signedType != bridge.SignedType_SIGNED_BRIDGE_ROUTE && signedType != bridge.SignedType_SIGNED_BRIDGE_MAP {
		return fmt.Errorf("a rule of type %d", row.GetSignedType())
	}
	owner, err := IdFromBytes(row.GetOwner())
	if err != nil {
		return err
	}
	if row.GetFirstAt() == 0 || row.GetNewestAt() < row.GetFirstAt() {
		return errors.New("filings out of place")
	}
	rule := &BridgeLedgerRule{
		RuleId: bytes.Clone(row.GetRuleId()), SignedType: signedType, Owner: owner,
		FirstAt: row.GetFirstAt(), FirstMs: row.GetFirstMs(), NewestAt: row.GetNewestAt(), NewestMs: row.GetNewestMs(),
		Expires: row.GetExpires(), Standing: row.GetStanding(), Withdrawn: withdrawal,
	}
	for _, routeRuleId := range row.GetRouteRuleIds() {
		rule.RouteRuleIds = append(rule.RouteRuleIds, bytes.Clone(routeRuleId))
	}
	hasBody := row.GetRoute() != nil || row.GetMap() != nil
	switch row.GetDisposition() {
	case protocol.BridgeLedgerDisposition_BRIDGE_LEDGER_DISPOSITION_VOID:
		if hasBody || len(row.GetApprovalId()) != 0 || row.GetStanding() {
			return errors.New("a void rule with a body or an approval")
		}
		rule.Void = true
	case protocol.BridgeLedgerDisposition_BRIDGE_LEDGER_DISPOSITION_ACTIVE, protocol.BridgeLedgerDisposition_BRIDGE_LEDGER_DISPOSITION_WITHDRAWN:
		if (withdrawal != nil) != (row.GetDisposition() == protocol.BridgeLedgerDisposition_BRIDGE_LEDGER_DISPOSITION_WITHDRAWN) {
			return errors.New("a withdrawal and a disposition at odds")
		}
		switch {
		case signedType == bridge.SignedType_SIGNED_BRIDGE_ROUTE && row.GetRoute() != nil && row.GetMap() == nil:
			if row.GetRoute().GetApproval() != nil {
				return errors.New("a body that keeps its approval")
			}
			if err := bridgeCheckRouteBody(row.GetRoute(), self.settings); err != nil {
				return err
			}
			rule.Route = row.GetRoute()
		case signedType == bridge.SignedType_SIGNED_BRIDGE_MAP && row.GetMap() != nil && row.GetRoute() == nil:
			if row.GetMap().GetApproval() != nil {
				return errors.New("a body that keeps its approval")
			}
			if err := bridgeCheckMapBody(row.GetMap(), self.settings); err != nil {
				return err
			}
			rule.Map = row.GetMap()
		default:
			return errors.New("a rule in force with no body of its kind")
		}
		if len(row.GetApprovalId()) != 0 {
			approvalId, err := IdFromBytes(row.GetApprovalId())
			if err != nil || row.GetStanding() {
				return errors.New("an approval malformed, or beside a standing grant")
			}
			if err := self.countApproval(approvalId, row.GetApprovalUses(), rule.RuleId); err != nil {
				return err
			}
			rule.ApprovalId, rule.ApprovalNotAfterMs, rule.ApprovalUses = approvalId, row.GetApprovalNotAfterMs(), max(1, row.GetApprovalUses())
		} else if !row.GetStanding() {
			return errors.New("a rule in force under neither a decision nor a standing grant")
		}
	default:
		return fmt.Errorf("disposition %d", row.GetDisposition())
	}
	if self.rules[key] != nil || self.reserved[key] != nil {
		return errors.New("a rule id twice")
	}
	self.rules[key] = rule
	if rule.Active() && rule.Route != nil && rule.Route.GetExposedPrefix() != nil {
		first, last, _ := bridgeUpperRangeOf(rule.Route.GetExposedPrefix())
		// an HA replica shares the range, which the lowest id holds: rows come in id order
		if held := self.upperRangeHolding(first, last); held == nil {
			self.upper = append(self.upper, bridgeUpperRange{first: first, last: last, rule: rule})
		}
	}
	return nil
}

// One subject's egress spec.
func (self *BridgeLedger) loadEgressRow(row *protocol.BridgeLedgerEgressRow) error {
	subject, err := IdFromBytes(row.GetSubject())
	if err != nil {
		return err
	}
	egress := &BridgeLedgerEgress{Subject: subject, Mode: row.GetMode(), At: row.GetAt(), ExitTagId: bytes.Clone(row.GetExitTagId())}
	switch {
	case row.GetAt() == 0:
		return errors.New("a spec with no entry")
	case row.GetMode() != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS && row.GetMode() != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE:
		return fmt.Errorf("mode %d", row.GetMode())
	case row.GetMode() == bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE && (len(row.GetExitSidecarIds()) != 0 || len(row.GetExitTagId()) != 0):
		return errors.New("exits under none")
	case len(row.GetExitTagId()) != 0 && (len(row.GetExitTagId()) != len(Id{}) || len(row.GetExitSidecarIds()) != 0):
		return errors.New("an exit tag malformed, or beside exits")
	case self.settings.BodyListMaxCount < len(row.GetExitSidecarIds()):
		return fmt.Errorf("%d exits", len(row.GetExitSidecarIds()))
	}
	for _, exitBytes := range row.GetExitSidecarIds() {
		exitId, err := IdFromBytes(exitBytes)
		if err != nil || slices.Contains(egress.ExitSidecarIds, exitId) {
			return errors.New("an exit malformed or named twice")
		}
		egress.ExitSidecarIds = append(egress.ExitSidecarIds, exitId)
	}
	self.egress[subject] = egress
	return nil
}

// One alias.
func (self *BridgeLedger) loadAliasRow(row *protocol.BridgeLedgerAliasRow) error {
	signer, err := IdFromBytes(row.GetSigner())
	if err != nil {
		return err
	}
	if row.GetAt() == 0 || row.GetReleasedAt() != 0 || row.GetReleasedMs() != 0 || row.GetBody() == nil {
		return errors.New("an alias out of place, or released, which this build cannot read")
	}
	if err := self.holdAlias(row.GetBody(), nil); err != nil {
		return err
	}
	self.aliases = append(self.aliases, &BridgeLedgerAlias{Body: row.GetBody(), Signer: signer, At: row.GetAt()})
	return nil
}
