// The config head (§7.9's Repo paragraph): the files of the config repo's file-mode main ref at one config_version,
// in the layout plan-TEAM-config-head-format #1 settles.
//
//	genesis                          the Signed Genesis, verbatim, which the first head writes and every head keeps
//	fold/<d>/<i>                     the i-th fold, i from 1 and d = i / 1024, each zero-padded to 8 digits: one
//	                                 ConfigFold per head that advanced folded_through, its records in (after,
//	                                 folded_through] in n order, no BASE
//	service_settings                 one Signed ServiceSettings, verbatim
//	versioning_rules                 one Signed VersioningRules, verbatim
//	bridge/block                     one Signed BridgeBlock, verbatim
//	bridge/share/<share_id hex>      a BridgeShareSigner (§17.9)
//	socket/key                       K_sock's SocketKeyFile (plan-SOCK-ksock-rotation)
//	policy.hujson                    the policy's source bytes (§8)
//	tags groups rules names labels resolve
//	                                 one deterministically encoded protobuf each
//
// Only ServiceSettings, VersioningRules and BridgeBlock ride heads alone (plan-TEAM-config-head-format #2): every record
// with a StatementHeader enters the log at once, so a head holds those only as the fold's records. A config head takes
// effect at the base that names it (§7.9's state row).
//
// What a head check asks of a base (§7.9's BASE row): the head's genesis is the log's, it holds as records exactly the
// statements and ticks in (the previous base's folded_through, folded_through], each by id with its carrying position
// and none past it, and its compile is the base's rows. CheckConfigBase runs those; that the head chains to genesis
// through config writers' pushes is the evs ref's, which ConfigClient reads (TEAM-M2-10).
//
// A head knows every path it may hold, and refuses one it does not, so a writer and a reader of one version agree on
// what a head compiles from. Immutable once built; every accessor returns a copy. On every leg, with no connect import.
// Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The paths of a config head (plan-TEAM-config-head-format #1).
const (
	ConfigHeadGenesisPath         = "genesis"
	ConfigHeadServiceSettingsPath = "service_settings"
	ConfigHeadVersioningRulesPath = "versioning_rules"
	ConfigHeadBridgeBlockPath     = "bridge/block"
	ConfigHeadBridgeSharePrefix   = "bridge/share/"
	ConfigHeadSocketKeyPath       = SocketKeyFilePath
	ConfigHeadPolicyPath          = "policy.hujson"
	ConfigHeadTagsPath            = "tags"
	ConfigHeadGroupsPath          = "groups"
	ConfigHeadRulesPath           = "rules"
	ConfigHeadNamesPath           = "names"
	ConfigHeadLabelsPath          = "labels"
	ConfigHeadResolvePath         = "resolve"

	configHeadFoldPrefix = "fold/"
	// folds per fold/<d>/ directory
	configHeadFoldsPerDir = 1024
	// fold/<d>/<i>'s digits each
	configHeadFoldDigits = 8
)

// A bridge/share file's name: a share_id, 16 B, in lowercase hex.
const configHeadShareIdHexLength = 2 * 16

// The single-file paths a head may hold.
var configHeadFilePaths = map[string]bool{
	ConfigHeadGenesisPath:         true,
	ConfigHeadServiceSettingsPath: true,
	ConfigHeadVersioningRulesPath: true,
	ConfigHeadBridgeBlockPath:     true,
	ConfigHeadSocketKeyPath:       true,
	ConfigHeadPolicyPath:          true,
	ConfigHeadTagsPath:            true,
	ConfigHeadGroupsPath:          true,
	ConfigHeadRulesPath:           true,
	ConfigHeadNamesPath:           true,
	ConfigHeadLabelsPath:          true,
	ConfigHeadResolvePath:         true,
}

var (
	// The head's files are not a head: an unknown path, a fold out of place, a malformed record or a genesis that
	// does not verify.
	ErrConfigHeadMalformed = errors.New("config head malformed")
	// The head is not the one the base needs: another genesis, records missing or extra, or another compile.
	ErrConfigHeadMismatch = errors.New("config head mismatch")
)

// fold/<d>/<i>, the path of the i-th fold, i from 1.
func ConfigFoldPath(i uint64) string {
	return fmt.Sprintf("%s%0*d/%0*d", configHeadFoldPrefix, configHeadFoldDigits, i/configHeadFoldsPerDir, configHeadFoldDigits, i)
}

// The fold index a path names, false for a path that is no fold's.
func configFoldIndex(path string) (uint64, bool) {
	rest, ok := strings.CutPrefix(path, configHeadFoldPrefix)
	if !ok {
		return 0, false
	}
	dirPart, indexPart, ok := strings.Cut(rest, "/")
	if !ok || len(dirPart) != configHeadFoldDigits || len(indexPart) != configHeadFoldDigits {
		return 0, false
	}
	index, err := strconv.ParseUint(indexPart, 10, 64)
	if err != nil || index == 0 {
		return 0, false
	}
	if ConfigFoldPath(index) != path {
		return 0, false
	}
	return index, true
}

// Whether path is one a head may hold.
func configHeadPathKnown(path string) bool {
	if configHeadFilePaths[path] {
		return true
	}
	if _, ok := configFoldIndex(path); ok {
		return true
	}
	if shareIdHex, ok := strings.CutPrefix(path, ConfigHeadBridgeSharePrefix); ok {
		decoded, err := hex.DecodeString(shareIdHex)
		return err == nil && len(shareIdHex) == configHeadShareIdHexLength && hex.EncodeToString(decoded) == shareIdHex
	}
	return false
}

// One config head.
type ConfigHead struct {
	files         map[string][]byte
	signedGenesis []byte
	genesis       *bridge.Genesis
	// folds[i-1] is fold i
	folds []*protocol.ConfigFold
}

// The head the files make, checked: every path known, a genesis that verifies under the key it names, and folds 1..k
// with none missing, each starting where the one before ended, its records strictly inside its range in n order,
// statements by a 32-byte id and ticks by none.
func NewConfigHead(files map[string][]byte) (*ConfigHead, error) {
	self := &ConfigHead{files: map[string][]byte{}}
	foldIndexes := []uint64{}
	for path, data := range files {
		if !configHeadPathKnown(path) {
			return nil, fmt.Errorf("%w: a path %q no head holds", ErrConfigHeadMalformed, path)
		}
		self.files[path] = bytes.Clone(data)
		if index, ok := configFoldIndex(path); ok {
			foldIndexes = append(foldIndexes, index)
		}
	}

	self.signedGenesis = self.files[ConfigHeadGenesisPath]
	if len(self.signedGenesis) == 0 {
		return nil, fmt.Errorf("%w: no genesis", ErrConfigHeadMalformed)
	}
	genesis, err := configParseGenesis(self.signedGenesis)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigHeadMalformed, err)
	}
	self.genesis = genesis

	slices.Sort(foldIndexes)
	after := uint64(0)
	for position, index := range foldIndexes {
		if index != uint64(position)+1 {
			return nil, fmt.Errorf("%w: fold %d is missing", ErrConfigHeadMalformed, position+1)
		}
		fold := &protocol.ConfigFold{}
		if err := proto.Unmarshal(self.files[ConfigFoldPath(index)], fold); err != nil {
			return nil, fmt.Errorf("%w: fold %d: %w", ErrConfigHeadMalformed, index, err)
		}
		if err := configCheckFold(fold, after); err != nil {
			return nil, fmt.Errorf("%w: fold %d: %w", ErrConfigHeadMalformed, index, err)
		}
		self.folds = append(self.folds, fold)
		after = fold.GetFoldedThrough()
	}
	return self, nil
}

// A fold's own shape, given where the one before it ended.
func configCheckFold(fold *protocol.ConfigFold, after uint64) error {
	if fold.GetAfter() != after {
		return fmt.Errorf("starts after %d, not after %d", fold.GetAfter(), after)
	}
	if fold.GetFoldedThrough() <= fold.GetAfter() {
		return fmt.Errorf("folds through %d, not past %d", fold.GetFoldedThrough(), fold.GetAfter())
	}
	previousN := fold.GetAfter()
	for i, record := range fold.GetRecords() {
		if record.GetN() <= previousN || fold.GetFoldedThrough() < record.GetN() {
			return fmt.Errorf("record %d at %d is out of order or range", i, record.GetN())
		}
		previousN = record.GetN()
		switch record.GetKind() {
		case bridge.AuthEntryKindStatement:
			if len(record.GetId()) != sha256.Size {
				return fmt.Errorf("statement %d has an id of %d bytes", i, len(record.GetId()))
			}
		case bridge.AuthEntryKindTick:
			if len(record.GetId()) != 0 {
				return fmt.Errorf("tick %d has an id", i)
			}
		default:
			return fmt.Errorf("record %d of kind %d", i, record.GetKind())
		}
	}
	return nil
}

// The head's files, path to bytes: what a writer pushes. A copy.
func (self *ConfigHead) Files() map[string][]byte {
	files := make(map[string][]byte, len(self.files))
	for path, data := range self.files {
		files[path] = bytes.Clone(data)
	}
	return files
}

// The head's paths, sorted.
func (self *ConfigHead) Paths() []string {
	return slices.Sorted(maps.Keys(self.files))
}

// One file's bytes, nil when the head holds none. A copy.
func (self *ConfigHead) File(path string) []byte {
	return bytes.Clone(self.files[path])
}

// The head's Genesis and its Signed bytes verbatim, whose SHA-256 is A_0 (plan-TEAM-genesis-custody #4), as CORE-M2-06's
// anchor reads them. The Genesis has verified under the key it names; which genesis to trust is the caller's.
func (self *ConfigHead) Genesis() (*bridge.Genesis, []byte) {
	return proto.Clone(self.genesis).(*bridge.Genesis), bytes.Clone(self.signedGenesis)
}

// How many folds the head holds.
func (self *ConfigHead) FoldCount() uint64 {
	return uint64(len(self.folds))
}

// The position the head's newest fold holds records through, 0 for a head with no fold.
func (self *ConfigHead) FoldedThrough() uint64 {
	if len(self.folds) == 0 {
		return 0
	}
	return self.folds[len(self.folds)-1].GetFoldedThrough()
}

// The records in (after, through]: the folds that tile that range exactly, end to end. A range no folds tile, one
// starting or ending inside a fold, is an error; an empty range holds none.
func (self *ConfigHead) RecordsIn(after uint64, through uint64) ([]*protocol.ConfigRecord, error) {
	if through < after {
		return nil, fmt.Errorf("%w: the range (%d, %d]", ErrConfigHeadMismatch, after, through)
	}
	records := []*protocol.ConfigRecord{}
	if after == through {
		return records, nil
	}
	start := slices.IndexFunc(self.folds, func(fold *protocol.ConfigFold) bool { return fold.GetAfter() == after })
	if start < 0 {
		return nil, fmt.Errorf("%w: no fold starts after %d", ErrConfigHeadMismatch, after)
	}
	for _, fold := range self.folds[start:] {
		if through < fold.GetFoldedThrough() {
			break
		}
		for _, record := range fold.GetRecords() {
			records = append(records, proto.Clone(record).(*protocol.ConfigRecord))
		}
		if fold.GetFoldedThrough() == through {
			return records, nil
		}
	}
	return nil, fmt.Errorf("%w: no folds end at %d", ErrConfigHeadMismatch, through)
}

// The head a writer saves next: this head's files with one more fold, the given records in (FoldedThrough(),
// foldedThrough]. folded_through stays where it was when there is nothing new to fold, and then the head is this one.
func (self *ConfigHead) WithFold(records []ConfigFoldRecord, foldedThrough uint64) (*ConfigHead, error) {
	if foldedThrough == self.FoldedThrough() && len(records) == 0 {
		return self, nil
	}
	fold := &protocol.ConfigFold{After: self.FoldedThrough(), FoldedThrough: foldedThrough}
	for _, record := range records {
		fold.Records = append(fold.Records, &protocol.ConfigRecord{
			Id:     bytes.Clone(record.Id),
			N:      record.N,
			TimeMs: record.TimeMs,
			Kind:   record.Kind,
			Body:   bytes.Clone(record.Body),
		})
	}
	foldBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(fold)
	if err != nil {
		return nil, err
	}
	files := self.Files()
	files[ConfigFoldPath(self.FoldCount()+1)] = foldBytes
	return NewConfigHead(files)
}

// The head with one file set, or removed for nil data: a policy edit, a ServiceSettings, a K_sock rotation.
func (self *ConfigHead) WithFile(path string, data []byte) (*ConfigHead, error) {
	if path == ConfigHeadGenesisPath {
		return nil, fmt.Errorf("%w: the genesis never changes", ErrConfigHeadMalformed)
	}
	if _, ok := configFoldIndex(path); ok {
		return nil, fmt.Errorf("%w: folds change only with WithFold", ErrConfigHeadMalformed)
	}
	files := self.Files()
	if data == nil {
		delete(files, path)
	} else {
		files[path] = bytes.Clone(data)
	}
	return NewConfigHead(files)
}

// A record that rides a head alone, a Signed ServiceSettings, VersioningRules or BridgeBlock: its Signed and body,
// parsed as the one type its path holds. Nil and no error for a path the head does not hold.
func (self *ConfigHead) signedRecord(path string, signedType bridge.SignedType) (*bridge.Signed, proto.Message, error) {
	data := self.files[path]
	if data == nil {
		return nil, nil, nil
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(data, signed); err != nil {
		return nil, nil, fmt.Errorf("%w: %s: %w", ErrConfigHeadMalformed, path, err)
	}
	if bridge.SignedType(signed.GetType()) != signedType {
		return nil, nil, fmt.Errorf("%w: %s holds a %s", ErrConfigHeadMalformed, path, bridge.SignedType(signed.GetType()))
	}
	purpose, _ := ConfigStatementPurpose(signedType)
	message, err := ParseConfigStatement(purpose, signedType, signed.GetBody())
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s: %w", ErrConfigHeadMalformed, path, err)
	}
	return signed, message, nil
}

// The ServiceSettings the head holds and its Signed, nil for none, so §7.9's defaults hold.
func (self *ConfigHead) ServiceSettings() (*protocol.ServiceSettings, *bridge.Signed, error) {
	signed, message, err := self.signedRecord(ConfigHeadServiceSettingsPath, bridge.SignedType_SIGNED_SERVICE_SETTINGS)
	if err != nil || signed == nil {
		return nil, nil, err
	}
	return message.(*protocol.ServiceSettings), signed, nil
}

// The VersioningRules the head holds and its Signed, nil for none. A format-1 reader applies nothing from it but still
// applies the head holding it (owner decision 164).
func (self *ConfigHead) VersioningRules() (*protocol.VersioningRules, *bridge.Signed, error) {
	signed, message, err := self.signedRecord(ConfigHeadVersioningRulesPath, bridge.SignedType_SIGNED_VERSIONING_RULES)
	if err != nil || signed == nil {
		return nil, nil, err
	}
	return message.(*protocol.VersioningRules), signed, nil
}

// The names file, empty when the head holds none.
func (self *ConfigHead) Names() (*protocol.ConfigNameTable, error) {
	table := &protocol.ConfigNameTable{}
	if data := self.files[ConfigHeadNamesPath]; data != nil {
		if err := proto.Unmarshal(data, table); err != nil {
			return nil, fmt.Errorf("%w: names: %w", ErrConfigHeadMalformed, err)
		}
	}
	return table, nil
}

// Whether a record that rides a head alone was signed by one who may sign it at state: its signature under the
// sidecar's identity key, the sidecar standing and of an Owner's or Admin's member, as ServiceSettings' signer row
// asks (§7.9). A head is judged at the state its base lands on.
func configHeadRecordSignedByAdmin(state *ConfigState, signed *bridge.Signed, signedType bridge.SignedType) error {
	signerId, err := configBaseSigner(signed)
	if err != nil {
		return err
	}
	row, standing := state.standingSidecar(signerId, state.TimeMs())
	if !standing {
		return fmt.Errorf("its signer %s is not standing", signerId)
	}
	memberId, untagged := configRowMember(row)
	if !untagged {
		return fmt.Errorf("its signer %s is a tagged sidecar", signerId)
	}
	switch state.Member(memberId).GetRole() {
	case bridge.MemberRole_MEMBER_ROLE_OWNER, bridge.MemberRole_MEMBER_ROLE_ADMIN:
	default:
		return fmt.Errorf("its signer %s is no Owner's or Admin's", signerId)
	}
	purpose, _ := ConfigStatementPurpose(signedType)
	return bridge.VerifySigned(signed, purpose, signedType, bridge.SignedKeyAlgEd25519, state.IdentityKey(signerId))
}

// Whether the sidecar may write config heads at state: a config writer (§7.9's Repo paragraph), never an ephemeral
// sidecar, whose head is refused whatever else it is.
func CheckConfigHeadWriter(state *ConfigState, sidecarId Id) error {
	if row := state.SidecarRow(sidecarId); row != nil && row.GetEphemeral() {
		return fmt.Errorf("%w: an ephemeral sidecar's head", ErrConfigHeadMismatch)
	}
	if !state.IsConfigWriter(sidecarId) {
		return fmt.Errorf("%w: %s writes no config head at %d", ErrConfigHeadMismatch, sidecarId, state.Pin().GetVersion())
	}
	return nil
}

// Checks head against one base (§7.9's BASE row), for a full reader's ConfigRowsSource.CheckHead: the head's genesis is
// the log's; it holds as records exactly check.Folded, each by id with its carrying position, and none past the base's
// folded_through; its ServiceSettings, if any, was signed by an Owner's or Admin's standing device; and its compile
// (CompileProjectionRows over rows, the rows the log's records give at folded_through, with this head) is check.Rows,
// byte for byte. rows is the reader's: nil refuses, since no base compiles from nothing. Any error makes the base a
// fork.
func CheckConfigBase(head *ConfigHead, check *ConfigHeadCheck, rows *ConfigCompileRows) (*ConfigHeadFacts, error) {
	if head == nil || check == nil || check.Previous == nil || check.Header == nil {
		return nil, fmt.Errorf("%w: nothing to check", ErrConfigHeadMismatch)
	}
	if bridge.GenesisChain(head.signedGenesis) != check.Previous.genesisChain {
		return nil, fmt.Errorf("%w: another network's genesis", ErrConfigHeadMismatch)
	}

	foldedThrough := check.Header.GetFoldedThrough()
	if head.FoldedThrough() != foldedThrough {
		return nil, fmt.Errorf("%w: the head folds through %d, the base through %d", ErrConfigHeadMismatch, head.FoldedThrough(), foldedThrough)
	}
	if check.FoldedKnown {
		previousFoldedThrough := uint64(0)
		if check.Previous.base != nil {
			previousFoldedThrough = check.Previous.base.header.GetFoldedThrough()
		}
		records, err := head.RecordsIn(previousFoldedThrough, foldedThrough)
		if err != nil {
			return nil, err
		}
		if len(records) != len(check.Folded) {
			return nil, fmt.Errorf("%w: the head holds %d records in (%d, %d], the log %d", ErrConfigHeadMismatch, len(records), previousFoldedThrough, foldedThrough, len(check.Folded))
		}
		for i, record := range records {
			want := check.Folded[i]
			if !bytes.Equal(record.GetId(), want.Id) || record.GetN() != want.N || record.GetTimeMs() != want.TimeMs ||
				record.GetKind() != want.Kind || !bytes.Equal(record.GetBody(), want.Body) {
				return nil, fmt.Errorf("%w: the head's record at %d is not the log's entry %d", ErrConfigHeadMismatch, record.GetN(), want.N)
			}
		}
	}

	facts := &ConfigHeadFacts{}
	settings, settingsSigned, err := head.ServiceSettings()
	if err != nil {
		return nil, err
	}
	if settingsSigned != nil {
		if err := configHeadRecordSignedByAdmin(check.Previous, settingsSigned, bridge.SignedType_SIGNED_SERVICE_SETTINGS); err != nil {
			return nil, fmt.Errorf("%w: service_settings: %w", ErrConfigHeadMismatch, err)
		}
		if err := CheckServiceSettings(settings); err != nil {
			return nil, fmt.Errorf("%w: service_settings: %w", ErrConfigHeadMismatch, err)
		}
		facts.Settings = settings
	}

	if rows == nil {
		return nil, fmt.Errorf("%w: no rows to compile the head with", ErrConfigHeadMismatch)
	}
	compiled, err := CompileProjectionRows(head, rows)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(compiled, check.Rows) {
		return nil, fmt.Errorf("%w: the head compiles to other rows", ErrConfigHeadMismatch)
	}
	return facts, nil
}
