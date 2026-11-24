//go:build !ios_extension && !sidecar_http

// The member's harness config store (CACL-M11-01; DESIGN §16.7, plan-MCP-harness-config-schema #1 and #2, QD-529,
// QD-104; DESIGN-COMPUTE §16.4, §16.6, IC-23): the one door to harness/config.json on the main file-mode ref of the
// member's vault in this network, where the compute keys live beside DESIGN's own: `models` (CACL), `compute.disclosures`
// (CTRUST), `approvals` (SAFE) and `compute.indexer_grant` (ENC). DESIGN's `claims` and `record.redact.pii` may later
// read it through SidecarClaimsConfig and DirectoryRunsConfig, which this file leaves unwired.
//
//	format      UTF-8 JSON, one object, "version": 1, at most ModelsKeySettings.ConfigMaxByteCount (64 KiB)
//	missing     no vault, no file, or the newest version taken a removal: defaults
//	unreadable  not UTF-8, not one object, a key twice in one object, no "version": 1 or past the cap: defaults and a
//	            config_unreadable gap; a write refuses such a file, since it never writes over bytes it cannot keep
//	no vault    a tagged sidecar, a cloud one among them, reads no vault: defaults, never a stale copy
//	writers     a version is taken only where its push's writer is consented for the member at the newest verified
//	            state, untagged and no enclave (capability bit 3); any other writer's version is passed over and alarmed
//	            (record_alarm path_rule, once a version), and the newest version the read takes is read instead, so
//	            nothing an enclave or a tagged sidecar writes is ever taken, and none outlasts its revocation (IC-23)
//	write       only the person's act: origin SidecarActConfirmed, no harness process among the caller's ancestors,
//	            on an approval-capable device; MCP, a hook and an unconfirmed control call are refused before anything
//	            is read, as MCP's guard refuses the vault's harness/ path (DESIGN §16.6). One base-versioned write of
//	            the whole file: each change splices its keys' values into the bytes as read, so every other key, its
//	            bytes and their order stay exactly as they were, never re-serialized from a parsed tree; a write that
//	            another landed before reads the file again and applies the change again, up to ConfigWriteAttemptCount
//	            times
//
// The store reads the vault at each call and keeps nothing between calls but which versions it alarmed on. A key is a
// path of names, models or compute then disclosures, so `compute.disclosures` is the member disclosures of the member
// compute. Nothing here creates, derives or unwraps a key. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"unicode/utf8"
)

// The file's path on the member's vault's main ref (DESIGN §16.7).
const MemberHarnessConfigPath = "harness/config.json"

// The file's format: the key every file carries, and the one version of it.
const (
	memberHarnessConfigVersionKey = "version"
	memberHarnessConfigVersion    = 1
)

// The coverage gap a file that does not read names (DESIGN §16.7).
const MemberHarnessConfigGapUnreadable = "config_unreadable"

// Where a read's values came from.
type MemberHarnessConfigSource string

const (
	// A version of the file, which reads.
	MemberHarnessConfigSourceFile MemberHarnessConfigSource = "file"
	// No vault, no file, or a removal: the defaults.
	MemberHarnessConfigSourceMissing MemberHarnessConfigSource = "missing"
	// A file that does not read: the defaults, and a config_unreadable gap.
	MemberHarnessConfigSourceUnreadable MemberHarnessConfigSource = "unreadable"
	// A sidecar that reads no vault, a tagged one: the defaults.
	MemberHarnessConfigSourceNoVault MemberHarnessConfigSource = "no_vault"
)

var (
	// The member's harness config is written only by the person's act: a confirmed command on /dev/tty or in an app's
	// UI, with no harness process among its caller's ancestors, on an approval-capable device. Nothing was written.
	ErrHarnessConfigRefused = errors.New("the harness config is written only by the person's own act on an approval-capable device, never through MCP, a hook or a harness")
	// No verified config state, or no evs client: nothing was read or written.
	ErrHarnessConfigUnavailable = errors.New("the harness config cannot be read now")
	// The member holds no vault to write the file in, or this sidecar is one that reads none. Nothing was written.
	ErrHarnessConfigNoVault = errors.New("the member holds no vault to keep the harness config in")
	// The file as it stands does not read, so a change would write over bytes it cannot keep. Nothing was written.
	ErrHarnessConfigUnreadable = errors.New("the harness config does not read: fix or remove it before changing it")
	// The change would leave the file past ModelsKeySettings.ConfigMaxByteCount. Nothing was written.
	ErrHarnessConfigTooLarge = errors.New("the harness config would pass its size cap")
	// Another write landed before each of the write's tries. Nothing was written.
	ErrHarnessConfigConflict = errors.New("the harness config kept changing under the write")
	// A change names a key under a value that is no object. Nothing was written.
	ErrHarnessConfigShape = errors.New("the harness config holds no object where the change names a key")
	// A change's value is not one JSON value. Nothing was written.
	ErrHarnessConfigEdit = errors.New("a harness config change that is no JSON value")
)

// What the store calls on the member's vault: an EvsRepo's reads and its one write.
type MemberHarnessConfigVault interface {
	History(ctx context.Context, args *EvsReadArgs) (*EvsHistory, error)
	ReadHead(ctx context.Context, args *EvsReadArgs, out io.Writer) (*EvsFileInfo, error)
	WritePaths(ctx context.Context, args *EvsWritePathsArgs) (*EvsWritePathsResult, error)
}

var _ MemberHarnessConfigVault = (*EvsRepo)(nil)

// What the store judges by, at the newest verified state: a ConfigState gives it (NewMemberHarnessConfigAuthority).
type MemberHarnessConfigAuthority interface {
	// The member a sidecar's admission names, false for a tagged sidecar or one the state does not hold.
	Member(sidecarId Id) (Id, bool)
	// The member's live vault, the earliest created, false for none.
	Vault(memberId Id) (Id, bool)
	// Whether the store takes a version a sidecar wrote as the member's config: the sidecar consented for the member,
	// untagged, with no capability bit 3 (DESIGN-COMPUTE §16.6, IC-23).
	ConfigWriter(sidecarId Id, memberId Id) bool
	// Whether the sidecar may write the member's config on the person's act: approval-capable (DESIGN §16.6).
	ApprovalCapable(sidecarId Id) bool
}

// The store's judgments at one verified state: its rows, its acl and its record logs.
type memberHarnessConfigStateAuthority struct {
	state *ConfigState
	acl   *AclState
	auth  RecordAuthView
}

// The judgments at state, or ErrHarnessConfigUnavailable where it is nil or its acl part does not build.
func NewMemberHarnessConfigAuthority(state *ConfigState) (MemberHarnessConfigAuthority, error) {
	if state == nil {
		return nil, fmt.Errorf("%w: no verified config state", ErrHarnessConfigUnavailable)
	}
	acl, err := state.Acl()
	if err != nil || acl == nil {
		return nil, fmt.Errorf("%w: the state's acl does not build", ErrHarnessConfigUnavailable)
	}
	return &memberHarnessConfigStateAuthority{state: state, acl: acl, auth: NewRecordAuthView(state)}, nil
}

// The member the sidecar's row names, false for a tagged sidecar or none.
func (self *memberHarnessConfigStateAuthority) Member(sidecarId Id) (Id, bool) {
	row := self.state.SidecarRow(sidecarId)
	if row == nil {
		return Id{}, false
	}
	return configRowMember(row)
}

// The record's vault rule (RecordAuthView.Vault).
func (self *memberHarnessConfigStateAuthority) Vault(memberId Id) (Id, bool) {
	return self.auth.Vault(memberId)
}

// Consented for the member, untagged, and no enclave by its row's capability bit 3, which no admission carries before
// the enclaves feature (DESIGN-COMPUTE §16.6).
func (self *memberHarnessConfigStateAuthority) ConfigWriter(sidecarId Id, memberId Id) bool {
	row := self.state.SidecarRow(sidecarId)
	if row == nil {
		return false
	}
	rowMemberId, untagged := configRowMember(row)
	if !untagged || rowMemberId != memberId || configRowEnclave(row) {
		return false
	}
	return self.acl.ConsentedFor(sidecarId, memberId)
}

// AclState.ApprovalCapable, refusing an enclave's row as well.
func (self *memberHarnessConfigStateAuthority) ApprovalCapable(sidecarId Id) bool {
	row := self.state.SidecarRow(sidecarId)
	return row != nil && !configRowEnclave(row) && self.acl.ApprovalCapable(sidecarId)
}

// What a store runs on.
type MemberHarnessConfigArgs struct {
	// This sidecar's id, which reads and writes as its member's device; an error, before it has one, reads and writes
	// nothing.
	Self func() (Id, error)
	// The judgments at the newest verified state; an error reads and writes nothing.
	Authority func() (MemberHarnessConfigAuthority, error)
	// The vault's calls by its repo id: EvsClient.Repo's. Nil, or nil for a vault, reads and writes nothing.
	Vault func(repoId Id) MemberHarnessConfigVault
	// record_alarm's one sink (RecordAlarm): a version passed over. Nil drops it.
	Alarm func(alarm *RecordAlarm)
	// Nil is DefaultModelsKeySettings.
	Settings *ModelsKeySettings
}

// What a write needs of its caller (DESIGN-COMPUTE §16.4, DESIGN §16.6): who asked, and whether a harness runs above it.
type MemberHarnessConfigUpdateArgs struct {
	// The act's origin: only SidecarActConfirmed writes.
	Origin SidecarActOrigin
	// A harness process is among the caller's ancestors (Sidecar.HarnessAncestor), which refuses the write.
	HarnessAncestor bool
}

// One change to the file: the value at a key's path set, or the key removed.
type MemberHarnessConfigEdit struct {
	// The key's path from the file's object: models, or compute then disclosures.
	Path []string
	// The value, one JSON value, which goes into the file as these bytes; nil removes the key, and a key the file does
	// not hold stays absent.
	Value json.RawMessage
}

// A change, given the file as it reads now: the edits to make, none to write nothing. Update calls it again on the file
// as it reads again after another write landed first, so it must depend on read alone.
type MemberHarnessConfigChange func(read *MemberHarnessConfigRead) ([]*MemberHarnessConfigEdit, error)

// One read of the file.
type MemberHarnessConfigRead struct {
	// Where the values came from.
	Source MemberHarnessConfigSource
	// config_unreadable for a file that does not read, else empty.
	Gap string
	// Why the file does not read, naming no value from it.
	Reason string
	// The vault read, zero for none.
	VaultId Id
	// The version taken and its push's writer, 0 and zero for none.
	Version         uint64
	WriterSidecarId Id
	// The versions passed over above the one taken, newest first: an enclave's, a tagged sidecar's or another
	// writer's the store takes nothing from.
	PassedOver []uint64
	// The path's newest version, which a write is made on: 0 where evs shows nothing of the path.
	base uint64
	// the file's bytes and its object, nil for the defaults
	data   []byte
	object *harnessJsonObject
}

// The file's bytes as read, nil for the defaults.
func (self *MemberHarnessConfigRead) Bytes() []byte {
	return bytes.Clone(self.data)
}

// The value at the key's path, verbatim, false where the file reads as the defaults, the key is absent, or a name on
// its path holds no object.
func (self *MemberHarnessConfigRead) Key(path ...string) (json.RawMessage, bool) {
	if self.object == nil || len(path) == 0 {
		return nil, false
	}
	object := self.object
	for i, name := range path {
		member, found := object.member(name)
		if !found {
			return nil, false
		}
		if i == len(path)-1 {
			return bytes.Clone(self.data[member.valueStart:member.valueEnd]), true
		}
		nested, err := parseHarnessJsonObject(self.data, member.valueStart, member.valueEnd)
		if err != nil {
			return nil, false
		}
		object = nested
	}
	return nil, false
}

// The member's harness config in this network. See the file header.
type MemberHarnessConfig struct {
	args     *MemberHarnessConfigArgs
	settings *ModelsKeySettings

	stateLock sync.Mutex
	// the pushes whose versions were alarmed on, each once
	alarmedPushIds map[Id]bool
}

// A store on args.
func NewMemberHarnessConfig(args *MemberHarnessConfigArgs) (*MemberHarnessConfig, error) {
	if args == nil || args.Self == nil || args.Authority == nil {
		return nil, fmt.Errorf("%w: a store needs its sidecar and its authority", ErrHarnessConfigUnavailable)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultModelsKeySettings()
	}
	return &MemberHarnessConfig{args: args, settings: settings, alarmedPushIds: map[Id]bool{}}, nil
}

// Where this sidecar reads: the authority, this sidecar and its member, and the vault's id and calls; a read of the
// defaults where the sidecar reads no vault or the member holds none.
type memberHarnessConfigPlace struct {
	authority MemberHarnessConfigAuthority
	sidecarId Id
	memberId  Id
	vaultId   Id
	vault     MemberHarnessConfigVault
}

// The place, or the defaults' read where there is none to read.
func (self *MemberHarnessConfig) place() (*memberHarnessConfigPlace, *MemberHarnessConfigRead, error) {
	sidecarId, err := self.args.Self()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrHarnessConfigUnavailable, err)
	}
	authority, err := self.args.Authority()
	if err != nil {
		return nil, nil, err
	}
	memberId, member := authority.Member(sidecarId)
	if !member {
		return nil, &MemberHarnessConfigRead{Source: MemberHarnessConfigSourceNoVault}, nil
	}
	vaultId, held := authority.Vault(memberId)
	if !held {
		return nil, &MemberHarnessConfigRead{Source: MemberHarnessConfigSourceMissing}, nil
	}
	var vault MemberHarnessConfigVault
	if self.args.Vault != nil {
		vault = self.args.Vault(vaultId)
	}
	if vault == nil {
		return nil, nil, fmt.Errorf("%w: no evs client", ErrHarnessConfigUnavailable)
	}
	return &memberHarnessConfigPlace{authority: authority, sidecarId: sidecarId, memberId: memberId, vaultId: vaultId, vault: vault}, nil, nil
}

// The file as this sidecar reads it now: see the file header. An error reads nothing: no state, no evs client, or a
// read of the vault that failed.
func (self *MemberHarnessConfig) Read(ctx context.Context) (*MemberHarnessConfigRead, error) {
	place, defaults, err := self.place()
	if err != nil || defaults != nil {
		return defaults, err
	}
	return self.readAt(ctx, place)
}

// The file in the place's vault: the newest version a writer the store takes from wrote, each one above it passed over
// and alarmed.
func (self *MemberHarnessConfig) readAt(ctx context.Context, place *memberHarnessConfigPlace) (*MemberHarnessConfigRead, error) {
	read := &MemberHarnessConfigRead{Source: MemberHarnessConfigSourceMissing, VaultId: place.vaultId}
	history, err := place.vault.History(ctx, &EvsReadArgs{Path: MemberHarnessConfigPath})
	if errors.Is(err, ErrEvsPathAbsent) {
		return read, nil
	}
	if err != nil {
		return nil, err
	}
	if 0 < len(history.Versions) {
		read.base = history.Versions[0].Version
	}
	for i, version := range history.Versions {
		if self.settings.ConfigReadVersionMaxCount <= i {
			return readUnreadable(read, fmt.Sprintf("no version among the newest %d is one a member's device wrote", self.settings.ConfigReadVersionMaxCount)), nil
		}
		if version.Ignored {
			// a version this device does not follow under the repo's prefix rules, which evs_alarm names
			read.PassedOver = append(read.PassedOver, version.Version)
			continue
		}
		if !place.authority.ConfigWriter(version.SignerSidecarId, place.memberId) {
			read.PassedOver = append(read.PassedOver, version.Version)
			self.alarm(place.vaultId, version)
			continue
		}
		read.Version, read.WriterSidecarId = version.Version, version.SignerSidecarId
		if version.Removed {
			return read, nil
		}
		buffer := &harnessConfigBuffer{maxByteCount: self.settings.ConfigMaxByteCount}
		if _, err := place.vault.ReadHead(ctx, &EvsReadArgs{Path: MemberHarnessConfigPath, Version: version.Version}, buffer); err != nil {
			if errors.Is(err, errHarnessConfigOversize) {
				return readUnreadable(read, fmt.Sprintf("version %d is past %d bytes", version.Version, self.settings.ConfigMaxByteCount)), nil
			}
			return nil, err
		}
		object, err := parseHarnessConfig(buffer.data, self.settings)
		if err != nil {
			return readUnreadable(read, fmt.Sprintf("version %d: %v", version.Version, err)), nil
		}
		read.Source, read.data, read.object = MemberHarnessConfigSourceFile, buffer.data, object
		return read, nil
	}
	if !history.Whole {
		// an older life the walk did not reach may hold a version a member's device wrote
		return readUnreadable(read, "the versions the read reached hold none a member's device wrote"), nil
	}
	return read, nil
}

// read as the defaults with the gap and why.
func readUnreadable(read *MemberHarnessConfigRead, reason string) *MemberHarnessConfigRead {
	read.Source, read.Gap, read.Reason = MemberHarnessConfigSourceUnreadable, MemberHarnessConfigGapUnreadable, reason
	read.data, read.object = nil, nil
	return read
}

// record_alarm path_rule for a version a writer the store takes nothing from pushed, once a push.
func (self *MemberHarnessConfig) alarm(vaultId Id, version *EvsHistoryVersion) {
	first := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.alarmedPushIds[version.PushId] {
			return false
		}
		self.alarmedPushIds[version.PushId] = true
		return true
	}()
	if !first || self.args.Alarm == nil {
		return
	}
	writerId := version.SignerSidecarId
	self.args.Alarm(&RecordAlarm{Reason: SidecarRecordAlarmPathRule, LogId: vaultId, SidecarId: &writerId})
}

// Writes change into the file, on the person's act alone: see the file header. Answers the file as written, or as read
// where the change made no edit.
func (self *MemberHarnessConfig) Update(ctx context.Context, args *MemberHarnessConfigUpdateArgs, change MemberHarnessConfigChange) (*MemberHarnessConfigRead, error) {
	if args == nil || args.Origin != SidecarActConfirmed {
		return nil, fmt.Errorf("%w: the act's origin is no person's confirmation", ErrHarnessConfigRefused)
	}
	if args.HarnessAncestor {
		return nil, fmt.Errorf("%w: a harness process is among the caller's ancestors", ErrHarnessConfigRefused)
	}
	if change == nil {
		return nil, fmt.Errorf("%w: no change", ErrHarnessConfigEdit)
	}
	sidecarId, err := self.args.Self()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHarnessConfigUnavailable, err)
	}
	authority, err := self.args.Authority()
	if err != nil {
		return nil, err
	}
	if !authority.ApprovalCapable(sidecarId) {
		return nil, fmt.Errorf("%w: this device is not approval-capable", ErrHarnessConfigRefused)
	}
	place, defaults, err := self.place()
	if err != nil {
		return nil, err
	}
	if defaults != nil {
		return nil, ErrHarnessConfigNoVault
	}
	for range max(self.settings.ConfigWriteAttemptCount, 1) {
		read, err := self.readAt(ctx, place)
		if err != nil {
			return nil, err
		}
		if read.Source == MemberHarnessConfigSourceUnreadable {
			return nil, fmt.Errorf("%w: %s", ErrHarnessConfigUnreadable, read.Reason)
		}
		edits, err := change(read)
		if err != nil {
			return nil, err
		}
		if len(edits) == 0 {
			return read, nil
		}
		data := read.data
		if data == nil {
			data = []byte(fmt.Sprintf(`{"%s":%d}`, memberHarnessConfigVersionKey, memberHarnessConfigVersion))
		}
		for _, edit := range edits {
			if data, err = applyHarnessConfigEdit(data, edit); err != nil {
				return nil, err
			}
		}
		if self.settings.ConfigMaxByteCount < len(data) {
			return nil, fmt.Errorf("%w: %d bytes, past %d", ErrHarnessConfigTooLarge, len(data), self.settings.ConfigMaxByteCount)
		}
		object, err := parseHarnessConfig(data, self.settings)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrHarnessConfigEdit, err)
		}
		if read.data != nil && bytes.Equal(data, read.data) {
			return read, nil
		}
		base := read.base
		result, err := place.vault.WritePaths(ctx, &EvsWritePathsArgs{Writes: []*EvsPathWrite{{
			Path:          MemberHarnessConfigPath,
			Content:       bytes.NewReader(data),
			IfBaseVersion: &base,
		}}})
		var conflict *EvsPathConflictError
		if errors.Is(err, ErrEvsPathMoved) || errors.As(err, &conflict) {
			// another write landed first: read the file again and apply the change again
			continue
		}
		if err != nil {
			return nil, err
		}
		written := &MemberHarnessConfigRead{
			Source:          MemberHarnessConfigSourceFile,
			VaultId:         place.vaultId,
			WriterSidecarId: place.sidecarId,
			data:            data,
			object:          object,
		}
		if result != nil && 0 < len(result.PathVersions) {
			written.Version, written.base = result.PathVersions[0], result.PathVersions[0]
		}
		return written, nil
	}
	return nil, fmt.Errorf("%w: %d tries", ErrHarnessConfigConflict, max(self.settings.ConfigWriteAttemptCount, 1))
}

// A version's content past the cap.
var errHarnessConfigOversize = errors.New("past the harness config's cap")

// What one version's read writes into: its bytes, refusing any past maxByteCount.
type harnessConfigBuffer struct {
	maxByteCount int
	data         []byte
}

// Appends, or errHarnessConfigOversize past the cap.
func (self *harnessConfigBuffer) Write(data []byte) (int, error) {
	if self.maxByteCount < len(self.data)+len(data) {
		return 0, errHarnessConfigOversize
	}
	self.data = append(self.data, data...)
	return len(data), nil
}

// The file's object, or why it does not read: UTF-8, one object and nothing after it, no key twice in it, "version"
// the integer 1, at most the cap.
func parseHarnessConfig(data []byte, settings *ModelsKeySettings) (*harnessJsonObject, error) {
	if settings.ConfigMaxByteCount < len(data) {
		return nil, fmt.Errorf("past %d bytes", settings.ConfigMaxByteCount)
	}
	if !utf8.Valid(data) {
		return nil, errors.New("not UTF-8")
	}
	object, err := parseHarnessJsonObject(data, 0, len(data))
	if err != nil {
		return nil, err
	}
	member, found := object.member(memberHarnessConfigVersionKey)
	if !found {
		return nil, errors.New("no version")
	}
	raw := data[member.valueStart:member.valueEnd]
	var version json.Number
	// a json.Number also takes a string that holds a number, which is no version
	if raw[0] == '"' || json.Unmarshal(raw, &version) != nil {
		return nil, errors.New("a version that is no number")
	}
	if number, err := version.Int64(); err != nil || number != memberHarnessConfigVersion {
		return nil, errors.New("another version")
	}
	return object, nil
}

// One JSON object as its bytes give it: its members in order, each key with its value's span. Offsets are into the
// bytes it was parsed from.
type harnessJsonObject struct {
	// its '{', and the offset after its '}'
	start int
	end   int
	// in the order written
	members []harnessJsonMember
}

// One member of an object.
type harnessJsonMember struct {
	key string
	// the key's opening quote, and the value's span, its bytes exactly as written
	keyStart   int
	valueStart int
	valueEnd   int
}

// The member named key, false for none.
func (self *harnessJsonObject) member(key string) (harnessJsonMember, bool) {
	for _, member := range self.members {
		if member.key == key {
			return member, true
		}
	}
	return harnessJsonMember{}, false
}

// The index of the member named key, -1 for none.
func (self *harnessJsonObject) index(key string) int {
	for i, member := range self.members {
		if member.key == key {
			return i
		}
	}
	return -1
}

var (
	// A value that is no object where one is read.
	errHarnessJsonNotObject = errors.New("not one object")
	// An object naming one key twice, which readers could take either way.
	errHarnessJsonDuplicate = errors.New("a key twice in one object")
)

// The object data[from:to] holds, whitespace about it, refusing anything else there or a key named twice in it.
func parseHarnessJsonObject(data []byte, from int, to int) (*harnessJsonObject, error) {
	if from < 0 || to < from || len(data) < to {
		return nil, errHarnessJsonNotObject
	}
	text := data[from:to]
	decoder := json.NewDecoder(bytes.NewReader(text))
	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errHarnessJsonNotObject, err)
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return nil, errHarnessJsonNotObject
	}
	object := &harnessJsonObject{start: from + int(decoder.InputOffset()) - 1}
	seen := map[string]bool{}
	for decoder.More() {
		previous := int(decoder.InputOffset())
		token, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errHarnessJsonNotObject, err)
		}
		key, ok := token.(string)
		if !ok {
			return nil, errHarnessJsonNotObject
		}
		if seen[key] {
			return nil, errHarnessJsonDuplicate
		}
		seen[key] = true
		keyStart := previous
		for keyStart < len(text) && text[keyStart] != '"' {
			keyStart += 1
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("%w: %v", errHarnessJsonNotObject, err)
		}
		valueEnd := int(decoder.InputOffset())
		object.members = append(object.members, harnessJsonMember{
			key:        key,
			keyStart:   from + keyStart,
			valueStart: from + valueEnd - len(value),
			valueEnd:   from + valueEnd,
		})
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, errHarnessJsonNotObject
	}
	object.end = from + int(decoder.InputOffset())
	if len(bytes.TrimSpace(data[object.end:to])) != 0 {
		return nil, fmt.Errorf("%w: more after it", errHarnessJsonNotObject)
	}
	return object, nil
}

// A key as JSON writes it.
func harnessJsonKey(key string) []byte {
	encoded, _ := json.Marshal(key)
	return encoded
}

// value under each of path's names in turn, innermost last: {"b":{"c":value}} for path b, c.
func harnessJsonNest(path []string, value json.RawMessage) []byte {
	nested := []byte(value)
	for i := len(path) - 1; 0 <= i; i -= 1 {
		nested = append(append(append(append([]byte("{"), harnessJsonKey(path[i])...), ':'), nested...), '}')
	}
	return nested
}

// data with the edit made, every byte outside the value it sets or the member it adds or removes kept.
func applyHarnessConfigEdit(data []byte, edit *MemberHarnessConfigEdit) ([]byte, error) {
	if edit == nil || len(edit.Path) == 0 {
		return nil, fmt.Errorf("%w: no key", ErrHarnessConfigEdit)
	}
	if edit.Value != nil && !json.Valid(edit.Value) {
		return nil, ErrHarnessConfigEdit
	}
	if len(edit.Path) == 1 && edit.Path[0] == memberHarnessConfigVersionKey {
		return nil, fmt.Errorf("%w: the version is the format's", ErrHarnessConfigEdit)
	}
	return harnessJsonSplice(data, 0, len(data), edit.Path, edit.Value)
}

// The object in data[from:to] with value set at path, or its key removed for a nil value.
func harnessJsonSplice(data []byte, from int, to int, path []string, value json.RawMessage) ([]byte, error) {
	object, err := parseHarnessJsonObject(data, from, to)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHarnessConfigShape, err)
	}
	index := object.index(path[0])
	splice := func(start int, end int, text []byte) []byte {
		spliced := make([]byte, 0, len(data)-(end-start)+len(text))
		spliced = append(spliced, data[:start]...)
		spliced = append(spliced, text...)
		return append(spliced, data[end:]...)
	}
	insert := func(member []byte) []byte {
		if len(object.members) == 0 {
			return splice(object.start+1, object.start+1, member)
		}
		last := object.members[len(object.members)-1]
		return splice(last.valueEnd, last.valueEnd, append([]byte(","), member...))
	}
	if index < 0 {
		if value == nil {
			return data, nil
		}
		return insert(append(append(harnessJsonKey(path[0]), ':'), harnessJsonNest(path[1:], value)...)), nil
	}
	member := object.members[index]
	if 1 < len(path) {
		return harnessJsonSplice(data, member.valueStart, member.valueEnd, path[1:], value)
	}
	if value != nil {
		return splice(member.valueStart, member.valueEnd, value), nil
	}
	switch {
	case index < len(object.members)-1:
		// the member, its comma and the space up to the next key
		return splice(member.keyStart, object.members[index+1].keyStart, nil), nil
	case 0 < index:
		// the comma before the last member, and the member
		return splice(object.members[index-1].valueEnd, member.valueEnd, nil), nil
	}
	return splice(member.keyStart, member.valueEnd, nil), nil
}
