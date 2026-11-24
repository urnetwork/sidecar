//go:build !ios_extension && !sidecar_http

// The member's harness config store (CACL-M11-01) on a vault and an authority of the test's own: the file's bytes kept
// through a change, the defaults where nothing reads, the gap where the file does not, the cap, the person's act
// alone, versions from writers the store takes nothing from passed over and alarmed, and a write that another landed
// before applied again.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One version of the test vault's file.
type testMemberConfigVersion struct {
	version uint64
	pushId  Id
	signer  Id
	removed bool
	data    []byte
}

// A vault holding harness/config.json's versions, oldest first, as an EvsRepo serves them: History newest first and
// whole, ReadHead by version, WritePaths held to its base version.
type testMemberConfigVault struct {
	versions []*testMemberConfigVersion
	// the sidecar each write is signed by
	writer Id
	// runs once, before the next write lands: another device's write in between
	beforeWrite func()
	writeCount  int
	historyErr  error
}

// The newest version's number, 0 for none.
func (self *testMemberConfigVault) newest() uint64 {
	if len(self.versions) == 0 {
		return 0
	}
	return self.versions[len(self.versions)-1].version
}

// Appends a version written by signer: data, or a removal for nil.
func (self *testMemberConfigVault) put(signer Id, data []byte) uint64 {
	version := self.newest() + 1
	self.versions = append(self.versions, &testMemberConfigVersion{
		version: version, pushId: testConfigId(fmt.Sprintf("push %d", version)), signer: signer, removed: data == nil, data: bytes.Clone(data),
	})
	return version
}

// The path's versions, newest first.
func (self *testMemberConfigVault) History(ctx context.Context, args *EvsReadArgs) (*EvsHistory, error) {
	if self.historyErr != nil {
		return nil, self.historyErr
	}
	if args.Path != MemberHarnessConfigPath {
		return nil, ErrEvsPathAbsent
	}
	if len(self.versions) == 0 {
		return nil, ErrEvsPathAbsent
	}
	history := &EvsHistory{Path: args.Path, HeadVersion: self.newest(), Whole: true}
	for i := len(self.versions) - 1; 0 <= i; i -= 1 {
		version := self.versions[i]
		history.Versions = append(history.Versions, &EvsHistoryVersion{
			Version: version.version, PushId: version.pushId, SignerSidecarId: version.signer, Removed: version.removed,
		})
	}
	return history, nil
}

// One version's content.
func (self *testMemberConfigVault) ReadHead(ctx context.Context, args *EvsReadArgs, out io.Writer) (*EvsFileInfo, error) {
	for _, version := range self.versions {
		if version.version == args.Version && !version.removed {
			if _, err := out.Write(version.data); err != nil {
				return nil, err
			}
			return &EvsFileInfo{Path: args.Path, Version: version.version, SignerSidecarId: version.signer, Size: uint64(len(version.data))}, nil
		}
	}
	return nil, ErrEvsPathAbsent
}

// One write of the file, refused ErrEvsPathMoved where its base is not the newest version.
func (self *testMemberConfigVault) WritePaths(ctx context.Context, args *EvsWritePathsArgs) (*EvsWritePathsResult, error) {
	if before := self.beforeWrite; before != nil {
		self.beforeWrite = nil
		before()
	}
	if len(args.Writes) != 1 || args.Writes[0].Path != MemberHarnessConfigPath {
		return nil, errors.New("one write of the harness config")
	}
	write := args.Writes[0]
	if write.IfBaseVersion == nil || *write.IfBaseVersion != self.newest() {
		return nil, ErrEvsPathMoved
	}
	data := make([]byte, write.Content.Size())
	if _, err := write.Content.ReadAt(data, 0); err != nil && err != io.EOF {
		return nil, err
	}
	self.writeCount += 1
	version := self.put(self.writer, data)
	return &EvsWritePathsResult{Version: version, PathVersions: []uint64{version}}, nil
}

// The judgments of a test network: each device's member, the consented and approval-capable ones, the enclaves, and
// each member's vault.
type testMemberConfigAuthority struct {
	members         map[Id]Id
	consented       map[Id]bool
	approvalCapable map[Id]bool
	enclaves        map[Id]bool
	vaults          map[Id]Id
}

func (self *testMemberConfigAuthority) Member(sidecarId Id) (Id, bool) {
	memberId, found := self.members[sidecarId]
	return memberId, found
}

func (self *testMemberConfigAuthority) Vault(memberId Id) (Id, bool) {
	vaultId, found := self.vaults[memberId]
	return vaultId, found
}

func (self *testMemberConfigAuthority) ConfigWriter(sidecarId Id, memberId Id) bool {
	owner, found := self.members[sidecarId]
	return found && owner == memberId && self.consented[sidecarId] && !self.enclaves[sidecarId]
}

func (self *testMemberConfigAuthority) ApprovalCapable(sidecarId Id) bool {
	return self.approvalCapable[sidecarId] && !self.enclaves[sidecarId]
}

// A member with a vault, its phone (this device), its laptop, a read-only device of it, a tagged sidecar it sponsors
// and an enclave of it, the store as the phone reads it, and every alarm the store raised.
type testMemberConfigWorld struct {
	member   Id
	vaultId  Id
	phone    Id
	laptop   Id
	readOnly Id
	tagged   Id
	enclave  Id

	authority *testMemberConfigAuthority
	vault     *testMemberConfigVault
	store     *MemberHarnessConfig
	settings  *ModelsKeySettings
	infer     *InferSettings
	alarms    []*RecordAlarm
}

func newTestMemberConfigWorld(t *testing.T) *testMemberConfigWorld {
	world := &testMemberConfigWorld{
		member:   testConfigId("harness member"),
		vaultId:  testConfigId("harness vault"),
		phone:    testConfigId("harness phone"),
		laptop:   testConfigId("harness laptop"),
		readOnly: testConfigId("harness read-only"),
		tagged:   testConfigId("harness tagged"),
		enclave:  testConfigId("harness enclave"),
		settings: DefaultModelsKeySettings(),
		infer:    DefaultInferSettings(),
	}
	world.authority = &testMemberConfigAuthority{
		members:         map[Id]Id{world.phone: world.member, world.laptop: world.member, world.readOnly: world.member, world.enclave: world.member},
		consented:       map[Id]bool{world.phone: true, world.laptop: true, world.readOnly: true, world.enclave: true},
		approvalCapable: map[Id]bool{world.phone: true, world.laptop: true},
		enclaves:        map[Id]bool{world.enclave: true},
		vaults:          map[Id]Id{world.member: world.vaultId},
	}
	world.vault = &testMemberConfigVault{writer: world.phone}
	world.store = world.storeOf(t, world.phone)
	return world
}

// A store reading as sidecarId.
func (self *testMemberConfigWorld) storeOf(t *testing.T, sidecarId Id) *MemberHarnessConfig {
	store, err := NewMemberHarnessConfig(&MemberHarnessConfigArgs{
		Self:      func() (Id, error) { return sidecarId, nil },
		Authority: func() (MemberHarnessConfigAuthority, error) { return self.authority, nil },
		Vault: func(repoId Id) MemberHarnessConfigVault {
			if repoId != self.vaultId {
				return nil
			}
			return self.vault
		},
		Alarm:    func(alarm *RecordAlarm) { self.alarms = append(self.alarms, alarm) },
		Settings: self.settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// The person's act on the phone.
var testMemberConfigConfirmed = &MemberHarnessConfigUpdateArgs{Origin: SidecarActConfirmed}

func TestHarnessConfigUnknownKeysKept(t *testing.T) {
	world := newTestMemberConfigWorld(t)
	original := "{\n" +
		"  \"version\": 1,\n" +
		"  \"claims\": {\"default\": \"auto\", \"projects\": {\"example.com/app\": \"off\"}},\n" +
		"  \"zz_later\": [1, 2.50, {\"nested\": true}, \"\\u00e9\"],\n" +
		"  \"models\": {\"future_field\": \"kept\",   \"tee_only\": false},\n" +
		"  \"record\": {\"redact\": {\"pii\": \"hash\"}}\n" +
		"}\n"
	world.vault.put(world.laptop, []byte(original))

	written, err := SetHarnessModelsKey(t.Context(), world.store, world.settings, world.infer, testMemberConfigConfirmed, func(key *HarnessModelsKey) error {
		key.TeeOnly = true
		key.Default = "local-gemma-4-e4b-off"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !written.TeeOnly || written.Default != "local-gemma-4-e4b-off" {
		t.Fatalf("written %+v", written)
	}
	want := "{\n" +
		"  \"version\": 1,\n" +
		"  \"claims\": {\"default\": \"auto\", \"projects\": {\"example.com/app\": \"off\"}},\n" +
		"  \"zz_later\": [1, 2.50, {\"nested\": true}, \"\\u00e9\"],\n" +
		"  \"models\": {\"future_field\": \"kept\",   \"tee_only\": true,\"default\":\"local-gemma-4-e4b-off\"},\n" +
		"  \"record\": {\"redact\": {\"pii\": \"hash\"}}\n" +
		"}\n"
	got := string(world.vault.versions[len(world.vault.versions)-1].data)
	if got != want {
		t.Fatalf("the file became\n%s\nwant\n%s", got, want)
	}

	// and read back, the unknown field is named and passed over
	read, err := ReadHarnessModelsKey(t.Context(), world.store, world.settings, world.infer)
	if err != nil {
		t.Fatal(err)
	}
	if read.Unreadable || !read.Key.TeeOnly || len(read.Warnings) != 1 || !strings.Contains(read.Warnings[0], "future_field") {
		t.Fatalf("read %+v", read)
	}
	if raw, found := read.Config.Key("record", "redact", "pii"); !found || string(raw) != `"hash"` {
		t.Fatalf("a nested key reads %q, %v", raw, found)
	}
}

func TestHarnessConfigEditsKeepBytes(t *testing.T) {
	file := "{ \"version\":1 , \"a\" : 1,\n \"b\":{ },\"c\":[3] }"
	cases := []struct {
		edit *MemberHarnessConfigEdit
		want string
	}{
		{edit: &MemberHarnessConfigEdit{Path: []string{"a"}, Value: []byte(`"x"`)}, want: "{ \"version\":1 , \"a\" : \"x\",\n \"b\":{ },\"c\":[3] }"},
		{edit: &MemberHarnessConfigEdit{Path: []string{"a"}}, want: "{ \"version\":1 , \"b\":{ },\"c\":[3] }"},
		{edit: &MemberHarnessConfigEdit{Path: []string{"c"}}, want: "{ \"version\":1 , \"a\" : 1,\n \"b\":{ } }"},
		{edit: &MemberHarnessConfigEdit{Path: []string{"b", "x"}, Value: []byte(`true`)}, want: "{ \"version\":1 , \"a\" : 1,\n \"b\":{\"x\":true },\"c\":[3] }"},
		{edit: &MemberHarnessConfigEdit{Path: []string{"d", "e", "f"}, Value: []byte(`2`)}, want: "{ \"version\":1 , \"a\" : 1,\n \"b\":{ },\"c\":[3],\"d\":{\"e\":{\"f\":2}} }"},
		{edit: &MemberHarnessConfigEdit{Path: []string{"absent"}}, want: file},
	}
	for _, c := range cases {
		got, err := applyHarnessConfigEdit([]byte(file), c.edit)
		if err != nil || string(got) != c.want {
			t.Errorf("%v: %q, %v; want %q", c.edit.Path, got, err, c.want)
		}
	}
	// the only member of an object, removed
	got, err := applyHarnessConfigEdit([]byte(`{"version":1,"m":{"x":1}}`), &MemberHarnessConfigEdit{Path: []string{"m", "x"}})
	if err != nil || string(got) != `{"version":1,"m":{}}` {
		t.Errorf("the only member: %q, %v", got, err)
	}
	refused := []*MemberHarnessConfigEdit{
		{Path: []string{"c", "x"}, Value: []byte(`1`)},
		{Path: []string{"a"}, Value: []byte(`{`)},
		{Path: []string{"version"}, Value: []byte(`2`)},
		{Path: nil, Value: []byte(`1`)},
	}
	for _, edit := range refused {
		if _, err := applyHarnessConfigEdit([]byte(file), edit); err == nil {
			t.Errorf("%v: %q made", edit.Path, edit.Value)
		}
	}
}

func TestHarnessConfigMissingTakesDefaults(t *testing.T) {
	world := newTestMemberConfigWorld(t)
	check := func(label string, store *MemberHarnessConfig, source MemberHarnessConfigSource) {
		t.Helper()
		read, err := ReadHarnessModelsKey(t.Context(), store, world.settings, world.infer)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		key := read.Key
		if read.Config.Source != source || read.Unreadable || read.Gap != "" || key.Allow != nil || key.TeeOnly ||
			key.SignInMailMode() != HarnessSignInMailWithhold || key.Default != "" {
			t.Fatalf("%s: %+v, %+v", label, read, key)
		}
		gate := NewComputeModelGate(nil, read, world.infer)
		if err := gate.Allows("chutes-qwen3.8-27b-tee-high", ComputeLabelNone); err != nil {
			t.Fatalf("%s: the defaults refuse a none model: %v", label, err)
		}
	}
	// no file in the vault
	check("no file", world.store, MemberHarnessConfigSourceMissing)
	// a removal as the newest version
	world.vault.put(world.laptop, []byte(`{"version":1,"models":{"tee_only":true}}`))
	world.vault.put(world.laptop, nil)
	check("removed", world.store, MemberHarnessConfigSourceMissing)
	// a file with no models key
	world.vault.put(world.laptop, []byte(`{"version":1}`))
	check("no models key", world.store, MemberHarnessConfigSourceFile)
	// no vault for the member
	delete(world.authority.vaults, world.member)
	check("no vault", world.store, MemberHarnessConfigSourceMissing)
	// a tagged sidecar reads none
	check("tagged", world.storeOf(t, world.tagged), MemberHarnessConfigSourceNoVault)
	if world.vault.writeCount != 0 || len(world.alarms) != 0 {
		t.Fatalf("%d writes, %d alarms", world.vault.writeCount, len(world.alarms))
	}
}

func TestHarnessConfigUnreadableGap(t *testing.T) {
	files := []string{
		`not json`,
		`[1, 2]`,
		`{"version": 2}`,
		`{"models": {}}`,
		`{"version": 1.5}`,
		`{"version": "1"}`,
		`{"version": 1, "a": 1, "a": 2}`,
		`{"version": 1} {}`,
		"{\"version\": 1, \"a\": \"\xff\"}",
		`{"version": 1, "models": {"tee_only": "yes"}}`,
		`{"version": 1, "models": {"allow": ["Chutes-*"]}}`,
		`{"version": 1, "models": []}`,
	}
	for i, file := range files {
		world := newTestMemberConfigWorld(t)
		world.vault.put(world.laptop, []byte(file))
		read, err := ReadHarnessModelsKey(t.Context(), world.store, world.settings, world.infer)
		if err != nil {
			t.Fatalf("file %d: %v", i, err)
		}
		if !read.Unreadable || read.Gap != MemberHarnessConfigGapUnreadable || read.Reason == "" {
			t.Errorf("file %d reads %+v", i, read)
			continue
		}
		// the closed reading: every model refused under rule allow, a local one included
		gate := NewComputeModelGate(nil, read, world.infer)
		refused := &ComputeModelRefusedError{}
		if err := gate.Allows("local-gemma-4-e4b-off", ComputeLabelLocal); !errors.As(err, &refused) || refused.Rule != ComputeModelRuleAllow {
			t.Errorf("file %d: the gate answers %v", i, err)
		}
		// whose bytes a write never goes over, unless only the models key is what does not read
		_, err = SetHarnessModelsKey(t.Context(), world.store, world.settings, world.infer, testMemberConfigConfirmed, func(key *HarnessModelsKey) error {
			key.TeeOnly = true
			return nil
		})
		if read.Config.Source == MemberHarnessConfigSourceUnreadable {
			if !errors.Is(err, ErrHarnessConfigUnreadable) || world.vault.writeCount != 0 {
				t.Errorf("file %d: a write over it answered %v after %d writes", i, err, world.vault.writeCount)
			}
			continue
		}
		// a models key that does not read in a file that does is replaced whole by the person's act
		if err != nil || world.vault.writeCount != 1 {
			t.Errorf("file %d: replacing its models key answered %v after %d writes", i, err, world.vault.writeCount)
		}
	}
}

func TestHarnessConfigOversizeRefused(t *testing.T) {
	world := newTestMemberConfigWorld(t)
	world.settings.ConfigMaxByteCount = 128
	world.store = world.storeOf(t, world.phone)
	// a version past the cap reads as unreadable, defaults and the gap
	world.vault.put(world.laptop, []byte(`{"version":1,"pad":"`+strings.Repeat("x", 200)+`"}`))
	read, err := world.store.Read(t.Context())
	if err != nil || read.Source != MemberHarnessConfigSourceUnreadable || read.Gap != MemberHarnessConfigGapUnreadable {
		t.Fatalf("an oversize version read %+v, %v", read, err)
	}
	// a change that would pass the cap is refused, nothing written
	world.vault.put(world.laptop, []byte(`{"version":1}`))
	_, err = SetHarnessModelsKey(t.Context(), world.store, world.settings, world.infer, testMemberConfigConfirmed, func(key *HarnessModelsKey) error {
		key.Allow = []string{"local-*", "chutes-*", "saygm-*", "engy-*", "targon-*", "lium-*", "hippius-*", "cathedral-*"}
		return nil
	})
	if !errors.Is(err, ErrHarnessConfigTooLarge) || world.vault.writeCount != 0 {
		t.Fatalf("an oversize change answered %v after %d writes", err, world.vault.writeCount)
	}
}

func TestHarnessConfigWriteRefusedToOtherOrigins(t *testing.T) {
	world := newTestMemberConfigWorld(t)
	world.vault.put(world.laptop, []byte(`{"version":1}`))
	change := func(key *HarnessModelsKey) error {
		key.TeeOnly = false
		key.Allow = []string{"*"}
		return nil
	}
	refused := []struct {
		label string
		store *MemberHarnessConfig
		args  *MemberHarnessConfigUpdateArgs
	}{
		{label: "mcp", store: world.store, args: &MemberHarnessConfigUpdateArgs{Origin: SidecarActMcp}},
		{label: "hook", store: world.store, args: &MemberHarnessConfigUpdateArgs{Origin: SidecarActHook}},
		{label: "unconfirmed", store: world.store, args: &MemberHarnessConfigUpdateArgs{Origin: SidecarActUnconfirmed}},
		{label: "no args", store: world.store, args: nil},
		{label: "harness ancestor", store: world.store, args: &MemberHarnessConfigUpdateArgs{Origin: SidecarActConfirmed, HarnessAncestor: true}},
		{label: "read-only device", store: world.storeOf(t, world.readOnly), args: testMemberConfigConfirmed},
		{label: "tagged sidecar", store: world.storeOf(t, world.tagged), args: testMemberConfigConfirmed},
		{label: "enclave", store: world.storeOf(t, world.enclave), args: testMemberConfigConfirmed},
	}
	for _, c := range refused {
		if _, err := SetHarnessModelsKey(t.Context(), c.store, world.settings, world.infer, c.args, change); !errors.Is(err, ErrHarnessConfigRefused) {
			t.Errorf("%s: %v", c.label, err)
		}
	}
	if world.vault.writeCount != 0 {
		t.Fatalf("%d writes", world.vault.writeCount)
	}
	// and the person's act writes
	if _, err := SetHarnessModelsKey(t.Context(), world.store, world.settings, world.infer, testMemberConfigConfirmed, change); err != nil || world.vault.writeCount != 1 {
		t.Fatalf("the person's act: %v, %d writes", err, world.vault.writeCount)
	}
}

func TestHarnessConfigTaggedWriterIgnored(t *testing.T) {
	world := newTestMemberConfigWorld(t)
	first := world.vault.put(world.laptop, []byte(`{"version":1,"models":{"tee_only":true}}`))
	tagged := world.vault.put(world.tagged, []byte(`{"version":1,"models":{"tee_only":false}}`))
	enclave := world.vault.put(world.enclave, []byte(`{"version":1,"models":{"tee_only":false,"allow":["*"]}}`))
	for range 2 {
		read, err := ReadHarnessModelsKey(t.Context(), world.store, world.settings, world.infer)
		if err != nil {
			t.Fatal(err)
		}
		if read.Config.Version != first || read.Config.WriterSidecarId != world.laptop || !read.Key.TeeOnly ||
			!slices.Equal(read.Config.PassedOver, []uint64{enclave, tagged}) {
			t.Fatalf("read %+v, %+v", read.Config, read.Key)
		}
	}
	// each version alarmed once, naming its writer and the vault
	if len(world.alarms) != 2 {
		t.Fatalf("%d alarms", len(world.alarms))
	}
	writers := []Id{}
	for _, alarm := range world.alarms {
		if alarm.Reason != SidecarRecordAlarmPathRule || alarm.LogId != world.vaultId || alarm.SidecarId == nil {
			t.Fatalf("alarm %+v", alarm)
		}
		writers = append(writers, *alarm.SidecarId)
	}
	if !slices.Contains(writers, world.tagged) || !slices.Contains(writers, world.enclave) {
		t.Fatalf("alarms named %v", writers)
	}
	// a write goes on the newest version, the enclave's, with the content taken from the laptop's
	if _, err := SetHarnessModelsKey(t.Context(), world.store, world.settings, world.infer, testMemberConfigConfirmed, func(key *HarnessModelsKey) error {
		key.SignInMail = HarnessSignInMailAllow
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	newest := world.vault.versions[len(world.vault.versions)-1]
	if newest.version != enclave+1 || string(newest.data) != `{"version":1,"models":{"tee_only":true,"sign_in_mail":"allow"}}` {
		t.Fatalf("the write made version %d: %s", newest.version, newest.data)
	}
	// a member's device that is consented no more writes nothing the store takes
	world.authority.consented[world.laptop] = false
	world.vault.put(world.laptop, []byte(`{"version":1,"models":{"tee_only":false}}`))
	read, err := ReadHarnessModelsKey(t.Context(), world.store, world.settings, world.infer)
	if err != nil || read.Config.Version != newest.version || !read.Key.TeeOnly {
		t.Fatalf("after the laptop's consent ended: %+v, %v", read, err)
	}
}

func TestHarnessConfigPassesOverAtMostItsBound(t *testing.T) {
	world := newTestMemberConfigWorld(t)
	world.settings.ConfigReadVersionMaxCount = 2
	world.store = world.storeOf(t, world.phone)
	world.vault.put(world.laptop, []byte(`{"version":1,"models":{"tee_only":true}}`))
	for range 2 {
		world.vault.put(world.tagged, []byte(`{"version":1}`))
	}
	read, err := world.store.Read(t.Context())
	if err != nil || read.Source != MemberHarnessConfigSourceUnreadable || read.Gap != MemberHarnessConfigGapUnreadable {
		t.Fatalf("past the bound: %+v, %v", read, err)
	}
	// nothing at all from a member's device: the defaults
	only := newTestMemberConfigWorld(t)
	only.vault.put(only.tagged, []byte(`{"version":1,"models":{"tee_only":false}}`))
	read, err = only.store.Read(t.Context())
	if err != nil || read.Source != MemberHarnessConfigSourceMissing || len(read.PassedOver) != 1 {
		t.Fatalf("no member version: %+v, %v", read, err)
	}
}

func TestHarnessConfigConflictReapplies(t *testing.T) {
	world := newTestMemberConfigWorld(t)
	world.vault.put(world.laptop, []byte(`{"version":1}`))
	// the laptop writes the approvals key between the phone's read and its write
	world.vault.beforeWrite = func() {
		world.vault.put(world.laptop, []byte(`{"version":1,"approvals":{"mode":"ask"}}`))
	}
	changeCount := 0
	written, err := SetHarnessModelsKey(t.Context(), world.store, world.settings, world.infer, testMemberConfigConfirmed, func(key *HarnessModelsKey) error {
		changeCount += 1
		key.TeeOnly = true
		return nil
	})
	if err != nil || !written.TeeOnly {
		t.Fatal(err)
	}
	if changeCount != 2 {
		t.Fatalf("the change ran %d times", changeCount)
	}
	newest := world.vault.versions[len(world.vault.versions)-1]
	if string(newest.data) != `{"version":1,"approvals":{"mode":"ask"},"models":{"tee_only":true}}` {
		t.Fatalf("the file became %s", newest.data)
	}
	// a write that never finds the file still: the tries run out, nothing written
	attempts := 0
	var keepMoving func()
	keepMoving = func() {
		attempts += 1
		world.vault.put(world.laptop, []byte(fmt.Sprintf(`{"version":1,"n":%d}`, attempts)))
		world.vault.beforeWrite = keepMoving
	}
	world.vault.beforeWrite = keepMoving
	writeCount := world.vault.writeCount
	_, err = SetHarnessModelsKey(t.Context(), world.store, world.settings, world.infer, testMemberConfigConfirmed, func(key *HarnessModelsKey) error {
		key.TeeOnly = false
		return nil
	})
	if !errors.Is(err, ErrHarnessConfigConflict) || world.vault.writeCount != writeCount || attempts != world.settings.ConfigWriteAttemptCount {
		t.Fatalf("a write that kept losing: %v after %d tries", err, attempts)
	}
}

// The store's judgments at a verified state: a member's untagged consented device writes what the store takes, a tagged
// sidecar does not and reads no vault, and a row carrying capability bit 3 never does, whatever else it holds.
func TestMemberHarnessConfigAuthorityJudgesRows(t *testing.T) {
	net := newTestConfigNet(t)
	tagId := testConfigId("ci tag")
	net.withTagOwner(tagId, net.ownerMemberId)
	agent := net.device("tagged agent", Id{})
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(agent, []Id{tagId}, false, net.timeMs+24*60*60*1000, 0))
	authority, err := NewMemberHarnessConfigAuthority(net.log.State())
	if err != nil {
		t.Fatal(err)
	}
	if memberId, member := authority.Member(net.owner.sidecarId); !member || memberId != net.ownerMemberId {
		t.Fatalf("the owner's device: %s, %v", memberId, member)
	}
	if !authority.ConfigWriter(net.owner.sidecarId, net.ownerMemberId) || !authority.ApprovalCapable(net.owner.sidecarId) {
		t.Fatal("the owner's consented device writes nothing the store takes")
	}
	if _, member := authority.Member(agent.sidecarId); member || authority.ConfigWriter(agent.sidecarId, net.ownerMemberId) || authority.ApprovalCapable(agent.sidecarId) {
		t.Fatal("a tagged sidecar reads or writes as a member's device")
	}
	if authority.ConfigWriter(net.owner.sidecarId, testConfigId("another member")) {
		t.Fatal("a device writes another member's config")
	}
	if _, err := NewMemberHarnessConfigAuthority(nil); !errors.Is(err, ErrHarnessConfigUnavailable) {
		t.Fatalf("no state: %v", err)
	}
	// bit 3, which no admission carries before the enclaves feature, refuses a row however it is admitted
	row := &bridge.SidecarRow{MemberId: net.ownerMemberId.Bytes(), Capabilities: uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_ENCLAVE)}
	if !configRowEnclave(row) || configRowEnclave(&bridge.SidecarRow{Capabilities: uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED)}) {
		t.Fatal("bit 3 misread")
	}
}
