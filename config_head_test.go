// The config head (config_head.go) and its compile (config_compile.go): the layout plan-TEAM-config-head-format #1
// settles, the BASE check's records, and rows that are the same bytes for the same input. Pure, on every leg.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A statement's record at n, its id and body made up: the head check compares bytes and parses none.
func testConfigFoldRecord(n uint64, kind uint32) ConfigFoldRecord {
	record := ConfigFoldRecord{N: n, TimeMs: testConfigStartMs + int64(n), Kind: kind, Body: []byte{byte(n), byte(kind)}}
	if kind == bridge.AuthEntryKindStatement {
		id := sha256.Sum256(record.Body)
		record.Id = id[:]
	}
	return record
}

// A head of net's genesis with folds of the given records, each fold ending at its folded_through.
func testConfigHead(t testing.TB, net *testConfigNet, folds ...[]ConfigFoldRecord) *ConfigHead {
	t.Helper()
	head, err := NewConfigHead(map[string][]byte{ConfigHeadGenesisPath: net.signedGenesis})
	if err != nil {
		t.Fatal(err)
	}
	for _, records := range folds {
		head, err = head.WithFold(records, records[len(records)-1].N)
		if err != nil {
			t.Fatal(err)
		}
	}
	return head
}

// An acl compile that keeps the log's acl statements as they are, for tests on hand-made rows (C-05).
func registerTestConfigAclCompiler(t testing.TB) {
	t.Helper()
	t.Cleanup(RegisterConfigAclCompiler(func(head *ConfigHead, aclStatements *protocol.AclRows) (*protocol.AclRows, error) {
		return aclStatements, nil
	}))
}

// fold/<d>/<i>: i from 1, d = i / 1024, each eight digits.
func TestConfigFoldPath(t *testing.T) {
	for i, want := range map[uint64]string{
		1:       "fold/00000000/00000001",
		1023:    "fold/00000000/00001023",
		1024:    "fold/00000001/00001024",
		2049:    "fold/00000002/00002049",
		1048576: "fold/00001024/01048576",
	} {
		if got := ConfigFoldPath(i); got != want {
			t.Fatalf("fold %d: %q, want %q", i, got, want)
		}
		if index, ok := configFoldIndex(want); !ok || index != i {
			t.Fatalf("%q reads as fold %d", want, index)
		}
	}
	for _, path := range []string{"fold/00000000/00000000", "fold/00000001/00000001", "fold/0/1", "fold/00000000/00000001/x", "folds/00000000/00000001"} {
		if _, ok := configFoldIndex(path); ok {
			t.Fatalf("%q reads as a fold", path)
		}
	}
}

// A head holds the paths its layout names and no other, a verified genesis, and folds 1..k with none missing, each
// starting where the one before ended, its records inside its range in order.
func TestConfigHeadRefusesWhatIsNoHead(t *testing.T) {
	net := newTestConfigNet(t)
	head := testConfigHead(t, net,
		[]ConfigFoldRecord{testConfigFoldRecord(1, bridge.AuthEntryKindStatement), testConfigFoldRecord(2, bridge.AuthEntryKindTick)},
		[]ConfigFoldRecord{testConfigFoldRecord(4, bridge.AuthEntryKindStatement)},
	)
	if head.FoldCount() != 2 || head.FoldedThrough() != 4 {
		t.Fatalf("folds %d through %d", head.FoldCount(), head.FoldedThrough())
	}
	genesis, signedGenesis := head.Genesis()
	if !bytes.Equal(signedGenesis, net.signedGenesis) || !bytes.Equal(genesis.GetNetworkId(), net.networkId.Bytes()) {
		t.Fatal("the head's genesis is not its file's")
	}

	files := head.Files()
	accept := func(name string, edit func(files map[string][]byte)) {
		t.Helper()
		edited := head.Files()
		edit(edited)
		if _, err := NewConfigHead(edited); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	refuse := func(name string, edit func(files map[string][]byte)) {
		t.Helper()
		edited := head.Files()
		edit(edited)
		if _, err := NewConfigHead(edited); !errors.Is(err, ErrConfigHeadMalformed) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	accept("every single-file path", func(files map[string][]byte) {
		for path := range configHeadFilePaths {
			if path != ConfigHeadGenesisPath {
				files[path] = []byte{}
			}
		}
		files[ConfigHeadBridgeSharePrefix+hex.EncodeToString(testConfigId("share").Bytes())] = []byte{1}
	})
	refuse("an unknown path", func(files map[string][]byte) { files["policy.json"] = []byte("{}") })
	refuse("a share named in upper case", func(files map[string][]byte) {
		files[ConfigHeadBridgeSharePrefix+"0123456789ABCDEF0123456789ABCDEF"] = []byte{1}
	})
	refuse("no genesis", func(files map[string][]byte) { delete(files, ConfigHeadGenesisPath) })
	refuse("a genesis that does not verify", func(files map[string][]byte) {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(files[ConfigHeadGenesisPath], signed); err != nil {
			t.Fatal(err)
		}
		signed.Signature[0] ^= 1
		files[ConfigHeadGenesisPath] = testConfigMarshal(t, signed)
	})
	refuse("a missing fold", func(files map[string][]byte) { delete(files, ConfigFoldPath(1)) })
	refuse("a fold that does not start where the last ended", func(files map[string][]byte) {
		fold := &protocol.ConfigFold{After: 3, FoldedThrough: 4}
		files[ConfigFoldPath(2)] = testConfigMarshal(t, fold)
	})
	refuse("a record out of its fold's range", func(files map[string][]byte) {
		fold := &protocol.ConfigFold{After: 2, FoldedThrough: 4, Records: []*protocol.ConfigRecord{{N: 5, Kind: bridge.AuthEntryKindTick}}}
		files[ConfigFoldPath(2)] = testConfigMarshal(t, fold)
	})
	refuse("records out of order", func(files map[string][]byte) {
		fold := &protocol.ConfigFold{After: 2, FoldedThrough: 4, Records: []*protocol.ConfigRecord{{N: 4, Kind: bridge.AuthEntryKindTick}, {N: 3, Kind: bridge.AuthEntryKindTick}}}
		files[ConfigFoldPath(2)] = testConfigMarshal(t, fold)
	})
	refuse("a base folded in", func(files map[string][]byte) {
		fold := &protocol.ConfigFold{After: 2, FoldedThrough: 4, Records: []*protocol.ConfigRecord{{N: 3, Kind: bridge.AuthEntryKindBase}}}
		files[ConfigFoldPath(2)] = testConfigMarshal(t, fold)
	})
	refuse("a statement with no id", func(files map[string][]byte) {
		fold := &protocol.ConfigFold{After: 2, FoldedThrough: 4, Records: []*protocol.ConfigRecord{{N: 3, Kind: bridge.AuthEntryKindStatement}}}
		files[ConfigFoldPath(2)] = testConfigMarshal(t, fold)
	})
	refuse("a tick with an id", func(files map[string][]byte) {
		fold := &protocol.ConfigFold{After: 2, FoldedThrough: 4, Records: []*protocol.ConfigRecord{{N: 3, Kind: bridge.AuthEntryKindTick, Id: make([]byte, 32)}}}
		files[ConfigFoldPath(2)] = testConfigMarshal(t, fold)
	})
	if _, err := head.WithFile(ConfigHeadGenesisPath, files[ConfigHeadGenesisPath]); err == nil {
		t.Fatal("a head's genesis changed")
	}
	if _, err := head.WithFile(ConfigFoldPath(3), []byte{}); err == nil {
		t.Fatal("a fold was written but by WithFold")
	}
}

// The records in a range are the folds that tile it exactly.
func TestConfigHeadRecordsInTilesFolds(t *testing.T) {
	net := newTestConfigNet(t)
	head := testConfigHead(t, net,
		[]ConfigFoldRecord{testConfigFoldRecord(1, bridge.AuthEntryKindStatement), testConfigFoldRecord(2, bridge.AuthEntryKindTick)},
		[]ConfigFoldRecord{testConfigFoldRecord(4, bridge.AuthEntryKindStatement)},
		[]ConfigFoldRecord{testConfigFoldRecord(5, bridge.AuthEntryKindStatement), testConfigFoldRecord(9, bridge.AuthEntryKindStatement)},
	)
	for _, c := range []struct {
		after   uint64
		through uint64
		ns      []uint64
	}{
		{after: 0, through: 2, ns: []uint64{1, 2}},
		{after: 2, through: 9, ns: []uint64{4, 5, 9}},
		{after: 0, through: 9, ns: []uint64{1, 2, 4, 5, 9}},
		{after: 4, through: 4, ns: []uint64{}},
	} {
		records, err := head.RecordsIn(c.after, c.through)
		if err != nil {
			t.Fatalf("(%d, %d]: %v", c.after, c.through, err)
		}
		ns := []uint64{}
		for _, record := range records {
			ns = append(ns, record.GetN())
		}
		if !equalUint64s(ns, c.ns) {
			t.Fatalf("(%d, %d]: %v, want %v", c.after, c.through, ns, c.ns)
		}
	}
	for _, c := range [][2]uint64{{1, 2}, {0, 3}, {2, 5}, {9, 10}, {4, 2}} {
		if _, err := head.RecordsIn(c[0], c[1]); !errors.Is(err, ErrConfigHeadMismatch) {
			t.Fatalf("(%d, %d]: err = %v", c[0], c[1], err)
		}
	}
	// a writer that folds nothing new keeps the head
	same, err := head.WithFold(nil, head.FoldedThrough())
	if err != nil || same != head {
		t.Fatalf("an empty fold made another head: %v", err)
	}
}

func equalUint64s(a []uint64, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// §7.9's BASE row on the head: it holds exactly the records in (the previous base's folded_through, folded_through],
// each by id with its carrying position, none missing, none extra, none past; its genesis is the log's; its compile
// is the base's rows.
func TestConfigBaseCheckHoldsExactlyTheFoldedRecords(t *testing.T) {
	net := newTestConfigNet(t)
	registerTestConfigAclCompiler(t)
	previous := net.statesAt[0]
	folded := []ConfigFoldRecord{
		testConfigFoldRecord(1, bridge.AuthEntryKindStatement),
		testConfigFoldRecord(2, bridge.AuthEntryKindTick),
		testConfigFoldRecord(3, bridge.AuthEntryKindStatement),
	}
	head := testConfigHead(t, net, folded)
	compileRows := &ConfigCompileRows{
		Members: []*bridge.MemberRow{{MemberId: net.ownerMemberId.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_OWNER}},
	}
	rows, err := CompileProjectionRows(head, compileRows)
	if err != nil {
		t.Fatal(err)
	}
	check := func(head *ConfigHead, folded []ConfigFoldRecord, foldedThrough uint64, rows []byte) error {
		_, err := CheckConfigBase(head, &ConfigHeadCheck{
			Previous:    previous,
			Header:      &bridge.ProjectionHeader{FoldedThrough: foldedThrough},
			Folded:      folded,
			FoldedKnown: true,
			Rows:        rows,
		}, compileRows)
		return err
	}
	if err := check(head, folded, 3, rows); err != nil {
		t.Fatal(err)
	}

	missing := testConfigHead(t, net, folded[:2])
	if err := check(missing, folded, 3, rows); !errors.Is(err, ErrConfigHeadMismatch) {
		t.Fatalf("a head missing a folded statement: %v", err)
	}
	extra := testConfigHead(t, net, append(append([]ConfigFoldRecord{}, folded...), testConfigFoldRecord(4, bridge.AuthEntryKindStatement)))
	if err := check(extra, folded, 3, rows); !errors.Is(err, ErrConfigHeadMismatch) {
		t.Fatalf("a head holding an extra statement: %v", err)
	}
	other := append([]ConfigFoldRecord{}, folded...)
	other[1] = testConfigFoldRecord(2, bridge.AuthEntryKindStatement)
	if err := check(testConfigHead(t, net, other), folded, 3, rows); !errors.Is(err, ErrConfigHeadMismatch) {
		t.Fatalf("a head holding another record at a position: %v", err)
	}
	moved := append([]ConfigFoldRecord{}, folded...)
	moved[2].N = 3
	moved[2].TimeMs += 1
	if err := check(testConfigHead(t, net, moved), folded, 3, rows); !errors.Is(err, ErrConfigHeadMismatch) {
		t.Fatalf("a head holding a record at another time: %v", err)
	}
	if err := check(head, folded, 3, append(bytes.Clone(rows), 0)); !errors.Is(err, ErrConfigHeadMismatch) {
		t.Fatalf("a head that compiles to other rows: %v", err)
	}
	if _, err := CheckConfigBase(head, &ConfigHeadCheck{Previous: previous, Header: &bridge.ProjectionHeader{FoldedThrough: 3}, Folded: folded, FoldedKnown: true, Rows: rows}, nil); err == nil {
		t.Fatal("a head checked with no rows")
	}

	// another network's genesis is no head of this log
	otherNet := newTestConfigNet(t)
	otherNet.networkId = testConfigId("another network")
	otherGenesis := &bridge.Genesis{
		NetworkId:              otherNet.networkId.Bytes(),
		ConfigRepoId:           testConfigId("config repo").Bytes(),
		OwnerMemberId:          otherNet.ownerMemberId.Bytes(),
		OwnerSidecarId:         otherNet.owner.sidecarId.Bytes(),
		OwnerIdentityPublicKey: otherNet.owner.publicKey(),
		TimeMs:                 testConfigStartMs,
	}
	otherNet.signedGenesis = otherNet.sign(otherNet.owner, bridge.SignedType_SIGNED_GENESIS, otherGenesis)
	if err := check(testConfigHead(t, otherNet, folded), folded, 3, rows); !errors.Is(err, ErrConfigHeadMismatch) {
		t.Fatalf("another genesis: %v", err)
	}
}

// No acl compile, no rows (C-05): CompileProjectionRows refuses until ACL registers one.
func TestCompileProjectionRowsRefusesWithoutAnAclCompile(t *testing.T) {
	net := newTestConfigNet(t)
	head := testConfigHead(t, net)
	defer RegisterConfigAclCompiler(nil)()
	if _, err := CompileProjectionRows(head, &ConfigCompileRows{}); !errors.Is(err, ErrConfigCompileUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

// Rows are the same bytes whatever order their lists come in, refuse a repeated id, and refuse past 4 MiB.
func TestCompileProjectionRowsIsDeterministicAndBounded(t *testing.T) {
	net := newTestConfigNet(t)
	registerTestConfigAclCompiler(t)
	head := testConfigHead(t, net)
	members := []*bridge.MemberRow{}
	sidecars := []*bridge.SidecarRow{}
	for i := 0; i < 16; i += 1 {
		members = append(members, &bridge.MemberRow{MemberId: testConfigId("member " + string(rune('a'+i))).Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER})
		sidecars = append(sidecars, &bridge.SidecarRow{SidecarId: testConfigId("sidecar " + string(rune('a'+i))).Bytes(), AdmittedAt: uint64(i + 1)})
	}
	compiled, err := CompileProjectionRows(head, &ConfigCompileRows{Members: members, Sidecars: sidecars})
	if err != nil {
		t.Fatal(err)
	}
	reversedMembers := append([]*bridge.MemberRow{}, members...)
	reversedSidecars := append([]*bridge.SidecarRow{}, sidecars...)
	for i, j := 0, len(reversedMembers)-1; i < j; i, j = i+1, j-1 {
		reversedMembers[i], reversedMembers[j] = reversedMembers[j], reversedMembers[i]
		reversedSidecars[i], reversedSidecars[j] = reversedSidecars[j], reversedSidecars[i]
	}
	again, err := CompileProjectionRows(head, &ConfigCompileRows{Members: reversedMembers, Sidecars: reversedSidecars})
	if err != nil || !bytes.Equal(compiled, again) {
		t.Fatalf("another order compiled to other bytes: %v", err)
	}
	// and the caller's rows are not reordered
	if !bytes.Equal(reversedMembers[0].GetMemberId(), members[len(members)-1].GetMemberId()) {
		t.Fatal("the caller's list was sorted in place")
	}

	if _, err := CompileProjectionRows(head, &ConfigCompileRows{Members: append(members, members[3])}); !errors.Is(err, ErrConfigRowsMalformed) {
		t.Fatalf("a repeated member: %v", err)
	}
	if _, err := CompileProjectionRows(head, &ConfigCompileRows{Sidecars: []*bridge.SidecarRow{{}}}); !errors.Is(err, ErrConfigRowsMalformed) {
		t.Fatalf("a sidecar with no id: %v", err)
	}

	large := []*bridge.KeyRow{}
	// 1,024-byte keys, past 4 MiB in all
	for i := 0; i < configRowsMaxByteCount/1024+128; i += 1 {
		keyId := sha256.Sum256([]byte{byte(i), byte(i >> 8), byte(i >> 16)})
		large = append(large, &bridge.KeyRow{KeyId: keyId[:], PublicKey: make([]byte, 1024)})
	}
	if _, err := CompileProjectionRows(head, &ConfigCompileRows{RegisteredKeys: large}); !errors.Is(err, ErrConfigRowsTooLarge) {
		t.Fatalf("rows over 4 MiB: %v", err)
	}
}

// Fixed rows and their bytes and rows_sha256, embedded so the page Worker's leg reads them too.
//
//go:embed testdata/config/rows/vectors.json
var testConfigRowsVectors []byte

// testdata/config/rows/vectors.json: fixed rows and their bytes and rows_sha256, the same on every leg.
func TestCompileProjectionRowsVectors(t *testing.T) {
	net := newTestConfigNet(t)
	registerTestConfigAclCompiler(t)
	head := testConfigHead(t, net)
	data := testConfigRowsVectors
	vectors := []struct {
		Name       string `json:"name"`
		Rows       string `json:"rows"`
		Compiled   string `json:"compiled"`
		RowsSha256 string `json:"rows_sha256"`
	}{}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, vector := range vectors {
		input := &bridge.ProjectionRows{}
		rowsBytes, err := hex.DecodeString(vector.Rows)
		if err != nil {
			t.Fatal(err)
		}
		if err := proto.Unmarshal(rowsBytes, input); err != nil {
			t.Fatal(err)
		}
		aclStatements := &protocol.AclRows{}
		if err := proto.Unmarshal(input.GetAcl(), aclStatements); err != nil {
			t.Fatal(err)
		}
		compiled, err := CompileProjectionRows(head, &ConfigCompileRows{
			Members:        input.GetMembers(),
			Sidecars:       input.GetSidecars(),
			Delegations:    input.GetDelegations(),
			RegisteredKeys: input.GetRegisteredKeys(),
			AclStatements:  aclStatements,
			Proposals:      input.GetProposals(),
		})
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		hash := sha256.Sum256(compiled)
		if hex.EncodeToString(compiled) != vector.Compiled || hex.EncodeToString(hash[:]) != vector.RowsSha256 {
			t.Fatalf("%s: compiled %x\nsha256 %x", vector.Name, compiled, hash)
		}
	}
}

// A config writer alone writes heads, and an ephemeral sidecar's head is refused.
func TestConfigHeadWriters(t *testing.T) {
	net := newTestConfigNet(t)
	state := net.log.State()
	if err := CheckConfigHeadWriter(state, net.owner.sidecarId); err != nil {
		t.Fatal(err)
	}
	if err := CheckConfigHeadWriter(state, testConfigId("nobody")); !errors.Is(err, ErrConfigHeadMismatch) {
		t.Fatalf("a stranger: %v", err)
	}
	// the owner's device made ephemeral writes no head, whatever else it is
	ephemeral := configCopyState(state)
	ephemeral.sidecars = configCloneMap(state.sidecars)
	row := proto.Clone(state.sidecars[net.owner.sidecarId]).(*bridge.SidecarRow)
	row.Ephemeral = true
	ephemeral.sidecars[net.owner.sidecarId] = row
	if err := CheckConfigHeadWriter(ephemeral, net.owner.sidecarId); !errors.Is(err, ErrConfigHeadMismatch) {
		t.Fatalf("an ephemeral sidecar: %v", err)
	}
}

// §22.7's privacy canaries: device names, tags, groups and policy text a head holds never reach its compiled rows,
// which a server stores (§2.8 api-7); compile carries only the rows and the acl part's ids.
func TestCompiledRowsHoldNoHeadText(t *testing.T) {
	net := newTestConfigNet(t)
	registerTestConfigAclCompiler(t)
	head := testConfigHead(t, net)
	names := testConfigMarshal(t, &protocol.ConfigNameTable{Names: []*protocol.ConfigName{{SidecarId: net.owner.sidecarId.Bytes(), Name: "orchid-device-label"}}})
	var err error
	for path, data := range map[string][]byte{
		ConfigHeadNamesPath:  names,
		ConfigHeadPolicyPath: []byte(`{"tagOwners": {"tag:canary-tag": ["group:canary-group"]}, "note": "canary-policy-text"}`),
		ConfigHeadTagsPath:   []byte("canary-tag"),
		ConfigHeadGroupsPath: []byte("canary-group"),
	} {
		head, err = head.WithFile(path, data)
		if err != nil {
			t.Fatal(err)
		}
	}
	compiled, err := CompileProjectionRows(head, ConfigCompileRowsOf(net.log.State()))
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{"orchid-device-label", "canary-tag", "canary-group", "canary-policy-text"} {
		if bytes.Contains(compiled, []byte(canary)) {
			t.Fatalf("the rows hold %q", canary)
		}
	}
	labels, err := ConfigNames(mustConfigNames(t, head), net.log.State().Rows().GetSidecars(), nil)
	if err != nil || labels[net.owner.sidecarId] != "orchid-device-label" {
		t.Fatalf("labels %v, err %v", labels, err)
	}
}

func mustConfigNames(t testing.TB, head *ConfigHead) *protocol.ConfigNameTable {
	t.Helper()
	table, err := head.Names()
	if err != nil {
		t.Fatal(err)
	}
	return table
}
