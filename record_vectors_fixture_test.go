//go:build !js

// The fixture behind testdata/record/vectors.json (RECORD-M3-11): one body of every kind M3 writes, sealed in order on
// a fresh chain with fixed draws, so the bytes follow from the inputs. The js leg opens no files and holds no chain
// store here, so sealing again stays off it; record_vectors_test.go checks the file's bytes on every leg.
//
//	go test -run TestRecordFreezeVectorsSealAgainToTheFile -update-record-freeze-vectors    rewrites the file

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var updateRecordFreezeVectors = flag.Bool("update-record-freeze-vectors", false, "rewrite testdata/record/vectors.json")

const testRecordFreezeVectorsPath = "testdata/record/vectors.json"

// One entry's inputs: its kind, who the source is, and its body as a message or as stored.
type testRecordFreezeInput struct {
	kind   RecordKind
	source RecordSource
	body   proto.Message
	stored []byte
	// filed in the fixture's run by its agent
	agent bool
}

// The fixture's ids and keys.
type testRecordFreezeFixture struct {
	seed         []byte
	writer       Id
	logId        Id
	slotId       Id
	approverSeed []byte
	inputs       []*testRecordFreezeInput
	// the decision's Signed as stored, and the request it binds
	decision []byte
	request  *StoredApprovalRequest
}

// The draws of the entry at index: its entry_id, key, salt and nonce, each a byte repeated and none shared.
func testRecordFreezeDraws(index int) []byte {
	random := bytes.Repeat([]byte{byte(0x40 + index)}, 16)
	random = append(random, bytes.Repeat([]byte{byte(0x80 + index)}, RecordKeyByteCount)...)
	random = append(random, bytes.Repeat([]byte{byte(0xc0 + index)}, RecordSaltByteCount)...)
	return append(random, bytes.Repeat([]byte{byte(0x01 + index)}, RecordSealNonceByteCount)...)
}

// One body of each M3 kind, in testRecordFreezeKinds' order, every value synthetic.
func testRecordFreezeBuild(t *testing.T) *testRecordFreezeFixture {
	t.Helper()
	fixture := &testRecordFreezeFixture{
		seed:         bytes.Repeat([]byte{0x99}, ed25519.SeedSize),
		writer:       Id(bytes.Repeat([]byte{0x33}, 16)),
		logId:        Id(bytes.Repeat([]byte{0x44}, 16)),
		slotId:       Id(bytes.Repeat([]byte{0x09}, 16)),
		approverSeed: bytes.Repeat([]byte{0x99}, ed25519.SeedSize),
	}
	runId := bytes.Repeat([]byte{0x77}, 16)
	hash := func(value byte) []byte { return bytes.Repeat([]byte{value}, 32) }
	id := func(value byte) []byte { return bytes.Repeat([]byte{value}, 16) }

	storedAction := testRecordStored(t, testRecordDnsAction())
	requestStored := testRecordStored(t, testRecordRequest(t, storedAction))
	request, err := ParseStoredApprovalRequest(requestStored)
	if err != nil {
		t.Fatal(err)
	}
	fixture.request = request
	fixture.decision = testRecordStored(t, testRecordSignDecision(t, testRecordDecisionBody(request, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE)))
	cancelBody := testRecordStored(t, &protocol.ApprovalCancel{ApprovalId: request.Request.GetApprovalId()})
	cancel := testRecordStored(t, &bridge.Signed{
		Body:      cancelBody,
		SignerId:  fixture.writer.Bytes(),
		Signature: ed25519.Sign(ed25519.NewKeyFromSeed(fixture.seed), bridge.SignedBytes(ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_CANCEL, cancelBody)),
		Type:      uint32(bridge.SignedType_SIGNED_APPROVAL_CANCEL),
	})

	fixture.inputs = []*testRecordFreezeInput{
		{kind: RecordKindClaim, source: RecordSourceAgent, agent: true, body: &protocol.CoordinationBody{
			Text: "taking the limiter's retry path", ExpiresMillis: 1762390800000, ClaimState: 1}},
		{kind: RecordKindHandoff, source: RecordSourceAgent, agent: true, body: &protocol.CoordinationBody{Text: "the retry path is ready for review"}},
		{kind: RecordKindAsk, source: RecordSourceAgent, agent: true, body: &protocol.CoordinationBody{
			Text: "which backoff does the gateway expect?", ExpiresMillis: 1762390800000}},
		{kind: RecordKindAnswer, source: RecordSourceAgent, agent: true, body: &protocol.CoordinationBody{Text: "exponential, capped at 30 s"}},
		{kind: RecordKindCheck, source: RecordSourceAgent, agent: true, body: &protocol.CoordinationBody{Text: "the retry tests pass", Result: 1}},
		{kind: RecordKindNote, source: RecordSourceAgent, agent: true, body: &protocol.CoordinationBody{Text: "synthetic note"}},
		{kind: RecordKindContext, source: RecordSourceHook, agent: true, body: &protocol.ContextBody{
			Stage: 1, Harness: "claude-code", HarnessVersion: "2.1.0", AgentLabel: "limiter-fix", SessionIds: []string{"session-0001"},
			Model: "sonnet", PermissionMode: "default", Project: "github.com/example/limiter", Branch: "fix/retry",
			Title: "Fix the limiter's retry path", ConfigSha256: hash(0x21)}},
		{kind: RecordKindChange, source: RecordSourceObserved, agent: true, body: &protocol.ChangeBody{
			Project: "github.com/example/limiter", BaseCommit: "1111111111111111111111111111111111111111", PathCount: 1, EditCount: 1, Capture: 3,
			Paths: []*protocol.ChangedPath{{Path: "limiter/retry.go", BeforeSha256: hash(0x22), AfterSha256: hash(0x23), Mode: 0o100644, Attribution: 1, BlobEntryId: id(0x24)}}}},
		{kind: RecordKindPermission, source: RecordSourceHook, agent: true, body: &protocol.PermissionBody{
			Decision: 2, DecidedBy: 1, PermissionMode: "default", ToolClass: 1, ToolName: "Bash", ArgumentsSha256: hash(0x25)}},
		{kind: RecordKindApproval, source: RecordSourceObserved, agent: true, stored: requestStored},
		{kind: RecordKindApprovalDecision, source: RecordSourceApprover, stored: fixture.decision},
		{kind: RecordKindApprovalCancel, source: RecordSourceObserved, stored: cancel},
		{kind: RecordKindApprovalUse, source: RecordSourceObserved, agent: true, body: &protocol.ApprovalUseBody{
			ApprovalId: request.Request.GetApprovalId(), UseIndex: 1, PayloadSha256: request.Request.GetPayloadSha256(), EffectKey: hash(0x26),
			State: 1, ReservedMillis: 1762387203000, OutcomeMillis: 1762387204000}},
		{kind: RecordKindRestore, source: RecordSourceObserved, agent: true, body: &protocol.RestoreBody{
			RestoredRunId: runId, PreviewId: id(0x27), RestoredCount: 1,
			Paths: []*protocol.RestoredPath{{Path: "limiter/retry.go", Result: "restored"}}}},
		{kind: RecordKindMembership, source: RecordSourceObserved, body: &protocol.MembershipBody{
			Event: 1, MemberId: id(0x66), SidecarId: id(0x55), AuthPosition: 412, StatementSha256: hash(0x28)}},
		{kind: RecordKindKey, source: RecordSourceObserved, body: &protocol.KeyBody{
			Event: 1, GroupId: id(0x29), Generation: 3, AuthPosition: 413, StatementSha256: hash(0x2a)}},
		{kind: RecordKindCoverage, source: RecordSourceObserved, agent: true, body: &protocol.Coverage{
			RunId: runId, Harness: "claude-code", Version: "0.0.0-test", Sources: []string{RecordCoverageSourceHooks},
			Gaps: []string{RecordCoverageGapTruncation + ":2"}, FirstSeq: 1, LastSeq: 17}},
		{kind: RecordKindRead, source: RecordSourceObserved, body: &protocol.ReadBody{ObjectIds: [][]byte{id(0x2b), hash(0x2c)}, Purpose: 1}},
		{kind: RecordKindErasure, source: RecordSourceObserved, body: &protocol.ErasureBody{ErasureId: id(0x2d), EntryIds: [][]byte{id(0x2e)}, Reason: 1}},
		{kind: RecordKindInventory, source: RecordSourceObserved, body: &protocol.InventoryBody{
			SponsorMemberId: id(0x66), Day: 20398, CredentialRef: id(0x2f),
			Agents: []*protocol.InventoryAgent{{AgentId: id(0x88), AgentLabel: "limiter-fix", AgentSource: 1, Harnesses: []string{"claude-code/2.1.0"},
				Models: []string{"sonnet"}, Projects: []string{"github.com/example/limiter"}, Runs: 1, FirstSeenMillis: 1762387200000, LastSeenMillis: 1762387260000}}}},
		{kind: RecordKindTranscript, source: RecordSourceHook, agent: true, body: &protocol.TranscriptBody{
			FirstLine: 1, LineCount: 1, Lines: []byte("{\"type\":\"user\",\"text\":\"synthetic\"}\n")}},
		{kind: RecordKindToolCall, source: RecordSourceHook, agent: true, body: &protocol.ToolCallBody{
			ToolName: "Bash", ToolUseId: "toolu_01", ToolClass: 1, Input: []byte("{\"command\":\"go test ./limiter\"}"), Output: []byte("ok"),
			StartedMillis: 1762387201000, EndedMillis: 1762387202000, Paths: []string{"limiter"}}},
		{kind: RecordKindHookEvent, source: RecordSourceHook, agent: true, body: &protocol.HookEventBody{
			Event: "PreToolUse", Payload: []byte("{\"tool_name\":\"Bash\"}"), ArgumentsSha256: hash(0x25)}},
		{kind: RecordKindBlob, source: RecordSourceObserved, agent: true, body: &protocol.BlobBody{
			Path: "limiter/retry.go", Content: []byte("package limiter\n"), Sha256: hash(0x23), Size: 16}},
	}
	return fixture
}

// Seals the fixture on a fresh chain and writes down what came of it.
func testRecordFreezeCompute(t *testing.T) *testRecordFreezeVectors {
	t.Helper()
	fixture := testRecordFreezeBuild(t)
	key := ed25519.NewKeyFromSeed(fixture.seed)
	draws := []byte{}
	for index := range fixture.inputs {
		draws = append(draws, testRecordFreezeDraws(index)...)
	}
	env := testRecordSealEnv(t, fixture.writer, key, draws)
	requestSha256 := fixture.request.Sha256()
	payloadSha256 := fixture.request.Action.PayloadSha256()
	vectors := &testRecordFreezeVectors{
		Comment: "RECORD-M3-11's freeze vectors over stored bytes: one entry of every kind M3 writes, sealed in order as one " +
			"writer's chain in one log, each drawing its entry_id, key, salt and nonce from random, in that order, and " +
			"pushed in one slot at key_index 0 up; each entry's slot row is key || salt; deposit_batch is the first two " +
			"entries as a depositor sends them; decision is the approval_decision entry's body, a Signed by the approver's " +
			"key; actions are one of each kind the builder makes. Ed25519 signs deterministically, so the bytes follow " +
			"from the inputs, and every leg must compute them. go test -run TestRecordFreezeVectorsSealAgainToTheFile " +
			"-update-record-freeze-vectors rewrites this file.",
		IdentitySeed:          hex.EncodeToString(fixture.seed),
		WriterSidecarId:       hex.EncodeToString(fixture.writer[:]),
		LogId:                 hex.EncodeToString(fixture.logId[:]),
		SlotId:                hex.EncodeToString(fixture.slotId[:]),
		ApproverSeed:          hex.EncodeToString(fixture.approverSeed),
		Decision:              hex.EncodeToString(fixture.decision),
		DecisionRequestSha256: hex.EncodeToString(requestSha256[:]),
		DecisionPayloadSha256: hex.EncodeToString(payloadSha256[:]),
	}
	agentId := Id(bytes.Repeat([]byte{0x88}, 16))
	runId := Id(bytes.Repeat([]byte{0x77}, 16))
	batch := &protocol.RecordDepositBatch{}
	for index, input := range fixture.inputs {
		args := &RecordSealArgs{
			LogId:         fixture.logId,
			Kind:          input.kind,
			Source:        input.source,
			TimeMillis:    1762387200000 + int64(index)*1000,
			PolicyVersion: 412,
			Body:          input.body,
			StoredBody:    input.stored,
		}
		if input.agent {
			args.AgentId = &agentId
			args.AgentSource = RecordAgentSourceAsserted
			args.RunId = &runId
		}
		if input.kind == RecordKindApproval || input.kind == RecordKindApprovalUse {
			args.ActionId = fixture.request.Request.GetActionId()
		}
		sealed, err := RecordSeal(env, args)
		if err != nil {
			t.Fatalf("%s: %v", input.kind, err)
		}
		header, err := sealed.Header()
		if err != nil {
			t.Fatal(err)
		}
		body := input.stored
		if body == nil {
			body = testRecordStored(t, input.body)
		}
		if index < 2 {
			batch.Entries = append(batch.Entries, sealed.Deposit())
		}
		vectors.Entries = append(vectors.Entries, &testRecordFreezeEntry{
			Kind:           input.kind.String(),
			KindNo:         uint32(input.kind),
			Random:         hex.EncodeToString(testRecordFreezeDraws(index)),
			Body:           hex.EncodeToString(body),
			Seq:            sealed.Seq,
			PrevSha256:     hex.EncodeToString(header.Header.GetPrevSha256()),
			Header:         hex.EncodeToString(header.Bytes),
			Signed:         hex.EncodeToString(sealed.Signed),
			SealedBody:     hex.EncodeToString(sealed.SealedBody),
			BodyCommitment: hex.EncodeToString(header.Header.GetBodyCommitment()),
			Leaf:           hex.EncodeToString(sealed.Leaf[:]),
			KeyIndex:       uint32(index),
			SlotRow:        hex.EncodeToString(sealed.SlotRow(uint32(index)).Row),
			Entry:          hex.EncodeToString(sealed.EntryBytes(&fixture.slotId, uint32(index))),
		})
	}
	vectors.DepositBatch = hex.EncodeToString(testRecordStored(t, batch))
	for _, action := range testComputeCanonicalActionVectors(t).Actions {
		stored, err := ParseStoredCanonicalAction(testRecordFreezeHex(t, action.Stored))
		if err != nil {
			t.Fatal(err)
		}
		vectors.Actions = append(vectors.Actions, &testRecordFreezeAction{
			Name: action.Name, KindNo: stored.Action.GetKind(), Stored: action.Stored, PayloadSha256: action.PayloadSha256,
		})
	}
	return vectors
}

// Sealing the fixture again gives the file's bytes, entry for entry, and the file's actions are one of each kind the
// builder makes.
func TestRecordFreezeVectorsSealAgainToTheFile(t *testing.T) {
	computed := testRecordFreezeCompute(t)
	if *updateRecordFreezeVectors {
		encoded, err := json.MarshalIndent(computed, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(testRecordFreezeVectorsPath, append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := os.ReadFile(testRecordFreezeVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !*updateRecordFreezeVectors && !bytes.Equal(encoded, testRecordFreezeVectorBytes) {
		t.Fatal("the embedded vectors are not the file")
	}
	vectors := &testRecordFreezeVectors{}
	if err := json.Unmarshal(encoded, vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Entries) != len(computed.Entries) {
		t.Fatalf("%d entries in the file, %d sealed", len(vectors.Entries), len(computed.Entries))
	}
	for index, entry := range computed.Entries {
		if *entry != *vectors.Entries[index] {
			t.Errorf("sealing the %s entry again gave other bytes", entry.Kind)
		}
	}
	if vectors.DepositBatch != computed.DepositBatch || vectors.Decision != computed.Decision ||
		vectors.DecisionRequestSha256 != computed.DecisionRequestSha256 || vectors.DecisionPayloadSha256 != computed.DecisionPayloadSha256 {
		t.Error("the deposit batch or the decision differs from the fixture's")
	}
	if !slices.EqualFunc(vectors.Actions, computed.Actions, func(a *testRecordFreezeAction, b *testRecordFreezeAction) bool { return *a == *b }) {
		t.Error("the actions differ from the builder's")
	}
	kinds := map[uint32]bool{}
	for _, action := range vectors.Actions {
		kinds[action.KindNo] = true
	}
	for name, action := range testBuildableActions() {
		if !kinds[action.GetKind()] {
			t.Errorf("no action of %s's kind %d", name, action.GetKind())
		}
	}
}

var updateRecordFuzzSeeds = flag.Bool("update-record-fuzz-seeds", false, "rewrite testdata/fuzz/FuzzRecordHeader and FuzzRecordEntry")

// Each tag-and-value record of an encoding, in order.
func testRecordFreezeFields(t *testing.T, encoded []byte) [][]byte {
	t.Helper()
	fields := [][]byte{}
	for 0 < len(encoded) {
		_, _, length := protowire.ConsumeField(encoded)
		if length < 0 {
			t.Fatal("an encoding that does not parse")
		}
		fields = append(fields, encoded[:length])
		encoded = encoded[length:]
	}
	return fields
}

// §22.6's seed shapes of one valid encoding, by name: itself, its fields reordered, its first varint field repeated,
// unknown fields of each wire type, an unknown repeated field packed and the same unpacked, and its first varint
// field's value one byte longer than it needs to be.
func testRecordFuzzSeeds(t *testing.T, valid []byte) map[string][]byte {
	t.Helper()
	fields := testRecordFreezeFields(t, valid)
	reordered := slices.Clone(fields)
	slices.Reverse(reordered)
	var varintField []byte
	nonMinimal := []byte{}
	for _, field := range fields {
		number, wireType, tagLength := protowire.ConsumeTag(field)
		if wireType != protowire.VarintType || varintField != nil {
			nonMinimal = append(nonMinimal, field...)
			continue
		}
		varintField = field
		value, _ := protowire.ConsumeVarint(field[tagLength:])
		nonMinimal = protowire.AppendTag(nonMinimal, number, wireType)
		widened := protowire.AppendVarint(nil, value)
		widened[len(widened)-1] |= 0x80
		nonMinimal = append(nonMinimal, widened...)
		nonMinimal = append(nonMinimal, 0x00)
	}
	if varintField == nil {
		t.Fatal("no varint field to repeat")
	}
	unknown := bytes.Clone(valid)
	unknown = protowire.AppendTag(unknown, 99, protowire.BytesType)
	unknown = protowire.AppendBytes(unknown, []byte("later"))
	unknown = protowire.AppendTag(unknown, 98, protowire.VarintType)
	unknown = protowire.AppendVarint(unknown, 1500)
	unknown = protowire.AppendTag(unknown, 96, protowire.Fixed32Type)
	unknown = protowire.AppendFixed32(unknown, 7)
	unknown = protowire.AppendTag(unknown, 95, protowire.Fixed64Type)
	unknown = protowire.AppendFixed64(unknown, 9)
	packed := bytes.Clone(valid)
	packed = protowire.AppendTag(packed, 97, protowire.BytesType)
	packed = protowire.AppendBytes(packed, []byte{0x01, 0x02, 0xac, 0x02})
	unpacked := bytes.Clone(valid)
	for _, value := range []uint64{1, 2, 300} {
		unpacked = protowire.AppendTag(unpacked, 97, protowire.VarintType)
		unpacked = protowire.AppendVarint(unpacked, value)
	}
	return map[string][]byte{
		"seed-valid":       valid,
		"seed-reordered":   bytes.Join(reordered, nil),
		"seed-repeated":    append(bytes.Clone(valid), varintField...),
		"seed-unknown":     unknown,
		"seed-packed":      packed,
		"seed-unpacked":    unpacked,
		"seed-non-minimal": nonMinimal,
	}
}

// The seed files of FuzzRecordHeader and FuzzRecordEntry are the vectors' first header and entry in §22.6's shapes,
// in go test's corpus format, so every test run feeds them to both targets.
func TestRecordFuzzSeedsAreTheVectorsShapes(t *testing.T) {
	vectors := testRecordFreezeLoad(t)
	targets := map[string][]byte{
		"FuzzRecordHeader": testRecordFreezeHex(t, vectors.Entries[0].Header),
		"FuzzRecordEntry":  testRecordFreezeHex(t, vectors.Entries[0].Entry),
	}
	for target, valid := range targets {
		directory := filepath.Join("testdata", "fuzz", target)
		seeds := testRecordFuzzSeeds(t, valid)
		if *updateRecordFuzzSeeds {
			if err := os.MkdirAll(directory, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		for name, seed := range seeds {
			content := []byte(fmt.Sprintf("go test fuzz v1\n[]byte(%q)\n", seed))
			if *updateRecordFuzzSeeds {
				if err := os.WriteFile(filepath.Join(directory, name), content, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			held, err := os.ReadFile(filepath.Join(directory, name))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(held, content) {
				t.Errorf("%s/%s is not the vectors' %s", target, name, name)
			}
		}
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if _, ok := seeds[entry.Name()]; !ok && strings.HasPrefix(entry.Name(), "seed-") {
				t.Errorf("%s/%s is a seed this fixture does not make", target, entry.Name())
			}
		}
	}
}
