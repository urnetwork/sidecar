//go:build !js

// record_hash.go's values over stored bytes: RECORD.md section 20's vectors byte for byte, §16.6's ids over a fixed
// stored action and request in testdata/record/hashes.json, QD-771's detail vectors (a version-4 and a version-3
// action's sealed_detail nonce, recomputed here by hand and opened in record_action_detail_vectors_test.go), a
// re-encoded copy failing each hash, §22.5's §16 T1 request_sha256 case, and the parsers' refusals. The js leg opens
// no files, so these stay off it.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var updateRecordVectors = flag.Bool("update-record-vectors", false, "rewrite testdata/record/hashes.json")

const testRecordVectorsPath = "testdata/record/hashes.json"

// testdata/record/hashes.json: each case's inputs and the values computed from them, in lowercase hex.
type testRecordVectors struct {
	Comment        string `json:"comment"`
	BodyCommitment struct {
		Salt       string `json:"salt"`
		Body       string `json:"body"`
		Commitment string `json:"commitment"`
	} `json:"body_commitment"`
	Leaves []struct {
		SignedBody string `json:"signed_body"`
		Leaf       string `json:"leaf"`
	} `json:"leaves"`
	ToolActionId struct {
		RunId     string `json:"run_id"`
		ToolUseId string `json:"tool_use_id"`
		ActionId  string `json:"action_id"`
	} `json:"tool_action_id"`
	Approval struct {
		ApprovalId      string `json:"approval_id"`
		CanonicalAction string `json:"canonical_action"`
		PayloadSha256   string `json:"payload_sha256"`
		ActionId        string `json:"action_id"`
		EffectKey       string `json:"effect_key"`
		Request         string `json:"request"`
		RequestSha256   string `json:"request_sha256"`
	} `json:"approval"`
	DetailSeal []testRecordDetailSealVector `json:"detail_seal"`
}

// QD-771's vector for one action whose sealed_detail is sealed beside its clear fields: the inputs, the network, the
// config repo's test key (RK_g, its repo_id and g) and the action as stored, and what they derive, the clear bytes cut
// from it, the nonce and the aad, with the detail it opens to, deterministically encoded.
type testRecordDetailSealVector struct {
	Name       string `json:"name"`
	NetworkId  string `json:"network_id"`
	RepoId     string `json:"repo_id"`
	RepoKey    string `json:"repo_key"`
	Generation uint64 `json:"generation"`
	Stored     string `json:"stored"`
	Clear      string `json:"clear"`
	Nonce      string `json:"nonce"`
	Aad        string `json:"aad"`
	Detail     string `json:"detail"`
}

// Hex to bytes, failing the test on bad hex.
func testRecordHex(t *testing.T, text string) []byte {
	t.Helper()
	value, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// The fixed request the vectors hash: testRecordDnsAction's action, under approval_id 16 x 0x22, filed by a run
// 16 x 0x77 of agent 16 x 0x88 from sidecar 16 x 0x55, for approver 16 x 0x66.
func testRecordRequest(t *testing.T, storedAction []byte) *protocol.ApprovalRequest {
	approvalId := Id(bytes.Repeat([]byte{0x22}, 16))
	actionId := ApprovalActionId(approvalId, storedAction)
	payloadSha256 := ApprovalPayloadSha256(storedAction)
	return &protocol.ApprovalRequest{
		ApprovalId:         approvalId[:],
		ActionId:           actionId[:],
		RunId:              bytes.Repeat([]byte{0x77}, 16),
		AgentId:            bytes.Repeat([]byte{0x88}, 16),
		CanonicalAction:    storedAction,
		PayloadSha256:      payloadSha256[:],
		Summary:            "point www at the new host",
		Risk:               uint32(protocol.SidecarRisk_SIDECAR_RISK_NORMAL),
		RequesterSidecarId: bytes.Repeat([]byte{0x55}, 16),
		Approvers:          [][]byte{bytes.Repeat([]byte{0x66}, 16)},
		NotAfterMillis:     1762387200000,
		Version:            1,
	}
}

// The vectors' inputs, built as a daemon stores them, and every value computed from those inputs.
func testRecordComputeVectors(t *testing.T) *testRecordVectors {
	vectors := &testRecordVectors{
		Comment: "RECORD-M2-02's vectors: RECORD.md section 20's commitment, leaves and tool action_id, then §16.6's " +
			"payload_sha256, action_id, effect_key and request_sha256 over a fixed stored dns_set action and its request, " +
			"then section 20's detail nonces (QD-771): a version-4 bridge_forward and a version-3 access_request as " +
			"stored, each sealed_detail sealed beside its clear fields, nonce = SHA-256(the stored bytes with the field-38 " +
			"record cut out)[:16], aad = \"urnetwork-sidecar-v1/sealed-body\" || 0x00 || u32be(SIGNED_GRANT_ACTIVATE) || " +
			"network_id || nonce || u64be(generation), under the synthetic config key repo_key. Inputs are stored bytes, " +
			"never re-encoded. go test -run TestRecordHashVectors -update-record-vectors rewrites this file.",
	}
	salt := bytes.Repeat([]byte{0x11}, 32)
	body := []byte{0x0a, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f}
	commitment, err := RecordBodyCommitment(salt, body)
	if err != nil {
		t.Fatal(err)
	}
	vectors.BodyCommitment.Salt = hex.EncodeToString(salt)
	vectors.BodyCommitment.Body = hex.EncodeToString(body)
	vectors.BodyCommitment.Commitment = hex.EncodeToString(commitment[:])
	for _, signedBody := range []string{"h0", "h1", "h2"} {
		leaf := RecordLeafHash([]byte(signedBody))
		vectors.Leaves = append(vectors.Leaves, struct {
			SignedBody string `json:"signed_body"`
			Leaf       string `json:"leaf"`
		}{SignedBody: hex.EncodeToString([]byte(signedBody)), Leaf: hex.EncodeToString(leaf[:])})
	}
	runId := Id(bytes.Repeat([]byte{0x77}, 16))
	toolActionId, err := RecordToolActionId(runId, "toolu_01")
	if err != nil {
		t.Fatal(err)
	}
	vectors.ToolActionId.RunId = hex.EncodeToString(runId[:])
	vectors.ToolActionId.ToolUseId = "toolu_01"
	vectors.ToolActionId.ActionId = hex.EncodeToString(toolActionId[:])

	storedAction := testRecordStored(t, testRecordDnsAction())
	storedRequest := testRecordStored(t, testRecordRequest(t, storedAction))
	testRecordFillApproval(vectors, storedAction, storedRequest)

	// a version-4 forward as the builder stores it, and a version-3 access request as a build that knows version 3
	// does, each detail sealed beside its clear fields
	for _, c := range []struct {
		name   string
		action *protocol.CanonicalAction
		detail *protocol.CanonicalActionDetail
	}{
		{name: "bridge_forward", action: testBuildableActions()["bridge_forward"], detail: testForwardDetail()},
		{name: "access_request", action: testRecordAccessRequestAction(), detail: testRecordAccessRequestDetail()},
	} {
		stored, err := newCanonicalAction(c.action, testRecordVersionsKnown(1, 3, 4))
		if err != nil {
			t.Fatal(err)
		}
		repoKey := testConfigSealKey(testActionDetailGeneration)
		vector := testRecordDetailSealVector{
			Name: c.name, NetworkId: hex.EncodeToString(testActionDetailNetworkId().Bytes()),
			RepoId: hex.EncodeToString(repoKey.repoId.Bytes()), RepoKey: hex.EncodeToString(repoKey.repoKey),
			Generation: repoKey.Generation(), Stored: hex.EncodeToString(stored.Bytes),
			Detail: hex.EncodeToString(testRecordStored(t, c.detail)),
		}
		testRecordFillDetailSeal(t, &vector)
		vectors.DetailSeal = append(vectors.DetailSeal, vector)
	}
	return vectors
}

// A detail vector's derived values, by hand from its inputs, as QD-771 states them: the stored bytes with the field-38
// record cut out, the first 16 bytes of their SHA-256, and config_seal.go's aad with those in the nonce's place.
func testRecordFillDetailSeal(t *testing.T, vector *testRecordDetailSealVector) {
	t.Helper()
	clear := []byte{}
	for _, record := range testRecordFields(t, testRecordHex(t, vector.Stored)) {
		if number, _, _ := protowire.ConsumeTag(record); number != 38 {
			clear = append(clear, record...)
		}
	}
	clearSha256 := sha256.Sum256(clear)
	nonce := clearSha256[:16]
	aad := bytes.Join([][]byte{
		[]byte("urnetwork-sidecar-v1/sealed-body"),
		{0x00},
		binary.BigEndian.AppendUint32(nil, uint32(bridge.SignedType_SIGNED_GRANT_ACTIVATE)),
		testRecordHex(t, vector.NetworkId),
		nonce,
		binary.BigEndian.AppendUint64(nil, vector.Generation),
	}, nil)
	vector.Clear = hex.EncodeToString(clear)
	vector.Nonce = hex.EncodeToString(nonce)
	vector.Aad = hex.EncodeToString(aad)
}

// The approval case's values from its two stored inputs.
func testRecordFillApproval(vectors *testRecordVectors, storedAction []byte, storedRequest []byte) {
	approvalId := Id(bytes.Repeat([]byte{0x22}, 16))
	payloadSha256 := ApprovalPayloadSha256(storedAction)
	actionId := ApprovalActionId(approvalId, storedAction)
	effectKey := ApprovalEffectKey(approvalId, actionId)
	requestSha256 := ApprovalRequestSha256(storedRequest)
	vectors.Approval.ApprovalId = hex.EncodeToString(approvalId[:])
	vectors.Approval.CanonicalAction = hex.EncodeToString(storedAction)
	vectors.Approval.PayloadSha256 = hex.EncodeToString(payloadSha256[:])
	vectors.Approval.ActionId = hex.EncodeToString(actionId[:])
	vectors.Approval.EffectKey = hex.EncodeToString(effectKey[:])
	vectors.Approval.Request = hex.EncodeToString(storedRequest)
	vectors.Approval.RequestSha256 = hex.EncodeToString(requestSha256[:])
}

// Every value in the file recomputes from the file's own inputs, and section 20's values are the file's. The stored
// action and request come from the file, never from a marshal here, so a change in how protobuf encodes cannot move
// a vector.
func TestRecordHashVectors(t *testing.T) {
	if *updateRecordVectors {
		encoded, err := json.MarshalIndent(testRecordComputeVectors(t), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll("testdata/record", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(testRecordVectorsPath, append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := os.ReadFile(testRecordVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	vectors := &testRecordVectors{}
	if err := json.Unmarshal(encoded, vectors); err != nil {
		t.Fatal(err)
	}

	commitment, err := RecordBodyCommitment(testRecordHex(t, vectors.BodyCommitment.Salt), testRecordHex(t, vectors.BodyCommitment.Body))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(commitment[:]) != vectors.BodyCommitment.Commitment {
		t.Errorf("body_commitment is %x", commitment)
	}
	if len(vectors.Leaves) != 3 {
		t.Fatalf("%d leaves", len(vectors.Leaves))
	}
	for _, c := range vectors.Leaves {
		if leaf := RecordLeafHash(testRecordHex(t, c.SignedBody)); hex.EncodeToString(leaf[:]) != c.Leaf {
			t.Errorf("leaf of %s is %x", c.SignedBody, leaf)
		}
	}
	toolActionId, err := RecordToolActionId(Id(testRecordHex(t, vectors.ToolActionId.RunId)), vectors.ToolActionId.ToolUseId)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(toolActionId[:]) != vectors.ToolActionId.ActionId {
		t.Errorf("the tool action_id is %x", toolActionId)
	}

	storedAction := testRecordHex(t, vectors.Approval.CanonicalAction)
	storedRequest := testRecordHex(t, vectors.Approval.Request)
	recomputed := &testRecordVectors{}
	testRecordFillApproval(recomputed, storedAction, storedRequest)
	if recomputed.Approval != vectors.Approval {
		t.Errorf("the approval case recomputes as %+v", recomputed.Approval)
	}
	// The stored request and action are what their parsers take, with the ids the file names.
	request, err := ParseStoredApprovalRequest(storedRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(request.Action.Bytes, storedAction) || hex.EncodeToString(request.Request.GetActionId()) != vectors.Approval.ActionId {
		t.Error("the stored request does not carry the stored action and its action_id")
	}
	if requestSha256 := request.Sha256(); hex.EncodeToString(requestSha256[:]) != vectors.Approval.RequestSha256 {
		t.Errorf("the parsed request hashes as %x", requestSha256)
	}

	// QD-771's detail vectors: a version-4 and a version-3 action, each value recomputed by hand from the file's own
	// inputs and by record_hash.go's derivation, and each stored action one a build that knows its version parses,
	// its detail naming the vector's generation
	versions := []uint32{}
	for _, vector := range vectors.DetailSeal {
		recomputed := vector
		testRecordFillDetailSeal(t, &recomputed)
		if recomputed != vector {
			t.Errorf("%s: the detail vector recomputes as %+v", vector.Name, recomputed)
		}
		stored := testRecordHex(t, vector.Stored)
		derived, err := CanonicalActionDetailSealContext(Id(testRecordHex(t, vector.NetworkId)), stored)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(derived.Nonce) != vector.Nonce || hex.EncodeToString(derived.aad(vector.Generation)) != vector.Aad {
			t.Errorf("%s: the derivation gives nonce %x and aad %x", vector.Name, derived.Nonce, derived.aad(vector.Generation))
		}
		parsed, err := parseStoredCanonicalAction(stored, testRecordVersionsKnown(1, 3, 4))
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		if generation, err := ConfigSealedGeneration(parsed.Action.GetSealedDetail()); err != nil || generation != vector.Generation {
			t.Errorf("%s: its detail names generation %d: %v", vector.Name, generation, err)
		}
		versions = append(versions, parsed.Action.GetVersion())
	}
	if !slices.Equal(versions, []uint32{canonicalActionVersionSealedGrant, canonicalActionVersionAccessRequest}) {
		t.Fatalf("the detail vectors are of versions %v", versions)
	}

	// Section 20's values are the file's, byte for byte.
	section := newRecordMd(t).section(t, "20")
	recordMdRequire(t, "section 20", section,
		vectors.BodyCommitment.Commitment,
		vectors.Leaves[0].Leaf, vectors.Leaves[1].Leaf, vectors.Leaves[2].Leaf,
		vectors.ToolActionId.ActionId,
		vectors.DetailSeal[0].Nonce, vectors.DetailSeal[1].Nonce,
	)
}

// Each tag-and-value record of an encoding, in order.
func testRecordFields(t *testing.T, encoded []byte) [][]byte {
	fields := [][]byte{}
	for len(encoded) > 0 {
		_, wireType, tagLength := protowire.ConsumeTag(encoded)
		valueLength := protowire.ConsumeFieldValue(0, wireType, encoded[tagLength:])
		if tagLength < 0 || valueLength < 0 {
			t.Fatal("an encoding that does not parse")
		}
		fields = append(fields, encoded[:tagLength+valueLength])
		encoded = encoded[tagLength+valueLength:]
	}
	return fields
}

// The same message with its first two fields swapped: protobuf reads it alike, and no hash here may.
func testRecordReordered(t *testing.T, encoded []byte) []byte {
	fields := testRecordFields(t, encoded)
	if len(fields) < 2 {
		t.Fatal("too few fields to reorder")
	}
	fields[0], fields[1] = fields[1], fields[0]
	return bytes.Join(fields, nil)
}

// The same message with its first varint field's value one byte longer than it needs to be.
func testRecordNonMinimal(t *testing.T, encoded []byte) []byte {
	out := []byte{}
	widened := false
	for _, field := range testRecordFields(t, encoded) {
		number, wireType, tagLength := protowire.ConsumeTag(field)
		if widened || wireType != protowire.VarintType {
			out = append(out, field...)
			continue
		}
		value, _ := protowire.ConsumeVarint(field[tagLength:])
		out = protowire.AppendTag(out, number, wireType)
		out = append(out, protowire.AppendVarint(nil, value)...)
		out[len(out)-1] |= 0x80
		out = append(out, 0x00)
		widened = true
	}
	if !widened {
		t.Fatal("no varint to widen")
	}
	return out
}

// §16.8's what freezes: a re-encoding of an action, a request or a header reads as the same message, and every hash
// over it differs from the hash over what was stored, so no verifier may hash a re-marshal.
func TestRecordHashesCoverStoredBytes(t *testing.T) {
	approvalId := Id(bytes.Repeat([]byte{0x22}, 16))
	storedAction := testRecordStored(t, testRecordDnsAction())
	original, err := ParseStoredCanonicalAction(storedAction)
	if err != nil {
		t.Fatal(err)
	}
	for name, recoded := range map[string][]byte{
		"reordered":   testRecordReordered(t, storedAction),
		"non-minimal": testRecordNonMinimal(t, storedAction),
	} {
		parsed, err := ParseStoredCanonicalAction(recoded)
		if err != nil {
			t.Fatalf("a %s action: %v", name, err)
		}
		if !proto.Equal(parsed.Action, original.Action) {
			t.Errorf("a %s action reads differently", name)
		}
		if parsed.PayloadSha256() == original.PayloadSha256() || parsed.ActionId(approvalId) == original.ActionId(approvalId) {
			t.Errorf("a %s action hashes as the stored one", name)
		}
		if ApprovalEffectKey(approvalId, parsed.ActionId(approvalId)) == ApprovalEffectKey(approvalId, original.ActionId(approvalId)) {
			t.Errorf("a %s action keys the same effect", name)
		}
	}

	storedRequest := testRecordStored(t, testRecordRequest(t, storedAction))
	request, err := ParseStoredApprovalRequest(storedRequest)
	if err != nil {
		t.Fatal(err)
	}
	decision := testRecordDecision(t, request, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE)
	for name, recoded := range map[string][]byte{
		"reordered":   testRecordReordered(t, storedRequest),
		"non-minimal": testRecordNonMinimal(t, storedRequest),
	} {
		parsed, err := ParseStoredApprovalRequest(recoded)
		if err != nil {
			t.Fatalf("a %s request: %v", name, err)
		}
		if !proto.Equal(parsed.Request, request.Request) {
			t.Errorf("a %s request reads differently", name)
		}
		if parsed.Sha256() == request.Sha256() || decision.Binds(parsed) {
			t.Errorf("a decision on the stored request binds a %s copy", name)
		}
	}
	if !decision.Binds(request) {
		t.Error("the decision does not bind its own request")
	}

	header := testRecordOrderHeader(t, 0x0a, 3, 0x01)
	for name, recoded := range map[string][]byte{
		"reordered":   testRecordReordered(t, header.Bytes),
		"non-minimal": testRecordNonMinimal(t, header.Bytes),
	} {
		parsed, err := ParseStoredRecordHeader(recoded)
		if err != nil {
			t.Fatalf("a %s header: %v", name, err)
		}
		if !proto.Equal(parsed.Header, header.Header) || parsed.LeafHash() == header.LeafHash() {
			t.Errorf("a %s header reads differently or keeps the leaf", name)
		}
	}
}

// A signed decision on request, by a fixed approver key, on channel.
func testRecordDecision(t *testing.T, request *StoredApprovalRequest, channel protocol.ApprovalChannel) *StoredApprovalDecision {
	t.Helper()
	signed := testRecordSignDecision(t, testRecordDecisionBody(request, channel))
	decision, err := ParseSignedApprovalDecision(signed)
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

// The approver key the tests sign decisions with.
func testRecordApproverKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x99}, ed25519.SeedSize))
}

// An approval of request on channel, with the evidence that channel carries.
func testRecordDecisionBody(request *StoredApprovalRequest, channel protocol.ApprovalChannel) *protocol.ApprovalDecision {
	requestSha256 := request.Sha256()
	payloadSha256 := request.Action.PayloadSha256()
	decision := &protocol.ApprovalDecision{
		ApprovalId:         request.Request.GetApprovalId(),
		RequestSha256:      requestSha256[:],
		PayloadSha256:      payloadSha256[:],
		Decision:           uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE),
		Uses:               1,
		NotAfterMillis:     request.Request.GetNotAfterMillis(),
		ApproverMemberId:   bytes.Repeat([]byte{0x66}, 16),
		Channel:            uint32(channel),
		RequesterSidecarId: request.Request.GetRequesterSidecarId(),
		AuthPin:            &bridge.AuthPin{Version: 412, Chain: bytes.Repeat([]byte{0x12}, 32)},
		Version:            1,
	}
	if channel == protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS {
		decision.EvidenceSha256 = bytes.Repeat([]byte{0x13}, 32)
	}
	return decision
}

// decision in its Signed, signed as §6.9 says under purpose approval.
func testRecordSignDecision(t *testing.T, decision *protocol.ApprovalDecision) *bridge.Signed {
	t.Helper()
	body := testRecordStored(t, decision)
	return &bridge.Signed{
		Body:      body,
		Signature: ed25519.Sign(testRecordApproverKey(), bridge.SignedBytes(ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, body)),
		Type:      uint32(bridge.SignedType_SIGNED_APPROVAL_DECISION),
	}
}

// §22.5's §16 T1 request_sha256 case: a decision holds no run, agent, approver list or expiry, and still binds each,
// since request_sha256 covers the stored request; a request differing in any of them is one the decision never saw.
func TestRequestSha256BindsRunAgentApproversAndExpiry(t *testing.T) {
	storedAction := testRecordStored(t, testRecordDnsAction())
	request, err := ParseStoredApprovalRequest(testRecordStored(t, testRecordRequest(t, storedAction)))
	if err != nil {
		t.Fatal(err)
	}
	decision := testRecordDecision(t, request, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE)
	if !decision.Binds(request) {
		t.Fatal("the decision does not bind its own request")
	}
	// It holds no run or agent id (§16.8), nor the rest of what request_sha256 binds for it.
	decisionFields := decision.Decision.ProtoReflect().Descriptor().Fields()
	for _, name := range []protoreflect.Name{"run_id", "agent_id", "approvers", "summary", "tainted", "canonical_action"} {
		if decisionFields.ByName(name) != nil {
			t.Errorf("the decision now holds %s itself", name)
		}
	}
	variants := map[string]func(request *protocol.ApprovalRequest){
		"run_id":   func(request *protocol.ApprovalRequest) { request.RunId = bytes.Repeat([]byte{0x78}, 16) },
		"agent_id": func(request *protocol.ApprovalRequest) { request.AgentId = bytes.Repeat([]byte{0x89}, 16) },
		"approvers": func(request *protocol.ApprovalRequest) {
			request.Approvers = append(request.Approvers, bytes.Repeat([]byte{0x67}, 16))
		},
		"not_after_millis": func(request *protocol.ApprovalRequest) { request.NotAfterMillis += 1 },
		"tainted":          func(request *protocol.ApprovalRequest) { request.Tainted = true },
		"summary":          func(request *protocol.ApprovalRequest) { request.Summary = "something else" },
	}
	for name, change := range variants {
		variant := testRecordRequest(t, storedAction)
		change(variant)
		parsed, err := ParseStoredApprovalRequest(testRecordStored(t, variant))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if decision.Binds(parsed) {
			t.Errorf("a decision binds a request with another %s", name)
		}
	}
	// Another requester may not spend it either, even with the same request bytes otherwise.
	other := testRecordRequest(t, storedAction)
	other.RequesterSidecarId = bytes.Repeat([]byte{0x56}, 16)
	parsed, err := ParseStoredApprovalRequest(testRecordStored(t, other))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Binds(parsed) {
		t.Error("a decision binds another requester's request")
	}
}

// A header with an unknown kind and an unknown field parses, keeps both and its bytes, and reads its kind
// generically, so a v1 reader keeps and verifies a later writer's entry (§22.6's record.proto headers).
func TestParseStoredRecordHeaderKeepsWhatItCannotName(t *testing.T) {
	header := testRecordOrderHeader(t, 0x0a, 1, 0x01).Header
	header.Kind = 60000
	header.PrevSha256 = make([]byte, 32)
	stored := testRecordStored(t, header)
	stored = protowire.AppendVarint(protowire.AppendTag(stored, 1000, protowire.VarintType), 1)
	parsed, err := ParseStoredRecordHeader(stored)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.Bytes, stored) || parsed.LeafHash() != RecordLeafHash(stored) {
		t.Error("the parse did not keep the stored bytes")
	}
	if parsed.Kind() != 60000 || parsed.Kind().Known() || parsed.Kind().String() != "kind 60000" {
		t.Errorf("the kind reads %s", parsed.Kind())
	}
	if len(parsed.Header.ProtoReflect().GetUnknown()) == 0 {
		t.Error("the unknown field is gone")
	}
	// A source and a kind no table holds are kept too: the reader shows them as unknown.
	header.Source = 9
	header.Kind = 0
	if _, err := ParseStoredRecordHeader(testRecordStored(t, header)); err != nil {
		t.Errorf("a header of source 9 and kind 0: %v", err)
	}
}

// A header whose ids, chain, commitment or content refs are not their lengths, or whose seq is 0, does not parse.
func TestParseStoredRecordHeaderRefusesMalformed(t *testing.T) {
	cases := map[string]func(header *protocol.RecordHeader){
		"seq 0":              func(header *protocol.RecordHeader) { header.Seq = 0 },
		"entry_id":           func(header *protocol.RecordHeader) { header.EntryId = header.EntryId[:15] },
		"log_id":             func(header *protocol.RecordHeader) { header.LogId = nil },
		"writer":             func(header *protocol.RecordHeader) { header.WriterSidecarId = bytes.Repeat([]byte{1}, 17) },
		"prev_sha256":        func(header *protocol.RecordHeader) { header.PrevSha256 = header.PrevSha256[:31] },
		"body_commitment":    func(header *protocol.RecordHeader) { header.BodyCommitment = nil },
		"agent_id":           func(header *protocol.RecordHeader) { header.AgentId = []byte{1} },
		"run_id":             func(header *protocol.RecordHeader) { header.RunId = bytes.Repeat([]byte{1}, 32) },
		"action_id":          func(header *protocol.RecordHeader) { header.ActionId = bytes.Repeat([]byte{1}, 16) },
		"grant_id":           func(header *protocol.RecordHeader) { header.GrantId = bytes.Repeat([]byte{1}, 16) },
		"content commitment": func(header *protocol.RecordHeader) { header.Content[0].Commitment = []byte{1} },
		"content object_id":  func(header *protocol.RecordHeader) { header.Content[0].ObjectId = nil },
	}
	for name, change := range cases {
		header := testRecordOrderHeader(t, 0x0a, 2, 0x01).Header
		header.Content = []*protocol.ContentRef{{
			RepoId:     bytes.Repeat([]byte{0x21}, 16),
			ObjectId:   bytes.Repeat([]byte{0x22}, 16),
			Commitment: bytes.Repeat([]byte{0x23}, 32),
		}}
		if _, err := ParseStoredRecordHeader(testRecordStored(t, header)); err != nil {
			t.Fatalf("the unchanged header: %v", err)
		}
		change(header)
		if _, err := ParseStoredRecordHeader(testRecordStored(t, header)); !errors.Is(err, ErrRecordStoredInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParseStoredRecordHeader([]byte{0x0a, 0xff}); !errors.Is(err, ErrRecordStoredInvalid) {
		t.Errorf("bytes that do not parse: %v", err)
	}
}

// A commitment takes a 32-byte salt, and a tool action_id a non-empty id that fits its length prefix.
func TestRecordHashesRefuseWhatTheirFormulasCannotHold(t *testing.T) {
	for _, salt := range [][]byte{nil, bytes.Repeat([]byte{1}, 31), bytes.Repeat([]byte{1}, 33)} {
		if _, err := RecordBodyCommitment(salt, []byte("body")); !errors.Is(err, ErrRecordStoredInvalid) {
			t.Errorf("a salt of %d bytes: %v", len(salt), err)
		}
	}
	runId := Id(bytes.Repeat([]byte{0x77}, 16))
	if _, err := RecordToolActionId(runId, ""); !errors.Is(err, ErrRecordStoredInvalid) {
		t.Errorf("an empty tool_use_id: %v", err)
	}
	if _, err := RecordToolActionId(runId, string(bytes.Repeat([]byte("x"), 65536))); !errors.Is(err, ErrRecordStoredInvalid) {
		t.Errorf("a tool_use_id past its prefix: %v", err)
	}
	if _, err := RecordToolActionId(runId, string(bytes.Repeat([]byte("x"), 65535))); err != nil {
		t.Errorf("a tool_use_id at its prefix: %v", err)
	}
	// Two runs' calls of one id are two actions.
	first, _ := RecordToolActionId(runId, "toolu_01")
	second, _ := RecordToolActionId(Id(bytes.Repeat([]byte{0x78}, 16)), "toolu_01")
	if first == second {
		t.Error("two runs' calls share an action_id")
	}
}

// What an approver and a spender refuse in a request: an unknown version or field, a risk SidecarRisk does not name,
// no expiry, a payload_sha256 or action_id that is not its action's, and an action ParseStoredCanonicalAction refuses.
func TestParseStoredApprovalRequestRefuses(t *testing.T) {
	storedAction := testRecordStored(t, testRecordDnsAction())
	cases := map[string]struct {
		change func(request *protocol.ApprovalRequest)
		err    error
	}{
		"version 2":      {change: func(request *protocol.ApprovalRequest) { request.Version = 2 }, err: ErrApprovalVersionUnknown},
		"version 0":      {change: func(request *protocol.ApprovalRequest) { request.Version = 0 }, err: ErrApprovalVersionUnknown},
		"risk 0":         {change: func(request *protocol.ApprovalRequest) { request.Risk = 0 }, err: ErrRecordStoredInvalid},
		"risk 3":         {change: func(request *protocol.ApprovalRequest) { request.Risk = 3 }, err: ErrRecordStoredInvalid},
		"no expiry":      {change: func(request *protocol.ApprovalRequest) { request.NotAfterMillis = 0 }, err: ErrRecordStoredInvalid},
		"approval_id":    {change: func(request *protocol.ApprovalRequest) { request.ApprovalId = request.ApprovalId[:8] }, err: ErrRecordStoredInvalid},
		"approver":       {change: func(request *protocol.ApprovalRequest) { request.Approvers = [][]byte{{1}} }, err: ErrRecordStoredInvalid},
		"payload_sha256": {change: func(request *protocol.ApprovalRequest) { request.PayloadSha256[0] ^= 1 }, err: ErrRecordStoredInvalid},
		"action_id":      {change: func(request *protocol.ApprovalRequest) { request.ActionId[0] ^= 1 }, err: ErrRecordStoredInvalid},
		"unknown field": {
			change: func(request *protocol.ApprovalRequest) {
				request.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
			},
			err: ErrRecordStoredInvalid,
		},
		"action version 2": {
			change: func(request *protocol.ApprovalRequest) {
				action := testRecordDnsAction()
				action.Version = 2
				request.CanonicalAction = testRecordStored(t, action)
				payloadSha256 := ApprovalPayloadSha256(request.CanonicalAction)
				actionId := ApprovalActionId(Id(request.ApprovalId), request.CanonicalAction)
				request.PayloadSha256 = payloadSha256[:]
				request.ActionId = actionId[:]
			},
			err: ErrCanonicalActionVersionUnknown,
		},
	}
	for name, c := range cases {
		request := testRecordRequest(t, storedAction)
		c.change(request)
		if _, err := ParseStoredApprovalRequest(testRecordStored(t, request)); !errors.Is(err, c.err) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// What a spender and a gate refuse in a decision, and what they ignore: sshsig, which no decision needs
// (plan-MCP-risk-classifier#1).
func TestParseSignedApprovalDecisionRefuses(t *testing.T) {
	storedAction := testRecordStored(t, testRecordDnsAction())
	request, err := ParseStoredApprovalRequest(testRecordStored(t, testRecordRequest(t, storedAction)))
	if err != nil {
		t.Fatal(err)
	}
	for _, channel := range []protocol.ApprovalChannel{
		protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE,
		protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE,
		protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS,
	} {
		decision := testRecordDecision(t, request, channel)
		if !decision.Binds(request) {
			t.Errorf("channel %s: the decision does not bind its request", channel)
		}
	}
	ignored := testRecordDecisionBody(request, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE)
	ignored.Sshsig = []byte("not a signature")
	if _, err := ParseSignedApprovalDecision(testRecordSignDecision(t, ignored)); err != nil {
		t.Errorf("an sshsig, ignored: %v", err)
	}
	deny := testRecordDecisionBody(request, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE)
	deny.Decision = uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_DENY)
	deny.Uses = 0
	if _, err := ParseSignedApprovalDecision(testRecordSignDecision(t, deny)); err != nil {
		t.Errorf("a denial of no uses: %v", err)
	}

	cases := map[string]struct {
		change func(decision *protocol.ApprovalDecision)
		err    error
	}{
		"version 2":            {change: func(decision *protocol.ApprovalDecision) { decision.Version = 2 }, err: ErrApprovalVersionUnknown},
		"verdict 0":            {change: func(decision *protocol.ApprovalDecision) { decision.Decision = 0 }, err: ErrRecordStoredInvalid},
		"verdict 3":            {change: func(decision *protocol.ApprovalDecision) { decision.Decision = 3 }, err: ErrRecordStoredInvalid},
		"channel 0":            {change: func(decision *protocol.ApprovalDecision) { decision.Channel = 0 }, err: ErrRecordStoredInvalid},
		"channel 4":            {change: func(decision *protocol.ApprovalDecision) { decision.Channel = 4 }, err: ErrRecordStoredInvalid},
		"device with evidence": {change: func(decision *protocol.ApprovalDecision) { decision.EvidenceSha256 = bytes.Repeat([]byte{1}, 32) }, err: ErrRecordStoredInvalid},
		"presence with evidence": {
			change: func(decision *protocol.ApprovalDecision) {
				decision.Channel = uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE)
				decision.EvidenceSha256 = bytes.Repeat([]byte{1}, 32)
			},
			err: ErrRecordStoredInvalid,
		},
		"harness without evidence": {
			change: func(decision *protocol.ApprovalDecision) {
				decision.Channel = uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS)
			},
			err: ErrRecordStoredInvalid,
		},
		"approval of no uses": {change: func(decision *protocol.ApprovalDecision) { decision.Uses = 0 }, err: ErrRecordStoredInvalid},
		"no expiry":           {change: func(decision *protocol.ApprovalDecision) { decision.NotAfterMillis = 0 }, err: ErrRecordStoredInvalid},
		"no pin":              {change: func(decision *protocol.ApprovalDecision) { decision.AuthPin = nil }, err: ErrRecordStoredInvalid},
		"request_sha256":      {change: func(decision *protocol.ApprovalDecision) { decision.RequestSha256 = decision.RequestSha256[:16] }, err: ErrRecordStoredInvalid},
		"approver_member_id":  {change: func(decision *protocol.ApprovalDecision) { decision.ApproverMemberId = nil }, err: ErrRecordStoredInvalid},
		"unknown field": {
			change: func(decision *protocol.ApprovalDecision) {
				decision.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
			},
			err: ErrRecordStoredInvalid,
		},
	}
	for name, c := range cases {
		decision := testRecordDecisionBody(request, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE)
		c.change(decision)
		if _, err := ParseSignedApprovalDecision(testRecordSignDecision(t, decision)); !errors.Is(err, c.err) {
			t.Errorf("%s: %v", name, err)
		}
	}

	cancel := testRecordSignDecision(t, testRecordDecisionBody(request, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE))
	cancel.Type = uint32(bridge.SignedType_SIGNED_APPROVAL_CANCEL)
	if _, err := ParseSignedApprovalDecision(cancel); !errors.Is(err, ErrRecordStoredInvalid) {
		t.Errorf("a Signed of another type: %v", err)
	}
	if _, err := ParseSignedApprovalDecision(nil); !errors.Is(err, ErrRecordStoredInvalid) {
		t.Errorf("no Signed: %v", err)
	}
	storedSigned := testRecordStored(t, testRecordSignDecision(t, testRecordDecisionBody(request, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE)))
	if _, err := ParseStoredApprovalDecision(storedSigned); err != nil {
		t.Errorf("a stored Signed decision: %v", err)
	}
}

// A decision verifies under its approver's key over the bytes it was signed as, and not once a byte changes or under
// another purpose's signature.
func TestStoredApprovalDecisionVerifies(t *testing.T) {
	storedAction := testRecordStored(t, testRecordDnsAction())
	request, err := ParseStoredApprovalRequest(testRecordStored(t, testRecordRequest(t, storedAction)))
	if err != nil {
		t.Fatal(err)
	}
	publicKey := testRecordApproverKey().Public().(ed25519.PublicKey)
	decision := testRecordDecision(t, request, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE)
	if err := decision.Verify(bridge.SignedKeyAlgEd25519, publicKey); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decision.Bytes, decision.Signed.GetBody()) {
		t.Error("the decision's bytes are not its Signed's body")
	}

	tampered := proto.Clone(decision.Signed).(*bridge.Signed)
	tampered.Body = slices.Clone(tampered.Body)
	tampered.Body[len(tampered.Body)-1] ^= 1
	tamperedDecision := &StoredApprovalDecision{Decision: decision.Decision, Signed: tampered, Bytes: tampered.Body}
	if err := tamperedDecision.Verify(bridge.SignedKeyAlgEd25519, publicKey); err == nil {
		t.Error("a changed byte verifies")
	}

	// The same body signed under record-entry is no approval.
	misPurposed := proto.Clone(decision.Signed).(*bridge.Signed)
	misPurposed.Signature = ed25519.Sign(testRecordApproverKey(), bridge.SignedBytes(RecordEntryPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, misPurposed.Body))
	wrongPurpose := &StoredApprovalDecision{Decision: decision.Decision, Signed: misPurposed, Bytes: misPurposed.Body}
	if err := wrongPurpose.Verify(bridge.SignedKeyAlgEd25519, publicKey); err == nil {
		t.Error("a decision signed under record-entry verifies")
	}

	otherKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x98}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if err := decision.Verify(bridge.SignedKeyAlgEd25519, otherKey); err == nil {
		t.Error("a decision verifies under another key")
	}
}

// §16.6's two formulas as the design writes them, recomputed by hand over the vectors' stored action, so a domain
// string or an order here cannot drift from the text.
func TestApprovalIdsFollowSectionSixteenSix(t *testing.T) {
	design, err := os.ReadFile("DESIGN.md")
	if errors.Is(err, os.ErrNotExist) {
		design, err = os.ReadFile("../DESIGN.md")
	}
	if err != nil {
		t.Fatal(err)
	}
	recordMdRequire(t, "§16.6", string(design),
		`action_id SHA-256("urnetwork-sidecar-v1/action" || approval_id || this use's CanonicalAction bytes)`,
		`effect_key SHA-256("urnetwork-sidecar-v1/effect" || approval_id || action_id)`,
	)
	approvalId := Id(bytes.Repeat([]byte{0x22}, 16))
	storedAction := testRecordStored(t, testRecordDnsAction())
	actionId := sha256.Sum256(bytes.Join([][]byte{[]byte("urnetwork-sidecar-v1/action"), approvalId[:], storedAction}, nil))
	if ApprovalActionId(approvalId, storedAction) != actionId {
		t.Error("action_id is not §16.6's formula")
	}
	effectKey := sha256.Sum256(bytes.Join([][]byte{[]byte("urnetwork-sidecar-v1/effect"), approvalId[:], actionId[:]}, nil))
	if ApprovalEffectKey(approvalId, actionId) != effectKey {
		t.Error("effect_key is not §16.6's formula")
	}
	if ApprovalPayloadSha256(storedAction) != sha256.Sum256(storedAction) {
		t.Error("payload_sha256 is not SHA-256 of the stored action")
	}
	// Another approval of the same action is another action and another effect.
	otherApprovalId := Id(bytes.Repeat([]byte{0x23}, 16))
	if ApprovalActionId(otherApprovalId, storedAction) == actionId || ApprovalEffectKey(otherApprovalId, actionId) == effectKey {
		t.Error("two approvals of one action share an id")
	}
}
