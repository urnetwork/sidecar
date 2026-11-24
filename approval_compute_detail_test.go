//go:build !ios_extension && !js

package sidecar

// CACL-M12-01: version 5's sealed detail (approval_compute_detail.go; DESIGN-COMPUTE §16.3). Fixed keys and nonces give
// testdata/approval_compute/detail_vectors.json, byte for byte: a CanonicalActionDetail5 sealed as version 4's detail
// is, under the config repo's key and the action's own clear identity, its aad's SignedType SIGNED_APPROVAL_DECISION.
// It opens beside its clear fields alone and in its network alone; one sealed under SIGNED_GRANT_ACTIVATE beside the
// same fields opens nowhere; each version's opener refuses the other's detail; and a detail is held to its action.
// SIDECAR_WRITE_VECTORS rewrites the vectors. Synthetic values only.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Where the vectors are, from this directory.
const testComputeDetailVectorsPath = "testdata/approval_compute/detail_vectors.json"

// One sealed action: what sealed it, what it holds, and what it derives.
type testComputeDetailVector struct {
	Name       string `json:"name"`
	NetworkId  string `json:"network_id"`
	RepoId     string `json:"repo_id"`
	Generation uint64 `json:"generation"`
	RepoKey    string `json:"repo_key"`
	// the bytes the AEAD's nonce was drawn from
	Random string `json:"random"`
	// CanonicalActionDetail5 as the seal took it
	Detail string `json:"detail"`
	// the action's clear fields as stored, field 38 left out
	Clear string `json:"clear"`
	// the context's nonce: SHA-256(clear)[:16]
	Nonce         string `json:"nonce"`
	Stored        string `json:"stored"`
	PayloadSha256 string `json:"payload_sha256"`
}

// The vectors file.
type testComputeDetailVectorFile struct {
	Comment []string                   `json:"comment"`
	Vectors []*testComputeDetailVector `json:"vectors"`
}

// The vectors this build makes from the fixtures: kinds 19 and 21 as their builders seal them.
func testComputeDetailVectorsBuilt(t *testing.T) *testComputeDetailVectorFile {
	t.Helper()
	file := &testComputeDetailVectorFile{Comment: []string{
		"DESIGN-COMPUTE §16.3's version-5 sealed detail (CACL-M12-01): a CanonicalActionDetail5 sealed under the config",
		"repo's key in config_seal.go's format, its context SIGNED_APPROVAL_DECISION, the network and SHA-256 over the",
		"action's clear fields as stored, field 38 left out, its first 16 bytes the nonce. Synthetic values only.",
		"SIDECAR_WRITE_VECTORS=1 go test -run '^TestVersion5SealedDetailVectors$' . rewrites this file.",
	}}
	repoKey := testConfigSealKey(testActionDetailGeneration)
	for _, kind := range []SidecarActionKind{SidecarActionEnclaveCreate, SidecarActionComputeBudgetRaise} {
		stored := testComputeStored(t, kind)
		clear, _ := testCutDetailRecords(t, stored.Bytes)
		nonce := sha256.Sum256(clear)
		detailBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(testComputeDetails()[kind])
		if err != nil {
			t.Fatal(err)
		}
		payloadSha256 := stored.PayloadSha256()
		random, err := io.ReadAll(testActionDetailRandom())
		if err != nil {
			t.Fatal(err)
		}
		file.Vectors = append(file.Vectors, &testComputeDetailVector{
			Name:          approvalKindName(kind),
			NetworkId:     hex.EncodeToString(testActionDetailNetworkId().Bytes()),
			RepoId:        hex.EncodeToString(repoKey.repoId.Bytes()),
			Generation:    repoKey.generation,
			RepoKey:       hex.EncodeToString(repoKey.repoKey),
			Random:        hex.EncodeToString(random),
			Detail:        hex.EncodeToString(detailBytes),
			Clear:         hex.EncodeToString(clear),
			Nonce:         hex.EncodeToString(nonce[:configNonceByteCount]),
			Stored:        hex.EncodeToString(stored.Bytes),
			PayloadSha256: hex.EncodeToString(payloadSha256[:]),
		})
	}
	return file
}

// The vectors on disk equal what this build makes, and each opens as its approver opens it: under the context its own
// stored bytes derive, SIGNED_APPROVAL_DECISION, in its network alone, to its detail; under a device holding no
// generation to none; and a detail sealed beside the same clear fields under SIGNED_GRANT_ACTIVATE to none.
func TestVersion5SealedDetailVectors(t *testing.T) {
	built := testComputeDetailVectorsBuilt(t)
	if os.Getenv(testWriteVectorsEnvironment) != "" {
		encoded, err := json.MarshalIndent(built, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(testComputeDetailVectorsPath, append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := os.ReadFile(testComputeDetailVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	held := &testComputeDetailVectorFile{}
	if err := json.Unmarshal(encoded, held); err != nil {
		t.Fatal(err)
	}
	builtBytes, _ := json.Marshal(built)
	heldBytes, _ := json.Marshal(held)
	if string(builtBytes) != string(heldBytes) {
		t.Errorf("%s is stale; %s=1 rewrites it", testComputeDetailVectorsPath, testWriteVectorsEnvironment)
	}
	if len(held.Vectors) != 2 {
		t.Fatalf("%d vectors", len(held.Vectors))
	}
	for _, vector := range held.Vectors {
		stored, err := ParseStoredCanonicalAction(testRecordHex(t, vector.Stored))
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		networkId := Id(testRecordHex(t, vector.NetworkId))
		repoKeyAt := testConfigSealKeyAt(&EvsRepoKey{
			repoId: Id(testRecordHex(t, vector.RepoId)), generation: vector.Generation, repoKey: testRecordHex(t, vector.RepoKey),
		})
		want := &protocol.CanonicalActionDetail5{}
		if err := proto.Unmarshal(testRecordHex(t, vector.Detail), want); err != nil {
			t.Fatal(err)
		}
		context, err := CanonicalActionDetail5SealContext(networkId, stored.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if context.SignedType != bridge.SignedType_SIGNED_APPROVAL_DECISION || hex.EncodeToString(context.Nonce) != vector.Nonce {
			t.Errorf("%s: the derived context %+v", vector.Name, context)
		}
		if nonce := sha256.Sum256(testRecordHex(t, vector.Clear)); hex.EncodeToString(nonce[:configNonceByteCount]) != vector.Nonce {
			t.Errorf("%s: the nonce is not SHA-256 of the clear fields", vector.Name)
		}
		if payload := stored.PayloadSha256(); hex.EncodeToString(payload[:]) != vector.PayloadSha256 {
			t.Errorf("%s: payload_sha256", vector.Name)
		}
		detail, err := OpenCanonicalActionDetail5(stored, networkId, repoKeyAt)
		if err != nil || !proto.Equal(detail, want) {
			t.Errorf("%s: opened %+v, %v", vector.Name, detail, err)
		}
		if _, err := OpenCanonicalActionDetail5(stored, testConfigId("another network"), repoKeyAt); !errors.Is(err, ErrConfigSealInvalid) {
			t.Errorf("%s in another network: %v", vector.Name, err)
		}
		if _, err := OpenCanonicalActionDetail5(stored, networkId, nil); !errors.Is(err, ErrConfigSealGenerationMissing) {
			t.Errorf("%s on a device holding no generation: %v", vector.Name, err)
		}
		// the version-4 opener takes no version-5 detail
		if _, err := OpenCanonicalActionDetail(stored, networkId, repoKeyAt); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("%s through version 4's opener: %v", vector.Name, err)
		}

		// sealed under SIGNED_GRANT_ACTIVATE beside the same clear fields, with their nonce and network, it opens nowhere
		grantContext, err := CanonicalActionDetailSealContext(networkId, stored.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if grantContext.SignedType != bridge.SignedType_SIGNED_GRANT_ACTIVATE || string(grantContext.Nonce) != string(context.Nonce) {
			t.Errorf("%s: version 4's context %+v", vector.Name, grantContext)
		}
		otherType := proto.Clone(stored.Action).(*protocol.CanonicalAction)
		if otherType.SealedDetail, err = SealConfigBody(testConfigSealKey(testActionDetailGeneration), grantContext, want, testActionDetailRandom()); err != nil {
			t.Fatal(err)
		}
		carried, err := NewCanonicalAction(otherType)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenCanonicalActionDetail5(carried, networkId, repoKeyAt); !errors.Is(err, ErrConfigSealInvalid) {
			t.Errorf("%s sealed under SIGNED_GRANT_ACTIVATE: %v", vector.Name, err)
		}
	}
}

// A detail opens beside the clear fields it was sealed with alone: an action differing in one, the shape, the provider,
// the mode or the price on kind 19, the amount, period or agent on kind 21, parses and opens to nothing.
func TestVersion5SealedDetailOpensBesideItsOwnClearFieldsAlone(t *testing.T) {
	repoKeyAt := testConfigSealKeyAt(testConfigSealKey(testActionDetailGeneration))
	for kind, changes := range map[SidecarActionKind]map[string]func(action *protocol.CanonicalAction){
		SidecarActionEnclaveCreate: {
			"shape":    func(action *protocol.CanonicalAction) { action.Enclave.Shape = "cpu-8" },
			"provider": func(action *protocol.CanonicalAction) { action.Enclave.Provider = "lium" },
			"price":    func(action *protocol.CanonicalAction) { action.Enclave.PricePerHour += 1 },
			"mode": func(action *protocol.CanonicalAction) {
				action.EgressMode = uint32(bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE)
			},
		},
		SidecarActionComputeBudgetRaise: {
			"amount": func(action *protocol.CanonicalAction) { action.Budget.Amount += 1 },
			"period": func(action *protocol.CanonicalAction) { action.Budget.Period = approvalComputeBudgetPeriodMonth },
			"agent":  func(action *protocol.CanonicalAction) { action.Budget.AgentId = testComputeId(0x61) },
		},
	} {
		stored := testComputeStored(t, kind)
		if _, err := OpenCanonicalActionDetail5(stored, testActionDetailNetworkId(), repoKeyAt); err != nil {
			t.Fatalf("kind %d beside its own fields: %v", kind, err)
		}
		for name, change := range changes {
			altered := proto.Clone(stored.Action).(*protocol.CanonicalAction)
			change(altered)
			parsed, err := ParseStoredCanonicalAction(testRecordStored(t, altered))
			if err != nil {
				t.Fatalf("kind %d, another %s: %v", kind, name, err)
			}
			if _, err := OpenCanonicalActionDetail5(parsed, testActionDetailNetworkId(), repoKeyAt); !errors.Is(err, ErrConfigSealInvalid) {
				t.Errorf("kind %d beside another %s: %v", kind, name, err)
			}
		}
	}
	// version 5's opener takes no version-4 detail, and version 4's sealer seals no version-5 action
	if _, err := OpenCanonicalActionDetail5(testSealedForward(t), testActionDetailNetworkId(), repoKeyAt); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a version-4 detail through version 5's opener: %v", err)
	}
	if _, err := NewSealedCanonicalAction(testComputeActions(t)[SidecarActionEnclaveCreate], testForwardDetail(), testConfigSealKey(testActionDetailGeneration), testActionDetailNetworkId(), nil); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a version-5 action through version 4's sealer: %v", err)
	}
	forward := proto.Clone(testBuildableActions()["bridge_forward"]).(*protocol.CanonicalAction)
	forward.SealedDetail = nil
	if _, err := NewSealedCanonicalAction5(forward, &protocol.CanonicalActionDetail5{Name: "x", Role: 1}, testConfigSealKey(testActionDetailGeneration), testActionDetailNetworkId(), nil); err == nil {
		t.Error("a forward sealed a version-5 detail")
	}
	// kinds 20 and 22 to 26 seal nothing at version 5
	for _, kind := range []SidecarActionKind{SidecarActionEnclaveEgressDirect, SidecarActionTaintedSend, SidecarActionServiceWrite} {
		if _, err := NewSealedCanonicalAction5(testComputeActions(t)[kind], &protocol.CanonicalActionDetail5{}, testConfigSealKey(testActionDetailGeneration), testActionDetailNetworkId(), nil); err == nil {
			t.Errorf("kind %d sealed a detail", kind)
		}
	}
}

// A detail is held to its action: kind 19's names its enclave and a role and no grant; kind 21's names no enclave, role
// or harness, and a grant only where field 43 names no agent; no field this build cannot name.
func TestVersion5SealedDetailHeldToItsAction(t *testing.T) {
	create := testComputeActions(t)[SidecarActionEnclaveCreate]
	raise := testComputeActions(t)[SidecarActionComputeBudgetRaise]
	grantRaise := proto.Clone(raise).(*protocol.CanonicalAction)
	grantRaise.Budget.AgentId = nil
	unknown := &protocol.CanonicalActionDetail5{Name: "builder", Role: 1}
	unknown.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	for name, c := range map[string]struct {
		action *protocol.CanonicalAction
		detail *protocol.CanonicalActionDetail5
		ok     bool
	}{
		"a create":                       {action: create, detail: &protocol.CanonicalActionDetail5{Name: "builder", Role: 1, Harness: "pig"}, ok: true},
		"the indexer":                    {action: create, detail: &protocol.CanonicalActionDetail5{Name: "indexer", Role: 2}, ok: true},
		"a create with no name":          {action: create, detail: &protocol.CanonicalActionDetail5{Role: 1}},
		"a create with no role":          {action: create, detail: &protocol.CanonicalActionDetail5{Name: "builder"}},
		"role 3":                         {action: create, detail: &protocol.CanonicalActionDetail5{Name: "builder", Role: 3}},
		"a create naming a grant":        {action: create, detail: &protocol.CanonicalActionDetail5{Name: "builder", Role: 1, GrantId: testComputeId(1)}},
		"an agent's raise":               {action: raise, detail: &protocol.CanonicalActionDetail5{}, ok: true},
		"a grant's raise":                {action: grantRaise, detail: &protocol.CanonicalActionDetail5{GrantId: testComputeId(1)}, ok: true},
		"a raise naming both":            {action: raise, detail: &protocol.CanonicalActionDetail5{GrantId: testComputeId(1)}},
		"a raise naming an enclave":      {action: raise, detail: &protocol.CanonicalActionDetail5{Name: "builder"}},
		"a raise naming a harness":       {action: raise, detail: &protocol.CanonicalActionDetail5{Harness: "pig"}},
		"a field this build cannot name": {action: create, detail: unknown},
		"no detail":                      {action: create},
	} {
		err := CheckCanonicalActionDetail5(c.action, c.detail)
		if (err == nil) != c.ok || (!c.ok && !errors.Is(err, ErrCanonicalActionDetailInvalid)) {
			t.Errorf("%s: %v", name, err)
		}
		if !c.ok || c.detail == nil {
			continue
		}
		clear := proto.Clone(c.action).(*protocol.CanonicalAction)
		if _, err := NewSealedCanonicalAction5(clear, c.detail, testConfigSealKey(testActionDetailGeneration), testActionDetailNetworkId(), nil); err != nil {
			t.Errorf("%s did not seal: %v", name, err)
		}
	}
	// sealed beside an action it is not held to, it is refused where it is opened, after its AEAD passes
	misheld := proto.Clone(create).(*protocol.CanonicalAction)
	clearBytes, err := canonicalActionClearBytes(misheld)
	if err != nil {
		t.Fatal(err)
	}
	sealContext, err := CanonicalActionDetail5SealContext(testActionDetailNetworkId(), clearBytes)
	if err != nil {
		t.Fatal(err)
	}
	if misheld.SealedDetail, err = SealConfigBody(testConfigSealKey(testActionDetailGeneration), sealContext, &protocol.CanonicalActionDetail5{Role: 1}, nil); err != nil {
		t.Fatal(err)
	}
	stored, err := NewCanonicalAction(misheld)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCanonicalActionDetail5(stored, testActionDetailNetworkId(), testConfigSealKeyAt(testConfigSealKey(testActionDetailGeneration))); !errors.Is(err, ErrCanonicalActionDetailInvalid) {
		t.Errorf("a create's detail with no name: %v", err)
	}
}

// The production path: a daemon's sidecar seals a create's detail under its installed config key in its own network
// (Sidecar.SealActionDetail5), and opens it with its installed keys (Sidecar.OpenActionDetail5); with no config keys
// installed it seals and opens nothing.
func TestVersion5SealedDetailWithTheDevicesInstalledKeys(t *testing.T) {
	world := newTestApproverWorld(t)
	clear := testComputeActions(t)[SidecarActionEnclaveCreate]
	detail := testComputeDetails()[SidecarActionEnclaveCreate]
	if _, err := world.sidecar.SealActionDetail5(t.Context(), clear, detail); !errors.Is(err, ErrConfigSealGenerationMissing) {
		t.Errorf("sealing with no config keys: %v", err)
	}
	if _, err := world.sidecar.OpenActionDetail5(testComputeStored(t, SidecarActionEnclaveCreate)); !errors.Is(err, ErrConfigSealGenerationMissing) {
		t.Errorf("opening with no config keys: %v", err)
	}
	t.Cleanup(world.sidecar.InstallConfigKeys(&testConfigKeys{key: testConfigSealKey(testActionDetailGeneration)}))
	create, err := world.sidecar.SealActionDetail5(t.Context(), clear, detail)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := world.sidecar.OpenActionDetail5(create)
	if err != nil || !proto.Equal(opened, detail) {
		t.Errorf("the sidecar's own open: %+v, %v", opened, err)
	}
	// sealed in the sidecar's own network, so a device in the test's network opens nothing of it
	if _, err := OpenCanonicalActionDetail5(create, testActionDetailNetworkId(), testConfigSealKeyAt(testConfigSealKey(testActionDetailGeneration))); !errors.Is(err, ErrConfigSealInvalid) {
		t.Errorf("another network's device: %v", err)
	}
	if opened, err := world.sidecar.OpenActionDetail5(testComputeStored(t, SidecarActionFetchUnlistedUrl)); err != nil || opened != nil {
		t.Errorf("an action with no detail: %+v, %v", opened, err)
	}
}
