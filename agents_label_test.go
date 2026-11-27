//go:build !ios_extension && !sidecar_http

// QD-1434's keyed label (agents_label.go): its bytes against testdata/agents/label/vectors.json, which an
// implementation apart from this one computed; the same key at every generation of the config repo, another for
// another network; and every key it refuses to derive from.

package sidecar

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

//go:embed testdata/agents/label/vectors.json
var testAgentRepoLabelVectorsJson []byte

// What testdata/agents/label/vectors.json holds.
type testAgentRepoLabelVectors struct {
	NetworkId    string `json:"network_id"`
	ConfigRepoId string `json:"config_repo_id"`
	Rk1          string `json:"rk1"`
	KRef         string `json:"k_ref"`
	KLabel       string `json:"k_label"`
	Labels       []struct {
		Name     string `json:"name"`
		LabelMac string `json:"label_mac"`
	} `json:"labels"`
}

// The vectors, decoded, with the config repo's key at generation holding RK_1, as a ladder walk leaves one.
func testAgentRepoLabelWorld(t *testing.T, generation uint64) (*testAgentRepoLabelVectors, Id, Id, *EvsRepoKey) {
	t.Helper()
	vectors := &testAgentRepoLabelVectors{}
	if err := json.Unmarshal(testAgentRepoLabelVectorsJson, vectors); err != nil {
		t.Fatal(err)
	}
	decode := func(text string) []byte {
		decoded, err := hex.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	networkId, configRepoId := Id(decode(vectors.NetworkId)), Id(decode(vectors.ConfigRepoId))
	key := &EvsRepoKey{
		repoId:       configRepoId,
		generation:   generation,
		repoKey:      bytes.Repeat([]byte{byte(generation)}, gkmRepoKeyByteCount),
		firstRepoKey: decode(vectors.Rk1),
	}
	if generation == 1 {
		key.repoKey = decode(vectors.Rk1)
	}
	return vectors, networkId, configRepoId, key
}

// K_ref, K_label and each name's label_mac are the vectors' bytes, from the config repo's key at its first generation
// and at a later one alike; Labels takes a name's label and refuses another name's, a short one and none.
func TestAgentRepoLabelVectors(t *testing.T) {
	for _, generation := range []uint64{1, 7} {
		vectors, networkId, configRepoId, configKey := testAgentRepoLabelWorld(t, generation)
		refKey, err := configKey.DeriveKey(EvsKeyPurposeRef, nil)
		if err != nil || hex.EncodeToString(refKey) != vectors.KRef {
			t.Fatalf("generation %d: K_ref %x, %v", generation, refKey, err)
		}
		labelKey, err := NewAgentRepoLabelKey(networkId, configRepoId, configKey)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(labelKey.key) != vectors.KLabel || labelKey.NetworkId() != networkId {
			t.Fatalf("generation %d: K_label %x", generation, labelKey.key)
		}
		for _, vector := range vectors.Labels {
			name := AgentName(vector.Name)
			labelMac := labelKey.Mac(name)
			if hex.EncodeToString(labelMac) != vector.LabelMac || len(labelMac) != AgentRepoLabelMacByteCount {
				t.Errorf("generation %d, %s: %x, want %s", generation, name, labelMac, vector.LabelMac)
			}
			if !labelKey.Labels(labelMac, name) || labelKey.Labels(labelMac, name+"-2") || labelKey.Labels(labelMac[:15], name) ||
				labelKey.Labels(nil, name) {
				t.Errorf("generation %d, %s: Labels takes another", generation, name)
			}
		}
	}
}

// Another network's K_label labels one name otherwise, so a label links nothing across networks.
func TestAgentRepoLabelPerNetwork(t *testing.T) {
	_, networkId, configRepoId, configKey := testAgentRepoLabelWorld(t, 3)
	first, err := NewAgentRepoLabelKey(networkId, configRepoId, configKey)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewAgentRepoLabelKey(NewId(), configRepoId, configKey)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Mac("scout"), other.Mac("scout")) {
		t.Fatal("two networks label scout alike")
	}
}

// No K_label from no key, another repo's key, a key whose ladder has not reached RK_1, a zero network or config repo,
// or a K_ref of the wrong size.
func TestAgentRepoLabelKeyRefusals(t *testing.T) {
	_, networkId, configRepoId, configKey := testAgentRepoLabelWorld(t, 3)
	unladdered := &EvsRepoKey{repoId: configRepoId, generation: 3, repoKey: bytes.Repeat([]byte{3}, gkmRepoKeyByteCount)}
	for _, c := range []struct {
		name         string
		networkId    Id
		configRepoId Id
		key          *EvsRepoKey
	}{
		{name: "no key", networkId: networkId, configRepoId: configRepoId},
		{name: "another repo's key", networkId: networkId, configRepoId: NewId(), key: configKey},
		{name: "a key without RK_1", networkId: networkId, configRepoId: configRepoId, key: unladdered},
		{name: "no network", configRepoId: configRepoId, key: configKey},
		{name: "no config repo", networkId: networkId, key: configKey},
	} {
		if _, err := NewAgentRepoLabelKey(c.networkId, c.configRepoId, c.key); !errors.Is(err, ErrAgentRepoLabelKey) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if _, err := newAgentRepoLabelKey(networkId, make([]byte, 31)); !errors.Is(err, ErrAgentRepoLabelKey) {
		t.Errorf("a short K_ref: %v", err)
	}
}

// A verified state as EvsClient's Config gives one: agent_repos on, a Genesis naming the config repo, no sidecar row.
type testAgentLabelView struct {
	GkmAuthView
	configRepoId Id
}

func (self *testAgentLabelView) AuthFeatureOn(feature AuthFeature) bool {
	return feature == AuthFeatureAgentRepos
}

func (self *testAgentLabelView) Genesis() *bridge.Genesis {
	return &bridge.Genesis{ConfigRepoId: self.configRepoId.Bytes()}
}

func (self *testAgentLabelView) SidecarRow(sidecarId Id) *bridge.SidecarRow {
	return nil
}

// A key client holding the config repo's key at generation 1 alone, beside evs's test client's group records.
type testAgentLabelGkm struct {
	*evsTestGkm
	configKey *EvsRepoKey
}

func (self *testAgentLabelGkm) RepoKey(ctx context.Context, repoId Id, generation uint64) (*EvsRepoKey, error) {
	if repoId == self.configKey.RepoId() && generation == 1 {
		return self.configKey, nil
	}
	return nil, ErrGkmKeyMissing
}

// EvsClient derives K_label from the config repo's first generation at its verified state's network, none before a
// state; CreateRepo files an agent repo's label in its RepoCreate and refuses a create whose label does not fit its
// kind, an agent repo's missing one and another kind's carrying one, before anything is filed.
func TestEvsCreateRepoFilesAnAgentRepoLabel(t *testing.T) {
	test := newEvsTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}), newEvsTestStore(t))
	if _, err := test.client.AgentRepoLabelKey(context.Background()); !errors.Is(err, ErrEvsNoConfig) {
		t.Fatalf("a label key with no state: %v", err)
	}
	_, _, configRepoId, configKey := testAgentRepoLabelWorld(t, 1)
	test.client.args.Config = func() GkmAuthView { return &testAgentLabelView{configRepoId: configRepoId} }
	test.client.args.Gkm = &testAgentLabelGkm{evsTestGkm: test.gkm, configKey: configKey}
	labelKey, err := test.client.AgentRepoLabelKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want, err := NewAgentRepoLabelKey(testNetworkId, configRepoId, configKey)
	if err != nil {
		t.Fatal(err)
	}
	if labelKey.NetworkId() != testNetworkId || !bytes.Equal(labelKey.Mac("scout"), want.Mac("scout")) {
		t.Fatal("the client's K_label is another")
	}

	ownerId := evsTestId("member")
	labelMac := labelKey.Mac("scout")
	for _, refused := range []*EvsCreateRepoArgs{
		{Kind: protocol.RepoKind_REPO_KIND_GENERAL, LabelMac: labelMac},
		{Kind: protocol.RepoKind_REPO_KIND_AGENTS, OwnerMemberId: &ownerId, LabelMac: labelMac},
		{Kind: protocol.RepoKind_REPO_KIND_AGENT, OwnerMemberId: &ownerId},
		{Kind: protocol.RepoKind_REPO_KIND_AGENT, OwnerMemberId: &ownerId, LabelMac: labelMac[:10]},
	} {
		if _, err := test.client.CreateRepo(context.Background(), refused); !errors.Is(err, errInvalidSettings) {
			t.Errorf("%s with a label of %d bytes: %v", refused.Kind, len(refused.LabelMac), err)
		}
	}
	if len(test.poster.filed) != 0 {
		t.Fatalf("filed %v", test.poster.filed)
	}
	repo, err := test.client.CreateRepo(context.Background(), &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_AGENT, OwnerMemberId: &ownerId, LabelMac: labelMac})
	if err != nil {
		t.Fatal(err)
	}
	created := test.poster.bodies[0].(*protocol.RepoCreate)
	if created.GetKind() != protocol.RepoKind_REPO_KIND_AGENT || !bytes.Equal(created.GetLabelMac(), labelMac) ||
		!bytes.Equal(created.GetRepoId(), repo.RepoId().Bytes()) {
		t.Fatalf("RepoCreate %v", created)
	}
}
