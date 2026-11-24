// §16.6's authorization features (CACL-M11-02): the reserved numbers, bits that only accumulate, an entry before a
// feature's base refused alike by a reader with the feature and one without, implicit rules that compile only once
// their feature is on, the older build that fails a feature's base, and the first head's features.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The entry of a base folding through the tip, its head's ServiceSettings turning on features, sequenced and not yet
// applied by any reader: the tip moves to it.
func testFeatureBase(t *testing.T, net *testConfigNet, features AuthFeature) []byte {
	t.Helper()
	state := net.statesAt[net.n]
	if state == nil {
		t.Fatalf("no state at the tip %d", net.n)
	}
	configVersion := state.Base().GetConfigVersion() + 1
	net.source.settings[[sha256.Size]byte(testConfigHeadSha256(configVersion))] = &protocol.ServiceSettings{AuthFeatures: uint32(features)}
	entryBytes := net.makeBase(net.owner, state.Rows(), net.n, configVersion, state.threshold)
	testFeatureSequence(t, net, entryBytes)
	return entryBytes
}

// Moves the net's tip to an entry made there, as push does, applying it at no reader.
func testFeatureSequence(t *testing.T, net *testConfigNet, entryBytes []byte) {
	t.Helper()
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(entryBytes, entry); err != nil {
		t.Fatal(err)
	}
	chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
	if err != nil {
		t.Fatal(err)
	}
	net.n, net.chain, net.timeMs = entry.GetN(), chain, entry.GetTimeMs()
	net.entries = append(net.entries, entryBytes)
}

// Applies the net's entries from position from on at reader, failing the test on an error.
func testFeatureCatchUp(t *testing.T, net *testConfigNet, reader *ConfigLog, from uint64) {
	t.Helper()
	for n := from; n <= net.n; n += 1 {
		if _, err := reader.Apply(net.entries[n-1], net.source); err != nil {
			t.Fatalf("entry %d: %v", n, err)
		}
	}
}

func TestAuthFeatureFieldsReserved(t *testing.T) {
	field := func(message proto.Message, name string) protoreflect.FieldDescriptor {
		descriptor := message.ProtoReflect().Descriptor().Fields().ByName(protoreflect.Name(name))
		if descriptor == nil {
			t.Fatalf("%s has no %s", message.ProtoReflect().Descriptor().FullName(), name)
		}
		return descriptor
	}
	if descriptor := field(&protocol.ServiceSettings{}, "auth_features"); descriptor.Number() != 11 || descriptor.Kind() != protoreflect.Uint32Kind {
		t.Fatalf("ServiceSettings.auth_features is %d, %s", descriptor.Number(), descriptor.Kind())
	}
	if descriptor := field(&bridge.ProjectionSettings{}, "auth_features"); descriptor.Number() != 3 || descriptor.Kind() != protoreflect.Uint32Kind {
		t.Fatalf("ProjectionSettings.auth_features is %d, %s", descriptor.Number(), descriptor.Kind())
	}
	if bridge.SidecarCapability_SIDECAR_CAPABILITY_ENCLAVE != 8 {
		t.Fatalf("bit 3 is %d", bridge.SidecarCapability_SIDECAR_CAPABILITY_ENCLAVE)
	}
	for _, c := range []struct {
		feature AuthFeature
		value   uint32
		name    string
	}{
		{feature: AuthFeatureAgentRepos, value: 1, name: "agent_repos"},
		{feature: AuthFeatureComputePolicy, value: 2, name: "compute_policy"},
		{feature: AuthFeatureListeners, value: 4, name: "listeners"},
		{feature: AuthFeatureEnclaves, value: 8, name: "enclaves"},
	} {
		parsed, err := ParseAuthFeature(c.name)
		if uint32(c.feature) != c.value || c.feature.String() != c.name || err != nil || parsed != c.feature {
			t.Errorf("%s: %d, %q, %v", c.name, c.feature, c.feature.String(), err)
		}
	}
	if _, err := ParseAuthFeature("everything"); !errors.Is(err, ErrAuthFeatureUnknown) {
		t.Fatalf("an unknown name: %v", err)
	}
	if names := (AuthFeatureAgentRepos | AuthFeatureEnclaves | AuthFeature(64)).String(); names != "agent_repos,enclaves,bit6" {
		t.Fatalf("names %q", names)
	}
	// the names read back as the set, as a daemon event's do across the wire
	for _, features := range []AuthFeature{0, AuthFeatureListeners, AuthFeatureAgentRepos | AuthFeatureEnclaves | AuthFeature(64)} {
		if parsed := ParseAuthFeatureNames(features.String()); parsed != features {
			t.Errorf("%q reads back as %d", features.String(), parsed)
		}
	}
	if parsed := ParseAuthFeatureNames("listeners,nothing,bit06,bit99"); parsed != AuthFeatureListeners {
		t.Fatalf("names that are none read as %d", parsed)
	}
	// admissions keep refusing bit 3 as a bit they do not know until ENC's admission takes it
	net := newTestConfigNet(t)
	device := net.device("an enclave before its feature", net.ownerMemberId)
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
		net.admission(device, nil, false, 0, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_ENCLAVE)), ErrConfigRefused)
}

func TestAuthFeatureBitsOnlyAccumulate(t *testing.T) {
	net := newTestConfigNet(t)
	net.log.authFeatures = AuthFeatureAgentRepos | AuthFeatureListeners
	base := testFeatureBase(t, net, AuthFeatureAgentRepos)
	if verdict, err := net.log.Apply(base, net.source); err != nil || !verdict.Accepted() {
		t.Fatalf("the base turning agent_repos on: %v", err)
	}
	net.statesAt[net.n] = net.log.State()
	net.verdicts[net.n] = ConfigVerdict{Kind: bridge.AuthEntryKindBase}
	state := net.log.State()
	if !state.AuthFeatureOn(AuthFeatureAgentRepos) || state.AuthFeatureOn(AuthFeatureListeners) || state.AuthFeatures() != AuthFeatureAgentRepos {
		t.Fatalf("features on: %s", state.AuthFeatures())
	}

	// api refuses a base clearing the bit and takes one adding another
	headerOf := func(entryBytes []byte) ([]byte, []byte) {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			t.Fatal(err)
		}
		_, header, err := configParseBase(entry)
		if err != nil {
			t.Fatal(err)
		}
		return entry.GetBody(), net.source.rows[[sha256.Size]byte(header.GetRowsSha256())]
	}
	at := net.n
	clearing := testFeatureBase(t, net, 0)
	signedHeader, rows := headerOf(clearing)
	if err := net.log.CheckBase(signedHeader, rows, net.timeMs); !errors.Is(err, ErrConfigRule) {
		t.Fatalf("api's check of a base clearing agent_repos: %v", err)
	}
	// and every reader withholds it: the log stays where it was, unforked
	if _, err := net.log.Apply(clearing, net.source); !errors.Is(err, ErrAuthFeatureCleared) || !errors.Is(err, ErrConfigHeadUnavailable) {
		t.Fatalf("a reader's apply of a base clearing agent_repos: %v", err)
	}
	if net.log.State().n != at || net.log.Fork() != nil {
		t.Fatalf("the reader stands at %d, fork %v", net.log.State().n, net.log.Fork())
	}
	// a base adding listeners at the same position is api's to take
	net.n, net.chain, net.entries = at, net.log.State().chain, net.entries[:at]
	adding := testFeatureBase(t, net, AuthFeatureAgentRepos|AuthFeatureListeners)
	signedHeader, rows = headerOf(adding)
	if err := net.log.CheckBase(signedHeader, rows, net.timeMs); err != nil {
		t.Fatalf("api's check of a base adding listeners: %v", err)
	}
	// and one turning on a feature api's release lacks is refused before it is appended
	net.log.authFeatures = AuthFeatureAgentRepos
	if err := net.log.CheckBase(signedHeader, rows, net.timeMs); !errors.Is(err, ErrAuthFeatureUnsupported) {
		t.Fatalf("api's check of a feature its release lacks: %v", err)
	}
}

func TestAuthFeatureEntryBeforeBaseRefusedAlike(t *testing.T) {
	net := newTestConfigNet(t)
	// a reader of a release that implements agent_repos, and one of a release that predates it
	implements := net.log
	implements.authFeatures = AuthFeatureAgentRepos
	predates := net.newReader()
	predates.authFeatures = 0
	before := net.n

	// an agents repo's creation before the feature's base: refused by both readers alike
	create := func() []byte {
		return net.makeEntry(bridge.AuthEntryKindStatement, net.sign(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
			Header: net.header(), RepoId: testConfigId("agents repo").Bytes(), Kind: protocol.RepoKind_REPO_KIND_AGENTS,
		}))
	}
	entry := create()
	testFeatureSequence(t, net, entry)
	verdicts := []ConfigVerdict{}
	for _, reader := range []*ConfigLog{implements, predates} {
		// the feature's check, as each area's entry rule calls it, refuses on the state the entry lands on
		if err := reader.State().RequireAuthFeature(AuthFeatureAgentRepos, net.n); !errors.Is(err, ErrAuthFeatureOff) || !errors.Is(err, ErrConfigRefused) {
			t.Fatalf("the feature's check before its base: %v", err)
		}
		verdict, err := reader.Apply(entry, net.source)
		if err != nil {
			t.Fatal(err)
		}
		verdicts = append(verdicts, verdict)
	}
	if verdicts[0].Accepted() || verdicts[1].Accepted() || verdicts[0].tailBits() != verdicts[1].tailBits() ||
		!bytes.Equal(testConfigRowsBytes(t, implements.State()), testConfigRowsBytes(t, predates.State())) {
		t.Fatalf("the readers judged the entry before the base apart: %v, %v", verdicts[0].Refusal, verdicts[1].Refusal)
	}
	net.statesAt[net.n] = implements.State()
	net.verdicts[net.n] = verdicts[0]

	// the base: the reader that implements it turns it on, the one that predates it holds
	base := testFeatureBase(t, net, AuthFeatureAgentRepos)
	baseAt := net.n
	if _, err := implements.Apply(base, net.source); err != nil {
		t.Fatal(err)
	}
	if _, err := predates.Apply(base, net.source); !errors.Is(err, ErrConfigUpgradeRequired) {
		t.Fatalf("the predating reader at the base: %v", err)
	}
	// the feature is on past its base alone
	state := implements.State()
	if err := state.RequireAuthFeature(AuthFeatureAgentRepos, baseAt+1); err != nil {
		t.Fatalf("past the base: %v", err)
	}
	for _, position := range []uint64{before, baseAt} {
		if err := state.RequireAuthFeature(AuthFeatureAgentRepos, position); !errors.Is(err, ErrAuthFeatureOff) {
			t.Fatalf("at %d, before or at the base: %v", position, err)
		}
	}
	if err := state.RequireAuthFeature(AuthFeatureListeners, baseAt+1); !errors.Is(err, ErrAuthFeatureOff) {
		t.Fatalf("a feature the base did not turn on: %v", err)
	}
	if err := state.RequireAuthFeature(AuthFeature(16), baseAt+1); !errors.Is(err, ErrAuthFeatureOff) {
		t.Fatalf("a bit no feature has: %v", err)
	}
	// the predating reader judges nothing past the base, so the two never judge an entry apart
	after := create()
	testFeatureSequence(t, net, after)
	if _, err := predates.Apply(after, net.source); !errors.Is(err, ErrConfigUpgradeRequired) || predates.State().n != baseAt-1 {
		t.Fatalf("the predating reader past the base: %v at %d", err, predates.State().n)
	}
}

// A grant only a feature's implicit fragment adds, which the tests register under listeners.
const testFeatureFragment = `{"grants": [{"src": ["autogroup:tagged"], "dst": ["autogroup:member"], "allow": ["dial"], "ip": ["tcp:22"]}]}`

func TestAuthFeatureImplicitRulesOnlyOnceOn(t *testing.T) {
	WithAuthFeaturesImplementedForTest(t, AuthFeatureListeners|AuthFeatureAgentRepos, map[AuthFeature][]byte{
		AuthFeatureListeners: []byte(testFeatureFragment),
	})
	world := newAclCompileWorld("implicit")
	off := world.compile(t)
	// off, the rows are the frozen implicit document's, byte for byte
	golden, err := CompileAcl(world.input())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aclEncodeRows(t, off), aclEncodeRows(t, golden)) {
		t.Fatal("the implicit rows differ with no feature on")
	}
	featureRuleId := aclImplicitFeatureRuleId(AuthFeatureListeners, 0)
	if slices.ContainsFunc(off.GetRules(), func(rule *protocol.AclRule) bool { return bytes.Equal(rule.GetRuleId(), featureRuleId.Bytes()) }) {
		t.Fatal("the fragment's rule compiled with its feature off")
	}
	// on, its rule compiles beside the implicit document's, under its own domain's id
	input := world.input()
	input.AuthFeatures = AuthFeatureListeners | AuthFeatureAgentRepos
	on, err := CompileAcl(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(on.GetRules()) != len(off.GetRules())+1 ||
		!slices.ContainsFunc(on.GetRules(), func(rule *protocol.AclRule) bool { return bytes.Equal(rule.GetRuleId(), featureRuleId.Bytes()) }) {
		t.Fatalf("on, %d rules beside %d", len(on.GetRules()), len(off.GetRules()))
	}
	for i := range uint32(8) {
		if aclImplicitRuleId(i) == featureRuleId || aclImplicitFeatureRuleId(AuthFeatureAgentRepos, 0) == featureRuleId {
			t.Fatal("a feature rule's id is another rule's")
		}
	}
	// the compile is the same on every run, and a feature with no fragment adds nothing
	again, err := CompileAcl(input)
	if err != nil || !bytes.Equal(aclEncodeRows(t, on), aclEncodeRows(t, again)) {
		t.Fatalf("a second compile differs: %v", err)
	}
	input.AuthFeatures = AuthFeatureAgentRepos
	if agentsOnly, err := CompileAcl(input); err != nil || !bytes.Equal(aclEncodeRows(t, agentsOnly), aclEncodeRows(t, off)) {
		t.Fatalf("a feature with no fragment changed the rows: %v", err)
	}
	// a network with a document compiles its own rules and no fragment
	documented := newAclCompileWorld("implicit")
	documented.setPolicy(t, `{"grants": [{"src": ["autogroup:member"], "dst": ["*"], "allow": ["*"]}]}`)
	documentInput := documented.input()
	documentInput.AuthFeatures = AuthFeatureListeners
	withDocument, err := CompileAcl(documentInput)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(withDocument.GetRules(), func(rule *protocol.AclRule) bool { return bytes.Equal(rule.GetRuleId(), featureRuleId.Bytes()) }) {
		t.Fatal("a document's network compiled a feature's implicit rule")
	}
	// a fragment of more than grants and requests is no fragment
	if err := checkAuthFeatureFragment([]byte(`{"tagOwners": {"tag:enclave": ["autogroup:member"]}}`)); err == nil {
		t.Fatal("a fragment with tagOwners is taken")
	}
}

func TestAuthFeatureOlderBuildWithholds(t *testing.T) {
	registerTestConfigAclCompiler(t)
	net := newTestConfigNet(t)
	compileRows := ConfigCompileRowsOf(net.log.State())
	head := func(features AuthFeature) *ConfigHead {
		files := map[string][]byte{ConfigHeadGenesisPath: net.signedGenesis}
		if features != 0 {
			files[ConfigHeadServiceSettingsPath] = net.sign(net.owner, bridge.SignedType_SIGNED_SERVICE_SETTINGS, &protocol.ServiceSettings{AuthFeatures: uint32(features)})
		}
		configHead, err := NewConfigHead(files)
		if err != nil {
			t.Fatal(err)
		}
		return configHead
	}
	// an older build's compile: the rows with no field 3, as a release before the reservation writes them
	olderCompile := func(rows []byte) []byte {
		projection := &bridge.ProjectionRows{}
		if err := proto.Unmarshal(rows, projection); err != nil {
			t.Fatal(err)
		}
		projection.GetSettings().AuthFeatures = 0
		return testConfigMarshal(t, projection)
	}
	// with no feature on, every release compiles the same rows
	none, err := CompileProjectionRows(head(0), compileRows)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(olderCompile(none), none) {
		t.Fatal("a release before the reservation compiles other rows with no feature on")
	}
	// a head turning one on: the base names rows the older build's compile cannot reach, so its rows check fails there
	turnedOn, err := CompileProjectionRows(head(AuthFeatureAgentRepos), compileRows)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(olderCompile(turnedOn)) == sha256.Sum256(turnedOn) {
		t.Fatal("the older build's compile matches a base turning a feature on")
	}
	features, err := configRowsAuthFeatures(turnedOn)
	if err != nil || features != AuthFeatureAgentRepos {
		t.Fatalf("the rows carry %s, %v", features, err)
	}
	if features, err := configRowsAuthFeatures(olderCompile(turnedOn)); err != nil || features != 0 {
		t.Fatalf("the older rows carry %s, %v", features, err)
	}
}

func TestAuthFeatureFirstHeadSettings(t *testing.T) {
	net := newTestConfigNet(t)
	sign := func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
		signature := ed25519.Sign(net.owner.key, bridge.SignedBytes(purpose, signedType, body))
		return &bridge.Signed{Body: body, SignerId: net.owner.sidecarId.Bytes(), Signature: signature, Type: uint32(signedType)}, nil
	}
	bare, err := NewConfigHead(map[string][]byte{ConfigHeadGenesisPath: net.signedGenesis})
	if err != nil {
		t.Fatal(err)
	}
	// none implemented: no record added
	if same, err := configHeadWithAuthFeatures(bare, sign, 0); err != nil || same != bare {
		t.Fatalf("no features: %v", err)
	}
	// a release implementing two: a record carrying both
	withTwo, err := configHeadWithAuthFeatures(bare, sign, AuthFeatureAgentRepos|AuthFeatureComputePolicy)
	if err != nil {
		t.Fatal(err)
	}
	settings, _, err := withTwo.ServiceSettings()
	if err != nil || AuthFeature(settings.GetAuthFeatures()) != AuthFeatureAgentRepos|AuthFeatureComputePolicy {
		t.Fatalf("the first head's settings %v, %v", settings, err)
	}
	// a starting record's fields are kept beside the bits
	kept, err := NewConfigHead(map[string][]byte{
		ConfigHeadGenesisPath:         net.signedGenesis,
		ConfigHeadServiceSettingsPath: net.sign(net.owner, bridge.SignedType_SIGNED_SERVICE_SETTINGS, &protocol.ServiceSettings{MailStrict: true, AuthFeatures: uint32(AuthFeatureListeners)}),
	})
	if err != nil {
		t.Fatal(err)
	}
	merged, err := configHeadWithAuthFeatures(kept, sign, AuthFeatureAgentRepos)
	if err != nil {
		t.Fatal(err)
	}
	settings, _, err = merged.ServiceSettings()
	if err != nil || !settings.GetMailStrict() || AuthFeature(settings.GetAuthFeatures()) != AuthFeatureAgentRepos|AuthFeatureListeners {
		t.Fatalf("the merged settings %v, %v", settings, err)
	}
}
