//go:build !ios_extension

// The config kind's prepare and commit (evs_config_push.go; QD-824): the first config head sealed and signed before
// base 1 with no request sent and nothing asked of gkm, under the drafted generation pin {group, 1, C_1} with C_1 =
// H(repo_id, 1, RK_1) and the genesis state's pin {0, A_0}, every record inline; what it refuses; and the commit posting
// the same bytes, a ref that moved first answering ErrConfigHeadConflict.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A config push world: a network at base 1 (testConfigNet) whose owner device's client prepares through a transport
// that records each request and answers it from push, nil refusing every request.
type evsConfigPushWorld struct {
	t            *testing.T
	net          *testConfigNet
	configRepoId Id
	client       *EvsClient
	tokens       *evsTestTokens

	stateLock sync.Mutex
	requests  []string
	pushed    []*protocol.EvsPushRequest
	push      func(request *protocol.EvsPushRequest) (int, proto.Message)
}

func newEvsConfigPushWorld(t *testing.T, sidecarId Id) *evsConfigPushWorld {
	t.Helper()
	world := &evsConfigPushWorld{t: t, net: newTestConfigNet(t), tokens: &evsTestTokens{}}
	configRepoId, err := IdFromBytes(world.net.statesAt[0].Genesis().GetConfigRepoId())
	if err != nil {
		t.Fatal(err)
	}
	world.configRepoId = configRepoId
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		world.stateLock.Lock()
		world.requests = append(world.requests, request.Method+" "+request.URL.Path)
		push := world.push
		world.stateLock.Unlock()
		if push == nil || !strings.HasSuffix(request.URL.Path, "/push") {
			writer.WriteHeader(http.StatusForbidden)
			reply, _ := proto.Marshal(&protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE})
			writer.Write(reply)
			return
		}
		pushRequest := &protocol.EvsPushRequest{}
		if err := proto.Unmarshal(body, pushRequest); err != nil {
			t.Errorf("a push request that does not parse: %v", err)
		}
		world.stateLock.Lock()
		world.pushed = append(world.pushed, pushRequest)
		world.stateLock.Unlock()
		status, reply := push(pushRequest)
		replyBytes, _ := proto.Marshal(reply)
		writer.WriteHeader(status)
		writer.Write(replyBytes)
	})
	owner := world.net.owner
	identity := &SidecarIdentity{NetworkId: world.net.networkId, SidecarId: sidecarId, ClientId: testConfigId("owner client")}
	client, err := NewEvsClient(&EvsClientArgs{
		NetworkId:    world.net.networkId,
		EvsUrl:       "https://evs.example",
		Transport:    &evsTestTransport{handler: handler},
		ServiceToken: world.tokens.token,
		Sign: func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
			return &bridge.Signed{
				Body:      body,
				SignerId:  owner.sidecarId.Bytes(),
				Signature: ed25519.Sign(owner.key, bridge.SignedBytes(purpose, signedType, body)),
				Type:      uint32(signedType),
			}, nil
		},
		Identity: func() *SidecarIdentity { return identity },
		// the verifier's state, base 1's; the prepare reads none
		Config: func() GkmAuthView { return world.net.statesAt[1] },
		// asked nothing: the key comes in
		Gkm:      gkmRefusingClient{},
		Store:    newEvsTestStore(t),
		Clock:    newEvsTestClock(),
		Log:      NewNoopLogger(),
		Settings: DefaultEvsSettings(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	world.client = client
	return world
}

// The requests the client sent, each its method and path.
func (self *evsConfigPushWorld) sent() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.requests...)
}

// Generation 1 of a repo as KF1's bootstrap draft holds it, over a fixed RK_1.
func (self *evsConfigPushWorld) draftedKey(repoId Id, fill byte) *EvsRepoKey {
	self.t.Helper()
	key, err := newGkmDraftedFirstKey(repoId, testConfigId("config group"), bytes.Repeat([]byte{fill}, gkmRepoKeyByteCount))
	if err != nil {
		self.t.Fatal(err)
	}
	return key
}

// The first head: the Genesis, a policy and a share file under a directory, past what a segment would need below 16
// KiB, plus files.
func (self *evsConfigPushWorld) head(files map[string][]byte) *ConfigHead {
	self.t.Helper()
	all := map[string][]byte{
		ConfigHeadGenesisPath: self.net.signedGenesis,
		ConfigHeadPolicyPath:  []byte(`{"acls": []}`),
		ConfigHeadBridgeSharePrefix + strings.Repeat("a1", 16): bytes.Repeat([]byte("share a1; "), 300),
	}
	for path, data := range files {
		all[path] = data
	}
	head, err := NewConfigHead(all)
	if err != nil {
		self.t.Fatal(err)
	}
	return head
}

// The first head's push, prepared before anything of the network exists at evs: nothing sent, nothing asked of gkm;
// a statement on the config repo's main ref at version 0 from C_0 under the drafted generation pin, its C_1 =
// SHA-256("UR evs 1.0 commit" || repo_id || u64be(1) || RK_1), signed by the Genesis's owner at {0, A_0}; every
// file a creation riding inline, each parent directory and the root taking a delta; C_1 the chain value of that push.
func TestEvsPrepareConfigHeadSealsTheFirstHeadBeforeBaseOne(t *testing.T) {
	world := newEvsConfigPushWorld(t, testConfigId("owner device"))
	genesis := world.net.statesAt[0]
	key := world.draftedKey(world.configRepoId, 0x5c)
	head := world.head(nil)
	push, err := world.client.PrepareConfigHead(context.Background(), key, genesis, head)
	if err != nil {
		t.Fatal(err)
	}
	if sent := world.sent(); len(sent) != 0 {
		t.Fatalf("the prepare sent %v", sent)
	}
	statement, err := ParseEvsStatement(push.SignedPush)
	if err != nil {
		t.Fatal(err)
	}
	evsPush := statement.Push
	refKey, err := NewEvsRefKey(key)
	if err != nil {
		t.Fatal(err)
	}
	mainRefId, err := EvsRefId(refKey, EvsMainRefName)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(evsPush.GetRepoId(), world.configRepoId.Bytes()) || !bytes.Equal(evsPush.GetRefId(), mainRefId.Bytes()) ||
		evsPush.GetBaseVersion() != 0 || protocol.EvsRefKind(evsPush.GetRefKind()) != protocol.EvsRefKind_EVS_REF_SHARED ||
		protocol.EvsRefMode(evsPush.GetRefMode()) != protocol.EvsRefMode_EVS_REF_FILE || evsPush.GetPathEpoch() != 1 {
		t.Fatalf("the first push's ref and base: %v", evsPush)
	}
	start := EvsChainStart(world.configRepoId, mainRefId)
	if !bytes.Equal(evsPush.GetBaseChain(), start[:]) {
		t.Fatal("the first push is not based on C_0")
	}
	if !bytes.Equal(evsPush.GetGroupId(), key.GroupId().Bytes()) || evsPush.GetGeneration() != 1 ||
		!bytes.Equal(evsPush.GetGenerationCommitment(), gkmCommitment(world.configRepoId, 1, key.repoKey)) {
		t.Fatal("the push's generation pin is not {group, 1, H(repo_id, 1, RK_1)}")
	}
	if auth := evsPush.GetAuth(); auth.GetVersion() != 0 || !bytes.Equal(auth.GetChain(), world.net.statesAt[0].Pin().GetChain()) {
		t.Fatalf("the first push's auth pin: %v", auth)
	}
	if err := bridge.VerifySigned(statement.Signed, evsPushPurpose, bridge.SignedType_SIGNED_EVS_PUSH, bridge.SignedKeyAlgEd25519, world.net.owner.publicKey()); err != nil {
		t.Fatalf("the push's signature under the Genesis's owner key: %v", err)
	}
	pushId, err := IdFromBytes(evsPush.GetPushId())
	if err != nil {
		t.Fatal(err)
	}
	if push.Version != 1 || push.Chain != EvsChainNext(start, pushId, EvsStatementSha256(push.SignedPush)) || len(push.Payload) == 0 || push.Head != head {
		t.Fatal("the push's version, C_1 or payload")
	}
	checked, err := EvsCheckPayload(statement, push.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(checked.NewObjects) != 0 || len(checked.SlotBodies) != 0 {
		t.Fatal("the first push introduces an object to upload")
	}
	// every file and each directory above one, the root's delta among them, each a creation
	directories := map[string]bool{"": true}
	for _, path := range head.Paths() {
		names := strings.Split(path, "/")
		for depth := 1; depth < len(names); depth += 1 {
			directories[strings.Join(names[:depth], "/")] = true
		}
	}
	if len(checked.Changes) != len(head.Paths())+len(directories) {
		t.Fatalf("%d changes for %d files and %d directories", len(checked.Changes), len(head.Paths()), len(directories))
	}
	inline := 0
	for _, change := range checked.Changes {
		if change.Change.GetBaseEntryVersion() != 0 || !change.WritesEntry() {
			t.Fatalf("a change that creates nothing: %v", change.Change)
		}
		entry := &protocol.EvsEntryVersion{}
		if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
			t.Fatal(err)
		}
		for _, locator := range entry.GetChain() {
			if protocol.EvsLocatorKind(locator.GetKind()) != protocol.EvsLocatorKind_EVS_LOCATOR_INLINE {
				t.Fatalf("a record of the first head outside its entry: kind %d", locator.GetKind())
			}
			inline += 1
		}
	}
	if inline != len(head.Paths()) {
		t.Fatalf("%d inline records for %d files", inline, len(head.Paths()))
	}
}

// What the prepare refuses, each before anything is sent: a state past the genesis, a key of a repo the Genesis does
// not name as its config repo, a signer that is not the Genesis's owner, and a file past what rides inline.
func TestEvsPrepareConfigHeadRefusesWhatIsNoFirstHead(t *testing.T) {
	world := newEvsConfigPushWorld(t, testConfigId("owner device"))
	ctx := context.Background()
	genesis := world.net.statesAt[0]
	if _, err := world.client.PrepareConfigHead(ctx, world.draftedKey(world.configRepoId, 1), world.net.statesAt[1], world.head(nil)); !errors.Is(err, ErrEvsWriteInvalid) {
		t.Errorf("a first head at base 1's state: %v", err)
	}
	if _, err := world.client.PrepareConfigHead(ctx, world.draftedKey(testConfigId("another repo"), 1), genesis, world.head(nil)); !errors.Is(err, ErrEvsWriteInvalid) {
		t.Errorf("a key of another repo: %v", err)
	}
	large := world.head(map[string][]byte{ConfigHeadBridgeSharePrefix + strings.Repeat("b2", 16): bytes.Repeat([]byte{0x6b}, 64*1024)})
	if _, err := world.client.PrepareConfigHead(ctx, world.draftedKey(world.configRepoId, 1), genesis, large); !errors.Is(err, ErrEvsWriteInvalid) {
		t.Errorf("a file past what rides inline: %v", err)
	}
	other := newEvsConfigPushWorld(t, testConfigId("another device"))
	if _, err := other.client.PrepareConfigHead(ctx, other.draftedKey(other.configRepoId, 1), other.net.statesAt[0], other.head(nil)); !errors.Is(err, ErrEvsWriteInvalid) {
		t.Errorf("a signer that is not the Genesis's owner: %v", err)
	}
	if sent := append(world.sent(), other.sent()...); len(sent) != 0 {
		t.Errorf("a refused prepare sent %v", sent)
	}
}

// The commit posts the prepared statement and payload under the config repo's rw scope and takes evs's version 1;
// a push evs commits at another version, or refuses on a moved base, is ErrConfigHeadConflict; and a push no evs client
// prepared, holding no payload, is refused unsent.
func TestEvsCommitConfigHeadPostsThePreparedPush(t *testing.T) {
	world := newEvsConfigPushWorld(t, testConfigId("owner device"))
	ctx := context.Background()
	push, err := world.client.PrepareConfigHead(ctx, world.draftedKey(world.configRepoId, 2), world.net.statesAt[0], world.head(nil))
	if err != nil {
		t.Fatal(err)
	}
	world.push = func(request *protocol.EvsPushRequest) (int, proto.Message) {
		return http.StatusOK, &protocol.EvsPushReply{Version: 1}
	}
	if err := world.client.CommitConfigHead(ctx, push); err != nil {
		t.Fatal(err)
	}
	if len(world.pushed) != 1 || !bytes.Equal(world.pushed[0].GetStatement(), push.SignedPush) || !bytes.Equal(world.pushed[0].GetPayload(), push.Payload) ||
		len(world.pushed[0].GetReceipts()) != 0 {
		t.Fatal("the commit posted other bytes than the prepared push")
	}
	rwScope := "repo:" + world.configRepoId.String() + ":rw"
	scoped := false
	for _, scopes := range world.tokens.scopes {
		for _, scope := range scopes {
			scoped = scoped || scope == rwScope
		}
	}
	if !scoped {
		t.Errorf("no token carried %s: %v", rwScope, world.tokens.scopes)
	}

	world.push = func(request *protocol.EvsPushRequest) (int, proto.Message) {
		return http.StatusOK, &protocol.EvsPushReply{Version: 2}
	}
	if err := world.client.CommitConfigHead(ctx, push); !errors.Is(err, ErrConfigHeadConflict) {
		t.Errorf("a push committed at another version: %v", err)
	}
	world.push = func(request *protocol.EvsPushRequest) (int, proto.Message) {
		return http.StatusConflict, &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE}
	}
	if err := world.client.CommitConfigHead(ctx, push); !errors.Is(err, ErrConfigHeadConflict) {
		t.Errorf("a push on a moved base: %v", err)
	}
	pushedCount := len(world.pushed)
	unprepared := &ConfigHeadPush{Head: push.Head, Version: 1, Chain: push.Chain, SignedPush: push.SignedPush}
	if err := world.client.CommitConfigHead(ctx, unprepared); !errors.Is(err, ErrEvsWriteInvalid) || len(world.pushed) != pushedCount {
		t.Errorf("a push with no payload: %v", err)
	}
	digest := sha256.Sum256(push.SignedPush)
	if statement, err := ParseEvsStatement(push.SignedPush); err != nil || statement.Sha256 != digest {
		t.Errorf("the prepared statement's hash: %v", err)
	}
}

// A reader at base 1 takes the first config head's push at the genesis pin, judged at S(0), whose rows are empty and
// whose one config writer is the Genesis's owner (§7.9; QD-081 #4); the same statement read as another repo's is
// refused, since S(0) holds no repo but the config repo.
func TestEvsVerifierTakesTheFirstConfigPushAtTheGenesis(t *testing.T) {
	world := newEvsConfigPushWorld(t, testConfigId("owner device"))
	key := world.draftedKey(world.configRepoId, 3)
	push, err := world.client.PrepareConfigHead(context.Background(), key, world.net.statesAt[0], world.head(nil))
	if err != nil {
		t.Fatal(err)
	}
	if writers := world.net.statesAt[0].RepoWriters(world.configRepoId); len(writers) != 0 {
		t.Fatalf("S(0)'s rows list writers %v", writers)
	}
	statement, err := ParseEvsStatement(push.SignedPush)
	if err != nil {
		t.Fatal(err)
	}
	refId, err := IdFromBytes(statement.Push.GetRefId())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.client.Verifier().VerifyStatement(t.Context(), push.SignedPush, world.configRepoId, refId); err != nil {
		t.Fatalf("the first config push at the genesis pin: %v", err)
	}
	if err := evsCheckRefRules(world.net.statesAt[0], statement, testConfigId("another repo"), refId, world.net.owner.sidecarId); !errors.Is(err, ErrEvsStatementRefused) {
		t.Errorf("a genesis-pinned push of another repo: %v", err)
	}
	stranger := testConfigId("stranger")
	if err := evsCheckRefRules(world.net.statesAt[0], statement, world.configRepoId, refId, stranger); !errors.Is(err, ErrEvsStatementRefused) {
		t.Errorf("a genesis-pinned config push of another signer: %v", err)
	}
}
