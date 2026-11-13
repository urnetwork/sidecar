package gkmservice

// KEYS-M8-01 at gkm (DESIGN-DETAILS 4.2.2): a forwarding Delegation's reader key object, its upload held to the
// Delegation's own sidecar and the row's digest, each refusal beside its twin; its read by the config's readers alone;
// the object under its token's network alone (QD-763); the wrap checks holding a DelegationWrap to the key its row
// names; a forwarding sidecar reading its own Delegations' wraps; the reconciler's deletion of the object a day after
// its Delegation ended or was superseded, a hold keeping it; and QD-675's sweep of one network's prefix.

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A forwarding Delegation's reader key: its X-Wing public key, the key's digest and the Delegation's id.
type gkmTestForwardingKey struct {
	delegationId []byte
	publicKey    []byte
	keySha256    []byte
	privateKey   hpke.PrivateKey
}

// A fresh reader key for a Delegation named by label.
func newGkmTestForwardingKey(t *testing.T, label string) *gkmTestForwardingKey {
	t.Helper()
	privateKey, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.PublicKey().Bytes()
	delegationId := sha256.Sum256([]byte("forwarding delegation " + label))
	keySha256 := sha256.Sum256(publicKey)
	return &gkmTestForwardingKey{delegationId: delegationId[:], publicKey: publicKey, keySha256: keySha256[:], privateKey: privateKey}
}

// The path of a Delegation's key object at gkm's route.
func gkmTestDelegationKeyPath(delegationId []byte) string {
	return "/gkm/delegation-keys/" + hex.EncodeToString(delegationId)
}

// The object a Delegation's key is stored at in the fixture's network on the first cluster, nil for none.
func (self *gkmFixture) delegationKeyObject(delegationId []byte) []byte {
	self.t.Helper()
	return self.networkDelegationKeyObject(sidecar.Id(self.networkId), delegationId)
}

// The object a Delegation's key is stored at in a network on the first cluster, nil for none.
func (self *gkmFixture) networkDelegationKeyObject(networkId sidecar.Id, delegationId []byte) []byte {
	self.t.Helper()
	key, err := GkmDelegationKeyKey(networkId, delegationId)
	if err != nil {
		self.t.Fatal(err)
	}
	return self.object("meta-1", key)
}

// Stores a Delegation's key in a network on the first cluster, as an upload would have.
func (self *gkmFixture) putDelegationKey(networkId sidecar.Id, key *gkmTestForwardingKey) {
	self.t.Helper()
	objectKey, err := GkmDelegationKeyKey(networkId, key.delegationId)
	if err != nil {
		self.t.Fatal(err)
	}
	self.put("meta-1", objectKey, key.publicKey)
}

// The format value holds X-Wing's public key size.
func TestGkmDelegationKeyByteCountIsXWings(t *testing.T) {
	privateKey, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if size := len(privateKey.PublicKey().Bytes()); size != gkmDelegationKeyByteCount {
		t.Errorf("an X-Wing public key is %d bytes", size)
	}
}

// PUT /gkm/delegation-keys/<delegation_id>: 409 until gkm's state holds the row; then only the sidecar the row names,
// and only the key whose SHA-256 is the row's digest; a Delegation that does not forward takes none; a parked sidecar
// none; the same bytes again answer 200, and the object holds the key.
func TestGkmDelegationKeyUploadIsTheForwardingSidecarsAndHeldToTheRowsDigest(t *testing.T) {
	fixture := newGkmFixture(t)
	memberId := testId("member-a")
	configRepoId := testId("repo-config")
	fixture.placeRepo(configRepoId, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	forwarding := fixture.newSidecar("sc-forwarding", memberDeviceFacts(memberId))
	other := fixture.newSidecar("sc-other", memberDeviceFacts(memberId))
	for _, testSidecar := range []*gkmTestSidecar{forwarding, other} {
		fixture.auth.grant(testSidecar.sidecarId, configRepoId, sidecar.AclEvsRead)
	}
	forwardingToken := fixture.token(forwarding.sidecarId, repoScope(configRepoId, "r"))
	otherToken := fixture.token(other.sidecarId, repoScope(configRepoId, "r"))
	key := newGkmTestForwardingKey(t, "first")
	path := gkmTestDelegationKeyPath(key.delegationId)

	if recorder := fixture.serve(http.MethodPut, path, forwardingToken, key.publicKey); recorder.Code != http.StatusConflict {
		t.Errorf("an upload before gkm's state holds the row: %d", recorder.Code)
	}
	if fixture.delegationKeyObject(key.delegationId) != nil {
		t.Fatal("an upload gkm answered 409 stored the key")
	}
	forwardingId := forwarding.sidecarId
	fixture.auth.setDelegationKey(key.delegationId, &GkmDelegationKeyFacts{ReaderKeySha256: key.keySha256, ForwardSidecarId: &forwardingId, ConfigRepoId: configRepoId})

	other1216 := newGkmTestForwardingKey(t, "another key").publicKey
	for _, c := range []struct {
		name   string
		path   string
		token  string
		body   []byte
		status int
	}{
		{name: "another sidecar's upload", path: path, token: otherToken, body: key.publicKey, status: http.StatusForbidden},
		{name: "a key the row does not name", path: path, token: forwardingToken, body: other1216, status: http.StatusForbidden},
		{name: "a key one byte short", path: path, token: forwardingToken, body: key.publicKey[1:], status: http.StatusBadRequest},
		{name: "a key one byte long", path: path, token: forwardingToken, body: append(bytes.Clone(key.publicKey), 0), status: http.StatusBadRequest},
		{name: "an id out of form", path: "/gkm/delegation-keys/" + strings.ToUpper(hex.EncodeToString(key.delegationId)), token: forwardingToken, body: key.publicKey, status: http.StatusBadRequest},
		{name: "a short id", path: "/gkm/delegation-keys/" + hex.EncodeToString(key.delegationId[1:]), token: forwardingToken, body: key.publicKey, status: http.StatusBadRequest},
	} {
		if recorder := fixture.serve(http.MethodPut, c.path, c.token, c.body); recorder.Code != c.status {
			t.Errorf("%s: %d, want %d", c.name, recorder.Code, c.status)
		}
	}
	if fixture.delegationKeyObject(key.delegationId) != nil {
		t.Fatal("a refused upload stored a key")
	}

	// the twin: the Delegation's own sidecar, its row's key
	if recorder := fixture.serve(http.MethodPut, path, forwardingToken, key.publicKey); recorder.Code != http.StatusOK {
		t.Fatalf("the forwarding sidecar's upload: %d", recorder.Code)
	}
	if !bytes.Equal(fixture.delegationKeyObject(key.delegationId), key.publicKey) {
		t.Fatal("the object does not hold the key")
	}
	// a retry after a lost answer
	if recorder := fixture.serve(http.MethodPut, path, forwardingToken, key.publicKey); recorder.Code != http.StatusOK {
		t.Errorf("the same bytes again: %d", recorder.Code)
	}

	// a Delegation that does not forward keeps its key in its row
	agentKey := newGkmTestForwardingKey(t, "an auth key's")
	fixture.auth.setDelegationKey(agentKey.delegationId, &GkmDelegationKeyFacts{ReaderKeySha256: agentKey.keySha256, ConfigRepoId: configRepoId})
	if recorder := fixture.serve(http.MethodPut, gkmTestDelegationKeyPath(agentKey.delegationId), forwardingToken, agentKey.publicKey); recorder.Code != http.StatusForbidden {
		t.Errorf("an upload for a Delegation that does not forward: %d", recorder.Code)
	}

	// a parked sidecar writes nothing, its own record included
	parkedKey := newGkmTestForwardingKey(t, "parked")
	fixture.auth.setDelegationKey(parkedKey.delegationId, &GkmDelegationKeyFacts{ReaderKeySha256: parkedKey.keySha256, ForwardSidecarId: &forwardingId, ConfigRepoId: configRepoId})
	fixture.auth.update(forwarding.sidecarId, func(facts *GkmSidecarFacts) { facts.Parked = true })
	if recorder := fixture.serve(http.MethodPut, gkmTestDelegationKeyPath(parkedKey.delegationId), forwardingToken, parkedKey.publicKey); recorder.Code != http.StatusForbidden {
		t.Errorf("a parked sidecar's upload: %d", recorder.Code)
	}
	fixture.auth.update(forwarding.sidecarId, func(facts *GkmSidecarFacts) { facts.Parked = false })

	// a state not loaded allows nothing
	fixture.auth.unloaded = true
	if recorder := fixture.serve(http.MethodPut, gkmTestDelegationKeyPath(parkedKey.delegationId), forwardingToken, parkedKey.publicKey); recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("an upload while the state is cold: %d", recorder.Code)
	}
}

// GET /gkm/delegation-keys/<delegation_id>: the stored bytes to a token reading the network's config repo; 403 to one
// that reads only another repo; 404 for a Delegation with no object, one gkm's state does not hold and one that does
// not forward; 503 while the state is cold.
func TestGkmDelegationKeyReadIsTheConfigsReaders(t *testing.T) {
	fixture := newGkmFixture(t)
	memberId := testId("member-a")
	configRepoId := testId("repo-config")
	otherRepoId := testId("repo-other")
	fixture.placeRepo(configRepoId, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	fixture.placeRepo(otherRepoId, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	forwarding := fixture.newSidecar("sc-forwarding", memberDeviceFacts(memberId))
	reader := fixture.newSidecar("sc-reader", memberDeviceFacts(memberId))
	outsider := fixture.newSidecar("sc-outsider", memberDeviceFacts(memberId))
	fixture.auth.grant(forwarding.sidecarId, configRepoId, sidecar.AclEvsRead)
	fixture.auth.grant(reader.sidecarId, configRepoId, sidecar.AclEvsRead)
	fixture.auth.grant(outsider.sidecarId, otherRepoId, sidecar.AclEvsRead)
	forwardingId := forwarding.sidecarId
	key := newGkmTestForwardingKey(t, "read")
	fixture.auth.setDelegationKey(key.delegationId, &GkmDelegationKeyFacts{ReaderKeySha256: key.keySha256, ForwardSidecarId: &forwardingId, ConfigRepoId: configRepoId})
	readerToken := fixture.token(reader.sidecarId, repoScope(configRepoId, "r"))
	path := gkmTestDelegationKeyPath(key.delegationId)

	if recorder := fixture.serve(http.MethodGet, path, readerToken, nil); recorder.Code != http.StatusNotFound {
		t.Errorf("a read before the upload: %d", recorder.Code)
	}
	if recorder := fixture.serve(http.MethodPut, path, fixture.token(forwarding.sidecarId, repoScope(configRepoId, "r")), key.publicKey); recorder.Code != http.StatusOK {
		t.Fatalf("the upload: %d", recorder.Code)
	}
	recorder := fixture.serve(http.MethodGet, path, readerToken, nil)
	if recorder.Code != http.StatusOK || !bytes.Equal(recorder.Body.Bytes(), key.publicKey) {
		t.Errorf("a config reader's read: %d", recorder.Code)
	}
	if recorder := fixture.serve(http.MethodGet, path, fixture.token(outsider.sidecarId, repoScope(otherRepoId, "r")), nil); recorder.Code != http.StatusForbidden {
		t.Errorf("a read by a token that does not read the config: %d", recorder.Code)
	}
	// the state drops the reader from the config: its token, unexpired, reads nothing
	fixture.auth.drop(reader.sidecarId, configRepoId)
	if recorder := fixture.serve(http.MethodGet, path, readerToken, nil); recorder.Code != http.StatusForbidden {
		t.Errorf("a read by a sidecar the state no longer lets read the config: %d", recorder.Code)
	}
	fixture.auth.grant(reader.sidecarId, configRepoId, sidecar.AclEvsRead)

	unknown := newGkmTestForwardingKey(t, "unknown")
	if recorder := fixture.serve(http.MethodGet, gkmTestDelegationKeyPath(unknown.delegationId), readerToken, nil); recorder.Code != http.StatusNotFound {
		t.Errorf("a Delegation gkm's state holds no row of: %d", recorder.Code)
	}
	agentKey := newGkmTestForwardingKey(t, "an auth key's")
	fixture.auth.setDelegationKey(agentKey.delegationId, &GkmDelegationKeyFacts{ReaderKeySha256: agentKey.keySha256, ConfigRepoId: configRepoId})
	if recorder := fixture.serve(http.MethodGet, gkmTestDelegationKeyPath(agentKey.delegationId), readerToken, nil); recorder.Code != http.StatusNotFound {
		t.Errorf("a Delegation that does not forward: %d", recorder.Code)
	}
	fixture.auth.unloaded = true
	if recorder := fixture.serve(http.MethodGet, path, readerToken, nil); recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("a read while the state is cold: %d", recorder.Code)
	}
}

// QD-763: a forwarding Delegation's key object is its token's network's, gkm/dkey/<network_id>/<delegation_id>, at the
// upload and at every read, and no request names a network. A path that names another network's id beside the
// Delegation's reaches no route and stores or serves nothing, and a query naming one changes nothing; a token of
// another network, whose state holds no row of the Delegation, has its upload answer 409 and its reads 404, and reaches
// nothing of the first network's; and where both networks' states hold a row of one delegation_id, each network's
// sidecar uploads to its own network's object and each token reads only its own.
func TestGkmDelegationKeyObjectIsTheTokensNetworks(t *testing.T) {
	fixture := newGkmFixture(t)
	networkA, networkB := sidecar.Id(fixture.networkId), testId("network-b")
	fixture.host.Gates.OpenService(sidecar.ServiceGateGkm, connect.Id(networkA), connect.Id(networkB))
	memberId := testId("member-a")
	configRepoA, configRepoB := testId("repo-config-a"), testId("repo-config-b")
	fixture.placeRepo(configRepoA, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	fixture.placeRepo(configRepoB, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	forwardingA := fixture.newSidecar("sc-forward-a", memberDeviceFacts(memberId))
	readerA := fixture.newSidecar("sc-reader-a", memberDeviceFacts(memberId))
	forwardingB := fixture.newSidecar("sc-forward-b", memberDeviceFacts(memberId))
	readerB := fixture.newSidecar("sc-reader-b", memberDeviceFacts(memberId))
	for _, testSidecar := range []*gkmTestSidecar{forwardingA, readerA} {
		fixture.auth.grant(testSidecar.sidecarId, configRepoA, sidecar.AclEvsRead)
	}
	for _, testSidecar := range []*gkmTestSidecar{forwardingB, readerB} {
		fixture.auth.grant(testSidecar.sidecarId, configRepoB, sidecar.AclEvsRead)
	}
	forwardingAId, forwardingBId := forwardingA.sidecarId, forwardingB.sidecarId
	forwardingTokenA := fixture.token(forwardingA.sidecarId, repoScope(configRepoA, "r"))
	readerTokenA := fixture.token(readerA.sidecarId, repoScope(configRepoA, "r"))
	forwardingTokenB := fixture.networkToken(networkB, forwardingB.sidecarId, repoScope(configRepoB, "r"))
	readerTokenB := fixture.networkToken(networkB, readerB.sidecarId, repoScope(configRepoB, "r"))
	key := newGkmTestForwardingKey(t, "a's")
	fixture.auth.setDelegationKey(key.delegationId, &GkmDelegationKeyFacts{ReaderKeySha256: key.keySha256, ForwardSidecarId: &forwardingAId, ConfigRepoId: configRepoA})
	path := gkmTestDelegationKeyPath(key.delegationId)

	if recorder := fixture.serve(http.MethodPut, path, forwardingTokenA, key.publicKey); recorder.Code != http.StatusOK {
		t.Fatalf("the upload: %d", recorder.Code)
	}
	if !bytes.Equal(fixture.networkDelegationKeyObject(networkA, key.delegationId), key.publicKey) {
		t.Fatal("the key is not under its token's network")
	}
	if fixture.networkDelegationKeyObject(networkB, key.delegationId) != nil {
		t.Fatal("an upload stored a key under a network its token is not of")
	}

	// a path naming the other network beside the Delegation reaches no route
	namingB := "/gkm/delegation-keys/" + hex.EncodeToString(networkB[:]) + "/" + hex.EncodeToString(key.delegationId)
	if recorder := fixture.serve(http.MethodPut, namingB, forwardingTokenA, key.publicKey); recorder.Code != http.StatusNotFound {
		t.Errorf("an upload whose path names another network: %d", recorder.Code)
	}
	if recorder := fixture.serve(http.MethodGet, namingB, readerTokenA, nil); recorder.Code != http.StatusNotFound {
		t.Errorf("a read whose path names another network: %d", recorder.Code)
	}
	// a query naming it is not read: the same bytes again land where they stand
	if recorder := fixture.serve(http.MethodPut, path+"?network_id="+hex.EncodeToString(networkB[:]), forwardingTokenA, key.publicKey); recorder.Code != http.StatusOK {
		t.Errorf("an upload with a query naming another network: %d", recorder.Code)
	}
	if fixture.networkDelegationKeyObject(networkB, key.delegationId) != nil {
		t.Fatal("a request naming another network stored a key under it")
	}

	// the other network's tokens: its state holds no row of the Delegation
	if recorder := fixture.serve(http.MethodGet, path, readerTokenB, nil); recorder.Code != http.StatusNotFound {
		t.Errorf("another network's read: %d", recorder.Code)
	}
	if recorder := fixture.serve(http.MethodPost, "/gkm/delegation-keys", readerTokenB, fixture.delegationKeysBody(key.delegationId)); recorder.Code != http.StatusNotFound {
		t.Errorf("another network's batch: %d", recorder.Code)
	}
	if recorder := fixture.serve(http.MethodPut, path, forwardingTokenB, key.publicKey); recorder.Code != http.StatusConflict {
		t.Errorf("another network's upload: %d", recorder.Code)
	}
	if fixture.networkDelegationKeyObject(networkB, key.delegationId) != nil {
		t.Fatal("another network's refused upload stored a key")
	}

	// both states hold a row of the one delegation_id, each with its own key: each network's object is its own
	keyB := newGkmTestForwardingKey(t, "b's")
	fixture.auth.setNetworkDelegationKey(networkB, key.delegationId, &GkmDelegationKeyFacts{ReaderKeySha256: keyB.keySha256, ForwardSidecarId: &forwardingBId, ConfigRepoId: configRepoB})
	if recorder := fixture.serve(http.MethodPut, path, forwardingTokenB, key.publicKey); recorder.Code != http.StatusForbidden {
		t.Errorf("the other network's sidecar uploading the first network's key: %d", recorder.Code)
	}
	if recorder := fixture.serve(http.MethodPut, path, forwardingTokenB, keyB.publicKey); recorder.Code != http.StatusOK {
		t.Fatalf("the other network's upload of its own key: %d", recorder.Code)
	}
	if !bytes.Equal(fixture.networkDelegationKeyObject(networkB, key.delegationId), keyB.publicKey) {
		t.Error("the other network's object does not hold its key")
	}
	if !bytes.Equal(fixture.networkDelegationKeyObject(networkA, key.delegationId), key.publicKey) {
		t.Error("the first network's object changed")
	}
	if recorder := fixture.serve(http.MethodGet, path, readerTokenA, nil); recorder.Code != http.StatusOK || !bytes.Equal(recorder.Body.Bytes(), key.publicKey) {
		t.Errorf("the first network's read: %d", recorder.Code)
	}
	if recorder := fixture.serve(http.MethodGet, path, readerTokenB, nil); recorder.Code != http.StatusOK || !bytes.Equal(recorder.Body.Bytes(), keyB.publicKey) {
		t.Errorf("the other network's read: %d", recorder.Code)
	}
	recorder := fixture.serve(http.MethodPost, "/gkm/delegation-keys", readerTokenB, fixture.delegationKeysBody(key.delegationId))
	reply := &protocol.GkmDelegationKeysReply{}
	if recorder.Code != http.StatusOK || proto.Unmarshal(recorder.Body.Bytes(), reply) != nil || len(reply.GetReaderKeys()) != 1 || !bytes.Equal(reply.GetReaderKeys()[0], keyB.publicKey) {
		t.Errorf("the other network's batch: %d", recorder.Code)
	}
}

// A POST /gkm/delegation-keys body naming delegationIds.
func (self *gkmFixture) delegationKeysBody(delegationIds ...[]byte) []byte {
	return self.marshal(&protocol.GkmDelegationKeysRequest{DelegationIds: delegationIds})
}

// POST /gkm/delegation-keys (KEYS-M8-02, QD-637): each stored key in the request's order to a token reading the
// network's config repo, an empty entry for a Delegation with no object, one the state holds no row of and one that
// does not forward, so none of them fails the batch; 256 ids answered and 257 refused, as an empty list and an id of
// another size are; 403 to a token that reads only another repo, or that the state no longer lets read the config;
// 404 for a batch naming no forwarding Delegation the state holds; 503 while the state is cold.
func TestGkmDelegationKeysReadAnswersInOrderToTheConfigsReaders(t *testing.T) {
	fixture := newGkmFixture(t)
	memberId := testId("member-a")
	configRepoId := testId("repo-config")
	otherRepoId := testId("repo-other")
	fixture.placeRepo(configRepoId, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	fixture.placeRepo(otherRepoId, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	forwarding := fixture.newSidecar("sc-forwarding", memberDeviceFacts(memberId))
	reader := fixture.newSidecar("sc-reader", memberDeviceFacts(memberId))
	outsider := fixture.newSidecar("sc-outsider", memberDeviceFacts(memberId))
	fixture.auth.grant(forwarding.sidecarId, configRepoId, sidecar.AclEvsRead)
	fixture.auth.grant(reader.sidecarId, configRepoId, sidecar.AclEvsRead)
	fixture.auth.grant(outsider.sidecarId, otherRepoId, sidecar.AclEvsRead)
	forwardingId := forwarding.sidecarId
	forwardingToken := fixture.token(forwarding.sidecarId, repoScope(configRepoId, "r"))
	readerToken := fixture.token(reader.sidecarId, repoScope(configRepoId, "r"))

	// two forwarding Delegations whose keys are stored, one whose key is not, one the state holds no row of and one
	// that keeps its key in its row
	stored := []*gkmTestForwardingKey{newGkmTestForwardingKey(t, "stored 1"), newGkmTestForwardingKey(t, "stored 2")}
	unstored := newGkmTestForwardingKey(t, "unstored")
	unknown := newGkmTestForwardingKey(t, "unknown")
	agentKey := newGkmTestForwardingKey(t, "an auth key's")
	for _, key := range append(append([]*gkmTestForwardingKey{}, stored...), unstored) {
		fixture.auth.setDelegationKey(key.delegationId, &GkmDelegationKeyFacts{ReaderKeySha256: key.keySha256, ForwardSidecarId: &forwardingId, ConfigRepoId: configRepoId})
	}
	fixture.auth.setDelegationKey(agentKey.delegationId, &GkmDelegationKeyFacts{ReaderKeySha256: agentKey.keySha256, ConfigRepoId: configRepoId})
	for _, key := range stored {
		if recorder := fixture.serve(http.MethodPut, gkmTestDelegationKeyPath(key.delegationId), forwardingToken, key.publicKey); recorder.Code != http.StatusOK {
			t.Fatalf("the upload: %d", recorder.Code)
		}
	}

	order := [][]byte{stored[1].delegationId, unstored.delegationId, unknown.delegationId, stored[0].delegationId, agentKey.delegationId, stored[1].delegationId}
	want := [][]byte{stored[1].publicKey, {}, {}, stored[0].publicKey, {}, stored[1].publicKey}
	recorder := fixture.serve(http.MethodPost, "/gkm/delegation-keys", readerToken, fixture.delegationKeysBody(order...))
	if recorder.Code != http.StatusOK {
		t.Fatalf("a config reader's batch: %d", recorder.Code)
	}
	reply := &protocol.GkmDelegationKeysReply{}
	if err := proto.Unmarshal(recorder.Body.Bytes(), reply); err != nil {
		t.Fatal(err)
	}
	if len(reply.GetReaderKeys()) != len(want) {
		t.Fatalf("%d answers for %d ids", len(reply.GetReaderKeys()), len(want))
	}
	for i, readerKey := range reply.GetReaderKeys() {
		if !bytes.Equal(readerKey, want[i]) {
			t.Errorf("answer %d: %d bytes, want %d", i, len(readerKey), len(want[i]))
		}
	}

	// the bound: 256 ids answered, 257 refused, §10.14's value the default
	if fixture.settings.DelegationKeysMaxCount != 256 {
		t.Errorf("the default batch bound: %d", fixture.settings.DelegationKeysMaxCount)
	}
	full := [][]byte{}
	for range fixture.settings.DelegationKeysMaxCount {
		full = append(full, stored[0].delegationId)
	}
	recorder = fixture.serve(http.MethodPost, "/gkm/delegation-keys", readerToken, fixture.delegationKeysBody(full...))
	if recorder.Code != http.StatusOK {
		t.Fatalf("a batch of %d: %d", len(full), recorder.Code)
	}
	if err := proto.Unmarshal(recorder.Body.Bytes(), reply); err != nil || len(reply.GetReaderKeys()) != fixture.settings.DelegationKeysMaxCount {
		t.Errorf("a batch of %d: %d answers, %v", len(full), len(reply.GetReaderKeys()), err)
	}
	for _, c := range []struct {
		name string
		body []byte
	}{
		{name: "257 ids", body: fixture.delegationKeysBody(append(full, stored[0].delegationId)...)},
		{name: "no id", body: fixture.delegationKeysBody()},
		{name: "a short id", body: fixture.delegationKeysBody(stored[0].delegationId, stored[1].delegationId[1:])},
		{name: "a body that does not parse", body: []byte{0xff, 0xff, 0xff}},
	} {
		if recorder := fixture.serve(http.MethodPost, "/gkm/delegation-keys", readerToken, c.body); recorder.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", c.name, recorder.Code)
		}
	}

	// the scope: a token that reads only another repo, then one the state no longer lets read the config
	if recorder := fixture.serve(http.MethodPost, "/gkm/delegation-keys", fixture.token(outsider.sidecarId, repoScope(otherRepoId, "r")), fixture.delegationKeysBody(order...)); recorder.Code != http.StatusForbidden {
		t.Errorf("a batch by a token that does not read the config: %d", recorder.Code)
	}
	fixture.auth.drop(reader.sidecarId, configRepoId)
	if recorder := fixture.serve(http.MethodPost, "/gkm/delegation-keys", readerToken, fixture.delegationKeysBody(order...)); recorder.Code != http.StatusForbidden {
		t.Errorf("a batch by a sidecar the state no longer lets read the config: %d", recorder.Code)
	}
	fixture.auth.grant(reader.sidecarId, configRepoId, sidecar.AclEvsRead)

	if recorder := fixture.serve(http.MethodPost, "/gkm/delegation-keys", readerToken, fixture.delegationKeysBody(unknown.delegationId, agentKey.delegationId)); recorder.Code != http.StatusNotFound {
		t.Errorf("a batch naming no forwarding Delegation the state holds: %d", recorder.Code)
	}
	fixture.auth.unloaded = true
	if recorder := fixture.serve(http.MethodPost, "/gkm/delegation-keys", readerToken, fixture.delegationKeysBody(order...)); recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("a batch while the state is cold: %d", recorder.Code)
	}
}

// A Signed DelegationWrap of key's generation to a Delegation, sealed to publicKey, staged or late at pin and at.
func (self *gkmGroupWorld) delegationWrap(signer *gkmTestSidecar, key *sidecar.EvsRepoKey, delegationId []byte, publicKey []byte, kind sidecar.GkmDeliveryKind, pin *bridge.AuthPin, at time.Time) []byte {
	self.t.Helper()
	args := &sidecar.GkmDeliveryArgs{
		GroupId:            self.groupId,
		Type:               sidecar.GkmWrapTypeDelegation,
		Recipient:          delegationId,
		RecipientPublicKey: publicKey,
		Kind:               kind,
	}
	if kind == sidecar.GkmDeliveryLate {
		args.Auth = pin
		args.Time = at
	}
	delivery, err := sidecar.SealGkmDelivery(key, args)
	if err != nil {
		self.t.Fatal(err)
	}
	signed, err := sidecar.SignGkmDelivery(delivery, sidecar.GkmWrapTypeDelegation, signer.sign)
	if err != nil {
		self.t.Fatal(err)
	}
	return self.fixture.marshal(signed)
}

// A STAGED DelegationWrap is held to the key its Delegation's row names wherever gkm's state holds the row: sealed to
// another key it answers 409; with the row's key 201; to a Delegation gkm's state does not hold yet it passes to the
// members' checks, since a rotator's state may be ahead of gkm's.
func TestGkmStagedDelegationWrapIsHeldToItsRowsKey(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	key2, _ := world.nextGeneration(world.admin, world.key1, nil)
	forwardingId := testId("sc-forwarding")
	held := newGkmTestForwardingKey(t, "held")
	fixture.auth.setDelegationKey(held.delegationId, &GkmDelegationKeyFacts{ReaderKeySha256: held.keySha256, ForwardSidecarId: &forwardingId, ConfigRepoId: world.repoId})
	ahead := newGkmTestForwardingKey(t, "ahead of gkm")
	stray := newGkmTestForwardingKey(t, "stray").publicKey
	now := fixture.clock.Now()
	toStray := world.delegationWrap(world.admin, key2, held.delegationId, stray, sidecar.GkmDeliveryStaged, nil, now)
	if status := world.postWrap(world.adminToken, 2, gkmTestC8(key2), toStray); status != http.StatusConflict {
		t.Errorf("a staged wrap to a key the row does not name: %d", status)
	}
	toRowKey := world.delegationWrap(world.admin, key2, held.delegationId, held.publicKey, sidecar.GkmDeliveryStaged, nil, now)
	if status := world.postWrap(world.adminToken, 2, gkmTestC8(key2), toRowKey); status != http.StatusCreated {
		t.Errorf("a staged wrap to the row's key: %d", status)
	}
	toAhead := world.delegationWrap(world.admin, key2, ahead.delegationId, ahead.publicKey, sidecar.GkmDeliveryStaged, nil, now)
	if status := world.postWrap(world.adminToken, 2, gkmTestC8(key2), toAhead); status != http.StatusCreated {
		t.Errorf("a staged wrap to a Delegation gkm's state does not hold yet: %d", status)
	}
}

// A forwarding sidecar reads its own forwarding Delegations' deliveries, d:<delegation_id>, as its VPN component's
// forwarding client does acting as it; another sidecar's forwarding Delegation, and a Delegation gkm's state does not
// hold, it does not.
func TestGkmForwardingSidecarReadsItsOwnDelegationsWraps(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	forwarding := fixture.newSidecar("sc-forwarding", memberDeviceFacts(world.memberId))
	other := fixture.newSidecar("sc-other", memberDeviceFacts(world.memberId))
	for _, testSidecar := range []*gkmTestSidecar{forwarding, other} {
		fixture.auth.grant(testSidecar.sidecarId, world.repoId, sidecar.AclEvsRead)
	}
	forwardingId, otherId := forwarding.sidecarId, other.sidecarId
	own := newGkmTestForwardingKey(t, "own")
	others := newGkmTestForwardingKey(t, "other's")
	unknown := newGkmTestForwardingKey(t, "unknown")
	fixture.auth.setDelegationKey(own.delegationId, &GkmDelegationKeyFacts{ReaderKeySha256: own.keySha256, ForwardSidecarId: &forwardingId, ConfigRepoId: world.repoId})
	fixture.auth.setDelegationKey(others.delegationId, &GkmDelegationKeyFacts{ReaderKeySha256: others.keySha256, ForwardSidecarId: &otherId, ConfigRepoId: world.repoId})
	key2, claim2 := world.nextGeneration(world.admin, world.key1, nil)
	staged := world.delegationWrap(world.admin, key2, own.delegationId, own.publicKey, sidecar.GkmDeliveryStaged, nil, fixture.clock.Now())
	if status := world.postWrap(world.adminToken, 2, gkmTestC8(key2), staged); status != http.StatusCreated {
		t.Fatalf("the staged wrap: %d", status)
	}
	if recorder := world.postClaim(world.adminToken, 2, claim2); recorder.Code != http.StatusCreated {
		t.Fatalf("the claim: %d", recorder.Code)
	}
	read := func(token string, delegationId []byte) (int, []*bridge.Signed) {
		path := "/gkm/groups/" + sidecar.EvsKeyId(world.groupId) + "/wraps/2?recipient=d:" + hex.EncodeToString(delegationId)
		recorder := fixture.serve(http.MethodGet, path, token, nil)
		reply := &protocol.GkmWrapsReply{}
		if recorder.Code == http.StatusOK && proto.Unmarshal(recorder.Body.Bytes(), reply) != nil {
			t.Fatal("a wraps answer that does not parse")
		}
		return recorder.Code, reply.GetWraps()
	}
	forwardingToken := fixture.token(forwarding.sidecarId, repoScope(world.repoId, "r"))
	if code, wraps := read(forwardingToken, own.delegationId); code != http.StatusOK || len(wraps) != 1 || !bytes.Equal(fixture.marshal(wraps[0]), staged) {
		t.Errorf("its own forwarding Delegation's wraps: %d, %d", code, len(wraps))
	}
	if code, _ := read(forwardingToken, others.delegationId); code != http.StatusForbidden {
		t.Errorf("another sidecar's forwarding Delegation's wraps: %d", code)
	}
	if code, _ := read(forwardingToken, unknown.delegationId); code != http.StatusForbidden {
		t.Errorf("a Delegation gkm's state does not hold: %d", code)
	}
	if code, _ := read(fixture.token(other.sidecarId, repoScope(world.repoId, "r")), own.delegationId); code != http.StatusForbidden {
		t.Errorf("another sidecar reading the forwarding Delegation's wraps: %d", code)
	}
}

// Sets the world's network's state with PositionTime answering from a copy of positionTimes, and announces it.
func (self *gkmReconcilerWorld) setWithTimes(view sidecar.GkmAuthView, positionTimes map[uint64]time.Time) {
	self.setNetworkWithTimes(self.networkId, view, []sidecar.Id{self.repoId}, positionTimes)
}

// Sets a network's state with PositionTime answering from a copy of positionTimes, and announces it.
func (self *gkmReconcilerWorld) setNetworkWithTimes(networkId sidecar.Id, view sidecar.GkmAuthView, repoIds []sidecar.Id, positionTimes map[uint64]time.Time) {
	positionTimes = maps.Clone(positionTimes)
	changed := func() func(change *GkmStateChange) {
		self.state.stateLock.Lock()
		defer self.state.stateLock.Unlock()
		self.state.networkStates[networkId] = &GkmNetworkState{
			View:    view,
			RepoIds: slices.Clone(repoIds),
			PositionTime: func(n uint64) (time.Time, bool) {
				at, ok := positionTimes[n]
				return at, ok
			},
		}
		return self.state.changed
	}()
	if changed != nil {
		changed(&GkmStateChange{NetworkId: networkId})
	}
}

// A state of another network than the world's, on that network's own log, whose rows hold the Delegations given and
// no repo.
func gkmTestNetworkDelegations(log *sidecartest.FakeGkmAuthLog, delegations []*bridge.DelegationRow) *sidecartest.FakeGkmAuthView {
	fixture := &sidecartest.FakeGkmAuthFixture{
		Rows:         sidecartest.FakeGkmAuthRows(),
		IdentityKeys: map[sidecar.Id][]byte{},
	}
	fixture.Rows.Delegations = delegations
	return log.Append(fixture)
}

// Runs fn, then waits until the reconciler holds view for a network, as awaitState does for the world's.
func (self *gkmReconcilerWorld) awaitNetworkState(networkId sidecar.Id, view sidecar.GkmAuthView, fn func()) {
	self.t.Helper()
	_, changed := self.reconciler.Passes()
	fn()
	for {
		held := func() sidecar.GkmAuthView {
			self.reconciler.stateLock.Lock()
			defer self.reconciler.stateLock.Unlock()
			if entry, ok := self.reconciler.networkEntries[networkId]; ok && entry.state != nil {
				return entry.state.View
			}
			return nil
		}()
		if held == view {
			return
		}
		select {
		case <-changed:
			_, changed = self.reconciler.Passes()
		case <-self.fixture.ctx.Done():
			self.t.Fatal("the reconciler never read the network's state")
		}
	}
}

// Waits until the reconciler has swept a network's key objects at at: the pass that swept has handed the deleter what
// it found.
func (self *gkmReconcilerWorld) awaitSweep(networkId sidecar.Id, at time.Time) {
	self.t.Helper()
	for {
		_, changed := self.reconciler.Passes()
		swept := func() bool {
			self.reconciler.stateLock.Lock()
			defer self.reconciler.stateLock.Unlock()
			entry, ok := self.reconciler.networkEntries[networkId]
			return ok && entry.delegationKeySweptAt.Equal(at)
		}()
		if swept {
			return
		}
		select {
		case <-changed:
		case <-self.fixture.ctx.Done():
			self.t.Fatal("the reconciler never swept the network")
		}
	}
}

// A BlobStore over another that records the prefix of every LIST its clusters serve, so a test sees what a process
// listed. Safe for concurrent use.
type listRecordingBlobs struct {
	sidecar.BlobStore
	stateLock sync.Mutex
	prefixes  []string
}

// One cluster of listRecordingBlobs.
type listRecordingCluster struct {
	sidecar.BlobCluster
	blobs *listRecordingBlobs
}

func (self *listRecordingBlobs) Cluster(clusterId string) (sidecar.BlobCluster, error) {
	cluster, err := self.BlobStore.Cluster(clusterId)
	if err != nil {
		return nil, err
	}
	return &listRecordingCluster{BlobCluster: cluster, blobs: self}, nil
}

func (self *listRecordingBlobs) FirstCluster() (sidecar.BlobCluster, error) {
	cluster, err := self.BlobStore.FirstCluster()
	if err != nil {
		return nil, err
	}
	return &listRecordingCluster{BlobCluster: cluster, blobs: self}, nil
}

func (self *listRecordingCluster) List(ctx context.Context, keyPrefix string, startAfter string, limit int) ([]*sidecar.BlobInfo, bool, error) {
	func() {
		self.blobs.stateLock.Lock()
		defer self.blobs.stateLock.Unlock()
		self.blobs.prefixes = append(self.blobs.prefixes, keyPrefix)
	}()
	return self.BlobCluster.List(ctx, keyPrefix, startAfter, limit)
}

// The prefixes listed whose LIST could return a key under prefix: prefix itself, one under it, or one it is under,
// as gkm/dkey/ whole would be.
func (self *listRecordingBlobs) listedReaching(prefix string) []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	reaching := []string{}
	for _, listed := range self.prefixes {
		if strings.HasPrefix(listed, prefix) || strings.HasPrefix(prefix, listed) {
			reaching = append(reaching, listed)
		}
	}
	return reaching
}

// Closes the world's reconciler and starts another on the same host and state with no table, as a restart would,
// its store recording every LIST.
func (self *gkmReconcilerWorld) restart() *listRecordingBlobs {
	self.t.Helper()
	self.reconciler.Close()
	host := self.fixture.host.ServiceHost()
	blobs := &listRecordingBlobs{BlobStore: host.Blobs}
	host.Blobs = blobs
	restarted, err := NewGkmReconciler(self.fixture.ctx, host, DefaultGkmReconcilerSettings(), &GkmReconcilerDeps{State: self.state})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(restarted.Close)
	self.reconciler = restarted
	return blobs
}

// A state whose rows hold the Delegations given, a member device of the world's reading and writing the repo.
func (self *gkmReconcilerWorld) appendDelegations(delegations []*bridge.DelegationRow) *sidecartest.FakeGkmAuthView {
	writer := testId("sc-writer")
	fixture := &sidecartest.FakeGkmAuthFixture{
		Rows:         sidecartest.FakeGkmAuthRows(&protocol.AclRepo{RepoId: self.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}),
		IdentityKeys: map[sidecar.Id][]byte{},
		RepoReaders:  map[sidecar.Id][]sidecar.Id{self.repoId: {writer}},
		RepoWriters:  map[sidecar.Id][]sidecar.Id{self.repoId: {writer}},
	}
	sidecarRows, memberRow := sidecartest.FakeGkmAuthMemberDevices(self.memberId, writer)
	fixture.Rows.Sidecars = sidecarRows
	fixture.Rows.Members = []*bridge.MemberRow{memberRow}
	fixture.Rows.Delegations = delegations
	return self.log.Append(fixture)
}

// Waits until the key objects' deleter has finished count deletions in all.
func (self *gkmReconcilerWorld) awaitDelegationKeyDeletes(count int) {
	self.t.Helper()
	for {
		finished, changed := self.reconciler.DelegationKeyDeletes()
		if count <= finished {
			return
		}
		select {
		case <-changed:
		case <-self.fixture.ctx.Done():
			self.t.Fatal("the deleter never finished")
		}
	}
}

// A forwarding Delegation's row for a sidecar, at position at.
func gkmTestForwardingRow(key *gkmTestForwardingKey, sidecarId sidecar.Id, at uint64) *bridge.DelegationRow {
	return &bridge.DelegationRow{
		DelegationId:     bytes.Clone(key.delegationId),
		Signer:           sidecarId.Bytes(),
		At:               at,
		ForwardSidecarId: sidecarId.Bytes(),
		ReaderKeySha256:  bytes.Clone(key.keySha256),
	}
}

// The reconciler deletes a forwarding Delegation's key object DelegationKeyRetention after its Delegation ended or
// was superseded, at the time its state gives that position: an end a day old at once, one 23 hours old an hour later;
// the live Delegation's object stays, and so does an object while a hold covers the network, which goes at the retry
// once the hold is gone.
func TestGkmReconcilerDeletesAForwardingKeyObjectADayAfterItsEnd(t *testing.T) {
	world := newGkmReconcilerWorld(t)
	fixture := world.fixture
	settings := world.reconciler.settings
	appSidecarId, laptopSidecarId := testId("sc-app"), testId("sc-laptop")
	superseded := newGkmTestForwardingKey(t, "superseded")
	live := newGkmTestForwardingKey(t, "live")
	revoked := newGkmTestForwardingKey(t, "revoked")
	for _, key := range []*gkmTestForwardingKey{superseded, live, revoked} {
		fixture.putDelegationKey(world.networkId, key)
	}
	now := fixture.clock.Now()
	supersededRow := gkmTestForwardingRow(superseded, appSidecarId, 2)
	supersededRow.SupersededAt = 4
	liveRow := gkmTestForwardingRow(live, appSidecarId, 4)
	revokedRow := gkmTestForwardingRow(revoked, laptopSidecarId, 3)
	revokedRow.EndedAt = 5
	positionTimes := map[uint64]time.Time{
		4: now.Add(-settings.DelegationKeyRetention + time.Hour),
		5: now.Add(-settings.DelegationKeyRetention - time.Hour),
	}
	view := world.appendDelegations([]*bridge.DelegationRow{supersededRow, liveRow, revokedRow})
	world.awaitState(view, func() { world.setWithTimes(view, positionTimes) })
	world.awaitDelegationKeyDeletes(1)
	if fixture.delegationKeyObject(revoked.delegationId) != nil {
		t.Errorf("a revoked Delegation's object a day and an hour after its end stands")
	}
	if fixture.delegationKeyObject(superseded.delegationId) == nil || fixture.delegationKeyObject(live.delegationId) == nil {
		t.Fatalf("an object deleted before its day")
	}
	// the superseded one's day ends in an hour: the network's wake deletes it then
	world.awaitPass(func() { fixture.clock.Advance(time.Hour) })
	world.awaitDelegationKeyDeletes(2)
	if fixture.delegationKeyObject(superseded.delegationId) != nil {
		t.Errorf("a superseded Delegation's object a day after its supersession stands")
	}
	if fixture.delegationKeyObject(live.delegationId) == nil {
		t.Errorf("the live forwarding Delegation's object was deleted")
	}

	// a hold covering the network keeps a due object, which goes at the retry once the hold ends
	caseId := testId("case-dkey")
	if err := sidecartest.PlaceHold(fixture.ctx, fixture.host.Blobs, &sidecar.HoldRecord{
		NetworkId:  world.networkId,
		CaseId:     caseId,
		Kind:       sidecar.HoldKindPreserve2703f,
		Scope:      sidecar.HoldScopeNetwork(),
		PlaceTime:  fixture.clock.Now(),
		ExpireTime: fixture.clock.Now().Add(365 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	// past the hold set's reread, as any reader of holds is
	fixture.clock.Advance(sidecar.DefaultHoldSetSettings().RereadInterval)
	held := newGkmTestForwardingKey(t, "held")
	fixture.putDelegationKey(world.networkId, held)
	heldRow := gkmTestForwardingRow(held, laptopSidecarId, 6)
	heldRow.EndedAt = 7
	positionTimes[7] = fixture.clock.Now().Add(-2 * settings.DelegationKeyRetention)
	heldView := world.appendDelegations([]*bridge.DelegationRow{supersededRow, liveRow, revokedRow, heldRow})
	world.awaitState(heldView, func() { world.setWithTimes(heldView, positionTimes) })
	world.awaitDelegationKeyDeletes(3)
	if fixture.delegationKeyObject(held.delegationId) == nil {
		t.Fatalf("an object deleted under a hold")
	}
	if err := sidecartest.RemoveHold(fixture.ctx, fixture.host.Blobs, world.networkId, caseId); err != nil {
		t.Fatal(err)
	}
	// the pass that queued it woke the network again for the retry
	world.awaitPass(func() { fixture.clock.Advance(settings.DelegationKeyRetryInterval) })
	world.awaitDelegationKeyDeletes(4)
	if fixture.delegationKeyObject(held.delegationId) != nil {
		t.Errorf("an object a hold kept still stands at the retry after its hold ended")
	}
	if fixture.delegationKeyObject(live.delegationId) == nil {
		t.Errorf("the live forwarding Delegation's object was deleted")
	}
}

// How many forwarding Delegations' ends the reconciler tracks for the world's network.
func (self *gkmReconcilerWorld) trackedDelegationKeyEnds() int {
	self.reconciler.stateLock.Lock()
	defer self.reconciler.stateLock.Unlock()
	return len(self.reconciler.delegationKeyEnds[self.networkId])
}

// QD-675: a forwarding Delegation's row leaves the rows once retention passes its end by 4,096 positions (QD-648),
// which a busy network reaches before the key object's day has run. The end the reconciler saw stays tracked, so the
// object stands until DelegationKeyRetention after the end and goes then, with no row left to name it, and the sweep
// due at the state that dropped the row leaves it to that schedule; the live Delegation's object stays, and once the
// object is gone and its row has left nothing is tracked for it.
func TestGkmReconcilerDeletesAForwardingKeyObjectWhoseRowLeftBeforeItsDay(t *testing.T) {
	world := newGkmReconcilerWorld(t)
	fixture := world.fixture
	settings := world.reconciler.settings
	appSidecarId, laptopSidecarId := testId("sc-app"), testId("sc-laptop")
	ended := newGkmTestForwardingKey(t, "ended")
	live := newGkmTestForwardingKey(t, "live")
	for _, key := range []*gkmTestForwardingKey{ended, live} {
		fixture.putDelegationKey(world.networkId, key)
	}
	now := fixture.clock.Now()
	endedRow := gkmTestForwardingRow(ended, laptopSidecarId, 2)
	endedRow.EndedAt = 3
	liveRow := gkmTestForwardingRow(live, appSidecarId, 4)
	// the end is 22 hours old: its object's day ends in two hours
	positionTimes := map[uint64]time.Time{3: now.Add(-settings.DelegationKeyRetention + 2*time.Hour)}
	view := world.appendDelegations([]*bridge.DelegationRow{endedRow, liveRow})
	world.awaitState(view, func() { world.setWithTimes(view, positionTimes) })
	if world.trackedDelegationKeyEnds() != 1 {
		t.Fatalf("%d ends tracked, not the one", world.trackedDelegationKeyEnds())
	}

	// the network sequences past the row's 4,096 positions within the hour, and a base drops the row: the host no
	// longer tells its position's time either, only its newest entry's, so the sweep due an hour after the first
	// judges the network and finds the object no row names, whose end it tracks
	world.awaitPass(func() { fixture.clock.Advance(time.Hour) })
	leftView := world.appendDelegations([]*bridge.DelegationRow{liveRow})
	world.awaitState(leftView, func() {
		world.setWithTimes(leftView, map[uint64]time.Time{leftView.Pin().GetVersion(): fixture.clock.Now()})
	})
	world.awaitSweep(world.networkId, fixture.clock.Now())
	if finished, _ := world.reconciler.DelegationKeyDeletes(); finished != 0 {
		t.Fatalf("%d deletions before the object's day ended", finished)
	}
	if fixture.delegationKeyObject(ended.delegationId) == nil {
		t.Fatalf("an object deleted before its day, when its row left")
	}
	if world.trackedDelegationKeyEnds() != 1 {
		t.Fatalf("the end was forgotten when its row left: %d tracked", world.trackedDelegationKeyEnds())
	}

	// its day ends in another hour: the wake the earlier pass set deletes it then, with no row to name it
	world.awaitPass(func() { fixture.clock.Advance(time.Hour) })
	world.awaitDelegationKeyDeletes(1)
	if fixture.delegationKeyObject(ended.delegationId) != nil {
		t.Errorf("an object whose row left stands a day after its Delegation ended")
	}
	if fixture.delegationKeyObject(live.delegationId) == nil {
		t.Errorf("the live forwarding Delegation's object was deleted")
	}

	// the network's next pass, at the retry's wake, finds the object gone and no row naming it, and forgets the end
	world.awaitPass(func() { fixture.clock.Advance(settings.DelegationKeyRetryInterval) })
	if world.trackedDelegationKeyEnds() != 0 {
		t.Errorf("%d ends tracked after the object went and its row left", world.trackedDelegationKeyEnds())
	}
	if finished, _ := world.reconciler.DelegationKeyDeletes(); finished != 1 {
		t.Errorf("%d deletions for one object", finished)
	}
}

// QD-675's sweep after a restart, on the prefix the key's network gives (QD-763). The first process tracks two ended
// Delegations' ends, neither yet due, and stops; while no process runs, one's row leaves the rows. The process that
// starts after it, with no table, lists the network's gkm/dkey/<network_id>/ at the network's first pass and deletes
// at once the object whose row left, before the day its end would have given it; the ended row the rows still hold
// goes at the time the host's position times give, so the restart does not start its day again; and the live
// Delegation's object stays. A second network it reads is swept against its own rows alone: its live Delegation's
// object stays, though the first network's rows name it nowhere, and its object whose row left goes. A third
// network it never reads is never listed, nor gkm/dkey/ whole, and its objects stand, a live one and one no row
// names alike.
func TestGkmReconcilerAfterARestartSweepsAnObjectWhoseRowLeft(t *testing.T) {
	world := newGkmReconcilerWorld(t)
	fixture := world.fixture
	settings := world.reconciler.settings
	appSidecarId, laptopSidecarId, phoneSidecarId := testId("sc-app"), testId("sc-laptop"), testId("sc-phone")
	networkB, networkC := testId("network-b"), testId("network-c")
	ended := newGkmTestForwardingKey(t, "ended")
	left := newGkmTestForwardingKey(t, "left")
	live := newGkmTestForwardingKey(t, "live")
	liveB := newGkmTestForwardingKey(t, "live in b")
	leftB := newGkmTestForwardingKey(t, "left in b")
	liveC := newGkmTestForwardingKey(t, "live in c")
	leftC := newGkmTestForwardingKey(t, "left in c")
	for _, key := range []*gkmTestForwardingKey{ended, left, live} {
		fixture.putDelegationKey(world.networkId, key)
	}
	for _, key := range []*gkmTestForwardingKey{liveB, leftB} {
		fixture.putDelegationKey(networkB, key)
	}
	for _, key := range []*gkmTestForwardingKey{liveC, leftC} {
		fixture.putDelegationKey(networkC, key)
	}
	start := fixture.clock.Now()
	endedRow := gkmTestForwardingRow(ended, laptopSidecarId, 2)
	endedRow.EndedAt = 3
	leftRow := gkmTestForwardingRow(left, phoneSidecarId, 4)
	leftRow.EndedAt = 5
	liveRow := gkmTestForwardingRow(live, appSidecarId, 6)
	// the ended row's day ends in two hours, the left row's in four
	positionTimes := map[uint64]time.Time{
		3: start.Add(-settings.DelegationKeyRetention + 2*time.Hour),
		5: start.Add(-settings.DelegationKeyRetention + 4*time.Hour),
	}
	view := world.appendDelegations([]*bridge.DelegationRow{endedRow, leftRow, liveRow})
	world.awaitState(view, func() { world.setWithTimes(view, positionTimes) })
	world.awaitPass(func() { fixture.clock.Advance(time.Hour) })
	if world.trackedDelegationKeyEnds() != 2 {
		t.Fatalf("%d ends tracked before the restart, not the two", world.trackedDelegationKeyEnds())
	}

	// the restart, and the left row's leaving while no process ran: a busy network's log moved 4,096 positions past
	// its end within the hour, and its newest entry is now
	blobs := world.restart()
	if world.trackedDelegationKeyEnds() != 0 {
		t.Fatalf("a new reconciler tracks %d ends", world.trackedDelegationKeyEnds())
	}
	restartedView := world.appendDelegations([]*bridge.DelegationRow{endedRow, liveRow})
	restartedTimes := maps.Clone(positionTimes)
	restartedTimes[restartedView.Pin().GetVersion()] = fixture.clock.Now()
	world.awaitState(restartedView, func() { world.setWithTimes(restartedView, restartedTimes) })
	world.awaitSweep(world.networkId, fixture.clock.Now())
	world.awaitDelegationKeyDeletes(1)
	if fixture.delegationKeyObject(left.delegationId) != nil {
		t.Errorf("the object whose row left while no process ran stands after the restart's sweep")
	}
	if fixture.delegationKeyObject(ended.delegationId) == nil {
		t.Fatalf("the ended row's object went before its day, after a restart")
	}
	if fixture.delegationKeyObject(live.delegationId) == nil {
		t.Fatalf("the live forwarding Delegation's object was deleted")
	}
	if listed := blobs.listedReaching(GkmDelegationKeyNetworkPrefix(world.networkId)); len(listed) != 1 {
		t.Errorf("the network's prefix was listed %d times at its first pass: %v", len(listed), listed)
	}

	// a second network, read now: its own rows judge its own prefix
	logB := sidecartest.NewFakeGkmAuthLog()
	viewB := gkmTestNetworkDelegations(logB, []*bridge.DelegationRow{gkmTestForwardingRow(liveB, appSidecarId, 2)})
	world.awaitNetworkState(networkB, viewB, func() {
		world.setNetworkWithTimes(networkB, viewB, nil, map[uint64]time.Time{viewB.Pin().GetVersion(): fixture.clock.Now()})
	})
	world.awaitSweep(networkB, fixture.clock.Now())
	world.awaitDelegationKeyDeletes(2)
	if fixture.networkDelegationKeyObject(networkB, leftB.delegationId) != nil {
		t.Errorf("the second network's object whose row left stands after its sweep")
	}
	if fixture.networkDelegationKeyObject(networkB, liveB.delegationId) == nil {
		t.Errorf("the second network's live Delegation's object was deleted")
	}

	// the ended row's day ends an hour after the restart, as the first process counted it
	world.awaitPass(func() { fixture.clock.Advance(time.Hour) })
	world.awaitDelegationKeyDeletes(3)
	if fixture.delegationKeyObject(ended.delegationId) != nil {
		t.Errorf("an ended Delegation's object stands a day after its end, a restart between")
	}
	if fixture.delegationKeyObject(live.delegationId) == nil {
		t.Errorf("the live forwarding Delegation's object was deleted")
	}

	// long after, past both networks' later sweeps, the third network's objects stand and nothing listed them
	world.awaitPass(func() { fixture.clock.Advance(settings.DelegationKeySweepInterval) })
	world.awaitPass(func() { fixture.clock.Advance(2 * settings.DelegationKeyRetention) })
	if fixture.networkDelegationKeyObject(networkC, liveC.delegationId) == nil || fixture.networkDelegationKeyObject(networkC, leftC.delegationId) == nil {
		t.Errorf("an object of a network this process never read was deleted")
	}
	if listed := blobs.listedReaching(GkmDelegationKeyNetworkPrefix(networkC)); len(listed) != 0 {
		t.Errorf("a network this process never read was listed: %v", listed)
	}
	if fixture.networkDelegationKeyObject(networkB, liveB.delegationId) == nil || fixture.delegationKeyObject(live.delegationId) == nil {
		t.Errorf("a live Delegation's object went at a later sweep")
	}
	if finished, _ := world.reconciler.DelegationKeyDeletes(); finished != 3 {
		t.Errorf("%d deletions, not the three", finished)
	}
}

// The sweep judges an object against the state it holds only where that state has reached the object's row: an object
// no row names, written at or after the time of the state's newest entry less DelegationKeySweepClockSkew, may be a
// new Delegation's whose row gkm's own state held at its upload and this one has not reached, and stays, while one
// written before goes. Once a later state names it, later sweeps keep it.
func TestGkmReconcilerSweepKeepsAnObjectItsStateMayNotHaveReached(t *testing.T) {
	world := newGkmReconcilerWorld(t)
	fixture := world.fixture
	settings := world.reconciler.settings
	appSidecarId, laptopSidecarId := testId("sc-app"), testId("sc-laptop")
	old := newGkmTestForwardingKey(t, "old")
	fresh := newGkmTestForwardingKey(t, "fresh")
	fixture.putDelegationKey(world.networkId, old)
	world.awaitIdle()
	fixture.clock.Advance(time.Hour)
	// written a minute after the newest entry the state below holds
	fixture.putDelegationKey(world.networkId, fresh)
	behindView := world.appendDelegations([]*bridge.DelegationRow{})
	world.awaitState(behindView, func() {
		world.setWithTimes(behindView, map[uint64]time.Time{behindView.Pin().GetVersion(): fixture.clock.Now().Add(-time.Minute)})
	})
	world.awaitSweep(world.networkId, fixture.clock.Now())
	world.awaitDelegationKeyDeletes(1)
	if fixture.delegationKeyObject(old.delegationId) != nil {
		t.Errorf("an object no row names, written well before the state's newest entry, stands")
	}
	if fixture.delegationKeyObject(fresh.delegationId) == nil {
		t.Fatalf("an object written after the state's newest entry was deleted: its row may be one the state has not reached")
	}

	// the state reaches the new Delegation's row: later sweeps keep its object
	freshRow := gkmTestForwardingRow(fresh, laptopSidecarId, 2)
	liveRow := gkmTestForwardingRow(newGkmTestForwardingKey(t, "another live"), appSidecarId, 3)
	world.awaitPass(func() { fixture.clock.Advance(time.Minute) })
	reachedView := world.appendDelegations([]*bridge.DelegationRow{freshRow, liveRow})
	world.awaitState(reachedView, func() {
		world.setWithTimes(reachedView, map[uint64]time.Time{reachedView.Pin().GetVersion(): fixture.clock.Now()})
	})
	world.awaitPass(func() { fixture.clock.Advance(settings.DelegationKeySweepInterval) })
	world.awaitSweep(world.networkId, fixture.clock.Now())
	world.awaitPass(func() { fixture.clock.Advance(settings.DelegationKeySweepInterval) })
	world.awaitSweep(world.networkId, fixture.clock.Now())
	if fixture.delegationKeyObject(fresh.delegationId) == nil {
		t.Errorf("a live Delegation's object went once the state named it")
	}
	if finished, _ := world.reconciler.DelegationKeyDeletes(); finished != 1 {
		t.Errorf("%d deletions, not the old object's one", finished)
	}
}

// The sweep comes again each DelegationKeySweepInterval, against the newest state the reconciler holds, and finds an
// object no row and no tracked end names that appeared since, as one whose end a full table let go by would: not at a
// state's pass before the interval has run, at the sweep after it. A hold covering the network keeps it, and the
// sweep after the hold ends deletes it.
func TestGkmReconcilerSweepsANetworkAgainEachInterval(t *testing.T) {
	world := newGkmReconcilerWorld(t)
	fixture := world.fixture
	settings := world.reconciler.settings
	appSidecarId := testId("sc-app")
	live := newGkmTestForwardingKey(t, "live")
	stray := newGkmTestForwardingKey(t, "stray")
	fixture.putDelegationKey(world.networkId, live)
	liveRow := gkmTestForwardingRow(live, appSidecarId, 2)
	view := world.appendDelegations([]*bridge.DelegationRow{liveRow})
	world.awaitState(view, func() {
		world.setWithTimes(view, map[uint64]time.Time{view.Pin().GetVersion(): fixture.clock.Now()})
	})
	firstSweep := fixture.clock.Now()
	world.awaitSweep(world.networkId, firstSweep)

	// an object no row names appears after the first sweep, and a later state's pass comes before the interval
	fixture.putDelegationKey(world.networkId, stray)
	world.awaitPass(func() { fixture.clock.Advance(settings.DelegationKeySweepInterval / 2) })
	laterView := world.appendDelegations([]*bridge.DelegationRow{liveRow})
	world.awaitState(laterView, func() {
		world.setWithTimes(laterView, map[uint64]time.Time{laterView.Pin().GetVersion(): fixture.clock.Now()})
	})
	if fixture.delegationKeyObject(stray.delegationId) == nil {
		t.Fatalf("an object went at a state's pass before the sweep's interval had run")
	}

	// a hold covers the network when the interval's sweep comes: the deleter keeps the object
	caseId := testId("case-dkey-sweep")
	if err := sidecartest.PlaceHold(fixture.ctx, fixture.host.Blobs, &sidecar.HoldRecord{
		NetworkId:  world.networkId,
		CaseId:     caseId,
		Kind:       sidecar.HoldKindPreserve2703f,
		Scope:      sidecar.HoldScopeNetwork(),
		PlaceTime:  fixture.clock.Now(),
		ExpireTime: fixture.clock.Now().Add(365 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	world.awaitPass(func() {
		fixture.clock.Advance(firstSweep.Add(settings.DelegationKeySweepInterval).Sub(fixture.clock.Now()))
	})
	world.awaitSweep(world.networkId, firstSweep.Add(settings.DelegationKeySweepInterval))
	world.awaitDelegationKeyDeletes(1)
	if fixture.delegationKeyObject(stray.delegationId) == nil {
		t.Fatalf("an object deleted under a hold")
	}

	// the hold ends: the next interval's sweep deletes it
	if err := sidecartest.RemoveHold(fixture.ctx, fixture.host.Blobs, world.networkId, caseId); err != nil {
		t.Fatal(err)
	}
	world.awaitPass(func() { fixture.clock.Advance(settings.DelegationKeySweepInterval) })
	world.awaitSweep(world.networkId, firstSweep.Add(2*settings.DelegationKeySweepInterval))
	world.awaitDelegationKeyDeletes(2)
	if fixture.delegationKeyObject(stray.delegationId) != nil {
		t.Errorf("an object no row names stands at the sweep after its hold ended")
	}
	if fixture.delegationKeyObject(live.delegationId) == nil {
		t.Errorf("the live forwarding Delegation's object was deleted")
	}
}
