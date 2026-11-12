package sidecartest

import (
	"context"
	"encoding/binary"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A store with a metadata cluster, and a helper that writes an epoch object there as gkm writes it.
type storedFixture struct {
	store   *FakeBlobs
	cluster sidecar.BlobCluster
	groupId sidecar.Id
}

func newStoredFixture(t *testing.T) *storedFixture {
	t.Helper()
	store := NewFakeBlobs(NewFakeClock(DefaultClockStart()), NewFaultQueue(), nil, nil)
	cluster, err := store.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	return &storedFixture{store: store, cluster: cluster, groupId: sidecar.NewId()}
}

// The key gkm's objects.go builds for epoch n, gkm/<group_id>/epoch/<20 digits>.
func (self *storedFixture) epochKey(epoch uint64) string {
	return "gkm/" + sidecar.EvsKeyId(self.groupId) + "/epoch/" + strings.Repeat("0", 19) + string(rune('0'+epoch))
}

func (self *storedFixture) put(t *testing.T, epoch uint64, object *protocol.GkmEpochObject) string {
	t.Helper()
	body, err := proto.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return self.putBytes(t, epoch, body)
}

func (self *storedFixture) putBytes(t *testing.T, epoch uint64, body []byte) string {
	t.Helper()
	key := self.epochKey(epoch)
	if _, err := self.cluster.PutIfNoneMatch(context.Background(), key, body, nil); err != nil {
		t.Fatal(err)
	}
	return key
}

func (self *storedFixture) check(t *testing.T, headerOnly bool) []string {
	t.Helper()
	findings, err := CheckStoredCommits(context.Background(), self.store, nil, headerOnly)
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

// A GkmCommitHeader's bytes, as a committer writes it into authenticated_data.
func storedTestHeader(t *testing.T, generation uint64) []byte {
	t.Helper()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GkmCommitHeader{Generation: generation, Auth: &bridge.AuthPin{Version: 7, Chain: make([]byte, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// A member's commit, framed as a PrivateMessage, and a joiner's external commit, a PublicMessage from
// new_member_commit, each pass; so does epoch 0's object, which carries no commit. A member's commit in the clear,
// and a handshake blob that is no MLSMessage at all, each fail, naming the object.
func TestAnExternalCommitPassesThePrivateMessageAssertAndAPlaintextBlobFails(t *testing.T) {
	fixture := newStoredFixture(t)
	engines, groups := fakeMlsTestGroup(t, 2)
	staged, err := groups[0].Commit(&sidecar.MlsCommitArgs{Path: true, AuthenticatedData: storedTestHeader(t, 1)})
	if err != nil {
		t.Fatal(err)
	}
	groupInfo, err := groups[0].GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	external, err := engines[1].JoinExternal(groupInfo, &sidecar.MlsCommitArgs{Removes: []uint32{groups[1].Self().LeafIndex}, Path: true, AuthenticatedData: storedTestHeader(t, 1)})
	if err != nil {
		t.Fatal(err)
	}
	fixture.put(t, 0, &protocol.GkmEpochObject{Header: &protocol.GkmCommitHeader{Generation: 1}})
	fixture.put(t, 1, &protocol.GkmEpochObject{Commit: staged.Message(), Header: &protocol.GkmCommitHeader{Generation: 1}})
	fixture.put(t, 2, &protocol.GkmEpochObject{Commit: external.Message(), Header: &protocol.GkmCommitHeader{Generation: 1}})
	if findings := fixture.check(t, true); len(findings) != 0 {
		t.Fatalf("honest commits: %q", findings)
	}

	// a member's commit in the clear: the external commit's framing with the sender a member
	inClear := slices.Clone(external.Message())
	groupIdByteCount, rest, ok := storedMlsVectorLength(inClear[4:])
	if !ok {
		t.Fatal("the external commit's group id")
	}
	senderAt := len(inClear) - len(rest) + groupIdByteCount + 8
	inClear[senderAt] = 1
	clearKey := fixture.put(t, 3, &protocol.GkmEpochObject{Commit: inClear})
	plaintextKey := fixture.put(t, 4, &protocol.GkmEpochObject{Commit: []byte(`{"handshake":"add","member":"plaintext"}`)})
	privateWireFormat := slices.Clone(staged.Message())
	binary.BigEndian.PutUint16(privateWireFormat[2:4], 5)
	keyPackageKey := fixture.put(t, 5, &protocol.GkmEpochObject{Commit: privateWireFormat})
	notAnObjectKey := fixture.putBytes(t, 6, []byte("\xff\xff\xff not a GkmEpochObject"))
	findings := fixture.check(t, false)
	for _, want := range []struct {
		key  string
		says string
	}{
		{key: clearKey, says: "a member's commit in the clear"},
		{key: plaintextKey, says: "no MLSMessage"},
		{key: keyPackageKey, says: "wire format 5"},
		{key: notAnObjectKey, says: "no GkmEpochObject"},
	} {
		if !slices.ContainsFunc(findings, func(finding string) bool {
			return strings.Contains(finding, want.key) && strings.Contains(finding, want.says)
		}) {
			t.Errorf("no finding names %s as %q: %q", want.key, want.says, findings)
		}
	}
	if len(findings) != 4 {
		t.Errorf("%d findings: %q", len(findings), findings)
	}
}

// In S3 and S4 GkmCommitHeader carries the generation and the auth pin alone: a field the header does not define, in
// the object's copy or in the commit's authenticated_data, fails under headerOnly and passes without it.
func TestAGkmCommitHeaderCarriesOnlyTheGenerationAndThePin(t *testing.T) {
	fixture := newStoredFixture(t)
	_, groups := fakeMlsTestGroup(t, 2)
	padded := protowire.AppendTag(storedTestHeader(t, 1), 9, protowire.BytesType)
	padded = protowire.AppendBytes(padded, []byte("a roster in the clear"))
	staged, err := groups[0].Commit(&sidecar.MlsCommitArgs{Path: true, AuthenticatedData: padded})
	if err != nil {
		t.Fatal(err)
	}
	commitKey := fixture.put(t, 1, &protocol.GkmEpochObject{Commit: staged.Message()})
	header := &protocol.GkmCommitHeader{Generation: 2}
	header.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 3, protowire.VarintType), 5))
	objectKey := fixture.put(t, 0, &protocol.GkmEpochObject{Header: header})
	if findings := fixture.check(t, false); len(findings) != 0 {
		t.Errorf("without headerOnly: %q", findings)
	}
	findings := fixture.check(t, true)
	if len(findings) != 2 ||
		!slices.ContainsFunc(findings, func(finding string) bool {
			return strings.Contains(finding, commitKey) && strings.Contains(finding, "commit's GkmCommitHeader")
		}) ||
		!slices.ContainsFunc(findings, func(finding string) bool {
			return strings.Contains(finding, objectKey) && strings.Contains(finding, "its GkmCommitHeader carries")
		}) {
		t.Errorf("findings %q", findings)
	}
}

// Only epoch objects are read: a GroupForm, a Welcome pointer and other families under gkm/ are no stored commit.
func TestOnlyEpochObjectsAreStoredCommits(t *testing.T) {
	fixture := newStoredFixture(t)
	for _, key := range []string{"gkm/repo/r/00000000000000000001", "gkm/welcome/s/g/00000000000000000001", "gkm/" + sidecar.EvsKeyId(fixture.groupId) + "/group-info"} {
		if _, err := fixture.cluster.PutIfNoneMatch(context.Background(), key, []byte("plaintext"), nil); err != nil {
			t.Fatal(err)
		}
	}
	if findings := fixture.check(t, true); len(findings) != 0 {
		t.Errorf("findings %q", findings)
	}
}

// evs and gkm write Redis only in the families §22.7 lists: a write to another family fails, naming the service, the
// key and the call, a script's keys counting as written, and another service writes what it likes.
func TestAWriteToAnUnlistedFamilyFails(t *testing.T) {
	host := NewFakeHost(context.Background(), NewFakeClock(DefaultClockStart()), NewFaultQueue(), nil, nil).ServiceHost()
	writers := NewStoredWriters(nil)
	ctx := context.Background()
	evs := writers.Host("evs", host).Redis
	gkm := writers.Host("gkm", host).Redis
	sockets := writers.Host("sockets", host).Redis
	for _, key := range []string{"{scp_c}ver", "{wakeq_3}", "{nvb_set}r", "{evsq_r}q", "{evsl_r}lease", "{evsh_r}h", "{evsd_r}d"} {
		if err := evs.Set(ctx, key, []byte("v"), 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := gkm.HashSet(ctx, "{gka_g}", map[string][]byte{"leaf": []byte("day")}); err != nil {
		t.Fatal(err)
	}
	if err := sockets.Set(ctx, "{svc_a}b", []byte("v"), 0); err != nil {
		t.Fatal(err)
	}
	if findings := writers.Check(); len(findings) != 0 {
		t.Fatalf("listed writes: %q", findings)
	}
	if err := evs.Set(ctx, "{dns}serial:x", []byte("v"), 0); err != nil {
		t.Fatal(err)
	}
	// a script counts as it is sent, whatever the store makes of it: T2's FakeRedis runs no script without its Go twin
	gkm.RunScript(ctx, &sidecar.RedisScript{Name: "toy-write", Source: "return 1"}, []string{"{tok_a}x"}, nil)
	if _, found, err := evs.Get(ctx, "{dns}serial:x"); err != nil || !found {
		t.Fatalf("a read: %t, %v", found, err)
	}
	findings := writers.Check()
	for _, want := range []string{"evs wrote {dns}serial:x by set", "gkm wrote {tok_a}x by script:toy-write"} {
		if !slices.ContainsFunc(findings, func(finding string) bool { return strings.Contains(finding, want) }) {
			t.Errorf("no finding says %q: %q", want, findings)
		}
	}
	if len(findings) != 2 {
		t.Errorf("%d findings: %q", len(findings), findings)
	}
}

// Only api writes {acl_}e: gkm's write of it fails, and sockets', and api's passes, as does gkm's of another {acl_}
// key it may not write for its own reason.
func TestOnlyApiWritesTheAclEpoch(t *testing.T) {
	host := NewFakeHost(context.Background(), NewFakeClock(DefaultClockStart()), NewFaultQueue(), nil, nil).ServiceHost()
	writers := NewStoredWriters(nil)
	ctx := context.Background()
	if err := writers.Host("api", host).Redis.Set(ctx, "{acl_n}e", []byte("7"), 0); err != nil {
		t.Fatal(err)
	}
	if findings := writers.Check(); len(findings) != 0 {
		t.Fatalf("api's write: %q", findings)
	}
	if _, err := writers.Host("sockets", host).Redis.Increment(ctx, "{acl_n}e", 0); err != nil {
		t.Fatal(err)
	}
	findings := writers.Check()
	if len(findings) != 1 || !strings.Contains(findings[0], "sockets wrote {acl_n}e by incr, which api alone writes") {
		t.Errorf("findings %q", findings)
	}
}

// evs and gkm touch no Postgres: a planted call of the Postgres-backed Tasks from evs fails, naming the job, while
// taskworker's, whose process holds a pool, passes.
func TestAPlantedPostgresTouchFromEvsFails(t *testing.T) {
	host := NewFakeHost(context.Background(), NewFakeClock(DefaultClockStart()), NewFaultQueue(), nil, nil).ServiceHost()
	writers := NewStoredWriters(nil)
	ctx := context.Background()
	if err := writers.Host("taskworker", host).Tasks.Schedule(ctx, &sidecar.TaskRequest{Name: "evs.nightly", OnceKey: "a"}); err != nil {
		t.Fatal(err)
	}
	if findings := writers.Check(); len(findings) != 0 {
		t.Fatalf("taskworker's: %q", findings)
	}
	if err := writers.Host("evs", host).Tasks.Schedule(ctx, &sidecar.TaskRequest{Name: "evs.evacuate", OnceKey: "b"}); err != nil {
		t.Fatal(err)
	}
	findings := writers.Check()
	if len(findings) != 1 || !strings.Contains(findings[0], "evs touched Postgres: Tasks.Schedule evs.evacuate") {
		t.Errorf("findings %q", findings)
	}
}
