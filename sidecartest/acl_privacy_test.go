package sidecartest

// §22.7's privacy harness on the policy (ACL-M2-16; §8.7, owner decision 72, R-ACL-12, X2, I-13, I-18): a network's
// writer saves a document whose policy text, tags, groups, repo labels and socket names are all canaries, as a person's
// own names would be, and every base the writer publishes, every entry api sequences and api's read cache {acl_}e hold
// none of them in any form, nor K_sock: servers see the reach graph and keyed ids only. T2 on the Net's fake stores,
// which its capture reads (proj/ and projrows/ on its first metadata cluster, {acl_}e in its Redis); the network_acl_*
// tables are Postgres's, which server's T3 test scans (server/api/sidecar_acl_t3_test.go). Under sidecar_leaktest, a
// policy canary leaked into each store class through the class's own leak is found, so the clean scan is no blind one.

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One policy world: a Net and the admission world on its first metadata cluster, with ACL's compile.
type aclPrivacyWorld struct {
	net       *Net
	admission *AdmissionNet
	// the names the document uses, each a value no store may hold
	tag, group, label, socket, note, comment string
	socketKey                                []byte
	plan                                     *sidecar.AclSavePlan
}

// A world whose writer saved a document of canaries, and api's read cache written after every entry. The caller
// closes it before it opens another: under sidecar_testhooks a Net holds the process's hooks.
func newAclPrivacyWorld(t *testing.T) *aclPrivacyWorld {
	net := NewNet(t.Context(), nil)
	tier, err := net.AdmissionTier()
	if err != nil {
		net.Close()
		t.Fatal(err)
	}
	tier.AclCompile = AclAdmissionCompile
	admission := NewAdmissionNet(t, tier)
	capture := net.Capture()

	// a tag and a group hold 50 bytes at most, so each is a canary's first 40 characters behind a letter, forbidden in
	// every form; a repo label and a socket segment hold a whole canary text
	self := &aclPrivacyWorld{
		net:       net,
		admission: admission,
		tag:       "t" + capture.CanaryText("acl tag")[:40],
		group:     "g" + capture.CanaryText("acl group")[:40],
		label:     capture.CanaryText("acl repo label"),
		socket:    capture.CanaryText("acl socket name"),
		note:      capture.CanaryText("acl policy note"),
		comment:   capture.CanaryText("acl policy comment"),
		socketKey: bytes.Repeat([]byte{0x6b}, 32),
	}
	capture.Forbid("acl tag", []byte(self.tag))
	capture.Forbid("acl group", []byte(self.group))
	capture.AddSecret("acl K_sock", self.socketKey)

	memberId, first := admission.ConsentedMember("m")
	repoId := admission.Id("labelled repo")
	admission.MustLand(admission.Sign(first, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
		Header: admission.Header(), RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
	}))
	// the head's labels file and K_sock, which a config writer's head carries beside the policy (§8.8's Placement)
	labels, err := proto.Marshal(&protocol.ConfigLabelTable{Labels: []*protocol.ConfigRepoLabel{{Label: self.label, RepoId: repoId.Bytes()}}})
	if err != nil {
		t.Fatal(err)
	}
	socketKeyFile, err := proto.Marshal(&protocol.SocketKeyFile{CurrentKey: self.socketKey})
	if err != nil {
		t.Fatal(err)
	}
	admission.SaveHead(func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		head, err := head.WithFile(sidecar.ConfigHeadLabelsPath, labels)
		if err != nil {
			return nil, err
		}
		return head.WithFile(sidecar.ConfigHeadSocketKeyPath, socketKeyFile)
	})
	source := fmt.Sprintf(`{
		// %s
		"groups": { "group:%s": ["m@acme.example"] },
		"tagOwners": { "tag:%s": ["group:%s"] },
		"grants": [
			{ "src": ["group:%s"], "dst": ["evs:%s"], "allow": ["write"], "note": "%s" },
			{ "src": ["group:%s"], "dst": ["sock:%s"], "allow": ["dial"] },
			{ "src": ["tag:%s"], "dst": ["sock:%s"], "allow": ["listen"] },
			{ "src": ["autogroup:member"], "dst": ["autogroup:self"], "allow": ["dial", "route"] },
		],
	}`, self.comment, self.group, self.tag, self.group, self.group, self.label, self.note, self.group, self.socket, self.tag, self.socket)
	self.plan, _ = admission.SaveAclPolicy([]byte(source), AclSaveMembers{"m@acme.example": memberId})
	// the document compiled to what it says: the labelled repo is written by the group, and the socket has a rule
	if len(self.plan.Rows.GetRules()) < 4 {
		t.Fatalf("the document compiled to %d rules", len(self.plan.Rows.GetRules()))
	}
	acl, err := admission.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	if rights := acl.EvsAccess(sidecar.AclSidecarSubject(first.SidecarId), repoId, sidecar.AclTokenAudienceEvs, admission.Clock().Now()).Rights; !rights.Has(sidecar.AclEvsWrite) {
		t.Fatalf("the group's write on the labelled repo: %04b", rights)
	}
	// more entries after the base, so {acl_}e holds statements and a base
	admission.AdmitMember(admission.Owner(), "after the policy", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	admission.Fold(true)
	for n := uint64(1); n <= admission.Tip().GetVersion(); n += 1 {
		if err := aclPrivacyCacheEntry(t.Context(), net.Host().Redis, admission, n); err != nil {
			t.Fatal(err)
		}
	}
	return self
}

// Ends the world: the writer and its follower, then the Net.
func (self *aclPrivacyWorld) close() {
	self.admission.Close()
	self.net.Close()
}

// What api's one script writes after entry n (server/model/config_log_redis.go), in the Net's Redis.
func aclPrivacyCacheEntry(ctx context.Context, redis sidecar.Redis, admission *AdmissionNet, n uint64) error {
	networkId := admission.NetworkId()
	current, _, err := redis.Get(ctx, sidecar.AclVersionKey(networkId))
	if err != nil {
		return err
	}
	version := int64(0)
	if 0 < len(current) {
		if version, err = strconv.ParseInt(string(current), 10, 64); err != nil {
			return err
		}
	}
	if err := redis.HashSet(ctx, sidecar.AclEntryCacheKey(networkId), map[string][]byte{
		sidecar.AclEntryCacheField(n):     admission.Entry(n),
		sidecar.AclEntryCacheFieldBase:    []byte(strconv.FormatUint(admission.State().Base().GetVersion(), 10)),
		sidecar.AclEntryCacheFieldTip:     []byte(strconv.FormatUint(n, 10)),
		sidecar.AclEntryCacheFieldVersion: []byte(strconv.FormatInt(version+1, 10)),
	}); err != nil {
		return err
	}
	_, err = redis.Increment(ctx, sidecar.AclVersionKey(networkId), 48*time.Hour)
	return err
}

// Every canary, tag, group and K_sock of the document is in no stored byte: the bases' entries and rows, every other
// entry, and {acl_}e, while the head that holds them stays the writer's, and the stores do hold the log.
func TestAclPolicyCanariesReachNoStore(t *testing.T) {
	world := newAclPrivacyWorld(t)
	defer world.close()
	networkId := world.admission.NetworkId().String()
	entries, rows := 0, 0
	for name := range world.net.Fakes().Blobs.Dump() {
		switch {
		case strings.Contains(name, "/proj/"+networkId+"/"):
			entries += 1
		case strings.Contains(name, "/projrows/"+networkId+"/"):
			rows += 1
		}
	}
	// entries: the genesis, base 1, the member, its device, the repo, the labels and K_sock head's base, the policy's
	// base, the member after it and the fold; rows: the bootstrap's, the policy's and the fold's, which bases with the
	// same rows share
	if entries < 9 || rows < 3 {
		t.Fatalf("the store holds %d proj/ and %d projrows/ objects of the network", entries, rows)
	}
	if _, found := world.net.Fakes().Redis.Dump()[sidecar.AclEntryCacheKey(world.admission.NetworkId())]; !found {
		t.Fatal("{acl_}e holds nothing")
	}
	// the head the writer saved does hold them, so their absence below is the projection's doing
	policy := world.plan.Head.File(sidecar.ConfigHeadPolicyPath)
	for _, name := range []string{world.tag, world.group, world.label, world.socket, world.note, world.comment} {
		if !bytes.Contains(policy, []byte(name)) {
			t.Fatalf("the saved policy does not name %q", name)
		}
	}
	for _, finding := range world.net.Capture().Scan() {
		t.Errorf("%s", finding)
	}
}

// Under sidecar_leaktest: each store class's own leak (leak_enabled.go) carries the saved policy's note, whole, into
// its store, and the scan finds it there, so a policy text that reached a store would not pass unseen.
func TestAclPolicyCanaryLeakedIntoEachStoreClassIsCaught(t *testing.T) {
	if !LeaksLinked {
		t.Skip("the leaks link only under sidecar_leaktest, which test.sh's leak leg builds")
	}
	ran := 0
	for class, leak := range LeakClasses() {
		if class.Point() != "CC3" {
			continue
		}
		func() {
			// one world at a time: under sidecar_testhooks a Net holds the process's hooks
			world := newAclPrivacyWorld(t)
			defer world.close()
			if findings := world.net.Capture().Scan(); len(findings) != 0 {
				t.Fatalf("%s: findings before the leak: %v", class, findings)
			}
			leak.Put(t, world.net, []byte(world.note))
			caught := false
			for _, finding := range world.net.Capture().Scan() {
				if finding.Needle == "acl policy note" && finding.Class == class {
					caught = true
				}
			}
			if !caught {
				t.Errorf("a policy note leaked into %s went unseen", class)
			}
			ran += 1
		}()
	}
	if ran == 0 {
		t.Fatal("no store class's leak ran")
	}
	t.Logf("%d store classes caught a leaked policy note", ran)
}
