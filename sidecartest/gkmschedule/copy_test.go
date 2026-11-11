package gkmschedule

// FS-105's ReaderKey legs on T2 (KEYS-M2-28; FI-29, §2.10's copied keychain row, D-KEYS-25, §10.5's readerkey row),
// on a fake clock over 60 days, the auth pins current throughout: on day 0 a passive copy is taken of an uncovered
// agent's keychain, its ReaderKey K0's private half among it; the agent replaces its ReaderKey every 6 days, each
// valid 6 days; a writer leaf rotates through the 60 days. On day 29 gkm serves the rotator the authentic K0
// advertisement, which the rotator refuses as expired and seals nothing to, and the agent gets that generation only
// once its current key is served, by a late delivery. No key the copy holds opens a generation claimed after day 37.
// An advertisement valid past 7 days is refused at gkm, and by a rotator a server serves it to.
//
// The member device's 60-day bound in a 60-leaf group, and the active clone's day-10 key and KeyPackage with the
// compromise revocation that ends it, are the review phase's (see the task's record).

import (
	"crypto/hpke"
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// FS-105: the 60 days of a copied agent keychain, the day-29 replay of K0 and the 37-day bound.
func TestFsKeysCopyACopiedAgentKeychainOpensNothingPastItsBound(t *testing.T) {
	world := NewFsKeysWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	agent := world.AddAgent("ag")
	world.Grant(true, a)
	world.Grant(false, agent)
	world.Admin(a)
	world.Advance()
	world.Publish()
	world.Create(a)
	// day 0: the passive copy, K0 alone
	copied := agent.CopyReaderKeys()
	k0 := agent.ReaderKey
	if !world.OpensWrapOf(agent, 1, copied) {
		t.Fatal("the copy does not open generation 1, delivered to K0")
	}

	start := world.Clock.Now()
	day := func(n int) time.Time { return start.Add(time.Duration(n) * 24 * time.Hour) }
	claimedOn := map[uint64]int{1: 0}
	for n := 1; n <= 60; n += 1 {
		world.Clock.AdvanceTo(day(n))
		if n%6 == 0 {
			agent.PublishReaderKey()
		}
		switch n {
		case 1, 8, 15, 22, 38, 45, 60:
			key, err := a.Client.RotateRepo(world.Ctx, world.RepoId)
			if err != nil {
				t.Fatalf("day %d's rotation: %v", n, err)
			}
			claimedOn[key.Generation()] = n
		case 29:
			// gkm serves the rotator the authentic K0 advertisement, whose not_after passed on day 6
			a.Transport.Respond = func(request *http.Request) *http.Response {
				if request.Method == http.MethodPost && request.URL.Path == "/gkm/reader-keys" {
					return FsKeysAnswer(&protocol.GkmReaderKeysReply{ReaderKeys: []*bridge.Signed{k0}})
				}
				return nil
			}
			key, err := a.Client.RotateRepo(world.Ctx, world.RepoId)
			a.Transport.Respond = nil
			if err != nil {
				t.Fatalf("day 29's rotation: %v", err)
			}
			claimedOn[key.Generation()] = n
			if world.WrapRecipients(key.Generation())[agent.SidecarId()] {
				t.Fatal("the rotator sealed to an expired advertisement")
			}
			// the agent's current key, honestly served, gets it late
			if err := a.Client.DeliverLate(world.Ctx, world.RepoId, fsKeysRecipient(agent.SidecarId())); err != nil {
				t.Fatalf("the late delivery to the agent's current key: %v", err)
			}
			if !world.OpensWrapOf(agent, key.Generation(), agent.CopyReaderKeys()) {
				t.Errorf("the agent's current key does not open day 29's generation")
			}
		}
	}
	for generation, claimed := range claimedOn {
		opens := world.OpensWrapOf(agent, generation, copied)
		if 37 < claimed && opens {
			t.Errorf("the day-0 copy opens generation %d, claimed on day %d", generation, claimed)
		}
		if claimed < 6 && !opens {
			t.Errorf("the day-0 copy does not open generation %d, claimed on day %d while K0 stood", generation, claimed)
		}
	}
	if err := agent.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	if held, err := agent.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil || held.Generation() != uint64(len(claimedOn)) {
		t.Errorf("the agent itself does not hold the newest generation: %v", err)
	}
}

// FS-105: an advertisement valid past 7 days is refused by gkm at its upload, and by a rotator a server serves it to,
// which seals nothing to it.
func TestFsKeysCopyAnAdvertisementValidPastSevenDaysIsRefused(t *testing.T) {
	world := NewFsKeysWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	agent := world.AddAgent("ag")
	world.Grant(true, a)
	world.Grant(false, agent)
	world.Admin(a)
	world.Advance()
	world.Publish()
	world.Create(a)
	world.Clock.Advance(25 * time.Hour)
	// signed by the agent's own identity key, as the client's constructor would never make it
	now := world.Clock.Now()
	privateKey, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	body, err := proto.Marshal(&protocol.ReaderKey{
		SidecarId: agent.SidecarId().Bytes(), XwingPublicKey: privateKey.PublicKey().Bytes(), NotAfter: now.Add(8 * 24 * time.Hour).UnixMilli(),
	})
	if err != nil {
		t.Fatal(err)
	}
	long, err := agent.signer.Sign("reader-key", bridge.SignedType_SIGNED_READER_KEY, body, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Api.UploadReaderKey(world.Ctx, long); !sidecar.IsGkmStatus(err, http.StatusForbidden) {
		t.Errorf("an advertisement valid 8 days at its upload: %v", err)
	}
	a.Transport.Respond = func(request *http.Request) *http.Response {
		if request.Method == http.MethodPost && request.URL.Path == "/gkm/reader-keys" {
			return FsKeysAnswer(&protocol.GkmReaderKeysReply{ReaderKeys: []*bridge.Signed{long}})
		}
		return nil
	}
	key, err := a.Client.RotateRepo(world.Ctx, world.RepoId)
	a.Transport.Respond = nil
	if err != nil {
		t.Fatal(err)
	}
	if world.WrapRecipients(key.Generation())[agent.SidecarId()] {
		t.Errorf("a rotator sealed to an advertisement valid past 7 days")
	}
}
