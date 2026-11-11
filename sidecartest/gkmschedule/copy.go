package gkmschedule

// FS-105's ReaderKey legs on T2 (KEYS-M2-28; FI-29, §2.10's copied keychain row, D-KEYS-25, §10.5's readerkey row),
// on a fake clock over 60 days, the auth pins current throughout: on day 0 a passive copy is taken of an uncovered
// agent's keychain, its ReaderKey K0's private half among it; the agent replaces its ReaderKey every 6 days, each
// valid 6 days; a writer leaf rotates through the 60 days. On day 29 gkm serves the rotator the authentic K0
// advertisement, which the rotator refuses as expired and seals nothing to, and the agent gets that generation only
// once its current key is served, by a late delivery. No key the copy holds opens a generation claimed after day 37.
// An advertisement valid past 7 days is refused at gkm, and by a rotator a server serves it to.
//
// Then an active clone of member device D, a leaf, signs a fresh ReaderKey and KeyPackage under D's identity on day
// 10: a wrapped rotator seals to the clone's key, which took D's slot, and the clone reads; D, replacing its key a
// day on and taking a late delivery, commits path-only, and neither ends anything, the clone re-signing a key a day
// later and reading the next rotation again; until D's
// SidecarRevoke{reason: compromise}, after which gkm refuses the clone's uploads and tokens and D's commits, every
// later rotation excludes D, nothing the clone or D kept opens it, and D's member enrolls a new device, which reads.
//
// The member device's 60-day bound in a 60-leaf group copied and running, and the device the clone admitted being
// parked, are the review phase's and TEAM's (see the task's record).

import (
	"crypto/hpke"
	"net/http"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// FS-105: the 60 days of a copied agent keychain, the day-29 replay of K0 and the 37-day bound.
func FsKeysScheduleCopiedAgentKeychain(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
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
func FsKeysScheduleLongAdvertisement(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
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

// FS-105's active clone: see the file header.
func FsKeysScheduleActiveClone(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	d := world.AddMember("d", false)
	w := world.AddAgent("w")
	world.Grant(true, a, w)
	world.Grant(false, d)
	world.Admin(a)
	world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	if _, err := w.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	// day 0: the copy; day 10: the clone's fresh ReaderKey and KeyPackage under D's identity
	clone := world.Clone(d, "clone")
	// a's upkeep replaces its ReaderKey every 6 days, as each holder's does
	world.Clock.Advance(6 * 24 * time.Hour)
	a.PublishReaderKey()
	world.Clock.Advance(4 * 24 * time.Hour)
	clone.PublishReaderKey()
	clone.PublishKeyPackages()
	// a wrapped rotator seals to the key gkm serves for D, the clone's, and the clone reads
	key, err := w.Client.RotateRepo(world.Ctx, world.RepoId)
	if err != nil {
		t.Fatalf("the wrapped rotation on day 10: %v", err)
	}
	if !world.OpensWrapOf(d, key.Generation(), clone.CopyReaderKeys()) {
		t.Errorf("the clone does not read the generation sealed to its key")
	}
	// the clone's key took D's slot, so D opens that generation only once it replaces its key a day on and a
	// writer delivers late to the key it signed; its path-only commit follows
	world.Clock.Advance(25 * time.Hour)
	d.PublishReaderKey()
	if err := a.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	if err := a.Client.DeliverLate(world.Ctx, world.RepoId, fsKeysRecipient(d.SidecarId())); err != nil {
		t.Fatalf("the late delivery to D's own key: %v", err)
	}
	if err := d.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	if err := d.Client.SelfUpdate(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("D's path-only commit: %v", err)
	}
	// D's commit and its key replacement end nothing: a day on the clone signs again and reads the next rotation
	// (a's upkeep replacing its key of day 6 as it lapses)
	world.Clock.Advance(25 * time.Hour)
	a.PublishReaderKey()
	clone.PublishReaderKey()
	key, err = w.Client.RotateRepo(world.Ctx, world.RepoId)
	if err != nil {
		t.Fatal(err)
	}
	if !world.OpensWrapOf(d, key.Generation(), clone.CopyReaderKeys()) {
		t.Errorf("D's own commit and key replacement ended the clone's reading")
	}

	// D's SidecarRevoke{reason: compromise}, from a since_n before the copy
	world.Revoke(d)
	world.VoidTokens(d)
	world.Advance()
	now := world.Clock.Now()
	readerKey, _, err := sidecar.NewGkmReaderKey(d.SidecarId(), now, now.Add(6*24*time.Hour), clone.signer.Sign)
	if err != nil {
		t.Fatal(err)
	}
	if err := clone.Api.UploadReaderKey(world.Ctx, readerKey); err == nil {
		t.Errorf("gkm took the clone's ReaderKey after D's revocation")
	}
	if _, err := clone.Api.Epochs(world.Ctx, world.RepoId, world.GroupId, 0); err == nil {
		t.Errorf("gkm served the clone's token after D's revocation")
	}
	// gkm's guard refuses a revoked device's commit before it reads the body
	commitPath := "/gkm/groups/" + sidecar.EvsKeyId(world.GroupId) + "/epochs/" + strconv.FormatUint(world.NewestEpoch()+1, 10)
	if status := world.RawStatus(d, http.MethodPost, commitPath, nil, "repo:"+world.RepoId.String()+":r"); status != http.StatusForbidden && status != http.StatusUnauthorized {
		t.Errorf("a commit under the revoked device's token: %d", status)
	}
	removed, err := a.Client.EnsureWritable(world.Ctx, world.RepoId)
	if err != nil || removed.Cause() != sidecar.GkmCauseRemove {
		t.Fatalf("the rotation past D's revocation: %v", err)
	}
	if labels := world.Roster(a); labels != "a" {
		t.Errorf("the tree past D's revocation: %s", labels)
	}
	held := append(clone.CopyReaderKeys(), d.CopyReaderKeys()...)
	if reached := world.KeysOpenAny(held); removed.Generation() <= reached {
		t.Errorf("the clone's and D's keys reach generation %d, past D's revocation", reached)
	}
	if reached := world.RemovedReach(d); removed.Generation() <= reached {
		t.Errorf("D's MLS state reaches generation %d, past its revocation", reached)
	}
	// D's member enrolls a new device, which joins and reads the generation past D
	e := world.AddMember("e", false)
	world.Grant(false, e)
	world.Advance()
	world.Publish()
	world.AddPending(a)
	if err := e.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	if current, err := e.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil || current.Generation() != removed.Generation() {
		t.Errorf("the member's new device does not read the generation past D: %v", err)
	}
}
