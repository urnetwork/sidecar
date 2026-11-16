//go:build !sidecar_http && !js && !ios_extension

// MAIL-M8-01's burners on MAIL-M7-17's client world: S10's receive-only half (a burner receives, a burned label gets
// 550 5.1.1 with no DNS or server change, and a receive-only burner makes no child); a kill after the record's push,
// then a retry, leaving one burner and one vault entry; a burned label never drawn again; the local limits on a fake
// clock; the first burner's copy under each coverage value; a label shadowing a published host skipped; and the label
// DRBG drawing the same candidates from the same key.

package sidecar

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The client world's api with the burner limits a test sets beside the receiver's.
type mailBurnerTestApi struct {
	*mailClientTestApi
	stateLock  sync.Mutex
	limits     map[string]int64
	limitCalls int
}

func (self *mailBurnerTestApi) Limits(ctx context.Context) (*QuotaLimits, error) {
	answer, err := self.mailClientTestApi.Limits(ctx)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.limitCalls += 1
	for key, value := range self.limits {
		answer.Limits[key] = value
	}
	return answer, nil
}

func (self *mailBurnerTestApi) set(key string, value int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.limits[key] = value
}

// A vault store whose next writes fail, as a process killed between a burner's record and its entry.
type mailBurnerTestVaultStore struct {
	*mailVaultTestStore
	failLock   sync.Mutex
	failWrites int
}

func (self *mailBurnerTestVaultStore) Write(ctx context.Context, writes []*mailStoreWrite) ([]uint64, error) {
	self.failLock.Lock()
	failing := 0 < self.failWrites
	if failing {
		self.failWrites -= 1
	}
	self.failLock.Unlock()
	if failing {
		return nil, errors.New("the process stopped")
	}
	return self.mailVaultTestStore.Write(ctx, writes)
}

// The world's parts with the vault over the failing store.
type mailBurnerTestParts struct {
	*mailClientTestParts
	vaultStore *mailBurnerTestVaultStore
	authority  *mailVaultTestAuthority
	clock      Clock
}

func (self *mailBurnerTestParts) vault(mailboxId Id, ownerMemberId Id, args *MailVaultArgs) *MailVault {
	return newMailVault(self.vaultStore, ownerMemberId, args.SidecarId, self.authority, self.clock, nil, DefaultMailVaultSettings())
}

// A member's device with mail on, a fake clock, the vault and generous burner limits.
type mailBurnerTestWorld struct {
	*mailClientTestWorld
	clock *mailTestClock
	api   *mailBurnerTestApi
	parts *mailBurnerTestParts
}

func newMailBurnerTestWorld(t *testing.T) *mailBurnerTestWorld {
	t.Helper()
	world := newMailClientTestWorld(t)
	clock := &mailTestClock{now: time.UnixMilli(testMailIngestPushMillis).UTC()}
	world.client.clock = clock
	world.enable()
	api := &mailBurnerTestApi{mailClientTestApi: world.api, limits: map[string]int64{mailLimitBurnersActive: 50, mailLimitBurnerCreatesPerDay: 20}}
	parts := &mailBurnerTestParts{
		mailClientTestParts: &mailClientTestParts{world: world},
		vaultStore:          &mailBurnerTestVaultStore{mailVaultTestStore: newMailVaultTestStore()},
		authority:           newMailVaultTestAuthority(world.device, world.member),
		clock:               clock,
	}
	binding, _, err := world.client.bound()
	if err != nil {
		t.Fatal(err)
	}
	bound := *binding
	bound.Api = api
	world.client.Bind(&bound)
	world.client.stateLock.Lock()
	world.client.partsOverride = parts
	world.client.stateLock.Unlock()
	return &mailBurnerTestWorld{mailClientTestWorld: world, clock: clock, api: api, parts: parts}
}

// How mailcfg resolves address now.
func (self *mailBurnerTestWorld) resolve(address string) *MailAddressLookup {
	self.t.Helper()
	recipient, err := ParseMailRecipient(testMailIngestRoot, address)
	if err != nil {
		self.t.Fatal(err)
	}
	config, err := self.client.syncedConfig(context.Background())
	if err != nil {
		self.t.Fatal(err)
	}
	lookup, err := config.Resolve(context.Background(), recipient)
	if err != nil {
		self.t.Fatal(err)
	}
	return lookup
}

var testMailBurnerLabelPattern = regexp.MustCompile(`^[a-z]+-[0-9]{4}$`)

// S10's receive-only half: a burner receives under the network's label, a burned label gets 550 5.1.1 (unknown to
// mailcfg) with no call to the server and no record of its own beyond mailcfg's, and the vault entry reads burned. A
// receive-only burner is no replying one, so it makes no child.
func TestMailBurnerReceivesThenABurnedLabelGets550WithNoDnsChange(t *testing.T) {
	world := newMailBurnerTestWorld(t)
	ctx := context.Background()
	created, err := world.client.CreateBurner(ctx, &MailBurnerCreateArgs{Site: "https://shop.example.org/signup"})
	if err != nil {
		t.Fatal(err)
	}
	if !testMailBurnerLabelPattern.MatchString(created.Label) || created.Address != "example@"+created.Label+".acme.root.example" ||
		created.Info.Replying || created.EntryId == (Id{}) {
		t.Fatalf("the burner %+v", created)
	}
	if lookup := world.resolve(created.Address); !lookup.Known || lookup.Kind != protocol.MailAddressKind_MAIL_ADDRESS_BURNER {
		t.Fatalf("a live burner %+v", lookup)
	}
	// any local part reaches the label
	if lookup := world.resolve("anything@" + created.Label + ".acme.root.example"); !lookup.Known {
		t.Fatal("another local part at the label")
	}
	entries, err := world.client.VaultEntries(ctx)
	if err != nil || len(entries) != 1 || entries[0].GetAddress() != created.Address || entries[0].GetTitle() != "https://shop.example.org/signup" {
		t.Fatalf("the vault entry %+v: %v", entries, err)
	}

	enables := world.api.enableCount
	limitCalls := world.api.limitCalls
	if err := world.client.Burn(ctx, created.Address); err != nil {
		t.Fatal(err)
	}
	if lookup := world.resolve(created.Address); lookup.Known {
		t.Fatalf("a burned label still receives: %+v", lookup)
	}
	if world.api.enableCount != enables || world.api.limitCalls != limitCalls {
		t.Fatal("a burn called the server")
	}
	entries, err = world.client.VaultEntries(ctx)
	if err != nil || entries[0].GetState() != protocol.VaultEntryState_VAULT_ENTRY_BURNED || entries[0].GetTitle() == "" {
		t.Fatalf("the vault entry after the burn %+v: %v", entries, err)
	}
	burners, err := world.client.Burners(ctx)
	if err != nil || len(burners) != 1 || burners[0].State != protocol.MailBurnerState_MAIL_BURNER_BURNED {
		t.Fatalf("burners %+v: %v", burners, err)
	}
	// burned for good: it is never resumed
	if err := world.client.PauseBurner(ctx, created.Label, false); !errors.Is(err, ErrMailConfigBurned) {
		t.Fatalf("a burned label resumed: %v", err)
	}
}

// Pause answers as a burn does, reversibly.
func TestMailBurnerPauseIsReversible(t *testing.T) {
	world := newMailBurnerTestWorld(t)
	ctx := context.Background()
	created, err := world.client.CreateBurner(ctx, &MailBurnerCreateArgs{Site: "news.example.net"})
	if err != nil {
		t.Fatal(err)
	}
	if err := world.client.PauseBurner(ctx, created.Address, true); err != nil {
		t.Fatal(err)
	}
	if world.resolve(created.Address).Known {
		t.Fatal("a paused burner receives")
	}
	if err := world.client.PauseBurner(ctx, created.Label, false); err != nil {
		t.Fatal(err)
	}
	if !world.resolve(created.Address).Known {
		t.Fatal("a resumed burner does not receive")
	}
}

// A kill after the record's push, before the vault entry, then the same use again: one burner, one entry, the same
// label, and the burner's Lookup finds it from the key.
func TestMailBurnerKillAfterTheRecordThenARetryLeavesOneBurner(t *testing.T) {
	world := newMailBurnerTestWorld(t)
	ctx := context.Background()
	world.parts.vaultStore.failWrites = 1
	first, err := world.client.CreateBurner(ctx, &MailBurnerCreateArgs{Site: "shop.example.org"})
	if !errors.Is(err, ErrMailBurnerNoVaultEntry) || first == nil || first.EntryId != (Id{}) {
		t.Fatalf("the killed creation %+v: %v", first, err)
	}
	again, err := world.client.CreateBurner(ctx, &MailBurnerCreateArgs{Site: "shop.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	if again.Label != first.Label || again.EntryId == (Id{}) {
		t.Fatalf("the retry %+v, after %+v", again, first)
	}
	burners, err := world.client.Burners(ctx)
	if err != nil || len(burners) != 1 {
		t.Fatalf("burners %d: %v", len(burners), err)
	}
	entries, err := world.client.VaultEntries(ctx)
	if err != nil || len(entries) != 1 {
		t.Fatalf("vault entries %d: %v", len(entries), err)
	}
	config, err := world.client.syncedConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	action := world.gate.lastAction()
	outcome, err := config.Lookup(ctx, action.Canonical, mailConfigTestEffectKey(action.Canonical))
	_, label, ok := parseMailConfigEffectRef(outcome.EffectRef)
	if err != nil || outcome.State != ApprovalOutcomeDone || !ok || label != first.Label {
		t.Fatalf("the burner's lookup %+v: %v", outcome, err)
	}
}

// A burned label is never drawn again: a creation whose drawer offers it first takes the next.
func TestMailBurnerABurnedLabelIsNeverDrawnAgain(t *testing.T) {
	world := newMailBurnerTestWorld(t)
	ctx := context.Background()
	created, err := world.client.CreateBurner(ctx, &MailBurnerCreateArgs{Site: "shop.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	if err := world.client.Burn(ctx, created.Label); err != nil {
		t.Fatal(err)
	}
	config, err := world.client.syncedConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	config.SetBurnerLabels(func(effectKey []byte) []string { return []string{created.Label, "heron-0007"} })
	next, err := world.client.CreateBurner(ctx, &MailBurnerCreateArgs{Site: "othershop.example"})
	if err != nil || next.Label != "heron-0007" {
		t.Fatalf("a creation offered a burned label %+v: %v", next, err)
	}
}

// The local limits, from GET /sidecar/limits: active burners and creations within a day, on a fake clock; a limit not
// there to read refuses; -1 bounds nothing. A refused creation reaches no gate.
func TestMailBurnerLimitsAreRefusedLocally(t *testing.T) {
	world := newMailBurnerTestWorld(t)
	ctx := context.Background()
	world.api.set(mailLimitBurnersActive, 2)
	world.api.set(mailLimitBurnerCreatesPerDay, 3)
	create := func(site string) (*MailBurnerCreated, error) {
		return world.client.CreateBurner(ctx, &MailBurnerCreateArgs{Site: site})
	}
	first, err := create("alpha.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := create("bravo.example"); err != nil {
		t.Fatal(err)
	}
	actions, _ := world.gate.counts()
	var limit *MailBurnerLimitError
	if _, err := create("charlie.example"); !errors.As(err, &limit) || limit.Limit != mailLimitBurnersActive || limit.Count != 2 {
		t.Fatalf("past the active limit: %v", err)
	}
	if after, _ := world.gate.counts(); after != actions {
		t.Fatal("a refused creation reached the gate")
	}
	// a burned burner is no longer active, but its creation still counts for the day
	if err := world.client.Burn(ctx, first.Address); err != nil {
		t.Fatal(err)
	}
	if _, err := create("charlie.example"); err != nil {
		t.Fatalf("under the active limit again: %v", err)
	}
	if err := world.client.Burn(ctx, "a@"+mustMailBurnerLabel(t, world, "charlie.example")+".acme.root.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := create("delta.example"); !errors.As(err, &limit) || limit.Limit != mailLimitBurnerCreatesPerDay {
		t.Fatalf("past the creations of a day: %v", err)
	}
	world.clock.now = world.clock.now.Add(25 * time.Hour)
	if _, err := create("delta.example"); err != nil {
		t.Fatalf("a day later: %v", err)
	}
	world.api.set(mailLimitBurnersActive, 10)
	world.api.set(mailLimitBurnerCreatesPerDay, 0)
	if _, err := create("echo.example"); !errors.As(err, &limit) || limit.Value != 0 || limit.Limit != mailLimitBurnerCreatesPerDay {
		t.Fatalf("a limit not there to read: %v", err)
	}
	world.api.set(mailLimitBurnerCreatesPerDay, -1)
	world.api.set(mailLimitBurnersActive, -1)
	if _, err := create("echo.example"); err != nil {
		t.Fatalf("unbounded: %v", err)
	}
}

// The label of the burner made for site, which a test burns.
func mustMailBurnerLabel(t *testing.T, world *mailBurnerTestWorld, site string) string {
	t.Helper()
	entries, err := world.client.VaultEntries(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.GetTitle() == site {
			recipient, err := ParseMailRecipient(testMailIngestRoot, entry.GetAddress())
			if err != nil {
				t.Fatal(err)
			}
			return recipient.BurnerLabel
		}
	}
	t.Fatalf("no burner for %s", site)
	return ""
}

// Before this member's first burner the copy shows while coverage is foreground-only or none, and not under indexer
// or for a second burner; coverage never refuses a creation.
func TestMailBurnerFirstBurnerShowsTheCopyUnderEachCoverage(t *testing.T) {
	cases := []struct {
		name     string
		coverage func(world *mailBurnerTestWorld)
		want     string
	}{
		{name: "none", coverage: func(world *mailBurnerTestWorld) {}, want: MailCoverageForegroundOnlyCopy},
		{name: "indexer", coverage: func(world *mailBurnerTestWorld) {
			team := newTestMailIndexerTeam(world.t, protocol.TeamMailMode_TEAM_MAIL_MODE_INDEXERS)
			binding, _, _ := world.client.bound()
			bound := *binding
			bound.Config = func() (*ConfigState, error) { return team.net.log.State(), nil }
			bound.IndexerServices = team.services
			world.client.Bind(&bound)
		}, want: ""},
	}
	for _, c := range cases {
		world := newMailBurnerTestWorld(t)
		c.coverage(world)
		ctx := context.Background()
		first, err := world.client.CreateBurner(ctx, &MailBurnerCreateArgs{Site: "firstshop.example"})
		if err != nil || first.CoverageCopy != c.want {
			t.Errorf("%s: the first burner's copy %q: %v", c.name, first.CoverageCopy, err)
			continue
		}
		second, err := world.client.CreateBurner(ctx, &MailBurnerCreateArgs{Site: "secondshop.example"})
		if err != nil || second.CoverageCopy != "" {
			t.Errorf("%s: a second burner's copy %q: %v", c.name, second.CoverageCopy, err)
		}
	}
	// foreground-only reads the same copy as none
	if MailCoverageCopy(MailCoverageForegroundOnly) != MailCoverageForegroundOnlyCopy {
		t.Fatal("foreground-only's copy")
	}
}

// A label shadowing a host the network publishes is skipped.
func TestMailBurnerALabelShadowingAPublishedHostIsSkipped(t *testing.T) {
	key := []byte("a use's effect key")
	labels, err := NewMailBurnerLabels(&MailBurnerLabelsArgs{CandidateCount: 4, DrawsPerCandidate: 64})
	if err != nil {
		t.Fatal(err)
	}
	drawn := labels.Draw(key)
	shadowing, err := NewMailBurnerLabels(&MailBurnerLabelsArgs{
		CandidateCount: 4, DrawsPerCandidate: 64, PublishedHosts: func() []string { return []string{"www", strings.ToUpper(drawn[0])} },
	})
	if err != nil {
		t.Fatal(err)
	}
	skipped := shadowing.Draw(key)
	if slices.Contains(skipped, drawn[0]) || !slices.Equal(skipped[:3], drawn[1:]) || len(skipped) != 4 {
		t.Fatalf("drawn %v, with the first published %v", drawn, skipped)
	}
	zone := &DnsZone{Root: "root.example.", Label: "acme", RecordSets: []DnsZoneRecordSet{
		{Name: "www.acme.root.example."}, {Name: "a.b.acme.root.example"}, {Name: "acme.root.example."}, {Name: "elsewhere.example."},
	}}
	if published := mailBurnerPublishedLabels(zone); !slices.Equal(published, []string{"www", "b"}) {
		t.Fatalf("the published labels %v", published)
	}
}

// The DRBG draws the same candidates from the same key, others from another, each a word-number label, none twice;
// an empty key draws from a random seed.
func TestMailBurnerLabelsDrawFromTheEffectKey(t *testing.T) {
	labels, err := NewMailBurnerLabels(&MailBurnerLabelsArgs{CandidateCount: 16, DrawsPerCandidate: 64})
	if err != nil {
		t.Fatal(err)
	}
	first := labels.Draw([]byte("key one"))
	if again := labels.Draw([]byte("key one")); !slices.Equal(first, again) {
		t.Fatal("one key drew two lists")
	}
	if other := labels.Draw([]byte("key two")); slices.Equal(first, other) {
		t.Fatal("two keys drew one list")
	}
	seen := map[string]bool{}
	for _, label := range first {
		if !testMailBurnerLabelPattern.MatchString(label) || !IsWordNumberDnsLabel(label) || seen[label] {
			t.Errorf("a candidate %q", label)
		}
		if _, err := MailBurnerPath(label); err != nil {
			t.Errorf("a candidate with no path: %q", label)
		}
		seen[label] = true
	}
	if len(first) != 16 {
		t.Fatalf("%d candidates", len(first))
	}
	if slices.Equal(labels.Draw(nil), labels.Draw(nil)) {
		t.Fatal("a keyless draw repeated")
	}
	if words := MailBurnerWords(); len(words) < 256 || slices.Contains(words, "") {
		t.Fatalf("%d words", len(words))
	}
	if _, err := NewMailBurnerLabels(&MailBurnerLabelsArgs{CandidateCount: 1, DrawsPerCandidate: 1, Words: []string{"Otter"}}); !errors.Is(err, ErrMailBurnerLabelsInvalid) {
		t.Fatalf("a word that is no lowercase word: %v", err)
	}
}

// A burner's local part is its site's name, else mail; a site out of shape is refused before anything happens.
func TestMailBurnerLocalPartAndSite(t *testing.T) {
	for site, want := range map[string]string{
		"https://shop.example.org/signup": "example", "example.org": "example", "EXAMPLE.ORG:8443": "example",
		"https://news.example.co.uk": "example", "postmaster.example": "mail", "": "mail", "%%%": "mail",
	} {
		if got := mailBurnerLocalPart(site); got != want {
			t.Errorf("%q: %q, not %q", site, got, want)
		}
	}
	world := newMailBurnerTestWorld(t)
	for _, site := range []string{"", "a\r\nb", strings.Repeat("x", 4096)} {
		if _, err := world.client.CreateBurner(context.Background(), &MailBurnerCreateArgs{Site: site}); !errors.Is(err, ErrMailBurnerInvalid) {
			t.Errorf("a site out of shape: %v", err)
		}
	}
	for _, name := range []string{"nobody@acme.root.example", "x@otter-4821.elsewhere.example", "not-a-label"} {
		if err := world.client.Burn(context.Background(), name); !errors.Is(err, ErrMailBurnerInvalid) {
			t.Errorf("a burn of %q: %v", name, err)
		}
	}
}

// Making and burning a burner logs no address, label or site (I-13).
func TestMailBurnerLogsNoLabel(t *testing.T) {
	world := newMailBurnerTestWorld(t)
	created, err := world.client.CreateBurner(context.Background(), &MailBurnerCreateArgs{Site: "secret-site.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	if err := world.client.Burn(context.Background(), created.Address); err != nil {
		t.Fatal(err)
	}
	for _, line := range world.log.snapshot() {
		if strings.Contains(line, created.Label) || strings.Contains(line, "secret-site") || strings.Contains(line, "@") {
			t.Errorf("a line names the burner: %q", line)
		}
	}
}
