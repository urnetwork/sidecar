package sidecartest

// §22.7's directory row at M6 (TEST-M6-01; I-20, owner decisions 170 and 181), on S13's world (s13_test.go): a team's
// directory over this package's fakes, every entry sealed and signed for real.
//
//	"the directory's plaintext, decrypted with a member's keys, holds no canary from a prompt past the first line, a
//	tool input or output, a touched path or a diff (I-20); title canaries reach it only in its sealed cards, entries
//	and index files, and never evs metadata, logs or another network's repos; a private repo's display-name canary
//	never reaches it, and after a revoke no stored card, entry or index file holding a revoked name has a readable key"
//
// Two captures hold the two views. stored is evs's: every stream entry as evs holds it, with its path, and every line
// the devices' directory clients log, which on these steps is none; no canary of any kind may be there, a title's
// included, since a title is sealed. opened is a member's: every entry body and notice a member's device opens with its keys. A run's title is
// meant to be there, which every admitted sidecar reads (§2.8's evs-27, the directory's row), so that kind is
// declared for that view rather than asserted absent, and the test asserts it did arrive, so the view is no empty
// one; every other kind is a finding there.
//
// The canaries are planted where M6 has a path for them. A run reaches the directory through its start alone, whose
// title is SessionStart's text: the prompt's later lines carry the prompt canary and, as a prompt quotes them, a tool
// input, a tool output, a touched path and a diff. A private repo's display name is given to its marker's write and
// as the project label of a run inside it. The mutant for the first clause is a daemon that joins the prompt's lines
// before it hands the title over; for the last, a revocation whose erasure never runs.
//
// Not here: canaries a hook or an MCP tool hands a daemon (no daemon is composed into this world), another network's
// repos, and format 2's cards and index files, which join at the later of M6-out and M10-out (TEST-M10-06).

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

const (
	privacyDirectoryTitleKind   = "a run title"
	privacyDirectoryRevokedKind = "a revoked repo's name"
	privacyDirectoryPrivateKind = "a private repo's display name"
	privacyDirectoryPromptKind  = "a prompt past its first line"
)

// The kinds that reach no view of the directory, with the prompt's first.
var privacyDirectoryKinds = []string{
	privacyDirectoryPromptKind, "a tool input", "a tool output", "a touched path", "a diff", privacyDirectoryPrivateKind,
}

// S13's world with the two views captured: see the file header.
type privacyDirectoryWorld struct {
	*s13World
	stored *PrivacyCapture
	opened *PrivacyCapture
	// each kind's canary text
	canaries map[string]string
	title    string
	revoked  string
	// the devices whose opened view is captured
	readers []*s13Device
}

func newPrivacyDirectoryWorld(t *testing.T) *privacyDirectoryWorld {
	t.Helper()
	world := &privacyDirectoryWorld{
		s13World: newS13World(t), stored: NewPrivacyCapture(), opened: NewPrivacyCapture(), canaries: map[string]string{},
	}
	// the devices again, their clients logging into evs's view: nothing has been written yet
	world.logs = func(device *s13Device) sidecar.Logger {
		return world.stored.Logger("directory client " + device.sidecarId.String())
	}
	for _, device := range []*s13Device{world.a, world.b, world.d} {
		world.open(device)
	}
	canary := func(kind string) string {
		text := world.stored.CanaryText(kind)
		world.opened.Forbid(kind, []byte(text))
		return text
	}
	for _, kind := range privacyDirectoryKinds {
		world.canaries[kind] = canary(kind)
	}
	world.title = canary(privacyDirectoryTitleKind)
	if err := world.opened.Declare("evs-27", privacyDirectoryTitleKind, PrivacyClassObject); err != nil {
		t.Fatal(err)
	}
	// evs's view, read at each scan: each stream's entries as stored, and their paths
	world.stored.AddSource(func() []*PrivacyItem {
		items := []*PrivacyItem{}
		streams := world.streams.For(world.d.sidecarId)
		heads, err := streams.Streams(t.Context(), world.directoryId)
		if err != nil {
			t.Errorf("evs's streams: %v", err)
			return nil
		}
		for _, head := range heads {
			versions, err := streams.ReadStream(t.Context(), world.directoryId, head.SidecarId, 0)
			if err != nil {
				t.Errorf("evs's stream of %s: %v", head.SidecarId, err)
				continue
			}
			for _, version := range versions {
				for _, entry := range version.Entries {
					name := fmt.Sprintf("evs stream %s version %d", head.SidecarId, version.Version)
					items = append(items,
						&PrivacyItem{Class: PrivacyClassObject, Name: name + " entry", Body: bytes.Clone(entry.Entry)},
						&PrivacyItem{Class: PrivacyClassObject, Name: name + " path", Body: []byte(entry.Path)},
					)
				}
			}
		}
		return items
	})
	// a member's view, read at each scan
	world.opened.AddSource(func() []*PrivacyItem {
		items := []*PrivacyItem{}
		for _, device := range world.readers {
			items = append(items, world.openedBy(device)...)
		}
		return items
	})
	world.readers = []*s13Device{world.b}
	return world
}

// Everything device opens of the directory with its keys: each entry's body, and each notice.
func (self *privacyDirectoryWorld) openedBy(device *s13Device) []*PrivacyItem {
	t := self.t
	ctx := t.Context()
	if err := device.client.Sync(ctx); err != nil {
		t.Errorf("a reader's sync: %v", err)
		return nil
	}
	reader := device.record.Reader()
	if err := reader.Sync(ctx, self.directoryId); err != nil {
		t.Errorf("a reader's read: %v", err)
		return nil
	}
	items := []*PrivacyItem{}
	for _, entry := range reader.Entries(self.directoryId) {
		name := fmt.Sprintf("opened by %s: entry %s", device.sidecarId, entry.EntryId)
		items = append(items,
			&PrivacyItem{Class: PrivacyClassObject, Name: name, Body: bytes.Clone(entry.Body)},
			&PrivacyItem{Class: PrivacyClassObject, Name: name + " sealed plaintext", Body: bytes.Clone(entry.Sealed)},
		)
	}
	for _, file := range device.client.Cards() {
		items = append(items, &PrivacyItem{Class: PrivacyClassObject, Name: fmt.Sprintf("opened by %s: %s", device.sidecarId, file.Path), Body: bytes.Clone(file.Content)})
	}
	return items
}

func (self *privacyDirectoryWorld) must(err error) {
	self.t.Helper()
	if err != nil {
		self.t.Fatal(err)
	}
}

// A's repos and runs: X private, its marker's write given a display name, Y announced under name; a run in Y whose
// prompt carries the title canary on its first line and every other canary after it, joined into one line by a daemon
// that joinsLines; and a run in X whose project label is X's display name.
func (self *privacyDirectoryWorld) announce(ctx context.Context, name string, joinsLines bool) {
	a := self.a
	self.must(a.client.Sync(ctx))
	_, err := a.client.AnnounceRepo(ctx, &sidecar.DirectoryRepoAnnounceArgs{
		RepoId: self.privateId, DisplayName: self.canaries[privacyDirectoryPrivateKind], Private: true, Confirmed: true,
	})
	self.must(err)
	_, err = a.client.AnnounceRepo(ctx, &sidecar.DirectoryRepoAnnounceArgs{RepoId: self.announcedId, DisplayName: name, Confirmed: true})
	self.must(err)
	self.must(a.record.Flush(ctx))
	self.must(a.client.Sync(ctx))
	// short lines, so a title of the first two joined is still under the 120 B a title is cut to
	prompt := []string{
		"fix " + self.title,
		self.canaries[privacyDirectoryPromptKind],
		"it ran with " + self.canaries["a tool input"] + " and printed " + self.canaries["a tool output"],
		"after it touched " + self.canaries["a touched path"],
		"+ " + self.canaries["a diff"],
	}
	separator := "\n"
	if joinsLines {
		separator = " "
	}
	for _, start := range []*sidecar.DirectoryRunStart{
		{
			RunId: sidecar.NewId(), Claims: sidecar.DirectoryRunClaimsAuto, ProjectKey: "y", AgentLabel: "builder", Harness: "codex",
			Title: strings.Join(prompt, separator), RepoId: &self.announcedId, Branch: "main",
		},
		{
			RunId: sidecar.NewId(), Claims: sidecar.DirectoryRunClaimsAuto, ProjectKey: "x", AgentLabel: "builder", Harness: "codex",
			Title: "rework the private module", RepoId: &self.privateId, Project: self.canaries[privacyDirectoryPrivateKind], Branch: "main",
		},
	} {
		self.must(a.client.Runs().Started(start))
	}
	self.clock.Advance(10 * time.Second)
	self.must(a.record.Flush(ctx))
}

// What of §22.7's row the two views break, nil when evs's view holds no canary, a member's holds none but the title,
// and, where titled asks, the title arrived there: a run's entry is gone once its repo's revocation is erased.
func (self *privacyDirectoryWorld) errors(titled bool) []error {
	errs := []error{}
	for _, finding := range self.stored.Scan() {
		errs = append(errs, fmt.Errorf("evs's view: %s", finding))
	}
	for _, finding := range self.opened.Scan() {
		errs = append(errs, fmt.Errorf("a member's view: %s", finding))
	}
	if self.stored.ItemCount(PrivacyClassObject) == 0 {
		errs = append(errs, fmt.Errorf("evs's view read no stored entry, which shows nothing"))
	}
	if !titled {
		return errs
	}
	arrived := false
	for _, device := range self.readers {
		for _, item := range self.openedBy(device) {
			arrived = arrived || bytes.Contains(item.Body, []byte(self.title))
		}
	}
	if !arrived {
		errs = append(errs, fmt.Errorf("no member opened the title canary, so a member's view shows nothing"))
	}
	return errs
}

// The entries device opens that hold name, by a capture of its own: every form of the name is looked for.
func (self *privacyDirectoryWorld) readableName(device *s13Device, name string) []*PrivacyFinding {
	capture := NewPrivacyCapture()
	capture.Forbid(privacyDirectoryRevokedKind, []byte(name))
	for _, item := range self.openedBy(device) {
		capture.AddItem(item)
	}
	return capture.Scan()
}

// A member device admitted now, which reads the directory from nothing.
func (self *privacyDirectoryWorld) freshReader() *s13Device {
	device := self.device(false)
	self.publish()
	self.open(device)
	return device
}

// One pass of the directory admin's erasure runner, twice over, as S13 runs it.
func (self *privacyDirectoryWorld) erase(ctx context.Context) {
	d := self.d
	d.client.BindEraser(d.record.Eraser().Erase)
	runner, err := sidecar.NewDirectoryErasureRunner(&sidecar.DirectoryErasureRunnerArgs{Client: d.client, Erase: d.record.Eraser().Erase, Random: bytes.NewReader(make([]byte, 64))})
	self.must(err)
	for range 2 {
		self.must(d.client.Sync(ctx))
		_, err := runner.Pass(ctx)
		self.must(err)
		self.must(d.record.Flush(ctx))
	}
}

// The row, whole: evs's view holds no canary, a title's included; a member's view holds the title and no canary from
// past the prompt's first line, of a tool input or output, a touched path, a diff or a private repo's display name;
// and once a revoked announcement's erasure has run, neither a member that read the name before nor one admitted
// after opens an entry that holds it.
func TestDirectoryPlaintextHoldsNoCanary(t *testing.T) {
	ctx := t.Context()
	world := newPrivacyDirectoryWorld(t)
	name := world.stored.CanaryText(privacyDirectoryRevokedKind)
	world.announce(ctx, name, false)
	for _, err := range world.errors(true) {
		t.Error(err)
	}
	// a repo's name is no title: announced, evs's view holds it sealed alone, and a member opens it
	if len(world.readableName(world.b, name)) == 0 {
		t.Fatal("no member opened the announced repo's name before its revocation, so the erasure shows nothing")
	}
	world.must(world.a.client.Sync(ctx))
	_, err := world.a.client.RevokeRepo(ctx, &sidecar.DirectoryRevokeArgs{RepoId: world.announcedId, Confirmed: true})
	world.must(err)
	world.must(world.a.record.Flush(ctx))
	world.erase(ctx)
	for _, device := range []*s13Device{world.b, world.d, world.freshReader()} {
		for _, finding := range world.readableName(device, name) {
			t.Errorf("after the erasure a member opens the revoked name: %s", finding)
		}
	}
	// the rest of the row stands after the revocation's and the erasure's writes
	world.readers = append(world.readers, world.d)
	for _, err := range world.errors(false) {
		t.Error(err)
	}
}

// A canary from past a prompt's first line in an entry fails: a daemon that joins the prompt's lines hands over a
// title that holds them, and the row names each kind in a member's view, while evs's view, which holds entries
// sealed, stays clean.
func TestDirectoryACanaryPastAPromptsFirstLineInAnEntryFails(t *testing.T) {
	ctx := t.Context()
	world := newPrivacyDirectoryWorld(t)
	world.announce(ctx, "launch site", true)
	errs := world.errors(true)
	text := fmt.Sprint(errs)
	if len(errs) == 0 || !strings.Contains(text, "a member's view") || !strings.Contains(text, privacyDirectoryPromptKind) {
		t.Fatalf("a prompt's later lines in an entry passed the row: %v", errs)
	}
	if strings.Contains(text, "evs's view") {
		t.Errorf("the sealed entry showed at evs: %v", errs)
	}
	if strings.Contains(text, privacyDirectoryTitleKind) {
		t.Errorf("the title, which is declared for a member's view, is a finding: %v", errs)
	}
}

// A revoked name still readable fails: with the revocation filed and its erasure not yet run, the entries that hold
// the name still open for a member admitted afterwards, and the erasure's run ends that.
func TestDirectoryARevokedNameStillReadableFails(t *testing.T) {
	ctx := t.Context()
	world := newPrivacyDirectoryWorld(t)
	name := world.stored.CanaryText(privacyDirectoryRevokedKind)
	world.announce(ctx, name, false)
	world.must(world.a.client.Sync(ctx))
	_, err := world.a.client.RevokeRepo(ctx, &sidecar.DirectoryRevokeArgs{RepoId: world.announcedId, Confirmed: true})
	world.must(err)
	world.must(world.a.record.Flush(ctx))
	if len(world.readableName(world.freshReader(), name)) == 0 {
		t.Fatal("a revocation whose erasure never ran left no readable copy of the name: the row's last clause would pass a runner that does nothing")
	}
	world.erase(ctx)
	for _, finding := range world.readableName(world.freshReader(), name) {
		t.Errorf("after the erasure: %s", finding)
	}
}
