//go:build !ios_extension

// MAIL-M10-01's tests (§15.7's search index row; R-MAIL-17, D-MAIL-16, I-19, R-CTX-35; FS-76's mail document cases at
// unit level): an ingest with the index on commits m/, i/ and the message's index delta in one push, the row of
// outside mail carrying the outside bit and a member's not; with the index off or outside the format2 gate it writes
// no index file and still writes i/; a vault canary, or one in any family but m/, never reaches an index file; a CUT
// landing between an ingest's build and its push gets the push 409 INDEX_EPOCH, and the push rebuilt from a fresh read
// leaves the erased message out; s/model is versionless in the gate, versioned in a locked mailbox and outside the
// gate; and a format-1 group inbox's first build covers its old mail, each message in its window or in all.
//
// They run on the evs stand-in with format 2 on, §11.8's 5d modeled and a committed push's staged segments and slots
// kept, in a mailbox, whose records are slot-keyed, and in a group inbox, a general repo laid out as one.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// One plan the client's hook saw: its paths, and the index files the in-ref writer added, by path.
type mailIndexTestPlan struct {
	paths      []string
	indexFiles map[string][]byte
	indexEpoch uint64
}

// A device ingesting one mail repo on the evs stand-in, format 2 on and 5d's epoch modeled, with the in-ref index
// writer on its client; every path a plan names is registered with the stand-in as the hook sees it.
type mailIndexTestWorld struct {
	t          *testing.T
	writer     *evsTestWriter
	kind       protocol.RepoKind
	deposits   *mailIngestTestRepo
	authority  *mailIngestTestAuthority
	receiverId Id
	ingestor   *MailIngestor

	plansLock sync.Mutex
	plans     []*mailIndexTestPlan
}

// A world whose repo is of kind: a mailbox, or a group inbox for a general repo. Its one device is the repo's admin, as
// each consented device files RepoAdmin for itself (§15.7's admins row), so its CUTs and settings count.
func newMailIndexTestWorld(t *testing.T, kind protocol.RepoKind) *mailIndexTestWorld {
	t.Helper()
	writer := newEvsTestWriter(t)
	func() {
		writer.world.config.stateLock.Lock()
		defer writer.world.config.stateLock.Unlock()
		repo := proto.Clone(writer.world.config.repo).(*protocol.AclRepo)
		repo.Kind = kind
		if kind == protocol.RepoKind_REPO_KIND_GENERAL {
			repo.Inbox = protocol.RepoInbox_REPO_INBOX_GROUP
		}
		signer := writer.world.signer.sidecarId.Bytes()
		repo.Admins = append(repo.Admins, &protocol.AclRepoAdminRow{SidecarId: signer, Signer: signer, At: 1})
		writer.world.config.repo = repo
	}()
	writer.server.format2 = true
	writer.server.indexEpochs = true
	writer.test.client.SetFormat2Source(func() bool { return true })
	writer.test.client.EnableFormat2Reader()
	world := &mailIndexTestWorld{
		t: t, writer: writer, kind: kind, deposits: newMailIngestTestRepo(),
		authority:  &mailIngestTestAuthority{classes: map[Id]MailDepositorClass{}, maySend: map[string]bool{}},
		receiverId: NewId(),
	}
	indexWriter, err := newIndexWriter(&indexWriterArgs{
		client: writer.test.client,
		store: func(repo *EvsRepo, refName []byte) indexRefStore {
			return newIndexEvsStore(repo, refName, false)
		},
		isAdmin: func(repoId Id) func(file *indexFileVersion) bool {
			return world.isAdmin
		},
		settings: DefaultIndexFormatSettings(),
		clock:    writer.test.clock,
		log:      NewNoopLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	writer.test.client.SetWritePlanHook(func(ctx context.Context, plan *EvsWritePlan) error {
		err := indexWriter.Prepare(ctx, plan)
		world.note(plan)
		return err
	})
	t.Cleanup(func() { writer.test.client.SetWritePlanHook(nil) })
	world.ingestor = newMailIngestor(writer.world.repoId, world.deposits, world.store(), &MailIngestArgs{
		SidecarId: writer.world.signer.sidecarId, Root: testMailIngestRoot, Authority: world.authority,
	})
	return world
}

// The world's one signer, this device, is the repo's admin.
func (self *mailIndexTestWorld) isAdmin(file *indexFileVersion) bool {
	return file.signerSidecarId == self.writer.world.signer.sidecarId
}

// A mail store over the device's repo.
func (self *mailIndexTestWorld) store() mailStore {
	return newMailEvsStore(self.writer.repo, nil, nil)
}

// Registers a plan's paths with the stand-in and keeps what the index writer added.
func (self *mailIndexTestWorld) note(plan *EvsWritePlan) {
	recorded := &mailIndexTestPlan{indexFiles: map[string][]byte{}, indexEpoch: plan.IndexEpoch}
	for _, planned := range plan.Paths {
		recorded.paths = append(recorded.paths, planned.Path)
		self.writer.server.know(planned.Path)
	}
	for _, write := range plan.indexWrites {
		self.writer.server.know(write.Path)
		if write.Content == nil {
			continue
		}
		content := make([]byte, write.Content.Size())
		if _, err := write.Content.ReadAt(content, 0); err != nil && !errors.Is(err, io.EOF) {
			self.t.Error(err)
		}
		recorded.indexFiles[write.Path] = content
	}
	self.plansLock.Lock()
	defer self.plansLock.Unlock()
	self.plans = append(self.plans, recorded)
}

// The plans the hook saw so far.
func (self *mailIndexTestWorld) seen() []*mailIndexTestPlan {
	self.plansLock.Lock()
	defer self.plansLock.Unlock()
	return slices.Clone(self.plans)
}

// A receiver's deposit of message and its m/ path, under the sealed receive time's month.
func (self *mailIndexTestWorld) deposit(message []byte) (*mailIngestTestDeposit, string) {
	self.t.Helper()
	deposit := self.deposits.deposit(self.receiverId, self.receiverId, testMailIngestPlaintext(self.t, message, testMailIngestTrailer(self.receiverId, message)))
	month := MailYearMonthOf(testMailIngestReceiveMillis)
	return deposit, MailMessagePath(month, deposit.id)
}

// One pass, which must not fail.
func (self *mailIndexTestWorld) ingest() *MailIngestPass {
	self.t.Helper()
	pass, err := self.ingestor.Ingest(context.Background())
	if err != nil {
		self.t.Fatal(err)
	}
	return pass
}

// path's doc_key on the main ref, chunk 0.
func (self *mailIndexTestWorld) docKey(path string) [indexIdByteCount]byte {
	self.t.Helper()
	repoKey, err := self.writer.gkm.EnsureWritable(context.Background(), self.writer.world.repoId)
	if err != nil {
		self.t.Fatal(err)
	}
	refKey, err := indexRefKey(repoKey)
	if err != nil {
		self.t.Fatal(err)
	}
	key, err := indexDocKey(refKey, self.writer.world.refId, []byte(path), 0)
	if err != nil {
		self.t.Fatal(err)
	}
	return key
}

// The ref version the newest version of path committed at, 0 where it does not stand.
func (self *mailIndexTestWorld) commitVersion(path string) uint64 {
	self.writer.world.stateLock.Lock()
	defer self.writer.world.stateLock.Unlock()
	state := self.writer.world.paths[path]
	if state == nil || state.removal != nil || state.versions[state.newest] == nil {
		return 0
	}
	return state.versions[state.newest].commitVersion
}

// How many versions of path the stand-in holds.
func (self *mailIndexTestWorld) versionCount(path string) int {
	self.writer.world.stateLock.Lock()
	defer self.writer.world.stateLock.Unlock()
	if state := self.writer.world.paths[path]; state != nil {
		return len(state.versions)
	}
	return 0
}

// The files that stand under prefix, in path order.
func (self *mailIndexTestWorld) files(prefix string) []string {
	self.writer.world.stateLock.Lock()
	defer self.writer.world.stateLock.Unlock()
	files := []string{}
	for path, state := range self.writer.world.paths {
		if !strings.HasPrefix(path, prefix) || state.removal != nil || state.versions[state.newest] == nil {
			continue
		}
		entry := &protocol.EvsEntryVersion{}
		if proto.Unmarshal(state.versions[state.newest].entryBytes, entry) == nil && entry.GetKind() == uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE) {
			files = append(files, path)
		}
	}
	slices.Sort(files)
	return files
}

// The ref's index read back through the verifying reader.
func (self *mailIndexTestWorld) view() *indexView {
	self.t.Helper()
	view, err := indexLoadView(context.Background(), &indexViewArgs{
		store: newIndexEvsStore(self.writer.repo, nil, false), repoId: self.writer.world.repoId, refId: self.writer.world.refId,
		repoKind: self.kind, isAdmin: self.isAdmin, settings: DefaultIndexFormatSettings(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return view
}

// Every entry of every writer's heads in the view's roots.
func testMailIndexHeadEntries(view *indexView) []*indexEntry {
	entries := []*indexEntry{}
	for _, root := range view.roots {
		for _, bucket := range root.buckets {
			for _, writer := range bucket.writers {
				for _, slot := range slices.Concat(writer.slots, writer.large) {
					entries = append(entries, slot.slot.entries...)
				}
			}
		}
	}
	return entries
}

// The entry of key among entries, nil for none.
func testMailIndexEntryOf(entries []*indexEntry, key [indexIdByteCount]byte) *indexEntry {
	for _, entry := range entries {
		if entry.key == key {
			return entry
		}
	}
	return nil
}

// Whether keys holds every key of text read as a body.
func testMailIndexKeysHold(t *testing.T, keys indexKeySet, text string) bool {
	t.Helper()
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		t.Fatal(err)
	}
	wanted, err := normalizer.documentKeys([]indexTextField{{number: indexFieldBody, text: strings.NewReader(text)}})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range wanted {
		if _, found := slices.BinarySearch(keys, key); !found {
			return false
		}
	}
	return 0 < len(wanted)
}

// §15.7's ingest row with the index on: one push writes m/, the i/ row and this device's head, whose one entry is the
// message's document at m/'s version, its row mail with subject, from and to, and outside, since the message came from
// outside the network; its key set holds the body's words. A second message, member-signed, is read back onto the
// same head in its own one push, its row without the outside bit; no entry is any i/ path's.
func TestMailIngestIndexCommitsTheDeltaWithTheMessageInOnePush(t *testing.T) {
	world := newMailIndexTestWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	_, outsidePath := world.deposit(testMailIngestMessage("Harbor lights", "The evening ferry leaves pier nine at dusk."))
	before, _ := world.writer.server.sentCounts()
	if pass := world.ingest(); pass.Ingested != 1 || pass.Consumed != 1 {
		t.Fatalf("pass %+v", pass)
	}
	if after, _ := world.writer.server.sentCounts(); after != before+1 {
		t.Fatalf("%d pushes for one message", after-before)
	}
	month := MailYearMonthOf(testMailIngestReceiveMillis)
	heads := world.files(indexFileModePrefix)
	commit := world.commitVersion(outsidePath)
	if len(heads) != 1 || commit == 0 || world.commitVersion(MailIndexPath(month, 0)) != commit || world.commitVersion(heads[0]) != commit {
		t.Fatalf("m/, i/ and the head %v are not one commit at %d", heads, commit)
	}
	entries := testMailIndexHeadEntries(world.view())
	entry := testMailIndexEntryOf(entries, world.docKey(outsidePath))
	if len(entries) != 1 || entry == nil || entry.kind != indexEntryFull || entry.version != world.writer.entry(t, outsidePath).GetVersion() {
		t.Fatalf("the head's entries %d, the message's %+v", len(entries), entry)
	}
	row := entry.row
	if row.docKind != IndexDocMail || row.locator != outsidePath || row.flags&indexRowOutside == 0 || row.flags&indexRowTainted != 0 ||
		row.fields[indexFieldSubject] != "Harbor lights" || !strings.Contains(row.fields[indexFieldFrom], "ada@sender.example") ||
		!strings.Contains(row.fields[indexFieldTo], testMailIngestRecipient) {
		t.Errorf("the row %+v", row)
	}
	if !testMailIndexKeysHold(t, entry.keys, "ferry leaves pier nine") {
		t.Error("the key set lacks the body's words")
	}

	// a member's same-network mail, which its signer may send as: one push, the same head read back, no outside bit
	memberDeviceId := NewId()
	world.authority.maySend[memberDeviceId.String()+" cy@acme.root.example"] = true
	message := []byte("From: Cy <cy@acme.root.example>\r\nTo: " + testMailIngestRecipient + "\r\nSubject: lunch plans\r\n\r\nnoon at the quay?\r\n")
	trailer := &protocol.MailDeposit{Version: mailFormatVersion, MailFrom: []byte("cy@acme.root.example"), Recipients: []string{testMailIngestRecipient}}
	member := world.deposits.deposit(memberDeviceId, memberDeviceId, testMailIngestPlaintext(t, message, trailer))
	memberPath := MailMessagePath(MailYearMonthOf(uint64(testMailIngestPushMillis)), member.id)
	before, _ = world.writer.server.sentCounts()
	if pass := world.ingest(); pass.Ingested != 1 {
		t.Fatalf("the member's pass %+v", pass)
	}
	if after, _ := world.writer.server.sentCounts(); after != before+1 {
		t.Fatalf("%d pushes for the member's message", after-before)
	}
	entries = testMailIndexHeadEntries(world.view())
	memberEntry := testMailIndexEntryOf(entries, world.docKey(memberPath))
	if len(entries) != 2 || testMailIndexEntryOf(entries, world.docKey(outsidePath)) == nil || memberEntry == nil {
		t.Fatalf("the head after the member's: %d entries", len(entries))
	}
	if memberEntry.row.flags&indexRowOutside != 0 || memberEntry.row.fields[indexFieldSubject] != "lunch plans" {
		t.Errorf("the member's row %+v", memberEntry.row)
	}
	for _, segment := range []string{MailIndexPath(month, 0), MailIndexPath(MailYearMonthOf(uint64(testMailIngestPushMillis)), 0)} {
		if testMailIndexEntryOf(entries, world.docKey(segment)) != nil {
			t.Error("an i/ segment is a document")
		}
	}
}

// i/ stays the message list whatever the index: outside the format2 gate, and with the index off by an admin's
// settings, an ingest writes m/ and its i/ row and no index file.
func TestMailIngestIndexOffWritesNoIndexFileAndStillWritesI(t *testing.T) {
	month := MailYearMonthOf(testMailIngestReceiveMillis)
	ungated := newMailIndexTestWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	ungated.writer.test.client.SetFormat2Source(func() bool { return false })
	_, path := ungated.deposit(testMailIngestMessage("Plain list", "kept in i/ alone"))
	if pass := ungated.ingest(); pass.Ingested != 1 {
		t.Fatalf("outside the gate: pass %+v", pass)
	}
	if files := ungated.files(indexFileModePrefix); len(files) != 0 || ungated.commitVersion(path) == 0 || ungated.commitVersion(MailIndexPath(month, 0)) == 0 {
		t.Fatalf("outside the gate: index files %v, m/ at %d, i/ at %d", files, ungated.commitVersion(path), ungated.commitVersion(MailIndexPath(month, 0)))
	}

	off := newMailIndexTestWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	settings, err := indexEncodeSettings(&protocol.IndexSettings{Off: true})
	if err != nil {
		t.Fatal(err)
	}
	settingsPath := indexNewPaths(false, indexRootNumber).settings()
	_, err = newIndexEvsStore(off.writer.repo, nil, false).Commit(context.Background(), &indexPush{
		pushId: NewId(), kind: indexPushIndex, signedTimeMs: off.writer.test.clock.Now().UnixMilli(),
		files: []*indexPushFile{{path: settingsPath, plaintext: settings}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, path = off.deposit(testMailIngestMessage("Off index", "nothing indexed here"))
	if pass := off.ingest(); pass.Ingested != 1 {
		t.Fatalf("with the index off: pass %+v", pass)
	}
	if files := off.files(indexFileModePrefix); !slices.Equal(files, []string{settingsPath}) || off.commitVersion(path) == 0 || off.commitVersion(MailIndexPath(month, 0)) == 0 {
		t.Fatalf("with the index off: index files %v, m/ at %d", files, off.commitVersion(path))
	}
}

// A mailbox's never row (§15.7's search index row, §11.14's never row): after one message is ingested, writes of
// vault/, o/, or/, forward, ra/, f/, r/, s/model and p/, each holding a canary, add no index file to their push; the
// ingest of a second message reads the head back and writes it holding the two messages' documents alone. No index
// file a plan carried, or the head as it stands, holds a canary or any of those paths' doc_keys.
func TestMailIngestIndexVaultCanaryNeverReachesAnIndexFile(t *testing.T) {
	world := newMailIndexTestWorld(t, protocol.RepoKind_REPO_KIND_MAILBOX)
	ctx := context.Background()
	canary := "canary-vault-7f3a9c2e-crimson-heron"
	_, firstPath := world.deposit(testMailIngestMessage("Receipt", "Thank you for your order of rope and tar."))
	if pass := world.ingest(); pass.Ingested != 1 {
		t.Fatalf("the first pass %+v", pass)
	}
	effectKey := sha256.Sum256([]byte("an outbox effect"))
	outboxPath, err := MailOutboxPath(effectKey[:])
	if err != nil {
		t.Fatal(err)
	}
	outcomePath, err := MailOutcomePath(effectKey[:])
	if err != nil {
		t.Fatal(err)
	}
	aliasPath, err := MailReverseAliasPath("q4zr8tokenalias")
	if err != nil {
		t.Fatal(err)
	}
	vaultEntry, err := proto.Marshal(&protocol.VaultEntry{Title: "bank " + canary, Username: "bo", Password: canary, Notes: "pin " + canary})
	if err != nil {
		t.Fatal(err)
	}
	month := MailYearMonthOf(testMailIngestReceiveMillis)
	never := []*mailStoreWrite{
		{Path: MailVaultPath(NewId()), Content: vaultEntry},
		{Path: outboxPath, Content: []byte("Subject: draft " + canary + "\r\n\r\n" + canary)},
		{Path: outcomePath, Content: []byte(canary)},
		{Path: MailForwardPath, Content: []byte(canary + "@forward.example")},
		{Path: aliasPath, Content: []byte(canary)},
		{Path: MailFlagPath(month, 0), Content: []byte(canary)},
		{Path: MailGroupRefPath(month, NewId()), Content: []byte(canary)},
		{Path: MailProverPath(NewId()), Content: []byte(canary)},
		// bytes no model parses, which the next ingest's scorer reads as an untrained filter
		{Path: MailSpamModelPath, Content: []byte(canary)},
	}
	for _, write := range never {
		if _, err := world.store().Write(ctx, []*mailStoreWrite{write}); err != nil {
			t.Fatal(err)
		}
		if plans := world.seen(); len(plans[len(plans)-1].indexFiles) != 0 {
			t.Fatal("a write of the never row's families carried an index file")
		}
	}
	_, secondPath := world.deposit(testMailIngestMessage("Shipping", "Your rope ships on the morning tide."))
	if pass := world.ingest(); pass.Ingested != 1 {
		t.Fatalf("the second pass %+v", pass)
	}
	neverKeys := map[[indexIdByteCount]byte]bool{}
	for _, write := range never {
		neverKeys[world.docKey(write.Path)] = true
	}
	for _, plan := range world.seen() {
		for path, content := range plan.indexFiles {
			if bytes.Contains(content, []byte(canary)) {
				t.Fatal("an index file holds the canary")
			}
			parsed, ok := indexParsePath(path, false)
			if !ok || (parsed.kind != indexPathSlot && parsed.kind != indexPathLargeEntry) {
				continue
			}
			sum := sha256.Sum256(content)
			slot, err := indexDecodeSlot(content, sum[:], false, DefaultIndexFormatSettings())
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range slot.entries {
				if neverKeys[entry.key] || (entry.row != nil && !strings.HasPrefix(entry.row.locator, "m/")) {
					t.Fatalf("an index entry of the never row: %+v", entry.row)
				}
			}
		}
	}
	entries := testMailIndexHeadEntries(world.view())
	if len(entries) != 2 || testMailIndexEntryOf(entries, world.docKey(firstPath)) == nil || testMailIndexEntryOf(entries, world.docKey(secondPath)) == nil {
		t.Fatalf("the head holds %d entries, not the two messages'", len(entries))
	}
}

// §11.14's epoch row through ingest: a CUT listing an earlier message lands after the ingest of a later one built its
// push and before evs checks it, so the push, naming the epoch before the CUT, is refused 409 INDEX_EPOCH; the sender
// plans it again from a fresh read, and the push that commits names the CUT's epoch and carries the head without the
// erased message, the later one's document in it and its m/ written once.
func TestMailIngestIndexCutBetweenBuildAndPushRebuildsWithoutTheDocument(t *testing.T) {
	world := newMailIndexTestWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	ctx := context.Background()
	_, erasedPath := world.deposit(testMailIngestMessage("Tide tables", "high water at six"))
	if pass := world.ingest(); pass.Ingested != 1 {
		t.Fatalf("the first pass %+v", pass)
	}
	erasedVersion := world.writer.entry(t, erasedPath).GetVersion()
	eraser, err := indexNewEraser(&indexEraserArgs{
		store: newIndexEvsStore(world.writer.repo, nil, false), repoId: world.writer.world.repoId, refId: world.writer.world.refId,
		repoKind: world.kind, isAdmin: world.isAdmin, format: DefaultIndexFormatSettings(),
		eraser: world.writer.world.signer.sidecarId, clock: world.writer.test.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, laterPath := world.deposit(testMailIngestMessage("Ferry times", "the late boat sails at ten"))
	var cut *IndexCutResult
	var cutErr error
	world.writer.server.raceNextPush(func() {
		cut, cutErr = eraser.Cut(ctx, &IndexCutArgs{
			ErasureId: NewId(), Documents: []*IndexCutDocument{{Key: world.docKey(erasedPath), Version: erasedVersion}},
		})
	})
	plansBefore := len(world.seen())
	before, _ := world.writer.server.sentCounts()
	if pass := world.ingest(); pass.Ingested != 1 || pass.Present != 0 {
		t.Fatalf("the racing pass %+v", pass)
	}
	if cutErr != nil || cut == nil || !cut.Pushed {
		t.Fatalf("the CUT: %+v %v", cut, cutErr)
	}
	// the ingest's refused push, the CUT's, the ingest's rebuilt one
	if after, _ := world.writer.server.sentCounts(); after != before+3 {
		t.Fatalf("%d pushes, not the refused one, the CUT and the rebuilt one", after-before)
	}
	plans := world.seen()[plansBefore:]
	if len(plans) != 3 || plans[0].indexEpoch != 0 || plans[2].indexEpoch != cut.Version || len(plans[2].indexFiles) == 0 {
		t.Fatalf("the plans' epochs: %d plans", len(plans))
	}
	view := world.view()
	if view.head.indexEpoch != cut.Version {
		t.Fatalf("the head's index_epoch %d, the CUT's %d", view.head.indexEpoch, cut.Version)
	}
	entries := testMailIndexHeadEntries(view)
	if testMailIndexEntryOf(entries, world.docKey(erasedPath)) != nil {
		t.Fatal("the rebuilt head still holds the erased message")
	}
	if testMailIndexEntryOf(entries, world.docKey(laterPath)) == nil {
		t.Fatal("the rebuilt head lacks the later message")
	}
	heads := world.files(indexFileModePrefix + "i1/")
	if world.versionCount(laterPath) != 1 || len(heads) != 1 || world.commitVersion(heads[0]) != world.commitVersion(laterPath) {
		t.Fatalf("the later message, %d versions, and the head %v: not one commit", world.versionCount(laterPath), heads)
	}
}

// One teach step of s/model's versioning: the gate and the lock as it runs, the verdict's move, the versioning its
// write must take.
type mailSpamVersioningStep struct {
	gate   bool
	locked bool
	before MailSpamClass
	after  MailSpamClass
	want   uint32
}

// Runs steps on a fresh group inbox's s/model, each a teach that must write the next version at its versioning; the
// model then holds the steps' last verdict alone.
func testMailSpamVersioning(t *testing.T, steps []mailSpamVersioningStep) {
	t.Helper()
	world := newMailIndexTestWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	ctx := context.Background()
	gate := false
	world.writer.test.client.SetFormat2Source(func() bool { return gate })
	world.writer.server.know(MailSpamModelPath)
	parsed, err := MailParseMessage(bytes.NewReader(testMailIngestMessage("Prize claim", "claim your prize now")), DefaultMailParseSettings())
	if err != nil {
		t.Fatal(err)
	}
	scorer := NewMailSpamScorer(world.store(), DefaultMailSpamSettings())
	lock := func(locked bool) {
		world.writer.world.config.stateLock.Lock()
		defer world.writer.world.config.stateLock.Unlock()
		repo := proto.Clone(world.writer.world.config.repo).(*protocol.AclRepo)
		repo.Lock = protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_UNSPECIFIED
		if locked {
			repo.Lock = protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED
		}
		world.writer.world.config.repo = repo
	}
	for index, step := range steps {
		gate = step.gate
		lock(step.locked)
		if err := scorer.Teach(ctx, parsed, step.before, step.after); err != nil {
			t.Fatalf("step %d: %v", index, err)
		}
		entry := world.writer.entry(t, MailSpamModelPath)
		if entry.GetVersioning() != step.want || entry.GetVersion() != uint64(index+1) {
			t.Errorf("step %d: s/model at version %d, versioning %d, want %d", index, entry.GetVersion(), entry.GetVersioning(), step.want)
		}
	}
	model, _, err := scorer.read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	last := steps[len(steps)-1].after
	spamCount, hamCount := model.MessageCounts()
	if (last == MailSpamClassSpam) != (spamCount == 1) || (last == MailSpamClassNotSpam) != (hamCount == 1) || 1 < spamCount+hamCount {
		t.Errorf("the model learned %d spam and %d not-spam, not the last verdict alone", spamCount, hamCount)
	}
}

// §15.7's s/model row: a format-1 writer's model is versioned; once the format2 gate opens, its next write turns it
// versionless, and every write after keeps it so, each teach reading the versionless model back.
func TestMailSpamModelTurnsVersionlessInTheGate(t *testing.T) {
	kept, versionless := uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT), uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)
	testMailSpamVersioning(t, []mailSpamVersioningStep{
		{gate: false, before: MailSpamClassNone, after: MailSpamClassSpam, want: kept},
		{gate: true, before: MailSpamClassSpam, after: MailSpamClassNotSpam, want: versionless},
		{gate: true, before: MailSpamClassNotSpam, after: MailSpamClassSpam, want: versionless},
	})
}

// §15.7's s/model row and §11.7's refused row: in a locked mailbox the model is written versioned, and versionless
// again at its first write once the lock is lifted.
func TestMailSpamModelIsVersionedInALockedRepo(t *testing.T) {
	kept, versionless := uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT), uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)
	testMailSpamVersioning(t, []mailSpamVersioningStep{
		{gate: true, locked: true, before: MailSpamClassNone, after: MailSpamClassSpam, want: kept},
		{gate: true, locked: true, before: MailSpamClassSpam, after: MailSpamClassNotSpam, want: kept},
		{gate: true, before: MailSpamClassNotSpam, after: MailSpamClassSpam, want: versionless},
	})
}

// §15.7's v1 row and §11.14's on row, FS-72's first build for mail: a mailbox's mail taken under format 1 is in no
// index; the first build, on a device holding the mail, writes the root whole from it, each message in the window of
// the push that wrote it (the build's own, the one before) or in all, every row outside, and nothing of a vault entry
// beside the mail. An ingest after it carries its own delta.
func TestMailIndexFirstBuildCoversAFormat1MailboxsOldMail(t *testing.T) {
	testMailIndexFirstBuildOfOldMail(t, protocol.RepoKind_REPO_KIND_MAILBOX)
}

// The same for a group inbox, a general repo laid out as a mailbox.
func TestMailIndexFirstBuildCoversAFormat1GroupInboxsOldMail(t *testing.T) {
	testMailIndexFirstBuildOfOldMail(t, protocol.RepoKind_REPO_KIND_GENERAL)
}

// A first build of a repo of kind, a mailbox or a group inbox for a general repo: see the tests above.
func testMailIndexFirstBuildOfOldMail(t *testing.T, kind protocol.RepoKind) {
	world := newMailIndexTestWorld(t, kind)
	ctx := context.Background()
	gate := false
	world.writer.test.client.SetFormat2Source(func() bool { return gate })
	clock := world.writer.test.clock
	startDay := indexDayOf(clock.Now().UnixMilli())
	windowStart := (startDay + 200) / 30 * 30
	ingestAt := func(day uint32, subject string, body string) string {
		t.Helper()
		clock.advance(time.Duration(day-indexDayOf(clock.Now().UnixMilli())) * 24 * time.Hour)
		_, path := world.deposit(testMailIngestMessage(subject, body))
		if pass := world.ingest(); pass.Ingested != 1 {
			t.Fatalf("%s: pass %+v", subject, pass)
		}
		return path
	}
	old := ingestAt(startDay, "Old ledger", "turnips counted in the spring")
	mid := ingestAt(windowStart-10, "Radish report", "radishes in the window before")
	recent := ingestAt(windowStart+2, "Parsnip news", "parsnips in this window")
	canary := "canary-build-4b1d-grey-plover"
	besidePath := MailVaultPath(NewId())
	world.writer.server.know(besidePath)
	if _, err := world.store().Write(ctx, []*mailStoreWrite{{Path: besidePath, Content: []byte(canary)}}); err != nil {
		t.Fatal(err)
	}
	if files := world.files(indexFileModePrefix); len(files) != 0 {
		t.Fatalf("format 1 wrote index files %v", files)
	}

	gate = true
	result, err := MailIndexFirstBuild(ctx, &MailIndexBuildArgs{Repo: world.writer.repo})
	if err != nil {
		t.Fatal(err)
	}
	if result.Version == 0 || result.Skipped != "" || result.MessageCount != 3 || result.EntryCount != 3 || result.LeftOutCount != 0 {
		t.Fatalf("the build %+v", result)
	}
	view := world.view()
	root := view.writeRoot()
	if len(root.buckets) != 2 || root.buckets[0].window.startDay != windowStart-30 || root.buckets[1].window.startDay != windowStart {
		t.Fatalf("buckets %v", root.bucketWindows())
	}
	if !testShardsHold(t, view, root.buckets[0].shards, world.docKey(mid)) || !testShardsHold(t, view, root.buckets[1].shards, world.docKey(recent)) ||
		!testShardsHold(t, view, root.allShards, world.docKey(old)) {
		t.Fatal("a message is not in its window's shards or in all")
	}
	shards := slices.Concat(root.buckets[0].shards, root.buckets[1].shards, root.allShards)
	decoded, err := indexDecodeBucketShards(ctx, view, shards)
	if err != nil {
		t.Fatal(err)
	}
	documentCount := 0
	for _, shard := range decoded {
		for _, document := range shard.documents {
			documentCount += 1
			if document.row.flags&indexRowOutside == 0 || document.row.flags&indexRowTainted != 0 || !strings.HasPrefix(document.row.locator, "m/") {
				t.Errorf("a built row %+v", document.row)
			}
			if document.key == world.docKey(besidePath) {
				t.Error("the build indexed a vault file")
			}
		}
	}
	if documentCount != 3 {
		t.Fatalf("%d documents in the shards", documentCount)
	}
	for _, plan := range world.seen() {
		for _, content := range plan.indexFiles {
			if bytes.Contains(content, []byte(canary)) {
				t.Fatal("an index file holds the canary")
			}
		}
	}

	// from the build on, an ingest's push carries its own delta
	newer := ingestAt(windowStart+3, "Beet notes", "beets after the build")
	if entry := testMailIndexEntryOf(testMailIndexHeadEntries(world.view()), world.docKey(newer)); entry == nil {
		t.Fatal("an ingest after the build carried no delta")
	}
}
