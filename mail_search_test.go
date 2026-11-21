//go:build !sidecar_http && !js && !ios_extension

// MAIL-M10-03's mail search: the join's answers from f/ and i/ and what it reads when; a spam or trashed message
// absent from a search unless asked, with nothing of either in the index; a phone's hit confirmed by i/'s snippet and
// one left possible; MailClient.Search's request over the mailbox, and that only "search more" may leave the device;
// a mailbox refused on every indexer but its owner's; and a query that shows in nothing a server is asked. IMAP
// SEARCH on the engine is in mail_imap_search_test.go.

package sidecar

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A mailStore that keeps every path it is asked for: what evs would see of a device reading through it.
type mailSearchTestCapture struct {
	mailStore
	stateLock sync.Mutex
	asked     []string
}

func (self *mailSearchTestCapture) Read(ctx context.Context, path string, maxByteCount int) ([]byte, uint64, error) {
	self.note(path)
	return self.mailStore.Read(ctx, path, maxByteCount)
}

func (self *mailSearchTestCapture) List(ctx context.Context, directory string) ([]string, error) {
	self.note(directory)
	return self.mailStore.List(ctx, directory)
}

func (self *mailSearchTestCapture) note(path string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.asked = append(self.asked, path)
}

func (self *mailSearchTestCapture) taken() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	asked := self.asked
	self.asked = nil
	return asked
}

// A join over mailbox as repo mailboxId, with the given group stores, on clock.
func testMailSearchJoin(t *testing.T, mailboxId Id, mailbox mailStore, groups map[Id]mailStore, settings *MailSearchSettings, clock Clock) *MailSearchJoin {
	t.Helper()
	join, err := NewMailSearchJoin(&MailSearchJoinArgs{
		View: &MailViewArgs{
			MailboxId: mailboxId,
			Mailbox:   mailbox,
			Groups: func(ctx context.Context, repoId Id) (mailStore, error) {
				if group, ok := groups[repoId]; ok {
					return group, nil
				}
				return nil, ErrEvsPathAbsent
			},
			Settings: DefaultMailStoreSettings(),
		},
		Settings: settings,
		Clock:    clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return join
}

// An entry with a spam score and a snippet.
func testMailSearchEntry(n uint64, timeMillis uint64, spamScore uint32, snippet string) *protocol.IndexEntry {
	entry := testMailIndexEntry(n, timeMillis)
	entry.SpamScore = spamScore
	entry.Snippet = snippet
	return entry
}

// The join answers what the message list decides: seen, flagged, trash and labels from f/, spam from the person's
// verdict, else the score against the threshold; a group's message in its group repo; and nothing of a message it
// holds no entry for, or asked of the wrong repo. It reads at Sync alone, again once a write is said or its interval
// passes, and past its bound the oldest months join as unknown.
func TestMailSearchJoinAnswersFromFlagsAndScores(t *testing.T) {
	ctx := context.Background()
	mailbox := newMailTestStore()
	group := newMailTestStore()
	month, older := MailYearMonth(202611), MailYearMonth(202610)
	threshold := DefaultMailStoreSettings().SpamScoreThreshold
	testMailAppend(t, mailbox,
		testMailSearchEntry(1, testMailDayMillis(month, 1), 0, ""),
		testMailSearchEntry(2, testMailDayMillis(month, 2), threshold, ""),
		testMailSearchEntry(3, testMailDayMillis(month, 3), 0, ""),
		testMailSearchEntry(4, testMailDayMillis(month, 4), threshold+1, ""),
		testMailSearchEntry(5, testMailDayMillis(month, 5), 0, ""),
		testMailSearchEntry(6, testMailDayMillis(older, 6), threshold, ""),
	)
	testMailAppend(t, group, testMailSearchEntry(10, testMailDayMillis(month, 7), 0, ""))
	reference, err := proto.Marshal(&protocol.MailGroupRef{RepoId: testMailGroupId.Bytes(), MessageId: testMailId(10).Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	mailbox.put(MailGroupRefPath(month, testMailId(10)), reference)
	testMailFlag(t, mailbox, 1,
		&MailFlagChange{Month: month, MessageId: testMailId(3), Kind: protocol.MailFlagKind_MAIL_FLAG_TRASH, Set: true},
		&MailFlagChange{Month: month, MessageId: testMailId(4), Kind: protocol.MailFlagKind_MAIL_FLAG_LABEL, Label: MailLabelNotSpam, Set: true},
		&MailFlagChange{Month: month, MessageId: testMailId(5), Kind: protocol.MailFlagKind_MAIL_FLAG_SEEN, Set: true},
		&MailFlagChange{Month: month, MessageId: testMailId(5), Kind: protocol.MailFlagKind_MAIL_FLAG_FLAGGED, Set: true},
		&MailFlagChange{Month: month, MessageId: testMailId(5), Kind: protocol.MailFlagKind_MAIL_FLAG_LABEL, Label: "work", Set: true},
		&MailFlagChange{Month: month, MessageId: testMailId(10), Kind: protocol.MailFlagKind_MAIL_FLAG_SEEN, Set: true},
	)
	clock := &mailTestClock{now: time.UnixMilli(int64(testMailDayMillis(month, 20)))}
	join := testMailSearchJoin(t, testMailMailboxId, mailbox, map[Id]mailStore{testMailGroupId: group}, nil, clock)
	flagsOf := func(repoId Id, in MailYearMonth, n uint64) *SearchMailFlags {
		t.Helper()
		flags, held, err := join.MailFlags(ctx, repoId, in, testMailId(n))
		if err != nil {
			t.Fatal(err)
		}
		if !held {
			return nil
		}
		return flags
	}
	if flagsOf(testMailMailboxId, month, 2) != nil {
		t.Fatal("a join that never synced answered")
	}
	if join.pinRepo(testMailMailboxId) != nil {
		t.Fatal("unopened mailbox accepted as a search view")
	}
	if err := join.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	pinned := join.pinRepo(testMailMailboxId)
	if pinned == nil || !pinned() || join.pinRepo(NewId()) != nil {
		t.Fatal("mail scope must follow its held flag table")
	}
	reads := mailbox.readCount + group.readCount
	if flags := flagsOf(testMailMailboxId, month, 1); flags == nil || flags.Spam || flags.Trash || flags.Seen || flags.Flagged || len(flags.Labels) != 0 {
		t.Errorf("a plain message: %+v", flags)
	}
	if flags := flagsOf(testMailMailboxId, month, 2); flags == nil || !flags.Spam || flags.Trash {
		t.Errorf("a message at the threshold: %+v", flags)
	}
	if flags := flagsOf(testMailMailboxId, month, 3); flags == nil || !flags.Trash || flags.Spam {
		t.Errorf("a trashed message: %+v", flags)
	}
	if flags := flagsOf(testMailMailboxId, month, 4); flags == nil || flags.Spam {
		t.Errorf("a message the person said is not spam: %+v", flags)
	}
	if flags := flagsOf(testMailMailboxId, month, 5); flags == nil || !flags.Seen || !flags.Flagged || !slices.Contains(flags.Labels, "work") {
		t.Errorf("a seen, flagged and labeled message: %+v", flags)
	}
	if flags := flagsOf(testMailMailboxId, older, 6); flags == nil || !flags.Spam {
		t.Errorf("an older month's message: %+v", flags)
	}
	if flags := flagsOf(testMailGroupId, month, 10); flags == nil || !flags.Seen {
		t.Errorf("a group's message: %+v", flags)
	}
	// the wrong repo, the wrong month and an id it holds no entry for are unknown
	if flagsOf(testMailMailboxId, month, 10) != nil || flagsOf(testMailGroupId, month, 2) != nil || flagsOf(testMailMailboxId, older, 2) != nil || flagsOf(testMailMailboxId, month, 99) != nil {
		t.Error("a message the table does not hold as asked was answered")
	}
	if repos := join.Repos(); !slices.Equal(repos, []Id{testMailMailboxId, testMailGroupId}) {
		t.Errorf("the repos %v", repos)
	}
	if mailbox.readCount+group.readCount != reads {
		t.Fatal("an answer read a store")
	}

	// a write the join does not hear of shows only once its interval passes; one it hears of at the next sync
	testMailFlag(t, mailbox, 1, &MailFlagChange{Month: month, MessageId: testMailId(1), Kind: protocol.MailFlagKind_MAIL_FLAG_TRASH, Set: true})
	reads = mailbox.readCount + group.readCount
	if err := join.Sync(ctx); err != nil || mailbox.readCount+group.readCount != reads || flagsOf(testMailMailboxId, month, 1).Trash {
		t.Fatalf("a sync inside the interval read again: %v", err)
	}
	join.Invalidate()
	if pinned() {
		t.Fatal("an invalidated flag table retained its search hits")
	}
	if err := join.Sync(ctx); err != nil || !flagsOf(testMailMailboxId, month, 1).Trash {
		t.Fatalf("a sync after a write was said: %v", err)
	}
	if pinned() || join.pinRepo(testMailMailboxId) == nil {
		t.Fatal("refresh must establish new hits without reopening the previous table")
	}
	testMailFlag(t, mailbox, 1, &MailFlagChange{Month: month, MessageId: testMailId(1), Kind: protocol.MailFlagKind_MAIL_FLAG_TRASH, Set: false})
	clock.now = clock.now.Add(DefaultMailSearchSettings().RefreshInterval)
	if err := join.Sync(ctx); err != nil || flagsOf(testMailMailboxId, month, 1).Trash {
		t.Fatalf("a sync past the interval: %v", err)
	}

	// past the bound the oldest month is left out, and joins as unknown
	bounded := testMailSearchJoin(t, testMailMailboxId, mailbox, map[Id]mailStore{testMailGroupId: group}, &MailSearchSettings{MessageMaxCount: 6}, clock)
	if err := bounded.Sync(ctx); err != nil || bounded.LeftOut() != 1 {
		t.Fatalf("the bounded sync: %v, %d left out", err, bounded.LeftOut())
	}
	if _, held, _ := bounded.MailFlags(ctx, testMailMailboxId, older, testMailId(6)); held {
		t.Error("a message past the bound was answered")
	}
	if _, held, _ := bounded.MailFlags(ctx, testMailMailboxId, month, testMailId(2)); !held {
		t.Error("a message inside the bound was not answered")
	}

	// a sync that cannot read keeps the table it had and says so
	failing := &mailSearchTestFailingStore{mailStore: mailbox}
	kept := testMailSearchJoin(t, testMailMailboxId, failing, nil, nil, clock)
	if err := kept.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	failing.err = errors.New("the mailbox cannot be read")
	kept.Invalidate()
	if err := kept.Sync(ctx); !errors.Is(err, failing.err) {
		t.Fatalf("a failed sync: %v", err)
	}
	if _, held, _ := kept.MailFlags(ctx, testMailMailboxId, month, testMailId(2)); !held {
		t.Error("a failed sync dropped the table")
	}
	if _, err := NewMailSearchJoin(&MailSearchJoinArgs{}); err == nil {
		t.Error("a join over no view")
	}
	if _, err := NewMailSearchJoin(&MailSearchJoinArgs{View: kept.source, Settings: &MailSearchSettings{}}); err == nil {
		t.Error("a join with no bound")
	}
}

// A mailStore whose reads fail once err is set.
type mailSearchTestFailingStore struct {
	mailStore
	err error
}

func (self *mailSearchTestFailingStore) List(ctx context.Context, directory string) ([]string, error) {
	if self.err != nil {
		return nil, self.err
	}
	return self.mailStore.List(ctx, directory)
}

// A mail document of the engine world: its subject in the row, its body in its key set alone.
func testMailSearchDocument(t *testing.T, index int, month MailYearMonth, n uint64, subject string, body string) *indexPendingDocument {
	t.Helper()
	document := testEngineDocument(t, "mail search", index, 1, MailMessagePath(month, testMailId(n)), subject+"\n"+body)
	document.row.docKind = indexDocMail
	document.row.fields[indexFieldTitle] = ""
	document.row.fields[indexFieldSubject] = subject
	return document
}

// An engine over world's cache with mail's join and display.
func testMailSearchEngine(t *testing.T, world *testEngineWorld, join SearchJoinSource, display SearchDisplaySource) *testEngineWorld {
	t.Helper()
	args := &SearchEngineArgs{
		Settings: world.sync.cache.settings, Cache: world.sync.cache.cache, Sync: world.sync.sync, Scope: world.scope,
		Gkm: &evsTestReadGkm{newest: 1}, Clock: world.sync.cache.clock, Log: NewNoopLogger(), Join: join,
	}
	if display != nil {
		args.Display = func(repoId Id, refId Id) SearchDisplaySource { return display }
	}
	engine, err := NewSearchEngine(args)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	return &testEngineWorld{sync: world.sync, scope: world.scope, engine: engine}
}

// A spam or trashed message is absent from a search unless the search asks for it, by mail's join alone: the index's
// rows hold a message's subject and nothing of either, the same row whatever its flags. No search reads the mailbox
// or evs, and the query shows in nothing either was asked.
func TestMailSearchLeavesOutSpamAndTrashUnlessAsked(t *testing.T) {
	ctx := context.Background()
	month := MailYearMonth(202611)
	threshold := DefaultMailStoreSettings().SpamScoreThreshold
	spam := testMailSearchDocument(t, 1, month, 1, "quarterly invoice from the vendor", "pay now")
	trash := testMailSearchDocument(t, 2, month, 2, "invoice reminder, already paid", "thanks")
	plain := testMailSearchDocument(t, 3, month, 3, "the invoice for the harbor repairs", "attached")
	world := newTestEngineWorld(t, nil, spam, trash, plain)
	for _, document := range []*indexPendingDocument{spam, trash, plain} {
		for field, value := range document.row.fields {
			if field != indexFieldSubject && value != "" {
				t.Fatalf("a mail row holds field %d", field)
			}
		}
	}
	mailbox := &mailSearchTestCapture{mailStore: newMailTestStore()}
	testMailAppend(t, mailbox,
		testMailSearchEntry(1, testMailDayMillis(month, 1), threshold, ""),
		testMailSearchEntry(2, testMailDayMillis(month, 2), 0, ""),
		testMailSearchEntry(3, testMailDayMillis(month, 3), 0, ""),
	)
	testMailFlag(t, mailbox, 1, &MailFlagChange{Month: month, MessageId: testMailId(2), Kind: protocol.MailFlagKind_MAIL_FLAG_TRASH, Set: true})
	join := testMailSearchJoin(t, world.sync.repoId, mailbox, nil, nil, &mailTestClock{now: time.UnixMilli(int64(testMailDayMillis(month, 20)))})
	if err := join.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	// what the sync asked of the mailbox is the same whatever is searched after it: it names months, never a message
	for _, asked := range mailbox.taken() {
		if strings.Contains(asked, evsTokenEncoding.EncodeToString(testMailId(1).Bytes())) {
			t.Fatalf("the sync asked for a message: %s", asked)
		}
	}
	joined := testMailSearchEngine(t, world, join, nil)
	fetchesBefore := len(world.sync.source.fetched())
	path := func(n uint64) string { return MailMessagePath(month, testMailId(n)) }
	cases := []struct {
		label   string
		request *SearchRequest
		want    []string
	}{
		{label: "the default", request: &SearchRequest{Text: "invoice", Scope: SearchLatest}, want: []string{path(3)}},
		{label: "spam asked", request: &SearchRequest{Text: "invoice", Scope: SearchLatest, IncludeSpam: true}, want: []string{path(1), path(3)}},
		{label: "trash asked", request: &SearchRequest{Text: "invoice", Scope: SearchLatest, IncludeTrash: true}, want: []string{path(2), path(3)}},
		{label: "both asked", request: &SearchRequest{Text: "invoice", Scope: SearchLatest, IncludeSpam: true, IncludeTrash: true}, want: []string{path(1), path(2), path(3)}},
	}
	for _, c := range cases {
		hits, _ := joined.all(t, c.request)
		want := slices.Clone(c.want)
		slices.Sort(want)
		if paths := testHitPaths(hits); !slices.Equal(paths, want) {
			t.Errorf("%s: %v", c.label, paths)
		}
	}
	if asked := mailbox.taken(); len(asked) != 0 {
		t.Fatalf("a search read the mailbox: %d reads", len(asked))
	}
	if len(world.sync.source.fetched()) != fetchesBefore {
		t.Fatal("a search read evs")
	}
}

// No query in a server capture: a search for a canary no document holds, and one a message holds, leave the canary
// in nothing the mailbox's stores or the index's source were asked for, the join's sync before them included.
func TestMailSearchQueryNeverShowsInWhatAServerIsAsked(t *testing.T) {
	ctx := context.Background()
	month := MailYearMonth(202611)
	const canary = "zebracanary"
	world := newTestEngineWorld(t, nil,
		testMailSearchDocument(t, 1, month, 1, "about the "+canary, "a body"),
		testMailSearchDocument(t, 2, month, 2, "something else", "another body"),
	)
	mailbox := &mailSearchTestCapture{mailStore: newMailTestStore()}
	testMailAppend(t, mailbox, testMailSearchEntry(1, testMailDayMillis(month, 1), 0, ""), testMailSearchEntry(2, testMailDayMillis(month, 2), 0, ""))
	mailbox.taken()
	join := testMailSearchJoin(t, world.sync.repoId, mailbox, nil, nil, &mailTestClock{now: time.UnixMilli(int64(testMailDayMillis(month, 20)))})
	joined := testMailSearchEngine(t, world, join, &SearchMailDisplay{View: func(repoId Id) *MailView { return nil }})
	fetchesBefore := len(world.sync.source.fetched())
	for _, text := range []string{canary, canary + " nowhere"} {
		if err := join.Sync(ctx); err != nil {
			t.Fatal(err)
		}
		hits, _ := joined.all(t, &SearchRequest{Text: text, Scope: SearchLatest, IncludeSpam: true, IncludeTrash: true})
		if text == canary && len(hits) != 1 {
			t.Fatalf("%d hits for the canary", len(hits))
		}
	}
	for _, asked := range append(mailbox.taken(), world.sync.source.fetched()[fetchesBefore:]...) {
		if strings.Contains(strings.ToLower(asked), canary) || strings.Contains(asked, evsTokenEncoding.EncodeToString(testMailId(1).Bytes())) {
			t.Fatalf("a server was asked for %q", asked)
		}
	}
}

// A phone holds no text: a hit whose i/ snippet holds the query is confirmed and shows the snippet, one whose text
// alone holds it is a possible match and labeled so, and neither is given as verified.
func TestMailSearchConfirmsByTheSnippetAndLeavesTheRestPossible(t *testing.T) {
	month := MailYearMonth(202611)
	world := newTestEngineWorld(t, nil,
		testMailSearchDocument(t, 1, month, 1, "notes from tuesday", "we agreed on the lighthouse budget and more"),
		testMailSearchDocument(t, 2, month, 2, "meeting moved", "long preamble first, the lighthouse comes much later"),
		testMailSearchDocument(t, 3, month, 3, "the lighthouse visit", "see you there"),
	)
	mailbox := newMailTestStore()
	testMailAppend(t, mailbox,
		testMailSearchEntry(1, testMailDayMillis(month, 1), 0, "we agreed on the lighthouse budget"),
		testMailSearchEntry(2, testMailDayMillis(month, 2), 0, "long preamble first"),
		testMailSearchEntry(3, testMailDayMillis(month, 3), 0, "see you there"),
	)
	view := NewMailView(&MailViewArgs{MailboxId: world.sync.repoId, Mailbox: mailbox, Settings: DefaultMailStoreSettings()})
	display := &SearchMailDisplay{View: func(repoId Id) *MailView {
		if repoId != world.sync.repoId {
			return nil
		}
		return view
	}}
	phone := testMailSearchEngine(t, world, nil, display)
	hits, _ := phone.all(t, &SearchRequest{Text: "lighthouse", Scope: SearchLatest})
	states := map[string]SearchHitState{}
	snippets := map[string]string{}
	for _, hit := range hits {
		states[hit.Path] = hit.State
		snippets[hit.Path] = hit.Snippet
	}
	path := func(n uint64) string { return MailMessagePath(month, testMailId(n)) }
	if len(hits) != 3 || states[path(1)] != SearchConfirmed || states[path(2)] != SearchPossible || states[path(3)] != SearchConfirmed {
		t.Fatalf("the states %v", states)
	}
	if !strings.Contains(snippets[path(1)], "lighthouse budget") || snippets[path(2)] != "" && strings.Contains(snippets[path(2)], "lighthouse") {
		t.Fatalf("the snippets %v", snippets)
	}
}

// A search stream of fixed pages, and what was asked of it.
type mailSearchTestEngine struct {
	stateLock sync.Mutex
	requests  []*SearchRequest
	pages     [][]SearchHit
	progress  SearchProgress
	err       error
	closed    int
}

func (self *mailSearchTestEngine) search(ctx context.Context, request *SearchRequest) (*SearchStream, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	copied := *request
	self.requests = append(self.requests, &copied)
	if self.err != nil {
		return nil, self.err
	}
	return NewSearchStream(&mailSearchTestStream{engine: self, pages: slices.Clone(self.pages), progress: self.progress}), nil
}

func (self *mailSearchTestEngine) last() *SearchRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.requests[len(self.requests)-1]
}

type mailSearchTestStream struct {
	engine   *mailSearchTestEngine
	pages    [][]SearchHit
	progress SearchProgress
}

func (self *mailSearchTestStream) Next() ([]SearchHit, SearchProgress, bool, error) {
	if len(self.pages) == 0 {
		return nil, self.progress, true, nil
	}
	page := self.pages[0]
	self.pages = self.pages[1:]
	return page, self.progress, len(self.pages) == 0, nil
}

func (self *mailSearchTestStream) Close() {
	self.engine.stateLock.Lock()
	defer self.engine.stateLock.Unlock()
	self.engine.closed += 1
}

// MailClient.Search asks the bound engine for the member's mailbox, spam and trash as the person asked, on this device
// alone unless it is "search more", and gives mail's hits only. With no engine bound it searches nothing.
func TestMailClientSearchAsksTheEngineForTheMailbox(t *testing.T) {
	world := newMailClientTestWorld(t)
	ctx := context.Background()
	mailboxId := world.enable()
	if _, err := world.client.CreateAlias(ctx, &MailAliasCreateArgs{LocalPart: "bo"}); err != nil {
		t.Fatal(err)
	}
	world.ingest.depositMessage(testMailIngestMessage("Welcome", "Your code is 482913."))
	world.ingestAll(mailboxId)
	page, err := world.client.List(ctx, &MailListArgs{})
	if err != nil || len(page.Entries) != 1 {
		t.Fatalf("the list: %v", err)
	}
	month, messageId := MailYearMonthOf(testMailIngestReceiveMillis), mailEntryId(page.Entries[0].Entry)

	if _, err := world.client.Search(ctx, &MailSearchArgs{Text: "code"}); !errors.Is(err, ErrMailSearchUnavailable) {
		t.Fatalf("a search with no engine bound: %v", err)
	}
	binding, _, err := world.client.bound()
	if err != nil {
		t.Fatal(err)
	}
	engine := &mailSearchTestEngine{pages: [][]SearchHit{{
		{Repo: mailboxId, Path: MailMessagePath(month, messageId), DocKind: int(IndexDocMail), State: SearchConfirmed},
		{Repo: mailboxId, Path: "notes/plan.md", DocKind: int(IndexDocFile), State: SearchVerified},
	}}}
	bound := *binding
	bound.Search = engine.search
	world.client.Bind(&bound)
	if _, err := world.client.Search(ctx, &MailSearchArgs{}); !errors.Is(err, ErrMailSearchInvalid) {
		t.Fatalf("a search with no query: %v", err)
	}

	stream, err := world.client.Search(ctx, &MailSearchArgs{Text: "code", IncludeTrash: true, PageSize: 7})
	if err != nil {
		t.Fatal(err)
	}
	hits, _, done, err := stream.Next()
	if err != nil || !done || len(hits) != 1 || hits[0].DocKind != int(IndexDocMail) {
		t.Fatalf("the hits %+v, %v", hits, err)
	}
	stream.Close()
	if engine.closed != 1 {
		t.Error("closing the search left the engine's stream open")
	}
	request := engine.last()
	if !slices.Equal(request.Repos, []Id{mailboxId}) || request.Scope != SearchLatest || request.Remote != SearchRemoteOff ||
		request.IncludeSpam || !request.IncludeTrash || request.PageSize != 7 || request.Text != "code" {
		t.Fatalf("the request %+v", request)
	}
	// "search more": all, under the network's remote mode, which the engine's eligibility then holds
	if _, err := world.client.Search(ctx, &MailSearchArgs{Text: "code", More: true, AllowMetered: true, IncludeSpam: true}); err != nil {
		t.Fatal(err)
	}
	if request := engine.last(); request.Scope != SearchAll || request.Remote != "" || !request.AllowMetered || !request.IncludeSpam || request.IncludeTrash {
		t.Fatalf("the search more request %+v", request)
	}

	// the engine's join and display are the client's: the message it synced, in its mailbox alone
	if flags, held, err := world.client.SearchJoinSource().MailFlags(ctx, mailboxId, month, messageId); err != nil || !held || flags.Trash {
		t.Fatalf("the join: %+v, %t, %v", flags, held, err)
	}
	if _, held, _ := world.client.SearchJoinSource().MailFlags(ctx, testMailGroupId, month, messageId); held {
		t.Error("the join answered for another repo")
	}
	display := world.client.SearchDisplay()
	if display.View(mailboxId) == nil || display.View(testMailGroupId) != nil {
		t.Error("the display's views")
	}
	shown, ok, err := display.SearchDisplay(ctx, &SearchTextRequest{RepoId: mailboxId, Kind: IndexDocMail, Name: []byte(MailMessagePath(month, messageId))})
	if err != nil || !ok || !strings.Contains(shown.Snippet, "482913") {
		t.Fatalf("the display: %+v, %t, %v", shown, ok, err)
	}
}

// A mailbox never reaches another member's indexer: of a team's designated indexers, only a consented device of the
// mailbox's own member answers its owner's phone, whatever the others read; and a search that is not "search more"
// asks none (TestMailClientSearchAsksTheEngineForTheMailbox).
func TestMailSearchMailboxIsServedOnlyByItsOwnersIndexer(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	state := team.net.log.State()
	if served, ok := searchRemoteConfigVerdict(state, team.danaNas.sidecarId, team.danaPhone.sidecarId, team.danaMailbox, testConfigSearchServices); !ok {
		t.Fatalf("the owner's own indexer: %d", served)
	}
	for label, indexer := range map[string]testConfigDevice{
		"another member's indexer": team.benNas, "a network-scope tagged indexer": team.agent, "the network owner's device": team.net.owner, "the auditor's indexer": team.auditorNas,
	} {
		if served, ok := searchRemoteConfigVerdict(state, indexer.sidecarId, team.danaPhone.sidecarId, team.danaMailbox, testConfigSearchServices); ok {
			t.Errorf("%s answers the mailbox: %d", label, served)
		}
	}
	// nor does another member's phone reach the mailbox through its owner's indexer
	if served, ok := searchRemoteConfigVerdict(state, team.danaNas.sidecarId, team.benPhone.sidecarId, team.danaMailbox, testConfigSearchServices); ok {
		t.Errorf("another member's phone reads the mailbox: %d", served)
	}
}
