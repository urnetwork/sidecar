//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !ios_extension && !windows

// MAIL-M10-03's IMAP SEARCH on the engine: a text term's result is the engine's verified result for the selected
// folder, a false candidate and a possible match left out; Trash finds its own; the request it sends stays on the
// device; what answers NO; and the folder's entries where no engine answers.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"

	"github.com/urnetwork/sidecar/protocol"
)

// A mailbox behind one IMAP session, whose text terms run on search.
type testMailImapSearchWorld struct {
	t       *testing.T
	mailbox *mailTestStore
	session *mailImapSession
	account *MailImapAccount
	month   MailYearMonth
}

// A message as ingest leaves it: its i/ entry and its m/ file.
func (self *testMailImapSearchWorld) deliver(n uint64, subject string, snippet string, body string) {
	self.t.Helper()
	entry := testMailSearchEntry(n, testMailDayMillis(self.month, int(n)), 0, snippet)
	entry.Subject = subject
	testMailAppend(self.t, self.mailbox, entry)
	self.mailbox.put(MailMessagePath(self.month, testMailId(n)), fmt.Appendf(nil,
		"From: Sender <sender@sender.example>\r\nTo: id@k3j4h5g6f7.root.example\r\nSubject: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n", subject, body))
}

// A session logged in to a mailbox of repo mailboxId, nothing selected, on a server with settings.
func newTestMailImapSearchWorld(t *testing.T, mailboxId Id, settings *MailImapServerSettings, search func(ctx context.Context, request *SearchRequest) (*SearchStream, error)) *testMailImapSearchWorld {
	t.Helper()
	world := &testMailImapSearchWorld{t: t, mailbox: newMailTestStore(), month: MailYearMonth(202611)}
	clock := &mailTestClock{now: time.UnixMilli(int64(testMailDayMillis(world.month, 20)))}
	store, err := NewMailImapStore(&MailImapStoreArgs{
		MailboxId: mailboxId, Mailbox: world.mailbox, Hlc: NewMailHlc(clock), SidecarId: testMailImapSidecarId, State: newTestMemoryStore(), Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := NewMailLocalCredential(&testMailSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewMailLocalCredentialSecret(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := credential.Install(secret.Verifier); err != nil {
		t.Fatal(err)
	}
	world.account = &MailImapAccount{
		NetworkId: testMailId(0xa1), Credential: credential, Store: func() (*MailImapStore, error) { return store, nil }, Search: search,
	}
	server, err := newMailImapServer(context.Background(), &MailImapServerArgs{
		Accounts: func() []*MailImapAccount { return []*MailImapAccount{world.account} },
		Clock:    clock,
		Settings: settings,
	}, &testMailImapLog{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	server.sessions.Update(func(count int) int { return count + 1 })
	world.session = newMailImapSession(server, nil)
	if err := world.session.Login(MailLocalCredentialUser, secret.Text); err != nil {
		t.Fatal(err)
	}
	return world
}

// The message numbers a SEARCH of folder answers, by UID and by sequence number, which must agree.
func (self *testMailImapSearchWorld) search(folder string, criteria *imap.SearchCriteria) ([]uint64, error) {
	self.t.Helper()
	if _, err := self.session.Select(folder, nil); err != nil {
		self.t.Fatal(err)
	}
	data, err := self.session.Search(imapserver.NumKindUID, criteria, nil)
	if err != nil {
		return nil, err
	}
	uids, ok := data.All.(imap.UIDSet)
	if !ok {
		self.t.Fatalf("a UID SEARCH answered %T", data.All)
	}
	numbers := []uint64{}
	for _, message := range self.session.snapshot.Messages {
		if uids.Contains(imap.UID(message.Uid)) {
			numbers = append(numbers, uint64(message.Key.Id[14])<<8|uint64(message.Key.Id[15]))
		}
	}
	bySeq, err := self.session.Search(imapserver.NumKindSeq, criteria, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	seqs, ok := bySeq.All.(imap.SeqSet)
	if !ok || bySeq.Count != data.Count || int(data.Count) != len(numbers) {
		self.t.Fatalf("SEARCH by sequence number answered %T with %d, by UID %d", bySeq.All, bySeq.Count, data.Count)
	}
	for index, message := range self.session.snapshot.Messages {
		if seqs.Contains(uint32(index+1)) != uids.Contains(imap.UID(message.Uid)) {
			self.t.Fatalf("message %d differs by sequence number and by UID", index+1)
		}
	}
	slices.Sort(numbers)
	return numbers, nil
}

// IMAP SEARCH's text terms equal the engine's verified result for the folder: a message whose text holds the term,
// and one whose subject does; never a false candidate, whose keys match and whose text does not, nor a message
// outside the folder. A search inside Trash finds its own. NOT and OR nest over the same answers, and the criteria
// an entry holds still read it.
func TestMailImapSearchEqualsTheEnginesVerifiedResult(t *testing.T) {
	ctx := context.Background()
	month := MailYearMonth(202611)
	engineWorld := newTestEngineWorld(t, nil,
		testMailSearchDocument(t, 1, month, 1, "notes from tuesday", "we agreed on the lighthouse budget"),
		// a false candidate: its keys hold the term, the message this device holds does not
		testMailSearchDocument(t, 2, month, 2, "meeting moved", "the lighthouse"),
		testMailSearchDocument(t, 3, month, 3, "the lighthouse visit", "see you there"),
		testMailSearchDocument(t, 4, month, 4, "lunch", "noodles"),
		testMailSearchDocument(t, 5, month, 5, "old plans", "the lighthouse again"),
	)
	mailboxId := engineWorld.sync.repoId
	var engine *SearchEngine
	world := newTestMailImapSearchWorld(t, mailboxId, nil, func(ctx context.Context, request *SearchRequest) (*SearchStream, error) {
		return engine.Search(ctx, request)
	})
	world.deliver(1, "notes from tuesday", "we agreed on", "we agreed on the lighthouse budget")
	world.deliver(2, "meeting moved", "to thursday", "to thursday")
	world.deliver(3, "the lighthouse visit", "see you there", "see you there")
	world.deliver(4, "lunch", "noodles", "noodles")
	world.deliver(5, "old plans", "again", "the lighthouse again")
	testMailFlag(t, world.mailbox, 1, &MailFlagChange{Month: month, MessageId: testMailId(5), Kind: protocol.MailFlagKind_MAIL_FLAG_TRASH, Set: true})
	join := testMailSearchJoin(t, mailboxId, world.mailbox, nil, nil, &mailTestClock{now: time.UnixMilli(int64(testMailDayMillis(month, 20)))})
	if err := join.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	text := &SearchContentTextSource{
		Content: func(ctx context.Context, repoId Id, refId Id, path []byte, version uint64) ([]byte, bool, error) {
			file := world.mailbox.file(string(path))
			if file == nil {
				return nil, false, nil
			}
			return file.content, true, nil
		},
		Place: func(repoId Id) (protocol.RepoKind, bool) { return protocol.RepoKind_REPO_KIND_MAILBOX, false },
	}
	var err error
	engine, err = NewSearchEngine(&SearchEngineArgs{
		Settings: engineWorld.sync.cache.settings, Cache: engineWorld.sync.cache.cache, Sync: engineWorld.sync.sync, Scope: engineWorld.scope,
		Gkm: &evsTestReadGkm{newest: 1}, Clock: engineWorld.sync.cache.clock, Log: NewNoopLogger(), Join: join,
		Text: func(repoId Id, refId Id) SearchTextSource { return text },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)

	// the engine's own verified result, by message number
	verified := func(request *SearchRequest) []uint64 {
		t.Helper()
		hits, _ := (&testEngineWorld{sync: engineWorld.sync, scope: engineWorld.scope, engine: engine}).all(t, request)
		numbers := []uint64{}
		for _, hit := range hits {
			if _, messageId, ok := searchJoinMailPath(hit.Path); ok && (hit.State == SearchVerified || hit.State == SearchConfirmed) {
				numbers = append(numbers, uint64(messageId[14])<<8|uint64(messageId[15]))
			}
		}
		slices.Sort(numbers)
		return numbers
	}
	want := verified(&SearchRequest{Text: `"lighthouse"`, Repos: []Id{mailboxId}, Scope: SearchAll, Remote: SearchRemoteOff})
	if !slices.Equal(want, []uint64{1, 3}) {
		t.Fatalf("the engine's verified result: %v", want)
	}
	for _, criteria := range []*imap.SearchCriteria{{Body: []string{"lighthouse"}}, {Text: []string{"LIGHTHOUSE"}}} {
		if got, err := world.search(MailImapFolderInbox, criteria); err != nil || !slices.Equal(got, want) {
			t.Fatalf("SEARCH %+v: %v, %v, want the engine's %v", criteria, got, err, want)
		}
	}
	// inside Trash the folder's own message is found, as the engine finds it once trash is asked
	wantTrash := verified(&SearchRequest{Text: `"lighthouse"`, Repos: []Id{mailboxId}, Scope: SearchAll, Remote: SearchRemoteOff, IncludeSpam: true, IncludeTrash: true})
	if !slices.Equal(wantTrash, []uint64{1, 3, 5}) {
		t.Fatalf("the engine's result with trash: %v", wantTrash)
	}
	if got, err := world.search(MailImapFolderTrash, &imap.SearchCriteria{Body: []string{"lighthouse"}}); err != nil || !slices.Equal(got, []uint64{5}) {
		t.Fatalf("SEARCH inside Trash: %v, %v", got, err)
	}
	// nesting reads the same answers; the entry's own criteria still hold
	if got, err := world.search(MailImapFolderInbox, &imap.SearchCriteria{Not: []imap.SearchCriteria{{Body: []string{"lighthouse"}}}}); err != nil || !slices.Equal(got, []uint64{2, 4}) {
		t.Fatalf("SEARCH NOT BODY: %v, %v", got, err)
	}
	or := &imap.SearchCriteria{Or: [][2]imap.SearchCriteria{{{Body: []string{"noodles"}}, {Body: []string{"budget"}}}}}
	if got, err := world.search(MailImapFolderInbox, or); err != nil || !slices.Equal(got, []uint64{1, 4}) {
		t.Fatalf("SEARCH OR: %v, %v", got, err)
	}
	both := &imap.SearchCriteria{Body: []string{"lighthouse"}, Header: []imap.SearchCriteriaHeaderField{{Key: "subject", Value: "VISIT"}}}
	if got, err := world.search(MailImapFolderInbox, both); err != nil || !slices.Equal(got, []uint64{3}) {
		t.Fatalf("SEARCH BODY and SUBJECT: %v, %v", got, err)
	}
	// a string the grammar reads as no term is held by every message
	if got, err := world.search(MailImapFolderInbox, &imap.SearchCriteria{Body: []string{"\"\""}}); err != nil || !slices.Equal(got, []uint64{1, 2, 3, 4}) {
		t.Fatalf("SEARCH of no term: %v, %v", got, err)
	}
}

// What SEARCH asks of the engine and what it takes from it: each distinct text term once, as a quoted phrase over
// the folder's repos, scope all, Remote off, spam and trash by the folder; only a verified or confirmed mail hit
// matches. More terms than the bound, a busy or failing engine, a too-broad search and one past the hit bound answer
// NO.
func TestMailImapSearchAsksTheEngineAndRefusesWhatItCannotAnswerWhole(t *testing.T) {
	month := MailYearMonth(202611)
	path := func(n uint64) string { return MailMessagePath(month, testMailId(n)) }
	engine := &mailSearchTestEngine{}
	settings := DefaultMailImapServerSettings()
	settings.SearchTermMaxCount = 2
	settings.SearchHitMaxCount = 3
	world := newTestMailImapSearchWorld(t, testMailMailboxId, settings, engine.search)
	for n := uint64(1); n <= 4; n += 1 {
		world.deliver(n, fmt.Sprintf("message %d", n), "", "a body")
	}
	engine.pages = [][]SearchHit{{
		{Repo: testMailMailboxId, Path: path(1), DocKind: int(IndexDocMail), State: SearchVerified},
		{Repo: testMailMailboxId, Path: path(2), DocKind: int(IndexDocMail), State: SearchPossible},
	}, {
		{Repo: testMailMailboxId, Path: path(3), DocKind: int(IndexDocMail), State: SearchConfirmed},
		{Repo: testMailMailboxId, Path: path(4), DocKind: int(IndexDocMail), State: SearchNear},
		// another repo's message of the same id, and a file, are no message of this folder
		{Repo: testMailGroupId, Path: path(2), DocKind: int(IndexDocMail), State: SearchVerified},
		{Repo: testMailMailboxId, Path: "notes/plan.md", DocKind: int(IndexDocFile), State: SearchVerified},
	}}
	criteria := &imap.SearchCriteria{Body: []string{`say "hello" there`}, Not: []imap.SearchCriteria{{Text: []string{`say "hello" there`}, Flag: []imap.Flag{imap.FlagSeen}}}}
	got, err := world.search(MailImapFolderInbox, criteria)
	if err != nil || !slices.Equal(got, []uint64{1, 3}) {
		t.Fatalf("SEARCH: %v, %v", got, err)
	}
	// one search a distinct term, by UID and again by sequence number
	if len(engine.requests) != 2 || engine.closed != 2 {
		t.Fatalf("%d searches, %d closed", len(engine.requests), engine.closed)
	}
	request := engine.last()
	if request.Text != `"say  hello  there"` || !slices.Equal(request.Repos, []Id{testMailMailboxId}) || request.Scope != SearchAll ||
		request.Remote != SearchRemoteOff || request.IncludeSpam || request.IncludeTrash {
		t.Fatalf("the request %+v", request)
	}
	if _, err := world.search(MailImapFolderTrash, criteria); err != nil {
		t.Fatal(err)
	}
	// Trash holds no message, so nothing is asked
	if len(engine.requests) != 2 {
		t.Fatalf("an empty folder asked the engine: %d searches", len(engine.requests))
	}

	refused := func(label string, criteria *imap.SearchCriteria, code imap.ResponseCode) {
		t.Helper()
		_, err := world.search(MailImapFolderInbox, criteria)
		var imapErr *imap.Error
		if !errors.As(err, &imapErr) || imapErr.Type != imap.StatusResponseTypeNo || imapErr.Code != code {
			t.Fatalf("%s: %v", label, err)
		}
	}
	refused("three terms", &imap.SearchCriteria{Body: []string{"a1", "b2"}, Or: [][2]imap.SearchCriteria{{{Text: []string{"c3"}}, {}}}}, imap.ResponseCodeLimit)
	refused("a term past the grammar's bound", &imap.SearchCriteria{Body: []string{strings.Repeat("abcdefgh ", 100)}}, imap.ResponseCodeLimit)
	engine.progress = SearchProgress{TooBroad: true}
	refused("a too-broad search", &imap.SearchCriteria{Body: []string{"body"}}, imap.ResponseCodeLimit)
	engine.progress = SearchProgress{}
	engine.pages = [][]SearchHit{{
		{Repo: testMailMailboxId, Path: path(1), DocKind: int(IndexDocMail), State: SearchVerified},
		{Repo: testMailMailboxId, Path: path(2), DocKind: int(IndexDocMail), State: SearchVerified},
		{Repo: testMailMailboxId, Path: path(3), DocKind: int(IndexDocMail), State: SearchVerified},
		{Repo: testMailMailboxId, Path: path(4), DocKind: int(IndexDocMail), State: SearchVerified},
	}}
	refused("past the hit bound", &imap.SearchCriteria{Body: []string{"body"}}, imap.ResponseCodeLimit)
	engine.err = ErrSearchBusy
	refused("a busy engine", &imap.SearchCriteria{Body: []string{"body"}}, imap.ResponseCodeUnavailable)
}

// Where no engine answers, SEARCH reads the folder's entries as it did before the engine: no engine bound, an engine
// no host installed, and a repo the engine left out of the search.
func TestMailImapSearchFallsBackToTheEntriesWhereNoEngineAnswers(t *testing.T) {
	engine := &mailSearchTestEngine{}
	for _, label := range []string{"none bound", "none installed", "the repo left out"} {
		search := engine.search
		engine.err, engine.pages, engine.progress = nil, nil, SearchProgress{}
		switch label {
		case "none bound":
			search = nil
		case "none installed":
			engine.err = ErrSidecarSearchUnavailable
		case "the repo left out":
			engine.pages = [][]SearchHit{{}}
			engine.progress = SearchProgress{Excluded: []SearchExclusion{{RepoId: testMailMailboxId, Reason: "index_off"}}}
		}
		world := newTestMailImapSearchWorld(t, testMailMailboxId, nil, search)
		world.deliver(1, "the lighthouse visit", "see you there", "see you there")
		world.deliver(2, "notes", "about the lighthouse", "about the lighthouse and more")
		world.deliver(3, "lunch", "noodles", "the lighthouse is far down the message")
		if got, err := world.search(MailImapFolderInbox, &imap.SearchCriteria{Body: []string{"Lighthouse"}}); err != nil || !slices.Equal(got, []uint64{1, 2}) {
			t.Fatalf("%s: %v, %v", label, got, err)
		}
	}
}
