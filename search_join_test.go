//go:build !ios_extension

package sidecar

// SEARCH-M10-28's mail joins (§15.7's search index row; D-MAIL-16): a message's path read back to its month and id
// and nothing else read as one; a mail hit the device knows to be spam or trash left out unless asked, one it holds no
// i/ entry for kept, and a hit that is no message never asked about; and the engine joining its mail hits before it
// gives them, reading nothing of evs.

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// A join over flags by message id, counting what it was asked.
type testSearchJoin struct {
	flags map[Id]*SearchMailFlags
	asked []Id
	err   error
}

func (self *testSearchJoin) MailFlags(ctx context.Context, repoId Id, month MailYearMonth, messageId Id) (*SearchMailFlags, bool, error) {
	self.asked = append(self.asked, messageId)
	if self.err != nil {
		return nil, false, self.err
	}
	flags, ok := self.flags[messageId]
	return flags, ok, nil
}

// A message's path round-trips to its month and id; i/ segments, a wrong shard, a short id and other families do not
// read as messages.
func TestSearchJoinMailPath(t *testing.T) {
	month, ok := ParseMailYearMonth("202611")
	if !ok {
		t.Fatal("a month")
	}
	messageId := evsTestId("message")
	path := MailMessagePath(month, messageId)
	gotMonth, gotId, ok := searchJoinMailPath(path)
	if !ok || gotMonth != month || gotId != messageId {
		t.Fatalf("%q read back as %v %v %v", path, gotMonth, gotId, ok)
	}
	parts := []string{"m", month.String(), "zz", evsTokenEncoding.EncodeToString(messageId[:])}
	for _, other := range []string{
		MailIndexPath(month, 1),
		MailGroupRefPath(month, messageId),
		"m/" + month.String() + "/" + parts[2] + "/" + parts[3],
		"m/" + month.String() + "/" + MailShard("x") + "/" + evsTokenEncoding.EncodeToString(messageId[:8]),
		"notes/m/202611/aa/bb",
	} {
		if _, _, ok := searchJoinMailPath(other); ok {
			t.Errorf("%q read as a message", other)
		}
	}
}

// The default leaves out spam and trash; asking keeps them; a message the device holds no i/ entry for stays; a file's
// hit is never asked about; and a join that fails fails the page.
func TestSearchJoinLeavesOutSpamAndTrash(t *testing.T) {
	month, _ := ParseMailYearMonth("202611")
	spam, trash, plain, unknown := evsTestId("spam"), evsTestId("trash"), evsTestId("plain"), evsTestId("unknown")
	join := &testSearchJoin{flags: map[Id]*SearchMailFlags{
		spam: {Spam: true}, trash: {Trash: true, Seen: true}, plain: {Labels: []string{"work"}},
	}}
	row := func(messageId Id) *indexRow {
		return &indexRow{docKind: indexDocMail, locator: MailMessagePath(month, messageId)}
	}
	repoId := evsTestId("mailbox")
	cases := []struct {
		messageId Id
		ask       SearchJoinAsk
		kept      bool
	}{
		{messageId: spam, kept: false},
		{messageId: trash, kept: false},
		{messageId: plain, kept: true},
		{messageId: unknown, kept: true},
		{messageId: spam, ask: SearchJoinAsk{Spam: true}, kept: true},
		{messageId: trash, ask: SearchJoinAsk{Spam: true}, kept: false},
		{messageId: trash, ask: SearchJoinAsk{Trash: true}, kept: true},
	}
	for _, c := range cases {
		kept, flags, err := searchJoinMailHit(context.Background(), join, c.ask, repoId, row(c.messageId))
		if err != nil || kept != c.kept {
			t.Errorf("message %v ask %+v: kept %v, %v", c.messageId, c.ask, kept, err)
		}
		if c.messageId == plain && (flags == nil || !slices.Equal(flags.Labels, []string{"work"})) {
			t.Errorf("the plain message's flags %+v", flags)
		}
	}
	asked := len(join.asked)
	file := &indexRow{docKind: indexDocFile, locator: MailMessagePath(month, spam)}
	if kept, _, err := searchJoinMailHit(context.Background(), join, SearchJoinAsk{}, repoId, file); !kept || err != nil || len(join.asked) != asked {
		t.Fatal("a file's hit was joined")
	}
	if kept, _, err := searchJoinMailHit(context.Background(), nil, SearchJoinAsk{}, repoId, row(spam)); !kept || err != nil {
		t.Fatal("no join keeps every hit")
	}
	join.err = errors.New("mail view unreadable")
	if _, _, err := searchJoinMailHit(context.Background(), join, SearchJoinAsk{}, repoId, row(plain)); err == nil {
		t.Fatal("a failed join kept the hit")
	}
}

// The engine asks its join of each mail hit and leaves out what the device knows to be spam or trash, reading
// nothing of evs; with no join it gives every mail hit.
func TestSearchEngineJoinsMailHits(t *testing.T) {
	month, _ := ParseMailYearMonth("202611")
	spam, trash, plain := evsTestId("spam message"), evsTestId("trash message"), evsTestId("plain message")
	mail := func(index int, messageId Id, subject string) *indexPendingDocument {
		document := testEngineDocument(t, "mail", index, 1, MailMessagePath(month, messageId), subject)
		document.row.docKind = indexDocMail
		document.row.fields[indexFieldTitle] = ""
		document.row.fields[indexFieldSubject] = subject
		return document
	}
	world := newTestEngineWorld(t, nil,
		mail(1, spam, "quarterly invoice from the vendor"),
		mail(2, trash, "invoice reminder, already paid"),
		mail(3, plain, "the invoice for the harbor repairs"),
	)
	join := &testSearchJoin{flags: map[Id]*SearchMailFlags{spam: {Spam: true}, trash: {Trash: true}, plain: {}}}
	settings := world.sync.cache.settings
	engine, err := NewSearchEngine(&SearchEngineArgs{
		Settings: settings, Cache: world.sync.cache.cache, Sync: world.sync.sync, Scope: world.scope,
		Gkm: &evsTestReadGkm{newest: 1}, Clock: world.sync.cache.clock, Log: NewNoopLogger(), Join: join,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	joined := &testEngineWorld{sync: world.sync, scope: world.scope, engine: engine}
	fetchesBefore := len(world.sync.source.fetched())
	hits, _ := joined.all(t, &SearchRequest{Text: "invoice", Scope: SearchLatest})
	if paths := testHitPaths(hits); !slices.Equal(paths, []string{MailMessagePath(month, plain)}) {
		t.Fatalf("joined hits %v", paths)
	}
	if len(join.asked) != 3 {
		t.Fatalf("the join was asked %d times", len(join.asked))
	}
	if len(world.sync.source.fetched()) != fetchesBefore {
		t.Fatal("a joined search read evs")
	}
	if hits, _ := world.all(t, &SearchRequest{Text: "invoice", Scope: SearchLatest}); len(hits) != 3 {
		t.Fatalf("with no join, %d hits", len(hits))
	}
}
