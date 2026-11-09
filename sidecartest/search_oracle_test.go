// SEARCH-M10-07's tests: a hand-computed corpus of twenty-odd documents checks Matches and Covered, the
// oracle's normalizer against INDEX-FORMAT.md's steps, the import check that keeps index code out of the
// oracle (with a planted reference it must catch), and the corpus generator's determinism and coverage.

package sidecartest

import (
	"bytes"
	"encoding/base64"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The files written apart from the index, which the import check reads.
var searchOracleFiles = []string{"search_oracle.go", "search_oracle_normalize.go", "search_oracle_extract.go", "search_corpus.go"}

// One repo of the hand corpus.
type searchHandRepo struct {
	repo *SearchCorpusRepo
	// its network and readers
	networkId sidecar.Id
	readerIds []sidecar.Id
}

// The hand corpus: its ledger, the reader, the networks and the repos by label.
type searchHand struct {
	t        *testing.T
	ledger   *SearchLedger
	oracle   *SearchOracle
	readerId sidecar.Id
	network1 sidecar.Id
	network2 sidecar.Id
	repos    map[string]*searchHandRepo
	labels   map[sidecar.Id]string
	refVer   map[string]uint64
	at       time.Time
}

func newSearchHand(t *testing.T) *searchHand {
	hand := &searchHand{
		t:        t,
		ledger:   NewSearchLedger(),
		readerId: sidecar.NewId(),
		network1: sidecar.NewId(),
		network2: sidecar.NewId(),
		repos:    map[string]*searchHandRepo{},
		labels:   map[sidecar.Id]string{},
		refVer:   map[string]uint64{},
		at:       DefaultClockStart(),
	}
	hand.oracle = NewSearchOracle(hand.ledger)
	other := sidecar.NewId()
	add := func(label string, kind protocol.RepoKind, networkId sidecar.Id, readerIds ...sidecar.Id) {
		repo := &SearchCorpusRepo{RepoId: sidecar.NewId(), Kind: kind, RefId: sidecar.NewId()}
		hand.repos[label] = &searchHandRepo{repo: repo, networkId: networkId, readerIds: readerIds}
		hand.labels[repo.RepoId] = label
	}
	add("notes", protocol.RepoKind_REPO_KIND_GENERAL, hand.network1, hand.readerId)
	add("mail", protocol.RepoKind_REPO_KIND_MAILBOX, hand.network1, hand.readerId)
	add("secret", protocol.RepoKind_REPO_KIND_SECRET, hand.network1, hand.readerId)
	add("unread", protocol.RepoKind_REPO_KIND_GENERAL, hand.network1, other)
	add("other", protocol.RepoKind_REPO_KIND_GENERAL, hand.network2, hand.readerId)
	add("off", protocol.RepoKind_REPO_KIND_GENERAL, hand.network1, hand.readerId)
	repos := []*SearchCorpusRepo{}
	for _, label := range slices.Sorted(func(yield func(string) bool) {
		for label := range hand.repos {
			if !yield(label) {
				return
			}
		}
	}) {
		repos = append(repos, hand.repos[label].repo)
	}
	keys, err := searchCorpusKeys(t.Context(), NewFakeClock(DefaultClockStart()), sidecar.NewId(), []sidecar.Id{hand.readerId, other}, repos)
	if err != nil {
		t.Fatal(err)
	}
	for _, handRepo := range hand.repos {
		err := hand.ledger.AddRepo(&SearchLedgerRepo{
			RepoId:       handRepo.repo.RepoId,
			NetworkId:    handRepo.networkId,
			Kind:         handRepo.repo.Kind,
			DefaultRefId: handRepo.repo.RefId,
			Key:          keys[handRepo.repo.RepoId],
			ReaderIds:    handRepo.readerIds,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return hand
}

// Commits changes to a repo at a time days after the corpus starts, indexed unless skip.
func (self *searchHand) commit(label string, days int, skip bool, changes ...*SearchChange) uint64 {
	self.t.Helper()
	repo := self.repos[label].repo
	self.refVer[label] += 1
	err := self.ledger.Commit(&SearchCommit{
		RepoId:     repo.RepoId,
		RefId:      repo.RefId,
		RefVersion: self.refVer[label],
		Time:       self.at.Add(time.Duration(days) * 24 * time.Hour),
		WriterId:   self.readerId,
		Changes:    changes,
		Indexed:    !skip,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return self.refVer[label]
}

func put(path string, version uint64, content string) *SearchChange {
	return &SearchChange{Path: path, Version: version, Content: []byte(content)}
}

func removed(path string, version uint64) *SearchChange {
	return &SearchChange{Path: path, Version: version}
}

// "label:path" for each document, sorted.
func (self *searchHand) names(keys []*DocumentKey) []string {
	names := []string{}
	for _, key := range keys {
		names = append(names, self.labels[key.RepoId]+":"+key.Name)
	}
	slices.Sort(names)
	return names
}

func (self *searchHand) network() *SearchScope {
	return &SearchScope{Partitions: SearchScopeAll, Breadth: SearchBreadthNetwork, NetworkIds: []sidecar.Id{self.network1}, ReaderId: self.readerId}
}

// The hand corpus written: twenty-odd documents, each edge of the oracle's reading once.
func writeSearchHand(t *testing.T) *searchHand {
	hand := newSearchHand(t)
	utf16 := []byte{0xFF, 0xFE}
	for _, r := range "# budget\nutf16word budget\n" {
		utf16 = append(utf16, byte(r), 0)
	}
	hand.commit("notes", 0, false,
		put("notes/budget.md", 1, "# Quarterly Budget\n\nThe quarterly budget review is due. We go over costs.\n"),
	)
	hand.commit("notes", 40, false,
		put("notes/tokyo.md", 1, "# 東京の会議\n\n東京都の天気は晴れ。\n"),
		put("notes/cafe.md", 1, "# Café notes\n\nThe café serves naïve coffee.\n"),
		put("notes/finance.md", 1, "# ﬁnance\n\nFull-width ＦＵＬＬ and x².\n"),
		put("notes/strasse.md", 1, "# Straße\n\nSTRASSE ΣΊΣΥΦΟΣ\n"),
		put("notes/cherokee.md", 1, "# ᏣᎳᎩ\n\nsyllabary\n"),
		put("notes/punct.md", 1, "# e-mail\n\nfoo---bar...baz C++ path/to/file.txt\n"),
		put("notes/hindi.md", 1, "# हिन्दी\n\nहिन्दी भाषा\n"),
		put("notes/edited.md", 1, "# Draft\n\noldword alpha\n"),
		put("notes/deleted.md", 1, "# Gone\n\nghostword\n"),
		put("notes/renamed-from.md", 1, "# Moved\n\nmovedword\n"),
		put("notes/recreated.md", 1, "# Phoenix\n\nashword\n"),
		put("notes/erased.md", 1, "# Plan\n\nerasedword\n"),
		&SearchChange{Path: "notes/image.png", Version: 1, Content: []byte("\x89PNG\r\n\x1a\n\x00\x00budget")},
		put(".ur-index/i1/settings", 1, "budget"),
		&SearchChange{Path: "notes/utf16.txt", Version: 1, Content: utf16},
	)
	hand.commit("notes", 41, false,
		put("notes/edited.md", 2, "# Draft\n\nnewword beta\n"),
		removed("notes/deleted.md", 2),
		removed("notes/renamed-from.md", 2),
		put("notes/renamed-to.md", 1, "# Moved\n\nmovedword\n"),
		removed("notes/recreated.md", 2),
	)
	hand.commit("notes", 42, false, put("notes/recreated.md", 3, "# Phoenix\n\nfireword\n"))
	hand.commit("notes", 43, true, put("notes/skipped.md", 1, "# Pending\n\npendingword\n"))
	if err := hand.ledger.Erase(hand.repos["notes"].repo.RepoId, hand.repos["notes"].repo.RefId, "notes/erased.md", 1); err != nil {
		t.Fatal(err)
	}
	attachment := base64.StdEncoding.EncodeToString([]byte("attachmentbytesword"))
	hand.commit("mail", 40, false,
		put("m/000001", 1, "From: \"Alice Example\" <alice@example.com>\r\nTo: bob@example.org\r\nSubject: Invoice 42\r\n"+
			"Received: from relay.example by mx.example\r\n\r\nPlease find the invoice attached. go team\r\n"),
		put("m/000002", 1, "From: carol@example.net\r\nTo: bob@example.org\r\nSubject: =?UTF-8?B?"+
			base64.StdEncoding.EncodeToString([]byte("Grüße aus Köln"))+"?=\r\nContent-Type: text/plain; charset=utf-8\r\n"+
			"Content-Transfer-Encoding: base64\r\n\r\n"+base64.StdEncoding.EncodeToString([]byte("base64word here"))+"\r\n"),
		put("m/000003", 1, "From: dave@example.com\r\nTo: bob@example.org\r\nSubject: alternative\r\n"+
			"Content-Type: multipart/alternative; boundary=\"b1\"\r\n\r\npreamble\r\n--b1\r\n"+
			"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"+
			"qpword caf=C3=A9 =\r\njoined\r\n--b1\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"+
			"<html><head><style>.hiddenstyleword{}</style><script>var hiddenscriptword = 1;</script></head>"+
			"<body><!-- hiddencommentword --><p class='a>b'>htmlword &lt;markup&gt;</p><b>bo</b>ld</body></html>\r\n--b1--\r\n"),
		put("m/000004", 1, "From: erin@example.org\r\nTo: bob@example.org\r\nCc: frank@example.org\r\nSubject: files\r\n"+
			"Content-Type: multipart/mixed; boundary=mix\r\n\r\n--mix\r\nContent-Type: text/plain\r\n\r\nmixedword invoice\r\n"+
			"--mix\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename*=utf-8''r%C3%A9sum%C3%A9.pdf\r\n"+
			"Content-Transfer-Encoding: base64\r\n\r\n"+attachment+"\r\n--mix--\r\n"),
		put("m/000005", 1, "From: gina@example.com\r\nTo: bob@example.org\r\nSubject: latin\r\n"+
			"Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nR=E9sum=E9 latin1word\r\n"),
		put("vault/key", 1, "vaultword"),
	)
	hand.commit("secret", 40, false, put("notes/s.md", 1, "budget secretword\n"))
	hand.commit("unread", 40, false, put("notes/u.md", 1, "budget unreadword\n"))
	hand.commit("other", 40, false, put("notes/o.md", 1, "budget otherword\n"))
	off := hand.repos["off"].repo
	if err := hand.ledger.SetIndexSettings(off.RepoId, off.RefId, &SearchIndexSettings{Off: true}, hand.at); err != nil {
		t.Fatal(err)
	}
	hand.commit("off", 40, false, put("notes/f.md", 1, "budget offword\n"))
	return hand
}

func TestSearchOracleHandCorpusMatches(t *testing.T) {
	hand := writeSearchHand(t)
	cases := []struct {
		query string
		want  []string
	}{
		{query: "budget", want: []string{"notes:notes/budget.md", "notes:notes/utf16.txt"}},
		{query: "go", want: []string{"mail:m/000001", "notes:notes/budget.md"}},
		{query: "东京", want: []string{}},
		{query: "東京", want: []string{"notes:notes/tokyo.md"}},
		{query: "京", want: []string{"notes:notes/tokyo.md"}},
		{query: "cafe", want: []string{"mail:m/000003", "notes:notes/cafe.md"}},
		{query: "naive", want: []string{"notes:notes/cafe.md"}},
		{query: "finance", want: []string{"notes:notes/finance.md"}},
		{query: "full", want: []string{"notes:notes/finance.md"}},
		{query: "x2", want: []string{"notes:notes/finance.md"}},
		{query: "strasse", want: []string{"notes:notes/strasse.md"}},
		{query: "σίσυφος", want: []string{"notes:notes/strasse.md"}},
		{query: "ꮳꮃꭹ", want: []string{"notes:notes/cherokee.md"}},
		{query: "\"foo bar\"", want: []string{"notes:notes/punct.md"}},
		{query: "e-mail", want: []string{"notes:notes/punct.md"}},
		{query: "हिन्दी", want: []string{"notes:notes/hindi.md"}},
		{query: "oldword", want: []string{}},
		{query: "newword", want: []string{"notes:notes/edited.md"}},
		{query: "ghostword", want: []string{}},
		{query: "movedword", want: []string{"notes:notes/renamed-to.md"}},
		{query: "ashword", want: []string{}},
		{query: "fireword", want: []string{"notes:notes/recreated.md"}},
		{query: "pendingword", want: []string{"notes:notes/skipped.md"}},
		{query: "erasedword", want: []string{}},
		{query: "utf16word", want: []string{"notes:notes/utf16.txt"}},
		{query: "invoice", want: []string{"mail:m/000001", "mail:m/000004"}},
		{query: "subject:invoice", want: []string{"mail:m/000001"}},
		{query: "alice@example.com", want: []string{"mail:m/000001"}},
		{query: "grusse", want: []string{"mail:m/000002"}},
		{query: "base64word", want: []string{"mail:m/000002"}},
		{query: "htmlword", want: []string{"mail:m/000003"}},
		{query: "markup", want: []string{"mail:m/000003"}},
		{query: "bold", want: []string{"mail:m/000003"}},
		{query: "hiddenscriptword", want: []string{}},
		{query: "hiddenstyleword", want: []string{}},
		{query: "hiddencommentword", want: []string{}},
		{query: "qpword", want: []string{"mail:m/000003"}},
		{query: "\"qpword cafe joined\"", want: []string{"mail:m/000003"}},
		{query: "resume", want: []string{"mail:m/000004", "mail:m/000005"}},
		{query: "attachmentbytesword", want: []string{}},
		{query: "latin1word", want: []string{"mail:m/000005"}},
		{query: "frank", want: []string{"mail:m/000004"}},
		{query: "relay", want: []string{}},
		{query: "vaultword", want: []string{}},
		{query: "secretword", want: []string{}},
		{query: "unreadword", want: []string{}},
		{query: "otherword", want: []string{}},
		{query: "offword", want: []string{}},
		{query: "budget -review", want: []string{"notes:notes/utf16.txt"}},
		{query: "oldword OR newword", want: []string{"notes:notes/edited.md"}},
		{query: "fireword OR movedword", want: []string{"notes:notes/recreated.md", "notes:notes/renamed-to.md"}},
		{query: "!!!", want: []string{}},
		{query: "", want: []string{}},
		{query: strings.Repeat("w ", 17), want: []string{}},
		{query: strings.Repeat("abcdefgh", 65), want: []string{}},
	}
	for _, c := range cases {
		got := hand.names(hand.oracle.Matches(c.query, hand.network()))
		if !slices.Equal(got, c.want) {
			t.Errorf("Matches(%q) = %v, want %v", c.query, got, c.want)
		}
	}
}

func TestSearchOracleRefusesQueriesPastLimits(t *testing.T) {
	hand := writeSearchHand(t)
	for _, query := range []string{strings.Repeat("w ", 17), strings.Repeat("abcdefgh", 65)} {
		if _, _, err := hand.oracle.Judge(query, hand.network()); !errors.Is(err, ErrSearchOracleQueryRefused) {
			t.Errorf("Judge(%.20q...) = %v, want ErrSearchOracleQueryRefused", query, err)
		}
	}
	if _, _, err := hand.oracle.Judge(strings.Repeat("w ", 16), hand.network()); err != nil {
		t.Errorf("16 terms refused: %v", err)
	}
}

func TestSearchOracleHandCorpusScopes(t *testing.T) {
	hand := writeSearchHand(t)
	notes := hand.repos["notes"].repo
	repoScope := func(labels ...string) *SearchScope {
		scope := &SearchScope{Partitions: SearchScopeAll, Breadth: SearchBreadthRepo, ReaderId: hand.readerId}
		for _, label := range labels {
			scope.Repos = append(scope.Repos, &SearchScopeRepo{RepoId: hand.repos[label].repo.RepoId})
		}
		return scope
	}
	// a repo scope searches a ref whose index is off by its text, and nothing covers it
	if got := hand.names(hand.oracle.Matches("budget", repoScope("off", "secret", "unread"))); !slices.Equal(got, []string{"off:notes/f.md"}) {
		t.Errorf("repo scope with the index off = %v", got)
	}
	if got := hand.oracle.Covered(repoScope("off")); len(got) != 0 {
		t.Errorf("Covered of an index that is off = %v", hand.names(got))
	}
	all := hand.network()
	all.Breadth = SearchBreadthAll
	all.NetworkIds = []sidecar.Id{hand.network1, hand.network2}
	if got := hand.names(hand.oracle.Matches("budget", all)); !slices.Equal(got, []string{"notes:notes/budget.md", "notes:notes/utf16.txt", "other:notes/o.md"}) {
		t.Errorf("all breadth = %v", got)
	}
	// a reader that reads nothing finds nothing
	stranger := hand.network()
	stranger.ReaderId = sidecar.NewId()
	if got := hand.oracle.Matches("budget", stranger); len(got) != 0 {
		t.Errorf("a stranger found %v", hand.names(got))
	}
	// latest: the budget note's bucket is rolled into all, so only phase 2 finds it
	latest := hand.network()
	latest.Partitions = SearchScopeLatest
	if got := hand.names(hand.oracle.Matches("budget", latest)); !slices.Equal(got, []string{"notes:notes/budget.md", "notes:notes/utf16.txt"}) {
		t.Errorf("latest before the roll-up = %v", got)
	}
	day := uint32(hand.at.Unix() / 86400)
	if err := hand.ledger.RolledThrough(notes.RepoId, notes.RefId, day/30*30); err != nil {
		t.Fatal(err)
	}
	if got := hand.names(hand.oracle.Matches("budget", latest)); !slices.Equal(got, []string{"notes:notes/utf16.txt"}) {
		t.Errorf("latest after the roll-up = %v", got)
	}
	cached := hand.network()
	cached.Partitions = SearchScopeCached
	if got := hand.names(hand.oracle.Matches("budget", cached)); !slices.Equal(got, []string{"notes:notes/utf16.txt"}) {
		t.Errorf("cached without all = %v", got)
	}
	cached.AllHeldRepoIds = []sidecar.Id{notes.RepoId}
	if got := hand.names(hand.oracle.Matches("budget", cached)); !slices.Equal(got, []string{"notes:notes/budget.md", "notes:notes/utf16.txt"}) {
		t.Errorf("cached with all = %v", got)
	}
	// since and until read each document's entry time
	dated := hand.network()
	dated.Since = hand.at.Add(30 * 24 * time.Hour)
	if got := hand.names(hand.oracle.Matches("budget", dated)); !slices.Equal(got, []string{"notes:notes/utf16.txt"}) {
		t.Errorf("since = %v", got)
	}
	dated.Since = time.Time{}
	dated.Until = hand.at.Add(time.Hour)
	if got := hand.names(hand.oracle.Matches("budget", dated)); !slices.Equal(got, []string{"notes:notes/budget.md"}) {
		t.Errorf("until = %v", got)
	}
	// an empty query lists only under filters
	listed := hand.network()
	listed.Filters = &SearchScopeFilters{PathPrefix: "notes/re"}
	if got := hand.names(hand.oracle.Matches("", listed)); !slices.Equal(got, []string{"notes:notes/recreated.md", "notes:notes/renamed-to.md"}) {
		t.Errorf("listing by path prefix = %v", got)
	}
	fields := hand.network()
	fields.Filters = &SearchScopeFilters{DocKinds: []SearchDocKind{SearchDocKindMail}, Fields: []*SearchScopeField{{Field: 2, Text: "Alice"}}}
	if got := hand.names(hand.oracle.Matches("", fields)); !slices.Equal(got, []string{"mail:m/000001"}) {
		t.Errorf("listing by from = %v", got)
	}
}

func TestSearchOracleHandCorpusCovered(t *testing.T) {
	hand := writeSearchHand(t)
	want := []string{
		"mail:m/000001", "mail:m/000002", "mail:m/000003", "mail:m/000004", "mail:m/000005",
		"notes:notes/budget.md", "notes:notes/cafe.md", "notes:notes/cherokee.md", "notes:notes/edited.md",
		"notes:notes/finance.md", "notes:notes/hindi.md", "notes:notes/punct.md", "notes:notes/recreated.md",
		"notes:notes/renamed-to.md", "notes:notes/strasse.md", "notes:notes/tokyo.md", "notes:notes/utf16.txt",
	}
	if got := hand.names(hand.oracle.Covered(hand.network())); !slices.Equal(got, want) {
		t.Errorf("Covered = %v, want %v", got, want)
	}
	// the backfill reaches the commit that skipped the index
	notes := hand.repos["notes"].repo
	if err := hand.ledger.Cover(notes.RepoId, notes.RefId, hand.refVer["notes"], hand.at.Add(43*24*time.Hour+10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	want = append(want, "notes:notes/skipped.md")
	slices.Sort(want)
	if got := hand.names(hand.oracle.Covered(hand.network())); !slices.Equal(got, want) {
		t.Errorf("Covered after the backfill = %v, want %v", got, want)
	}
	// each key is the format's doc_key at the document's newest version
	for _, key := range hand.oracle.Matches("fireword", hand.network()) {
		if key.Version != 3 || key.Chunk != 0 || key.DocKey == ([16]byte{}) {
			t.Errorf("%s: version %d, chunk %d, key %x", key, key.Version, key.Chunk, key.DocKey)
		}
	}
}

func TestSearchLedgerRefusesWhatEvsWould(t *testing.T) {
	hand := newSearchHand(t)
	hand.commit("notes", 0, false, put("notes/a.md", 2, "a"))
	notes := hand.repos["notes"].repo
	err := hand.ledger.Commit(&SearchCommit{RepoId: notes.RepoId, RefId: notes.RefId, RefVersion: 2, Changes: []*SearchChange{put("notes/a.md", 2, "b")}})
	if !errors.Is(err, ErrSearchLedgerInvalid) {
		t.Errorf("a version that does not rise: %v", err)
	}
	err = hand.ledger.Commit(&SearchCommit{RepoId: notes.RepoId, RefId: notes.RefId, RefVersion: 1, Changes: []*SearchChange{put("notes/b.md", 1, "b")}})
	if !errors.Is(err, ErrSearchLedgerInvalid) {
		t.Errorf("a ref version that does not rise: %v", err)
	}
	if err := hand.ledger.Commit(&SearchCommit{RepoId: sidecar.NewId(), RefVersion: 1}); !errors.Is(err, ErrSearchLedgerInvalid) {
		t.Errorf("an unknown repo: %v", err)
	}
	vault := &SearchLedgerRepo{RepoId: sidecar.NewId(), Kind: protocol.RepoKind_REPO_KIND_VAULT}
	if err := hand.ledger.AddRepo(vault); !errors.Is(err, ErrSearchOracleUnsupported) {
		t.Errorf("a vault, whose record documents are not read yet: %v", err)
	}
	// a scope naming a repo the ledger lacks is a schedule's error, which Matches panics on
	scope := &SearchScope{Breadth: SearchBreadthRepo, Repos: []*SearchScopeRepo{{RepoId: sidecar.NewId()}}, ReaderId: hand.readerId}
	if _, _, err := hand.oracle.Judge("a", scope); !errors.Is(err, ErrSearchLedgerInvalid) {
		t.Errorf("an unknown repo in scope: %v", err)
	}
}

// A scope that would make every answer empty is refused, so no schedule passes on it unchecked.
func TestSearchOracleRefusesScopesNamingNothing(t *testing.T) {
	hand := writeSearchHand(t)
	noReader := hand.network()
	noReader.ReaderId = sidecar.Id{}
	noRepo := &SearchScope{Breadth: SearchBreadthRepo, ReaderId: hand.readerId}
	noNetwork := &SearchScope{Breadth: SearchBreadthAll, ReaderId: hand.readerId}
	twoNetworks := hand.network()
	twoNetworks.NetworkIds = []sidecar.Id{hand.network1, hand.network2}
	for i, scope := range []*SearchScope{noReader, noRepo, noNetwork, twoNetworks} {
		if _, _, err := hand.oracle.Judge("budget", scope); !errors.Is(err, ErrSearchOracleScope) {
			t.Errorf("scope %d: %v, want ErrSearchOracleScope", i, err)
		}
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("Matches answered a scope naming no reader")
			}
		}()
		hand.oracle.Matches("budget", noReader)
	}()
}

func TestSearchOracleNormalizerSteps(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// step 1: one U+FFFD a bad byte, and U+FFFD then folds to a space
		{in: "a\xffb\xe6\x97c", want: "a b c"},
		// step 2: NFKC
		{in: "ﬁＡ²①", want: "fia21"},
		// step 3: full folding, with the Cherokee map
		{in: "Straße ΣΑΣ", want: "strasse σασ"},
		{in: "Ꭰ ꭰ Ᏸ ᏸ", want: "Ꭰ Ꭰ Ᏸ Ᏸ"},
		// step 4: marks after the five scripts' letters go, others stay, Hangul stays one syllable
		{in: "café Ελλάδα", want: "cafe ελλαδα"},
		{in: "が กิน 한", want: "が กิน 한"},
		{in: "हिन्दी", want: "हिन्दी"},
		{in: "שָׁלוֹם", want: "שלום"},
		// a spacing mark between keeps the nonspacing mark after it
		{in: "aः́", want: "aः́"},
		// step 5: a run outside L, M and N is one space, at the ends too
		{in: "--foo...bar--", want: " foo bar "},
		{in: "", want: ""},
	}
	for _, c := range cases {
		if got := searchOracleNormalize([]byte(c.in)); got != c.want {
			t.Errorf("normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	fields := &searchOracleFields{}
	fields[1] = []byte("Hello")
	fields[5] = []byte("World, ok")
	if got := searchOracleDocumentText(fields); got != " hello  world ok " {
		t.Errorf("document text = %q", got)
	}
	fields[1] = []byte(strings.Repeat("é", 600))
	if got := searchOracleDocumentText(fields); !strings.HasPrefix(got, " "+strings.Repeat("e", 600)+" ") {
		t.Errorf("a field cut at 1,024 B normalized: %d bytes", len(got))
	}
	fields[1] = []byte(strings.Repeat("日", 400))
	if got := searchOracleDocumentText(fields); !strings.HasPrefix(got, " "+strings.Repeat("日", 341)+" ") {
		t.Errorf("a field not cut on a code point: %q", got[:20])
	}
}

func TestSearchOracleTablesAreNormalizerOne(t *testing.T) {
	if err := searchOracleTablesErr(); err != nil {
		t.Fatal(err)
	}
}

func TestSearchOracleKeySetBound(t *testing.T) {
	random := rand.New(rand.NewPCG(1, 2))
	var dense strings.Builder
	for range 700000 {
		dense.WriteByte(byte(1 + random.IntN(255)))
	}
	if !searchOracleKeySetTooLarge(dense.String()) {
		t.Error("a chunk of 700,000 random bytes kept")
	}
	if searchOracleKeySetTooLarge(strings.Repeat("the same few words ", 60000)) {
		t.Error("a repetitive chunk skipped")
	}
}

func TestSearchOracleExtractsHtmlAsPublished(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "<b>a</b>b", want: "ab"},
		{in: "<p>a</p><p>b</p>", want: " a  b "},
		{in: "a<SCRIPT>x<p>y</p></Script>b", want: "ab"},
		{in: "a<style>x</style", want: "a"},
		{in: "a<!-- x > y -->b<!DOCTYPE html>c<?xml?>d", want: "abcd"},
		{in: "1 < 2 <3", want: "1 < 2 <3"},
		{in: "<a href=\"x>y\">link</a>", want: "link"},
		{in: "&lt;b&gt; &amp;", want: "<b> &"},
		{in: "<BR/>x<Div>y", want: " x y"},
	}
	for _, c := range cases {
		if got := searchOracleStripHtml(c.in); got != c.want {
			t.Errorf("strip(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSearchOracleDecodesHeaders(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte("héllo")) + "?=", want: "héllo"},
		{in: "=?iso-8859-1?q?caf=E9?= =?iso-8859-1?q?_au_lait?=", want: "café au lait"},
		{in: "a =?utf-8?q?b?= c", want: "a b c"},
		{in: "=?utf-8?x?bad?= ok", want: "=?utf-8?x?bad?= ok"},
		{in: "=?windows-1252?q?=80?=", want: "€"},
	}
	for _, c := range cases {
		if got := searchOracleDecodeWords(c.in); got != c.want {
			t.Errorf("decode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	mediaType, params := searchOracleParseParams("attachment; filename*0*=utf-8''r%C3%A9; filename*1=\"sum.pdf\"; name=\"a;b\"")
	if mediaType != "attachment" || params["filename"] != "résum.pdf" || params["name"] != "a;b" {
		t.Errorf("parameters = %q %q", mediaType, params)
	}
}

func TestSearchOracleSniffsFiles(t *testing.T) {
	cases := []struct {
		in   []byte
		text bool
	}{
		{in: []byte("plain text"), text: true},
		{in: []byte("bin\x00ary"), text: false},
		{in: []byte("bad \xff utf-8"), text: false},
		{in: append(bytes.Repeat([]byte("a"), 7999), 0xE6, 0x97, 0xA5), text: true},
		{in: append(bytes.Repeat([]byte("a"), 7998), 0xE6, 0x97, 0xA5), text: true},
		{in: append([]byte{0xFE, 0xFF}, 0, 'h', 0, 'i'), text: true},
	}
	for i, c := range cases {
		if _, text := searchOracleSniff(c.in); text != c.text {
			t.Errorf("case %d: text %v, want %v", i, text, c.text)
		}
	}
	if documents := searchOracleFileDocuments("big.txt", bytes.Repeat([]byte("abcdefgh\n"), 300000)); len(documents) != 3 {
		t.Errorf("a 2.6 MiB file is %d documents, want 3", len(documents))
	}
}

// The identifiers a root file named evs_index_* or search_* declares: its top-level names, and the
// methods it declares on exported types that no other root file declares. A method of an unexported
// type is reachable from this package only through an interface another file declares, or through a
// value an index function gave, which the names catch.
func searchIndexDeclarations(t *testing.T, rootDir string) (map[string]bool, map[string]bool) {
	fileSet := token.NewFileSet()
	entries, err := os.ReadDir(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	indexMethods := map[string]bool{}
	otherMethods := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		index := strings.HasPrefix(name, "evs_index_") || strings.HasPrefix(name, "search_")
		file, err := parser.ParseFile(fileSet, filepath.Join(rootDir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				receiver := ""
				if decl.Recv != nil && 0 < len(decl.Recv.List) {
					receiverType := decl.Recv.List[0].Type
					if star, ok := receiverType.(*ast.StarExpr); ok {
						receiverType = star.X
					}
					if generic, ok := receiverType.(*ast.IndexExpr); ok {
						receiverType = generic.X
					}
					if ident, ok := receiverType.(*ast.Ident); ok {
						receiver = ident.Name
					}
				}
				switch {
				case decl.Recv != nil && index && ast.IsExported(receiver):
					indexMethods[decl.Name.Name] = true
				case decl.Recv != nil && index:
				case decl.Recv != nil:
					otherMethods[decl.Name.Name] = true
				case index:
					names[decl.Name.Name] = true
				}
			case *ast.GenDecl:
				if !index {
					continue
				}
				for _, spec := range decl.Specs {
					switch spec := spec.(type) {
					case *ast.TypeSpec:
						names[spec.Name.Name] = true
					case *ast.ValueSpec:
						for _, ident := range spec.Names {
							names[ident.Name] = true
						}
					}
				}
			}
		}
	}
	for method := range otherMethods {
		delete(indexMethods, method)
	}
	return names, indexMethods
}

// What the oracle's sources reach of the index: imports outside the allowed set, root identifiers
// declared in index files, and methods only index files declare.
func searchOracleIndexFindings(t *testing.T, sources map[string][]byte, indexNames map[string]bool, indexMethods map[string]bool) []string {
	allowed := func(path string) bool {
		switch {
		case !strings.Contains(strings.Split(path, "/")[0], "."):
			// the standard library
			return true
		case path == "github.com/urnetwork/sidecar", path == "github.com/urnetwork/sidecar/protocol",
			path == "github.com/urnetwork/sidecar/protocol/bridge":
			return true
		case strings.HasPrefix(path, "golang.org/x/text/"):
			return true
		}
		return false
	}
	findings := []string{}
	fileSet := token.NewFileSet()
	ownNames := map[string]bool{}
	files := map[string]*ast.File{}
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for name := range sources {
			if !yield(name) {
				return
			}
		}
	}) {
		file, err := parser.ParseFile(fileSet, name, sources[name], parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = file
		ast.Inspect(file, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.FuncDecl:
				ownNames[node.Name.Name] = true
			case *ast.Field:
				for _, ident := range node.Names {
					ownNames[ident.Name] = true
				}
			}
			return true
		})
	}
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for name := range files {
			if !yield(name) {
				return
			}
		}
	}) {
		file := files[name]
		rootName := ""
		for _, spec := range file.Imports {
			path, _ := strconv.Unquote(spec.Path.Value)
			if !allowed(path) {
				findings = append(findings, name+" imports "+path)
			}
			if path == "github.com/urnetwork/sidecar" {
				rootName = "sidecar"
				if spec.Name != nil {
					rootName = spec.Name.Name
				}
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if ident, ok := selector.X.(*ast.Ident); ok && ident.Name == rootName && indexNames[selector.Sel.Name] {
				findings = append(findings, name+" uses sidecar."+selector.Sel.Name+", an index file's")
			} else if indexMethods[selector.Sel.Name] && !ownNames[selector.Sel.Name] {
				findings = append(findings, name+" calls ."+selector.Sel.Name+", a method only index files declare")
			}
			return true
		})
	}
	return findings
}

func TestSearchOracleImportsNoIndexCode(t *testing.T) {
	indexNames, indexMethods := searchIndexDeclarations(t, "..")
	if len(indexNames) == 0 {
		t.Fatal("no index declarations found in the root: the check would pass vacuously")
	}
	sources := map[string][]byte{}
	for _, name := range searchOracleFiles {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		sources[name] = source
	}
	if findings := searchOracleIndexFindings(t, sources, indexNames, indexMethods); len(findings) != 0 {
		t.Errorf("the oracle reaches index code: %v", findings)
	}
}

// The check catches an oracle file that links an index file's identifier or imports an index package.
func TestSearchOracleImportCheckCatchesIndexCode(t *testing.T) {
	indexNames, indexMethods := searchIndexDeclarations(t, "..")
	indexName := slices.Sorted(func(yield func(string) bool) {
		for name := range indexNames {
			if !yield(name) {
				return
			}
		}
	})[0]
	planted := map[string][]byte{
		"search_oracle_planted.go": []byte("package sidecartest\n\nimport \"github.com/urnetwork/sidecar\"\n\nvar planted = sidecar." + indexName + "\n"),
		"search_oracle_index.go":   []byte("package sidecartest\n\nimport _ \"github.com/urnetwork/sidecar/evsindex\"\n"),
	}
	findings := searchOracleIndexFindings(t, planted, indexNames, indexMethods)
	if len(findings) != 2 {
		t.Errorf("findings %v, want the planted identifier %s and the planted import", findings, indexName)
	}
}

func TestSearchCorpusDeterministic(t *testing.T) {
	render := func(corpus *SearchCorpus) string {
		var out strings.Builder
		out.WriteString(corpus.NetworkId.String() + corpus.Mailbox.RepoId.String() + corpus.Notes.RepoId.String())
		for _, step := range corpus.Steps {
			out.WriteString(step.At.Format(time.RFC3339Nano))
			if step.Cover != nil {
				out.WriteString("cover " + strconv.FormatUint(step.Cover.RefVersion, 10))
				continue
			}
			commit := step.Commit
			out.WriteString(commit.RefId.String() + strconv.FormatUint(commit.RefVersion, 10) + commit.WriterId.String() + strconv.FormatBool(commit.Indexed))
			for _, change := range commit.Changes {
				out.WriteString(change.Path + strconv.FormatUint(change.Version, 10))
				out.Write(change.Content)
			}
		}
		return out.String()
	}
	first := render(NewSearchCorpus(DefaultSearchCorpusSettings()))
	if second := render(NewSearchCorpus(DefaultSearchCorpusSettings())); first != second {
		t.Error("one seed gave two corpora")
	}
	settings := DefaultSearchCorpusSettings()
	settings.Seed = 2
	if render(NewSearchCorpus(settings)) == first {
		t.Error("two seeds gave one corpus")
	}
	set := func() []string {
		queries := []string{}
		for _, query := range NewSearchQuerySet(NewSearchCorpus(DefaultSearchCorpusSettings()), 7, 20).Queries {
			queries = append(queries, query.Class+":"+query.Text)
		}
		return queries
	}
	if !slices.Equal(set(), set()) {
		t.Error("one seed gave two query sets")
	}
}

func TestSearchCorpusCoversEachEdgeClass(t *testing.T) {
	corpus := NewSearchCorpus(DefaultSearchCorpusSettings())
	want := []string{"create", "edit", "rename", "delete", "recreate", "skip", "rfc2047", "rfc2231"}
	for _, class := range searchCorpusClasses {
		want = append(want, class.name)
	}
	want = append(want, searchCorpusMimeForms...)
	for _, name := range want {
		if corpus.Classes[name] == 0 {
			t.Errorf("no %s in the corpus: %v", name, corpus.Classes)
		}
	}
	first, last := corpus.Steps[0].At, corpus.Steps[len(corpus.Steps)-1].At
	if span := last.Sub(first); span < 190*24*time.Hour || 201*24*time.Hour < span {
		t.Errorf("the corpus spans %s, not FS-76's 200 days", span)
	}
	writers := map[sidecar.Id]bool{}
	for _, step := range corpus.Steps {
		if step.Commit != nil {
			writers[step.Commit.WriterId] = true
		}
	}
	if len(writers) != 4 {
		t.Errorf("%d writers, want FS-76's four", len(writers))
	}
}

// Every form of the query set is drawn, within 256 normalized bytes a term, and finds a document of the
// corpus, which the oracle judges at its end.
func TestSearchQuerySetFindsTheCorpus(t *testing.T) {
	corpus := NewSearchCorpus(DefaultSearchCorpusSettings())
	keys, err := corpus.Keys(t.Context(), NewFakeClock(DefaultClockStart()))
	if err != nil {
		t.Fatal(err)
	}
	ledger := NewSearchLedger()
	if err := corpus.Apply(ledger, keys); err != nil {
		t.Fatal(err)
	}
	oracle := NewSearchOracle(ledger)
	scope := &SearchScope{Partitions: SearchScopeAll, Breadth: SearchBreadthNetwork, NetworkIds: []sidecar.Id{corpus.NetworkId}, ReaderId: corpus.WriterIds[0]}
	if covered := oracle.Covered(scope); len(covered) == 0 {
		t.Fatal("the corpus covers nothing")
	}
	found := map[string]int{}
	for _, query := range NewSearchQuerySet(corpus, 7, 20).Queries {
		if 256 < len(searchOracleNormalize([]byte(query.Text))) {
			t.Errorf("%q passes 256 normalized bytes", query.Text)
		}
		if 0 < len(oracle.Matches(query.Text, scope)) {
			found[query.Class] += 1
		}
	}
	for _, class := range []string{"word", "prefix", "infix", "phrase", "cjk1", "cjk2", "address"} {
		if found[class] == 0 {
			t.Errorf("no %s query finds a document: %v", class, found)
		}
	}
}

func TestNetSearchOracleReadsItsLedger(t *testing.T) {
	net := NewNet(t.Context(), nil)
	defer net.Close()
	if net.SearchOracle() != net.SearchOracle() || net.SearchOracle().ledger != net.SearchLedger() {
		t.Fatal("the Net's oracle is not one oracle over its ledger")
	}
	corpus := NewSearchCorpus(&SearchCorpusSettings{Seed: 3, Start: DefaultClockStart(), Span: 10 * 24 * time.Hour, WriterCount: 2, MessageCount: 4, NoteCount: 4, BackfillDelay: 10 * time.Minute})
	keys, err := corpus.Keys(t.Context(), net.Clock())
	if err != nil {
		t.Fatal(err)
	}
	if err := corpus.Apply(net.SearchLedger(), keys); err != nil {
		t.Fatal(err)
	}
	scope := &SearchScope{Partitions: SearchScopeAll, NetworkIds: []sidecar.Id{corpus.NetworkId}, ReaderId: corpus.WriterIds[1]}
	if got := net.SearchOracle().Covered(scope); len(got) != 8 {
		t.Errorf("Covered = %d documents, want the corpus's 8", len(got))
	}
}
