// FS-76's corpus and query set (D-TEST-14): mail and notes written by four writers over 200 days of
// fake clock, with edits, renames, deletions, re-creations and commits that skip the index, every text
// drawn from the edge classes FS-76 names, all from one seed; and the queries a schedule runs against
// it, drawn from its own texts. Names and addresses are synthetic, under .example domains (CODESTYLE's
// test data rule).
//
// A corpus is a timeline of steps: commits, and the backfill that covers each commit that skipped the
// index BackfillDelay later. Apply replays it into a SearchLedger as if every push committed when
// written; a schedule instead drives real writers through the same steps and records what commits.
//
// Like the oracle, this file reads no root evs_index_ or search_ file.

package sidecartest

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"mime/quotedprintable"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

type SearchCorpusSettings struct {
	Seed int64
	// Where the first commit is.
	Start time.Time
	// How long the commits span: FS-76's 200 days.
	Span        time.Duration
	WriterCount int
	// Mail messages delivered, and notes created, over the span.
	MessageCount int
	NoteCount    int
	// Later commits to notes: edits, renames, deletions and re-creations.
	ChangeCount int
	// Of every 100 commits, how many skip the index, left to the backfill.
	SkipPercent int
	// How long after a commit that skipped the index its backfill lands: §11.14's 10 min.
	BackfillDelay time.Duration
}

func DefaultSearchCorpusSettings() *SearchCorpusSettings {
	return &SearchCorpusSettings{
		Seed:          1,
		Start:         DefaultClockStart(),
		Span:          200 * 24 * time.Hour,
		WriterCount:   4,
		MessageCount:  120,
		NoteCount:     60,
		ChangeCount:   120,
		SkipPercent:   10,
		BackfillDelay: 10 * time.Minute,
	}
}

type SearchCorpus struct {
	Settings  *SearchCorpusSettings
	NetworkId sidecar.Id
	WriterIds []sidecar.Id
	// Its messages' repo, whose ref holds m/ files, and its notes' general repo.
	Mailbox *SearchCorpusRepo
	Notes   *SearchCorpusRepo
	Steps   []*SearchCorpusStep
	// How many texts hold each edge class and how many commits each operation made, by name.
	Classes map[string]int

	// the corpus's member, for keys
	memberId sidecar.Id
	// each phrase the texts hold, by class, for the query set
	classPhrases map[string][]string
}

type SearchCorpusRepo struct {
	RepoId sidecar.Id
	Kind   protocol.RepoKind
	RefId  sidecar.Id
}

// A commit, or the backfill of commits that skipped the index.
type SearchCorpusStep struct {
	At     time.Time
	Commit *SearchCommit
	Cover  *SearchCorpusCover
}

// A backfill: an index push reaching every commit of a ref through RefVersion.
type SearchCorpusCover struct {
	RepoId     sidecar.Id
	RefId      sidecar.Id
	RefVersion uint64
}

// One edge class: phrases a text may draw, in their source forms.
type searchCorpusClass struct {
	name    string
	phrases []string
}

// FS-76's edge classes. Combining forms are written decomposed where the class is about the marks.
var searchCorpusClasses = []*searchCorpusClass{
	{name: "ascii", phrases: []string{
		"quarterly budget review", "project timeline", "deployment checklist", "meeting notes",
		"customer feedback", "release candidate", "performance regression", "database migration",
		"security audit", "holiday schedule", "onboarding guide", "incident postmortem",
		"design document", "search index", "trigram postings", "encrypted storage",
	}},
	{name: "cjk", phrases: []string{
		"日本語の漢字", "東京都の天気", "ひらがなとカタカナ", "検索エンジン", "北京大学", "数据库迁移",
		"搜索引擎", "한국어 검색", "서울 날씨", "会議の議事録",
	}},
	{name: "combining", phrases: []string{
		"café au lait", "naïve approach", "Ångström units", "Tiếng Viẹt",
		"हिन्दी भाषा", "กินข้าว", "שָׁלוֹם עֲלֵיכֶם", "مَرْحَبًا", "Ελληνικά́", "ǫ́sma",
	}},
	{name: "nfkc", phrases: []string{
		"ﬁnance ﬂow", "ＦＵＬＬＷＩＤＴＨ letters", "x² plus y³",
		"①②③ steps", "chapter Ⅻ", "ｶﾀｶﾅ", "weight 5㎏", "Ω resistance",
	}},
	{name: "casefold", phrases: []string{
		"STRASSE and Straße", "ΣΊΣΥΦΟΣ σίσυφος", "İstanbul ISTANBUL", "Kelvin scale",
		"ᏣᎳᎩ ꮳꮃꭹ", "ǅungla title", "ǅ ǆ Ǆ", "MASSE maße",
	}},
	{name: "punctuation", phrases: []string{
		"e-mail re:re:re: subject", "foo---bar...baz", "a.b.c.d", "wait!!! really???", "(parenthesized) [bracketed]",
		"C++ and C#", "#hashtag @mention", "$100.00 – €50,00", "path/to/file.txt", "semi;colon:separated",
	}},
	{name: "address", phrases: []string{
		"alice@example.com", "bob.smith+tag@mail.example.org", "carol_oneil@example.net",
		"dave.d@sub.example.com", "erin-r@example.org", "frank@corp.example",
	}},
}

// The class whose phrases are addresses, which mail headers draw.
const searchCorpusAddressClass = "address"

// A corpus from settings, all of it a function of settings.Seed.
func NewSearchCorpus(settings *SearchCorpusSettings) *SearchCorpus {
	if settings == nil {
		settings = DefaultSearchCorpusSettings()
	}
	random := rand.New(rand.NewPCG(uint64(settings.Seed), uint64(settings.Seed)^0x5eed5eed5eed5eed))
	id := func() sidecar.Id {
		var bytes [16]byte
		for i := range bytes {
			bytes[i] = byte(random.UintN(256))
		}
		return sidecar.Id(bytes)
	}
	corpus := &SearchCorpus{
		Settings:     settings,
		NetworkId:    id(),
		memberId:     id(),
		Classes:      map[string]int{},
		classPhrases: map[string][]string{},
	}
	for range settings.WriterCount {
		corpus.WriterIds = append(corpus.WriterIds, id())
	}
	corpus.Mailbox = &SearchCorpusRepo{RepoId: id(), Kind: protocol.RepoKind_REPO_KIND_MAILBOX, RefId: id()}
	corpus.Notes = &SearchCorpusRepo{RepoId: id(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, RefId: id()}
	writer := &searchCorpusWriter{corpus: corpus, random: random, pathVersions: map[string]uint64{}, refVersions: map[sidecar.Id]uint64{}}
	writer.write()
	return corpus
}

// The state of a corpus as it is written.
type searchCorpusWriter struct {
	corpus *SearchCorpus
	random *rand.Rand
	// each path's newest version, removals included, so a re-creation continues it
	pathVersions map[string]uint64
	refVersions  map[sidecar.Id]uint64
	// live notes' paths, and removed ones a re-creation may bring back
	livePaths    []string
	removedPaths []string
	noteSeq      int
	messageSeq   int
}

// Picks a phrase of a class and remembers it for the query set; a text holding it counts for its class.
func (self *searchCorpusWriter) phrase(class *searchCorpusClass) string {
	phrase := class.phrases[self.random.IntN(len(class.phrases))]
	if !slices.Contains(self.corpus.classPhrases[class.name], phrase) {
		self.corpus.classPhrases[class.name] = append(self.corpus.classPhrases[class.name], phrase)
	}
	return phrase
}

// A text of a few sentences, each drawing one class's phrase, its classes counted once.
func (self *searchCorpusWriter) text(sentences int) string {
	used := map[string]bool{}
	lines := []string{}
	for range sentences {
		class := searchCorpusClasses[self.random.IntN(len(searchCorpusClasses))]
		used[class.name] = true
		ascii := self.phrase(searchCorpusClasses[0])
		lines = append(lines, fmt.Sprintf("%s: %s.", ascii, self.phrase(class)))
	}
	used["ascii"] = true
	for name := range used {
		self.corpus.Classes[name] += 1
	}
	return strings.Join(lines, "\n")
}

func (self *searchCorpusWriter) count(name string) {
	self.corpus.Classes[name] += 1
}

func (self *searchCorpusWriter) write() {
	settings := self.corpus.Settings
	total := settings.MessageCount + settings.NoteCount + settings.ChangeCount
	if total == 0 {
		return
	}
	step := settings.Span / time.Duration(total)
	kinds := []string{}
	for range settings.MessageCount {
		kinds = append(kinds, "message")
	}
	for range settings.NoteCount {
		kinds = append(kinds, "note")
	}
	for range settings.ChangeCount {
		kinds = append(kinds, "change")
	}
	self.random.Shuffle(len(kinds), func(i int, j int) { kinds[i], kinds[j] = kinds[j], kinds[i] })
	covers := []*SearchCorpusStep{}
	for i, kind := range kinds {
		at := settings.Start.Add(time.Duration(i)*step + time.Duration(self.random.Int64N(int64(max(step, 1)))))
		var commit *SearchCommit
		switch {
		case kind == "message":
			commit = self.message(at)
		case kind == "note" || len(self.livePaths) == 0:
			commit = self.note(at)
		default:
			commit = self.change(at)
		}
		if self.random.IntN(100) < settings.SkipPercent {
			commit.Indexed = false
			self.count("skip")
			covers = append(covers, &SearchCorpusStep{
				At: at.Add(settings.BackfillDelay),
				Cover: &SearchCorpusCover{
					RepoId:     commit.RepoId,
					RefId:      commit.RefId,
					RefVersion: commit.RefVersion,
				},
			})
		}
		self.corpus.Steps = append(self.corpus.Steps, &SearchCorpusStep{At: at, Commit: commit})
	}
	self.corpus.Steps = append(self.corpus.Steps, covers...)
	slices.SortStableFunc(self.corpus.Steps, func(a *SearchCorpusStep, b *SearchCorpusStep) int {
		return a.At.Compare(b.At)
	})
}

// A commit of changes to repo's ref, at its next ref version.
func (self *searchCorpusWriter) commit(repo *SearchCorpusRepo, at time.Time, changes ...*SearchChange) *SearchCommit {
	self.refVersions[repo.RefId] += 1
	return &SearchCommit{
		RepoId:     repo.RepoId,
		RefId:      repo.RefId,
		RefVersion: self.refVersions[repo.RefId],
		Time:       at,
		WriterId:   self.corpus.WriterIds[self.random.IntN(len(self.corpus.WriterIds))],
		Changes:    changes,
		Indexed:    true,
	}
}

// path's next version, continuing past a removal (§11.7's versions).
func (self *searchCorpusWriter) change(at time.Time) *SearchCommit {
	switch roll := self.random.IntN(100); {
	case roll < 50:
		return self.edit(at)
	case roll < 65:
		return self.rename(at)
	case roll < 85 || len(self.removedPaths) == 0:
		return self.remove(at)
	default:
		return self.recreate(at)
	}
}

func (self *searchCorpusWriter) version(path string) uint64 {
	self.pathVersions[path] += 1
	return self.pathVersions[path]
}

func (self *searchCorpusWriter) noteContent(title string) []byte {
	return []byte(fmt.Sprintf("# %s\n\n%s\n", title, self.text(2+self.random.IntN(4))))
}

func (self *searchCorpusWriter) note(at time.Time) *SearchCommit {
	self.noteSeq += 1
	path := fmt.Sprintf("notes/%03d-%s.md", self.noteSeq, strings.ReplaceAll(self.phrase(searchCorpusClasses[0]), " ", "-"))
	title := self.phrase(searchCorpusClasses[self.random.IntN(len(searchCorpusClasses))])
	self.livePaths = append(self.livePaths, path)
	self.count("create")
	return self.commit(self.corpus.Notes, at, &SearchChange{Path: path, Version: self.version(path), Content: self.noteContent(title)})
}

func (self *searchCorpusWriter) pickLive() (string, int) {
	index := self.random.IntN(len(self.livePaths))
	return self.livePaths[index], index
}

// Appends sentences to a note, or rewrites its body.
func (self *searchCorpusWriter) edit(at time.Time) *SearchCommit {
	path, _ := self.pickLive()
	self.count("edit")
	content := self.noteContent(self.phrase(searchCorpusClasses[0]))
	return self.commit(self.corpus.Notes, at, &SearchChange{Path: path, Version: self.version(path), Content: content})
}

// A removal and a creation in one push (§11.14's key row).
func (self *searchCorpusWriter) rename(at time.Time) *SearchCommit {
	path, index := self.pickLive()
	self.noteSeq += 1
	renamed := fmt.Sprintf("notes/%03d-renamed.md", self.noteSeq)
	self.livePaths[index] = renamed
	self.removedPaths = append(self.removedPaths, path)
	self.count("rename")
	return self.commit(self.corpus.Notes, at,
		&SearchChange{Path: path, Version: self.version(path)},
		&SearchChange{Path: renamed, Version: self.version(renamed), Content: self.noteContent(self.phrase(searchCorpusClasses[0]))},
	)
}

func (self *searchCorpusWriter) remove(at time.Time) *SearchCommit {
	path, index := self.pickLive()
	self.livePaths = slices.Delete(self.livePaths, index, index+1)
	self.removedPaths = append(self.removedPaths, path)
	self.count("delete")
	return self.commit(self.corpus.Notes, at, &SearchChange{Path: path, Version: self.version(path)})
}

// A removed path written again: its version continues past its removal.
func (self *searchCorpusWriter) recreate(at time.Time) *SearchCommit {
	index := self.random.IntN(len(self.removedPaths))
	path := self.removedPaths[index]
	self.removedPaths = slices.Delete(self.removedPaths, index, index+1)
	self.livePaths = append(self.livePaths, path)
	self.count("recreate")
	return self.commit(self.corpus.Notes, at, &SearchChange{Path: path, Version: self.version(path), Content: self.noteContent(self.phrase(searchCorpusClasses[0]))})
}

// The MIME forms a message takes, each an FS-76 edge class.
var searchCorpusMimeForms = []string{
	"mime-plain", "mime-base64", "mime-qp", "mime-html", "mime-alternative", "mime-attachment", "mime-latin1",
}

// A delivered message at m/<n>: headers with RFC 2047 words and a body in one of the MIME forms.
func (self *searchCorpusWriter) message(at time.Time) *SearchCommit {
	self.messageSeq += 1
	path := fmt.Sprintf("m/%06d", self.messageSeq)
	addresses := self.corpusClass(searchCorpusAddressClass)
	from := self.phrase(addresses)
	to := []string{}
	for range 1 + self.random.IntN(3) {
		to = append(to, self.phrase(addresses))
	}
	subject := self.phrase(searchCorpusClasses[self.random.IntN(len(searchCorpusClasses))])
	headers := []string{
		"Message-ID: <" + path[2:] + "@corpus.example>",
		fmt.Sprintf("Date: %s", at.UTC().Format(time.RFC1123Z)),
		fmt.Sprintf("From: \"%s\" <%s>", strings.ToUpper(from[:1])+from[1:strings.Index(from, "@")], from),
		"To: " + strings.Join(to, ", "),
		"MIME-Version: 1.0",
		"Received: from relay.example by mx.example; " + at.UTC().Format(time.RFC1123Z),
	}
	if self.random.IntN(3) == 0 {
		headers = append(headers, "Cc: "+self.phrase(addresses))
	}
	switch self.random.IntN(3) {
	case 0:
		headers = append(headers, "Subject: =?UTF-8?B?"+base64.StdEncoding.EncodeToString([]byte(subject))+"?=")
		self.count("rfc2047")
	case 1:
		headers = append(headers, "Subject: =?utf-8?q?"+searchCorpusQEncode(subject)+"?=")
		self.count("rfc2047")
	default:
		headers = append(headers, "Subject: "+subject)
	}
	body := self.text(2 + self.random.IntN(4))
	form := searchCorpusMimeForms[self.random.IntN(len(searchCorpusMimeForms))]
	self.count(form)
	var content string
	switch form {
	case "mime-plain":
		content = searchCorpusMessage(headers, "Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: 8bit", body)
	case "mime-base64":
		content = searchCorpusMessage(headers, "Content-Type: text/plain; charset=UTF-8", "Content-Transfer-Encoding: base64", searchCorpusBase64(body))
	case "mime-qp":
		content = searchCorpusMessage(headers, "Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: quoted-printable", searchCorpusQuotedPrintable([]byte(body)))
	case "mime-html":
		content = searchCorpusMessage(headers, "Content-Type: text/html; charset=utf-8", "Content-Transfer-Encoding: 8bit", searchCorpusHtml(body))
	case "mime-alternative":
		content = strings.Join(append(headers,
			"Content-Type: multipart/alternative; boundary=\"alt-boundary\"",
			"",
			"This is a multi-part message in MIME format.",
			"--alt-boundary",
			"Content-Type: text/plain; charset=utf-8",
			"Content-Transfer-Encoding: quoted-printable",
			"",
			searchCorpusQuotedPrintable([]byte(body)),
			"--alt-boundary",
			"Content-Type: text/html; charset=utf-8",
			"Content-Transfer-Encoding: base64",
			"",
			searchCorpusBase64(searchCorpusHtml(body)),
			"--alt-boundary--",
			"",
		), "\r\n")
	case "mime-attachment":
		name := strings.ReplaceAll(self.phrase(searchCorpusClasses[self.random.IntN(len(searchCorpusClasses))]), " ", "_") + ".pdf"
		self.count("rfc2231")
		attachment := []byte{0x25, 0x50, 0x44, 0x46, 0x00, 0x01, 0xFF, 0xFE}
		content = strings.Join(append(headers,
			"Content-Type: multipart/mixed; boundary=mixed-boundary",
			"",
			"--mixed-boundary",
			"Content-Type: text/plain; charset=utf-8",
			"",
			body,
			"--mixed-boundary",
			"Content-Type: application/pdf",
			"Content-Disposition: attachment; filename*=utf-8''"+searchCorpusPercentEncode(name),
			"Content-Transfer-Encoding: base64",
			"",
			base64.StdEncoding.EncodeToString(attachment),
			"--mixed-boundary--",
			"",
		), "\r\n")
	case "mime-latin1":
		// only text Latin-1 can carry; the rest of the body stays in UTF-8 parts elsewhere
		latin := "Résumé du café: " + self.phrase(searchCorpusClasses[0])
		content = searchCorpusMessage(headers, "Content-Type: text/plain; charset=iso-8859-1", "Content-Transfer-Encoding: quoted-printable", searchCorpusQuotedPrintable(searchCorpusLatin1(latin)))
	}
	return self.commit(self.corpus.Mailbox, at, &SearchChange{Path: path, Version: self.version(path), Content: []byte(content)})
}

func (self *searchCorpusWriter) corpusClass(name string) *searchCorpusClass {
	for _, class := range searchCorpusClasses {
		if class.name == name {
			return class
		}
	}
	panic(fmt.Sprintf("search corpus: no class %q", name))
}

// A single-part message: headers, then the part's own, then its body.
func searchCorpusMessage(headers []string, contentType string, encoding string, body string) string {
	return strings.Join(append(slices.Clone(headers), contentType, encoding, "", body, ""), "\r\n")
}

func searchCorpusBase64(text string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(text))
	lines := []string{}
	for 76 < len(encoded) {
		lines = append(lines, encoded[:76])
		encoded = encoded[76:]
	}
	return strings.Join(append(lines, encoded), "\r\n")
}

func searchCorpusQuotedPrintable(raw []byte) string {
	var out strings.Builder
	writer := quotedprintable.NewWriter(&out)
	writer.Write(raw)
	writer.Close()
	return out.String()
}

// RFC 2047's Q form: '_' for a space, =XX for every byte but letters and digits.
func searchCorpusQEncode(text string) string {
	var out strings.Builder
	for _, c := range []byte(text) {
		switch {
		case c == ' ':
			out.WriteByte('_')
		case c < 0x80 && (unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c))):
			out.WriteByte(c)
		default:
			fmt.Fprintf(&out, "=%02X", c)
		}
	}
	return out.String()
}

// RFC 2231's %-encoding of every byte but unreserved ones.
func searchCorpusPercentEncode(text string) string {
	var out strings.Builder
	for _, c := range []byte(text) {
		if c < 0x80 && (unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c)) || c == '.' || c == '-' || c == '_') {
			out.WriteByte(c)
		} else {
			fmt.Fprintf(&out, "%%%02X", c)
		}
	}
	return out.String()
}

// text composed (é as U+00E9) and written as Latin-1, its characters past U+00FF as '?'.
func searchCorpusLatin1(text string) []byte {
	composed := strings.NewReplacer("é", "é", "É", "É").Replace(text)
	out := []byte{}
	for _, r := range composed {
		if r <= 0xFF {
			out = append(out, byte(r))
		} else {
			out = append(out, '?')
		}
	}
	return out
}

// text as HTML: a heading, a script and a style that must not be indexed, a comment, entities and
// paragraph tags around each line.
func searchCorpusHtml(text string) string {
	var out strings.Builder
	out.WriteString("<!DOCTYPE html><html><head><style>p { color: red; } .hidden-style-word {}</style>")
	out.WriteString("<script type=\"text/javascript\">var hiddenScriptWord = \"<p>\";</script></head><body>")
	out.WriteString("<!-- a hidden comment word -->")
	for _, line := range strings.Split(text, "\n") {
		out.WriteString("<p class=\"line\" data-x='a>b'>")
		out.WriteString(strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(line))
		out.WriteString("</p>")
	}
	out.WriteString("<br/><b>bold</b>text &amp; more</body></html>")
	return out.String()
}

// Keys for the corpus's repos from a fresh FakeGkm, as its writers would hold them: one group a repo,
// every writer a member device reading and writing both, created by the first writer. Each key holds
// RK_1, so K_ref derives.
func (self *SearchCorpus) Keys(ctx context.Context, clock Clock) (map[sidecar.Id]*sidecar.EvsRepoKey, error) {
	return searchCorpusKeys(ctx, clock, self.memberId, self.WriterIds, []*SearchCorpusRepo{self.Mailbox, self.Notes})
}

// Keys for repos from a fresh FakeGkm, every writer a member device of memberId reading and writing each,
// each group created by the first writer.
func searchCorpusKeys(ctx context.Context, clock Clock, memberId sidecar.Id, writerIds []sidecar.Id, repos []*SearchCorpusRepo) (map[sidecar.Id]*sidecar.EvsRepoKey, error) {
	blobs := NewFakeBlobs(clock, nil, nil, nil)
	gkm := NewFakeGkm(clock, blobs, nil)
	log := NewFakeGkmAuthLog()
	aclRepos := []*protocol.AclRepo{}
	for _, repo := range repos {
		aclRepos = append(aclRepos, &protocol.AclRepo{RepoId: repo.RepoId.Bytes(), Kind: repo.Kind})
	}
	fixture := &FakeGkmAuthFixture{
		Rows:         FakeGkmAuthRows(aclRepos...),
		IdentityKeys: map[sidecar.Id][]byte{},
		RepoReaders:  map[sidecar.Id][]sidecar.Id{},
		RepoWriters:  map[sidecar.Id][]sidecar.Id{},
	}
	signers := []*FakeGkmSigner{}
	for _, writerId := range writerIds {
		signer := NewFakeGkmSigner()
		signer.SidecarId = writerId
		signers = append(signers, signer)
		fixture.IdentityKeys[writerId] = signer.PublicKey()
	}
	sidecarRows, memberRow := FakeGkmAuthMemberDevices(memberId, writerIds...)
	fixture.Rows.Sidecars = sidecarRows
	fixture.Rows.Members = []*bridge.MemberRow{memberRow}
	for _, repo := range repos {
		fixture.RepoReaders[repo.RepoId] = slices.Clone(writerIds)
		fixture.RepoWriters[repo.RepoId] = slices.Clone(writerIds)
	}
	view := log.Append(fixture)
	clients := []sidecar.GkmClient{}
	for _, signer := range signers {
		client := gkm.Client(signer.SidecarId, signer.Sign)
		client.AuthAdvanced(view)
		clients = append(clients, client)
	}
	keys := map[sidecar.Id]*sidecar.EvsRepoKey{}
	for _, repo := range repos {
		key, err := clients[0].CreateGroup(ctx, &sidecar.GkmCreateGroupArgs{RepoId: repo.RepoId, Kind: repo.Kind})
		if err != nil {
			return nil, err
		}
		keys[repo.RepoId] = key
	}
	return keys, nil
}

// Replays the corpus into ledger as if every push committed when written: its repos, each read by every
// writer, then each step in time order.
func (self *SearchCorpus) Apply(ledger *SearchLedger, keys map[sidecar.Id]*sidecar.EvsRepoKey) error {
	for _, repo := range []*SearchCorpusRepo{self.Mailbox, self.Notes} {
		err := ledger.AddRepo(&SearchLedgerRepo{
			RepoId:       repo.RepoId,
			NetworkId:    self.NetworkId,
			Kind:         repo.Kind,
			DefaultRefId: repo.RefId,
			Key:          keys[repo.RepoId],
			ReaderIds:    self.WriterIds,
		})
		if err != nil {
			return err
		}
	}
	for _, step := range self.Steps {
		var err error
		if step.Commit != nil {
			err = ledger.Commit(step.Commit)
		} else {
			err = ledger.Cover(step.Cover.RepoId, step.Cover.RefId, step.Cover.RefVersion, step.At)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// A query a schedule runs, and the FS-76 form it exercises: "word", "prefix" (five letters), "infix"
// (four letters), "phrase" (two words), "cjk1", "cjk2" or "address".
type SearchCorpusQuery struct {
	Text  string
	Class string
}

// FS-76's query set over a corpus's texts.
type SearchQuerySet struct {
	Queries []*SearchCorpusQuery
}

// The query set's longest term, normalized: within a chunk's 256 B overlap (plan-SEARCH-small-readings#2).
const searchCorpusQueryTermByteCount = 256

// perClass queries of each form, drawn from corpus's own phrases from seed. A form the corpus gives no
// source for is left out, and every term stays within 256 normalized bytes.
func NewSearchQuerySet(corpus *SearchCorpus, seed int64, perClass int) *SearchQuerySet {
	random := rand.New(rand.NewPCG(uint64(seed), uint64(seed)^0x9e3779b97f4a7c15))
	words := []string{}
	cjk := []string{}
	addresses := slices.Clone(corpus.classPhrases[searchCorpusAddressClass])
	slices.Sort(addresses)
	for _, class := range slices.Sorted(func(yield func(string) bool) {
		for name := range corpus.classPhrases {
			if !yield(name) {
				return
			}
		}
	}) {
		for _, phrase := range corpus.classPhrases[class] {
			for _, word := range strings.Fields(phrase) {
				if class == "cjk" {
					cjk = append(cjk, word)
				}
				if strings.IndexFunc(word, unicode.IsLetter) >= 0 {
					words = append(words, word)
				}
			}
		}
	}
	ascii := []string{}
	for _, phrase := range corpus.classPhrases["ascii"] {
		ascii = append(ascii, strings.Fields(phrase)...)
	}
	slices.Sort(ascii)
	ascii = slices.Compact(ascii)
	set := &SearchQuerySet{}
	add := func(class string, text string) {
		if text == "" || searchCorpusQueryTermByteCount < len(searchOracleNormalize([]byte(text))) {
			return
		}
		set.Queries = append(set.Queries, &SearchCorpusQuery{Text: text, Class: class})
	}
	pick := func(from []string) string {
		if len(from) == 0 {
			return ""
		}
		return from[random.IntN(len(from))]
	}
	long := []string{}
	for _, word := range ascii {
		if 6 <= len(word) {
			long = append(long, word)
		}
	}
	for range perClass {
		add("word", pick(words))
		if word := pick(long); word != "" {
			add("prefix", word[:5])
			start := 1 + random.IntN(len(word)-5)
			add("infix", word[start:start+4])
		}
		if phrase := pick(corpus.classPhrases["ascii"]); phrase != "" {
			fields := strings.Fields(phrase)
			if 2 <= len(fields) {
				i := random.IntN(len(fields) - 1)
				add("phrase", "\""+fields[i]+" "+fields[i+1]+"\"")
			}
		}
		if word := []rune(pick(cjk)); 2 <= len(word) {
			i := random.IntN(len(word) - 1)
			add("cjk1", string(word[i]))
			add("cjk2", string(word[i:i+2]))
		}
		add("address", pick(addresses))
	}
	return set
}
