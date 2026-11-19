//go:build !ios_extension

// Mail search on a device (§15.7's search index row and Reads, §16.10; R-MAIL-17, D-MAIL-16, I-19; MAIL-M10-03): mail's
// SearchJoinSource, and MailClient.Search over the member's mailbox and the group repos its r/ references name.
//
//	join      MailSearchJoin answers a hit's seen, flagged, labels and trash from f/ and its spam from the person's
//	          verdict, else i/'s spam_score against the mailbox's threshold, exactly as the message list decides them
//	          (MailView), and nothing of them is stored in the index. It answers from a table in memory: about 19 bytes
//	          a message, its labels beside it where it has any
//	sync      the table is read by Sync, every month the mailbox holds through the same stores the list reads, before
//	          a search starts and never because a query chose a message, so what a search asks shows evs nothing
//	          (I-19). A sync inside RefreshInterval of the last reads nothing unless Invalidate said a write landed. A
//	          message past MessageMaxCount, oldest months first, and a message of a month a sync could not read, joins
//	          as unknown and stays, as search_join.go says of a message the device holds no i/ entry for
//	search    MailClient.Search runs one search on the bound engine (MailBinding.Search, which *Sidecar answers) over
//	          the mailbox and those group repos, leaving out spam and trash unless asked, and gives only mail's hits.
//	          A phone's hit is confirmed by the engine against i/'s subject, address and snippet through
//	          SearchDisplay, and the rest stay possible, labeled so (search_confirm.go). "Search more" asks scope all
//	          with the network's remote mode, so the engine's eligibility (§11.14, FI-24) decides which designated
//	          indexer may see the query: the member's mailbox only on their own consented devices. Without it the
//	          search stays on this device
//
// Nothing here logs a query, a hit, a path or an address (I-13). Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

var (
	// No engine is bound: the host installed none, or the client is bound to no Sidecar.
	ErrMailSearchUnavailable = errors.New("mail search: no search engine is bound")
	// A search with no query.
	ErrMailSearchInvalid = errors.New("mail search: no query")
)

// The join's tunables.
type MailSearchSettings struct {
	// How long a synced table answers before the next search reads the mailbox's i/ and f/ again: 30 s. A write this
	// device hears of (Invalidate) is read at the next search whatever the time.
	RefreshInterval time.Duration
	// The most messages the table holds, newest months first: 1,000,000, about 19 MiB. A message past it joins as
	// unknown.
	MessageMaxCount int
}

// The defaults, a fresh value each call.
func DefaultMailSearchSettings() *MailSearchSettings {
	return &MailSearchSettings{
		RefreshInterval: 30 * time.Second,
		MessageMaxCount: 1000 * 1000,
	}
}

// Whether every value is in range.
func (self *MailSearchSettings) valid() bool {
	return self != nil && 0 <= self.RefreshInterval && 0 < self.MessageMaxCount
}

// What a row keeps of a message's flags.
const (
	mailSearchJoinSeen uint8 = 1 << iota
	mailSearchJoinFlagged
	mailSearchJoinTrash
	mailSearchJoinSpam
)

// One message of the table: 19 bytes.
type mailSearchJoinRow struct {
	id Id
	// the repo holding it, as an index into its month's sources
	source uint16
	flags  uint8
}

// One month of the table.
type mailSearchJoinMonth struct {
	// by id
	rows []mailSearchJoinRow
	// the mailbox, then the group repos the month's r/ references name
	sources []Id
	// the labels of the messages that have any, each sorted
	labels map[Id][]string
}

// What a join is built on.
type MailSearchJoinArgs struct {
	// The stores the member's message list reads: the join reads the same i/, r/ and f/ through a view of its own, so
	// a list being paged keeps its months.
	View *MailViewArgs
	// Nil takes DefaultMailSearchSettings.
	Settings *MailSearchSettings
	// Nil is real time.
	Clock Clock
}

// Mail's SearchJoinSource over one member's message list. See the file header.
type MailSearchJoin struct {
	// the args the join was built on, which name the list it follows
	source   *MailViewArgs
	reader   *MailView
	settings *MailSearchSettings
	clock    Clock

	// held across a sync's reads, so two searches starting together read once; never held with stateLock
	syncLock sync.Mutex

	stateLock sync.Mutex
	months    map[MailYearMonth]*mailSearchJoinMonth
	// the group repos the table's months name, sorted
	groupIds []Id
	synced   bool
	syncedAt time.Time
	// a write landed since the last sync
	stale bool
	// messages the last sync left out past MessageMaxCount
	leftOut int
}

// A join over args' stores, holding nothing until it syncs.
func NewMailSearchJoin(args *MailSearchJoinArgs) (*MailSearchJoin, error) {
	if args == nil || args.View == nil || args.View.Mailbox == nil || args.View.Settings == nil {
		return nil, fmt.Errorf("%w: a mailbox's view", ErrMailClientInvalid)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultMailSearchSettings()
	}
	if !settings.valid() {
		return nil, fmt.Errorf("%w: the mail search join's bounds", errInvalidSettings)
	}
	clock := clockOrReal(args.Clock)
	view := *args.View
	return &MailSearchJoin{
		source: args.View, reader: NewMailView(&view), settings: settings, clock: clock, months: map[MailYearMonth]*mailSearchJoinMonth{},
	}, nil
}

// Says a write landed in the mailbox or one of its group repos, so the next Sync reads again.
func (self *MailSearchJoin) Invalidate() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.stale = true
}

// Whether the table still answers for now.
func (self *MailSearchJoin) fresh() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.synced && !self.stale && self.clock.Now().Sub(self.syncedAt) < self.settings.RefreshInterval
}

// Reads the table: every month's i/, r/ and f/, whatever any search asks. A failed read keeps the table as it was
// and is the caller's error, so a search starts on a join that is whole or not at all.
func (self *MailSearchJoin) Sync(ctx context.Context) error {
	self.syncLock.Lock()
	defer self.syncLock.Unlock()
	if self.fresh() {
		return nil
	}
	// a write that lands while this reads is the next sync's
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.stale = false
	}()
	self.reader.Invalidate()
	defer self.reader.Invalidate()
	monthNames, err := self.reader.listMonths(ctx)
	if err != nil {
		self.Invalidate()
		return err
	}
	months := map[MailYearMonth]*mailSearchJoinMonth{}
	groupIds := []Id{}
	messageCount, leftOut := 0, 0
	for _, month := range monthNames {
		built, err := self.reader.buildMonth(ctx, month)
		if err != nil {
			self.Invalidate()
			return err
		}
		if self.settings.MessageMaxCount < messageCount+len(built.keys) {
			leftOut += len(built.keys)
			continue
		}
		messageCount += len(built.keys)
		joinMonth := &mailSearchJoinMonth{rows: make([]mailSearchJoinRow, 0, len(built.keys)), sources: built.sources}
		for _, position := range built.byId {
			key := built.keys[position]
			flags := built.flags.flags(key.id)
			row := mailSearchJoinRow{id: key.id, source: key.source}
			if flags.Seen {
				row.flags |= mailSearchJoinSeen
			}
			if flags.Flagged {
				row.flags |= mailSearchJoinFlagged
			}
			if flags.Trash {
				row.flags |= mailSearchJoinTrash
			}
			if self.reader.spam(key, flags) {
				row.flags |= mailSearchJoinSpam
			}
			if 0 < len(flags.Labels) {
				if joinMonth.labels == nil {
					joinMonth.labels = map[Id][]string{}
				}
				joinMonth.labels[key.id] = flags.Labels
			}
			joinMonth.rows = append(joinMonth.rows, row)
		}
		months[month] = joinMonth
		for _, repoId := range built.sources[1:] {
			if !slices.Contains(groupIds, repoId) {
				groupIds = append(groupIds, repoId)
			}
		}
	}
	slices.SortFunc(groupIds, mailIdCompare)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.months, self.groupIds, self.leftOut = months, groupIds, leftOut
	self.synced, self.syncedAt = true, self.clock.Now()
	return nil
}

// The repos a member's mail search covers, as the last sync read them: the mailbox, then the group repos its r/
// references name, sorted.
func (self *MailSearchJoin) Repos() []Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]Id{self.reader.args.MailboxId}, self.groupIds...)
}

// The messages the last sync left out past MessageMaxCount, which join as unknown.
func (self *MailSearchJoin) LeftOut() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.leftOut
}

// See SearchJoinSource: the table's answer, from memory alone. A message of another repo than the one the table
// holds it in is not this one.
func (self *MailSearchJoin) MailFlags(ctx context.Context, repoId Id, month MailYearMonth, messageId Id) (*SearchMailFlags, bool, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	joinMonth := self.months[month]
	if joinMonth == nil {
		return nil, false, nil
	}
	index, found := slices.BinarySearchFunc(joinMonth.rows, messageId, func(row mailSearchJoinRow, target Id) int {
		return mailIdCompare(row.id, target)
	})
	if !found {
		return nil, false, nil
	}
	row := joinMonth.rows[index]
	if int(row.source) >= len(joinMonth.sources) || joinMonth.sources[row.source] != repoId {
		return nil, false, nil
	}
	return &SearchMailFlags{
		Seen:    row.flags&mailSearchJoinSeen != 0,
		Flagged: row.flags&mailSearchJoinFlagged != 0,
		Trash:   row.flags&mailSearchJoinTrash != 0,
		Spam:    row.flags&mailSearchJoinSpam != 0,
		Labels:  slices.Clone(joinMonth.labels[messageId]),
	}, true, nil
}

// The mailbox's join, built once a view: a mailbox whose view was made again, at a new binding, takes a new join.
func (self *MailClient) searchJoin() (*MailSearchJoin, error) {
	mailboxId, err := self.mailboxId()
	if err != nil {
		return nil, err
	}
	view, err := self.view()
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if join := self.searchJoins[mailboxId]; join != nil && join.source == view.args {
		return join, nil
	}
	join, err := NewMailSearchJoin(&MailSearchJoinArgs{View: view.args, Settings: self.settings.Search, Clock: self.clock})
	if err != nil {
		return nil, err
	}
	if self.searchJoins == nil {
		self.searchJoins = map[Id]*MailSearchJoin{}
	}
	self.searchJoins[mailboxId] = join
	return join, nil
}

// Says a write landed in the mailbox or a group repo, so the next search's join reads again.
func (self *MailClient) invalidateSearchJoin() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, join := range self.searchJoins {
		join.Invalidate()
	}
}

// The client's joins as the engine asks them: whichever mailbox's table holds the message.
type mailClientSearchJoin struct {
	client *MailClient
}

func (self *mailClientSearchJoin) MailFlags(ctx context.Context, repoId Id, month MailYearMonth, messageId Id) (*SearchMailFlags, bool, error) {
	joins := func() []*MailSearchJoin {
		self.client.stateLock.Lock()
		defer self.client.stateLock.Unlock()
		joins := make([]*MailSearchJoin, 0, len(self.client.searchJoins))
		for _, join := range self.client.searchJoins {
			joins = append(joins, join)
		}
		return joins
	}()
	for _, join := range joins {
		if flags, held, err := join.MailFlags(ctx, repoId, month, messageId); err != nil || held {
			return flags, held, err
		}
	}
	return nil, false, nil
}

// Mail's joins for SearchEngineArgs.Join: the host building the network's engine passes it, and it answers from the
// tables this client's searches synced, whatever mailbox the client is bound to by then.
func (self *MailClient) SearchJoinSource() SearchJoinSource {
	return &mailClientSearchJoin{client: self}
}

// Mail's display fields for SearchEngineArgs.Display: a message's i/ entry through the member's message list, for
// the mailbox and the group repos its r/ references name, which a host without the text confirms a hit against.
func (self *MailClient) SearchDisplay() *SearchMailDisplay {
	return &SearchMailDisplay{View: func(repoId Id) *MailView {
		join, err := self.searchJoin()
		if err != nil || !slices.Contains(join.Repos(), repoId) {
			return nil
		}
		view, err := self.view()
		if err != nil {
			return nil
		}
		return view
	}}
}

// What a mail search asks.
type MailSearchArgs struct {
	// §16.10's query.
	Text string
	// Spam and trash, which a search leaves out unless asked.
	IncludeSpam  bool
	IncludeTrash bool
	// Zero: unbounded.
	Since time.Time
	Until time.Time
	// Near hits even when 3 or more exact hits exist.
	Fuzzy bool
	// "Search more": the whole mailbox, which a designated indexer the engine finds eligible may answer for a host
	// that keeps no all partition. Without it the search covers the latest buckets on this device alone.
	More bool
	// With More, all may be fetched past §18.4's 25 MiB on a metered link.
	AllowMetered bool
	// Hits a page. Zero: the engine's.
	PageSize int
}

// Gives a search's mail hits alone: a group repo is a general repo, which may hold other documents.
type mailSearchSource struct {
	stream *SearchStream
}

func (self *mailSearchSource) Next() ([]SearchHit, SearchProgress, bool, error) {
	page, progress, done, err := self.stream.Next()
	if err != nil {
		return nil, progress, done, err
	}
	kept := make([]SearchHit, 0, len(page))
	for _, hit := range page {
		if hit.DocKind == int(IndexDocMail) {
			kept = append(kept, hit)
		}
	}
	return kept, progress, done, nil
}

func (self *mailSearchSource) Close() {
	self.stream.Close()
}

// The engine bound, and the mailbox's join synced for a search that starts now.
func (self *MailClient) searchParts(ctx context.Context) (func(ctx context.Context, request *SearchRequest) (*SearchStream, error), *MailSearchJoin, error) {
	binding, _, err := self.bound()
	if err != nil {
		return nil, nil, err
	}
	if binding.Search == nil {
		return nil, nil, ErrMailSearchUnavailable
	}
	join, err := self.searchJoin()
	if err != nil {
		return nil, nil, err
	}
	if err := join.Sync(ctx); err != nil {
		return nil, nil, err
	}
	return binding.Search, join, nil
}

// One search of the member's mail (§15.7): the mailbox and the group repos they read, spam and trash left out unless
// asked, each hit verified, confirmed or possible as the engine labels it. The caller closes the stream.
func (self *MailClient) Search(ctx context.Context, args *MailSearchArgs) (*SearchStream, error) {
	if args == nil || args.Text == "" {
		return nil, ErrMailSearchInvalid
	}
	search, join, err := self.searchParts(ctx)
	if err != nil {
		return nil, err
	}
	request := &SearchRequest{
		Text: args.Text, Repos: join.Repos(), Scope: SearchLatest, Since: args.Since, Until: args.Until, Fuzzy: args.Fuzzy,
		Remote: SearchRemoteOff, PageSize: args.PageSize, IncludeSpam: args.IncludeSpam, IncludeTrash: args.IncludeTrash,
	}
	if args.More {
		// the network's remote mode, which Search resolves: the engine asks only an indexer FI-24 allows
		request.Scope, request.Remote, request.AllowMetered = SearchAll, "", args.AllowMetered
	}
	stream, err := search(ctx, request)
	if err != nil {
		return nil, err
	}
	return NewSearchStream(&mailSearchSource{stream: stream}), nil
}

// The engine for IMAP SEARCH's text terms (mail_imap_search.go): the bound search, the mailbox's join synced first so
// the folder's spam and trash are joined as the folder lists them.
func (self *MailClient) imapSearch(ctx context.Context, request *SearchRequest) (*SearchStream, error) {
	search, _, err := self.searchParts(ctx)
	if err != nil {
		return nil, err
	}
	return search(ctx, request)
}
