// computetest.FakeCalendarServer (CTEST-M13-02; DESIGN-COMPUTE §18's mail-and-calendar and connected-services rows,
// with §23.6, §23.7 and §23.9): the calendars a calendar link reaches, for MAILCAL's and CONN's tests. One loopback
// HTTPS listener (fake_https.go) serves four fronts over one store, each answering as its provider documents, never
// more leniently, since §23.9's recovery reads a provider's state as the provider answers it:
//
//	caldav     calendar_caldav.go: go-webdav's CalDAV server over the fake's store, with what it leaves out served
//	           beside it: discovery (/.well-known/caldav, current-user-principal, calendar-home-set on the account's
//	           host or its partition host, calendar-user-address-set), collections with their privileges, zone and
//	           sharing or publishing as Nextcloud and iCloud report them, REPORT calendar-query with time ranges and
//	           expanded recurrences (RFC 4791 §9.6.5, §9.9), PUT create-only by If-None-Match and PUT and DELETE by
//	           If-Match on ETags, RECURRENCE-ID overrides and EXDATEs, and RFC 6638's scheduling, recorded as notices
//	ics        calendar_ics.go: feeds by secret address, a calendar's objects or a fixed document, with conditional GET
//	google     calendar_google.go: the Calendar API v3's calendarList, events list, get, insert (a client-chosen id),
//	           patch, delete and instances, under etags by If-Match, with Google's error bodies and its 403 rate limits
//	microsoft  calendar_graph.go: Graph's calendars, calendarView, events and instances, create with a transactionId,
//	           patch and delete, with no conditional write, as Graph documents events
//
// Every account is one front's: a caldav account authenticates by Basic (its name and app password), a google or
// microsoft one by bearer tokens the test registers (AddToken) or a TokenCheck answers (FakeOauthIssuer's, once
// CTEST-M13-04 lands). Every request is logged (Requests); every write, applied or refused, is logged with its
// precondition and what the provider mailed for it (Writes, FakeCalendarWrite; Notices), so a test asserts what was
// sent once and that no attendee was mailed twice. A stop (StopAfterApplying) holds the answer to a write the fake
// has applied, until the test releases it or drops it, which closes the connection with no answer: R2-03's recovery
// cases. A failure (FailNext) answers the next matching requests with a provider's error and touches nothing.
//
// Every value is synthetic: .example hosts, addresses at calendar.example, ids and ETags drawn from the seed and the
// fake's revision counter, so one script on one seed and one clock makes the same bytes. Nothing sleeps: a stop is a
// barrier the test releases, and every time is the injected clock's.
//
// Safe for concurrent use.

package computetest

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-ical"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The fronts, one per account (identifiers).
type FakeCalendarProtocol string

const (
	FakeCalendarCaldav    FakeCalendarProtocol = "caldav"
	FakeCalendarIcs       FakeCalendarProtocol = "ics"
	FakeCalendarGoogle    FakeCalendarProtocol = "google"
	FakeCalendarMicrosoft FakeCalendarProtocol = "microsoft"
)

// The hosts the fixed fronts serve, and a CalDAV account's host when its args name none (identifiers).
const (
	FakeCalendarCaldavHost = "caldav.calendar.example"
	FakeCalendarIcsHost    = "ics.calendar.example"
	FakeCalendarGoogleHost = "calendar-api.google.example"
	FakeCalendarGraphHost  = "graph.microsoft.example"
	// Where an account's address is when its args give none.
	fakeCalendarAddressDomain = "calendar.example"
)

// iTIP's methods, a notice's (RFC 5546; identifiers).
const (
	FakeCalendarNoticeRequest = "REQUEST"
	FakeCalendarNoticeCancel  = "CANCEL"
	FakeCalendarNoticeReply   = "REPLY"
)

var (
	// An account or calendar the call names does not exist, or exists already.
	ErrFakeCalendarUnknown = errors.New("computetest: the fake calendar server has no such account or calendar")
	ErrFakeCalendarExists  = errors.New("computetest: the fake calendar server has that account or calendar already")
	// Args the fake cannot serve: a name outside its pattern, a host that is not .example, a front an account cannot
	// have, a zone Go cannot load.
	ErrFakeCalendarArgs = errors.New("computetest: args the fake calendar server cannot serve")
	// A request the fake does not serve: a method or path no front of it answers. Its body names the request.
	ErrFakeCalendarUnserved = errors.New("computetest: the fake calendar server does not serve this request")
	// Data the fake cannot read: iCalendar or JSON a front refuses.
	ErrFakeCalendarData = errors.New("computetest: data the fake calendar server cannot read")
)

// The fake's settings (QD-702).
type FakeCalendarServerSettings struct {
	// The most bytes a request's body may hold, past which the fake answers 413 and reads no more: 16 MiB, past §23.7's
	// 4 MiB response and 10 MiB ICS caps, so the caps a test meets are the client's own.
	RequestBodyMaxByteCount int64
	// The most instances one recurring event expands to in a read: §23.7's 10,000 a series, the cap the client holds
	// itself to; a series past it is cut there. Non-positive expands none.
	ExpandInstanceMaxCount int
	// Google's events.list maxResults when a request names none (250), and the most it takes (2,500), as events.list
	// documents them.
	GoogleListDefaultCount int
	GoogleListMaxCount     int
	// Google's event ids, as events.insert documents them: 5 to 1,024 characters of base32hex.
	GoogleEventIdMinLength int
	GoogleEventIdMaxLength int
	// Graph's calendarView and instances page when a request names no $top (10), and the most $top takes (1,000).
	GraphPageDefaultCount int
	GraphPageMaxCount     int
	// Graph's bodyPreview: the body's first 255 characters, as Graph's event resource documents it.
	GraphBodyPreviewCharacterCount int
	// The reminder a new Graph event takes when its create names none: 15 minutes, Outlook's default.
	GraphDefaultReminder time.Duration
}

// The fake's defaults, the only place one is set.
func DefaultFakeCalendarServerSettings() *FakeCalendarServerSettings {
	return &FakeCalendarServerSettings{
		RequestBodyMaxByteCount: 16 * 1024 * 1024,
		ExpandInstanceMaxCount:  10000,
		GoogleListDefaultCount:  250,
		GoogleListMaxCount:      2500,
		GoogleEventIdMinLength:  5,
		GoogleEventIdMaxLength:  1024,
		GraphPageDefaultCount:   10,
		GraphPageMaxCount:       1000,

		GraphBodyPreviewCharacterCount: 255,
		GraphDefaultReminder:           15 * time.Minute,
	}
}

// What a bearer token is: whose account it opens and its scopes; ok false refuses it as invalid or expired.
type FakeCalendarTokenCheck func(token string) (account string, scopes []string, ok bool)

// What NewFakeCalendarServer builds on.
type FakeCalendarServerArgs struct {
	// Nil takes DefaultFakeCalendarServerSettings.
	Settings *FakeCalendarServerSettings
	// Every time the fake keeps or answers; nil takes a FakeClock at sidecartest.DefaultClockStart.
	Clock sidecar.Clock
	// What its keys, ids and ETags are drawn from; empty takes "computetest".
	Seed string
	// Answers a bearer token AddToken did not register: FakeOauthIssuer's access tokens, once CTEST-M13-04 lands. Nil
	// checks AddToken's alone.
	TokenCheck FakeCalendarTokenCheck
}

// One account (AddAccount).
type FakeCalendarAccountArgs struct {
	// caldav, google or microsoft.
	Protocol FakeCalendarProtocol
	// [a-z0-9][a-z0-9._-]{0,63}: caldav's user name and its principal's path segment; google's and microsoft's name
	// for AddToken and the token check.
	Name string
	// caldav: the app password Basic authentication takes.
	Password string
	// The account's own address: CalDAV's calendar-user-address-set, the organizer Google and Graph write; empty takes
	// <name>@calendar.example.
	Address     string
	DisplayName string
	// caldav: the host discovery starts from, a .example name; empty takes FakeCalendarCaldavHost.
	Host string
	// caldav: the host the home set and its calendars live on, as iCloud's pNN-caldav partition hosts, a .example name;
	// empty serves them on Host. Calendar paths on Host then answer 404.
	PartitionHost string
	// caldav: /.well-known/caldav's redirect status, 301 as Nextcloud answers when 0; 308 keeps a PROPFIND's method.
	WellKnownStatus int
}

// How a calendar's sharing or publishing reads (identifiers).
type FakeCalendarSharingDialect string

const (
	// owncloud's invite, as Nextcloud reports a shared calendar, and calendarserver's publish-url.
	FakeCalendarSharingNextcloud FakeCalendarSharingDialect = "nextcloud"
	// calendarserver's invite and publish-url, as iCloud reports them.
	FakeCalendarSharingIcloud FakeCalendarSharingDialect = "icloud"
)

// One person a calendar is shared with.
type FakeCalendarSharee struct {
	// mailto:<address>, or a principal's href
	Href       string
	CommonName string
	// Reads and writes; otherwise reads.
	ReadWrite bool
	Accepted  bool
}

// What a calendar's provider reports of its sharing and publishing (caldav; google and microsoft report none here).
type FakeCalendarSharing struct {
	Dialect FakeCalendarSharingDialect
	Sharees []*FakeCalendarSharee
	// Where it is published, read-only to anyone; empty for none.
	PublishUrl string
}

// One calendar (AddCalendar).
type FakeCalendarArgs struct {
	// caldav: the collection's path segment, required, [a-z0-9][a-z0-9._-]{0,63}; google: the calendar id, the primary
	// calendar's being the account's address when empty and Default; microsoft: drawn from the seed when empty.
	Id          string
	Name        string
	Description string
	// An IANA zone; empty takes UTC.
	TimeZone string
	// The account reads it and may not write it: CalDAV's privileges without write, Google's reader access role, Graph's
	// canEdit false.
	ReadOnly bool
	// google: the primary calendar; microsoft: the default calendar.
	Default bool
	// caldav: the server ignores a calendar-data expand (RFC 4791 §9.6.5), as some do, answering each object whole.
	NoExpand bool
	// caldav: max-resource-size, reported and enforced; 0 reports none.
	MaxResourceByteCount int64
	// caldav: its sharing and publishing; nil reports none.
	Sharing *FakeCalendarSharing
}

// A message a provider sends for a write: an invitation, an update or a cancellation to an attendee, or a reply to an
// organizer (iTIP's methods).
type FakeCalendarNotice struct {
	// FakeCalendarNoticeRequest, FakeCalendarNoticeCancel or FakeCalendarNoticeReply.
	Method string
	// Its recipient's address, without mailto:.
	To string
	// The event's UID, the instance's start for one occurrence.
	Uid        string
	Occurrence time.Time
	// A reply's participation, DECLINED.
	PartStat string
}

// One write the fake received, applied or refused, with its precondition and what came of it.
type FakeCalendarWrite struct {
	// Its place in the log, from 0.
	Index    int
	At       time.Time
	Protocol FakeCalendarProtocol
	// PUT, DELETE, POST or PATCH.
	Method   string
	Account  string
	Calendar string
	// caldav: the object's resource name; google and microsoft: the event id the request named, or the new event's.
	Resource string
	// The event's UID where the write carried or reached one.
	Uid string
	// As sent: caldav's If-None-Match and If-Match, Google's If-Match, Graph's If-Match (which Graph ignores).
	IfNoneMatch string
	IfMatch     string
	// microsoft: a create's transactionId; google: sendUpdates; caldav: Schedule-Reply.
	TransactionId string
	SendUpdates   string
	ScheduleReply string
	// The status the fake answered, and whether the write changed the calendar; a status of 0 is an answer a stop
	// dropped.
	Status  int
	Applied bool
	// The resource's revision before and after, as the provider names it: caldav's ETag header, google's etag,
	// microsoft's changeKey; empty where there was none.
	RevisionBefore string
	RevisionAfter  string
	// What the provider mailed for it.
	Notices []*FakeCalendarNotice
	// The body as received.
	Body []byte
}

// One request the fake received, as received.
type FakeCalendarRequest struct {
	At           time.Time
	ConnectionId uint64
	// The front it reached; empty for a host the fake does not serve.
	Protocol FakeCalendarProtocol
	Method   string
	Host     string
	Path     string
	RawQuery string
	// Every header as sent, Authorization included: the credentials here are the test's own.
	Header http.Header
	// 0 for an answer a stop dropped.
	Status int
}

// Which applied write a stop holds: each field left empty matches any.
type FakeCalendarStopMatch struct {
	Protocol FakeCalendarProtocol
	Method   string
	Calendar string
	Resource string
	Uid      string
}

// A barrier after a provider applied a write and before its answer leaves (R2-03's recovery cases): it holds the first
// applied write that matches, once. Release lets the answer go; Drop, or the request's own end, closes the connection
// with no answer, the write staying applied. Safe for concurrent use.
type FakeCalendarStop struct {
	match FakeCalendarStopMatch

	reached     chan struct{}
	released    chan struct{}
	dropped     chan struct{}
	reachedOnce sync.Once
	releaseOnce sync.Once
	dropOnce    sync.Once

	stateLock sync.Mutex
	write     *FakeCalendarWrite
}

// Closed once a write holds at the stop.
func (self *FakeCalendarStop) Reached() <-chan struct{} {
	return self.reached
}

// The write it holds, or nil before Reached.
func (self *FakeCalendarStop) Write() *FakeCalendarWrite {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.write
}

// The answer leaves, now or as a write reaches the stop.
func (self *FakeCalendarStop) Release() {
	self.releaseOnce.Do(func() {
		close(self.released)
	})
}

// The connection closes with no answer, now or as a write reaches the stop; the write stays applied.
func (self *FakeCalendarStop) Drop() {
	self.dropOnce.Do(func() {
		close(self.dropped)
	})
}

func (self *FakeCalendarStop) matches(write *FakeCalendarWrite) bool {
	match := &self.match
	return (match.Protocol == "" || match.Protocol == write.Protocol) &&
		(match.Method == "" || strings.EqualFold(match.Method, write.Method)) &&
		(match.Calendar == "" || match.Calendar == write.Calendar) &&
		(match.Resource == "" || match.Resource == write.Resource) &&
		(match.Uid == "" || match.Uid == write.Uid)
}

// Holds until Release (true), or Drop or ctx's end (false).
func (self *FakeCalendarStop) hold(ctx context.Context, write *FakeCalendarWrite) bool {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.write = write
	}()
	self.reachedOnce.Do(func() {
		close(self.reached)
	})
	select {
	case <-self.dropped:
		return false
	default:
	}
	select {
	case <-self.released:
		return true
	case <-self.dropped:
		return false
	case <-ctx.Done():
		return false
	}
}

// A provider's error for the next matching requests (FailNext): each field left empty matches any request.
type FakeCalendarFailure struct {
	Protocol FakeCalendarProtocol
	Method   string
	// The status: 429 or 503 anywhere, Google's 403 rate limits, Graph's 429.
	Status int
	// google: the reason Google's error guide names, rateLimitExceeded, userRateLimitExceeded, quotaExceeded or
	// backendError, its domain following it; microsoft: the error code, TooManyRequests or ApplicationThrottled; empty
	// takes the status's own.
	Reason string
	// Sent as Retry-After in whole seconds where positive.
	RetryAfter time.Duration
	// How many requests it answers; under one counts as one.
	Count int
}

type fakeCalendarAccount struct {
	args        FakeCalendarAccountArgs
	calendarIds []string
}

type fakeCalendar struct {
	account string
	args    FakeCalendarArgs
	zone    *time.Location
	// bumped at each change: the collection's ctag and sync token
	revision uint64
	changed  time.Time
	// caldav: objects by resource name
	objects map[string]*fakeCaldavObject
	// google: events by id, singles, masters and exceptions alike, cancelled ones kept
	googleEvents map[string]*fakeGoogleEvent
	// microsoft: events by immutable id
	graphEvents map[string]*fakeGraphEvent
}

type fakeCalendarToken struct {
	account string
	scopes  []string
}

// The state of one request, from its context: what a front's layers hand each other.
type fakeCalendarExchange struct {
	protocol FakeCalendarProtocol
	account  string
	// caldav: a REPORT's calendar-data expand window, which go-webdav's server does not pass on
	expand *fakeCalendarWindow
	// caldav: DELETE's If-Match and Schedule-Reply, which go-webdav's server does not pass on
	ifMatch       string
	scheduleReply string
	// caldav: a PUT that replaced a resource, answered 204 as RFC 9110 has it where go-webdav answers 201
	replaced bool
	// set when a write the store applied matched an armed stop
	stop      *FakeCalendarStop
	stopWrite *FakeCalendarWrite
	// the request's write is in the log
	writeLogged bool
}

type fakeCalendarExchangeKey struct{}

func fakeCalendarExchangeOf(ctx context.Context) *fakeCalendarExchange {
	exchange, _ := ctx.Value(fakeCalendarExchangeKey{}).(*fakeCalendarExchange)
	if exchange == nil {
		return &fakeCalendarExchange{}
	}
	return exchange
}

// See the file header.
type FakeCalendarServer struct {
	settings   *FakeCalendarServerSettings
	clock      sidecar.Clock
	seed       string
	tokenCheck FakeCalendarTokenCheck
	https      *fakeHttpsServer

	stateLock sync.Mutex
	accounts  map[string]*fakeCalendarAccount
	calendars map[string]*fakeCalendar
	tokens    map[string]*fakeCalendarToken
	icsFeeds  map[string]*FakeIcsFeed
	writes    []*FakeCalendarWrite
	notices   []*FakeCalendarNotice
	requests  []*FakeCalendarRequest
	stops     []*FakeCalendarStop
	// every stop made, so Close drops those still holding
	madeStops    []*FakeCalendarStop
	failures     []*FakeCalendarFailure
	revision     uint64
	drawnIdCount uint64
}

// A server listening on loopback at once; Close ends it.
func NewFakeCalendarServer(args *FakeCalendarServerArgs) (*FakeCalendarServer, error) {
	if args == nil {
		args = &FakeCalendarServerArgs{}
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultFakeCalendarServerSettings()
	}
	clock := args.Clock
	if clock == nil {
		clock = sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	}
	seed := args.Seed
	if seed == "" {
		seed = "computetest"
	}
	https, err := newFakeHttpsServer(seed + " calendar")
	if err != nil {
		return nil, err
	}
	self := &FakeCalendarServer{
		settings:   settings,
		clock:      clock,
		seed:       seed,
		tokenCheck: args.TokenCheck,
		https:      https,
		accounts:   map[string]*fakeCalendarAccount{},
		calendars:  map[string]*fakeCalendar{},
		tokens:     map[string]*fakeCalendarToken{},
		icsFeeds:   map[string]*FakeIcsFeed{},
	}
	https.handle(FakeCalendarIcsHost, self.front(FakeCalendarIcs, self.serveIcs))
	https.handle(FakeCalendarGoogleHost, self.front(FakeCalendarGoogle, self.serveGoogle))
	https.handle(FakeCalendarGraphHost, self.front(FakeCalendarMicrosoft, self.serveGraph))
	return self, nil
}

// Drops every stop still holding, so its request ends with no answer, then stops the listener.
func (self *FakeCalendarServer) Close() {
	stops := func() []*FakeCalendarStop {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return slices.Clone(self.madeStops)
	}()
	for _, stop := range stops {
		stop.Drop()
	}
	self.https.close()
}

// A client that reaches the fake's hosts alone and trusts its test authority, follows no redirect and keeps no
// cookie: what it receives is what the fake answered.
func (self *FakeCalendarServer) HttpClient() *http.Client {
	return self.https.httpClient()
}

// Dials the listener for a host the fake serves, on any port, and fails ErrFakeHostUnserved otherwise: the dialer a
// client's egress seam takes in a test.
func (self *FakeCalendarServer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	return self.https.dialContext(ctx, network, address)
}

// The pool that trusts the fake's certificates, and nothing else.
func (self *FakeCalendarServer) RootCAs() *x509.CertPool {
	return self.https.authority.rootPool
}

// The hosts served, sorted.
func (self *FakeCalendarServer) Hosts() []string {
	return self.https.hosts()
}

// The Calendar API v3's base, as a client's settings name Google's.
func (self *FakeCalendarServer) GoogleApiBase() string {
	return "https://" + FakeCalendarGoogleHost + "/calendar/v3"
}

// Graph's v1.0 base, as a client's settings name Microsoft's.
func (self *FakeCalendarServer) GraphApiBase() string {
	return "https://" + FakeCalendarGraphHost + "/v1.0"
}

var fakeCalendarNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// A .example host name, lowercased.
func fakeCalendarHost(host string) (string, error) {
	host = strings.ToLower(host)
	if !strings.HasSuffix(host, ".example") || strings.ContainsAny(host, "/:@ ") {
		return "", fmt.Errorf("%w: host %q is not a .example name", ErrFakeCalendarArgs, host)
	}
	return host, nil
}

// Adds an account; a caldav account's hosts are served from now on.
func (self *FakeCalendarServer) AddAccount(args *FakeCalendarAccountArgs) error {
	if args == nil || !fakeCalendarNamePattern.MatchString(args.Name) {
		return fmt.Errorf("%w: an account's name", ErrFakeCalendarArgs)
	}
	account := &fakeCalendarAccount{args: *args}
	switch args.Protocol {
	case FakeCalendarCaldav:
		if args.Password == "" {
			return fmt.Errorf("%w: a caldav account needs a password", ErrFakeCalendarArgs)
		}
		host := args.Host
		if host == "" {
			host = FakeCalendarCaldavHost
		}
		host, err := fakeCalendarHost(host)
		if err != nil {
			return err
		}
		account.args.Host = host
		if args.PartitionHost != "" {
			partitionHost, err := fakeCalendarHost(args.PartitionHost)
			if err != nil {
				return err
			}
			account.args.PartitionHost = partitionHost
		}
		switch args.WellKnownStatus {
		case 0:
			account.args.WellKnownStatus = http.StatusMovedPermanently
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect,
			http.StatusPermanentRedirect:
		default:
			return fmt.Errorf("%w: a well-known redirect status of %d", ErrFakeCalendarArgs, args.WellKnownStatus)
		}
	case FakeCalendarGoogle, FakeCalendarMicrosoft:
	default:
		return fmt.Errorf("%w: an account of protocol %q", ErrFakeCalendarArgs, args.Protocol)
	}
	if account.args.Address == "" {
		account.args.Address = args.Name + "@" + fakeCalendarAddressDomain
	}
	if account.args.DisplayName == "" {
		account.args.DisplayName = args.Name
	}
	err := func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if _, ok := self.accounts[args.Name]; ok {
			return fmt.Errorf("%w: account %q", ErrFakeCalendarExists, args.Name)
		}
		self.accounts[args.Name] = account
		return nil
	}()
	if err != nil {
		return err
	}
	if account.args.Protocol == FakeCalendarCaldav {
		handler := self.front(FakeCalendarCaldav, self.serveCaldav)
		self.https.handle(account.args.Host, handler)
		if account.args.PartitionHost != "" {
			self.https.handle(account.args.PartitionHost, handler)
		}
	}
	return nil
}

// The URL a person gives for a caldav account: its discovery host's root.
func (self *FakeCalendarServer) CaldavUrl(account string) (string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	accountState, ok := self.accounts[account]
	if !ok || accountState.args.Protocol != FakeCalendarCaldav {
		return "", fmt.Errorf("%w: caldav account %q", ErrFakeCalendarUnknown, account)
	}
	return "https://" + accountState.args.Host + "/", nil
}

// Registers a bearer token for a google or microsoft account, with its scopes; nil scopes pass every scope check.
func (self *FakeCalendarServer) AddToken(account string, token string, scopes []string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	accountState, ok := self.accounts[account]
	if !ok || accountState.args.Protocol == FakeCalendarCaldav {
		return fmt.Errorf("%w: a token for account %q", ErrFakeCalendarUnknown, account)
	}
	self.tokens[token] = &fakeCalendarToken{account: account, scopes: slices.Clone(scopes)}
	return nil
}

// Refuses token from now on, as an expired or revoked access token is.
func (self *FakeCalendarServer) RemoveToken(token string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.tokens, token)
}

func fakeCalendarKey(account string, calendarId string) string {
	return account + "\x00" + calendarId
}

// Adds a calendar to an account and answers its id.
func (self *FakeCalendarServer) AddCalendar(account string, args *FakeCalendarArgs) (string, error) {
	if args == nil {
		args = &FakeCalendarArgs{}
	}
	zone := time.UTC
	if args.TimeZone != "" {
		loaded, err := time.LoadLocation(args.TimeZone)
		if err != nil {
			return "", fmt.Errorf("%w: zone %q", ErrFakeCalendarArgs, args.TimeZone)
		}
		zone = loaded
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	accountState, ok := self.accounts[account]
	if !ok {
		return "", fmt.Errorf("%w: account %q", ErrFakeCalendarUnknown, account)
	}
	calendarArgs := *args
	calendarArgs.Sharing = fakeCalendarCloneSharing(args.Sharing)
	switch accountState.args.Protocol {
	case FakeCalendarCaldav:
		if !fakeCalendarNamePattern.MatchString(args.Id) || args.Id == "calendars" {
			return "", fmt.Errorf("%w: a caldav calendar's id %q", ErrFakeCalendarArgs, args.Id)
		}
	case FakeCalendarGoogle:
		if calendarArgs.Id == "" {
			if args.Default {
				calendarArgs.Id = accountState.args.Address
			} else {
				calendarArgs.Id = self.drawIdWithLock("google calendar", 13) + "@group.calendar.example"
			}
		}
	case FakeCalendarMicrosoft:
		if calendarArgs.Id == "" {
			calendarArgs.Id = "AAMkAGcal" + self.drawIdWithLock("graph calendar", 16)
		}
	}
	if calendarArgs.Id == "primary" || strings.ContainsAny(calendarArgs.Id, "/?#") {
		return "", fmt.Errorf("%w: a calendar's id %q", ErrFakeCalendarArgs, calendarArgs.Id)
	}
	key := fakeCalendarKey(account, calendarArgs.Id)
	if _, ok := self.calendars[key]; ok {
		return "", fmt.Errorf("%w: calendar %q", ErrFakeCalendarExists, calendarArgs.Id)
	}
	if calendarArgs.Default {
		for _, calendarId := range accountState.calendarIds {
			if self.calendars[fakeCalendarKey(account, calendarId)].args.Default {
				return "", fmt.Errorf("%w: a second default calendar", ErrFakeCalendarArgs)
			}
		}
	}
	self.calendars[key] = &fakeCalendar{
		account:      account,
		args:         calendarArgs,
		zone:         zone,
		changed:      self.clock.Now(),
		objects:      map[string]*fakeCaldavObject{},
		googleEvents: map[string]*fakeGoogleEvent{},
		graphEvents:  map[string]*fakeGraphEvent{},
	}
	accountState.calendarIds = append(accountState.calendarIds, calendarArgs.Id)
	return calendarArgs.Id, nil
}

func fakeCalendarCloneSharing(sharing *FakeCalendarSharing) *FakeCalendarSharing {
	if sharing == nil {
		return nil
	}
	clone := *sharing
	clone.Sharees = nil
	for _, sharee := range sharing.Sharees {
		shareeClone := *sharee
		clone.Sharees = append(clone.Sharees, &shareeClone)
	}
	return &clone
}

// Changes what a calendar's provider reports of its sharing and publishing, as when the person shares it after an
// approval; nil reports none.
func (self *FakeCalendarServer) SetSharing(account string, calendarId string, sharing *FakeCalendarSharing) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	calendar, ok := self.calendars[fakeCalendarKey(account, calendarId)]
	if !ok {
		return fmt.Errorf("%w: calendar %q", ErrFakeCalendarUnknown, calendarId)
	}
	calendar.args.Sharing = fakeCalendarCloneSharing(sharing)
	self.touchWithLock(calendar)
	return nil
}

// Arms a stop for the first applied write that matches; nil matches any.
func (self *FakeCalendarServer) StopAfterApplying(match *FakeCalendarStopMatch) *FakeCalendarStop {
	stop := &FakeCalendarStop{
		reached:  make(chan struct{}),
		released: make(chan struct{}),
		dropped:  make(chan struct{}),
	}
	if match != nil {
		stop.match = *match
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.stops = append(self.stops, stop)
	self.madeStops = append(self.madeStops, stop)
	return stop
}

// Answers the next matching requests with failure's error, touching nothing.
func (self *FakeCalendarServer) FailNext(failure *FakeCalendarFailure) {
	if failure == nil {
		return
	}
	clone := *failure
	if clone.Count < 1 {
		clone.Count = 1
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.failures = append(self.failures, &clone)
}

// Every write received, applied or refused, in order; copies, so a test's change reaches nothing here.
func (self *FakeCalendarServer) Writes() []*FakeCalendarWrite {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	writes := make([]*FakeCalendarWrite, 0, len(self.writes))
	for _, write := range self.writes {
		writes = append(writes, fakeCalendarCloneWrite(write))
	}
	return writes
}

func fakeCalendarCloneWrite(write *FakeCalendarWrite) *FakeCalendarWrite {
	clone := *write
	clone.Body = slices.Clone(write.Body)
	clone.Notices = nil
	for _, notice := range write.Notices {
		noticeClone := *notice
		clone.Notices = append(clone.Notices, &noticeClone)
	}
	return &clone
}

// Every message a provider sent, in order.
func (self *FakeCalendarServer) Notices() []*FakeCalendarNotice {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	notices := make([]*FakeCalendarNotice, 0, len(self.notices))
	for _, notice := range self.notices {
		clone := *notice
		notices = append(notices, &clone)
	}
	return notices
}

// Every request received, in order.
func (self *FakeCalendarServer) Requests() []*FakeCalendarRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	requests := make([]*FakeCalendarRequest, 0, len(self.requests))
	for _, request := range self.requests {
		clone := *request
		clone.Header = request.Header.Clone()
		requests = append(requests, &clone)
	}
	return requests
}

// The fake's clock.
func (self *FakeCalendarServer) now() time.Time {
	return self.clock.Now().UTC()
}

// Marks a calendar changed: a new ctag and sync token.
func (self *FakeCalendarServer) touchWithLock(calendar *fakeCalendar) {
	self.revision += 1
	calendar.revision = self.revision
	calendar.changed = self.now()
}

// A new revision of the fake's, for an ETag, an etag or a changeKey: hex of the seed, label and counter's hash.
func (self *FakeCalendarServer) nextRevisionWithLock(label string) string {
	self.revision += 1
	sum := sha256.Sum256([]byte(fmt.Sprintf("computetest calendar revision %s %s %d", self.seed, label, self.revision)))
	return hex.EncodeToString(sum[:8])
}

// An id from the seed: alphabet base32hex's lowercase, so a Google id is one.
func (self *FakeCalendarServer) drawIdWithLock(label string, byteCount int) string {
	self.drawnIdCount += 1
	raw := fakeBytes(self.seed, fmt.Sprintf("calendar id %s %d", label, self.drawnIdCount), byteCount)
	const alphabet = "0123456789abcdefghijklmnopqrstuv"
	out := make([]byte, 0, len(raw)*2)
	for _, b := range raw {
		out = append(out, alphabet[b>>4], alphabet[b&0x0f])
	}
	return string(out)
}

// Appends a write to the log and, when it was applied, hands it to the first armed stop it matches.
func (self *FakeCalendarServer) logWriteWithLock(exchange *fakeCalendarExchange, write *FakeCalendarWrite) {
	write.Index = len(self.writes)
	write.At = self.now()
	self.writes = append(self.writes, write)
	for _, notice := range write.Notices {
		self.notices = append(self.notices, notice)
	}
	if exchange != nil {
		exchange.writeLogged = true
	}
	if !write.Applied || exchange == nil || exchange.stop != nil {
		return
	}
	for i, stop := range self.stops {
		if stop.matches(write) {
			self.stops = slices.Delete(self.stops, i, i+1)
			exchange.stop = stop
			exchange.stopWrite = write
			return
		}
	}
}

// The failure the request takes, if one matches, counted down.
func (self *FakeCalendarServer) takeFailure(protocol FakeCalendarProtocol, method string) *FakeCalendarFailure {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for i, failure := range self.failures {
		if (failure.Protocol != "" && failure.Protocol != protocol) ||
			(failure.Method != "" && !strings.EqualFold(failure.Method, method)) {
			continue
		}
		failure.Count -= 1
		taken := *failure
		if failure.Count <= 0 {
			self.failures = slices.Delete(self.failures, i, i+1)
		}
		return &taken
	}
	return nil
}

// What each front's answer passes through: it records the status, turns a replacing PUT's 201 into 204, and holds at a
// stop the store armed for this request, closing the connection with no answer when the stop drops it.
type fakeCalendarWriter struct {
	http.ResponseWriter
	ctx         context.Context
	exchange    *fakeCalendarExchange
	status      int
	wroteHeader bool
}

func (self *fakeCalendarWriter) WriteHeader(status int) {
	if self.wroteHeader {
		return
	}
	self.wroteHeader = true
	if self.exchange.replaced && status == http.StatusCreated {
		status = http.StatusNoContent
	}
	if stop := self.exchange.stop; stop != nil {
		if !stop.hold(self.ctx, self.exchange.stopWrite) {
			panic(http.ErrAbortHandler)
		}
	}
	self.status = status
	self.ResponseWriter.WriteHeader(status)
}

func (self *fakeCalendarWriter) Write(body []byte) (int, error) {
	if !self.wroteHeader {
		self.WriteHeader(http.StatusOK)
	}
	return self.ResponseWriter.Write(body)
}

// A front: the request logged with its status, its body bounded, a scripted failure answered first, then serve.
func (self *FakeCalendarServer) front(protocol FakeCalendarProtocol, serve func(w *fakeCalendarWriter, r *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if splitHost, _, err := net.SplitHostPort(host); err == nil {
			host = splitHost
		}
		request := &FakeCalendarRequest{
			At:           self.now(),
			ConnectionId: fakeConnectionId(r.Context()),
			Protocol:     protocol,
			Method:       r.Method,
			Host:         strings.ToLower(host),
			Path:         r.URL.Path,
			RawQuery:     r.URL.RawQuery,
			Header:       r.Header.Clone(),
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.requests = append(self.requests, request)
		}()
		exchange := &fakeCalendarExchange{protocol: protocol}
		ctx := context.WithValue(r.Context(), fakeCalendarExchangeKey{}, exchange)
		r = r.WithContext(ctx)
		writer := &fakeCalendarWriter{ResponseWriter: w, ctx: ctx, exchange: exchange}
		defer func() {
			status := writer.status
			if !writer.wroteHeader {
				status = http.StatusOK
			}
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			request.Status = status
		}()
		if r.ContentLength > self.settings.RequestBodyMaxByteCount {
			http.Error(writer, "computetest: a body past the fake's cap", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(writer, r.Body, self.settings.RequestBodyMaxByteCount)
		if failure := self.takeFailure(protocol, r.Method); failure != nil {
			self.serveFailure(writer, protocol, failure)
			return
		}
		serve(writer, r)
	})
}

// A scripted failure in the front's own error form.
func (self *FakeCalendarServer) serveFailure(w http.ResponseWriter, protocol FakeCalendarProtocol, failure *FakeCalendarFailure) {
	if failure.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.FormatInt(int64((failure.RetryAfter+time.Second-1)/time.Second), 10))
	}
	switch protocol {
	case FakeCalendarGoogle:
		reason := failure.Reason
		if reason == "" {
			reason = fakeGoogleStatusReason(failure.Status)
		}
		fakeGoogleError(w, failure.Status, reason)
	case FakeCalendarMicrosoft:
		code := failure.Reason
		if code == "" {
			code = fakeGraphStatusCode(failure.Status)
		}
		fakeGraphError(w, failure.Status, code, http.StatusText(failure.Status))
	default:
		http.Error(w, http.StatusText(failure.Status), failure.Status)
	}
}

// Reads a request's body whole, bounded by the front's MaxBytesReader.
func fakeCalendarReadBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	return io.ReadAll(r.Body)
}

// The bearer token's account and scopes, for the google and microsoft fronts.
func (self *FakeCalendarServer) bearer(r *http.Request, protocol FakeCalendarProtocol) (string, []string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", nil, false
	}
	account, scopes, found := func() (string, []string, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if registered, ok := self.tokens[token]; ok {
			return registered.account, registered.scopes, true
		}
		return "", nil, false
	}()
	if !found && self.tokenCheck != nil {
		account, scopes, found = self.tokenCheck(token)
	}
	if !found {
		return "", nil, false
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	accountState, ok := self.accounts[account]
	if !ok || accountState.args.Protocol != protocol {
		return "", nil, false
	}
	return account, scopes, true
}

// Whether scopes grant one of wanted, each matched by its last path element, so Google's and Microsoft's full scope
// names and their short forms match alike; nil scopes grant everything.
func fakeCalendarScopesGrant(scopes []string, wanted ...string) bool {
	if scopes == nil {
		return true
	}
	short := func(scope string) string {
		return strings.ToLower(scope[strings.LastIndex(scope, "/")+1:])
	}
	for _, scope := range scopes {
		for _, want := range wanted {
			if short(scope) == short(want) {
				return true
			}
		}
	}
	return false
}

// A time window, end exclusive.
type fakeCalendarWindow struct {
	start time.Time
	end   time.Time
}

// One instance of an event: where it starts and ends, and for a recurring event the start it was scheduled at, its
// recurrence id.
type fakeCalendarInstance struct {
	start        time.Time
	end          time.Time
	allDay       bool
	recurrenceId time.Time
}

// RFC 4791 §9.9's overlap of an instance with a window: start before the window's end, and end after its start, an
// instance of no duration counting at its start.
func (self *fakeCalendarWindow) overlaps(start time.Time, end time.Time) bool {
	if !end.After(start) {
		return !start.Before(self.start) && start.Before(self.end)
	}
	return start.Before(self.end) && end.After(self.start)
}

// A component's date-time properties made readable by go-ical: a TZID Go cannot load is read by the object's own
// VTIMEZONE as a fixed offset, its first observance's TZOFFSETTO, or as UTC with none, and a list of values (EXDATE,
// RDATE) is split into one property each.
func fakeIcalReadableCopy(component *ical.Component, calendar *ical.Calendar) *ical.Component {
	copied := &ical.Component{Name: component.Name, Props: ical.Props{}, Children: component.Children}
	zoneOffsets := map[string]*time.Location{}
	if calendar != nil {
		for _, child := range calendar.Children {
			if child.Name != ical.CompTimezone {
				continue
			}
			tzid, _ := child.Props.Text(ical.PropTimezoneID)
			for _, observance := range child.Children {
				offset := observance.Props.Get(ical.PropTimezoneOffsetTo)
				if offset == nil {
					continue
				}
				if seconds, ok := fakeIcalUtcOffset(offset.Value); ok {
					zoneOffsets[tzid] = time.FixedZone(tzid, seconds)
					break
				}
			}
		}
	}
	for name, props := range component.Props {
		for _, prop := range props {
			values := []string{prop.Value}
			if name == ical.PropExceptionDates || name == ical.PropRecurrenceDates {
				values = strings.Split(prop.Value, ",")
			}
			for _, value := range values {
				clone := ical.Prop{Name: prop.Name, Value: value, Params: ical.Params{}}
				for key, paramValues := range prop.Params {
					clone.Params[key] = slices.Clone(paramValues)
				}
				if tzid := clone.Params.Get(ical.ParamTimezoneID); tzid != "" {
					if _, err := time.LoadLocation(tzid); err != nil {
						zone := zoneOffsets[tzid]
						if zone == nil {
							zone = time.UTC
						}
						if local, err := time.ParseInLocation("20060102T150405", value, zone); err == nil {
							clone.Params.Del(ical.ParamTimezoneID)
							clone.Value = local.UTC().Format("20060102T150405Z")
						}
					}
				}
				copied.Props[name] = append(copied.Props[name], clone)
			}
		}
	}
	return copied
}

// An iCalendar UTC offset, +hhmm[ss] or -hhmm[ss], in seconds.
func fakeIcalUtcOffset(value string) (int, bool) {
	if len(value) != 5 && len(value) != 7 {
		return 0, false
	}
	sign := 1
	switch value[0] {
	case '+':
	case '-':
		sign = -1
	default:
		return 0, false
	}
	parts := []int{}
	for i := 1; i < len(value); i += 2 {
		part, err := strconv.Atoi(value[i : i+2])
		if err != nil {
			return 0, false
		}
		parts = append(parts, part)
	}
	seconds := parts[0]*3600 + parts[1]*60
	if len(parts) == 3 {
		seconds += parts[2]
	}
	return sign * seconds, true
}

// Whether a property holds a date rather than a date-time.
func fakeIcalIsDate(prop *ical.Prop) bool {
	if prop == nil {
		return false
	}
	return prop.ValueType() == ical.ValueDate || (prop.Params.Get(ical.ParamValue) == "" && len(prop.Value) == len("20060102"))
}

// A VEVENT's instances overlapping window, its RRULE, RDATEs and EXDATEs read through go-ical (rrule-go) in zone,
// floating times in zone too, at most maxCount instances counted from the series' start; overrides, the VEVENTs of the
// same object carrying a RECURRENCE-ID, are the caller's. A non-recurring event is its one instance. truncated says the
// series ran past maxCount.
func fakeIcalInstances(master *ical.Component, calendar *ical.Calendar, zone *time.Location, window *fakeCalendarWindow, maxCount int) ([]*fakeCalendarInstance, bool, error) {
	readable := fakeIcalReadableCopy(master, calendar)
	event := &ical.Event{Component: readable}
	start, err := event.DateTimeStart(zone)
	if err != nil {
		return nil, false, fmt.Errorf("%w: DTSTART: %v", ErrFakeCalendarData, err)
	}
	end, err := event.DateTimeEnd(zone)
	if err != nil {
		return nil, false, fmt.Errorf("%w: DTEND: %v", ErrFakeCalendarData, err)
	}
	allDay := fakeIcalIsDate(readable.Props.Get(ical.PropDateTimeStart))
	duration := end.Sub(start)
	if duration < 0 {
		duration = 0
	}
	set, err := readable.RecurrenceSet(zone)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrFakeCalendarData, err)
	}
	if set == nil {
		instance := &fakeCalendarInstance{start: start, end: start.Add(duration), allDay: allDay}
		if window != nil && !window.overlaps(instance.start, instance.end) {
			return nil, false, nil
		}
		return []*fakeCalendarInstance{instance}, false, nil
	}
	instances := []*fakeCalendarInstance{}
	next := set.Iterator()
	for count := 0; ; count += 1 {
		occurrence, ok := next()
		if !ok {
			return instances, false, nil
		}
		if count >= maxCount {
			return instances, true, nil
		}
		if window != nil && !occurrence.Before(window.end) {
			return instances, false, nil
		}
		instance := &fakeCalendarInstance{
			start:        occurrence,
			end:          occurrence.Add(duration),
			allDay:       allDay,
			recurrenceId: occurrence,
		}
		if window == nil || window.overlaps(instance.start, instance.end) {
			instances = append(instances, instance)
		}
	}
}

// A RECURRENCE-ID's instant, read in zone.
func fakeIcalRecurrenceId(component *ical.Component, calendar *ical.Calendar, zone *time.Location) (time.Time, bool) {
	prop := component.Props.Get(ical.PropRecurrenceID)
	if prop == nil {
		return time.Time{}, false
	}
	readable := fakeIcalReadableCopy(&ical.Component{Name: component.Name, Props: ical.Props{ical.PropRecurrenceID: {*prop}}}, calendar)
	at, err := readable.Props.DateTime(ical.PropRecurrenceID, zone)
	if err != nil {
		return time.Time{}, false
	}
	return at, true
}
