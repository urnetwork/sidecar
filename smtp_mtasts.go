//go:build !sidecar_http

// TL2's policies (§14.4, D-SMTP-2): MTA-STS (RFC 8461), which the sidecar finds and fetches itself and
// caches to each policy's max_age, so a malicious or compelled edge can neither strip nor forge one.
// Discovery is the recipient domain's _mta-sts TXT record over the device's own DoH (SmtpDohForwarder,
// connect's DohCache.Forward); the policy comes over HTTPS from mta-sts.<domain> through the transport
// the device hands in, which dials directly and never through the edge, validates the policy host's
// certificate against the web's roots, follows no redirect and caches nothing (§3.3). The mx: patterns
// match as §4.1 says, a * only as a whole left-most label.
//
// Application follows §5.1. A cached policy younger than its max_age applies while the TXT record names
// its id, and also while no usable TXT record answers, since a missing record is no reason to drop a
// policy. A record naming another id, or one with nothing cached, fetches; a fetch that fails, a body
// that does not parse among the ways, leaves the cached policy if one is young enough, else no policy,
// and the same id is not fetched again for MtaStsFetchRetryTimeout. A fetched policy replaces the
// cached one whatever its mode, so mode: none clears an enforce policy as §8.3 intends. Only mode:
// enforce makes TL2 (SmtpTlsPolicy); testing and none apply nothing.
//
// Cached policies live in one sealed file, mta-sts, in the sender's directory of the store, as JSON
// rewritten whole by Commit, under the rules smtp_pins.go's header gives: names stay inside the sealed
// file, a file that does not parse is ErrSidecarStoreFailed and never an empty cache, and a store that
// cannot answer holds the send. Failed fetches are remembered in memory only. Nothing here logs, and
// no error names a domain (I-13).
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10). Safe for concurrent use.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/net/dns/dnsmessage"
)

// RFC 8461's format values, and the sealed file's.
const (
	// The TXT record's name is this before the Policy Domain (§3.1).
	smtpMtaStsTxtPrefix = "_mta-sts."
	// The record's version field, which a record must begin with (§3.1).
	smtpMtaStsTxtVersion = "v=STSv1"
	// The policy's version (§3.2).
	smtpMtaStsPolicyVersion = "STSv1"
	// An id is 1 to 32 letters and digits (§3.1).
	smtpMtaStsIdMaxLength = 32
	// An extension field's name is a letter or digit and then at most 31 more (§3.1, §3.2).
	smtpMtaStsFieldNameMaxLength = 32
	// max_age's largest value, 31557600 s (§3.2).
	smtpMtaStsMaxAgeMax = 31557600 * time.Second
	// max_age's most digits (§3.2).
	smtpMtaStsMaxAgeMaxDigitCount = 10
	// The policy's host is this before the Policy Domain, and its path is fixed (§3.2).
	smtpMtaStsHostPrefix = "mta-sts."
	smtpMtaStsPath       = "/.well-known/mta-sts.txt"
	// The media type a policy must be served as (§3.2).
	smtpMtaStsMediaType = "text/plain"
	// The cache's file in the sender's directory, and its format version.
	smtpMtaStsFileName    = "mta-sts"
	smtpMtaStsFileVersion = 1
)

var (
	// A policy body that is not RFC 8461 §3.2's.
	ErrSmtpMtaStsPolicyInvalid = errors.New("smtp mta-sts: invalid policy")
	// The policy could not be fetched.
	errSmtpMtaStsFetch = errors.New("smtp mta-sts: no policy fetched")
)

// What a policy asks a sender to do when an MX fails it (RFC 8461 §5).
type SmtpMtaStsMode uint32

const (
	// Never a policy's.
	SmtpMtaStsModeUnspecified SmtpMtaStsMode = 0
	// No delivery to an MX that fails: TL2.
	SmtpMtaStsModeEnforce SmtpMtaStsMode = 1
	// Delivery as though there were no policy, with reports; not TL2.
	SmtpMtaStsModeTesting SmtpMtaStsMode = 2
	// No policy, which replaces an earlier one (§8.3).
	SmtpMtaStsModeNone SmtpMtaStsMode = 3
)

// One recipient domain's policy (RFC 8461 §3.2).
type SmtpMtaStsPolicy struct {
	// The TXT record's id the policy was fetched under.
	Id   string
	Mode SmtpMtaStsMode
	// The mx: patterns, lowercase with no trailing dot: a host, or *. and a domain.
	MxPatterns []string
	// max_age, at most 31557600 s.
	MaxAge    time.Duration
	FetchTime time.Time
}

// When the policy stops applying: max_age after its fetch.
func (self *SmtpMtaStsPolicy) ExpireTime() time.Time {
	return self.FetchTime.Add(self.MaxAge)
}

// Whether the policy is mode: enforce, the only one that makes TL2.
func (self *SmtpMtaStsPolicy) Enforced() bool {
	return self.Mode == SmtpMtaStsModeEnforce
}

// Whether an mx: pattern names mxHost (RFC 8461 §4.1): exactly, or by *. standing for the whole
// left-most label, so *.example.net names mail.example.net and neither example.net nor
// a.b.example.net.
func (self *SmtpMtaStsPolicy) MatchesMx(mxHost string) bool {
	mxHost, ok := smtpTlsName(mxHost)
	if !ok {
		return false
	}
	for _, pattern := range self.MxPatterns {
		if suffix, wildcard := strings.CutPrefix(pattern, "*."); wildcard {
			label, rest, found := strings.Cut(mxHost, ".")
			if found && label != "" && rest == suffix {
				return true
			}
		} else if pattern == mxHost {
			return true
		}
	}
	return false
}

// A copy sharing nothing with this one.
func (self *SmtpMtaStsPolicy) clone() *SmtpMtaStsPolicy {
	clone := *self
	clone.MxPatterns = slices.Clone(self.MxPatterns)
	return &clone
}

// Whether name is an extension field's name: a letter or digit, then letters, digits, _, - and .
func smtpMtaStsFieldNameForm(name string) bool {
	if name == "" || smtpMtaStsFieldNameMaxLength < len(name) {
		return false
	}
	for i := range len(name) {
		c := name[i]
		alphaDigit := 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
		if !alphaDigit && (i == 0 || c != '_' && c != '-' && c != '.') {
			return false
		}
	}
	return true
}

// Whether id is 1 to 32 letters and digits.
func smtpMtaStsIdForm(id string) bool {
	if id == "" || smtpMtaStsIdMaxLength < len(id) {
		return false
	}
	for i := range len(id) {
		c := id[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9') {
			return false
		}
	}
	return true
}

// Whether value is a TXT field's value: printable US-ASCII without = and ;.
func smtpMtaStsTxtValueForm(value string) bool {
	if value == "" {
		return false
	}
	for i := range len(value) {
		c := value[i]
		if c < 0x21 || 0x7e < c || c == '=' || c == ';' {
			return false
		}
	}
	return true
}

// The id of the one MTA-STS TXT record among texts, each a record's strings joined (RFC 8461 §3.1),
// and false when there is not exactly one record beginning v=STSv1, or that one does not parse.
func parseSmtpMtaStsTxt(texts []string) (string, bool) {
	var records []string
	for _, text := range texts {
		rest, found := strings.CutPrefix(text, smtpMtaStsTxtVersion)
		if !found {
			continue
		}
		rest = strings.TrimLeft(rest, " \t")
		if !strings.HasPrefix(rest, ";") {
			continue
		}
		records = append(records, rest)
	}
	if len(records) != 1 {
		return "", false
	}
	// each field follows a ;, and only a final ; may leave nothing after it
	fields := strings.Split(records[0], ";")[1:]
	id := ""
	for index, field := range fields {
		field = strings.Trim(field, " \t")
		if field == "" {
			if index == len(fields)-1 && 0 < index {
				continue
			}
			return "", false
		}
		name, value, found := strings.Cut(field, "=")
		if !found || !smtpMtaStsFieldNameForm(name) || !smtpMtaStsTxtValueForm(value) {
			return "", false
		}
		if name == "id" {
			if !smtpMtaStsIdForm(value) {
				return "", false
			}
			if id == "" {
				id = value
			}
		}
	}
	return id, id != ""
}

// A policy body (RFC 8461 §3.2): key: value lines ended by LF or CRLF, version STSv1, mode, max_age
// and, unless the mode is none, at least one mx. The first of a repeated field other than mx counts,
// unknown fields are ignored, and anything else is ErrSmtpMtaStsPolicyInvalid. Id and FetchTime are
// the caller's to set.
func ParseSmtpMtaStsPolicy(body []byte) (*SmtpMtaStsPolicy, error) {
	if !utf8.Valid(body) {
		return nil, fmt.Errorf("%w: not utf-8", ErrSmtpMtaStsPolicyInvalid)
	}
	keyValues := map[string]string{}
	policy := &SmtpMtaStsPolicy{}
	for line := range strings.SplitSeq(string(body), "\n") {
		line = strings.TrimRight(strings.TrimSuffix(line, "\r"), " \t")
		if line == "" {
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found || !smtpMtaStsFieldNameForm(key) {
			return nil, fmt.Errorf("%w: a line that is no field", ErrSmtpMtaStsPolicyInvalid)
		}
		value = strings.TrimLeft(value, " \t")
		if key == "mx" {
			pattern, ok := smtpTlsName(strings.TrimPrefix(value, "*."))
			if !ok {
				return nil, fmt.Errorf("%w: an mx pattern", ErrSmtpMtaStsPolicyInvalid)
			}
			if strings.HasPrefix(value, "*.") {
				pattern = "*." + pattern
			}
			policy.MxPatterns = append(policy.MxPatterns, pattern)
			continue
		}
		if _, seen := keyValues[key]; !seen {
			keyValues[key] = value
		}
	}
	if keyValues["version"] != smtpMtaStsPolicyVersion {
		return nil, fmt.Errorf("%w: version", ErrSmtpMtaStsPolicyInvalid)
	}
	switch keyValues["mode"] {
	case "enforce":
		policy.Mode = SmtpMtaStsModeEnforce
	case "testing":
		policy.Mode = SmtpMtaStsModeTesting
	case "none":
		policy.Mode = SmtpMtaStsModeNone
	default:
		return nil, fmt.Errorf("%w: mode", ErrSmtpMtaStsPolicyInvalid)
	}
	maxAge := keyValues["max_age"]
	if maxAge == "" || smtpMtaStsMaxAgeMaxDigitCount < len(maxAge) {
		return nil, fmt.Errorf("%w: max_age", ErrSmtpMtaStsPolicyInvalid)
	}
	seconds, err := strconv.ParseUint(maxAge, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: max_age", ErrSmtpMtaStsPolicyInvalid)
	}
	// held to its maximum before it is a duration, which ten digits of seconds would overflow
	policy.MaxAge = time.Duration(min(seconds, uint64(smtpMtaStsMaxAgeMax/time.Second))) * time.Second
	if len(policy.MxPatterns) == 0 && policy.Mode != SmtpMtaStsModeNone {
		return nil, fmt.Errorf("%w: no mx", ErrSmtpMtaStsPolicyInvalid)
	}
	return policy, nil
}

// The cache's stored file.
type smtpMtaStsFile struct {
	Version  int                 `json:"version"`
	Policies []*smtpMtaStsRecord `json:"policies"`
}

// A cached policy's stored form.
type smtpMtaStsRecord struct {
	Domain        string   `json:"domain"`
	Id            string   `json:"id"`
	Mode          uint32   `json:"mode"`
	MxPatterns    []string `json:"mx,omitempty"`
	MaxAgeSeconds int64    `json:"max_age_s"`
	FetchTimeMs   int64    `json:"fetch_time_ms"`
}

// The id and time of a domain's last failed fetch.
type smtpMtaStsFailure struct {
	id   string
	time time.Time
}

// One network sender's MTA-STS policies.
type SmtpMtaSts struct {
	doh       SmtpDohForwarder
	transport http.RoundTripper
	store     SidecarStore
	settings  *SmtpSenderSettings
	clock     Clock

	// serializes the load and every write, outside stateLock
	writeLock sync.Mutex

	stateLock      sync.Mutex
	loaded         bool
	domainPolicies map[string]*SmtpMtaStsPolicy
	domainFailures map[string]*smtpMtaStsFailure
}

// The policies found through doh and fetched through transport, which must dial from this device and
// never through the edge, cached in store, the sender's directory, under settings, which must have
// passed validate, on clock (nil is real time). A nil doh or transport finds or fetches nothing, so
// only a cached policy applies.
func NewSmtpMtaSts(doh SmtpDohForwarder, transport http.RoundTripper, store SidecarStore, settings *SmtpSenderSettings, clock Clock) *SmtpMtaSts {
	return &SmtpMtaSts{
		doh:            doh,
		transport:      transport,
		store:          store,
		settings:       settings,
		clock:          clockOrReal(clock),
		domainPolicies: map[string]*SmtpMtaStsPolicy{},
		domainFailures: map[string]*smtpMtaStsFailure{},
	}
}

// Loads the cache once. A store that cannot answer is an error, and the next call tries again.
func (self *SmtpMtaSts) load() error {
	loaded := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.loaded
	}()
	if loaded {
		return nil
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	data, found, err := smtpReadStoreFile(self.store, smtpMtaStsFileName)
	if err != nil {
		return err
	}
	domainPolicies := map[string]*SmtpMtaStsPolicy{}
	if found {
		file := &smtpMtaStsFile{}
		if err := json.Unmarshal(data, file); err != nil || file.Version != smtpMtaStsFileVersion {
			return fmt.Errorf("%w: mta-sts policies do not parse", ErrSidecarStoreFailed)
		}
		for _, record := range file.Policies {
			domain, policy, ok := record.policy()
			if !ok {
				return fmt.Errorf("%w: an mta-sts policy is malformed", ErrSidecarStoreFailed)
			}
			domainPolicies[domain] = policy
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !self.loaded {
		self.domainPolicies = domainPolicies
		self.loaded = true
	}
	return nil
}

// The domain and policy a stored record gives, or false for anything but this version's well-formed
// record.
func (self *smtpMtaStsRecord) policy() (string, *SmtpMtaStsPolicy, bool) {
	if self == nil {
		return "", nil, false
	}
	domain, ok := smtpTlsName(self.Domain)
	mode := SmtpMtaStsMode(self.Mode)
	if !ok || domain != self.Domain || !smtpMtaStsIdForm(self.Id) || mode < SmtpMtaStsModeEnforce || SmtpMtaStsModeNone < mode ||
		self.MaxAgeSeconds < 0 || int64(smtpMtaStsMaxAgeMax/time.Second) < self.MaxAgeSeconds || self.FetchTimeMs <= 0 {
		return "", nil, false
	}
	if len(self.MxPatterns) == 0 && mode != SmtpMtaStsModeNone {
		return "", nil, false
	}
	for _, pattern := range self.MxPatterns {
		name, ok := smtpTlsName(strings.TrimPrefix(pattern, "*."))
		if !ok || name != strings.TrimPrefix(pattern, "*.") {
			return "", nil, false
		}
	}
	return domain, &SmtpMtaStsPolicy{
		Id:         self.Id,
		Mode:       mode,
		MxPatterns: slices.Clone(self.MxPatterns),
		MaxAge:     time.Duration(self.MaxAgeSeconds) * time.Second,
		FetchTime:  time.UnixMilli(self.FetchTimeMs),
	}, true
}

// Keeps policy as domain's, with the cache pruned of what expired at now and, past
// MtaStsPolicyMaxCount, of the policies closest to expiring: written first, then taken into memory.
func (self *SmtpMtaSts) put(domain string, policy *SmtpMtaStsPolicy) error {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	now := self.clock.Now()
	domainPolicies := func() map[string]*SmtpMtaStsPolicy {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return maps.Clone(self.domainPolicies)
	}()
	domainPolicies[domain] = policy
	for cachedDomain, cached := range domainPolicies {
		if !now.Before(cached.ExpireTime()) {
			delete(domainPolicies, cachedDomain)
		}
	}
	if overCount := len(domainPolicies) - self.settings.MtaStsPolicyMaxCount; 0 < overCount {
		domains := slices.SortedFunc(maps.Keys(domainPolicies), func(a string, b string) int {
			return domainPolicies[a].ExpireTime().Compare(domainPolicies[b].ExpireTime())
		})
		for _, expiring := range domains[:overCount] {
			delete(domainPolicies, expiring)
		}
	}
	file := &smtpMtaStsFile{Version: smtpMtaStsFileVersion, Policies: []*smtpMtaStsRecord{}}
	for _, cachedDomain := range slices.Sorted(maps.Keys(domainPolicies)) {
		cached := domainPolicies[cachedDomain]
		file.Policies = append(file.Policies, &smtpMtaStsRecord{
			Domain:        cachedDomain,
			Id:            cached.Id,
			Mode:          uint32(cached.Mode),
			MxPatterns:    cached.MxPatterns,
			MaxAgeSeconds: int64(cached.MaxAge / time.Second),
			FetchTimeMs:   cached.FetchTime.UnixMilli(),
		})
	}
	data, err := json.Marshal(file)
	if err != nil {
		return fmt.Errorf("%w: mta-sts policies do not encode", ErrSidecarStoreFailed)
	}
	testHookBarrier("smtp.mta_sts_write.before", "")
	if err := smtpWriteStoreFile(self.store, smtpMtaStsFileName, data); err != nil {
		return err
	}
	testHookBarrier("smtp.mta_sts_write.after", "")
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.domainPolicies = domainPolicies
	return nil
}

// The id domain's _mta-sts TXT record names, and false when no one valid record answered: none, more
// than one, one that does not parse, or no usable answer at all.
func (self *SmtpMtaSts) lookupId(ctx context.Context, domain string) (string, bool) {
	if self.doh == nil {
		return "", false
	}
	answer, ok := smtpDohLookup(ctx, self.doh, self.clock, self.settings.TlsLookupTimeout, dnsmessage.TypeTXT, smtpMtaStsTxtPrefix+domain)
	if !ok {
		return "", false
	}
	var texts []string
	for _, resource := range answer.resources {
		if txt, ok := resource.Body.(*dnsmessage.TXTResource); ok {
			texts = append(texts, strings.Join(txt.TXT, ""))
		}
	}
	return parseSmtpMtaStsTxt(texts)
}

// Fetches domain's policy over HTTPS (RFC 8461 §3.3): one GET, a 200 of text/plain within
// MtaStsPolicyMaxByteCount, and no redirect followed, within MtaStsFetchTimeout on the clock.
func (self *SmtpMtaSts) fetch(ctx context.Context, domain string) (*SmtpMtaStsPolicy, error) {
	if self.transport == nil {
		return nil, fmt.Errorf("%w: no transport", errSmtpMtaStsFetch)
	}
	fetchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := self.clock.AfterFunc(self.settings.MtaStsFetchTimeout, cancel)
	defer stop()
	request, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, "https://"+smtpMtaStsHostPrefix+domain+smtpMtaStsPath, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: a request that does not build", errSmtpMtaStsFetch)
	}
	// RoundTrip follows no redirect, and nothing here caches
	response, err := self.transport.RoundTrip(request)
	if err != nil {
		// the transport's error names the url, and so the domain: it stays here
		return nil, errSmtpMtaStsFetch
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", errSmtpMtaStsFetch, response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != smtpMtaStsMediaType {
		return nil, fmt.Errorf("%w: not text/plain", errSmtpMtaStsFetch)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(self.settings.MtaStsPolicyMaxByteCount)+1))
	if err != nil {
		return nil, errSmtpMtaStsFetch
	}
	if self.settings.MtaStsPolicyMaxByteCount < len(body) {
		return nil, fmt.Errorf("%w: past %d octets", errSmtpMtaStsFetch, self.settings.MtaStsPolicyMaxByteCount)
	}
	return ParseSmtpMtaStsPolicy(body)
}

// The policy that applies to a send to recipientDomain now (RFC 8461 §5.1), a copy, or nil when none
// does: none found, none fetched and none cached, or one that has expired. Only mode: enforce makes
// TL2, so a caller reads Enforced. Its only error is the store's, on which the caller holds the send:
// a cache that cannot be read could hide a policy that applies.
func (self *SmtpMtaSts) Policy(ctx context.Context, recipientDomain string) (*SmtpMtaStsPolicy, error) {
	domain, ok := smtpTlsName(recipientDomain)
	if !ok {
		return nil, ErrSmtpTlsRequest
	}
	if err := self.load(); err != nil {
		return nil, err
	}
	cachedAt := func(now time.Time) *SmtpMtaStsPolicy {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		cached, ok := self.domainPolicies[domain]
		if !ok || !now.Before(cached.ExpireTime()) {
			return nil
		}
		return cached.clone()
	}
	id, idOk := self.lookupId(ctx, domain)
	now := self.clock.Now()
	cached := cachedAt(now)
	if !idOk || cached != nil && cached.Id == id {
		return cached, nil
	}
	failed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		failure, ok := self.domainFailures[domain]
		return ok && failure.id == id && now.Before(failure.time.Add(self.settings.MtaStsFetchRetryTimeout))
	}()
	if failed {
		return cached, nil
	}
	policy, err := self.fetch(ctx, domain)
	if err != nil {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			// what no longer holds a fetch back goes, so the map holds only the last few minutes' failures
			for failedDomain, failure := range self.domainFailures {
				if !now.Before(failure.time.Add(self.settings.MtaStsFetchRetryTimeout)) {
					delete(self.domainFailures, failedDomain)
				}
			}
			self.domainFailures[domain] = &smtpMtaStsFailure{id: id, time: now}
		}()
		return cached, nil
	}
	policy.Id = id
	policy.FetchTime = self.clock.Now()
	if err := self.put(domain, policy); err != nil {
		return nil, err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.domainFailures, domain)
	}()
	return policy.clone(), nil
}
