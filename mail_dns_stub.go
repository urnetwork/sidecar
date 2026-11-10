//go:build !sidecar_http && !ios_extension

// A receiver's DNS stub (g0-recheck-0-receiver-evidence#1; MAIL-M7-07): the per-receiver cache in front of its own
// DohCache.Forward, which caches nothing, as Forward's doc says the caller's stub does. Answers are kept by record
// TTL, at most StubMaxTtl; NXDOMAIN and NODATA for min(the SOA's TTL and minimum, StubNegativeMaxTtl), and not at all
// without an SOA; a failure, a timeout or a budget's refusal never. StubEntryMaxCount answers are kept, least
// recently used out, in memory only.
//
// A reply is parsed with golang.org/x/net/dns/dnsmessage and held to its question: a response, not truncated, one
// question of the name and type asked in class IN, NOERROR or NXDOMAIN. Anything else, and bytes that do not parse,
// are no answer, which a check calls temperror; nothing here panics on what a resolver sends. The records kept are
// the asked type's at the name, or at the end of the CNAMEs the answer carries from it.
//
// Names are compared lowercase without the trailing dot, and are never logged (I-13). Safe for concurrent use.

package sidecar

import (
	"container/list"
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// No usable answer: a failed, refused, truncated or malformed reply, one to another question, or the query's
// timeout. A check calls it temperror.
var ErrMailDnsNoAnswer = errors.New("mail dns: no usable answer")

// What a receiver's lookups go over: connect's DohCache.Forward, the raw RFC 8484 reply to qType for a domain given
// without a trailing dot, and whether a usable one came (§2.8 ext-3). Each receiver owns its own (CODESTYLE's DoH
// rule). Safe for concurrent use.
type MailDohForwarder interface {
	Forward(ctx context.Context, qType dnsmessage.Type, domain string) (response []byte, usable bool)
}

// A lookup's key: the name, lowercase with no trailing dot, and the type.
type mailDnsKey struct {
	name  string
	qType dnsmessage.Type
}

// What a name and type resolved to.
type mailDnsAnswer struct {
	// NXDOMAIN; else NOERROR, records empty for NODATA.
	nameError bool
	records   []dnsmessage.Resource
}

// Whether the answer holds no record: NXDOMAIN or NODATA, both mox's not-found.
func (self *mailDnsAnswer) empty() bool {
	return self.nameError || len(self.records) == 0
}

// One answer kept.
type mailDnsStubEntry struct {
	key     mailDnsKey
	answer  *mailDnsAnswer
	expires time.Time
}

// A receiver's stub. See the file header.
type MailDnsStub struct {
	forwarder MailDohForwarder
	clock     Clock
	settings  *MailAuthSettings

	stateLock sync.Mutex
	// most recently used first
	order   *list.List
	entries map[mailDnsKey]*list.Element
}

// A stub over forwarder, its TTLs read on clock, real time when nil.
func NewMailDnsStub(forwarder MailDohForwarder, clock Clock, settings *MailAuthSettings) *MailDnsStub {
	return &MailDnsStub{
		forwarder: forwarder,
		clock:     clockOrReal(clock),
		settings:  settings,
		order:     list.New(),
		entries:   map[mailDnsKey]*list.Element{},
	}
}

// A name as the stub keys it.
func mailDnsName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// The answer kept for key while it is fresh.
func (self *MailDnsStub) get(key mailDnsKey) (*mailDnsAnswer, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	element, ok := self.entries[key]
	if !ok {
		return nil, false
	}
	entry := element.Value.(*mailDnsStubEntry)
	if !self.clock.Now().Before(entry.expires) {
		self.order.Remove(element)
		delete(self.entries, key)
		return nil, false
	}
	self.order.MoveToFront(element)
	return entry.answer, true
}

// Keeps an answer for ttl, dropping the least recently used past the bound.
func (self *MailDnsStub) put(key mailDnsKey, answer *mailDnsAnswer, ttl time.Duration) {
	if ttl <= 0 || self.settings.StubEntryMaxCount <= 0 {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entry := &mailDnsStubEntry{key: key, answer: answer, expires: self.clock.Now().Add(ttl)}
	if element, ok := self.entries[key]; ok {
		element.Value = entry
		self.order.MoveToFront(element)
		return
	}
	self.entries[key] = self.order.PushFront(entry)
	for self.settings.StubEntryMaxCount < self.order.Len() {
		oldest := self.order.Back()
		self.order.Remove(oldest)
		delete(self.entries, oldest.Value.(*mailDnsStubEntry).key)
	}
}

// The answers kept now.
func (self *MailDnsStub) Len() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.order.Len()
}

// One query for key once admit gives it a slot, held to QueryTimeout on the stub's clock and to ctx, its answer kept
// by its TTL. admit's error comes back as it was given, and no answer is kept for a failure. A caller asks get
// first, so a fresh kept answer spends nothing.
func (self *MailDnsStub) query(ctx context.Context, key mailDnsKey, admit func() (func(), error)) (*mailDnsAnswer, error) {
	release, err := admit()
	if err != nil {
		return nil, err
	}
	defer release()
	queryCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := self.clock.AfterFunc(self.settings.QueryTimeout, cancel)
	defer stop()
	response, usable := self.forwarder.Forward(queryCtx, key.qType, key.name)
	if !usable || queryCtx.Err() != nil {
		return nil, ErrMailDnsNoAnswer
	}
	answer, ttl, ok := parseMailDnsResponse(response, key)
	if !ok {
		return nil, ErrMailDnsNoAnswer
	}
	if answer.empty() {
		ttl = min(ttl, self.settings.StubNegativeMaxTtl)
	} else {
		ttl = min(ttl, self.settings.StubMaxTtl)
	}
	self.put(key, answer, ttl)
	return answer, nil
}

// A reply held to its question, and how long it may be kept: the shortest TTL of the records kept, or for NXDOMAIN
// and NODATA the authority SOA's TTL and minimum, the shorter, or 0 with no SOA. false for anything that is no
// usable answer.
func parseMailDnsResponse(response []byte, key mailDnsKey) (*mailDnsAnswer, time.Duration, bool) {
	var parser dnsmessage.Parser
	header, err := parser.Start(response)
	if err != nil || !header.Response || header.Truncated {
		return nil, 0, false
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 || questions[0].Type != key.qType || questions[0].Class != dnsmessage.ClassINET ||
		mailDnsName(questions[0].Name.String()) != key.name {
		return nil, 0, false
	}
	switch header.RCode {
	case dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError:
	default:
		return nil, 0, false
	}
	answers, err := parser.AllAnswers()
	if err != nil {
		return nil, 0, false
	}
	answer := &mailDnsAnswer{nameError: header.RCode == dnsmessage.RCodeNameError}
	ttlSeconds := uint32(0)
	if !answer.nameError {
		// one hop a record at most, so a loop of CNAMEs ends
		current := key.name
		for range answers {
			next := ""
			for _, resource := range answers {
				if cname, ok := resource.Body.(*dnsmessage.CNAMEResource); ok && resource.Header.Class == dnsmessage.ClassINET &&
					mailDnsName(resource.Header.Name.String()) == current {
					next = mailDnsName(cname.CNAME.String())
					break
				}
			}
			if next == "" {
				break
			}
			current = next
		}
		for _, resource := range answers {
			if resource.Header.Type == key.qType && resource.Header.Class == dnsmessage.ClassINET &&
				mailDnsName(resource.Header.Name.String()) == current {
				if len(answer.records) == 0 || resource.Header.TTL < ttlSeconds {
					ttlSeconds = resource.Header.TTL
				}
				answer.records = append(answer.records, resource)
			}
		}
	}
	if answer.empty() {
		ttlSeconds = 0
		authorities, err := parser.AllAuthorities()
		if err == nil {
			for _, resource := range authorities {
				if soa, ok := resource.Body.(*dnsmessage.SOAResource); ok {
					ttlSeconds = min(resource.Header.TTL, soa.MinTTL)
					break
				}
			}
		}
	}
	return answer, time.Duration(ttlSeconds) * time.Second, true
}
