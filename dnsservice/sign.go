// Online signing (§12.6's Signing, D-DNS-5; owner decisions 69 and 109). Signer wraps Answer: under DO
// it makes denials compact (denial.go) and adds an RRSIG to every RRset, made now by the current ZSK,
// ECDSA P-256. An RRSIG's owner and labels are the name as answered, so a wildcard's answer is signed
// as the queried name and shows neither that a wildcard covered it nor which names exist (RFC 4035
// §5.3.4 needs no proof of a closer name for it). DNSKEY answers come only from the released window's
// pre-signed RRset and signatures, since an edge holds no KSK.
//
// A cache keyed by the ZSK, owner, type and a digest of the RRset as answered serves first, and
// signatures_per_second caps only fresh signatures. Past the cap an answer needing a fresh one is never
// sent unsigned (reading 13): over UDP it goes out empty with TC set, so a resolver retries over TCP,
// and over TCP it is SERVFAIL. Without DO nothing is signed, and nothing is drawn from the cap.

package dnsservice

import (
	"container/list"
	"crypto/sha256"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/urnetwork/sidecar"
)

// What the cache knows an RRSIG by. Comparable, so it keys a map.
type dnsSignatureKey struct {
	// The ZSK's identity, so a new key never serves an old key's signature.
	zskId [sha256.Size]byte
	// Lowercase, since canonical form lowercases it and a query's case is the client's.
	owner  string
	rrType uint16
	// See dnsRrsetDigest.
	digest [sha256.Size]byte
}

// The cache's digest of an RRset as answered: each record's type, class, TTL and rdata as they go on
// the wire, uncompressed, behind the owner in lowercase. An answer's records come in an order its view
// and healthy set fix, so one RRset always digests alike. False for a record that does not pack, which
// is then signed fresh and not cached.
func dnsRrsetDigest(rrset []dns.RR) ([sha256.Size]byte, bool) {
	hash := sha256.New()
	hash.Write([]byte(strings.ToLower(rrset[0].Header().Name)))
	for _, record := range rrset {
		buffer := make([]byte, dns.Len(record))
		length, err := dns.PackRR(record, buffer, 0, nil, false)
		if err != nil {
			return [sha256.Size]byte{}, false
		}
		// the owner leads, uncompressed, so its labels run to the first zero octet
		start := 0
		for start < length && buffer[start] != 0 {
			start += int(buffer[start]) + 1
		}
		if length <= start {
			return [sha256.Size]byte{}, false
		}
		hash.Write(buffer[start+1 : length])
	}
	var digest [sha256.Size]byte
	hash.Sum(digest[:0])
	return digest, true
}

// One cached signature, and its place in the recency list.
type dnsSignatureEntry struct {
	key   dnsSignatureKey
	rrsig *dns.RRSIG
}

// Signatures by the RRset they cover, the least recently used dropped past the setting's count. Safe
// for concurrent use; a held RRSIG is never changed, so a caller copies it before setting its owner.
type dnsSignatureCache struct {
	entryCount int

	stateLock sync.Mutex
	entries   map[dnsSignatureKey]*list.Element
	recency   *list.List
}

func newDnsSignatureCache(entryCount int) *dnsSignatureCache {
	return &dnsSignatureCache{
		entryCount: entryCount,
		entries:    map[dnsSignatureKey]*list.Element{},
		recency:    list.New(),
	}
}

// The signature for key while it is valid at now with at least need left, or nil.
func (self *dnsSignatureCache) get(key dnsSignatureKey, now time.Time, need time.Duration) *dns.RRSIG {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	element, ok := self.entries[key]
	if !ok {
		return nil
	}
	rrsig := element.Value.(*dnsSignatureEntry).rrsig
	// RFC 4034 §3.1.5's times are serial numbers, read by RFC 1982 near now
	nowSeconds := uint32(now.Unix())
	if int32(nowSeconds-rrsig.Inception) < 0 || int64(int32(rrsig.Expiration-nowSeconds)) < int64(need/time.Second) {
		return nil
	}
	self.recency.MoveToFront(element)
	return rrsig
}

// Keeps rrsig for key, dropping the least recently used past the bound.
func (self *dnsSignatureCache) put(key dnsSignatureKey, rrsig *dns.RRSIG) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if element, ok := self.entries[key]; ok {
		element.Value.(*dnsSignatureEntry).rrsig = rrsig
		self.recency.MoveToFront(element)
		return
	}
	self.entries[key] = self.recency.PushFront(&dnsSignatureEntry{key: key, rrsig: rrsig})
	for self.entryCount < self.recency.Len() {
		oldest := self.recency.Back()
		self.recency.Remove(oldest)
		delete(self.entries, oldest.Value.(*dnsSignatureEntry).key)
	}
}

// signatures_per_second as a token bucket on the signer's clock. It holds one second's worth, and at
// least what one answer can need, so an answer is never refused for its size alone. Safe for
// concurrent use.
type dnsSignatureBudget struct {
	ratePerSecond float64
	capacity      float64

	stateLock sync.Mutex
	tokens    float64
	last      time.Time
}

// A full bucket at now.
func newDnsSignatureBudget(ratePerSecond int, answerMaxCount int, now time.Time) *dnsSignatureBudget {
	capacity := float64(max(ratePerSecond, answerMaxCount))
	return &dnsSignatureBudget{ratePerSecond: float64(ratePerSecond), capacity: capacity, tokens: capacity, last: now}
}

// Takes count signatures at now, all of them or none.
func (self *dnsSignatureBudget) take(count int, now time.Time) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if elapsed := now.Sub(self.last); 0 < elapsed {
		self.tokens = min(self.capacity, self.tokens+elapsed.Seconds()*self.ratePerSecond)
		self.last = now
	}
	if self.tokens < float64(count) {
		return false
	}
	self.tokens -= float64(count)
	return true
}

// Signs answers online. Safe for concurrent use: the cache and the cap are the only state, and both
// lock briefly. One signer serves every root an edge holds.
type Signer struct {
	settings *DnsSettings
	clock    sidecar.Clock
	// nil for SelfCheck's probes, which count nothing
	metrics *dnsMetrics
	// nil for SelfCheck's probes, which sign every RRset fresh
	cache *dnsSignatureCache
	// nil for SelfCheck's probes, which take nothing from the cap
	budget *dnsSignatureBudget
}

// A signer for an edge. settings must be valid. clock nil is real time, and metrics nil counts nothing.
func NewSigner(settings *DnsSettings, clock sidecar.Clock, metrics sidecar.Metrics) *Signer {
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	// the most RRsets one signed answer holds: a CNAME chain to its bound and its target, then the SOA
	// and NSEC of a denial
	answerMaxCount := settings.CnameChainMaxCount + 3
	self := &Signer{
		settings: settings,
		clock:    clock,
		cache:    newDnsSignatureCache(settings.Signing.CacheEntryCount),
		budget:   newDnsSignatureBudget(settings.SignaturesPerSecond, answerMaxCount, clock.Now()),
	}
	if metrics != nil {
		self.metrics = newDnsMetrics(metrics)
	}
	return self
}

// The answer to query from view under keys, at this moment's healthy set: Answer's, made compact and
// signed under DO. keys must be the set SelfCheck passed for view. With no keys, or keys of another
// root, a DO query gets SERVFAIL rather than an unsigned answer, and any other gets Answer's.
func (self *Signer) Answer(query *DnsQuery, view *ZoneView, keys *DnsSigningKeys, healthy *HealthySet) *dns.Msg {
	return self.answerAt(query, view, keys, healthy, self.clock.Now())
}

// How a reply's signing went.
type dnsSignResult int

const (
	dnsSigned dnsSignResult = iota
	// a fresh signature was needed and the cap had none
	dnsSignCapped
	// the ZSK refused, or a denial could not be made compact
	dnsSignFailed
)

// Answer at now, for a caller that holds the time: SelfCheck's probes.
func (self *Signer) answerAt(query *DnsQuery, view *ZoneView, keys *DnsSigningKeys, healthy *HealthySet, now time.Time) *dns.Msg {
	return self.signReply(query, Answer(query, view, healthy), view, keys, healthy, now)
}

// Signs reply, which is Answer's for query from view at healthy, in place, and returns it: the edge
// asks Answer first, so RRL can drop a response before anything is signed for it.
func (self *Signer) signReply(query *DnsQuery, reply *dns.Msg, view *ZoneView, keys *DnsSigningKeys, healthy *HealthySet, now time.Time) *dns.Msg {
	if reply == nil || (reply.Rcode != dns.RcodeSuccess && reply.Rcode != dns.RcodeNameError) {
		return reply
	}
	// Answer answers these two only for one IN question of opcode QUERY, from a view, with at most one
	// OPT, which its reply mirrors with the query's DO
	request := query.Message
	question := request.Question[0]
	if question.Qtype == dns.TypeNXNAME {
		// RFC 9824: NXNAME is a meta-type, never asked for
		return dnsEmptyReply(reply, dns.RcodeFormatError)
	}
	opt := reply.IsEdns0()
	signed := opt != nil && opt.Do()
	if keys == nil || keys.root != view.root {
		if signed {
			return dnsEmptyReply(reply, dns.RcodeServerFailure)
		}
		return reply
	}
	limit := dnsAnswerLimit(query, request.IsEdns0(), self.settings)
	if reply.Truncated {
		return reply
	}
	if question.Qtype == dns.TypeDNSKEY && dns.CanonicalName(question.Name) == view.root && dnsReplyDeniesData(reply) {
		reply.Answer = keys.dnskeyRecords(question.Name)
		reply.Ns = nil
		if signed {
			reply.Answer = append(reply.Answer, keys.dnskeyRrsigRecords(question.Name)...)
		}
		fitDnsAnswer(reply, limit)
		return reply
	}
	if !signed {
		return reply
	}
	compactAnswers := request.IsEdns0().Co()
	if !self.makeDenialCompact(reply, question, view, healthy, compactAnswers) {
		return dnsEmptyReply(reply, dns.RcodeServerFailure)
	}
	switch self.signSections(reply, keys, now) {
	case dnsSignCapped:
		if self.metrics != nil {
			self.metrics.signatureCapped.Add(1, dnsTransportLabel(query.Tcp))
		}
		if query.Tcp {
			return dnsEmptyReply(reply, dns.RcodeServerFailure)
		}
		capped := dnsEmptyReply(reply, dns.RcodeSuccess)
		capped.Authoritative = true
		capped.Truncated = true
		return capped
	case dnsSignFailed:
		return dnsEmptyReply(reply, dns.RcodeServerFailure)
	}
	if compactAnswers {
		opt.SetCo()
	}
	fitDnsAnswer(reply, limit)
	return reply
}

// reply with rcode and nothing but its question and OPT, which an error and a refusal at the cap carry.
func dnsEmptyReply(reply *dns.Msg, rcode int) *dns.Msg {
	reply.Rcode = rcode
	reply.Authoritative = false
	reply.Answer = nil
	reply.Ns = nil
	return reply
}

// The transport label of the signature_capped metric.
func dnsTransportLabel(tcp bool) string {
	if tcp {
		return "tcp"
	}
	return "udp"
}

// Turns a plain denial into RFC 9824's under DO: NXDOMAIN becomes NOERROR with an NSEC at the name
// whose types are RRSIG, NSEC and NXNAME, unless the client set CO (reading 14); an empty answer gets an
// NSEC at the name with its real types. An NSEC asked for at a name that exists is the answer itself.
// A positive answer is left as it is. False when the name is too long to deny compactly.
func (self *Signer) makeDenialCompact(reply *dns.Msg, question dns.Question, view *ZoneView, healthy *HealthySet, compactAnswers bool) bool {
	nameError := reply.Rcode == dns.RcodeNameError
	if !nameError && !dnsReplyDeniesData(reply) {
		return true
	}
	denied := dnsDeniedName(reply, question.Name)
	canonicalDenied := dns.CanonicalName(denied)
	// RFC 9077: an NSEC lives no longer than the negative TTL, which is the denial SOA's
	ttl := view.denialSoa().Hdr.Ttl
	var types []uint16
	if nameError {
		types = []uint16{dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNXNAME}
		if !compactAnswers {
			reply.Rcode = dns.RcodeSuccess
		}
	} else {
		types = append(view.dataTypes(canonicalDenied, healthy), dnsSignedNameTypes...)
		if canonicalDenied == view.root {
			types = append(types, dns.TypeDNSKEY)
		}
	}
	nsec, ok := dnsCompactNsec(denied, ttl, types)
	if !ok {
		return false
	}
	if !nameError && question.Qtype == dns.TypeNSEC && canonicalDenied == dns.CanonicalName(question.Name) {
		reply.Answer = append(reply.Answer, nsec)
		reply.Ns = nil
		return true
	}
	reply.Ns = append(reply.Ns, nsec)
	return true
}

// A section's records as RRsets, in the order they first appear. Answer writes each RRset's records
// together, so this keeps its order whole.
func dnsRrsets(records []dns.RR) [][]dns.RR {
	type rrsetKey struct {
		owner  string
		rrType uint16
	}
	rrsets := [][]dns.RR{}
	indexes := map[rrsetKey]int{}
	for _, record := range records {
		key := rrsetKey{owner: dns.CanonicalName(record.Header().Name), rrType: record.Header().Rrtype}
		if index, ok := indexes[key]; ok {
			rrsets[index] = append(rrsets[index], record)
			continue
		}
		indexes[key] = len(rrsets)
		rrsets = append(rrsets, []dns.RR{record})
	}
	return rrsets
}

// Puts an RRSIG behind every RRset in reply's answer and authority sections: the cache's when it holds
// one with enough time left, else a fresh one from the cap. Nothing changes unless every RRset can be
// signed, so a reply is never half-signed.
func (self *Signer) signSections(reply *dns.Msg, keys *DnsSigningKeys, now time.Time) dnsSignResult {
	type pendingRrset struct {
		rrset  []dns.RR
		key    dnsSignatureKey
		keyed  bool
		rrsig  *dns.RRSIG
		answer bool
	}
	// a cached signature serves while it has refresh_s left, or all the window has left when that is
	// less, since none is made to outlive the window
	need := dnsSeconds(self.settings.Signing.RefreshSeconds)
	if windowLeft := keys.notAfter.Sub(now); 0 < windowLeft && windowLeft < need {
		need = windowLeft
	}
	pendings := []*pendingRrset{}
	freshCount := 0
	for sectionIndex, section := range [][]dns.RR{reply.Answer, reply.Ns} {
		for _, rrset := range dnsRrsets(section) {
			pending := &pendingRrset{rrset: rrset, answer: sectionIndex == 0}
			if digest, ok := dnsRrsetDigest(rrset); ok && self.cache != nil {
				pending.key = dnsSignatureKey{
					zskId:  keys.zskId,
					owner:  strings.ToLower(rrset[0].Header().Name),
					rrType: rrset[0].Header().Rrtype,
					digest: digest,
				}
				pending.keyed = true
				pending.rrsig = self.cache.get(pending.key, now, need)
			}
			if pending.rrsig == nil {
				freshCount += 1
			}
			pendings = append(pendings, pending)
		}
	}
	if 0 < freshCount && self.budget != nil && !self.budget.take(freshCount, now) {
		return dnsSignCapped
	}
	for _, pending := range pendings {
		if pending.rrsig != nil {
			if self.metrics != nil {
				self.metrics.signatures.Add(1, dnsSignatureSourceCache)
			}
			continue
		}
		rrsig, err := self.sign(pending.rrset, keys, now)
		if err != nil {
			return dnsSignFailed
		}
		if self.metrics != nil {
			self.metrics.signatures.Add(1, dnsSignatureSourceFresh)
		}
		pending.rrsig = rrsig
		if pending.keyed {
			self.cache.put(pending.key, rrsig)
		}
	}
	answer := []dns.RR{}
	authority := []dns.RR{}
	for _, pending := range pendings {
		rrsig := dns.Copy(pending.rrsig).(*dns.RRSIG)
		rrsig.Hdr.Name = pending.rrset[0].Header().Name
		if pending.answer {
			answer = append(answer, pending.rrset...)
			answer = append(answer, rrsig)
		} else {
			authority = append(authority, pending.rrset...)
			authority = append(authority, rrsig)
		}
	}
	reply.Answer = answer
	reply.Ns = authority
	return dnsSigned
}

// A fresh RRSIG over rrset by keys' ZSK: its inception the setting's offset before now, and its
// expiration a jittered lifetime after, cut to the window's end while the window has not ended.
func (self *Signer) sign(rrset []dns.RR, keys *DnsSigningKeys, now time.Time) (*dns.RRSIG, error) {
	signing := &self.settings.Signing
	lifetime := dnsSeconds(signing.LifetimeSeconds)
	if 0 < signing.JitterSeconds {
		lifetime -= time.Duration(rand.Int64N(int64(dnsSeconds(signing.JitterSeconds)) + 1))
	}
	expiration := now.Add(lifetime)
	if keys.notAfter.Before(expiration) && now.Before(keys.notAfter) {
		expiration = keys.notAfter
	}
	header := rrset[0].Header()
	rrsig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: header.Name, Rrtype: dns.TypeRRSIG, Class: header.Class, Ttl: header.Ttl},
		Algorithm:  dnsSigningAlgorithm,
		KeyTag:     keys.zskTag,
		SignerName: keys.root,
		Inception:  uint32(now.Add(-dnsSeconds(signing.InceptionOffsetSeconds)).Unix()),
		Expiration: uint32(expiration.Unix()),
	}
	// miekg sets the labels from the owner, which is the name as answered, and the original TTL from
	// the RRset's
	if err := rrsig.Sign(keys.zsk, rrset); err != nil {
		return nil, err
	}
	return rrsig, nil
}
