//go:build !sidecar_http && !js && !ios_extension

// Every lookup a receiver's checks make (D-MAIL-3, D-MAIL-14, FS-121; MAIL-M7-07), over its own DohCache.Forward
// (§2.8 ext-3) through its MailDnsStub, within one message's MailAuthBudget, as the resolver mox's dkim, spf and dmarc
// take (mox's dns.Resolver). One MailAuthResolver is one message's lookups at one priority; WithPriority gives the
// same message's lookups at another, sharing its budget and its memo.
//
// The memo answers each name and type once a message, failures and bounds included, since mox's dkim.Verify looks
// up each signature's key with no dedupe and a sender may repeat one selector many times. A lookup runs under the
// budget's context, not its first caller's, so a caller that stops waiting leaves the answer for the rest. Cut tells
// a check which of its lookups a bound cut, since mox folds every lookup error into its own temperror text.
//
// TXT, A, AAAA, MX, PTR and TLSA are looked up; names are absolute, as mox gives them, and a relative one is refused.
// Authentic is always false: DohCache.Forward asks for no DNSSEC data (plan-MAIL-dnssec-evidence). CNAME, NS, SRV and
// port lookups are no check's, and are refused. An answer's records are mox's types: TXT records each one string,
// MX hosts and PTR names absolute, TLSA records as adns holds them.
//
// Off sidecar_http, since it links connect, and off js, where mox's adns does not compile. Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/mjl-/adns"
	moxdns "github.com/mjl-/mox/dns"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/urnetwork/connect"
)

// TLSA's record type (RFC 6698), which dnsmessage has no constant for.
const mailDnsTypeTlsa dnsmessage.Type = 52

// connect's own cache is what a receiver hands its stub, and this is what mox's packages take.
var (
	_ MailDohForwarder = (*connect.DohCache)(nil)
	_ moxdns.Resolver  = (*MailAuthResolver)(nil)
)

// A lookup no mail check makes, or of a relative name.
var ErrMailAuthLookupRefused = errors.New("mail auth: a lookup the checks do not make")

// One lookup of a message, shared by every caller asking it.
type mailAuthFlight struct {
	done   chan struct{}
	answer *mailDnsAnswer
	err    error
}

// One message's lookups and which of them a bound cut.
type mailAuthMemo struct {
	stateLock sync.Mutex
	flights   map[mailDnsKey]*mailAuthFlight
	// The names and types a bound cut, and the priorities they were asked at.
	cutKeys       map[mailDnsKey]bool
	cutPriorities map[MailAuthPriority]bool
}

// One message's lookups at one priority. See the file header.
type MailAuthResolver struct {
	stub     *MailDnsStub
	budget   *MailAuthBudget
	memo     *mailAuthMemo
	priority MailAuthPriority
}

// A message's lookups through stub within budget, asked at priority.
func NewMailAuthResolver(stub *MailDnsStub, budget *MailAuthBudget, priority MailAuthPriority) *MailAuthResolver {
	return &MailAuthResolver{
		stub:   stub,
		budget: budget,
		memo: &mailAuthMemo{
			flights:       map[mailDnsKey]*mailAuthFlight{},
			cutKeys:       map[mailDnsKey]bool{},
			cutPriorities: map[MailAuthPriority]bool{},
		},
		priority: priority,
	}
}

// The same message's lookups asked at priority, sharing this one's budget and memo.
func (self *MailAuthResolver) WithPriority(priority MailAuthPriority) *MailAuthResolver {
	return &MailAuthResolver{stub: self.stub, budget: self.budget, memo: self.memo, priority: priority}
}

// Whether a bound cut a lookup of name, absolute or not, and qType.
func (self *MailAuthResolver) Cut(name string, qType dnsmessage.Type) bool {
	self.memo.stateLock.Lock()
	defer self.memo.stateLock.Unlock()
	return self.memo.cutKeys[mailDnsKey{name: mailDnsName(name), qType: qType}]
}

// Whether a bound cut any lookup asked at priority.
func (self *MailAuthResolver) CutAt(priority MailAuthPriority) bool {
	self.memo.stateLock.Lock()
	defer self.memo.stateLock.Unlock()
	return self.memo.cutPriorities[priority]
}

// Starts the lookups of each name and type now, in order, each taking its place in the budget before this returns,
// and waits for none of them: how a check asks, in priority order, for every record it will need before mox asks
// for them one at a time.
func (self *MailAuthResolver) Prefetch(names []string, qType dnsmessage.Type) {
	for _, name := range names {
		self.start(name, qType)
	}
}

// The flight answering name and qType for the message, started now when it is the first ask: a fresh kept answer at
// once, spending nothing, else a place in the budget taken now and the query on its own goroutine. nil for a name that
// is not absolute.
func (self *MailAuthResolver) start(name string, qType dnsmessage.Type) *mailAuthFlight {
	if !strings.HasSuffix(name, ".") || name == "." {
		return nil
	}
	key := mailDnsKey{name: mailDnsName(name), qType: qType}
	flight, first := func() (*mailAuthFlight, bool) {
		self.memo.stateLock.Lock()
		defer self.memo.stateLock.Unlock()
		if flight, ok := self.memo.flights[key]; ok {
			return flight, false
		}
		flight := &mailAuthFlight{done: make(chan struct{})}
		self.memo.flights[key] = flight
		return flight, true
	}()
	if !first {
		return flight
	}
	if answer, ok := self.stub.get(key); ok {
		flight.answer = answer
		close(flight.done)
		return flight
	}
	ticket := self.budget.reserve(self.priority)
	priority := self.priority
	go func() {
		defer close(flight.done)
		flightCtx := self.budget.Context()
		answer, err := self.stub.query(flightCtx, key, func() (func(), error) {
			return ticket.wait(flightCtx)
		})
		// whatever the check's end cut is the deadline's, not the resolver's or a caller's
		if err != nil && !errors.Is(err, ErrMailAuthBound) && flightCtx.Err() != nil {
			err = ErrMailAuthDeadline
		}
		if errors.Is(err, ErrMailAuthBound) {
			self.memo.stateLock.Lock()
			self.memo.cutKeys[key] = true
			self.memo.cutPriorities[priority] = true
			self.memo.stateLock.Unlock()
		}
		flight.answer, flight.err = answer, err
	}()
	return flight
}

// name's records of qType, through the memo: ErrMailAuthBound's errors where a bound cut it, ErrMailDnsNoAnswer
// where no usable answer came. A name must be absolute.
func (self *MailAuthResolver) lookup(ctx context.Context, name string, qType dnsmessage.Type) (*mailDnsAnswer, error) {
	flight := self.start(name, qType)
	if flight == nil {
		return nil, ErrMailAuthLookupRefused
	}
	// an answer already in hand, a stub hit among them, is the answer whatever ctx says: a bound cuts only work not
	// yet done, so the same message and stub give the same evidence whenever the deadline falls
	select {
	case <-flight.done:
		return flight.answer, flight.err
	default:
	}
	select {
	case <-flight.done:
		return flight.answer, flight.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// An error as mox reads it: not found for NXDOMAIN and NODATA, temporary for anything else, a bound included, which
// errors.Is still finds through it.
func mailAuthDnsError(err error, answer *mailDnsAnswer) error {
	switch {
	case err == nil && answer.empty():
		return &adns.DNSError{Err: "no such record", IsNotFound: true}
	case err == nil:
		return nil
	case errors.Is(err, ErrMailAuthLookupRefused):
		return &adns.DNSError{UnwrapErr: err, Err: err.Error()}
	}
	return &adns.DNSError{UnwrapErr: err, Err: err.Error(), IsTemporary: true}
}

// Each TXT record as one string, its character-strings joined.
func (self *MailAuthResolver) LookupTXT(ctx context.Context, name string) ([]string, adns.Result, error) {
	answer, err := self.lookup(ctx, name, dnsmessage.TypeTXT)
	if err := mailAuthDnsError(err, answer); err != nil {
		return nil, adns.Result{}, err
	}
	texts := []string{}
	for _, record := range answer.records {
		if txt, ok := record.Body.(*dnsmessage.TXTResource); ok {
			texts = append(texts, strings.Join(txt.TXT, ""))
		}
	}
	return texts, adns.Result{}, nil
}

// network ip asks A and AAAA at once, ip4 A and ip6 AAAA. Any address answers; with none, a temporary failure of
// either is the error, else not found.
func (self *MailAuthResolver) LookupIP(ctx context.Context, network string, host string) ([]net.IP, adns.Result, error) {
	types := []dnsmessage.Type{}
	switch network {
	case "ip":
		types = []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA}
	case "ip4":
		types = []dnsmessage.Type{dnsmessage.TypeA}
	case "ip6":
		types = []dnsmessage.Type{dnsmessage.TypeAAAA}
	default:
		return nil, adns.Result{}, &adns.DNSError{UnwrapErr: ErrMailAuthLookupRefused, Err: ErrMailAuthLookupRefused.Error()}
	}
	answers := make([]*mailDnsAnswer, len(types))
	errs := make([]error, len(types))
	var waitGroup sync.WaitGroup
	for index, qType := range types {
		waitGroup.Go(func() {
			answers[index], errs[index] = self.lookup(ctx, host, qType)
		})
	}
	waitGroup.Wait()
	ips := []net.IP{}
	var failure error
	for index := range types {
		if err := mailAuthDnsError(errs[index], answers[index]); err != nil {
			var dnsError *adns.DNSError
			if failure == nil || (errors.As(err, &dnsError) && !dnsError.IsNotFound) {
				failure = err
			}
			continue
		}
		for _, record := range answers[index].records {
			switch body := record.Body.(type) {
			case *dnsmessage.AResource:
				ips = append(ips, net.IP(body.A[:]).To16())
			case *dnsmessage.AAAAResource:
				ips = append(ips, net.IP(body.AAAA[:]))
			}
		}
	}
	if len(ips) == 0 {
		return nil, adns.Result{}, failure
	}
	return ips, adns.Result{}, nil
}

// LookupIP's addresses for network ip.
func (self *MailAuthResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, adns.Result, error) {
	ips, result, err := self.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, result, err
	}
	addresses := make([]net.IPAddr, 0, len(ips))
	for _, ip := range ips {
		addresses = append(addresses, net.IPAddr{IP: ip})
	}
	return addresses, result, nil
}

// LookupIP's addresses for network ip, as text.
func (self *MailAuthResolver) LookupHost(ctx context.Context, host string) ([]string, adns.Result, error) {
	ips, result, err := self.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, result, err
	}
	addresses := make([]string, 0, len(ips))
	for _, ip := range ips {
		addresses = append(addresses, ip.String())
	}
	return addresses, result, nil
}

// MX records, each host absolute.
func (self *MailAuthResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, adns.Result, error) {
	answer, err := self.lookup(ctx, name, dnsmessage.TypeMX)
	if err := mailAuthDnsError(err, answer); err != nil {
		return nil, adns.Result{}, err
	}
	exchanges := []*net.MX{}
	for _, record := range answer.records {
		if mx, ok := record.Body.(*dnsmessage.MXResource); ok {
			exchanges = append(exchanges, &net.MX{Host: mx.MX.String(), Pref: mx.Pref})
		}
	}
	return exchanges, adns.Result{}, nil
}

// The PTR names of an address given as text, each absolute.
func (self *MailAuthResolver) LookupAddr(ctx context.Context, address string) ([]string, adns.Result, error) {
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return nil, adns.Result{}, &adns.DNSError{UnwrapErr: ErrMailAuthLookupRefused, Err: "not an address"}
	}
	answer, err := self.lookup(ctx, mailReverseName(ip), dnsmessage.TypePTR)
	if err := mailAuthDnsError(err, answer); err != nil {
		return nil, adns.Result{}, err
	}
	names := []string{}
	for _, record := range answer.records {
		if ptr, ok := record.Body.(*dnsmessage.PTRResource); ok {
			names = append(names, ptr.PTR.String())
		}
	}
	return names, adns.Result{}, nil
}

// An address's absolute reverse name, in in-addr.arpa or ip6.arpa.
func mailReverseName(ip netip.Addr) string {
	ip = ip.Unmap()
	if ip.Is4() {
		octets := ip.As4()
		return strconv.Itoa(int(octets[3])) + "." + strconv.Itoa(int(octets[2])) + "." + strconv.Itoa(int(octets[1])) + "." +
			strconv.Itoa(int(octets[0])) + ".in-addr.arpa."
	}
	const hexDigits = "0123456789abcdef"
	octets := ip.As16()
	var builder strings.Builder
	for index := len(octets) - 1; 0 <= index; index -= 1 {
		builder.WriteByte(hexDigits[octets[index]&0x0f])
		builder.WriteByte('.')
		builder.WriteByte(hexDigits[octets[index]>>4])
		builder.WriteByte('.')
	}
	builder.WriteString("ip6.arpa.")
	return builder.String()
}

// TLSA records at _<port>._<protocol>.<host>, host absolute; a record too short to hold its three fields is passed
// over.
func (self *MailAuthResolver) LookupTLSA(ctx context.Context, port int, protocol string, host string) ([]adns.TLSA, adns.Result, error) {
	answer, err := self.lookup(ctx, "_"+strconv.Itoa(port)+"._"+protocol+"."+host, mailDnsTypeTlsa)
	if err := mailAuthDnsError(err, answer); err != nil {
		return nil, adns.Result{}, err
	}
	records := []adns.TLSA{}
	for _, record := range answer.records {
		unknown, ok := record.Body.(*dnsmessage.UnknownResource)
		if !ok || len(unknown.Data) < 3 {
			continue
		}
		records = append(records, adns.TLSA{
			Usage: adns.TLSAUsage(unknown.Data[0]), Selector: adns.TLSASelector(unknown.Data[1]),
			MatchType: adns.TLSAMatchType(unknown.Data[2]), CertAssoc: append([]byte{}, unknown.Data[3:]...),
		})
	}
	return records, adns.Result{}, nil
}

// Refused: no check looks up a port.
func (self *MailAuthResolver) LookupPort(ctx context.Context, network string, service string) (int, error) {
	return 0, &adns.DNSError{UnwrapErr: ErrMailAuthLookupRefused, Err: ErrMailAuthLookupRefused.Error()}
}

// Refused: no check follows a CNAME by itself, and the records a lookup keeps already follow the answer's.
func (self *MailAuthResolver) LookupCNAME(ctx context.Context, host string) (string, adns.Result, error) {
	return "", adns.Result{}, &adns.DNSError{UnwrapErr: ErrMailAuthLookupRefused, Err: ErrMailAuthLookupRefused.Error()}
}

// Refused: no check looks up NS.
func (self *MailAuthResolver) LookupNS(ctx context.Context, name string) ([]*net.NS, adns.Result, error) {
	return nil, adns.Result{}, &adns.DNSError{UnwrapErr: ErrMailAuthLookupRefused, Err: ErrMailAuthLookupRefused.Error()}
}

// Refused: no check looks up SRV.
func (self *MailAuthResolver) LookupSRV(ctx context.Context, service string, protocol string, name string) (string, []*net.SRV, adns.Result, error) {
	return "", nil, adns.Result{}, &adns.DNSError{UnwrapErr: ErrMailAuthLookupRefused, Err: ErrMailAuthLookupRefused.Error()}
}
