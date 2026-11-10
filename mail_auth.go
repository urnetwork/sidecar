//go:build !sidecar_http && !js

// §15.5's reception-time checks (R-MAIL-16, D-MAIL-3, D-MAIL-14, I-11, FS-121; MAIL-M7-08, MAIL-M7-09): SPF, the DKIM
// signatures, DMARC, the forward-confirmed PTR of sender_ip, whether the SNI host's TLSA held this receiver's key, and
// the ARC chain, on mox's dkim, spf and dmarc behind mailAuthVerifiers and on MailArcVerifier, every lookup through one
// message's MailAuthResolver, within its MailAuthBudget's 64 queries, 8 in flight, 5 s each and 30 s in all.
// MailAuthSlots decides when a message's 30 s start, and MailEvidenceBuilder holds what a check found to 8,192 bytes.
//
// The order is §15.5's. First the DKIM fields' syntax and tags, with no lookup: mox's dkim.Verify with a policy that
// records each signature and refuses it, which reaches no DNS (mail_auth_dkim.go). Then at most 8 are selected, those
// whose d= aligns with From under DMARC's relaxed rule first, each group from the bottom of the header up. Then the
// lookups, in budget order: DMARC's record and the aligned keys, SPF, the PTR and the TLSA, the other keys, then
// ARC's, the keys fetched at once into the message's memo, since dkim.Verify looks them up one at a time and eight
// 4.9 s selectors would pass 30 s. Then dkim.Verify again, admitting only the selected, beside ARC's verification.
// DMARC's verdict is computed here from what was verified (mail_auth_dmarc.go), since mox's dmarc.Verify makes any
// DKIM temperror its own, aligned or not. A message costs at most 9 body hashes and 17 signature checks: 8 of each for
// DKIM, and ARC's newest AMS's body hash and its 9 checks.
//
// A check a bound cut is no result: incomplete for SPF and DKIM, temperror for DMARC only where an aligned check was
// cut and nothing aligned passed, and limits says what was skipped. Nothing here refuses mail (§15.5's session row),
// and no verdict strengthens because a check was cut. Domains, addresses and keys are never logged (I-13): mox logs
// through a logger that writes nothing.
//
// Off sidecar_http and js, since it links mox. Safe for concurrent use; one Check is one message.

package sidecar

import (
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dmarc"
	moxdns "github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/publicsuffix"
	"github.com/mjl-/mox/spf"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// What a check reads of one message and its session.
type MailAuthInput struct {
	// The message's bytes as received, before ingest adds headers, and how many.
	Message io.ReaderAt
	Size    int64
	// The sender's address, as the router saw it (MailIngress.sender_ip).
	SenderIp netip.Addr
	// MAIL FROM's reverse path as received, no brackets, empty for <>.
	MailFrom []byte
	// The EHLO name the sender gave after TLS, SPF's HELO identity (plan-MAIL-small-readings#14).
	EhloName string
	// MAIL carried SMTPUTF8.
	SmtpUtf8 bool
	// The SNI host the session named, and the SHA-256 of this receiver's SPKI, as its TLSA record holds it.
	SniHost            string
	ReceiverSpkiSha256 []byte
}

// What a check found: MailAuthEvidence's results before MailEvidenceBuilder bounds them.
type MailAuthOutcome struct {
	Spf *protocol.SpfResult
	// One entry a selected signature, in selection order.
	Dkim  []*protocol.DkimResult
	Dmarc *protocol.DmarcResult
	// The forward-confirmed PTR of sender_ip, lowercase with no trailing dot, or empty.
	PtrName     string
	SniTlsaLive bool
	// cv= and each verified set, the newest first.
	Arc *protocol.ArcResult
	// Set only when a bound cut the work.
	Limits *protocol.AuthLimits
	// limits' counts whether or not a bound cut the work, its reason 0 where none did: what MailEvidenceBuilder sets
	// limits from when its own bound cuts.
	Counts *protocol.AuthLimits
	// The From domain DMARC was judged for, empty where From named none.
	FromDomain string
	// The selected signatures whose d= aligns with From, which lead Dkim in selection order.
	DkimAlignedCount int
	// Signatures mox verified, each hashing the body once at most: no more than 8.
	DkimVerifiedCount int
	// ARC's body hashes and signature checks: at most 1 and 9.
	ArcBodyHashCount       int
	ArcSignatureCheckCount int
	// The view the checks read, which ARC reads too.
	View *MailHeaderView
}

// mox's dkim, spf and dmarc, as the checks call them: the one seam over them (plan-MAIL-mox-subset).
type mailAuthVerifiers struct {
	dkimVerify      func(ctx context.Context, elog *slog.Logger, resolver moxdns.Resolver, smtputf8 bool, policy func(*dkim.Sig) error, r io.ReaderAt, ignoreTestMode bool) ([]dkim.Result, error)
	dkimParseRecord func(text string) (*dkim.Record, bool, error)
	spfLookup       func(ctx context.Context, elog *slog.Logger, resolver moxdns.Resolver, domain moxdns.Domain) (spf.Status, string, *spf.Record, bool, error)
	spfEvaluate     func(ctx context.Context, elog *slog.Logger, record *spf.Record, resolver moxdns.Resolver, args spf.Args) (spf.Status, string, string, bool, error)
	dmarcLookup     func(ctx context.Context, elog *slog.Logger, resolver moxdns.Resolver, msgFrom moxdns.Domain) (dmarc.Status, moxdns.Domain, *dmarc.Record, string, bool, error)
	orgDomain       func(ctx context.Context, elog *slog.Logger, domain moxdns.Domain) moxdns.Domain
}

// mox's subset in third_party/mox (QD-193).
func moxMailAuthVerifiers() *mailAuthVerifiers {
	return &mailAuthVerifiers{
		dkimVerify:      dkim.Verify,
		dkimParseRecord: dkim.ParseRecord,
		spfLookup:       spf.Lookup,
		spfEvaluate:     spf.Evaluate,
		dmarcLookup:     dmarc.Lookup,
		orgDomain:       publicsuffix.Lookup,
	}
}

// A receiver's checks over its stub. Safe for concurrent use.
type MailAuthChecker struct {
	stub      *MailDnsStub
	clock     Clock
	settings  *MailAuthSettings
	verifiers *mailAuthVerifiers
	arc       *MailArcVerifier
	// What mox logs through: nothing, since its lines name domains and addresses (I-13).
	log *slog.Logger
}

// A checker whose lookups go through stub and whose time runs on clock, real time when nil.
func NewMailAuthChecker(stub *MailDnsStub, clock Clock, settings *MailAuthSettings) *MailAuthChecker {
	return &MailAuthChecker{
		stub:      stub,
		clock:     clockOrReal(clock),
		settings:  settings,
		verifiers: moxMailAuthVerifiers(),
		arc:       NewMailArcVerifier(clock, settings),
		log:       slog.New(slog.DiscardHandler),
	}
}

// One message's checks, its 30 s starting now. The only error is the message's own read failing; every DNS failure,
// timeout and bound is a result.
func (self *MailAuthChecker) Check(ctx context.Context, input *MailAuthInput) (*MailAuthOutcome, error) {
	view, err := NewMailHeaderView(input.Message, input.Size, self.settings.HeaderMaxByteCount)
	if err != nil {
		return nil, err
	}
	arcChain, err := self.arc.Parse(view)
	if err != nil {
		return nil, err
	}
	budget := NewMailAuthBudget(self.clock, self.settings)
	defer budget.Close()
	checkCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(budget.Context(), cancel)
	defer stop()
	resolver := NewMailAuthResolver(self.stub, budget, MailAuthPriorityDmarc)
	outcome := &MailAuthOutcome{View: view, FromDomain: mailFromDomain(view.From)}
	fromDomain, fromOk := moxdns.Domain{}, false
	if outcome.FromDomain != "" {
		if parsed, err := moxdns.ParseDomain(outcome.FromDomain); err == nil {
			fromDomain, fromOk = parsed, true
		}
	}

	testHookBarrier("mail.auth.check.before", "")
	// syntax and tags, with no lookup, then the selection
	selection := self.selectDkim(checkCtx, view, input, fromDomain, fromOk)
	// every record already known asked now, in §15.5's order, so under the query count the first take the budget
	dmarcResolver := resolver.WithPriority(MailAuthPriorityDmarc)
	spfResolver := resolver.WithPriority(MailAuthPrioritySpf)
	ptrResolver := resolver.WithPriority(MailAuthPriorityPtr)
	keysResolver := resolver.WithPriority(MailAuthPriorityKeys)
	if fromOk {
		dmarcResolver.Prefetch([]string{"_dmarc." + fromDomain.ASCII + "."}, dnsmessage.TypeTXT)
	}
	dmarcResolver.Prefetch(selection.keyNames(true), dnsmessage.TypeTXT)
	spfArgs, spfDomain, spfOk := mailSpfIdentity(input)
	if spfOk {
		spfResolver.Prefetch([]string{spfDomain.ASCII + "."}, dnsmessage.TypeTXT)
	}
	if input.SenderIp.IsValid() {
		ptrResolver.Prefetch([]string{mailReverseName(input.SenderIp)}, dnsmessage.TypePTR)
	}
	if input.SniHost != "" && len(input.ReceiverSpkiSha256) == sha256.Size {
		ptrResolver.Prefetch([]string{"_25._tcp." + mailDnsName(input.SniHost) + "."}, mailDnsTypeTlsa)
	}
	keysResolver.Prefetch(selection.keyNames(false), dnsmessage.TypeTXT)
	resolver.WithPriority(MailAuthPriorityArc).Prefetch(arcChain.KeyNames(), dnsmessage.TypeTXT)
	// then each check, its lookups through the memo
	var group sync.WaitGroup
	var dmarcFound *mailDmarcLookup
	group.Go(func() {
		dmarcFound = self.lookupDmarc(checkCtx, dmarcResolver, fromDomain, fromOk)
	})
	group.Go(func() {
		outcome.Spf = self.checkSpf(checkCtx, spfResolver, input, spfArgs, spfDomain, spfOk)
	})
	group.Go(func() {
		outcome.PtrName = self.checkPtr(checkCtx, ptrResolver, input.SenderIp)
	})
	group.Go(func() {
		outcome.SniTlsaLive = self.checkTlsa(checkCtx, ptrResolver, input.SniHost, input.ReceiverSpkiSha256)
	})
	group.Go(func() {
		outcome.DkimVerifiedCount = self.verifyDkim(checkCtx, resolver, view, input, selection)
	})
	var arcOutcome *MailArcOutcome
	group.Go(func() {
		arcOutcome = self.arc.Verify(checkCtx, resolver, arcChain)
	})
	group.Wait()
	testHookBarrier("mail.auth.check.after", "")

	for _, candidate := range selection.selected {
		outcome.Dkim = append(outcome.Dkim, candidate.result)
		if candidate.aligned {
			outcome.DkimAlignedCount += 1
		}
	}
	outcome.Arc = arcOutcome.Result
	outcome.ArcBodyHashCount, outcome.ArcSignatureCheckCount = arcOutcome.BodyHashCount, arcOutcome.SignatureCheckCount
	if !spfOk {
		spfDomain = moxdns.Domain{}
	}
	outcome.Dmarc = self.judgeDmarc(checkCtx, dmarcFound, selection, outcome.Spf, spfDomain, fromDomain)
	sentCount, refusedCount, deadline := budget.Spent()
	limits := &protocol.AuthLimits{
		DkimSeen:    uint32(min(view.DkimFieldCount, self.settings.DkimFieldMaxCount)),
		DkimChecked: uint32(selection.lookedUpCount()),
		ArcSets:     arcOutcome.HighestInstance,
		DnsQueries:  uint32(sentCount),
	}
	if view.Cut || self.settings.DkimFieldMaxCount < view.DkimFieldCount || selection.unselectedCount != 0 || 0 < refusedCount || arcChain.CountCut() {
		limits.Reason |= MailAuthLimitCount
	}
	if deadline {
		limits.Reason |= MailAuthLimitDeadline
	}
	outcome.Counts = proto.CloneOf(limits)
	if limits.Reason != 0 {
		outcome.Limits = limits
	}
	return outcome, nil
}
