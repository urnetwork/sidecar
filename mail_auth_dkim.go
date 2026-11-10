//go:build !sidecar_http && !js && !ios_extension

// §15.5's dkim row (MAIL-M7-08): syntax and tags first, with no lookup; then at most 8 signatures, those whose d=
// aligns with From under DMARC's relaxed rule first, each group from the bottom of the header up, oldest first; each
// (d=, s=) key looked up once; every other signature counted, never verified.
//
// Two passes of mox's dkim.Verify over the MailHeaderView. The first's policy refuses every signature, so it reaches
// no DNS, and its results give each DKIM-Signature field's parsed signature or its syntax error. rsa-sha1 is refused
// there as permerror (RFC 8301 §3), since mox's algHash accepts it. The second admits only the selected, their keys
// already fetched into the message's memo, and a key past 8,192 bits is refused as permerror before mox verifies
// under it, since mox sets no ceiling. Each selected signature then has one entry, in selection order: pass, fail,
// permerror, temperror, or incomplete where a bound cut its lookup or the view cut the header it signed.

package sidecar

import (
	"context"
	"crypto/rsa"
	"errors"
	"slices"
	"strings"

	"github.com/mjl-/mox/dkim"
	moxdns "github.com/mjl-/mox/dns"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// The first pass's answer to every signature: none is verified there.
	errMailDkimSyntaxPass = errors.New("mail auth: the syntax pass verifies nothing")
	// The second pass's answer to a signature it does not verify.
	errMailDkimUnselected = errors.New("mail auth: not selected")
)

// One DKIM-Signature field that parsed far enough to name its d= and s=.
type mailDkimCandidate struct {
	// Among the view's DKIM-Signature fields, top first.
	index   int
	sig     *dkim.Sig
	aligned bool
	// <s>._domainkey.<d>., where its key is published.
	keyName string
	// A verdict reached with no lookup: rsa-sha1, or a tag mox's checks refuse, such as an expired x=.
	early protocol.DkimVerdict
	// The second pass's parse of it, once admitted.
	admitted *dkim.Sig
	result   *protocol.DkimResult
}

// The selected signatures, in selection order, and how many parsed but were left unselected.
type mailDkimSelection struct {
	selected        []*mailDkimCandidate
	unselectedCount int
}

// The selected signatures' key names to fetch, each once: the aligned ones' or the rest's, leaving out those decided
// with no lookup.
func (self *mailDkimSelection) keyNames(aligned bool) []string {
	names := []string{}
	for _, candidate := range self.selected {
		if candidate.aligned == aligned && candidate.early == protocol.DkimVerdict_DKIM_VERDICT_UNSPECIFIED && !slices.Contains(names, candidate.keyName) {
			names = append(names, candidate.keyName)
		}
	}
	return names
}

// The selected signatures whose keys were looked up.
func (self *mailDkimSelection) lookedUpCount() int {
	count := 0
	for _, candidate := range self.selected {
		if candidate.early == protocol.DkimVerdict_DKIM_VERDICT_UNSPECIFIED {
			count += 1
		}
	}
	return count
}

// A signature's identity across the two passes: its b=, d= and s=.
func mailDkimSigKey(sig *dkim.Sig) string {
	return string(sig.Signature) + "\x00" + sig.Domain.ASCII + "\x00" + sig.Selector.ASCII
}

// Whether two domains align: the same name under strict, the same organizational domain under relaxed.
func (self *MailAuthChecker) aligned(ctx context.Context, a moxdns.Domain, b moxdns.Domain, strict bool) bool {
	if strict {
		return a.ASCII == b.ASCII
	}
	return self.verifiers.orgDomain(ctx, self.log, a).ASCII == self.verifiers.orgDomain(ctx, self.log, b).ASCII
}

// The first pass and the selection. A header section mox cannot read has no signature to select.
func (self *MailAuthChecker) selectDkim(ctx context.Context, view *MailHeaderView, input *MailAuthInput, from moxdns.Domain, fromOk bool) *mailDkimSelection {
	selection := &mailDkimSelection{}
	// a resolver with no queries, no time and nothing kept: even a policy that let one through would reach no DNS,
	// and the pass holds no 30 s timer beside the message's own
	noQueries := *self.settings
	noQueries.QueryMaxCount = 0
	noQueries.CheckTimeout = 0
	noBudget := NewMailAuthBudget(self.clock, &noQueries)
	defer noBudget.Close()
	refusing := NewMailAuthResolver(NewMailDnsStub(nil, self.clock, &noQueries), noBudget, MailAuthPriorityKeys)
	results, err := self.verifiers.dkimVerify(ctx, self.log, refusing, input.SmtpUtf8, func(sig *dkim.Sig) error {
		return errMailDkimSyntaxPass
	}, view, true)
	if err != nil {
		return selection
	}
	aligned := []*mailDkimCandidate{}
	unaligned := []*mailDkimCandidate{}
	for index, result := range results {
		// past the 64th, a field is only counted
		if self.settings.DkimFieldMaxCount <= index {
			break
		}
		if result.Sig == nil {
			continue
		}
		candidate := &mailDkimCandidate{
			index:   index,
			sig:     result.Sig,
			keyName: result.Sig.Selector.ASCII + "._domainkey." + result.Sig.Domain.ASCII + ".",
		}
		switch {
		case result.Status != dkim.StatusPolicy:
			candidate.early = protocol.DkimVerdict_DKIM_PERMERROR
		case strings.EqualFold(result.Sig.AlgorithmHash, "sha1"):
			candidate.early = protocol.DkimVerdict_DKIM_PERMERROR
		}
		if fromOk && self.aligned(ctx, result.Sig.Domain, from, false) {
			candidate.aligned = true
			aligned = append(aligned, candidate)
		} else {
			unaligned = append(unaligned, candidate)
		}
	}
	// each group from the bottom of the header up
	slices.Reverse(aligned)
	slices.Reverse(unaligned)
	ordered := append(aligned, unaligned...)
	selection.selected = ordered[:min(len(ordered), max(0, self.settings.DkimSelectMaxCount))]
	selection.unselectedCount = len(ordered) - len(selection.selected)
	return selection
}

// The entry of a candidate with verdict.
func mailDkimEntry(candidate *mailDkimCandidate, verdict protocol.DkimVerdict, publicKey []byte) *protocol.DkimResult {
	return &protocol.DkimResult{
		Domain:    candidate.sig.Domain.ASCII,
		Selector:  candidate.sig.Selector.ASCII,
		Result:    verdict,
		PublicKey: publicKey,
	}
}

// Whether a key record names an RSA key past the bound, which no signature is verified under.
func (self *MailAuthChecker) keyTooLarge(texts []string) bool {
	for _, text := range texts {
		record, isDkim, err := self.verifiers.dkimParseRecord(text)
		if !isDkim || err != nil {
			continue
		}
		if key, ok := record.PublicKey.(*rsa.PublicKey); ok && self.settings.DkimRsaMaxBitCount < key.N.BitLen() {
			return true
		}
	}
	return false
}

// The second pass: every selected signature's entry, and how many mox verified.
func (self *MailAuthChecker) verifyDkim(ctx context.Context, resolver *MailAuthResolver, view *MailHeaderView, input *MailAuthInput, selection *mailDkimSelection) int {
	keys := resolver.WithPriority(MailAuthPriorityKeys)
	admittable := map[string]*mailDkimCandidate{}
	for _, candidate := range selection.selected {
		if candidate.early != protocol.DkimVerdict_DKIM_VERDICT_UNSPECIFIED {
			candidate.result = mailDkimEntry(candidate, candidate.early, nil)
			continue
		}
		// the prefetched key, waited for here: a key past the bound is refused before mox verifies under it
		texts, _, err := keys.LookupTXT(ctx, candidate.keyName)
		if err == nil && self.keyTooLarge(texts) {
			candidate.result = mailDkimEntry(candidate, protocol.DkimVerdict_DKIM_PERMERROR, nil)
			continue
		}
		if _, ok := admittable[mailDkimSigKey(candidate.sig)]; !ok {
			admittable[mailDkimSigKey(candidate.sig)] = candidate
		}
	}
	verifiedCount := 0
	if 0 < len(admittable) && ctx.Err() == nil {
		results, err := self.verifiers.dkimVerify(ctx, self.log, keys, input.SmtpUtf8, func(sig *dkim.Sig) error {
			candidate, ok := admittable[mailDkimSigKey(sig)]
			if !ok || candidate.admitted != nil {
				return errMailDkimUnselected
			}
			candidate.admitted = sig
			verifiedCount += 1
			return nil
		}, view, true)
		if err == nil {
			for _, result := range results {
				for _, candidate := range admittable {
					if result.Sig != nil && candidate.admitted == result.Sig {
						var publicKey []byte
						if result.Record != nil {
							publicKey = slices.Clone(result.Record.Pubkey)
						}
						candidate.result = mailDkimEntry(candidate, self.dkimVerdict(ctx, keys, view, candidate, result.Status), publicKey)
					}
				}
			}
		}
	}
	// a selected signature with no verdict yet: the second pass never reached it, or a twin of one it did
	for _, candidate := range selection.selected {
		if candidate.result != nil {
			continue
		}
		if twin := admittable[mailDkimSigKey(candidate.sig)]; twin != nil && twin.result != nil {
			candidate.result = mailDkimEntry(candidate, twin.result.GetResult(), twin.result.GetPublicKey())
			continue
		}
		verdict := protocol.DkimVerdict_DKIM_PERMERROR
		if ctx.Err() != nil || keys.Cut(candidate.keyName, dnsmessage.TypeTXT) {
			verdict = protocol.DkimVerdict_DKIM_INCOMPLETE
		}
		candidate.result = mailDkimEntry(candidate, verdict, nil)
	}
	return verifiedCount
}

// mox's status as §15.5's verdict: a temperror a bound or the deadline caused is incomplete, and so is a fail under a
// view that cut the header section (plan-MAIL-small-readings#12).
func (self *MailAuthChecker) dkimVerdict(ctx context.Context, keys *MailAuthResolver, view *MailHeaderView, candidate *mailDkimCandidate, status dkim.Status) protocol.DkimVerdict {
	switch status {
	case dkim.StatusPass:
		return protocol.DkimVerdict_DKIM_PASS
	case dkim.StatusFail:
		if view.Cut {
			return protocol.DkimVerdict_DKIM_INCOMPLETE
		}
		return protocol.DkimVerdict_DKIM_FAIL
	case dkim.StatusTemperror:
		if ctx.Err() != nil || keys.Cut(candidate.keyName, dnsmessage.TypeTXT) {
			return protocol.DkimVerdict_DKIM_INCOMPLETE
		}
		return protocol.DkimVerdict_DKIM_TEMPERROR
	}
	return protocol.DkimVerdict_DKIM_PERMERROR
}
