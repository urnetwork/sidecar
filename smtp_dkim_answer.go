//go:build !sidecar_http && !ios_extension

// QD-1130's gate on a Team custom domain's DKIM selectors (§14.6, D-SMTP-15; owner decision 36): a sidecar signs
// only under a selector the domain answers. POST /smtp/dkim-keys writes every selector's key record at
// <sel>._domainkey.<net>.<root> (SMTP-M9-19), and a custom domain answers it at <sel>._domainkey.<domain> through a
// delegated _domainkey.<domain>, which §12's dns answers from that row as soon as it is written
// (dnsservice.DelegatedZones), or through a CNAME per selector that the customer adds by hand, which GET
// /network/dns names until it answers. So once its publish is answered, a custom domain's new selector awaits until
// the device's own DoH finds its key at <sel>._domainkey.<domain>:
//
//	first     the domain's first selector signs nothing while it awaits: SmtpDkimKeys.Current answers
//	          ErrSmtpDkimSelectorUnanswered, which holds the send as deferred
//	rotation  the new selector's publish retires nothing, and the selector it replaces keeps signing, published, so
//	          in DNS, for as long as it signs; the answer retires it, kept in DNS 7 days more. Since that waits on
//	          the customer, such a domain rotates DkimRetiredKeepTimeout before DkimRotateTimeout, the 7 days the
//	          replaced selector would have stayed in DNS, and a selector that awaits stands for its domain's
//	          rotation, so none is published beside it
//	lookups   one as soon as the publish is answered, so a delegated domain moves at once, then at most one each
//	          DkimAnswerRetryInterval while the selector awaits, each bounded by DkimAnswerLookupTimeout; a lookup
//	          that fails is no answer
//	domains   a domain at or below the dns root, the network's own name, a burner's or a scope's, waits on nothing,
//	          since dns answers its selector from the row its publish wrote. Without SmtpDkimDomainAnswers no domain
//	          waits, as SMTP-M9-03 had it: a host that sends a custom domain's mail installs them before its first
//	          send
//
// An answer is a key record (RFC 6376 §3.6.1) at the name, or where its CNAMEs lead, holding the selector's public
// key (SmtpDkimKeyRecordHolds), the rule api's GET /network/dns reads a domain's owed CNAMEs by. Logs name
// selectors, never a domain (I-13).
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// A Team custom domain does not answer this device's selector yet (QD-1130): neither a delegated
// _domainkey.<domain> nor the selector's CNAME, which GET /network/dns names, is in place, so nothing signs for the
// domain and the send holds as deferred.
var ErrSmtpDkimSelectorUnanswered = errors.New("smtp dkim: the domain does not answer the selector yet")

// What tells SmtpDkimKeys whether a Team custom domain answers a selector (QD-1130).
type SmtpDkimDomainAnswers struct {
	// The device's own DoH (§2.8 ext-3), connect's DohCache.Forward, as TL2 and TL3 take it. nil answers nothing,
	// so a custom domain's new selector never signs.
	Doh SmtpDohForwarder
	// The dns root, <root>, with or without its final dot: a domain at or below it is URnetwork's and waits on
	// nothing. Empty has every domain wait for its answer, which dns gives URnetwork's own as soon as it serves the
	// published row.
	Root string
}

// Has every new selector of a domain outside answers.Root await the domain's answer before it signs (see the file
// header); nil lets every selector sign once published. A host installs them before its first send.
func (self *SmtpDkimKeys) SetDomainAnswers(answers *SmtpDkimDomainAnswers) {
	var copied *SmtpDkimDomainAnswers
	if answers != nil {
		copied = &SmtpDkimDomainAnswers{
			Doh:  answers.Doh,
			Root: strings.TrimSuffix(strings.ToLower(answers.Root), "."),
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.answers = copied
}

// The installed answers, nil for none.
func (self *SmtpDkimKeys) domainAnswers() *SmtpDkimDomainAnswers {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.answers
}

// Whether domain's new selectors await its answer: a Team custom domain, outside the dns root, while answers are
// installed.
func (self *SmtpDkimKeys) awaitsAnswer(domain string) bool {
	answers := self.domainAnswers()
	if answers == nil {
		return false
	}
	if answers.Root == "" {
		return true
	}
	return domain != answers.Root && !strings.HasSuffix(domain, "."+answers.Root)
}

// <sel>._domainkey.<domain>, where a receiver looks a signature's key up (RFC 6376 §3.6.2.1), lowercase with no final
// dot. For a custom domain it is a per-selector CNAME's owner, and for <net>.<root> that CNAME's target.
func SmtpDkimKeyName(selector string, domain string) string {
	return strings.ToLower(selector) + "._domainkey." + strings.TrimSuffix(strings.ToLower(domain), ".")
}

// Whether record, awaiting its domain's answer, is answered now, under publishLock: looked up through the device's
// own DoH at most once each DkimAnswerRetryInterval. An answer takes it into use: the selectors it replaces that
// still sign are written retiring first, then it is written published, so a kill between leaves the domain signing
// under neither until the next call finds the answer again, and never under two; then their retire is sent, a
// failed one left for the next call's prepare. The error is the keychain's alone.
func (self *SmtpDkimKeys) answerWithPublishLock(ctx context.Context, records map[string]*smtpDkimRecord, record *smtpDkimRecord, now time.Time) (bool, error) {
	if lookupTime, ok := self.answerLookupTimes[record.Selector]; ok && now.Sub(lookupTime) < self.settings.DkimAnswerRetryInterval {
		return false, nil
	}
	self.answerLookupTimes[record.Selector] = now
	answers := self.domainAnswers()
	if answers == nil || answers.Doh == nil {
		return false, nil
	}
	testHookBarrier("smtp.dkim_answer.before", record.Selector)
	answered := smtpDkimLookupAnswer(ctx, answers.Doh, self.clock, self.settings.DkimAnswerLookupTimeout, record)
	testHookBarrier("smtp.dkim_answer.after", record.Selector)
	if !answered {
		if self.log.V(1).Enabled() {
			self.log.Infof("[smtp]dkim selector %s awaits its domain's answer\n", record.Selector)
		}
		return false, nil
	}
	delete(self.answerLookupTimes, record.Selector)
	retiring := []*smtpDkimRecord{}
	for _, replaced := range record.Replaces {
		existing, ok := records[replaced]
		if !ok || existing.State != smtpDkimStatePublished {
			continue
		}
		existing.State = smtpDkimStateRetiring
		existing.Replaces = nil
		if err := self.putWithPublishLock(existing); err != nil {
			return false, err
		}
		retiring = append(retiring, existing)
	}
	record.State = smtpDkimStatePublished
	record.AnswerTimeMs = now.UnixMilli()
	record.Replaces = nil
	if err := self.putWithPublishLock(record); err != nil {
		return false, err
	}
	if 0 < len(retiring) {
		if err := self.sendRetireWithPublishLock(ctx, retiring, now); err != nil {
			if smtpDkimStoreError(err) {
				return false, err
			}
			self.log.Infof("[smtp]dkim retire of %d selectors left for the next call: %v\n", len(retiring), err)
		}
	}
	return true, nil
}

// Whether doh finds record's public key at <sel>._domainkey.<domain> within timeout on clock: a TXT record there, or
// where its CNAMEs lead, that SmtpDkimKeyRecordHolds. A failed, refused, truncated or malformed lookup, one to
// another question, the timeout and NXDOMAIN are no answer.
func smtpDkimLookupAnswer(ctx context.Context, doh SmtpDohForwarder, clock Clock, timeout time.Duration, record *smtpDkimRecord) bool {
	answer, ok := smtpDohLookup(ctx, doh, clock, timeout, dnsmessage.TypeTXT, SmtpDkimKeyName(record.Selector, record.Domain))
	if !ok || !answer.exists {
		return false
	}
	for _, resource := range answer.resources {
		txt, ok := resource.Body.(*dnsmessage.TXTResource)
		if ok && SmtpDkimKeyRecordHolds(strings.Join(txt.TXT, ""), record.PublicKey) {
			return true
		}
	}
	return false
}

// Whether text, a key record's character-strings joined (RFC 6376 §3.6.2.2), publishes publicKey, DER
// SubjectPublicKeyInfo, for an rsa-sha256 signature as a receiver reads it (§3.6.1): a tag list with no tag named
// twice, whose v=, when present, is DKIM1, whose k=, when present, is rsa, whose h=, when present, lists sha256,
// whose s=, when present, lists * or email, and whose p= is publicKey's base64, folding white space aside. A revoked
// key, an empty p=, holds nothing.
func SmtpDkimKeyRecordHolds(text string, publicKey []byte) bool {
	if len(publicKey) == 0 {
		return false
	}
	stripFws := func(value string) string {
		return strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				return -1
			}
			return r
		}, value)
	}
	tags := map[string]string{}
	for spec := range strings.SplitSeq(text, ";") {
		if strings.TrimSpace(spec) == "" {
			// the list may end in a semicolon (§3.2)
			continue
		}
		name, value, ok := strings.Cut(spec, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return false
		}
		if _, seen := tags[name]; seen {
			return false
		}
		tags[name] = strings.TrimSpace(value)
	}
	listHas := func(list string, items ...string) bool {
		for _, item := range strings.Split(strings.ToLower(stripFws(list)), ":") {
			for _, want := range items {
				if item == want {
					return true
				}
			}
		}
		return false
	}
	if version, ok := tags["v"]; ok && version != "DKIM1" {
		return false
	}
	if keyType, ok := tags["k"]; ok && strings.ToLower(keyType) != "rsa" {
		return false
	}
	if hashes, ok := tags["h"]; ok && !listHas(hashes, "sha256") {
		return false
	}
	if services, ok := tags["s"]; ok && !listHas(services, "*", "email") {
		return false
	}
	encoded := stripFws(tags["p"])
	if encoded == "" {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	return err == nil && bytes.Equal(decoded, publicKey)
}
