//go:build !sidecar_http && !js && !ios_extension

// §15.5's spf row (MAIL-M7-08): RFC 7208's evaluation of sender_ip for MAIL FROM's domain, or the post-TLS EHLO's
// with a null reverse path (plan-MAIL-small-readings#14), within §4.6.4's limits, which mox's spf enforces: 10 terms
// that look up, 2 void lookups. The record relied on is kept, never a DNS transcript. A temperror a bound or the
// deadline caused is incomplete.

package sidecar

import (
	"context"
	"net"
	"strings"
	"unicode/utf8"

	moxdns "github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/spf"

	"github.com/urnetwork/sidecar/protocol"
)

// mox's status as §15.5's verdict.
var mailSpfVerdicts = map[spf.Status]protocol.SpfVerdict{
	spf.StatusPass:      protocol.SpfVerdict_SPF_PASS,
	spf.StatusFail:      protocol.SpfVerdict_SPF_FAIL,
	spf.StatusSoftfail:  protocol.SpfVerdict_SPF_SOFTFAIL,
	spf.StatusNeutral:   protocol.SpfVerdict_SPF_NEUTRAL,
	spf.StatusNone:      protocol.SpfVerdict_SPF_NONE,
	spf.StatusTemperror: protocol.SpfVerdict_SPF_TEMPERROR,
	spf.StatusPermerror: protocol.SpfVerdict_SPF_PERMERROR,
}

// The EHLO name as SPF's HELO identity: an address literal, or a domain; zero for anything else.
func mailSpfHello(ehloName string) moxdns.IPDomain {
	if literal, ok := strings.CutPrefix(ehloName, "["); ok {
		literal = strings.TrimSuffix(literal, "]")
		literal = strings.TrimPrefix(strings.TrimPrefix(literal, "IPv6:"), "ipv6:")
		if ip := net.ParseIP(literal); ip != nil {
			return moxdns.IPDomain{IP: ip}
		}
		return moxdns.IPDomain{}
	}
	if domain, err := moxdns.ParseDomain(ehloName); err == nil {
		return moxdns.IPDomain{Domain: domain}
	}
	return moxdns.IPDomain{}
}

// SPF's arguments for the session and the domain it judges: MAIL FROM's, else the EHLO's with a null reverse path.
// false where there is none, or no sender address: a reverse path that is no address, or an EHLO that is an
// address literal with a null reverse path.
func mailSpfIdentity(input *MailAuthInput) (spf.Args, moxdns.Domain, bool) {
	args := spf.Args{RemoteIP: net.IP(input.SenderIp.Unmap().AsSlice()), HelloDomain: mailSpfHello(input.EhloName)}
	if len(input.MailFrom) != 0 {
		address, err := smtp.ParseAddress(string(input.MailFrom))
		if err != nil {
			return args, moxdns.Domain{}, false
		}
		args.MailFromLocalpart, args.MailFromDomain = address.Localpart, address.Domain
	}
	domain := args.MailFromDomain
	if domain.IsZero() {
		domain = args.HelloDomain.Domain
	}
	return args, domain, !domain.IsZero() && input.SenderIp.IsValid()
}

// SPF's result for the session, judged for domain with args, as mailSpfIdentity gives them.
func (self *MailAuthChecker) checkSpf(ctx context.Context, resolver *MailAuthResolver, input *MailAuthInput, args spf.Args, domain moxdns.Domain, ok bool) *protocol.SpfResult {
	result := &protocol.SpfResult{Result: protocol.SpfVerdict_SPF_NONE}
	if input.SenderIp.IsValid() {
		result.Ip = input.SenderIp.Unmap().AsSlice()
	}
	if !ok {
		return result
	}
	result.Domain = domain.ASCII
	status, text, record, _, _ := self.verifiers.spfLookup(ctx, self.log, resolver, domain)
	if record != nil {
		if utf8.ValidString(text) {
			result.Records = []string{text}
		}
		status, _, _, _, _ = self.verifiers.spfEvaluate(ctx, self.log, record, resolver, args)
	}
	result.Result = mailSpfVerdicts[status]
	if result.Result == protocol.SpfVerdict_SPF_VERDICT_UNSPECIFIED {
		result.Result = protocol.SpfVerdict_SPF_PERMERROR
	}
	if result.Result == protocol.SpfVerdict_SPF_TEMPERROR && (ctx.Err() != nil || resolver.CutAt(MailAuthPrioritySpf)) {
		result.Result = protocol.SpfVerdict_SPF_INCOMPLETE
	}
	return result
}
