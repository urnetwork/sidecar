// §14.6's Team custom domains at the send gate (D-SMTP-15, R-SMTP-12, D-SMTP-5; SMTP-M9-34): a network's
// verified network_domain (§7.6) may be the header From domain, its _domainkey delegated to §12's dns or
// CNAMEd per selector to <net>.<root>, and the customer's _dmarc at adkim=s, so only a signature under the
// network's own selectors aligns (§2.8 EX2 names what delegating it into URnetwork's zone costs). The From
// row reaches this for a From in none of the network's zones and with no BURNER flag:
//
//	verified   the domain is one of SmtpGateFacts.VerifiedDomains, which the feed loads from network_domain
//	           while its verify_time stands, so a domain added and not yet proven, and one the daily recheck
//	           dropped, send nothing: DENIED from_domain. A verified name at or below <root> is no custom
//	           domain: the zone row answers the network's own names, and nothing else under <root> is the
//	           network's to send From
//	team       the network is on the team tier (QuotaLimits.Tier), or left a tier less than §20.7's 14 days
//	           ago (CustomDomainWithholdTime): past that the domain's mail From is withheld beside its web hosts
//	           (owner decision 420, QD-840), DENIED custom_domain_withheld, until a renewal puts the tier back,
//	           which the next preamble sees, nothing being deleted (D-QUOTA-6)
//	envelope   b.<net>.<root>, as for the network's own mail; b.<domain> for a domain in strict mode
//	           (StrictDomains; §15.4), with the customer's MX and SPF include. Z4 proves MAIL FROM is at it,
//	           and the edge derives it from the network alone, never from the sidecar (SPEC.md section 3)
//
// The signature's d= is header_from_domain (Z5's literal), so a custom-domain send signs under that domain or
// fails: its selectors go through POST /smtp/dkim-keys with d=<domain>, which takes them only while this row
// would pass the domain (SmtpCustomDomainSendable), and the server writes them at <sel>._domainkey.<net>.<root>,
// which a delegated _domainkey.<domain> answers (dnsservice.DelegatedZones) and a per-selector CNAME names.
//
// Nothing here is Postgres's: the facts are memory a feed fills off the path (I-12).

package smtpedgeservice

import (
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// The row's own refusal.
const smtpGateReasonCustomDomainWithheld = "custom_domain_withheld"

// Whether a network on tier, whose custom domains' mail From is withheld from withholdTime, sends From its
// verified domains at now (see the file header's team row): on the team tier, or before withholdTime. A zero
// withholdTime is a network that has left no tier, so only the team tier sends. The server's DKIM route asks
// the same, so a selector is never published under a domain the gate would refuse.
func SmtpCustomDomainSendable(tier string, withholdTime time.Time, now time.Time) bool {
	if tier == smtpTierTeam {
		return true
	}
	return !withholdTime.IsZero() && now.Before(withholdTime)
}

// Whether domain, lowercase with no final dot, is one of facts' verified domains outside root.
func smtpGateVerifiedDomain(facts *SmtpGateFacts, domain string, root string) bool {
	if domain == root || strings.HasSuffix(domain, "."+root) {
		return false
	}
	return slices.ContainsFunc(facts.VerifiedDomains, func(verifiedDomain string) bool {
		return strings.TrimSuffix(strings.ToLower(verifiedDomain), ".") == domain
	})
}

// The row for a From domain in none of the network's zones (see the file header), networkZone its
// <net>.<root>: the envelope its mail takes, or a refusal's reason. facts.Limits is loaded.
func checkSmtpCustomDomain(facts *SmtpGateFacts, fromDomain string, networkZone string, now time.Time, settings *SmtpEdgeSettings) (envelopeDomain string, reason string) {
	if !smtpGateVerifiedDomain(facts, fromDomain, strings.ToLower(settings.Root)) {
		return "", smtpGateReasonFrom
	}
	if !SmtpCustomDomainSendable(facts.Limits.Tier, facts.CustomDomainWithholdTime, now) {
		return "", smtpGateReasonCustomDomainWithheld
	}
	strict := slices.ContainsFunc(facts.StrictDomains, func(strictDomain string) bool {
		return strings.TrimSuffix(strings.ToLower(strictDomain), ".") == fromDomain
	})
	if strict {
		return sidecar.SmtpEnvelopeDomain(networkZone, fromDomain), ""
	}
	return sidecar.SmtpEnvelopeDomain(networkZone, ""), ""
}
