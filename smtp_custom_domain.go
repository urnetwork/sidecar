//go:build !ios_extension

// §14.6's sending identity as the sender and the edge share it (D-SMTP-5, D-SMTP-15, R-SMTP-12; SMTP-M9-34): the
// envelope domain MAIL FROM is at, which Z4 proves against the value the edge derives from the ticket's network and
// never takes from the sidecar (smtpproof/SPEC.md section 3), so both ends reach it by this one rule.
//
//	network   b.<net>.<root>, with the network's mail host as its MX and _spf.<root> in its SPF (§12.7). Mail of
//	          every zone of the network, an alias's, a scope's and a burner's, takes it
//	custom    a Team network's verified domain (§7.6) as the header From (D-SMTP-15) keeps b.<net>.<root>: SPF
//	          never aligns (D-SMTP-5), so DMARC at the customer's adkim=s rests on the network's own selectors
//	strict    strict mode (§15.4) moves a custom domain's envelope to b.<domain>, with the customer's MX and SPF
//	          include: a verified domain at or above an active strict-mode MX host the network maps (QD-1129). The
//	          edge's feed names the set (smtpedgeservice.SmtpGateFacts.StrictDomains) and the sender reads the same
//	          from GET /mail/status (MailNetworkStatus.StrictDomains), both through the server's one read of it,
//	          since an envelope the edge does not expect fails its part and cuts the connection. Both ends then pick
//	          a From's envelope by SmtpStrictCustomDomain, the edge's gate (gate_custom_domain.go) and MAIL's bounce
//	          address (mail_bounce.go) alike, and the sender asks again at each connection (SmtpSenderArgs.Envelope),
//	          so a strict-mode MX host mapped or unmapped after a message was queued moves its envelope with the
//	          edge's. Mapping the MX host moves the envelope whether or not mail.strict is signed yet
//
// A custom domain's DKIM selectors are SmtpDkimKeys' as any domain's: d= is the header From's domain, which Z5 holds
// literally, so a custom-domain send signs under that domain or fails, and its selectors go through POST
// /smtp/dkim-keys naming it. The server writes their records at <sel>._domainkey.<net>.<root>, which the customer's
// delegated _domainkey.<domain> (dnsservice.DelegatedZones) or a per-selector CNAME answers; a new selector signs
// only once the device's own DoH finds the domain answering it (QD-1130, smtp_dkim_answer.go), and GET /network/dns
// names the CNAMEs a domain owes until then.
//
// On every leg but the extension's; nothing here does I/O.

package sidecar

import (
	"strings"
)

// The envelope domain's label below the domain it serves (§12.7's b).
const smtpEnvelopeLabel = "b"

// The envelope domain of mail sent by the network whose zone is networkDomain, <net>.<root> (see the file header):
// b.<strictCustomDomain> for a header From in a custom domain in strict mode, which the caller names, and
// b.<networkDomain> otherwise. Lowercase, with no final dot.
func SmtpEnvelopeDomain(networkDomain string, strictCustomDomain string) string {
	domain := networkDomain
	if strictCustomDomain != "" {
		domain = strictCustomDomain
	}
	return smtpEnvelopeLabel + "." + strings.ToLower(strings.TrimSuffix(domain, "."))
}

// The custom domain in strict mode whose b. a header From in headerFromDomain sends with, under strictDomains, the
// network's set as the edge's feed and GET /mail/status name it (see the file header's strict row): headerFromDomain
// itself where the set names it, case and a final dot folded, and it lies outside root; "" otherwise. So a From in
// the network's own zones or a burner's, a custom domain the set does not name, and a subdomain of a strict domain
// that the set does not name itself all keep b.<net>.<root>. The edge's gate and MAIL's bounce address both pick by
// this, so on one set the two never disagree. Lowercase, with no final dot.
func SmtpStrictCustomDomain(headerFromDomain string, strictDomains []string, root string) string {
	canonical := func(name string) string {
		return strings.TrimSuffix(strings.ToLower(name), ".")
	}
	fromDomain := canonical(headerFromDomain)
	root = canonical(root)
	if fromDomain == "" || fromDomain == root || strings.HasSuffix(fromDomain, "."+root) {
		return ""
	}
	for _, strictDomain := range strictDomains {
		if canonical(strictDomain) == fromDomain {
			return fromDomain
		}
	}
	return ""
}
