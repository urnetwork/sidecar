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
//	          from GET /mail/status, since an envelope the edge does not expect fails its part and cuts the
//	          connection; until MAIL's bounce address follows it (mail_bounce.go), the feed names none and both ends
//	          keep b.<net>.<root>
//
// A custom domain's DKIM selectors are SmtpDkimKeys' as any domain's: d= is the header From's domain, which Z5 holds
// literally, so a custom-domain send signs under that domain or fails, and its selectors go through POST
// /smtp/dkim-keys naming it. The server writes their records at <sel>._domainkey.<net>.<root>, which the customer's
// delegated _domainkey.<domain> (dnsservice.DelegatedZones) or a per-selector CNAME answers; under CNAME mode a new
// selector signs only once the domain answers it (QD-1130), which SmtpDkimKeys does not do yet.
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
