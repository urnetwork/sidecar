// §13.8's CAA at <root>. It sits in the root so dnsservice can call it, and a name without this set is open to every
// CA, so an input that would leave the set empty or unusable is refused, never rendered.
//
// Errors name no input (I-13).

package sidecar

import (
	"errors"
	"net/url"
	"slices"
	"strings"
)

// §13.8's CAs, by the issuer domain each one's CAA checks for.
const (
	// Let's Encrypt.
	TlsCaaIssuerLetsEncrypt = "letsencrypt.org"
	// GTS, Google Trust Services.
	TlsCaaIssuerGts = "pki.goog"
	// ZeroSSL.
	TlsCaaIssuerZeroSsl = "sectigo.com"
)

// An account URI that a CAA record cannot carry, an issuer §13.8 does not name, or no account at all.
var ErrTlsCaaRecords = errors.New("tls caa records refused")

// Whether uri is an https URL that RFC 8659's value grammar can carry and a presentation-form string needs no escape
// for: printable ASCII, without the ; that ends a parameter, or the " and \ a zone file reads.
func tlsCaaAccountUriUsable(uri string) bool {
	for index := range len(uri) {
		c := uri[index]
		if c < 0x21 || 0x7E < c || c == ';' || c == '"' || c == '\\' {
			return false
		}
	}
	parsed, err := url.Parse(uri)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil
}

// The CAA records at <root> for URnetwork's ACME accounts, keyed by issuer domain, in presentation form without
// owner, TTL or class, as DnsRecordSet.Rdata holds them: for each account of each CA,
//
//	0 issue "<issuer>; accounturi=<uri>; validationmethods=dns-01"
//	0 issuewild "<issuer>; accounturi=<uri>; validationmethods=dns-01"
//
// in §13.8's CA order, then by URI, each record once, so a rendering is stable. A CAA property takes one accounturi:
// RFC 8657 makes one with two unsatisfiable, which would refuse every order, so a CA's accounts are one record each
// and any of them authorizes. An account URI belongs to the CA that issued it, so each is listed under that CA alone.
//
// A CA with no accounts gets no records and so can issue nothing, which is the closed direction while its account is
// not yet made. No accounts at all is refused, because an empty set would leave <root> to every CA. There is no
// per-label accounturi, so a network's name adds nothing here (§13.8). The iodef record is §12.7's.
func TlsRootCaaRecords(issuerAccountUris map[string][]string) ([]string, error) {
	for issuer := range issuerAccountUris {
		if !slices.Contains(tlsRootCaaIssuers(), issuer) {
			return nil, ErrTlsCaaRecords
		}
	}
	records := []string{}
	for _, issuer := range tlsRootCaaIssuers() {
		accountUris := slices.Sorted(slices.Values(issuerAccountUris[issuer]))
		accountUris = slices.Compact(accountUris)
		for _, tag := range []string{"issue", "issuewild"} {
			for _, accountUri := range accountUris {
				if !tlsCaaAccountUriUsable(accountUri) {
					return nil, ErrTlsCaaRecords
				}
				records = append(records, tlsCaaRecord(tag, issuer, accountUri))
			}
		}
	}
	if len(records) == 0 {
		return nil, ErrTlsCaaRecords
	}
	return records, nil
}

// §13.8's CAs in the order it writes them.
func tlsRootCaaIssuers() []string {
	return []string{TlsCaaIssuerLetsEncrypt, TlsCaaIssuerGts, TlsCaaIssuerZeroSsl}
}

// One record in presentation form.
func tlsCaaRecord(tag string, issuer string, accountUri string) string {
	var record strings.Builder
	record.WriteString(`0 `)
	record.WriteString(tag)
	record.WriteString(` "`)
	record.WriteString(issuer)
	record.WriteString(`; accounturi=`)
	record.WriteString(accountUri)
	record.WriteString(`; validationmethods=dns-01"`)
	return record.String()
}
