//go:build !ios_extension

// MTA-STS's policy for a zone's mail host (§12.7, §15.5, RFC 8461; DNS-M8-01): the text a mail-enabled
// network's receivers serve at https://mta-sts.<zone>/.well-known/mta-sts.txt as a system publish (MAIL-M8-08),
// and the id §12.7's _mta-sts TXT carries, "v=STSv1; id=<id>", which changes exactly when the text does, so a
// sender refetches the policy then and only then (RFC 8461 §3.1). Both sides compute both from one function, the
// dns writer at the zone's records and the receivers at their publish, so they never disagree.
//
// Burner domains publish no policy, and senders never take a parent zone's (RFC 8461 §3.4), so a <blabel> gets
// none: only a zone's apex, a network's, an alias's or a Team scope's, has one.

package sidecar

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// The policy mode §15.5 serves: senders that cannot validate the mail host's certificate do not deliver.
const MtaStsModeEnforce = "enforce"

// The policy's parameters. One object both the dns writer and the receivers read, so its defaults stay in one
// place: a change here changes the policy and its id together.
type MtaStsSettings struct {
	// §15.5's enforce.
	Mode string
	// Seconds a sender caches the policy (RFC 8461 §3.2 max_age): a week, which RFC 8461 §3.2 suggests as weeks or
	// more, and well under its 31557600 bound. Must be positive.
	MaxAgeSeconds int
	// How many hex digits of the policy's SHA-256 its id takes: 32, RFC 8461 §3.1's longest id.
	IdDigitCount int
}

// §15.5's policy: enforce, cached a week, its id 32 hex digits.
func DefaultMtaStsSettings() *MtaStsSettings {
	return &MtaStsSettings{
		Mode:          MtaStsModeEnforce,
		MaxAgeSeconds: 7 * 24 * 3600,
		IdDigitCount:  32,
	}
}

// The policy for the mail host mxHost, a name with or without its final dot (RFC 8461 §3.2), its lines ending in
// CRLF. settings nil takes DefaultMtaStsSettings.
func MtaStsPolicy(mxHost string, settings *MtaStsSettings) string {
	if settings == nil {
		settings = DefaultMtaStsSettings()
	}
	mxHost = strings.TrimSuffix(strings.ToLower(mxHost), ".")
	return fmt.Sprintf("version: STSv1\r\nmode: %s\r\nmx: %s\r\nmax_age: %d\r\n", settings.Mode, mxHost, settings.MaxAgeSeconds)
}

// The id of policy as _mta-sts carries it: the first IdDigitCount lowercase hex digits of its SHA-256, so it
// changes exactly when the policy does and stays within RFC 8461 §3.1's 1 to 32 alphanumerics. settings nil takes
// DefaultMtaStsSettings.
func MtaStsPolicyId(policy string, settings *MtaStsSettings) string {
	if settings == nil {
		settings = DefaultMtaStsSettings()
	}
	digest := sha256.Sum256([]byte(policy))
	text := hex.EncodeToString(digest[:])
	return text[:min(max(settings.IdDigitCount, 1), len(text))]
}
