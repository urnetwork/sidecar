//go:build !sidecar_http && !ios_extension

// §15.4's strict mode and §15.5's strict_chain (D-MAIL-12, I-11, FS-33, FI-11, X6; owner decision 98; QD-145, QD-204;
// MAIL-M7-24): under the config's signed mail.strict, a receiver takes mail only where URnetwork cannot redirect a
// DANE-validating sender, and seals strict_chain where it can show that.
//
//	setting   ServiceSettings.mail_strict, field 7, signed by an owner or admin, network-wide, default false (QD-204;
//	          §7.9's Settings fields), read from the newest base's config head. A head this device cannot open reads
//	          off, and so does every build before the field, which skips it as unknown (D-PHASE-9): strict mode then
//	          refuses nothing and claims nothing, ordinary mail
//	splice    under strict, a spliced session for a URnetwork-zone MX host (its SNI under the user root: mx.<net>,
//	          an alias's, a scope's) is refused, since an operator can replace the MX, A and TLSA records there and
//	          the sender then delivers where no receiver checks (RFC 7672 §2.2); a splice for a custom MX host is
//	          taken only where its customer-signed zone carries its TLSA with this receiver's key (§12.8 step 4), the
//	          zone watch's StrictChain over the host's own domain (D-TRUST-9). A refusal comes before any SMTP byte:
//	          a TLS alert and the stream's end, so the sender retries
//	direct    a direct-MX session (MailDirectListener) is taken under strict, but its mail stays in URnetwork's zone,
//	          EX2's residual: it never seals strict_chain
//	chain     strict_chain is true only under strict, for a spliced session whose SNI names a custom MX host, where
//	          the zone watch holds every recipient domain's MX hosts and that host's TLSA, with this key,
//	          customer-signed, none in a URnetwork zone (DnsWatch.StrictChain). Until C20's DohCache.ForwardDnssec
//	          lands the daemon attaches no validator, so StrictChain answers false and no mail claims it
//	          (plan-MAIL-dnssec-evidence's interim). Ingest's label takes tls_basis.strict_custom_mx from the sealed
//	          strict_chain alone (mail_label.go), and its words say only that URnetwork could not redirect a
//	          DANE-validating sender, never that this sender validated
//
// Nothing here logs a host or an address (I-13). Safe for concurrent use.

package sidecar

import (
	"context"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The TLS alert a refused splice sends before closing (RFC 8446 §6): a fatal handshake_failure, which a sender reads
// as a temporary failure and retries.
var mailStrictRefusalAlert = []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}

// Whether a config head's ServiceSettings turns mail.strict on: mail_strict set true. Nil settings, a head holding none,
// read off.
func MailStrictSetting(settings *protocol.ServiceSettings) bool {
	return settings.GetMailStrict()
}

// What NewMailStrictPolicy builds on.
type MailStrictPolicyArgs struct {
	// Whether the network's mail.strict is on now (MailStrictSetting at the newest base); nil reads off.
	Strict func() bool
	// The user root the network's own MX hosts are under, read at each use.
	Root func() string
	// The zone watch's chain (DnsWatch.StrictChain); nil holds none, so under strict no custom MX host is taken and
	// no mail claims strict_custom_mx.
	Chain func(ctx context.Context, sniHost string, recipientDomains []string, spkiSha256 []byte) bool
}

// §15.4's strict mode on one receiver (see the file header).
type MailStrictPolicy struct {
	args *MailStrictPolicyArgs
}

// A policy over args.
func NewMailStrictPolicy(args *MailStrictPolicyArgs) *MailStrictPolicy {
	if args == nil {
		args = &MailStrictPolicyArgs{}
	}
	return &MailStrictPolicy{args: args}
}

// Whether mail.strict is on now.
func (self *MailStrictPolicy) Strict() bool {
	return self.args.Strict != nil && self.args.Strict()
}

// Whether sniHost names one of the network's own MX hosts in URnetwork's zone: under the user root. An empty SNI or
// root counts as URnetwork's, the closed direction.
func (self *MailStrictPolicy) urnetworkZone(sniHost string) bool {
	root := ""
	if self.args.Root != nil {
		root = mailStrictHost(self.args.Root())
	}
	host := mailStrictHost(sniHost)
	return root == "" || host == "" || host == root || strings.HasSuffix(host, "."+root)
}

// Whether a spliced session for sniHost is taken (the file header's splice row): always outside strict.
func (self *MailStrictPolicy) AdmitSplice(ctx context.Context, sniHost string, spkiSha256 []byte) bool {
	if !self.Strict() {
		return true
	}
	if self.urnetworkZone(sniHost) || self.args.Chain == nil {
		return false
	}
	host := mailStrictHost(sniHost)
	// before any recipient is known, the host's own domain: §12.8 step 4's <mx>.<domain>
	_, domain, ok := strings.Cut(host, ".")
	if !ok || domain == "" {
		return false
	}
	return self.args.Chain(ctx, host, []string{domain}, spkiSha256)
}

// A host name as the chain is asked about it: lowercase, with no final dot.
func mailStrictHost(name string) string {
	return strings.TrimSuffix(dnsAsciiLower(name), ".")
}

// Whether a router-ticketed stream is taken, from its open metadata, before its handshake: outside strict every
// stream is, and under strict only one whose MailIngress names an SNI AdmitSplice takes. Metadata that is no router's
// is refused under strict, the closed direction.
func (self *MailStrictPolicy) AdmitMetadata(ctx context.Context, metadata []byte, maxByteCount int, spkiSha256 []byte) bool {
	if !self.Strict() {
		return true
	}
	sniHost, ok := mailIngressSni(metadata, maxByteCount)
	return ok && self.AdmitSplice(ctx, sniHost, spkiSha256)
}

// The SNI a router's MailIngress names, held to its bound and version; false for metadata that is no router's.
func mailIngressSni(metadata []byte, maxByteCount int) (string, bool) {
	if len(metadata) == 0 || maxByteCount < len(metadata) {
		return "", false
	}
	ingress := &protocol.MailIngress{}
	if err := proto.Unmarshal(metadata, ingress); err != nil || ingress.GetVersion() != mailFormatVersion {
		return "", false
	}
	return dnsAsciiLower(ingress.GetSni()), true
}

// strict_chain for one spliced session's message (the file header's chain row): never for a direct-MX session, which
// its caller does not ask about.
func (self *MailStrictPolicy) StrictChain(ctx context.Context, sniHost string, recipientDomains []string, spkiSha256 []byte) bool {
	if !self.Strict() || self.urnetworkZone(sniHost) || self.args.Chain == nil || len(recipientDomains) == 0 {
		return false
	}
	return self.args.Chain(ctx, mailStrictHost(sniHost), slices.Clone(recipientDomains), spkiSha256)
}

// The recipient domains of a transaction's addresses, lowercase, each once, in order.
func mailRecipientDomains(addresses []string) []string {
	domains := []string{}
	for _, address := range addresses {
		at := strings.LastIndexByte(address, '@')
		if at < 0 {
			continue
		}
		if domain := strings.TrimSuffix(dnsAsciiLower(address[at+1:]), "."); domain != "" && !slices.Contains(domains, domain) {
			domains = append(domains, domain)
		}
	}
	return domains
}
