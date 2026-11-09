// §15.8's address grammar (R-MAIL-3, R-MAIL-7, R-MAIL-9, D-MAIL-7): the recipients a network's receivers take
// mail for, parsed from an RCPT address under a root, and the local parts `ur id create`, an agent's registration
// and §16's mail_alias_create may claim. Pure and on every leg, the sidecar_http Worker included, since it links no
// connect, go-smtp or mox; server links it too, where a report's address names its network (ABUSE-M5-09).
//
// The forms, <net> being a network's label or one of its aliases, so an alias zone stands in for <net> in each:
//
//	admin@<net>.<root>                admin, with postmaster@ and abuse@ its aliases (RFC 5321 §4.5.1, RFC 2142)
//	<name>@<net>.<root>               an id, a group or an agent: which, and whether it exists, only mailcfg says
//	<name>@<scope>.<net>.<root>       the same in a Team scope (owner decision 58), admin and its aliases included
//	bounces+<token>@b.<net>.<root>    a DSN to a sending mailbox (§14.6)
//	<name>@<blabel>.<net>.<root>      a burner, any local part, <blabel> a word-number label (§15.9)
//	r-<token>@<blabel>.<net>.<root>   a burner's reverse alias (§15.10), which parses although r-* is reserved
//
// Parsing folds ASCII case, since §15.8's local parts are lowercase and DNS folds case, and refuses everything
// else: a quoted, empty or non-ASCII local part, a domain outside the root, an IP literal, and a burner or b. zone
// under a Team scope, which §15.8's table does not have. A <scope> or <net> is a lowercase LDH label but no
// word-number label, which only burners take (§12.7, owner decision 32), and none of §12.7's refused owners b, mx,
// mail and mta-sts, which are the bounce zone and hosts. Nothing else of §12.5's reserved block is refused here: a
// standing alias keeps its mail when that list grows, as NetworkLabelRow keeps it, and a name no network holds is
// unknown at the lookup. A refusal is answered 550 5.1.1 as an unknown address is, so the grammar tells a sender
// nothing a lookup would not.
//
// Errors never repeat an address, since alias names stay out of logs and servers (I-13).

package sidecar

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// The longest local part, RFC 5321 §4.5.3.1.1's 64 octets, which §15.8's grammar also reaches.
const mailLocalPartMaxByteCount = 64

// The longest address: a 64-byte local part, its @ and a 253-byte domain. MAIL-FORMAT.md caps IndexEntry.address
// here, which a parsed recipient never passes.
const MailAddressMaxByteCount = mailLocalPartMaxByteCount + 1 + dnsDomainMaxByteCount

// The local parts §15.8 reserves from creation, beside every r-* name.
var mailReservedLocalParts = []string{"admin", "postmaster", "abuse", "mailer-daemon", "bounces"}

// §15.8's local parts that reach admin's mailbox (RFC 5321 §4.5.1, RFC 2142).
var mailAdminLocalParts = []string{"admin", "postmaster", "abuse"}

// The prefixes of the two token forms, and the label of the bounce zone (§14.6).
const (
	mailReverseAliasPrefix = "r-"
	mailBouncePrefix       = "bounces+"
	mailBounceLabel        = "b"
)

// §12.7's refused owners in a network or alias zone that a mail zone label is never: the bounce zone and the mx,
// mail and mta-sts hosts.
var mailZoneRefusedLabels = []string{mailBounceLabel, "mx", "mail", "mta-sts"}

var (
	// An address that is none of §15.8's forms under the root. Wrapped with which part failed, never with the
	// address itself.
	ErrMailRecipientInvalid = errors.New("mail recipient is not an address of a network's zones")
	// A local part outside §15.8's grammar.
	ErrMailLocalPartInvalid = errors.New("mail local part must be 1 to 64 of a-z, 0-9, dot, underscore and dash, starting with a letter or digit")
	// A local part §15.8 reserves from creation.
	ErrMailLocalPartReserved = errors.New("mail local part is reserved")
)

// Which of §15.8's forms an address takes. The grammar cannot tell an id from a group or an agent: mailcfg's
// MailAddress.kind does, once a lookup finds the record.
type MailAddressKind string

const (
	// admin@, postmaster@ or abuse@ a network's or a scope's zone.
	MailAddressKindAdmin MailAddressKind = "admin"
	// <name>@ a network's or a scope's zone: an id, a group or an agent.
	MailAddressKindName MailAddressKind = "name"
	// bounces+<token>@b.<net>.<root>.
	MailAddressKindBounce MailAddressKind = "bounce"
	// <name>@<blabel>.<net>.<root>.
	MailAddressKindBurner MailAddressKind = "burner"
	// r-<token>@<blabel>.<net>.<root>.
	MailAddressKindReverseAlias MailAddressKind = "reverse_alias"
)

// The zone an address is in: <net>.<root>, or a Team scope's <scope>.<net>.<root>. A burner's <blabel> and the b.
// of a bounce sit under a network's zone, so neither is a field here.
type MailZone struct {
	// The user root, lowercase with no trailing dot, as NetworkLabelRow keeps it (§12.4).
	Root string
	// The network's label or one of its aliases, as the address spelled it, lowercase.
	Net string
	// A Team scope's label, or empty for the network's own zone.
	Scope string
}

// <net>.<root>, or <scope>.<net>.<root>.
func (self MailZone) Domain() string {
	if self.Scope == "" {
		return self.Net + "." + self.Root
	}
	return self.Scope + "." + self.Net + "." + self.Root
}

// Whether row's network is this zone's: the same root, and Net its label, its alias or an alias in its 90 days of
// retiring, which still names the network and nothing else (§12.5), as ResolveNetworkLabel matches a non-interactive
// text. A zone's Scope is the caller's to hold to the scopes it receives for.
func (self MailZone) OfNetwork(row NetworkLabelRow) bool {
	if self.Net == "" || self.Root != row.Root {
		return false
	}
	return self.Net == row.Label || self.Net == row.Alias || slices.Contains(row.RetiringAliases, self.Net)
}

// One recipient in one of §15.8's forms, every part lowercase.
type MailRecipient struct {
	Kind MailAddressKind
	// The local part: bounces+<token> for a bounce, r-<token> for a reverse alias.
	LocalPart string
	Zone      MailZone
	// A burner's or a reverse alias's <blabel>, else empty.
	BurnerLabel string
	// A bounce's or a reverse alias's <token>, else empty.
	Token string
}

// The domain: the zone's, under b. for a bounce and under <blabel>. for a burner or a reverse alias.
func (self MailRecipient) Domain() string {
	switch self.Kind {
	case MailAddressKindBounce:
		return mailBounceLabel + "." + self.Zone.Domain()
	case MailAddressKindBurner, MailAddressKindReverseAlias:
		return self.BurnerLabel + "." + self.Zone.Domain()
	}
	return self.Zone.Domain()
}

// <local part>@<domain>, lowercase: how a deposit lists its recipients and a reader shows the address.
func (self MailRecipient) Address() string {
	return self.LocalPart + "@" + self.Domain()
}

// Whether localPart has §15.8's shape, [a-z0-9][a-z0-9._-]{0,63}. A reserved name has it too:
// ValidateNewMailLocalPart is the check for a name about to be created.
func ValidMailLocalPart(localPart string) bool {
	if localPart == "" || mailLocalPartMaxByteCount < len(localPart) {
		return false
	}
	if !isDnsLowerBytes(localPart[:1], "") {
		return false
	}
	return isDnsLowerBytes(localPart, "._-")
}

// Whether §15.8 reserves localPart from creation: admin, postmaster, abuse, mailer-daemon, bounces and every r-*
// name, the last since r-<token> is a burner's reverse alias (§15.10).
func IsReservedMailLocalPart(localPart string) bool {
	return slices.Contains(mailReservedLocalParts, localPart) || strings.HasPrefix(localPart, mailReverseAliasPrefix)
}

// The check for a local part about to be created, by `ur id create`, an agent's registration or §16's
// mail_alias_create: ErrMailLocalPartInvalid or ErrMailLocalPartReserved, else nil. It takes the name as given,
// so a caller folds case first if it means to.
func ValidateNewMailLocalPart(localPart string) error {
	if !ValidMailLocalPart(localPart) {
		return ErrMailLocalPartInvalid
	}
	if IsReservedMailLocalPart(localPart) {
		return ErrMailLocalPartReserved
	}
	return nil
}

// Whether token can follow bounces+ or r- in a local part: 1 or more of §15.8's local-part bytes. Its own format
// is its writer's (MAIL-M9-04, MAIL-M9-05), and a lookup refuses a token that names nothing.
func validMailToken(token string) bool {
	return token != "" && isDnsLowerBytes(token, "._-")
}

// Whether label can name a network or a scope in a mail zone: lowercase LDH, not word-number and not one of
// mailZoneRefusedLabels.
func validMailZoneLabel(label string) bool {
	return isDnsLowerLdhLabel(label) && !IsWordNumberDnsLabel(label) && !slices.Contains(mailZoneRefusedLabels, label)
}

// address in one of §15.8's forms under root, any ASCII case: an RCPT's address without its angle brackets, or an
// address a report names. root is the user root, such as the one dns.yml names, with or without a trailing dot.
// Anything else is ErrMailRecipientInvalid, the address unrepeated.
func ParseMailRecipient(root string, address string) (MailRecipient, error) {
	invalid := func(reason string) (MailRecipient, error) {
		return MailRecipient{}, fmt.Errorf("%w: %s", ErrMailRecipientInvalid, reason)
	}
	root = canonicalNetworkLabelRoot(root)
	if !isNetworkLabelRoot(root) {
		return invalid("the root is not a domain name")
	}
	if MailAddressMaxByteCount < len(address) {
		return invalid("the address is too long")
	}
	address = dnsAsciiLower(address)
	localPart, domain, found := strings.Cut(address, "@")
	if !found || strings.Contains(domain, "@") {
		return invalid("the address has no single @")
	}
	if localPart == "" || mailLocalPartMaxByteCount < len(localPart) {
		return invalid("the local part is empty or too long")
	}
	if dnsDomainMaxByteCount < len(domain) {
		return invalid("the domain is too long")
	}
	zoneText, found := strings.CutSuffix(domain, "."+root)
	if !found || zoneText == "" {
		return invalid("the domain is not under the root")
	}
	labels := strings.Split(zoneText, ".")
	net := labels[len(labels)-1]
	if !validMailZoneLabel(net) {
		return invalid("the domain names no network")
	}
	zone := MailZone{Root: root, Net: net}

	switch len(labels) {
	case 1:
		// <name>@<net>.<root>
	case 2:
		first := labels[0]
		switch {
		case first == mailBounceLabel:
			token, found := strings.CutPrefix(localPart, mailBouncePrefix)
			if !found || !validMailToken(token) {
				return invalid("a bounce zone takes only bounces+<token>")
			}
			return MailRecipient{Kind: MailAddressKindBounce, LocalPart: localPart, Zone: zone, Token: token}, nil
		case IsWordNumberDnsLabel(first):
			if !ValidMailLocalPart(localPart) {
				return invalid("the local part breaks the grammar")
			}
			recipient := MailRecipient{Kind: MailAddressKindBurner, LocalPart: localPart, Zone: zone, BurnerLabel: first}
			if token, found := strings.CutPrefix(localPart, mailReverseAliasPrefix); found {
				if token == "" {
					return invalid("a reverse alias has no token")
				}
				recipient.Kind = MailAddressKindReverseAlias
				recipient.Token = token
			}
			return recipient, nil
		case validMailZoneLabel(first):
			zone.Scope = first
		default:
			return invalid("the domain names no scope")
		}
	default:
		return invalid("the domain is deeper than a scope")
	}

	if !ValidMailLocalPart(localPart) {
		return invalid("the local part breaks the grammar")
	}
	kind := MailAddressKindName
	if slices.Contains(mailAdminLocalParts, localPart) {
		kind = MailAddressKindAdmin
	}
	return MailRecipient{Kind: kind, LocalPart: localPart, Zone: zone}, nil
}
