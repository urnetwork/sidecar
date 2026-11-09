// §12.7's user records and the zone lint (DNS-M5-02; D-DNS-6, D-DNS-7, Q-DNS-6), as pure functions
// every writer runs inside §12.6's one transaction, before the serial:
//
//   - ValidateUserRecordSet holds a network's own RRset to §12.7's user table: public unicast A and
//     AAAA only, at most 8; a CNAME alone at a host and never into a tombstoned label; printable TXT
//     of at most 1024 bytes, with no SPF at @; MX at hosts only, at most 4; SRV only at
//     _svc._proto.<host>; *.<host> only for A and AAAA; no NS, DS, DNAME, PTR, CAA, HTTPS or SVCB; no
//     system owner, scope label or word-number label; a TTL within ttl.user_range.
//   - LintZoneWrite holds every writer's result, system rows included, to RFC 2181 §10.1 and §12.7's
//     DMARC rule, at each owner the write changed.
//   - copy_rows.go's PlanCopyRows keeps the wildcard answering where a write makes an empty
//     non-terminal.
//
// A ZoneView withholds at answer time what slips past these (zone.go): these are the gate and it is
// the backstop.

package dnsservice

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/miekg/dns"

	"github.com/urnetwork/sidecar"
)

// §12.7's caps on a user RRset. Requirements of the record table (D-DNS-7) that users are told, not
// tunables.
const (
	dnsUserAddressMaxCount = 8
	dnsUserMxMaxCount      = 4
	dnsUserTxtMaxByteCount = 1024
)

// The host labels §12.7 keeps for the system's mail and burner records in every network, alias and
// scope zone.
var dnsUserRefusedHostLabels = []string{"b", "mx", "mail", "mta-sts"}

// The underscore labels of §12.7's system owners and of names certs, mail and §13 rely on, which no
// user TXT takes: the challenges, DMARC, DKIM, MTA-STS, TLS-RPT, the PSL's proof, SPF's include and the
// custom-domain challenge.
var dnsUserRefusedUnderscoreLabels = []string{
	"_acme-challenge", "_dmarc", "_domainkey", "_mta-sts", "_smtp", "_tls", "_psl", "_spf", "_urnetwork-challenge",
}

// The protocols an SRV owner names (RFC 2782).
var dnsUserSrvProtocols = []string{"_tcp", "_udp"}

var (
	// A user RRset §12.7 refuses. The wrapping error says which rule.
	ErrDnsUserRecordRefused = errors.New("dns user record refused")
	// A write whose result breaks the zone lint. Nothing of it commits.
	ErrDnsZoneLint = errors.New("dns zone lint")
	// A DMARC record §12.7 refuses: ruf, fo, or a report address in the root.
	ErrDnsDmarcRefused = errors.New("dns dmarc record refused")
)

// What §12.7's user rules read beyond the RRset.
type DnsUserRecordContext struct {
	// The root, canonical: lowercase and fully qualified.
	Root string
	// The network's zone, <label>.<root>, canonical. An alias zone is a view of it, so user records
	// are written here.
	Apex string
	// ttl.user_range: the least and most a user TTL may be. A writer gives a record that names no TTL
	// ttl.user before it validates.
	TtlRange [2]uint32
	// The network's Team scope labels (§8, from M6), which no user host takes. Empty before M6.
	ScopeLabels []string
	// Whether a label directly below Root is tombstoned (§12.5): DNS-M5-10's lookup. A CNAME into the
	// root is refused while this is nil, the closed direction.
	Tombstoned func(label string) bool
}

// Whether name is a canonical name: lowercase, fully qualified, with no escape.
func isCanonicalDnsName(name string) bool {
	if _, ok := dns.IsDomainName(name); !ok || !dns.IsFqdn(name) {
		return false
	}
	return name == strings.ToLower(name) && strings.IndexByte(name, '\\') == -1
}

// Whether label is a lowercase LDH label.
func isDnsLowerHostLabel(label string) bool {
	return isDnsHostLabel(label) && label == strings.ToLower(label)
}

// A refusal of set, saying which rule.
func refuseDnsUserRecord(set *DnsRecordSet, format string, args ...any) error {
	return fmt.Errorf("%w: %s %s: %s", ErrDnsUserRecordRefused, set.Owner, dnsTypeText(set.Type), fmt.Sprintf(format, args...))
}

// Whether name is a hostname a record may point at: at least two labels, each LDH or an underscore
// label, as a DKIM or a verification target can be.
func isDnsTargetName(name string) bool {
	labels := dns.SplitDomainName(name)
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if strings.HasPrefix(label, "_") {
			label = label[1:]
		}
		if !isDnsHostLabel(label) {
			return false
		}
	}
	return true
}

// The shape of a user owner below a zone's apex.
type dnsUserOwnerForm int

const (
	// the apex itself
	dnsUserOwnerApex dnsUserOwnerForm = iota
	// <host>
	dnsUserOwnerHost
	// *.<host>
	dnsUserOwnerWildcard
	// _<label> or _<label>.<host>, for TXT
	dnsUserOwnerUnderscore
	// _<service>._<protocol>.<host>, for SRV
	dnsUserOwnerSrv
)

// owner's form below the context's apex and its host label, or why §12.7 refuses it as a user owner.
func (self *DnsUserRecordContext) userOwnerForm(owner string) (dnsUserOwnerForm, string, error) {
	if owner == self.Apex {
		return dnsUserOwnerApex, "", nil
	}
	if !dns.IsSubDomain(self.Apex, owner) {
		return 0, "", fmt.Errorf("is outside the zone %s", self.Apex)
	}
	labels := dns.SplitDomainName(strings.TrimSuffix(owner, "."+self.Apex))
	host := labels[len(labels)-1]
	checkHost := func() error {
		switch {
		case host == "*":
			return errors.New("* is the system's")
		case strings.HasPrefix(host, "_"):
			return nil
		case !isDnsLowerHostLabel(host):
			return fmt.Errorf("host %q is not a lowercase LDH label", host)
		case slices.Contains(dnsUserRefusedHostLabels, host):
			return fmt.Errorf("%s is a system owner", host)
		case slices.Contains(self.ScopeLabels, host):
			return fmt.Errorf("%s is a scope label", host)
		case sidecar.IsWordNumberDnsLabel(host):
			return fmt.Errorf("%s is a word-number label, which burners keep", host)
		}
		return nil
	}
	checkUnderscore := func(label string) error {
		if !strings.HasPrefix(label, "_") || !isDnsLowerHostLabel(label[1:]) {
			return fmt.Errorf("%q is not an underscore label", label)
		}
		if slices.Contains(dnsUserRefusedUnderscoreLabels, label) {
			return fmt.Errorf("%s is a system owner", label)
		}
		return nil
	}
	if err := checkHost(); err != nil {
		return 0, "", err
	}
	switch {
	case len(labels) == 1 && strings.HasPrefix(host, "_"):
		if err := checkUnderscore(host); err != nil {
			return 0, "", err
		}
		return dnsUserOwnerUnderscore, "", nil
	case len(labels) == 1:
		return dnsUserOwnerHost, host, nil
	case strings.HasPrefix(host, "_"):
		return 0, "", errors.New("is below an underscore label")
	case len(labels) == 2 && labels[0] == "*":
		return dnsUserOwnerWildcard, host, nil
	case len(labels) == 2:
		if err := checkUnderscore(labels[0]); err != nil {
			return 0, "", err
		}
		return dnsUserOwnerUnderscore, host, nil
	case len(labels) == 3:
		service, protocol := labels[0], labels[1]
		if !strings.HasPrefix(service, "_") || !isDnsLowerHostLabel(service[1:]) || !slices.Contains(dnsUserSrvProtocols, protocol) {
			return 0, "", errors.New("is not _<service>._tcp or _udp.<host>")
		}
		if slices.Contains(dnsUserRefusedUnderscoreLabels, service) {
			return 0, "", fmt.Errorf("%s is a system owner", service)
		}
		return dnsUserOwnerSrv, host, nil
	}
	return 0, "", errors.New("is deeper than §12.7's owners")
}

// The types §12.7 lets a user write at each owner form.
var dnsUserOwnerTypes = map[dnsUserOwnerForm][]uint16{
	dnsUserOwnerApex:       {dns.TypeA, dns.TypeAAAA, dns.TypeTXT},
	dnsUserOwnerHost:       {dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeTXT, dns.TypeMX},
	dnsUserOwnerWildcard:   {dns.TypeA, dns.TypeAAAA},
	dnsUserOwnerUnderscore: {dns.TypeTXT},
	dnsUserOwnerSrv:        {dns.TypeSRV},
}

// One TXT character-string's bytes. miekg/dns keeps a string in presentation form, a byte outside
// printable ASCII and a backslash or quote escaped (RFC 1035 §5.1), however it was read, so this undoes
// \DDD and \X.
func dnsTxtStringBytes(text string) ([]byte, error) {
	textBytes := make([]byte, 0, len(text))
	for index := 0; index < len(text); index += 1 {
		if text[index] != '\\' {
			textBytes = append(textBytes, text[index])
			continue
		}
		if index+3 < len(text) && isDnsDigit(text[index+1]) {
			if !isDnsDigit(text[index+2]) || !isDnsDigit(text[index+3]) {
				return nil, fmt.Errorf("a broken escape in %q", text)
			}
			value := int(text[index+1]-'0')*100 + int(text[index+2]-'0')*10 + int(text[index+3]-'0')
			if 255 < value {
				return nil, fmt.Errorf("a broken escape in %q", text)
			}
			textBytes = append(textBytes, byte(value))
			index += 3
			continue
		}
		if len(text) <= index+1 || isDnsDigit(text[index+1]) {
			return nil, fmt.Errorf("a broken escape in %q", text)
		}
		textBytes = append(textBytes, text[index+1])
		index += 1
	}
	return textBytes, nil
}

// Whether character is an ASCII digit.
func isDnsDigit(character byte) bool {
	return '0' <= character && character <= '9'
}

// A TXT record's character-strings as one text, its escapes undone.
func dnsTxtText(record *dns.TXT) (string, error) {
	var text strings.Builder
	for _, part := range record.Txt {
		partBytes, err := dnsTxtStringBytes(part)
		if err != nil {
			return "", err
		}
		text.Write(partBytes)
	}
	return text.String(), nil
}

// Holds set, a network's own RRset, to §12.7's user table (see the file header): its owner and type,
// its values and its TTL, after wire.go's rules. A refusal wraps ErrDnsUserRecordRefused and says
// which rule. Whether the RRset may replace what its key holds, such as a system row, is the record
// API's (DNS-M5-12), and whether it may sit beside its owner's other rows is LintZoneWrite's.
func ValidateUserRecordSet(context *DnsUserRecordContext, set *DnsRecordSet) error {
	if context == nil || !isCanonicalDnsName(context.Root) || !isCanonicalDnsName(context.Apex) ||
		context.Apex == context.Root || !dns.IsSubDomain(context.Root, context.Apex) {
		return fmt.Errorf("%w: no zone to validate in", ErrDnsUserRecordRefused)
	}
	if context.TtlRange[0] == 0 || context.TtlRange[1] < context.TtlRange[0] {
		return fmt.Errorf("%w: no ttl range to validate in", ErrDnsUserRecordRefused)
	}
	if set.Kind != DnsRecordKindUser {
		return refuseDnsUserRecord(set, "kind %q is not a user's", set.Kind)
	}
	records, err := set.parse(context.Root)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDnsUserRecordRefused, err)
	}
	if isRefusedUserType(set.Type) {
		return refuseDnsUserRecord(set, "a type only the system writes")
	}
	form, _, err := context.userOwnerForm(set.Owner)
	if err != nil {
		return refuseDnsUserRecord(set, "the owner %s", err)
	}
	if !slices.Contains(dnsUserOwnerTypes[form], set.Type) {
		return refuseDnsUserRecord(set, "not a type §12.7 lets a user write at this owner")
	}
	if set.Ttl < context.TtlRange[0] || context.TtlRange[1] < set.Ttl {
		return refuseDnsUserRecord(set, "ttl %d is outside %d to %d", set.Ttl, context.TtlRange[0], context.TtlRange[1])
	}

	switch set.Type {
	case dns.TypeA, dns.TypeAAAA:
		if dnsUserAddressMaxCount < len(records) {
			return refuseDnsUserRecord(set, "%d addresses, more than %d", len(records), dnsUserAddressMaxCount)
		}
		for _, record := range records {
			var ip net.IP
			switch typed := record.(type) {
			case *dns.A:
				ip = typed.A
			case *dns.AAAA:
				ip = typed.AAAA
			}
			address, ok := netip.AddrFromSlice(ip)
			if !ok || !isPublicDnsAddress(address) {
				return refuseDnsUserRecord(set, "%s is not a public unicast address", ip)
			}
		}
	case dns.TypeCNAME:
		target := dns.CanonicalName(records[0].(*dns.CNAME).Target)
		if !isDnsTargetName(target) {
			return refuseDnsUserRecord(set, "target %s is not a host name", target)
		}
		if target == set.Owner {
			return refuseDnsUserRecord(set, "names itself")
		}
		if dns.IsSubDomain(context.Root, target) && target != context.Root {
			labels := dns.SplitDomainName(strings.TrimSuffix(target, "."+context.Root))
			label := labels[len(labels)-1]
			if context.Tombstoned == nil {
				return refuseDnsUserRecord(set, "target %s is in the root, and no tombstone lookup was given", target)
			}
			if context.Tombstoned(label) {
				return refuseDnsUserRecord(set, "target %s is under the tombstoned label %s", target, label)
			}
		}
	case dns.TypeTXT:
		byteCount := 0
		for _, record := range records {
			text, err := dnsTxtText(record.(*dns.TXT))
			if err != nil {
				return refuseDnsUserRecord(set, "%v", err)
			}
			byteCount += len(text)
			for index := range len(text) {
				if text[index] < 0x20 || 0x7e < text[index] {
					return refuseDnsUserRecord(set, "a byte that is not printable ASCII")
				}
			}
			if form == dnsUserOwnerApex && strings.HasPrefix(strings.ToLower(text), "v=spf1") {
				return refuseDnsUserRecord(set, "SPF at the apex is the system's")
			}
		}
		if dnsUserTxtMaxByteCount < byteCount {
			return refuseDnsUserRecord(set, "%d bytes of text, more than %d", byteCount, dnsUserTxtMaxByteCount)
		}
	case dns.TypeMX:
		if dnsUserMxMaxCount < len(records) {
			return refuseDnsUserRecord(set, "%d exchanges, more than %d", len(records), dnsUserMxMaxCount)
		}
		for _, record := range records {
			if exchange := dns.CanonicalName(record.(*dns.MX).Mx); !isDnsTargetName(exchange) {
				return refuseDnsUserRecord(set, "exchange %s is not a host name", exchange)
			}
		}
	case dns.TypeSRV:
		for _, record := range records {
			if target := dns.CanonicalName(record.(*dns.SRV).Target); !isDnsTargetName(target) {
				return refuseDnsUserRecord(set, "target %s is not a host name", target)
			}
		}
	}
	return nil
}

// Holds a DMARC record to §12.7 and §14.6: v=DMARC1 first, a p tag, no tag twice, no ruf and no fo,
// and every rua a mailto: address outside root, since report mail into a user root would land with
// whoever holds the name. root is a zone name, with or without its final dot.
func ValidateDmarcRecord(root string, record string) error {
	root = strings.TrimSuffix(strings.ToLower(root), ".")
	if root == "" {
		return fmt.Errorf("%w: no root", ErrDnsDmarcRefused)
	}
	tags := map[string]string{}
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		if !ok || name == "" {
			return fmt.Errorf("%w: %q is not a tag", ErrDnsDmarcRefused, part)
		}
		if len(tags) == 0 && (name != "v" || value != "DMARC1") {
			return fmt.Errorf("%w: does not start v=DMARC1", ErrDnsDmarcRefused)
		}
		if _, repeated := tags[name]; repeated {
			return fmt.Errorf("%w: %s twice", ErrDnsDmarcRefused, name)
		}
		tags[name] = value
	}
	if tags["v"] != "DMARC1" || tags["p"] == "" {
		return fmt.Errorf("%w: no v=DMARC1 or no p", ErrDnsDmarcRefused)
	}
	for _, refused := range []string{"ruf", "fo"} {
		if _, ok := tags[refused]; ok {
			return fmt.Errorf("%w: %s is refused", ErrDnsDmarcRefused, refused)
		}
	}
	if rua, ok := tags["rua"]; ok {
		for _, uri := range strings.Split(rua, ",") {
			uri = strings.TrimSpace(uri)
			scheme, address, ok := strings.Cut(uri, ":")
			if !ok || strings.ToLower(scheme) != "mailto" {
				return fmt.Errorf("%w: rua %q is not a mailto: address", ErrDnsDmarcRefused, uri)
			}
			// a size limit follows a !, which a mailto address may not hold unescaped (RFC 7489 §6.2)
			address, _, _ = strings.Cut(address, "!")
			address, err := url.PathUnescape(address)
			if err != nil {
				return fmt.Errorf("%w: rua %q: %w", ErrDnsDmarcRefused, uri, err)
			}
			at := strings.LastIndexByte(address, '@')
			if at <= 0 || at == len(address)-1 {
				return fmt.Errorf("%w: rua %q has no address", ErrDnsDmarcRefused, uri)
			}
			domain := strings.TrimSuffix(strings.ToLower(address[at+1:]), ".")
			if domain == root || strings.HasSuffix(domain, "."+root) {
				return fmt.Errorf("%w: rua %q sends reports into %s", ErrDnsDmarcRefused, uri, root)
			}
		}
	}
	return nil
}

// Every row of rows at each owner, by owner.
func dnsRowsByOwner(rows []DnsRecordSet) map[string][]DnsRecordSet {
	ownerRows := map[string][]DnsRecordSet{}
	for _, row := range rows {
		ownerRows[row.Owner] = append(ownerRows[row.Owner], row)
	}
	return ownerRows
}

// Whether two owners' rows are the same rows, in any order.
func dnsOwnerRowsEqual(first []DnsRecordSet, second []DnsRecordSet) bool {
	if len(first) != len(second) {
		return false
	}
	for _, row := range first {
		if !slices.ContainsFunc(second, func(other DnsRecordSet) bool {
			return row.Key() == other.Key() && row.Ttl == other.Ttl && row.Kind == other.Kind && slices.Equal(row.Rdata, other.Rdata)
		}) {
			return false
		}
	}
	return true
}

// The zone lint (§12.7, D-DNS-6), over every writer's result, system rows included: at each owner the
// write changed between before and after, no CNAME beside any other row, copy rows included (RFC 2181
// §10.1), no CNAME at a wildcard, and every DMARC record at a _dmarc owner held to
// ValidateDmarcRecord. Owners the write left alone are not judged, so a row an older release let in
// costs its own owner and not every later write. A refusal wraps ErrDnsZoneLint, and the write takes
// no serial.
func LintZoneWrite(root string, before []DnsRecordSet, after []DnsRecordSet) error {
	beforeOwners := dnsRowsByOwner(before)
	afterOwners := dnsRowsByOwner(after)
	owners := []string{}
	for owner, rows := range afterOwners {
		if !dnsOwnerRowsEqual(rows, beforeOwners[owner]) {
			owners = append(owners, owner)
		}
	}
	slices.Sort(owners)
	for _, owner := range owners {
		rows := afterOwners[owner]
		for _, row := range rows {
			if row.Type != dns.TypeCNAME {
				continue
			}
			if 1 < len(rows) {
				return fmt.Errorf("%w: %s holds a CNAME beside other data", ErrDnsZoneLint, owner)
			}
			if strings.HasPrefix(owner, "*.") {
				return fmt.Errorf("%w: %s is a wildcard CNAME", ErrDnsZoneLint, owner)
			}
		}
		if !strings.HasPrefix(owner, "_dmarc.") {
			continue
		}
		for _, row := range rows {
			if row.Type != dns.TypeTXT {
				continue
			}
			records, err := row.Records()
			if err != nil {
				return fmt.Errorf("%w: %w", ErrDnsZoneLint, err)
			}
			for _, record := range records {
				text, err := dnsTxtText(record.(*dns.TXT))
				if err != nil {
					return fmt.Errorf("%w: %s: %w", ErrDnsZoneLint, owner, err)
				}
				if err := ValidateDmarcRecord(root, text); err != nil {
					return fmt.Errorf("%w: %s: %w", ErrDnsZoneLint, owner, err)
				}
			}
		}
	}
	return nil
}
