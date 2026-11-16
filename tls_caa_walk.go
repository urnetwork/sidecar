//go:build !ios_extension

// §12.8's and §13.8's CAA discovery for a Team custom host (RFC 8659 §3; D-DNS-9, D-TLS-11; TLS-M6-04): which CAA
// RRset governs issuance for a name, and every zone the answer rests on. It is pure code behind TlsCaaResolver, so
// certs (server.NewCertsCaaResolver) and an ordering desktop run one walk with no shared dependency, and no client leg
// links a DNS library (QD-288).
//
// The walk is RFC 8659 §3's RelevantCAASet: a CAA query for the name, then for each parent up to but not including
// the root, stopping at the first non-empty RRset. Each query follows CNAME and DNAME as DNS resolution does, and the
// climb goes on from the queried name, never from an alias's target. It adds §12.8's one rule: it refuses
// (ErrTlsCaaOperatorAlias, custom_host_caa_operator_alias) as soon as any name it meets is in a URnetwork zone, be it a
// queried name, an alias target, the zone one sits in or a nameserver of that zone, since URnetwork could then change
// the set a CA reads, and the customer's pin would no longer exclude URnetwork (§13.8; §2.8 EX1).
//
// The walk is half of certs' check of a strong-mode host. §12.8's canary probe (certsservice's caa_probe.go) is the
// other half, since only the probe sees a customer-side ALIAS that also flattens CAA, which no resolver's answer
// tells apart from the customer's own records.
//
// Records are CAA RDATA in presentation form, `<flags> <tag> "<value>"`, as a zone file and DnsRecordSet.Rdata write
// them. Errors name no input (I-13): a custom host may reach a log.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// The reason a walk that met a URnetwork zone refuses a strong-mode host, and the admin event's result at setup
// (§12.8 step 3).
const TlsCaaRefusalOperatorAlias = "custom_host_caa_operator_alias"

// The CAA property tag of §12.8's canary, the one certs publishes beside the customer's pin while it probes: a tag no
// CA knows, sent non-critical, so a CA reading it ignores it (RFC 8659 §4.1). dnsservice's DnsCaaCanaryTag names the
// same tag on the dns side.
const TlsCaaCanaryTag = "urcanary"

// RFC 8659 §4.1's flag that makes a property one a CA must understand to issue.
const tlsCaaFlagCritical = 128

var (
	// The walk met a name in a URnetwork zone: TlsCaaRefusalOperatorAlias.
	ErrTlsCaaOperatorAlias = errors.New(TlsCaaRefusalOperatorAlias)
	// A name that is no DNS name, or a resolver's answer the walk cannot read: a walk with no result, never a pass.
	ErrTlsCaaWalk = errors.New("tls caa walk refused")
	// A record that is no CAA RDATA in presentation form.
	ErrTlsCaaRecord = errors.New("tls caa record refused")
)

// One CAA property (RFC 8659 §4.1).
type TlsCaaRecord struct {
	Flags uint8
	// As the record wrote it. Tags compare without case.
	Tag string
	// The value with its quoting and escapes undone.
	Value string
}

// Whether a CA must understand the property to issue (RFC 8659 §4.1).
func (self *TlsCaaRecord) Critical() bool {
	return self.Flags&tlsCaaFlagCritical != 0
}

// The record in presentation form, with the value quoted and every byte a zone file cannot carry bare escaped as \DDD,
// as miekg/dns writes it, so dns's parser reads back exactly this property.
func (self *TlsCaaRecord) String() string {
	var builder strings.Builder
	builder.WriteString(strconv.Itoa(int(self.Flags)))
	builder.WriteString(" ")
	builder.WriteString(self.Tag)
	builder.WriteString(` "`)
	for index := range len(self.Value) {
		switch c := self.Value[index]; {
		case c == '"' || c == '\\':
			builder.WriteByte('\\')
			builder.WriteByte(c)
		case c < 0x20 || 0x7E < c:
			fmt.Fprintf(&builder, "\\%03d", c)
		default:
			builder.WriteByte(c)
		}
	}
	builder.WriteString(`"`)
	return builder.String()
}

// An issue or issuewild value's issuer domain and parameters (RFC 8659 §4.2, RFC 8657 §3): the issuer lowercase, ""
// for a value that names none, which admits no CA; parameter tags lowercase. ok is false for a value the grammar
// refuses, which a CA reads as admitting nothing.
func (self *TlsCaaRecord) IssueValue() (issuer string, parameters map[string]string, ok bool) {
	parts := strings.Split(self.Value, ";")
	issuer = strings.ToLower(strings.Trim(parts[0], " \t"))
	if issuer != "" && !tlsCaaDomainName(issuer) {
		return "", nil, false
	}
	parameters = map[string]string{}
	for _, part := range parts[1:] {
		part = strings.Trim(part, " \t")
		if part == "" {
			continue
		}
		tag, value, found := strings.Cut(part, "=")
		tag = strings.ToLower(strings.Trim(tag, " \t"))
		value = strings.Trim(value, " \t")
		if !found || !tlsCaaTag(tag) || value == "" {
			return "", nil, false
		}
		if _, twice := parameters[tag]; twice {
			return "", nil, false
		}
		parameters[tag] = value
	}
	return issuer, parameters, true
}

// Whether tag is RFC 8659 §4.1.1's: US-ASCII letters and digits. Its bound of 15 is a writer's rule this reader
// does not need, since a longer tag is still no property a CA knows.
func tlsCaaTag(tag string) bool {
	if tag == "" {
		return false
	}
	for index := range len(tag) {
		switch c := tag[index]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		default:
			return false
		}
	}
	return true
}

// Whether name is an issuer domain name: labels of letters, digits and hyphens joined by dots.
func tlsCaaDomainName(name string) bool {
	if name == "" || tlsDnsNameMaxByteCount < len(name) {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || tlsDnsLabelMaxByteCount < len(label) || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range len(label) {
			switch c := label[index]; {
			case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '-':
			default:
				return false
			}
		}
	}
	return true
}

// Reads one CAA RDATA in presentation form: decimal flags, a tag, and a value, quoted with \X and \DDD escapes or one
// bare token. Anything else is ErrTlsCaaRecord.
func ParseTlsCaaRecord(text string) (*TlsCaaRecord, error) {
	rest := strings.TrimLeft(text, " \t")
	flagsText, rest, found := strings.Cut(rest, " ")
	if !found {
		return nil, ErrTlsCaaRecord
	}
	flags, err := strconv.ParseUint(flagsText, 10, 8)
	if err != nil {
		return nil, ErrTlsCaaRecord
	}
	rest = strings.TrimLeft(rest, " \t")
	tag, rest, found := strings.Cut(rest, " ")
	if !found || !tlsCaaTag(tag) {
		return nil, ErrTlsCaaRecord
	}
	rest = strings.Trim(rest, " \t")
	if rest == "" {
		return nil, ErrTlsCaaRecord
	}
	if rest[0] != '"' {
		if strings.ContainsAny(rest, " \t\"\\") {
			return nil, ErrTlsCaaRecord
		}
		return &TlsCaaRecord{Flags: uint8(flags), Tag: tag, Value: rest}, nil
	}
	var value strings.Builder
	index := 1
	for {
		if len(rest) <= index {
			// no closing quote
			return nil, ErrTlsCaaRecord
		}
		c := rest[index]
		if c == '"' {
			index += 1
			break
		}
		if c != '\\' {
			value.WriteByte(c)
			index += 1
			continue
		}
		if len(rest) <= index+1 {
			return nil, ErrTlsCaaRecord
		}
		if '0' <= rest[index+1] && rest[index+1] <= '9' {
			if len(rest) < index+4 {
				return nil, ErrTlsCaaRecord
			}
			octet, err := strconv.ParseUint(rest[index+1:index+4], 10, 8)
			if err != nil {
				return nil, ErrTlsCaaRecord
			}
			value.WriteByte(byte(octet))
			index += 4
			continue
		}
		value.WriteByte(rest[index+1])
		index += 2
	}
	if strings.Trim(rest[index:], " \t") != "" {
		return nil, ErrTlsCaaRecord
	}
	return &TlsCaaRecord{Flags: uint8(flags), Tag: tag, Value: value.String()}, nil
}

// One name a CAA query reached.
type TlsCaaHop struct {
	// The queried name, or an alias's target, lowercase with no final dot.
	Name string
	// The zone Name sits in: the owner of the SOA its authoritative servers answer under.
	Zone string
	// The zone's authoritative servers, by the names its NS RRset gives.
	Nameservers []string
}

// One CAA query's answer, as resolution following aliases gives it.
type TlsCaaAnswer struct {
	// The queried name first, then one hop for each CNAME or DNAME the query followed.
	Hops []*TlsCaaHop
	// The CAA RRset at the last hop, in presentation form. Empty for NODATA and NXDOMAIN.
	Records []string
}

// What a walk asks. Answers a failed lookup (SERVFAIL, a timeout, an alias loop) as an error, which ends the walk
// with no result: a walk never reads an unanswered query as an empty set, since RFC 8659 §3's climb would then pass
// over a pin it never saw. Safe for concurrent use.
type TlsCaaResolver interface {
	// A CAA query for name, a lowercase name with no final dot, following CNAME and DNAME.
	LookupCaa(ctx context.Context, name string) (*TlsCaaAnswer, error)
}

// The walk's limits. DefaultTlsCaaWalkSettings is the only source of a default.
type TlsCaaWalkSettings struct {
	// The hops one answer may hold, the queried name included: past it the answer is unreadable, as resolvers stop
	// following an alias chain long before.
	HopMaxCount int
	// The nameservers one hop may name.
	NameserverMaxCount int
	// The records the effective set may hold.
	RecordMaxCount int
}

func DefaultTlsCaaWalkSettings() *TlsCaaWalkSettings {
	return &TlsCaaWalkSettings{
		HopMaxCount:        16,
		NameserverMaxCount: 16,
		RecordMaxCount:     64,
	}
}

// One query of a walk.
type TlsCaaStep struct {
	// The name queried: the walk's name, then each parent.
	Name   string
	Answer *TlsCaaAnswer
}

// One zone a walk visited.
type TlsCaaZone struct {
	Name        string
	Nameservers []string
}

// One query §12.8's probe repeats at a zone's authoritative servers.
type TlsCaaQuery struct {
	// The name a step queried, or an alias target it reached.
	Name        string
	Zone        string
	Nameservers []string
}

// What TlsCaaWalk found.
type TlsCaaResult struct {
	// The name walked.
	Name string
	// Each query, in order: the name, then each parent until the first non-empty set.
	Steps []*TlsCaaStep
	// RFC 8659 §3's relevant RRset: the first non-empty answer's records, in presentation form. Empty when no name up
	// to the root holds one.
	Effective []string
	// The name whose RRset Effective is: a step's name, or an alias target it reached. "" when Effective is empty.
	EffectiveOwner string
	// Every zone the walk visited, each once, in the order first visited.
	Zones []*TlsCaaZone
	// The first name in a URnetwork zone the walk met: set exactly when it refused with ErrTlsCaaOperatorAlias.
	OperatorName string
}

// The probe's queries: each name each step reached, with its zone's servers, each once, in walk order.
func (self *TlsCaaResult) Queries() []*TlsCaaQuery {
	queries := []*TlsCaaQuery{}
	for _, step := range self.Steps {
		for _, hop := range step.Answer.Hops {
			if slices.ContainsFunc(queries, func(query *TlsCaaQuery) bool { return query.Name == hop.Name }) {
				continue
			}
			queries = append(queries, &TlsCaaQuery{Name: hop.Name, Zone: hop.Zone, Nameservers: slices.Clone(hop.Nameservers)})
		}
	}
	return queries
}

// Whether the effective set lets issuer, a CA's issuer domain, issue a certificate for the walked name, one that is
// no wildcard, under the account accountUri (RFC 8659 §4.2 and §4.3, RFC 8657 §3): no critical property this reader
// does not know, and either no issue property at all, or one naming issuer whose accounturi, if it has one, is
// accountUri. An empty set lets every CA issue. What §13.8's pin is for: a set that also authorizes a URnetwork
// account excludes nothing.
func (self *TlsCaaResult) AuthorizesAccount(issuer string, accountUri string) bool {
	issuer = strings.ToLower(issuer)
	issueSeen := false
	authorized := false
	for _, text := range self.Effective {
		record, err := ParseTlsCaaRecord(text)
		if err != nil {
			// an unreadable record is read as RFC 8659 §4 reads a critical one: no issuance on a doubt
			return false
		}
		switch strings.ToLower(record.Tag) {
		case "issue":
			issueSeen = true
			recordIssuer, parameters, ok := record.IssueValue()
			if !ok || recordIssuer != issuer {
				continue
			}
			if recordAccountUri, pinned := parameters["accounturi"]; pinned && recordAccountUri != accountUri {
				continue
			}
			authorized = true
		case "issuewild", "iodef":
		default:
			if record.Critical() {
				return false
			}
		}
	}
	return !issueSeen || authorized
}

// Whether the effective set holds §12.8's canary property: once it does, the customer's own answers carry a set
// that certs published at a URnetwork name, the mark of an ALIAS that flattens CAA.
func (self *TlsCaaResult) HoldsCanary() bool {
	for _, text := range self.Effective {
		if record, err := ParseTlsCaaRecord(text); err == nil && strings.EqualFold(record.Tag, TlsCaaCanaryTag) {
			return true
		}
	}
	return false
}

// name lowercase with no final dot, false for what is no DNS name: no empty label, no label past 63 bytes, at most
// 253 bytes. Underscores and other bytes a resolver may hand back are kept, since an alias target need not be a host
// name.
func tlsCaaName(name string) (string, bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" || tlsDnsNameMaxByteCount < len(name) {
		return "", false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || tlsDnsLabelMaxByteCount < len(label) {
			return "", false
		}
		for index := range len(label) {
			if c := label[index]; c <= 0x20 || 0x7E < c {
				return "", false
			}
		}
	}
	return name, true
}

// Whether name is zone or a name under it.
func tlsCaaInZone(name string, zone string) bool {
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// RFC 8659 §3's walk for name over resolver, with §12.8's refusal of every name in operatorZones, the zones URnetwork
// controls (each <root> and platform domain). See the file header.
//
// Answers the result and nil when the walk ended: at the first non-empty set, or past the last label with Effective
// empty. Answers the result so far and ErrTlsCaaOperatorAlias when it met an operator name, with OperatorName set.
// A resolver's error ends the walk with that error, and an answer the walk cannot read with ErrTlsCaaWalk: neither
// is a verdict. No operator zones refuses the walk, since then nothing would be refused.
func TlsCaaWalk(ctx context.Context, resolver TlsCaaResolver, name string, operatorZones []string, settings *TlsCaaWalkSettings) (*TlsCaaResult, error) {
	if settings == nil {
		settings = DefaultTlsCaaWalkSettings()
	}
	name, ok := tlsCaaName(name)
	if !ok || resolver == nil || len(operatorZones) == 0 {
		return nil, ErrTlsCaaWalk
	}
	zones := make([]string, 0, len(operatorZones))
	for _, operatorZone := range operatorZones {
		zone, ok := tlsCaaName(operatorZone)
		if !ok {
			return nil, ErrTlsCaaWalk
		}
		zones = append(zones, zone)
	}
	operator := func(name string) bool {
		return slices.ContainsFunc(zones, func(zone string) bool { return tlsCaaInZone(name, zone) })
	}
	result := &TlsCaaResult{Name: name}
	refuse := func(operatorName string) (*TlsCaaResult, error) {
		result.OperatorName = operatorName
		return result, ErrTlsCaaOperatorAlias
	}
	unreadable := func(format string, arguments ...any) (*TlsCaaResult, error) {
		return result, fmt.Errorf("%w: %s", ErrTlsCaaWalk, fmt.Sprintf(format, arguments...))
	}
	for domain := name; domain != ""; {
		if operator(domain) {
			return refuse(domain)
		}
		answer, err := resolver.LookupCaa(ctx, domain)
		if err != nil {
			return result, err
		}
		if answer == nil || len(answer.Hops) == 0 || settings.HopMaxCount < len(answer.Hops) {
			return unreadable("an answer with no hops, or with more than %d", settings.HopMaxCount)
		}
		// an answer in canonical names, so every comparison after is exact
		read := &TlsCaaAnswer{Records: slices.Clone(answer.Records)}
		for index, hop := range answer.Hops {
			if hop == nil {
				return unreadable("an answer with an empty hop")
			}
			hopName, nameOk := tlsCaaName(hop.Name)
			zone, zoneOk := tlsCaaName(hop.Zone)
			if !nameOk || !zoneOk || !tlsCaaInZone(hopName, zone) || (index == 0 && hopName != domain) {
				return unreadable("a hop that is not the queried name or not in its zone")
			}
			if len(hop.Nameservers) == 0 || settings.NameserverMaxCount < len(hop.Nameservers) {
				return unreadable("a zone with no nameservers, or with more than %d", settings.NameserverMaxCount)
			}
			readHop := &TlsCaaHop{Name: hopName, Zone: zone}
			for _, nameserver := range hop.Nameservers {
				nameserverName, ok := tlsCaaName(nameserver)
				if !ok {
					return unreadable("a nameserver that is no name")
				}
				readHop.Nameservers = append(readHop.Nameservers, nameserverName)
			}
			read.Hops = append(read.Hops, readHop)
		}
		result.Steps = append(result.Steps, &TlsCaaStep{Name: domain, Answer: read})
		for _, hop := range read.Hops {
			// an alias into a URnetwork zone, a zone URnetwork serves, or one whose servers are URnetwork's
			if operator(hop.Name) {
				return refuse(hop.Name)
			}
			if operator(hop.Zone) {
				return refuse(hop.Zone)
			}
			for _, nameserver := range hop.Nameservers {
				if operator(nameserver) {
					return refuse(nameserver)
				}
			}
			if !slices.ContainsFunc(result.Zones, func(zone *TlsCaaZone) bool { return zone.Name == hop.Zone }) {
				result.Zones = append(result.Zones, &TlsCaaZone{Name: hop.Zone, Nameservers: slices.Clone(hop.Nameservers)})
			}
		}
		if 0 < len(read.Records) {
			if settings.RecordMaxCount < len(read.Records) {
				return unreadable("a set of more than %d records", settings.RecordMaxCount)
			}
			for _, text := range read.Records {
				if _, err := ParseTlsCaaRecord(text); err != nil {
					return unreadable("a record that is no CAA RDATA")
				}
			}
			result.Effective = read.Records
			result.EffectiveOwner = read.Hops[len(read.Hops)-1].Name
			return result, nil
		}
		// climb from the queried name, never from an alias's target (RFC 8659 §3)
		_, domain, _ = strings.Cut(domain, ".")
	}
	return result, nil
}
