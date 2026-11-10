// CompileAcl's targets, in the forms AclState reads (acl-m2-02-state-readings #2), and the canonical form a document
// rule's rules row is keyed by (plan-ACL-atom-and-rule-ids #3).
//
//	a subject        an atom, or the id a sidecar:, client: or network: selector names outright
//	*                autogroup:network's atom, the token prefix of no segment (every application socket and share/),
//	                 and the wildcard repo; its ip ranges stay on the device
//	sock:<name>      application and share/ names as §9.4's token path under K_sock, a glob as the token prefix of its
//	                 whole literal segments (a first-segment glob none), one target per key while a rotation holds a
//	                 previous key (plan-SOCK-ksock-rotation); tls/ and smtp/ names in public_name, glob kept
//	                 (plan-ACL-small-readings #10); ur/ names are their services' and reserved ones nobody's, so a
//	                 rule naming either refuses
//	ip:<cidr>        nothing: a route rule's targets are its via subjects (plan-BRIDGE-gate-row-prefixes #1)
//	evs:<repo>       the id, or a label's through the labels file, a label glob every label it matches, evs:* the
//	                 wildcard repo, sixteen zero bytes
//	dns:<host>       public_name, glob kept
//	mail:<alias>     mail_send, all a server sees of mail (D-ACL-12)
//
// Every target list is sorted by its targets' deterministic encodings and holds no repeat.
//
// The canonical form is RFC 8785 JCS of one JSON object per rule, with id and note left out, every list sorted, socket
// names in clear and an ip: name as the prefix its hosts entry gives, so an unchanged rule keeps its id across saves
// and K_sock rotations and any change of meaning makes a new one (FS-14). A grant writes allow, app_mode, audience,
// dst, expires (ms), ip, kind "grant", link_spki_sha256 (hex), sock, src and via, each only where set; a request
// writes allow, approver, approvers, dst, evidence (the effective list), expires_default and max_expiry (seconds),
// kind "request", names_harness and src.
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The targets one resource compiles to.
func (self *aclCompiler) targets(resource AclResource) ([]*protocol.AclTarget, error) {
	switch resource.Kind {
	case AclResourceSubject:
		target, err := self.subjectTarget(resource.Subject)
		if err != nil {
			return nil, err
		}
		return []*protocol.AclTarget{target}, nil
	case AclResourceAll:
		return []*protocol.AclTarget{
			{Atom: AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_NETWORK).Bytes()},
			{SocketPrefix: true},
			{RepoId: make([]byte, aclAtomByteCount)},
		}, nil
	case AclResourceSocket:
		return self.socketTargets(resource.Name)
	case AclResourceIp:
		return nil, nil
	case AclResourceRepo:
		return self.repoTargets(resource)
	case AclResourceDns:
		return []*protocol.AclTarget{{PublicName: resource.Name}}, nil
	case AclResourceMail:
		return []*protocol.AclTarget{{MailSend: true}}, nil
	}
	return nil, aclCompileRefusal("a resource of no kind")
}

// A sock: name's targets.
func (self *aclCompiler) socketTargets(name string) ([]*protocol.AclTarget, error) {
	segments := strings.Split(name, "/")
	if strings.Contains(segments[0], "*") {
		// a first-segment glob stays among application sockets and share/ (acl-policy-small-readings #2)
		return []*protocol.AclTarget{{SocketPrefix: true}}, nil
	}
	switch socketFirstSegmentNamespace(segments[0]) {
	case SocketNamespaceTls, SocketNamespaceSmtp:
		return []*protocol.AclTarget{{PublicName: name}}, nil
	case SocketNamespaceApplication, SocketNamespaceShare:
	default:
		return nil, aclCompileRefusal("a socket in a namespace no policy names (§9.4)")
	}
	if len(self.socketKeys) == 0 {
		return nil, aclCompileRefusal("an application socket and no K_sock")
	}
	glob := slices.IndexFunc(segments, func(segment string) bool { return strings.Contains(segment, "*") })
	targets := []*protocol.AclTarget{}
	for _, keys := range self.socketKeys {
		if glob < 0 {
			tokenPath, err := keys.TokenPath(name)
			if err != nil {
				return nil, aclCompileRefusal("a socket name §9.4 refuses")
			}
			targets = append(targets, &protocol.AclTarget{SocketTokens: [][]byte{tokenPath}})
			continue
		}
		tokenPrefix, err := keys.TokenPrefix(strings.Join(segments[:glob], "/"))
		if err != nil {
			return nil, aclCompileRefusal("a socket prefix §9.4 refuses")
		}
		targets = append(targets, &protocol.AclTarget{SocketTokens: [][]byte{tokenPrefix}, SocketPrefix: true})
	}
	return targets, nil
}

// An evs: resource's targets.
func (self *aclCompiler) repoTargets(resource AclResource) ([]*protocol.AclTarget, error) {
	switch {
	case resource.RepoId != (Id{}):
		return []*protocol.AclTarget{{RepoId: resource.RepoId.Bytes()}}, nil
	case resource.Name == "*":
		return []*protocol.AclTarget{{RepoId: make([]byte, aclAtomByteCount)}}, nil
	case !strings.Contains(resource.Name, "*"):
		repoId, found := self.labelRepoIds[resource.Name]
		if !found {
			return nil, aclCompileRefusal("a repo label the labels file does not hold")
		}
		return []*protocol.AclTarget{{RepoId: repoId.Bytes()}}, nil
	}
	targets := []*protocol.AclTarget{}
	for _, label := range self.labels {
		if aclGlobMatches(resource.Name, label) {
			targets = append(targets, &protocol.AclTarget{RepoId: self.labelRepoIds[label].Bytes()})
		}
	}
	return targets, nil
}

// Adds a resource's device-only detail.
func (self *aclCompiler) addLocalResource(resource AclResource, sockets *[]string, aliases *[]string, cidrs *[]netip.Prefix) {
	switch resource.Kind {
	case AclResourceSocket:
		*sockets = append(*sockets, resource.Name)
	case AclResourceMail:
		*aliases = append(*aliases, resource.Name)
	case AclResourceIp:
		*cidrs = append(*cidrs, resource.Cidr)
	case AclResourceAll:
		// * reaches every ip range, exits included (§8.4)
		*cidrs = append(*cidrs, netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"))
	}
}

// Targets sorted by their deterministic encodings, without repeats.
func aclSortTargets(targets []*protocol.AclTarget) []*protocol.AclTarget {
	type keyed struct {
		key    []byte
		target *protocol.AclTarget
	}
	keyedTargets := make([]keyed, 0, len(targets))
	encode := proto.MarshalOptions{Deterministic: true}
	for _, target := range targets {
		key, err := encode.Marshal(target)
		if err != nil {
			// a target of set fields always encodes
			panic(err)
		}
		keyedTargets = append(keyedTargets, keyed{key: key, target: target})
	}
	slices.SortFunc(keyedTargets, func(a keyed, b keyed) int { return bytes.Compare(a.key, b.key) })
	keyedTargets = slices.CompactFunc(keyedTargets, func(a keyed, b keyed) bool { return bytes.Equal(a.key, b.key) })
	sorted := make([]*protocol.AclTarget, 0, len(keyedTargets))
	for _, target := range keyedTargets {
		sorted = append(sorted, target.target)
	}
	return sorted
}

// One rule of a document and the key its rules row takes.
type AclRuleKey struct {
	// "grant" or "request", and the rule's index in its list.
	Kind  string
	Index int
	// SHA-256 of the rule's canonical form.
	CanonicalSha256 [32]byte
}

// Every rule's key, the grants', then the requests', in document order: what a writer looks up or adds a rules row by
// at save, and what compile reads a rule's id by.
func AclPolicyRuleKeys(policy *AclPolicy) ([]AclRuleKey, error) {
	if policy == nil {
		return nil, aclCompileRefusal("no policy")
	}
	keys := []AclRuleKey{}
	for i := range policy.Grants {
		canonical := aclGrantCanonical(&policy.Grants[i])
		keys = append(keys, AclRuleKey{Kind: "grant", Index: i, CanonicalSha256: sha256.Sum256(canonical)})
	}
	for j := range policy.Requests {
		canonical := aclRequestCanonical(policy, &policy.Requests[j])
		keys = append(keys, AclRuleKey{Kind: "request", Index: j, CanonicalSha256: sha256.Sum256(canonical)})
	}
	return keys, nil
}

// A resource's canonical text: §8.4's, an ip: name as the prefix it resolves to.
func aclResourceCanonical(resource AclResource) string {
	if resource.Kind == AclResourceIp {
		return "ip:" + resource.Cidr.String()
	}
	return resource.String()
}

// A port range's canonical text, as §8.4 writes one.
func aclPortRangeCanonical(ports AclPortRange) string {
	prefix := ""
	switch ports.Protocol {
	case aclIpProtocolTcp:
		prefix = "tcp:"
	case aclIpProtocolUdp:
		prefix = "udp:"
	case aclIpProtocolIcmp:
		return "icmp:*"
	}
	switch {
	case ports.First == 0 && ports.Last == 65535:
		return prefix + "*"
	case ports.First == ports.Last:
		return prefix + strconv.FormatUint(uint64(ports.First), 10)
	}
	return prefix + strconv.FormatUint(uint64(ports.First), 10) + "-" + strconv.FormatUint(uint64(ports.Last), 10)
}

// Texts sorted.
func aclSortedTexts[T any](values []T, text func(T) string) []string {
	texts := make([]string, 0, len(values))
	for _, value := range values {
		texts = append(texts, text(value))
	}
	slices.Sort(texts)
	return texts
}

// A grant's canonical form.
func aclGrantCanonical(grant *AclGrant) []byte {
	object := aclJcsObject{}
	object.strings("allow", aclSortedTexts(grant.Allow, aclActionName))
	switch grant.AppMode {
	case protocol.AclAppMode_ACL_APP_MODE_RAW:
		object.string("app_mode", "raw")
	}
	switch grant.Audience {
	case protocol.AclAudience_ACL_AUDIENCE_MEMBERS_DEVICE:
		object.string("audience", "members-device")
	case protocol.AclAudience_ACL_AUDIENCE_LINK:
		object.string("audience", "link")
	case protocol.AclAudience_ACL_AUDIENCE_PUBLIC:
		object.string("audience", "public")
	}
	object.strings("dst", aclSortedTexts(grant.Dst, aclResourceCanonical))
	if !grant.Expires.IsZero() {
		object.integer("expires", grant.Expires.UnixMilli())
	}
	if grant.Ip != nil {
		object.strings("ip", aclSortedTexts(grant.Ip, aclPortRangeCanonical))
	}
	object.string("kind", "grant")
	if grant.LinkSpkiSha256 != nil {
		object.string("link_spki_sha256", hex.EncodeToString(grant.LinkSpkiSha256))
	}
	if grant.Sock != nil {
		object.string("sock", aclResourceCanonical(*grant.Sock))
	}
	object.strings("src", aclSortedTexts(grant.Src, AclSelector.String))
	if grant.Via != nil {
		object.strings("via", aclSortedTexts(grant.Via, AclSelector.String))
	}
	return object.encode()
}

// A requests rule's canonical form: its effective evidence and expiry default too, since the document's defaults change
// what the rule means.
func aclRequestCanonical(policy *AclPolicy, request *AclRequest) []byte {
	evidence := request.Evidence
	if evidence == nil {
		evidence = policy.EvidenceDefault
	}
	object := aclJcsObject{}
	object.strings("allow", aclSortedTexts(request.Allow, aclActionName))
	object.strings("approver", aclSortedTexts(request.Approver, AclSelector.String))
	object.integer("approvers", int64(request.Approvers))
	object.strings("dst", aclSortedTexts(request.Dst, aclResourceCanonical))
	object.strings("evidence", aclSortedTexts(evidence, func(name AclEvidence) string { return string(name) }))
	object.integer("expires_default", int64(policy.ExpiresDefault/time.Second))
	object.string("kind", "request")
	object.integer("max_expiry", int64(request.MaxExpiry/time.Second))
	object.boolean("names_harness", slices.Contains(request.Evidence, AclEvidenceHarness))
	object.strings("src", aclSortedTexts(request.Src, AclSelector.String))
	return object.encode()
}

// One JSON object in RFC 8785's form, its members added in key order: ASCII keys, so byte order is UTF-16 order.
type aclJcsObject struct {
	keys    []string
	members []string
}

// Adds one member. Keys come in order, by construction, so a key out of order is this file's bug.
func (self *aclJcsObject) add(key string, value string) {
	if 0 < len(self.keys) && !(self.keys[len(self.keys)-1] < key) {
		panic(fmt.Sprintf("canonical keys out of order at %q", key))
	}
	self.keys = append(self.keys, key)
	self.members = append(self.members, aclJcsString(key)+":"+value)
}

// A string member.
func (self *aclJcsObject) string(key string, value string) {
	self.add(key, aclJcsString(value))
}

// A member holding a list of strings, in the order given.
func (self *aclJcsObject) strings(key string, values []string) {
	encoded := make([]string, 0, len(values))
	for _, value := range values {
		encoded = append(encoded, aclJcsString(value))
	}
	self.add(key, "["+strings.Join(encoded, ",")+"]")
}

// An integer member, within 2^53 as every value here is, so JCS writes it plainly.
func (self *aclJcsObject) integer(key string, value int64) {
	self.add(key, strconv.FormatInt(value, 10))
}

// A true or false member.
func (self *aclJcsObject) boolean(key string, value bool) {
	self.add(key, strconv.FormatBool(value))
}

// The object's bytes.
func (self *aclJcsObject) encode() []byte {
	return []byte("{" + strings.Join(self.members, ",") + "}")
}

// A JSON string as RFC 8785 serializes one: " and \ escaped, the short escapes for the five control characters that
// have one, \u00xx in lowercase hex for the rest below U+0020, everything else as its UTF-8.
func aclJcsString(value string) string {
	builder := strings.Builder{}
	builder.WriteByte('"')
	for _, c := range []byte(value) {
		switch c {
		case '"':
			builder.WriteString(`\"`)
		case '\\':
			builder.WriteString(`\\`)
		case '\b':
			builder.WriteString(`\b`)
		case '\t':
			builder.WriteString(`\t`)
		case '\n':
			builder.WriteString(`\n`)
		case '\f':
			builder.WriteString(`\f`)
		case '\r':
			builder.WriteString(`\r`)
		default:
			if c < 0x20 {
				fmt.Fprintf(&builder, `\u%04x`, c)
			} else {
				builder.WriteByte(c)
			}
		}
	}
	builder.WriteByte('"')
	return builder.String()
}
