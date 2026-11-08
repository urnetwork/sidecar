// The access policy document (§8.5): one HuJSON file in the config repo, which every sidecar parses
// and each base's writer compiles (D-ACL-1). Deny is the base and grants form a union (D-ACL-2), so
// nothing here orders, merges or evaluates a rule. This turns a document's bytes into a typed value and
// stops: §8.8's validation is ACL-M2-05's and its rows ACL-M2-04's.
//
// A typo must not silently drop a rule, so an unknown key, a key given twice and a value of the wrong
// type are refused everywhere, and keys match exactly. encoding/json does none of that for a struct: it
// keeps the last of two keys, takes "Src" for "src" and passes bad UTF-8, so the document is read token
// by token against the schema here, after a whole-document syntax check.
//
// Decoding is total and bounded. A source past aclPolicySourceMaxByteCount is refused before any work,
// aclStandardizeHujson refuses one nested deeper than the schema goes before encoding/json can recurse
// into it, and the reader holds no generic value, so it builds only what the schema names, a fixed
// multiple of the source.
//
// A refusal names a line, a column and a field path, and never repeats a value (I-13): policy text is
// member-chosen, and a reader's refusal of a bad head may reach a log.
//
// On every leg, the sidecar_http page Worker's included, since every admitted sidecar compiles policy.
// No connect type and no build tag.

package sidecar

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// What ParseAclPolicy refuses wraps this, so a caller can tell a bad document from anything else.
var ErrAclPolicyInvalid = errors.New("invalid acl policy")

// The most source a document may hold, §8.8's bound on what it compiles to, since a head's source and
// rows sit in one config repo. A format value and not a setting: every reader must refuse the same
// heads, or their rows diverge.
const aclPolicySourceMaxByteCount = 4 * 1024 * 1024

// The defaults every reader applies alike (§8.5, §8.6).
const (
	aclExpiresDefault   = 1 * time.Hour
	aclMaxExpiryDefault = 30 * 24 * time.Hour
)

// A SHA-256 pin's length (§13.7).
const aclSpkiSha256ByteCount = 32

// A channel an approval may arrive on (§16.6), as a document writes it. Rows carry
// ApprovalDecision.channel's numbers instead.
type AclEvidence string

const (
	AclEvidenceDevice   AclEvidence = "device"
	AclEvidencePresence AclEvidence = "presence"
	AclEvidenceHarness  AclEvidence = "harness"
)

// One parsed document, in the order it was written, with §8.5's and §8.6's defaults applied. Lists and
// not maps, so a compile that must be a pure function of its input has no map to iterate.
type AclPolicy struct {
	Groups    []AclGroup
	TagOwners []AclTagOwner
	Hosts     []AclHost
	Grants    []AclGrant
	Requests  []AclRequest
	// Nil without an audit block.
	Audit *AclAuditBlock
	Tests []AclPolicyTest
	// How long a requested grant lasts when it names no expires: 1 h unless the document says.
	ExpiresDefault time.Duration
	// The channels a requests rule accepts when it names none: all three unless the document says.
	EvidenceDefault []AclEvidence
}

// One entry of groups.
type AclGroup struct {
	Group AclSelector
	// Each an AclSelectorUser.
	Members []AclSelector
}

// One entry of tagOwners.
type AclTagOwner struct {
	Tag AclSelector
	// Who may apply the tag, which a list may leave to nobody.
	Owners []AclSelector
}

// One entry of hosts: a name for a range, which an ip: resource resolves through.
type AclHost struct {
	Name string
	// A single address reads as its /32 or /128.
	Cidr netip.Prefix
}

// One standing grant (§8.5).
type AclGrant struct {
	// Member-chosen text, not a root Id. It stays on devices (§8.7).
	Id    string
	Src   []AclSelector
	Dst   []AclResource
	Allow []protocol.AclAction
	// The ports of a subject or ip dst (§8.4). Nil for any.
	Ip []AclPortRange
	// The subjects an ip dst routes through (§8.4). Nil for none.
	Via []AclSelector
	// The zero time for none. Always after the epoch, since rows read 0 as no expiry.
	Expires time.Time
	// The socket a publish binds (§8.4), an AclResourceSocket. Nil for none.
	Sock *AclResource
	// A publish's. Zero, as in protocol, is members, whether written or not, so the parse never gives
	// AclAudience_ACL_AUDIENCE_MEMBERS.
	Audience protocol.AclAudience
	// A publish's. Zero, as in protocol, is http, whether written or not, so the parse never gives
	// AclAppMode_ACL_APP_MODE_HTTP.
	AppMode protocol.AclAppMode
	// The 32 bytes a raw link's grant pins (§13.7). Nil for none.
	LinkSpkiSha256 []byte
	// Member-chosen text for people. It stays on devices.
	Note string
}

// One requests rule (§8.5, §8.6): what a subject may ask for, and who answers. Unlike a grant it holds
// no ip, via, sock, audience, app_mode, link_spki_sha256 or expires, and those keys are refused here:
// AclRequestRule has no place for them, so a rule's narrowing would reach no row and a gate would
// honor the wider rule. They are the filed request's own (§13.10; question
// acl-policy-request-rule-fields).
type AclRequest struct {
	// As a grant's.
	Id    string
	Src   []AclSelector
	Dst   []AclResource
	Allow []protocol.AclAction
	// Who approves: the requester's owner or sponsor, autogroup:self, unless the rule says.
	Approver []AclSelector
	// How many of them must: 1 unless the rule says. Never 0.
	Approvers uint32
	// The longest a grant under this rule lasts: 30 days unless the rule says.
	MaxExpiry time.Duration
	// As the rule wrote it, nil if it did not, since a harness decision in a tainted run counts only
	// where the rule itself names harness (owner decision 142). AclPolicy.EvidenceDefault fills in for
	// a nil one.
	Evidence []AclEvidence
	// As a grant's.
	Note string
}

// The audit block (§8.5; owner decision 63), which counts only under a k-of-n AuditOptIn.
type AclAuditBlock struct {
	// An AclSelectorTag.
	Reader AclSelector
	// What its kind: entries name.
	RepoKinds []protocol.RepoKind
	// What its evs: entries name, each an exact repo and never a glob.
	Repos []AclResource
}

// One entry of tests (§8.5), which a writer's device runs before signing (D-ACL-9).
type AclPolicyTest struct {
	Src    AclSelector
	Accept []AclPolicyCheck
	Deny   []AclPolicyCheck
}

// One entry of a test's accept or deny: <resource>#<action>, as §8.5 and §15.10 write them, and
// optionally :<ports> after the action for a subject or ip resource.
type AclPolicyCheck struct {
	Resource AclResource
	Action   protocol.AclAction
	// Nil for no port.
	Ports *AclPortRange
}

// A refusal that names no value, which the reader then places.
func aclPolicyRefusal(reason string) error {
	return fmt.Errorf("%w: %s", ErrAclPolicyInvalid, reason)
}

// Turns one document into its typed form. nil and an error wrapping ErrAclPolicyInvalid for anything
// it refuses. source stays as it was.
func ParseAclPolicy(source []byte) (*AclPolicy, error) {
	if aclPolicySourceMaxByteCount < len(source) {
		return nil, aclPolicyRefusal("the source is too large")
	}
	standard, err := aclStandardizeHujson(source)
	if err != nil {
		return nil, err
	}
	if !json.Valid(standard) {
		// only to learn where: Valid's scan refused it, so this one never gets as far as a copy
		offset := 0
		var syntaxError *json.SyntaxError
		if errors.As(json.Unmarshal(standard, &json.RawMessage{}), &syntaxError) {
			offset = int(syntaxError.Offset)
		}
		line, column := aclSourcePosition(source, offset)
		return nil, fmt.Errorf("line %d, column %d: %w", line, column, aclPolicyRefusal("not HuJSON"))
	}
	decoder := json.NewDecoder(bytes.NewReader(standard))
	decoder.UseNumber()
	reader := &aclPolicyReader{source: source, decoder: decoder}
	policy := &AclPolicy{}
	if err := reader.readPolicy(policy); err != nil {
		return nil, err
	}
	if err := policy.resolveHosts(); err != nil {
		return nil, err
	}
	if policy.ExpiresDefault == 0 {
		policy.ExpiresDefault = aclExpiresDefault
	}
	if policy.EvidenceDefault == nil {
		policy.EvidenceDefault = []AclEvidence{AclEvidenceDevice, AclEvidencePresence, AclEvidenceHarness}
	}
	return policy, nil
}

// Fills in each ip: resource named by a hosts entry, which may stand after the rules that use it.
func (self *AclPolicy) resolveHosts() error {
	hostCidrs := map[string]netip.Prefix{}
	for _, host := range self.Hosts {
		hostCidrs[host.Name] = host.Cidr
	}
	resolved := func(resource *AclResource) bool {
		if resource.Kind != AclResourceIp || resource.Name == "" {
			return true
		}
		cidr, found := hostCidrs[resource.Name]
		resource.Cidr = cidr
		return found
	}
	refuse := func(format string, i int, j int) error {
		return fmt.Errorf("%s: %w", fmt.Sprintf(format, i, j), aclPolicyRefusal("an ip: name that hosts does not hold"))
	}
	for i := range self.Grants {
		for j := range self.Grants[i].Dst {
			if !resolved(&self.Grants[i].Dst[j]) {
				return refuse("grants[%d].dst[%d]", i, j)
			}
		}
	}
	for i := range self.Requests {
		for j := range self.Requests[i].Dst {
			if !resolved(&self.Requests[i].Dst[j]) {
				return refuse("requests[%d].dst[%d]", i, j)
			}
		}
	}
	for i := range self.Tests {
		for j := range self.Tests[i].Accept {
			if !resolved(&self.Tests[i].Accept[j].Resource) {
				return refuse("tests[%d].accept[%d]", i, j)
			}
		}
		for j := range self.Tests[i].Deny {
			if !resolved(&self.Tests[i].Deny[j].Resource) {
				return refuse("tests[%d].deny[%d]", i, j)
			}
		}
	}
	return nil
}

// One step of the path to the value being read: a schema's key, or an index. Member-chosen keys
// stand here as their index, so a path is safe to show.
type aclPolicyFrame struct {
	field string
	index int
}

// Reads a document that json.Valid passed, so each token it asks for exists and only the schema can
// refuse it. Each read method leaves the decoder after what it read.
type aclPolicyReader struct {
	source  []byte
	decoder *json.Decoder
	frames  []aclPolicyFrame
}

// A refusal at the current place: where in the source, and which field.
func (self *aclPolicyReader) refuse(reason error) error {
	line, column := aclSourcePosition(self.source, int(self.decoder.InputOffset()))
	path := strings.Builder{}
	for _, frame := range self.frames {
		if frame.field == "" {
			fmt.Fprintf(&path, "[%d]", frame.index)
			continue
		}
		if path.Len() != 0 {
			path.WriteByte('.')
		}
		path.WriteString(frame.field)
	}
	if path.Len() == 0 {
		return fmt.Errorf("line %d, column %d: %w", line, column, reason)
	}
	return fmt.Errorf("line %d, column %d, %s: %w", line, column, path.String(), reason)
}

// The next token. Only input that broke json.Valid's promise could fail here.
func (self *aclPolicyReader) readToken() (json.Token, error) {
	token, err := self.decoder.Token()
	if err != nil {
		return nil, self.refuse(aclPolicyRefusal("not HuJSON"))
	}
	return token, nil
}

// Takes the delimiter that opens the value ahead, or refuses a value of any other type.
func (self *aclPolicyReader) readOpening(opening json.Delim, reason string) error {
	token, err := self.readToken()
	if err != nil {
		return err
	}
	if token != opening {
		return self.refuse(aclPolicyRefusal(reason))
	}
	return nil
}

// Walks an object, handing read each key once with the decoder on that key's value.
func (self *aclPolicyReader) readObject(read func(key string) error) error {
	if err := self.readOpening('{', "not an object"); err != nil {
		return err
	}
	seenKeys := map[string]bool{}
	for self.decoder.More() {
		token, err := self.readToken()
		if err != nil {
			return err
		}
		key, isKey := token.(string)
		if !isKey {
			return self.refuse(aclPolicyRefusal("not HuJSON"))
		}
		if seenKeys[key] {
			return self.refuse(aclPolicyRefusal("a key given twice"))
		}
		seenKeys[key] = true
		if err := read(key); err != nil {
			return err
		}
	}
	_, err := self.readToken()
	return err
}

// Walks an object of schema keys. fields answers a key with the read for its value, or nil for a key
// the schema does not have.
func (self *aclPolicyReader) readFields(fields func(key string) func() error) error {
	return self.readObject(func(key string) error {
		read := fields(key)
		if read == nil {
			return self.refuse(aclPolicyRefusal("an unknown key"))
		}
		self.frames = append(self.frames, aclPolicyFrame{field: key})
		err := read()
		self.frames = self.frames[:len(self.frames)-1]
		return err
	})
}

// Walks an object of member-chosen keys, naming each by its index.
func (self *aclPolicyReader) readEntries(read func(key string) error) error {
	index := 0
	return self.readObject(func(key string) error {
		self.frames = append(self.frames, aclPolicyFrame{index: index})
		err := read(key)
		self.frames = self.frames[:len(self.frames)-1]
		index += 1
		return err
	})
}

// Walks an array.
func (self *aclPolicyReader) readArray(read func() error) error {
	if err := self.readOpening('[', "not a list"); err != nil {
		return err
	}
	for index := 0; self.decoder.More(); index += 1 {
		self.frames = append(self.frames, aclPolicyFrame{index: index})
		err := read()
		self.frames = self.frames[:len(self.frames)-1]
		if err != nil {
			return err
		}
	}
	_, err := self.readToken()
	return err
}

// A string, or a refusal of any other type.
func (self *aclPolicyReader) readString() (string, error) {
	token, err := self.readToken()
	if err != nil {
		return "", err
	}
	text, isString := token.(string)
	if !isString {
		return "", self.refuse(aclPolicyRefusal("not a string"))
	}
	return text, nil
}

// A string through parse, whose refusal lands here.
func aclPolicyRead[T any](reader *aclPolicyReader, parse func(text string) (T, error)) (T, error) {
	var value T
	text, err := reader.readString()
	if err != nil {
		return value, err
	}
	if value, err = parse(text); err != nil {
		return value, reader.refuse(err)
	}
	return value, nil
}

// A list of strings through parse, which may be empty only where the document can mean that.
func aclPolicyReadList[T any](reader *aclPolicyReader, parse func(text string) (T, error), emptyOk bool) ([]T, error) {
	values := []T{}
	err := reader.readArray(func() error {
		value, err := aclPolicyRead(reader, parse)
		if err != nil {
			return err
		}
		values = append(values, value)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(values) == 0 && !emptyOk {
		// an empty approver or evidence must not read as the default, nor an empty ip as any port
		return nil, reader.refuse(aclPolicyRefusal("an empty list"))
	}
	return values, nil
}

// A list of selectors for a position, never empty.
func (self *aclPolicyReader) readSelectors(position aclPosition) ([]AclSelector, error) {
	return aclPolicyReadList(self, func(text string) (AclSelector, error) {
		return parseAclSelector(text, position)
	}, false)
}

// The document, at the top level.
func (self *aclPolicyReader) readPolicy(policy *AclPolicy) error {
	return self.readFields(func(key string) func() error {
		switch key {
		case "groups":
			return func() (err error) {
				policy.Groups, err = self.readGroups()
				return err
			}
		case "tagOwners":
			return func() (err error) {
				policy.TagOwners, err = self.readTagOwners()
				return err
			}
		case "hosts":
			return func() (err error) {
				policy.Hosts, err = self.readHosts()
				return err
			}
		case "grants":
			return func() error {
				policy.Grants = []AclGrant{}
				return self.readArray(func() error {
					grant, err := self.readGrant()
					policy.Grants = append(policy.Grants, grant)
					return err
				})
			}
		case "requests":
			return func() error {
				policy.Requests = []AclRequest{}
				return self.readArray(func() error {
					request, err := self.readRequest()
					policy.Requests = append(policy.Requests, request)
					return err
				})
			}
		case "audit":
			return func() (err error) {
				policy.Audit, err = self.readAudit()
				return err
			}
		case "tests":
			return func() error {
				policy.Tests = []AclPolicyTest{}
				return self.readArray(func() error {
					test, err := self.readTest()
					policy.Tests = append(policy.Tests, test)
					return err
				})
			}
		case "expiresDefault":
			return func() (err error) {
				policy.ExpiresDefault, err = aclPolicyRead(self, parseAclDuration)
				return err
			}
		case "evidenceDefault":
			return func() (err error) {
				policy.EvidenceDefault, err = aclPolicyReadList(self, parseAclEvidence, false)
				return err
			}
		}
		return nil
	})
}

// groups: group:<name> to its members, which a group may hold none of.
func (self *aclPolicyReader) readGroups() ([]AclGroup, error) {
	groups := []AclGroup{}
	err := self.readEntries(func(key string) error {
		group, err := parseAclSelector(key, aclPositionSrc)
		if err == nil && group.Kind != AclSelectorGroup {
			err = aclPolicyRefusal("a groups key that is not group:<name>")
		}
		if err != nil {
			return self.refuse(err)
		}
		members, err := aclPolicyReadList(self, func(text string) (AclSelector, error) {
			return parseAclSelector(text, aclPositionGroupMember)
		}, true)
		groups = append(groups, AclGroup{Group: group, Members: members})
		return err
	})
	return groups, err
}

// tagOwners: tag:<name> to who may apply it.
func (self *aclPolicyReader) readTagOwners() ([]AclTagOwner, error) {
	tagOwners := []AclTagOwner{}
	err := self.readEntries(func(key string) error {
		tag, err := parseAclSelector(key, aclPositionSrc)
		if err == nil && tag.Kind != AclSelectorTag {
			err = aclPolicyRefusal("a tagOwners key that is not tag:<name>")
		}
		if err != nil {
			return self.refuse(err)
		}
		owners, err := aclPolicyReadList(self, func(text string) (AclSelector, error) {
			return parseAclSelector(text, aclPositionTagOwner)
		}, true)
		tagOwners = append(tagOwners, AclTagOwner{Tag: tag, Owners: owners})
		return err
	})
	return tagOwners, err
}

// hosts: a name to a range or address.
func (self *aclPolicyReader) readHosts() ([]AclHost, error) {
	hosts := []AclHost{}
	err := self.readEntries(func(key string) error {
		if !aclIsDnsLabel(key, false) {
			return self.refuse(aclPolicyRefusal("not a hosts name"))
		}
		cidr, err := aclPolicyRead(self, func(text string) (netip.Prefix, error) {
			if strings.Contains(text, "/") {
				return parseAclCidr(text)
			}
			address, err := netip.ParseAddr(text)
			if err != nil || address.Is4In6() || address.Zone() != "" {
				return netip.Prefix{}, aclPolicyRefusal("not an address or cidr")
			}
			return netip.PrefixFrom(address, address.BitLen()), nil
		})
		hosts = append(hosts, AclHost{Name: key, Cidr: cidr})
		return err
	})
	return hosts, err
}

// What a grant and a requests rule share, once read.
type aclPolicyRule struct {
	id    string
	src   []AclSelector
	dst   []AclResource
	allow []protocol.AclAction
	note  string
}

// The read for a key both rule shapes share, or nil for any other.
func (self *aclPolicyReader) readRuleField(key string, rule *aclPolicyRule) func() error {
	switch key {
	case "id":
		return func() (err error) {
			rule.id, err = self.readString()
			return err
		}
	case "src":
		return func() (err error) {
			rule.src, err = self.readSelectors(aclPositionSrc)
			return err
		}
	case "dst":
		return func() (err error) {
			rule.dst, err = aclPolicyReadList(self, parseAclResource, false)
			return err
		}
	case "allow":
		// each action once and in protocol's order, with * as every action (§8.5's implicit document). A
		// rule's actions need not all apply to each dst: §8.5's own rules list dial beside evs:*, and a
		// pair that means nothing compiles to nothing.
		return func() error {
			rule.allow = []protocol.AclAction{}
			add := func(action protocol.AclAction) {
				if !slices.Contains(rule.allow, action) {
					rule.allow = append(rule.allow, action)
				}
			}
			err := self.readArray(func() error {
				text, err := self.readString()
				if err != nil {
					return err
				}
				if text == "*" {
					for _, action := range aclNameActions {
						add(action)
					}
					return nil
				}
				action, err := parseAclAction(text)
				if err != nil {
					return self.refuse(err)
				}
				add(action)
				return nil
			})
			if err != nil {
				return err
			}
			if len(rule.allow) == 0 {
				return self.refuse(aclPolicyRefusal("an empty list"))
			}
			slices.Sort(rule.allow)
			return nil
		}
	case "note":
		return func() (err error) {
			rule.note, err = self.readString()
			return err
		}
	}
	return nil
}

// Refuses a rule without what makes it one: a rule granting nothing is a typo and not a choice.
func (self *aclPolicyReader) checkRule(rule *aclPolicyRule) error {
	switch {
	case rule.src == nil:
		return self.refuse(aclPolicyRefusal("a rule with no src"))
	case rule.dst == nil:
		return self.refuse(aclPolicyRefusal("a rule with no dst"))
	case rule.allow == nil:
		return self.refuse(aclPolicyRefusal("a rule with no allow"))
	}
	return nil
}

// One entry of grants.
func (self *aclPolicyReader) readGrant() (AclGrant, error) {
	grant := AclGrant{}
	rule := aclPolicyRule{}
	err := self.readFields(func(key string) func() error {
		if read := self.readRuleField(key, &rule); read != nil {
			return read
		}
		switch key {
		case "ip":
			return func() (err error) {
				grant.Ip, err = aclPolicyReadList(self, parseAclPortRange, false)
				return err
			}
		case "via":
			return func() (err error) {
				grant.Via, err = self.readSelectors(aclPositionVia)
				return err
			}
		case "expires":
			// an RFC 3339 time after the epoch: one at or before it would reach rows as 0, which reads as
			// no expiry, so a grant meant to be over would stand forever
			return func() (err error) {
				grant.Expires, err = aclPolicyRead(self, func(text string) (time.Time, error) {
					expires, err := time.Parse(time.RFC3339, text)
					if err != nil || expires.UnixMilli() <= 0 {
						return time.Time{}, aclPolicyRefusal("not an RFC 3339 time after the epoch")
					}
					return expires.UTC(), nil
				})
				return err
			}
		case "sock":
			// a socket, written as a dst entry is
			return func() error {
				sock, err := aclPolicyRead(self, func(text string) (AclResource, error) {
					resource, err := parseAclResource(text)
					if err == nil && resource.Kind != AclResourceSocket {
						err = aclPolicyRefusal("not a sock: resource")
					}
					return resource, err
				})
				grant.Sock = &sock
				return err
			}
		case "audience":
			// members, the default, reads as zero whether written or left out, as http does below: every
			// default here reads the same either way, so writing one out changes no value
			return func() (err error) {
				grant.Audience, err = aclPolicyRead(self, func(text string) (protocol.AclAudience, error) {
					switch text {
					case "members":
						return protocol.AclAudience_ACL_AUDIENCE_UNSPECIFIED, nil
					case "members-device":
						return protocol.AclAudience_ACL_AUDIENCE_MEMBERS_DEVICE, nil
					case "link":
						return protocol.AclAudience_ACL_AUDIENCE_LINK, nil
					case "public":
						return protocol.AclAudience_ACL_AUDIENCE_PUBLIC, nil
					}
					return 0, aclPolicyRefusal("an unknown audience")
				})
				return err
			}
		case "app_mode":
			return func() (err error) {
				grant.AppMode, err = aclPolicyRead(self, func(text string) (protocol.AclAppMode, error) {
					switch text {
					case "http":
						return protocol.AclAppMode_ACL_APP_MODE_UNSPECIFIED, nil
					case "raw":
						return protocol.AclAppMode_ACL_APP_MODE_RAW, nil
					}
					return 0, aclPolicyRefusal("an unknown app_mode")
				})
				return err
			}
		case "link_spki_sha256":
			// lowercase hex: one spelling of a pin
			return func() (err error) {
				grant.LinkSpkiSha256, err = aclPolicyRead(self, func(text string) ([]byte, error) {
					pin, err := hex.DecodeString(text)
					if err != nil || len(pin) != aclSpkiSha256ByteCount || hex.EncodeToString(pin) != text {
						return nil, aclPolicyRefusal("not a lowercase hex SHA-256")
					}
					return pin, nil
				})
				return err
			}
		}
		return nil
	})
	if err != nil {
		return AclGrant{}, err
	}
	if err := self.checkRule(&rule); err != nil {
		return AclGrant{}, err
	}
	grant.Id, grant.Src, grant.Dst, grant.Allow, grant.Note = rule.id, rule.src, rule.dst, rule.allow, rule.note
	return grant, nil
}

// One entry of requests.
func (self *aclPolicyReader) readRequest() (AclRequest, error) {
	request := AclRequest{}
	rule := aclPolicyRule{}
	err := self.readFields(func(key string) func() error {
		if read := self.readRuleField(key, &rule); read != nil {
			return read
		}
		switch key {
		case "approver":
			return func() (err error) {
				request.Approver, err = self.readSelectors(aclPositionApprover)
				return err
			}
		case "approvers":
			// a whole count, since a rule needing no approver would be no request at all. JSON's other
			// spellings of a number, 1.0 and 1e0, are refused: a count has one.
			return func() error {
				token, err := self.readToken()
				if err != nil {
					return err
				}
				number, isNumber := token.(json.Number)
				if !isNumber {
					return self.refuse(aclPolicyRefusal("not a count"))
				}
				count, err := strconv.ParseUint(string(number), 10, 32)
				if err != nil || count == 0 {
					return self.refuse(aclPolicyRefusal("not a count"))
				}
				request.Approvers = uint32(count)
				return nil
			}
		case "maxExpiry":
			return func() (err error) {
				request.MaxExpiry, err = aclPolicyRead(self, parseAclDuration)
				return err
			}
		case "evidence":
			return func() (err error) {
				request.Evidence, err = aclPolicyReadList(self, parseAclEvidence, false)
				return err
			}
		}
		return nil
	})
	if err != nil {
		return AclRequest{}, err
	}
	if err := self.checkRule(&rule); err != nil {
		return AclRequest{}, err
	}
	request.Id, request.Src, request.Dst, request.Allow, request.Note = rule.id, rule.src, rule.dst, rule.allow, rule.note
	if request.Approver == nil {
		request.Approver = []AclSelector{{
			Kind:      AclSelectorAutogroup,
			Autogroup: protocol.AclAutogroup_ACL_AUTOGROUP_SELF,
		}}
	}
	if request.Approvers == 0 {
		request.Approvers = 1
	}
	if request.MaxExpiry == 0 {
		request.MaxExpiry = aclMaxExpiryDefault
	}
	return request, nil
}

// audit: one reader and what it reads.
func (self *aclPolicyReader) readAudit() (*AclAuditBlock, error) {
	audit := &AclAuditBlock{}
	hasReader := false
	err := self.readFields(func(key string) func() error {
		switch key {
		case "reader":
			return func() (err error) {
				hasReader = true
				audit.Reader, err = aclPolicyRead(self, func(text string) (AclSelector, error) {
					return parseAclSelector(text, aclPositionAuditReader)
				})
				return err
			}
		case "repos":
			// kind:<kind>, or evs:<repo> naming exactly one
			return func() error {
				return self.readArray(func() error {
					text, err := self.readString()
					if err != nil {
						return err
					}
					if name, isKind := strings.CutPrefix(text, "kind:"); isKind {
						kind, known := aclNameRepoKinds[name]
						if !known {
							return self.refuse(aclPolicyRefusal("an unknown repo kind"))
						}
						audit.RepoKinds = append(audit.RepoKinds, kind)
						return nil
					}
					repo, err := parseAclResource(text)
					if err != nil {
						return self.refuse(err)
					}
					if repo.Kind != AclResourceRepo || strings.Contains(repo.Name, "*") {
						return self.refuse(aclPolicyRefusal("not a repo kind or an exact repo"))
					}
					audit.Repos = append(audit.Repos, repo)
					return nil
				})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !hasReader {
		return nil, self.refuse(aclPolicyRefusal("an audit block with no reader"))
	}
	if len(audit.RepoKinds) == 0 && len(audit.Repos) == 0 {
		return nil, self.refuse(aclPolicyRefusal("an audit block with no repos"))
	}
	return audit, nil
}

// One entry of tests.
func (self *aclPolicyReader) readTest() (AclPolicyTest, error) {
	test := AclPolicyTest{}
	hasSrc := false
	err := self.readFields(func(key string) func() error {
		switch key {
		case "src":
			return func() (err error) {
				hasSrc = true
				test.Src, err = aclPolicyRead(self, func(text string) (AclSelector, error) {
					return parseAclSelector(text, aclPositionTestSrc)
				})
				return err
			}
		case "accept":
			return func() (err error) {
				test.Accept, err = aclPolicyReadList(self, parseAclPolicyCheck, false)
				return err
			}
		case "deny":
			return func() (err error) {
				test.Deny, err = aclPolicyReadList(self, parseAclPolicyCheck, false)
				return err
			}
		}
		return nil
	})
	if err != nil {
		return AclPolicyTest{}, err
	}
	if !hasSrc {
		return AclPolicyTest{}, self.refuse(aclPolicyRefusal("a test with no src"))
	}
	if test.Accept == nil && test.Deny == nil {
		// a test that checks nothing would read as passing
		return AclPolicyTest{}, self.refuse(aclPolicyRefusal("a test with no accept or deny"))
	}
	return test, nil
}

// §8.4's actions by name. protocol.AclAction numbers them for the rows.
var aclNameActions = map[string]protocol.AclAction{
	"dial":    protocol.AclAction_ACL_ACTION_DIAL,
	"listen":  protocol.AclAction_ACL_ACTION_LISTEN,
	"route":   protocol.AclAction_ACL_ACTION_ROUTE,
	"read":    protocol.AclAction_ACL_ACTION_READ,
	"write":   protocol.AclAction_ACL_ACTION_WRITE,
	"admin":   protocol.AclAction_ACL_ACTION_ADMIN,
	"deposit": protocol.AclAction_ACL_ACTION_DEPOSIT,
	"publish": protocol.AclAction_ACL_ACTION_PUBLISH,
	"send":    protocol.AclAction_ACL_ACTION_SEND,
}

// §11.12's kinds by name, as §8.5's audit block writes them.
var aclNameRepoKinds = map[string]protocol.RepoKind{
	"general":     protocol.RepoKind_REPO_KIND_GENERAL,
	"record":      protocol.RepoKind_REPO_KIND_RECORD,
	"config":      protocol.RepoKind_REPO_KIND_CONFIG,
	"directory":   protocol.RepoKind_REPO_KIND_DIRECTORY,
	"team_record": protocol.RepoKind_REPO_KIND_TEAM_RECORD,
	"mailcfg":     protocol.RepoKind_REPO_KIND_MAILCFG,
	"vault":       protocol.RepoKind_REPO_KIND_VAULT,
	"mailbox":     protocol.RepoKind_REPO_KIND_MAILBOX,
	"secret":      protocol.RepoKind_REPO_KIND_SECRET,
}

// One action's name, which §8.5's allow and a check's #action both write.
func parseAclAction(text string) (protocol.AclAction, error) {
	action, known := aclNameActions[text]
	if !known {
		return 0, aclPolicyRefusal("an unknown action")
	}
	return action, nil
}

// One channel's name.
func parseAclEvidence(text string) (AclEvidence, error) {
	switch evidence := AclEvidence(text); evidence {
	case AclEvidenceDevice, AclEvidencePresence, AclEvidenceHarness:
		return evidence, nil
	}
	return "", aclPolicyRefusal("an unknown evidence channel")
}

// expiresDefault and maxExpiry: a positive count of minutes, hours or days, as §8.5 writes 24h and 7d.
func parseAclDuration(text string) (time.Duration, error) {
	if len(text) < 2 || text[0] == '0' {
		return 0, aclPolicyRefusal("not a duration")
	}
	var unit time.Duration
	switch text[len(text)-1] {
	case 'm':
		unit = time.Minute
	case 'h':
		unit = time.Hour
	case 'd':
		unit = 24 * time.Hour
	default:
		return 0, aclPolicyRefusal("not a duration")
	}
	count, err := strconv.ParseUint(text[:len(text)-1], 10, 63)
	if err != nil || uint64(math.MaxInt64)/uint64(unit) < count {
		return 0, aclPolicyRefusal("not a duration")
	}
	return time.Duration(count) * unit, nil
}

// One test check: <resource>#<action>, then :<ports> for a subject or ip resource. A check names one
// action, so * is no action here.
func parseAclPolicyCheck(text string) (AclPolicyCheck, error) {
	separator := strings.LastIndexByte(text, '#')
	if separator < 0 {
		return AclPolicyCheck{}, aclPolicyRefusal("no #action")
	}
	resource, err := parseAclResource(text[:separator])
	if err != nil {
		return AclPolicyCheck{}, err
	}
	actionText, portsText, hasPorts := strings.Cut(text[separator+1:], ":")
	action, err := parseAclAction(actionText)
	if err != nil {
		return AclPolicyCheck{}, err
	}
	check := AclPolicyCheck{Resource: resource, Action: action}
	if hasPorts {
		if resource.Kind != AclResourceSubject && resource.Kind != AclResourceIp && resource.Kind != AclResourceAll {
			return AclPolicyCheck{}, aclPolicyRefusal("ports on a resource that has none")
		}
		ports, err := parseAclPortRange(portsText)
		if err != nil {
			return AclPolicyCheck{}, err
		}
		check.Ports = &ports
	}
	return check, nil
}
