//go:build !ios_extension && !sidecar_http

// AgentMessage v1 (DESIGN-COMPUTE §20.7, R-SKILL-4, D-SKILL-12, R2-05; SKILL-M11-04): one message of a thread, UTF-8
// JSON at inbox/<thread>/<id>.json in an agent repo, the agents repo or the Team inbox, §20.7's fields in its order:
//
//	{"v": 1, "id": "<32 hex>", "thread": "<32 hex>", "seq": n,
//	 "from": {"member", "name", "agent_id", "sidecar_id", "repo"} | {"member", "person": true} | {"support": "urnetwork"},
//	 "to": {"member", "name", "repo"} | "*", "kind": "message|reply|ack|close|support",
//	 "subject": "<= 120 chars", "body": "markdown <= 32 KiB", "refs": [{"repo", "path", "version"}],
//	 "reply_to": {"member", "name", "repo"}, "effect": "<hex>", "created": "<RFC 3339, UTC>",
//	 "support": {"product", "entry", "seq", "type", "status", "fixed_in", "final"}}
//
//	ids       a message's id names its file, fixed when it is composed and kept across retries: for a kind-24 send the
//	          first 16 bytes of SHA-256("urnetwork-sidecar-v1/agent-message" || 0x00 || k), k the use's effect key
//	          (AgentMessageIdForEffect); for a Harness run's send k is the run id || the tool call's id
//	          (AgentMessageIdForCall), which a resumed run repeats with the call; a person's or an MCP caller's 16 random
//	          bytes drawn at composition. A thread's id is 16 random bytes; a support notice's thread and id derive
//	          from its product, entry and seq, so every device writes the one create-only path (§28.9)
//	order     seq orders a thread for display, equal seqs by id, so every reader shows one order
//	from      the writer's word: a reader trusts the push's provenance and its signer's admission, never from
//	          (agents_trust.go)
//	support   a notice carries the enumerated fields alone, no subject, body or refs (§28.9, CO-45)
//	read      v must be 1; fields a later release adds are passed over; a field out of its grammar or bound refuses the
//	          message, ErrAgentMessageInvalid, which names the field and never its value
//
// On the compute legs. Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// The message format's version (§20.7).
const AgentMessageVersion = 1

// The domain of a message id derived from a key, and of a support notice's thread and id (§20.7, §28.9).
const (
	agentMessageIdDomain       = "urnetwork-sidecar-v1/agent-message"
	agentSupportThreadIdDomain = "urnetwork-sidecar-v1/agent-support-thread"
	agentSupportNoticeIdDomain = "urnetwork-sidecar-v1/agent-support-notice"
)

// The inbox directory of an agent, agents and Team inbox repo, and a message file's suffix (§20.4's layout).
const (
	agentInboxDirectory     = "inbox"
	agentMessageFileSuffix  = ".json"
	agentMessageToAll       = "*"
	AgentMessageSupportFrom = "urnetwork"
)

// What a message is (§20.7).
type AgentMessageKind string

const (
	// Opens a thread.
	AgentMessageKindMessage AgentMessageKind = "message"
	// Continues one, any number of times (R-SKILL-9).
	AgentMessageKindReply AgentMessageKind = "reply"
	AgentMessageKindAck   AgentMessageKind = "ack"
	// Ends one: the Harness stops queuing it.
	AgentMessageKindClose AgentMessageKind = "close"
	// A support notice (§28.9), from {"support":"urnetwork"}.
	AgentMessageKindSupport AgentMessageKind = "support"
)

// Whether kind is one of §20.7's.
func (self AgentMessageKind) valid() bool {
	switch self {
	case AgentMessageKindMessage, AgentMessageKindReply, AgentMessageKindAck, AgentMessageKindClose, AgentMessageKindSupport:
		return true
	}
	return false
}

// A message that does not read: its version, a field out of its grammar or bound, or bytes that are no object.
var ErrAgentMessageInvalid = errors.New("agent message invalid")

// A message's id: 16 bytes, its file's name in hex.
type AgentMessageId [16]byte

// A thread's id: 16 random bytes, its directory's name in hex.
type AgentThreadId [16]byte

// 32 lowercase hex digits.
func (self AgentMessageId) String() string {
	return hex.EncodeToString(self[:])
}

// 32 lowercase hex digits.
func (self AgentThreadId) String() string {
	return hex.EncodeToString(self[:])
}

// 16 hex-encoded bytes of field, exactly 32 lowercase hex digits.
func parseAgentMessageHex16(text string, field string) ([16]byte, error) {
	var value [16]byte
	decoded, err := hex.DecodeString(text)
	if err != nil || len(decoded) != len(value) || hex.EncodeToString(decoded) != text {
		return value, fmt.Errorf("%w: %s is not 16 bytes of hex", ErrAgentMessageInvalid, field)
	}
	copy(value[:], decoded)
	return value, nil
}

// A message id from its hex.
func ParseAgentMessageId(text string) (AgentMessageId, error) {
	value, err := parseAgentMessageHex16(text, "id")
	return AgentMessageId(value), err
}

// A thread id from its hex.
func ParseAgentThreadId(text string) (AgentThreadId, error) {
	value, err := parseAgentMessageHex16(text, "thread")
	return AgentThreadId(value), err
}

// The first 16 bytes of SHA-256(domain || 0x00 || part || 0x00 || part ...).
func agentMessageDerived(domain string, parts ...[]byte) [16]byte {
	hash := sha256.New()
	hash.Write([]byte(domain))
	for _, part := range parts {
		hash.Write([]byte{0})
		hash.Write(part)
	}
	var value [16]byte
	copy(value[:], hash.Sum(nil))
	return value
}

// A kind-24 send's id from its effect key k (§20.7's ids row), which its kind's Lookup reads the one path of.
func AgentMessageIdForEffect(effectKey []byte) AgentMessageId {
	return AgentMessageId(agentMessageDerived(agentMessageIdDomain, effectKey))
}

// A Harness run's send's id: k is the run id || the tool call's id, which a resumed run repeats with the call (§24.7).
func AgentMessageIdForCall(runId Id, toolCallId string) AgentMessageId {
	key := append(bytes.Clone(runId[:]), []byte(toolCallId)...)
	return AgentMessageIdForEffect(key)
}

// 16 random bytes, drawn when a person's or an MCP caller's message is composed.
func NewAgentMessageId() (AgentMessageId, error) {
	var id AgentMessageId
	_, err := rand.Read(id[:])
	return id, err
}

// 16 random bytes, a new thread's.
func NewAgentThreadId() (AgentThreadId, error) {
	var thread AgentThreadId
	_, err := rand.Read(thread[:])
	return thread, err
}

// A support item's thread in an agent's repo, the same on every device (§28.9).
func AgentSupportThreadId(product string, entry string) AgentThreadId {
	return AgentThreadId(agentMessageDerived(agentSupportThreadIdDomain, []byte(product), []byte(entry)))
}

// A support event's notice id, the same on every device (§28.9).
func AgentSupportNoticeId(product string, entry string, seq uint32) AgentMessageId {
	return AgentMessageId(agentMessageDerived(agentSupportNoticeIdDomain, []byte(product), []byte(entry), []byte(fmt.Sprintf("%d", seq))))
}

// inbox/<thread>/<id>.json.
func AgentMessagePath(thread AgentThreadId, id AgentMessageId) string {
	return agentInboxDirectory + "/" + thread.String() + "/" + id.String() + agentMessageFileSuffix
}

// inbox/<thread>.
func AgentThreadPath(thread AgentThreadId) string {
	return agentInboxDirectory + "/" + thread.String()
}

// A message path's thread and id, false for a path that is no message's.
func ParseAgentMessagePath(path string) (AgentThreadId, AgentMessageId, bool) {
	rest, found := strings.CutPrefix(path, agentInboxDirectory+"/")
	if !found {
		return AgentThreadId{}, AgentMessageId{}, false
	}
	threadText, fileName, found := strings.Cut(rest, "/")
	if !found {
		return AgentThreadId{}, AgentMessageId{}, false
	}
	idText, found := strings.CutSuffix(fileName, agentMessageFileSuffix)
	if !found {
		return AgentThreadId{}, AgentMessageId{}, false
	}
	thread, err := ParseAgentThreadId(threadText)
	if err != nil {
		return AgentThreadId{}, AgentMessageId{}, false
	}
	id, err := ParseAgentMessageId(idText)
	if err != nil {
		return AgentThreadId{}, AgentMessageId{}, false
	}
	return thread, id, true
}

// One agent by its stable identity (§20.7's to row): its member, its name, unique within the member, and its agent repo,
// zero for a child with none yet.
type AgentAddress struct {
	MemberId Id
	Name     AgentName
	RepoId   Id
}

// Who a message says wrote it: an agent, the member's person, or support. The writer's word alone.
type AgentMessageFrom struct {
	MemberId  Id
	Name      AgentName
	AgentId   Id
	SidecarId Id
	RepoId    Id
	// {"member", "person": true}
	Person bool
	// {"support": "urnetwork"}
	Support bool
}

// One ref a message cites.
type AgentMessageRef struct {
	RepoId  Id
	Path    string
	Version uint64
}

// A support notice's enumerated fields (§28.9): rendered from their values, never as text.
type AgentMessageSupport struct {
	Product string
	Entry   string
	Seq     uint32
	Type    string
	Status  string
	FixedIn string
	Final   bool
}

// One message, as §20.7 writes it.
type AgentMessage struct {
	Id     AgentMessageId
	Thread AgentThreadId
	Seq    uint64
	From   AgentMessageFrom
	// nil for "*"
	To      *AgentAddress
	Kind    AgentMessageKind
	Subject string
	Body    string
	Refs    []*AgentMessageRef
	// Where a report goes, nil for none: the person's me for work the person asked for.
	ReplyTo *AgentAddress
	// An outward use's effect key (§16.3), nil for none.
	Effect  []byte
	Created time.Time
	Support *AgentMessageSupport
}

// Whether the message is to every agent.
func (self *AgentMessage) ToAll() bool {
	return self.To == nil
}

// The message's path.
func (self *AgentMessage) Path() string {
	return AgentMessagePath(self.Thread, self.Id)
}

// The message as its file's bytes, in §20.7's field order.
type agentMessageWire struct {
	V       int                `json:"v"`
	Id      string             `json:"id"`
	Thread  string             `json:"thread"`
	Seq     uint64             `json:"seq"`
	From    json.RawMessage    `json:"from"`
	To      json.RawMessage    `json:"to"`
	Kind    string             `json:"kind"`
	Subject string             `json:"subject,omitempty"`
	Body    string             `json:"body,omitempty"`
	Refs    []*agentMessageRef `json:"refs,omitempty"`
	ReplyTo *agentAddressWire  `json:"reply_to,omitempty"`
	Effect  string             `json:"effect,omitempty"`
	Created string             `json:"created"`
	Support *agentSupportWire  `json:"support,omitempty"`
}

// An address as a file writes it.
type agentAddressWire struct {
	Member string `json:"member"`
	Name   string `json:"name"`
	Repo   string `json:"repo"`
}

// An agent's from as a file writes it.
type agentFromAgentWire struct {
	Member    string `json:"member"`
	Name      string `json:"name"`
	AgentId   string `json:"agent_id"`
	SidecarId string `json:"sidecar_id"`
	Repo      string `json:"repo"`
}

// The person's from as a file writes it.
type agentFromPersonWire struct {
	Member string `json:"member"`
	Person bool   `json:"person"`
}

// Support's from as a file writes it.
type agentFromSupportWire struct {
	Support string `json:"support"`
}

// A ref as a file writes it.
type agentMessageRef struct {
	Repo    string `json:"repo"`
	Path    string `json:"path"`
	Version uint64 `json:"version"`
}

// A support notice's fields as a file writes them.
type agentSupportWire struct {
	Product string `json:"product"`
	Entry   string `json:"entry"`
	Seq     uint32 `json:"seq"`
	Type    string `json:"type"`
	Status  string `json:"status"`
	FixedIn string `json:"fixed_in"`
	Final   bool   `json:"final"`
}

// JSON without HTML escaping, its trailing newline cut.
func agentMessageJson(value any) ([]byte, error) {
	encoded := bytes.Buffer{}
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimRight(encoded.Bytes(), "\n"), nil
}

// An address's wire form.
func agentAddressWireOf(address *AgentAddress) *agentAddressWire {
	return &agentAddressWire{Member: agentCardIdText(address.MemberId), Name: string(address.Name), Repo: agentCardIdText(address.RepoId)}
}

// An address from its wire form: a member, a name, and a repo or none.
func parseAgentAddress(wire *agentAddressWire, field string, settings *SkillSettings) (*AgentAddress, error) {
	address := &AgentAddress{}
	var err error
	if address.MemberId, err = parseAgentCardId(wire.Member, field+".member", false); err != nil {
		return nil, fmt.Errorf("%w: %s.member", ErrAgentMessageInvalid, field)
	}
	if address.Name, err = ParseAgentName(wire.Name, settings); err != nil {
		return nil, fmt.Errorf("%w: %s.name", ErrAgentMessageInvalid, field)
	}
	if address.RepoId, err = parseAgentCardId(wire.Repo, field+".repo", true); err != nil {
		return nil, fmt.Errorf("%w: %s.repo", ErrAgentMessageInvalid, field)
	}
	return address, nil
}

// A subject: one line of UTF-8 within maxCharCount characters, no control character.
func checkAgentMessageSubject(subject string, maxCharCount int) error {
	if !utf8.ValidString(subject) || maxCharCount < utf8.RuneCountInString(subject) {
		return fmt.Errorf("%w: subject", ErrAgentMessageInvalid)
	}
	for _, r := range subject {
		if unicode.IsControl(r) || r == 0x2028 || r == 0x2029 {
			return fmt.Errorf("%w: subject", ErrAgentMessageInvalid)
		}
	}
	return nil
}

// A support notice's word: [a-z0-9_.+-] within maxByteCount, "" where allowEmpty.
func checkAgentSupportWord(word string, field string, maxByteCount int, allowEmpty bool) error {
	if (word == "" && !allowEmpty) || maxByteCount < len(word) {
		return fmt.Errorf("%w: support.%s", ErrAgentMessageInvalid, field)
	}
	for i := 0; i < len(word); i += 1 {
		c := word[i]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '_' || c == '.' || c == '+' || c == '-' || 'A' <= c && c <= 'Z') {
			return fmt.Errorf("%w: support.%s", ErrAgentMessageInvalid, field)
		}
	}
	return nil
}

// The message's bytes, refusing one that would not read back.
func EncodeAgentMessage(message *AgentMessage, settings *SkillSettings) ([]byte, error) {
	wire := &agentMessageWire{
		V:       AgentMessageVersion,
		Id:      message.Id.String(),
		Thread:  message.Thread.String(),
		Seq:     message.Seq,
		Kind:    string(message.Kind),
		Subject: message.Subject,
		Body:    message.Body,
		Created: agentCardTimeText(message.Created),
	}
	var err error
	switch from := message.From; {
	case from.Support:
		wire.From, err = agentMessageJson(&agentFromSupportWire{Support: AgentMessageSupportFrom})
	case from.Person:
		wire.From, err = agentMessageJson(&agentFromPersonWire{Member: agentCardIdText(from.MemberId), Person: true})
	default:
		wire.From, err = agentMessageJson(&agentFromAgentWire{
			Member: agentCardIdText(from.MemberId), Name: string(from.Name), AgentId: agentCardIdText(from.AgentId),
			SidecarId: agentCardIdText(from.SidecarId), Repo: agentCardIdText(from.RepoId),
		})
	}
	if err != nil {
		return nil, err
	}
	if message.To == nil {
		wire.To, err = agentMessageJson(agentMessageToAll)
	} else {
		wire.To, err = agentMessageJson(agentAddressWireOf(message.To))
	}
	if err != nil {
		return nil, err
	}
	for _, ref := range message.Refs {
		wire.Refs = append(wire.Refs, &agentMessageRef{Repo: agentCardIdText(ref.RepoId), Path: ref.Path, Version: ref.Version})
	}
	if message.ReplyTo != nil {
		wire.ReplyTo = agentAddressWireOf(message.ReplyTo)
	}
	if len(message.Effect) != 0 {
		wire.Effect = hex.EncodeToString(message.Effect)
	}
	if support := message.Support; support != nil {
		wire.Support = &agentSupportWire{
			Product: support.Product, Entry: support.Entry, Seq: support.Seq, Type: support.Type, Status: support.Status,
			FixedIn: support.FixedIn, Final: support.Final,
		}
	}
	data, err := agentMessageJson(wire)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if _, err := ParseAgentMessage(data, settings); err != nil {
		return nil, err
	}
	return data, nil
}

// One message's bytes as a reader takes them: see the file header.
func ParseAgentMessage(data []byte, settings *SkillSettings) (*AgentMessage, error) {
	if settings.MessageMaxByteCount < len(data) {
		return nil, fmt.Errorf("%w: past %d bytes", ErrAgentMessageInvalid, settings.MessageMaxByteCount)
	}
	wire := &agentMessageWire{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(wire); err != nil {
		return nil, fmt.Errorf("%w: not one JSON object", ErrAgentMessageInvalid)
	}
	if decoder.More() {
		return nil, fmt.Errorf("%w: bytes past the object", ErrAgentMessageInvalid)
	}
	if wire.V != AgentMessageVersion {
		return nil, fmt.Errorf("%w: version %d", ErrAgentMessageInvalid, wire.V)
	}
	message := &AgentMessage{Seq: wire.Seq, Kind: AgentMessageKind(wire.Kind), Subject: wire.Subject, Body: wire.Body}
	var err error
	if message.Id, err = ParseAgentMessageId(wire.Id); err != nil {
		return nil, err
	}
	if message.Thread, err = ParseAgentThreadId(wire.Thread); err != nil {
		return nil, err
	}
	if !message.Kind.valid() {
		return nil, fmt.Errorf("%w: kind", ErrAgentMessageInvalid)
	}
	if message.Seq == 0 {
		return nil, fmt.Errorf("%w: seq", ErrAgentMessageInvalid)
	}
	if err := parseAgentMessageFrom(wire.From, &message.From, settings); err != nil {
		return nil, err
	}
	if err := parseAgentMessageTo(wire.To, message, settings); err != nil {
		return nil, err
	}
	if err := checkAgentMessageSubject(message.Subject, settings.SubjectCharCount); err != nil {
		return nil, err
	}
	if !utf8.ValidString(message.Body) || settings.BodyByteCount < len(message.Body) {
		return nil, fmt.Errorf("%w: body", ErrAgentMessageInvalid)
	}
	if settings.MessageRefMaxCount < len(wire.Refs) {
		return nil, fmt.Errorf("%w: refs", ErrAgentMessageInvalid)
	}
	for _, ref := range wire.Refs {
		repoId, err := parseAgentCardId(ref.Repo, "refs.repo", false)
		if err != nil {
			return nil, fmt.Errorf("%w: refs.repo", ErrAgentMessageInvalid)
		}
		if ref.Path == "" || settings.MessageRefPathByteCount < len(ref.Path) || !utf8.ValidString(ref.Path) || strings.ContainsRune(ref.Path, 0) {
			return nil, fmt.Errorf("%w: refs.path", ErrAgentMessageInvalid)
		}
		message.Refs = append(message.Refs, &AgentMessageRef{RepoId: repoId, Path: ref.Path, Version: ref.Version})
	}
	if wire.ReplyTo != nil {
		if message.ReplyTo, err = parseAgentAddress(wire.ReplyTo, "reply_to", settings); err != nil {
			return nil, err
		}
	}
	if wire.Effect != "" {
		effect, err := hex.DecodeString(wire.Effect)
		if err != nil || hex.EncodeToString(effect) != wire.Effect || settings.MessageEffectByteCount < len(effect) {
			return nil, fmt.Errorf("%w: effect", ErrAgentMessageInvalid)
		}
		message.Effect = effect
	}
	if message.Created, err = parseAgentCardTime(wire.Created, "created", false); err != nil {
		return nil, fmt.Errorf("%w: created", ErrAgentMessageInvalid)
	}
	support := message.Kind == AgentMessageKindSupport
	if support != message.From.Support || support != (wire.Support != nil) {
		return nil, fmt.Errorf("%w: a support notice is of kind support, from support, with its fields", ErrAgentMessageInvalid)
	}
	if support {
		if message.Subject != "" || message.Body != "" || len(message.Refs) != 0 {
			return nil, fmt.Errorf("%w: a support notice with a subject, body or refs", ErrAgentMessageInvalid)
		}
		notice := wire.Support
		if notice.Product != AgentMessageSupportFrom {
			return nil, fmt.Errorf("%w: support.product", ErrAgentMessageInvalid)
		}
		for _, word := range []struct {
			field      string
			value      string
			allowEmpty bool
		}{
			{field: "entry", value: notice.Entry},
			{field: "type", value: notice.Type},
			{field: "status", value: notice.Status, allowEmpty: true},
			{field: "fixed_in", value: notice.FixedIn, allowEmpty: true},
		} {
			if err := checkAgentSupportWord(word.value, word.field, settings.CardFieldMaxByteCount, word.allowEmpty); err != nil {
				return nil, err
			}
		}
		message.Support = &AgentMessageSupport{
			Product: notice.Product, Entry: notice.Entry, Seq: notice.Seq, Type: notice.Type, Status: notice.Status,
			FixedIn: notice.FixedIn, Final: notice.Final,
		}
	}
	return message, nil
}

// from: an agent's, a person's or support's shape.
func parseAgentMessageFrom(raw json.RawMessage, from *AgentMessageFrom, settings *SkillSettings) error {
	fields := map[string]json.RawMessage{}
	if json.Unmarshal(raw, &fields) != nil {
		return fmt.Errorf("%w: from", ErrAgentMessageInvalid)
	}
	strict := func(value any) error {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(value) != nil {
			return fmt.Errorf("%w: from", ErrAgentMessageInvalid)
		}
		return nil
	}
	var err error
	switch {
	case fields["support"] != nil:
		wire := &agentFromSupportWire{}
		if err := strict(wire); err != nil || wire.Support != AgentMessageSupportFrom {
			return fmt.Errorf("%w: from.support", ErrAgentMessageInvalid)
		}
		from.Support = true
	case fields["person"] != nil:
		wire := &agentFromPersonWire{}
		if err := strict(wire); err != nil || !wire.Person {
			return fmt.Errorf("%w: from.person", ErrAgentMessageInvalid)
		}
		from.Person = true
		if from.MemberId, err = parseAgentCardId(wire.Member, "from.member", false); err != nil {
			return fmt.Errorf("%w: from.member", ErrAgentMessageInvalid)
		}
	default:
		wire := &agentFromAgentWire{}
		if err := strict(wire); err != nil {
			return err
		}
		if from.MemberId, err = parseAgentCardId(wire.Member, "from.member", false); err != nil {
			return fmt.Errorf("%w: from.member", ErrAgentMessageInvalid)
		}
		if from.Name, err = ParseAgentName(wire.Name, settings); err != nil {
			return fmt.Errorf("%w: from.name", ErrAgentMessageInvalid)
		}
		if from.AgentId, err = parseAgentCardId(wire.AgentId, "from.agent_id", false); err != nil {
			return fmt.Errorf("%w: from.agent_id", ErrAgentMessageInvalid)
		}
		if from.SidecarId, err = parseAgentCardId(wire.SidecarId, "from.sidecar_id", false); err != nil {
			return fmt.Errorf("%w: from.sidecar_id", ErrAgentMessageInvalid)
		}
		if from.RepoId, err = parseAgentCardId(wire.Repo, "from.repo", true); err != nil {
			return fmt.Errorf("%w: from.repo", ErrAgentMessageInvalid)
		}
	}
	return nil
}

// to: "*" or one address.
func parseAgentMessageTo(raw json.RawMessage, message *AgentMessage, settings *SkillSettings) error {
	all := ""
	if json.Unmarshal(raw, &all) == nil {
		if all != agentMessageToAll {
			return fmt.Errorf("%w: to", ErrAgentMessageInvalid)
		}
		return nil
	}
	wire := &agentAddressWire{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(wire) != nil {
		return fmt.Errorf("%w: to", ErrAgentMessageInvalid)
	}
	address, err := parseAgentAddress(wire, "to", settings)
	if err != nil {
		return err
	}
	message.To = address
	return nil
}
