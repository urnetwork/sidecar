//go:build !ios_extension && !sidecar_http

// An agent's card (DESIGN-COMPUTE §20.5; SKILL-M11-02): cards/<name>.json in its member's agents repo, UTF-8 JSON, one
// object, §20.5's fields in its order:
//
//	{"v": 1, "name": "limiter-fix", "agent_id": "<32 hex>", "sidecar_id": "<32 hex>", "host": "...", "harness": "...",
//	 "model": "...", "agent_repo": "<32 hex>" | "", "started": "<RFC 3339, UTC>", "parent": "<name>" | null,
//	 "retired": "<RFC 3339, UTC>"}
//
//	me        the person's own agent's card names the member in place of a sidecar and an agent (D-SKILL-9):
//	          "member": "<32 hex>", with no agent_id or sidecar_id, since any untagged consented device of the member
//	          writes it (agents_me.go)
//	text      host, harness and model are the writer's word: a reader shows the host the config gives the card's
//	          sidecar_id (§20.6's stub rule), and every field is bounded (SkillSettings.CardFieldMaxByteCount,
//	          CardMaxByteCount) and held to printable ASCII, so no card carries an unbounded or control-laden string
//	retired   set once, when its agent ends for good or has written no status for SkillSettings.RetireAfterIdle; the
//	          card is never removed (§20.5)
//	read      v must be 1; fields a later release adds are passed over, so a newer writer's card still reads; a field
//	          out of its grammar refuses the card, ErrAgentCardInvalid, which names the field and never its value
//
// On the compute legs. Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// The card format's version (§20.5).
const AgentCardVersion = 1

// The card directory of an agents repo, and a card's file name's suffix (§20.4's layout).
const (
	agentCardDirectory  = "cards"
	agentCardFileSuffix = ".json"
)

// A card that does not read: its version, a field out of its grammar, or bytes that are no object.
var ErrAgentCardInvalid = errors.New("agent card invalid")

// One card, as §20.5 writes it.
type AgentCard struct {
	Name AgentName
	// The durable agent_id, per sidecar and label (DESIGN §5.5); zero on the person's me card.
	AgentId Id
	// The sidecar the agent runs on, whose pushes alone write the card; zero on the person's me card.
	SidecarId Id
	// The member a me card names in place of a sidecar; zero on every other card.
	MemberId Id
	// The writer's word for where it runs, never shown as the host (AgentCardView.Host).
	Host string
	// The harness and its version, such as ur-harness 1.0 or claude-code 2.1.300.
	Harness string
	// The model's canonical name (§6.3), the writer's word.
	Model string
	// The agent's own repo, zero while it has none: a child agent_launch started in its parent's Harness until its
	// first agent_send, its messages meanwhile landing in its nearest ancestor's repo (§20.5's step 3).
	AgentRepo Id
	Started   time.Time
	// The agent that launched it, "" for none.
	Parent AgentName
	// When the card was retired, zero while it stands.
	Retired time.Time
}

// Whether the card is the person's me card, naming a member in place of a sidecar.
func (self *AgentCard) Person() bool {
	return self.MemberId != (Id{})
}

// Whether the card is retired.
func (self *AgentCard) IsRetired() bool {
	return !self.Retired.IsZero()
}

// cards/<name>.json, the card's path in the agents repo.
func AgentCardPath(name AgentName) string {
	return agentCardDirectory + "/" + string(name) + agentCardFileSuffix
}

// The card as its file's bytes, in §20.5's field order.
type agentCardWire struct {
	V         int     `json:"v"`
	Name      string  `json:"name"`
	AgentId   string  `json:"agent_id,omitempty"`
	SidecarId string  `json:"sidecar_id,omitempty"`
	Member    string  `json:"member,omitempty"`
	Host      string  `json:"host"`
	Harness   string  `json:"harness"`
	Model     string  `json:"model"`
	AgentRepo string  `json:"agent_repo"`
	Started   string  `json:"started"`
	Parent    *string `json:"parent"`
	Retired   string  `json:"retired,omitempty"`
}

// An id as a card writes it: 32 lowercase hex digits, "" for zero.
func agentCardIdText(id Id) string {
	if id == (Id{}) {
		return ""
	}
	return hex.EncodeToString(id[:])
}

// A card's id field: 32 lowercase hex digits naming a nonzero id, or "" for none where allowEmpty.
func parseAgentCardId(text string, field string, allowEmpty bool) (Id, error) {
	if text == "" && allowEmpty {
		return Id{}, nil
	}
	decoded, err := hex.DecodeString(text)
	if err != nil || len(decoded) != len(Id{}) || hex.EncodeToString(decoded) != text {
		return Id{}, fmt.Errorf("%w: %s is no id", ErrAgentCardInvalid, field)
	}
	id := Id(decoded)
	if id == (Id{}) {
		return Id{}, fmt.Errorf("%w: %s is the zero id", ErrAgentCardInvalid, field)
	}
	return id, nil
}

// A card's time: RFC 3339 in UTC to the second, as a writer gives it.
func agentCardTimeText(at time.Time) string {
	return at.UTC().Truncate(time.Second).Format(time.RFC3339)
}

// A card's time field, "" for none where allowEmpty.
func parseAgentCardTime(text string, field string, allowEmpty bool) (time.Time, error) {
	if text == "" && allowEmpty {
		return time.Time{}, nil
	}
	at, err := time.Parse(time.RFC3339, text)
	if err != nil || at.Location() != time.UTC {
		return time.Time{}, fmt.Errorf("%w: %s is no UTC time", ErrAgentCardInvalid, field)
	}
	return at, nil
}

// A card's free field: printable ASCII within the bound.
func checkAgentCardText(text string, field string, settings *SkillSettings) error {
	if settings.CardFieldMaxByteCount < len(text) {
		return fmt.Errorf("%w: %s is past %d bytes", ErrAgentCardInvalid, field, settings.CardFieldMaxByteCount)
	}
	for i := 0; i < len(text); i += 1 {
		if text[i] < 0x20 || 0x7e < text[i] {
			return fmt.Errorf("%w: %s is not printable ASCII", ErrAgentCardInvalid, field)
		}
	}
	return nil
}

// The card's bytes, refusing a card that would not read back: a me card names a member and neither agent nor sidecar,
// every other card an agent and a sidecar and no member.
func EncodeAgentCard(card *AgentCard, settings *SkillSettings) ([]byte, error) {
	wire := &agentCardWire{
		V:         AgentCardVersion,
		Name:      string(card.Name),
		AgentId:   agentCardIdText(card.AgentId),
		SidecarId: agentCardIdText(card.SidecarId),
		Member:    agentCardIdText(card.MemberId),
		Host:      card.Host,
		Harness:   card.Harness,
		Model:     card.Model,
		AgentRepo: agentCardIdText(card.AgentRepo),
		Started:   agentCardTimeText(card.Started),
	}
	if card.Parent != "" {
		parent := string(card.Parent)
		wire.Parent = &parent
	}
	if card.IsRetired() {
		wire.Retired = agentCardTimeText(card.Retired)
	}
	encoded := bytes.Buffer{}
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(wire); err != nil {
		return nil, err
	}
	data := encoded.Bytes()
	if _, err := ParseAgentCard(data, settings); err != nil {
		return nil, err
	}
	return data, nil
}

// One card's bytes as a reader takes them: see the file header.
func ParseAgentCard(data []byte, settings *SkillSettings) (*AgentCard, error) {
	if settings.CardMaxByteCount < len(data) {
		return nil, fmt.Errorf("%w: past %d bytes", ErrAgentCardInvalid, settings.CardMaxByteCount)
	}
	wire := &agentCardWire{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(wire); err != nil {
		return nil, fmt.Errorf("%w: not one JSON object", ErrAgentCardInvalid)
	}
	if decoder.More() {
		return nil, fmt.Errorf("%w: bytes past the object", ErrAgentCardInvalid)
	}
	if wire.V != AgentCardVersion {
		return nil, fmt.Errorf("%w: version %d", ErrAgentCardInvalid, wire.V)
	}
	card := &AgentCard{Host: wire.Host, Harness: wire.Harness, Model: wire.Model}
	var err error
	if card.Name, err = ParseAgentName(wire.Name, settings); err != nil {
		return nil, fmt.Errorf("%w: name: %w", ErrAgentCardInvalid, err)
	}
	if card.MemberId, err = parseAgentCardId(wire.Member, "member", true); err != nil {
		return nil, err
	}
	person := card.MemberId != (Id{})
	if card.AgentId, err = parseAgentCardId(wire.AgentId, "agent_id", person); err != nil {
		return nil, err
	}
	if card.SidecarId, err = parseAgentCardId(wire.SidecarId, "sidecar_id", person); err != nil {
		return nil, err
	}
	if person && (card.AgentId != (Id{}) || card.SidecarId != (Id{})) {
		return nil, fmt.Errorf("%w: a me card names a sidecar or an agent", ErrAgentCardInvalid)
	}
	if card.AgentRepo, err = parseAgentCardId(wire.AgentRepo, "agent_repo", true); err != nil {
		return nil, err
	}
	if card.Started, err = parseAgentCardTime(wire.Started, "started", false); err != nil {
		return nil, err
	}
	if card.Retired, err = parseAgentCardTime(wire.Retired, "retired", true); err != nil {
		return nil, err
	}
	if wire.Parent != nil {
		if card.Parent, err = ParseAgentName(*wire.Parent, settings); err != nil {
			return nil, fmt.Errorf("%w: parent: %w", ErrAgentCardInvalid, err)
		}
	}
	for _, field := range []struct {
		name string
		text string
	}{{name: "host", text: card.Host}, {name: "harness", text: card.Harness}, {name: "model", text: card.Model}} {
		if err := checkAgentCardText(field.text, field.name, settings); err != nil {
			return nil, err
		}
	}
	return card, nil
}

// Whether next keeps the card's identity: its name, agent, sidecar and member, so only its writer's own fields moved.
func agentCardSameAgent(card *AgentCard, next *AgentCard) bool {
	return card.Name == next.Name && card.AgentId == next.AgentId && card.SidecarId == next.SidecarId && card.MemberId == next.MemberId
}

// Whether next is card retired, and nothing else changed: what any untagged consented device of the member may write
// for an idle card (§20.5).
func agentCardRetiredOnly(card *AgentCard, next *AgentCard) bool {
	if card.IsRetired() || !next.IsRetired() {
		return false
	}
	retired := *next
	retired.Retired = time.Time{}
	return agentCardSameAgent(card, &retired) && card.Host == retired.Host && card.Harness == retired.Harness &&
		card.Model == retired.Model && card.AgentRepo == retired.AgentRepo && card.Started.Equal(retired.Started) &&
		card.Parent == retired.Parent
}
