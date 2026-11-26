//go:build !ios_extension && !sidecar_http

// An agent's name (DESIGN-COMPUTE §20.5, R-SKILL-2; SKILL-M11-02): [a-z0-9][a-z0-9-]{0,47}, unique among its member's
// agents in the network (Q-SKILL-1, QD-1351), and the agent's label as it stands (DESIGN §5.5), so the record, the
// directory and the inbox all say one name. A name is a card's path, cards/<name>.json, and an agent repo's,
// agent/<name>.
//
//	parse     exactly the grammar, at most SkillSettings.NameMaxByteCount bytes; anything else is ErrAgentNameInvalid,
//	          which names the bound and never the text
//	derive    a task's first SkillSettings.NameDerivedWordCount words, lower-cased, each run of other bytes one '-',
//	          cut to the bound at a word's edge where one falls inside it, "agent" where nothing is left (§20.5's
//	          step 1, the last resort after the launch's name and the harness config's default)
//	suffix    <name>-<n>, the name cut so the whole stays within the bound (§20.5's step 2)
//
// On the compute legs. Package-level functions are safe for concurrent use.

package sidecar

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The name of the person's own agent, which every untagged consented device of the member writes and joins (§20.7's
// person in a thread, D-SKILL-9), unless the person picks another.
const AgentNameMe = "me"

// The name a task with no word of the grammar derives.
const agentNameDerivedFallback = "agent"

// Not an agent name: [a-z0-9][a-z0-9-]{0,47}.
var ErrAgentNameInvalid = errors.New("an agent name is a-z, 0-9 and '-', starting with a letter or digit")

// An agent's name, held to §20.5's grammar by ParseAgentName.
type AgentName string

// The name as its card path's name.
func (self AgentName) String() string {
	return string(self)
}

// text as an agent name: exactly §20.5's grammar within settings' bound, else ErrAgentNameInvalid.
func ParseAgentName(text string, settings *SkillSettings) (AgentName, error) {
	refused := fmt.Errorf("%w, 1 to %d of them", ErrAgentNameInvalid, settings.NameMaxByteCount)
	if text == "" || settings.NameMaxByteCount < len(text) {
		return "", refused
	}
	for i := 0; i < len(text); i += 1 {
		c := text[i]
		alphanumeric := ('a' <= c && c <= 'z') || ('0' <= c && c <= '9')
		if !alphanumeric && (i == 0 || c != '-') {
			return "", refused
		}
	}
	return AgentName(text), nil
}

// A name derived from a task's first words (§20.5's step 1): see the file header. Always a valid name.
func DeriveAgentName(task string, settings *SkillSettings) AgentName {
	words := []string{}
	word := strings.Builder{}
	flush := func() {
		if 0 < word.Len() {
			words = append(words, word.String())
			word.Reset()
		}
	}
	for _, r := range strings.ToLower(task) {
		if settings.NameDerivedWordCount <= len(words) {
			break
		}
		if ('a' <= r && r <= 'z') || ('0' <= r && r <= '9') {
			word.WriteRune(r)
			continue
		}
		flush()
	}
	if len(words) < settings.NameDerivedWordCount {
		flush()
	}
	name := ""
	for _, next := range words {
		joined := next
		if name != "" {
			joined = name + "-" + next
		}
		if settings.NameMaxByteCount < len(joined) {
			if name == "" {
				name = next[:settings.NameMaxByteCount]
			}
			break
		}
		name = joined
	}
	if name == "" {
		return agentNameDerivedFallback
	}
	return AgentName(name)
}

// <name>-<suffix> within settings' bound, the name cut and any '-' it then ends on dropped (§20.5's step 2). suffix is at
// least 2.
func AgentNameWithSuffix(name AgentName, suffix int, settings *SkillSettings) AgentName {
	tail := "-" + strconv.Itoa(suffix)
	base := string(name)
	if room := settings.NameMaxByteCount - len(tail); room < len(base) {
		base = strings.TrimRight(base[:max(room, 1)], "-")
		if base == "" {
			base = agentNameDerivedFallback[:1]
		}
	}
	return AgentName(base + tail)
}
