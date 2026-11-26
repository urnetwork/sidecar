//go:build !ios_extension && !sidecar_http

// The support skill's text (DESIGN-COMPUTE §28.4): skill/support/SKILL.md in the Agent Skills format, compiled in
// beside recurd's, which the Harness lists after recurd's in every agent's system prompt and ur install-harness installs
// beside it for Claude Code, Codex and Cursor. Until G-SUP-service passes, no Harness carries it and no install writes
// it (§28.21): SupportSkillText answers it, and its consumers check SupportSettings.ServiceEnabled first.

package sidecar

import (
	_ "embed"
	"strings"
)

//go:embed skill/support/SKILL.md
var supportSkillText string

// The skill's name, as its front matter gives it.
const SupportSkillName = "support"

// The skill's SKILL.md, whole.
func SupportSkillText() string {
	return supportSkillText
}

// The skill's word count, which §28.4 bounds at 600: what its test holds.
func supportSkillWordCount() int {
	return len(strings.Fields(supportSkillText))
}
