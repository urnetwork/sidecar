//go:build !ios_extension && !sidecar_http

// The recURd skill's text (DESIGN-COMPUTE §20.9, R-SKILL-1, R-CCTX-16; SKILL-M11-06): skill/recurd/SKILL.md in the Agent
// Skills format, its front matter naming recurd and describing it, compiled in and versioned with ur. The Harness puts
// SkillText first in every agent's system prompt, before the person's and the project's instructions (HARN's to
// place), and ur install-harness installs a rendering beside the MCP entry for Claude Code, Codex and Cursor
// (mcp/harness_install_skill.go).
//
//	profiles  each section of the source follows a line <!-- recurd:profiles <profile>... -->, naming the profiles
//	          whose rendering holds it, until the next such line; the front matter is in every one. A rendering is the
//	          front matter and its profile's sections, the marker lines dropped
//	local     the local Harness: the managing lines, never the being-managed ones
//	enclave   an enclave's Harness: the being-managed lines and the enclave's own, never the managing ones
//	managing  an enclave agent that a rule lets manage another enclave (Q-HARN-9, QD-1323): enclave's lines and the
//	          managing ones too
//	installed an external harness, which manages no Harness: neither the managing nor the being-managed lines
//	installed-enclave  a harness installed in an enclave: installed's, with the being-managed and enclave lines, since
//	          threads reach it, though it reads them only at its next turn
//	bound     every rendering holds at most SkillSettings.TextWordCount words (1,500), which its test holds
//	seal      SkillTextSha256 hashes a rendering's bytes, never the source's, so an install seals what it wrote
//
// Nothing here writes to the team directory (Q-SKILL-5, QD-1355): the text keeps summaries in the agents repo.
//
// On the compute legs. Package-level functions are safe for concurrent use.

package sidecar

import (
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"slices"
	"strings"
)

//go:embed skill/recurd/SKILL.md
var skillTextSource string

// The skill's name, as its front matter gives it.
const SkillName = "recurd"

// Which agents a rendering of the skill is for (§20.9).
type SkillProfile string

const (
	// The local Harness, on the person's device.
	SkillProfileLocal SkillProfile = "local"
	// An enclave's Harness.
	SkillProfileEnclave SkillProfile = "enclave"
	// An enclave agent a rule lets manage another enclave.
	SkillProfileManaging SkillProfile = "managing"
	// An external harness ur install-harness installs into.
	SkillProfileInstalled SkillProfile = "installed"
	// An external harness installed in an enclave.
	SkillProfileInstalledEnclave SkillProfile = "installed-enclave"
)

// Every profile, in the order the design lists them.
func SkillProfiles() []SkillProfile {
	return []SkillProfile{SkillProfileLocal, SkillProfileEnclave, SkillProfileManaging, SkillProfileInstalled, SkillProfileInstalledEnclave}
}

// A profile no rendering is made for.
var ErrSkillProfileUnknown = errors.New("not a profile of the recurd skill")

// The line that opens a section and names its profiles.
const (
	skillProfileMarkerPrefix = "<!-- recurd:profiles "
	skillProfileMarkerSuffix = " -->"
)

// The source cut into its front matter and its sections, each with its profiles.
type skillTextSection struct {
	profiles []SkillProfile
	lines    []string
}

// The source's front matter's lines and its sections, an error for a source that holds no front matter or a marker
// naming no profile: a build error, which SkillText's test holds against.
func skillTextParts(source string) ([]string, []*skillTextSection, error) {
	lines := strings.Split(strings.TrimSuffix(source, "\n"), "\n")
	if len(lines) == 0 || lines[0] != "---" {
		return nil, nil, errors.New("the skill's source opens with no front matter")
	}
	end := slices.Index(lines[1:], "---")
	if end < 0 {
		return nil, nil, errors.New("the skill's front matter does not close")
	}
	front := lines[:end+2]
	sections := []*skillTextSection{}
	for _, line := range lines[end+2:] {
		if names, found := strings.CutPrefix(line, skillProfileMarkerPrefix); found {
			names, closed := strings.CutSuffix(names, skillProfileMarkerSuffix)
			section := &skillTextSection{}
			for _, name := range strings.Fields(names) {
				if !slices.Contains(SkillProfiles(), SkillProfile(name)) {
					return nil, nil, fmt.Errorf("a section names profile %q", name)
				}
				section.profiles = append(section.profiles, SkillProfile(name))
			}
			if !closed || len(section.profiles) == 0 {
				return nil, nil, errors.New("a section marker names no profile")
			}
			sections = append(sections, section)
			continue
		}
		if len(sections) == 0 {
			return nil, nil, errors.New("text before the first section's marker")
		}
		sections[len(sections)-1].lines = append(sections[len(sections)-1].lines, line)
	}
	return front, sections, nil
}

// The rendering of profile: the front matter and the sections it names, marker lines dropped, ending in a newline.
// ErrSkillProfileUnknown for a profile that is none.
func SkillText(profile SkillProfile) (string, error) {
	if !slices.Contains(SkillProfiles(), profile) {
		return "", fmt.Errorf("%w: %q", ErrSkillProfileUnknown, profile)
	}
	front, sections, err := skillTextParts(skillTextSource)
	if err != nil {
		return "", err
	}
	lines := slices.Clone(front)
	for _, section := range sections {
		if slices.Contains(section.profiles, profile) {
			lines = append(lines, section.lines...)
		}
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// SHA-256 of profile's rendering's bytes: what an install seals (§20.9).
func SkillTextSha256(profile SkillProfile) ([sha256.Size]byte, error) {
	text, err := SkillText(profile)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256([]byte(text)), nil
}

// The words a rendering holds, as its bound counts them: runs of non-space bytes.
func skillTextWordCount(text string) int {
	return len(strings.Fields(text))
}
