//go:build !js && !ios && !android && !sdk_mobile_bind

// The skills ur install-harness writes beside the MCP entry (DESIGN-COMPUTE §20.9, §28.4, R-SKILL-1, R-MCP-2;
// SKILL-M11-06): the recURd skill's rendering for an external harness, and the support skill's beside it once
// G-SUP-service passes, each a SKILL.md in the harness's skills directory, a person's or a project's:
//
//	claude-code  ~/.claude/skills/<skill>/SKILL.md, a project's <project>/.claude/skills/<skill>/SKILL.md
//	codex        ~/.codex/skills/<skill>/SKILL.md, a project's <project>/.codex/skills/<skill>/SKILL.md
//	cursor       ~/.cursor/skills/<skill>/SKILL.md, a project's <project>/.cursor/skills/<skill>/SKILL.md
//
//	profile    the installed profile, which manages no Harness, and for a harness installed in an enclave the
//	           installed-enclave one, with the being-managed lines (HarnessInstallArgs.Enclave, a template input the
//	           seal names)
//	support    support's SKILL.md only where the release's support switch is on (HarnessInstallArgs.SupportSkill,
//	           SupportSettings.ServiceEnabled, off until G-SUP-service passes, §28.21), a template input too
//	whole      the file is ur's whole: the install writes the rendering's bytes over whatever stands, and the seal holds
//	           the SHA-256 of those bytes as the file's entries, so any edit, a person's or another tool's, reads as a
//	           changed config (harness_hash.go), and a release whose rendering differs reads as one until the install
//	           runs again
//
// Nothing is written to the team directory (Q-SKILL-5, QD-1355).

package mcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"

	"github.com/urnetwork/sidecar"
)

// A skill's file name in its directory, as the Agent Skills format names it.
const harnessSkillFileName = "SKILL.md"

// The skills directory's name under a harness's own directory.
const harnessSkillsDirectoryName = "skills"

// One skill file, ur's whole.
type harnessSkillFile struct {
	// sidecar.SkillName or sidecar.SupportSkillName
	skill string
}

// The skill files of an install whose harness keeps its skills under directory: recurd's always, support's beside it
// where the template carries it.
func harnessSkillFiles(directory string, projectDirectory string, template *harnessTemplate) []*harnessFile {
	mode := harnessFileMode(projectDirectory)
	skills := []string{sidecar.SkillName}
	if template.supportSkill {
		skills = append(skills, sidecar.SupportSkillName)
	}
	files := []*harnessFile{}
	for _, skill := range skills {
		files = append(files, &harnessFile{
			path: filepath.Join(directory, harnessSkillsDirectoryName, skill, harnessSkillFileName),
			mode: mode,
			kind: &harnessSkillFile{skill: skill},
		})
	}
	return files
}

// The bytes the template puts in the file: its profile's rendering of recurd, or support's text.
func (self *harnessSkillFile) render(template *harnessTemplate) ([]byte, error) {
	switch self.skill {
	case sidecar.SkillName:
		profile := sidecar.SkillProfileInstalled
		if template.skillEnclave {
			profile = sidecar.SkillProfileInstalledEnclave
		}
		text, err := sidecar.SkillText(profile)
		if err != nil {
			return nil, err
		}
		return []byte(text), nil
	case sidecar.SupportSkillName:
		return []byte(sidecar.SupportSkillText()), nil
	}
	return nil, harnessConfigError("no skill %q", self.skill)
}

// What the seal hashes of bytes: their SHA-256, as JSON's value.
func harnessSkillEntries(content []byte) any {
	digest := sha256.Sum256(content)
	return map[string]any{"sha256": hex.EncodeToString(digest[:])}
}

func (self *harnessSkillFile) template(template *harnessTemplate) (any, error) {
	rendering, err := self.render(template)
	if err != nil {
		return nil, err
	}
	return harnessSkillEntries(rendering), nil
}

func (self *harnessSkillFile) nextEdit(content []byte, template *harnessTemplate, maxDepth int) (*harnessEdit, error) {
	rendering, err := self.render(template)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(content, rendering) {
		return nil, nil
	}
	return &harnessEdit{start: 0, end: len(content), text: string(rendering)}, nil
}

func (self *harnessSkillFile) extract(content []byte, template *harnessTemplate, maxDepth int) (any, error) {
	return harnessSkillEntries(content), nil
}

func (self *harnessSkillFile) competing(content []byte, template *harnessTemplate, maxDepth int) (int, error) {
	// a skill file answers for no ur tool
	return 0, nil
}
