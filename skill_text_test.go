//go:build !ios_extension && !sidecar_http

// The recURd skill's text (§20.9): each profile's rendering within its word bound, its front matter the Agent Skills
// format's, each profile holding exactly its lines, the tools named by their real names, nothing for the team
// directory, and each rendering byte for byte its golden under testdata/skill/.

package sidecar

import (
	"crypto/sha256"
	"embed"
	"errors"
	"os"
	"strings"
	"testing"
)

//go:embed testdata/skill
var testSkillGoldenFiles embed.FS

func TestSkillWordCountPerProfile(t *testing.T) {
	settings := DefaultSkillSettings()
	for _, profile := range SkillProfiles() {
		text, err := SkillText(profile)
		if err != nil {
			t.Fatal(err)
		}
		if count := skillTextWordCount(text); settings.TextWordCount < count || count == 0 {
			t.Errorf("%s: %d words, the bound %d", profile, count, settings.TextWordCount)
		}
	}
	if _, err := SkillText("everything"); !errors.Is(err, ErrSkillProfileUnknown) {
		t.Fatalf("a profile that is none: %v", err)
	}
}

func TestSkillFrontMatter(t *testing.T) {
	for _, profile := range SkillProfiles() {
		text, err := SkillText(profile)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(text, "\n")
		if lines[0] != "---" || lines[1] != "name: "+SkillName || !strings.HasPrefix(lines[2], "description: ") {
			t.Fatalf("%s: front matter %q", profile, lines[:3])
		}
		if strings.Contains(text, skillProfileMarkerPrefix) {
			t.Fatalf("%s: a marker line rendered", profile)
		}
	}
}

// Each profile holds exactly the lines §20.9 gives it, every tool by its real name, and nothing that mirrors a
// summary into the team directory.
func TestSkillProfilesHoldTheirLines(t *testing.T) {
	lines := map[string][]SkillProfile{
		"- managing harnesses:":       {SkillProfileLocal, SkillProfileManaging},
		"- being managed:":            {SkillProfileEnclave, SkillProfileManaging, SkillProfileInstalledEnclave},
		"- outbound from an enclave:": {SkillProfileEnclave, SkillProfileManaging, SkillProfileInstalledEnclave},
		"- who you are:":              SkillProfiles(),
		"- inbox:":                    SkillProfiles(),
		"- web search, where your tools include web_search:": SkillProfiles(),
	}
	for line, profiles := range lines {
		for _, profile := range SkillProfiles() {
			text, err := SkillText(profile)
			if err != nil {
				t.Fatal(err)
			}
			want := false
			for _, holding := range profiles {
				want = want || holding == profile
			}
			if strings.Contains(text, "\n"+line) != want {
				t.Errorf("%s holds %q: %t", profile, line, !want)
			}
		}
	}
	local, err := SkillText(SkillProfileLocal)
	if err != nil {
		t.Fatal(err)
	}
	managing, err := SkillText(SkillProfileManaging)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"agent_register", "agent_list", "agent_find", "agent_send", "agent_broadcast", "agent_summary",
		"agent_close", "harness_list", "agent_launch", "agent_prompt", "agent_wait", "agent_stop", "web_search",
		"connections_list", "connection_request", "service_call", "record_query", "mail_read"} {
		if !strings.Contains(local+managing, tool) {
			t.Errorf("no rendering names %s", tool)
		}
	}
	if !strings.Contains(local, "never copy them into the team directory") {
		t.Fatal("the text does not keep summaries out of the team directory (Q-SKILL-5)")
	}
}

// SHA-256 of a golden's bytes.
func testSkillSha256(data []byte) [sha256.Size]byte {
	return sha256.Sum256(data)
}

// Each rendering is its golden's bytes; SIDECAR_REGENERATE_SKILL_GOLDENS=1 rewrites them in the worktree.
func TestSkillTextGoldens(t *testing.T) {
	for _, profile := range SkillProfiles() {
		text, err := SkillText(profile)
		if err != nil {
			t.Fatal(err)
		}
		path := "testdata/skill/recurd." + string(profile) + ".md"
		if os.Getenv("SIDECAR_REGENERATE_SKILL_GOLDENS") == "1" {
			if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		golden, err := testSkillGoldenFiles.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(golden) != text {
			t.Errorf("%s renders other bytes than %s", profile, path)
		}
		hash, err := SkillTextSha256(profile)
		if err != nil || hash != testSkillSha256(golden) {
			t.Errorf("%s's hash is not its rendering's", profile)
		}
	}
}
