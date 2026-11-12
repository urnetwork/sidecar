//go:build !js && !ios && !android && !sdk_mobile_bind

package sidecar

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// §22.6: no hello line panics the parser, every refusal names a code and repeats nothing of the line, and an
// accepted hello names a mode the daemon knows.
func FuzzDaemonHello(f *testing.F) {
	f.Add([]byte(`{"ur_local":1,"mode":"control","version":"synthetic-version"}`))
	f.Add([]byte(`{"ur_local":1,"mode":"git","version":"synthetic-version","repo":"k7q2m9/repo","service":"git-upload-pack"}`))
	f.Add([]byte(`{"ur_local":1,"mode":"mcp","version":"synthetic-version","cwd":"synthetic-canary-cwd"}`))
	f.Add([]byte(`{"ur_local":1,"mode":"socket","version":"synthetic-version","socket":"k7q2m9:db/primary"}`))
	f.Add([]byte(`{"ur_local":1}`))
	f.Add([]byte(``))
	helloByteCount := DefaultSidecarSettings().LocalSettings.HelloByteCount
	f.Fuzz(func(t *testing.T, line []byte) {
		hello, code, err := parseDaemonHello(line, "synthetic-version", helloByteCount)
		if err != nil {
			if hello != nil || code == "" {
				t.Fatal("a refusal with a hello or without a code")
			}
			if 8 <= len(line) && strings.Contains(err.Error(), string(line)) {
				t.Fatal("the refusal repeats the line")
			}
			if bytes.Contains(line, []byte("synthetic-canary")) && strings.Contains(err.Error(), "synthetic-canary") {
				t.Fatal("the refusal repeats the canary")
			}
			return
		}
		switch hello.Mode {
		case DaemonModeMcp, DaemonModeControl, DaemonModeHook, DaemonModeGit, DaemonModeGitHook, DaemonModeSocket:
		default:
			t.Fatalf("accepted mode %q", hello.Mode)
		}
		if hello.Version != "synthetic-version" {
			t.Fatal("accepted another version")
		}
	})
}

// The only refusals ParseSidecarProject writes: its sentence, with a line number or without one.
var dotUrRefusalForm = regexp.MustCompile(`^\.ur is not the flat form ur reads(: line [0-9]+)?$`)

// §22.6 and §5.8: a committed .ur is hostile input. No file panics the parser, a refusal is its sentence and a line
// number and echoes nothing, and an accepted file holds only values of its keys' forms. D-CORE-18 on what it holds: its
// claims never widens a session past the member's value without a confirmation, a narrower one applies at once, and
// its project is the label the project's runs announce.
func FuzzDotUr(f *testing.F) {
	f.Add([]byte("network = \"k7q2m9\"\nagent = \"api-refactor\"\n"))
	f.Add([]byte("# comment\nnetwork = \"k7q2m9\" # trailing\r\nclaims = \"prompt\"\nproject = \"billing-api\"\n"))
	f.Add([]byte("claims = \"auto\"\n"))
	f.Add([]byte("claims = \"off\"\nproject = \"billing-api\"\n"))
	f.Add([]byte("claims = \"wide\"\n"))
	f.Add([]byte("network = 'k7q2m9'\n"))
	f.Add([]byte("[table]\nsecret = \"synthetic-canary\"\n"))
	f.Add([]byte("network = \"\\u006b\"\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, content []byte) {
		project, err := ParseSidecarProject(content)
		if err != nil {
			if project != nil || !errors.Is(err, ErrSidecarProjectMalformed) || !dotUrRefusalForm.MatchString(err.Error()) {
				t.Fatalf("a refusal of another form: %v", err)
			}
			return
		}
		if project.Network != "" && !isDnsLowerLdhLabel(project.Network) {
			t.Fatal("accepted a network that is no label")
		}
		for _, label := range []string{project.Agent, project.Project} {
			if label == "" {
				continue
			}
			if _, err := ParseSidecarAgent(label); err != nil {
				t.Fatal("accepted a label of another form")
			}
		}
		switch project.Claims {
		case "", "off", "prompt", "auto":
		default:
			t.Fatal("accepted a claims value of another form")
		}
		committed := SidecarClaims(0)
		if project.Claims != "" {
			var err error
			if committed, err = ParseSidecarClaims(project.Claims); err != nil {
				t.Fatal("an accepted claims value does not parse")
			}
		}
		for _, base := range []SidecarClaims{SidecarClaimsOff, SidecarClaimsPrompt, SidecarClaimsAuto} {
			resolution := ResolveSidecarClaims(&SidecarClaimsInputs{Team: true, TeamDefault: base, Committed: committed})
			if base < resolution.Claims {
				t.Fatalf(".ur's %s widened %s unconfirmed to %s", committed, base, resolution.Claims)
			}
			if committed.Known() && committed <= base && resolution.Claims != committed {
				t.Fatalf(".ur's narrower %s did not apply over %s", committed, base)
			}
			if (resolution.Pending != 0) != (committed.Known() && base < committed) {
				t.Fatalf(".ur's %s over %s pending %s", committed, base, resolution.Pending)
			}
		}
		if label := project.ProjectLabel(&SidecarProjectTree{TopLevel: "/synthetic/work"}); project.Project != "" && label != project.Project {
			t.Fatal("the label is not .ur's project")
		}
		if bytes.Contains(content, []byte("synthetic-canary")) && strings.Contains(project.Network+project.Agent+project.Project, "synthetic-canary") {
			t.Fatal("a key outside the form was read")
		}
	})
}
