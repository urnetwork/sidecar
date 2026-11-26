//go:build !js && !ios && !android && !sdk_mobile_bind

package mcp

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Until G-SUP-service passes the release's switch is off, and no session lists a support tool or the resource (§28.21).
func TestSupportToolsStayUnlistedWhileTheReleaseSwitchIsOff(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	server := newTestMcpServer(newFakeMcpDaemon(), clock)
	catalog := NewDaemonMcpCatalog(server, nil)
	for _, name := range []string{"support_send", "support_list", "support_read"} {
		if slices.Contains(catalog.Names(), name) {
			t.Errorf("%s is listed with the switch off", name)
		}
		if !slices.Contains(mcpCatalogUnbuilt, name) {
			t.Errorf("%s is not listed unbuilt", name)
		}
	}
	if err := checkMcpCatalog(catalog); err != nil {
		t.Error(err)
	}
	resources := NewMcpResources(t.Context(), server)
	for _, registration := range mcpResourceRegistrations.registrations {
		registration(resources, server)
	}
	if slices.Contains(resources.Templates(), mcpSupportResourceUri) {
		t.Error("the support resource is listed with the switch off")
	}
}

// With the switch on, each tool registers at its row's tier: support_send outward over MCP (Q-SUP-8), the reads R.
func TestSupportToolsRegisterAtTheirRowsWithTheSwitchOn(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	server := newTestMcpServer(newFakeMcpDaemon(), clock)
	server.settings.Support = sidecar.DefaultSupportSettings()
	server.settings.Support.ServiceEnabled = true
	catalog := NewDaemonMcpCatalog(server, nil)
	registered := map[string]*mcpCatalogTool{}
	for _, tool := range catalog.sorted() {
		registered[tool.tool.Name] = tool
	}
	for _, design := range mcpCatalogDesign {
		if design.owner != "support-skill" {
			continue
		}
		tool, ok := registered[design.name]
		if !ok {
			t.Errorf("%s is not registered with the switch on", design.name)
			continue
		}
		if tool.tier != design.tier || tool.mayAct != design.mayAct || tool.multiUse {
			t.Errorf("%s registers at %s, its row %s", design.name, tool.tier, design.tier)
		}
	}
	resources := NewMcpResources(t.Context(), server)
	for _, registration := range mcpResourceRegistrations.registrations {
		registration(resources, server)
	}
	if !slices.Contains(resources.Templates(), mcpSupportResourceUri) {
		t.Error("the support resource is not listed with the switch on")
	}
}

// support_send reads its files beneath the session's worktree: its run's where a hook bound one, else the harness's
// working directory its hello names, none with neither; a name that leaves the root is refused as the tool answers a
// refusal, by its code and never a path.
func TestSupportSendReadsFilesBeneathTheSessionsWorktree(t *testing.T) {
	worktree := t.TempDir()
	if err := os.WriteFile(filepath.Join(worktree, "build.log"), []byte("step 3 failed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	call := &McpCall{Session: &McpSession{hello: sidecar.DaemonHello{Cwd: worktree}}}
	if root := mcpSupportFilesRoot(call, nil); root != worktree {
		t.Fatalf("an unbound session's root: %q", root)
	}
	if root := mcpSupportFilesRoot(call, &sidecar.RunFile{Worktree: "/run/worktree"}); root != "/run/worktree" {
		t.Fatalf("a bound run's root: %q", root)
	}
	if root := mcpSupportFilesRoot(&McpCall{}, nil); root != "" {
		t.Fatalf("a call with no session: %q", root)
	}
	settings := sidecar.DefaultSupportSettings()
	files, err := sidecar.SupportReadFiles(mcpSupportFilesRoot(call, nil), []string{"build.log"}, settings)
	if err != nil || len(files) != 1 || string(files[0].Data) != "step 3 failed\n" {
		t.Fatalf("files %+v, %v", files, err)
	}
	_, err = sidecar.SupportReadFiles(mcpSupportFilesRoot(call, nil), []string{"../" + filepath.Base(worktree) + "-elsewhere/key.pem"}, settings)
	var mcpError *McpError
	if refused := mcpSupportError(err); !errors.As(refused, &mcpError) || mcpError.Code != McpCodeRefused || mcpError.Message != string(sidecar.SupportRefusalFileRefused) {
		t.Fatalf("a name that leaves the root: %v", refused)
	}
	if _, err := sidecar.SupportReadFiles(mcpSupportFilesRoot(&McpCall{}, nil), []string{"build.log"}, settings); sidecar.SupportRefusalOf(err) != sidecar.SupportRefusalFileRefused {
		t.Fatalf("a file with no root: %v", err)
	}
}
