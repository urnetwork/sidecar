// The stdio relay and production MCP catalog over a hosted, admitted Sidecar with a verified config follower.
package main

import (
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mcp"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest/enginenet"
)

// A relay can read the verified team and ACL state. The same session observes a denied repo and follower shutdown.
func TestUrMcpChecksTheHostedNetworksStandingPolicy(t *testing.T) {
	world := newTestUrFollowWorld(t, 1)
	network := world.networks[0]
	// Another device creates this ordinary repo and grants the hosted device no access.
	deniedRepo := sidecar.NewEvsRepoId()
	network.MustLand(network.Sign(network.Owner(), bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
		Header: network.Header(), RepoId: deniedRepo.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
	}))
	// The personal starter otherwise grants every member every general repo.
	network.SaveAclPolicy([]byte(`{"grants": []}`), nil)
	engines := enginenet.NewEngines(t, world.net, nil)
	engines.OpenNetwork(network.NetworkId())
	running := world.host(network, nil)
	world.standing(running, network)
	if err := engines.Sync(world.ctx, network.NetworkId()); err != nil {
		t.Fatal(err)
	}
	gkm, err := urDaemonGkmClient(running)
	if err != nil {
		t.Fatal(err)
	}
	repoId, err := engines.CreateRepo(world.ctx, &enginenet.CreateRepoArgs{Sidecar: running, Gkm: gkm, Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	if err != nil {
		t.Fatal(err)
	}
	evs, err := urNetworkEvsClient(running)
	if err != nil {
		t.Fatal(err)
	}
	const fileText = "MCP reads this fixture through the attached EVS client."
	marker := "ur_sk_" + strings.Repeat("Q7", 20)
	history := strings.Repeat("Ordinary retained project text. ", 320)
	repo := evs.Repo(repoId)
	write, err := repo.WritePaths(world.ctx, &sidecar.EvsWritePathsArgs{Writes: []*sidecar.EvsPathWrite{
		{Path: "README", Content: strings.NewReader(fileText)},
		{Path: "sample", Content: strings.NewReader(marker)},
		{Path: "history", Content: strings.NewReader(history)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		if err := daemon.AddSidecar(network.NetworkId(), running); err != nil {
			t.Fatal(err)
		}
		settings := mcp.NewMcpServerSettings(sidecar.DefaultSidecarSettings(), sidecar.Version)
		settings.Mcp.ResultByteCount = 8 * 1024
		server := mcp.NewMcpServer(mcp.DaemonOf(daemon), settings)
		mcp.NewDaemonMcpCatalog(server, nil).Install(server)
		mcp.NewDaemonMcpResources(world.ctx, server).Install()
		if err := daemon.RegisterMode(sidecar.DaemonModeMcp, server.Serve); err != nil {
			t.Fatal(err)
		}
	})
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	input, send := io.Pipe()
	receive, output := io.Pipe()
	cli.stdin, cli.stdout = input, output
	finished := make(chan int, 1)
	go func() {
		code := cli.main(world.ctx, []string{"ur", "mcp"})
		input.Close()
		output.Close()
		finished <- code
	}()
	defer func() {
		send.Close()
		io.Copy(io.Discard, receive)
		receive.Close()
		if code := <-finished; code != urExitOk {
			t.Errorf("relay exit %d: %s", code, stderr.String())
		}
	}()
	encoder, decoder := json.NewEncoder(send), json.NewDecoder(receive)
	nextId := 0
	call := func(method string, params map[string]any) (json.RawMessage, string) {
		t.Helper()
		nextId++
		if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": nextId, "method": method, "params": params}); err != nil {
			t.Fatal(err)
		}
		for {
			var response struct {
				Id     int             `json:"id"`
				Result json.RawMessage `json:"result"`
				Error  struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := decoder.Decode(&response); err != nil {
				t.Fatal(err)
			}
			if response.Id == nextId {
				return response.Result, response.Error.Message
			}
		}
	}
	if _, failure := call("initialize", map[string]any{
		"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test", "version": "1"},
	}); failure != "" {
		t.Fatal(failure)
	}
	if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		t.Fatal(err)
	}
	tool := func(name string, arguments map[string]any) (json.RawMessage, string) {
		return call("tools/call", map[string]any{"name": name, "arguments": arguments})
	}
	members, failure := tool("team_members", map[string]any{})
	if failure != "" || !strings.Contains(string(members), network.Owner().MemberId.String()) {
		t.Fatalf("verified membership: %s %s", members, failure)
	}
	listed, failure := tool("evs_repos", map[string]any{})
	if failure != "" || !strings.Contains(string(listed), network.ConfigRepoId().String()) || strings.Contains(string(listed), deniedRepo.String()) {
		t.Fatalf("readable repos: %s %s", listed, failure)
	}
	check := func(repoId sidecar.Id, want bool) {
		t.Helper()
		result, failure := tool("acl_check", map[string]any{"action": "read", "resource": "evs:" + repoId.String()})
		var answer struct {
			Content struct {
				Data struct {
					Allowed *bool `json:"allowed"`
				} `json:"data"`
			} `json:"structuredContent"`
		}
		if failure != "" || json.Unmarshal(result, &answer) != nil || answer.Content.Data.Allowed == nil || *answer.Content.Data.Allowed != want {
			t.Fatalf("read of %s: %s %s", repoId, result, failure)
		}
	}
	check(network.ConfigRepoId(), true)
	check(deniedRepo, false)
	if _, failure := tool("evs_read", map[string]any{"repo": deniedRepo.String(), "path": "README"}); !strings.Contains(failure, "does not allow") {
		t.Fatalf("ungranted file: %q", failure)
	}
	file, failure := tool("evs_read", map[string]any{"repo": repoId.String(), "path": "README"})
	if failure != "" || !strings.Contains(string(file), fileText) {
		t.Fatalf("readable file: %s %s", file, failure)
	}
	if _, failure := tool("evs_read", map[string]any{"repo": repoId.String(), "path": "sample"}); !strings.Contains(failure, "holds a credential") || strings.Contains(failure, marker) {
		t.Fatal("file read did not withhold the synthetic token")
	}
	if _, failure := tool("evs_write", map[string]any{"repo": repoId.String(), "path": "AGENTS.md", "base_version": 0, "content": marker}); !strings.Contains(failure, "reads as a secret") || strings.Contains(failure, marker) {
		t.Fatal("shared agent configuration did not return a redacted scanner refusal")
	}
	const note = "A shared note from the MCP fixture."
	if _, failure := tool("evs_write", map[string]any{"repo": repoId.String(), "path": "notes", "base_version": 0, "content": note}); failure != "" {
		t.Fatalf("ordinary shared write: %q", failure)
	}
	if written, failure := tool("evs_read", map[string]any{"repo": repoId.String(), "path": "notes"}); failure != "" || !strings.Contains(string(written), note) {
		t.Fatalf("ordinary shared write readback: %s %s", written, failure)
	}
	if _, failure := tool("evs_read", map[string]any{"repo": repoId.String(), "path": "rcpt/sample"}); !strings.Contains(failure, "approved-recipient") {
		t.Fatalf("unclassified recipient directory: %q", failure)
	}
	if _, failure := tool("evs_read", map[string]any{"repo": network.ConfigRepoId().String(), "path": "policy"}); !strings.Contains(failure, "config repo") {
		t.Fatalf("protected config read: %q", failure)
	}
	historical, failure := tool("evs_read", map[string]any{"repo": repoId.String(), "path": "history", "version": write.PathVersions[2]})
	var link struct {
		Content []struct{ Type, Uri string } `json:"content"`
	}
	if failure != "" || json.Unmarshal(historical, &link) != nil || len(link.Content) != 1 || link.Content[0].Type != "resource_link" || link.Content[0].Uri == "" {
		t.Fatalf("historical resource link: %s %s", historical, failure)
	}
	if _, err := repo.Write(world.ctx, &sidecar.EvsWriteArgs{Path: "history", Remove: true}); err != nil {
		t.Fatal(err)
	}
	resource, failure := call("resources/read", map[string]any{"uri": link.Content[0].Uri})
	if failure != "" || !strings.Contains(string(resource), history) {
		t.Fatalf("retained file after deletion: %s", failure)
	}
	running.ConfigFollower().Close()
	if _, failure := tool("team_members", map[string]any{}); !strings.Contains(failure, "policy") {
		t.Fatalf("membership after follower shutdown: %q", failure)
	}
}
