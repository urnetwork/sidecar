//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// The search tools as a test scripts them: the result a search answers, the env and arguments it was called with, and
// the hits a session opens.
type harnessTestSearch struct {
	result *SearchToolResult
	// called inside Search with the env, as SearchTools runs the env's taint, fence and admit
	during func(env *SearchToolEnv) error

	stateLock sync.Mutex
	envs      []*SearchToolEnv
	args      []*SearchToolArgs
	// hits by session and id
	sessionHits map[Id]map[string]*SearchHitRef
}

func (self *harnessTestSearch) Search(ctx context.Context, env *SearchToolEnv, args *SearchToolArgs) (*SearchToolResult, error) {
	self.stateLock.Lock()
	self.envs = append(self.envs, env)
	copied := *args
	self.args = append(self.args, &copied)
	during := self.during
	self.stateLock.Unlock()
	if during != nil {
		if err := during(env); err != nil {
			return nil, err
		}
	}
	return self.result, nil
}

func (self *harnessTestSearch) OpenHit(session Id, hitId string) (*SearchHitRef, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	ref, ok := self.sessionHits[session][hitId]
	if !ok {
		return nil, ErrSearchHitUnknown
	}
	return ref, nil
}

// The Harness's search answers SearchTools.Search's result as MCP's search tool does: the same arguments, decoded from
// the same JSON into SearchToolArgs and passed whole; the same data, the result whole in the envelope's data; the
// envelope's source search and its trust member where the result shows a member's data; the env's session the run's
// own, its fence MCP's markers, its taint the run's, write-ahead, and its admit the guard on each hit's whole path.
func TestHarnessSearchMatchesMcpResults(t *testing.T) {
	network := newHarnessTestNetwork()
	mailboxId, _ := network.addRepo(protocol.RepoKind_REPO_KIND_MAILBOX)
	repoId, _ := network.addRepo(protocol.RepoKind_REPO_KIND_GENERAL)
	want := &SearchToolResult{
		Hits: []*SearchToolHit{{HitId: "h1", RepoId: repoId.String(), Network: testNetworkId.String(), Doc: SearchToolDoc{Type: "file", Key: "00"},
			Version: 3, Match: "confirmed", By: "text", Partition: "current", Trust: "member", Source: "index", Snippet: "the plan",
			Open: &SearchToolOpen{Tool: "evs_read", Arguments: map[string]any{"repo": repoId.String(), "path": "plan.md", "version": float64(3)}}}},
		Coverage: []*SearchToolCoverage{{RepoId: repoId.String(), State: "searched"}},
		Counts:   SearchToolCounts{Confirmed: 1, Repos: 1},
		Status:   SearchToolStatus{Complete: true, Trust: "member"},
	}
	search := &harnessTestSearch{result: want}
	network.search = search
	world := newHarnessDesignTestWorld(t, network, nil, nil)
	arguments := `{"query":"plan","repos":["` + repoId.String() + `"],"filters":{"path_prefix":"docs/","kind":["file"]},"group_by":"none","limit":5,"wait_ms":100}`
	result, err := world.call(t, HarnessToolSearch, arguments)
	if err != nil {
		t.Fatal(err)
	}
	mcpArgs := &SearchToolArgs{}
	if err := json.Unmarshal([]byte(arguments), mcpArgs); err != nil {
		t.Fatal(err)
	}
	gotArgs, _ := json.Marshal(search.args[0])
	wantArgs, _ := json.Marshal(mcpArgs)
	if string(gotArgs) != string(wantArgs) {
		t.Fatalf("the arguments: %s, MCP's %s", gotArgs, wantArgs)
	}
	envelope := harnessDesignTestEnvelope(t, result, nil)
	wantData, _ := json.Marshal(want)
	if string(envelope.Data) != string(wantData) || envelope.Source != "search" || envelope.Trust != harnessDesignTrustMember ||
		result.Trust != HarnessToolTrusted || world.run.Tainted() {
		t.Fatalf("the envelope: %+v\n data %s\n want %s", envelope, envelope.Data, wantData)
	}
	env := search.envs[0]
	if env.Session != world.run.Id() || env.Fence("x") != HarnessUntrustedBegin+"\nx\n"+HarnessUntrustedEnd {
		t.Fatalf("the env's session %s, fence %q", env.Session, env.Fence("x"))
	}
	if env.Admit(mailboxId, "vault/ab/entry") || env.Admit(mailboxId, "vault") || !env.Admit(repoId, "docs/plan.md") {
		t.Fatalf("the env's admit does not hold the guard")
	}

	// include: the env's taint lands, fsynced, before the search keeps untrusted text, and the result is untrusted
	search.during = func(env *SearchToolEnv) error {
		if err := env.Taint(context.Background()); err != nil {
			return err
		}
		if !world.run.Tainted() {
			return errors.New("the taint had not landed")
		}
		env.Fence("an outsider's words")
		return nil
	}
	tainted := *want
	tainted.Status.Tainted, tainted.Status.Trust = true, "untrusted"
	search.result = &tainted
	result, err = world.call(t, HarnessToolSearch, `{"query":"plan","untrusted":"include"}`)
	if err != nil {
		t.Fatal(err)
	}
	if envelope := harnessDesignTestEnvelope(t, result, nil); envelope.Trust != harnessDesignTrustUntrusted || result.Trust != HarnessToolUntrusted || !world.run.Tainted() {
		t.Fatalf("an include: %+v", envelope)
	}
}

// The guard runs on a search's named repos and path_prefix before the search does, and §8's read on each: a mailbox's
// vault/ prefix and a secret repo are refused, and a repo the sidecar may not read is refused, none reaching the
// engine; an argument outside SearchToolArgs is refused with constant text.
func TestHarnessSearchGuardsNamedRepos(t *testing.T) {
	network := newHarnessTestNetwork()
	mailboxId, _ := network.addRepo(protocol.RepoKind_REPO_KIND_MAILBOX)
	secretId, _ := network.addRepo(protocol.RepoKind_REPO_KIND_SECRET)
	closedId, _ := network.addRepo(protocol.RepoKind_REPO_KIND_GENERAL)
	network.refused[protocol.AclAction_ACL_ACTION_READ] = map[Id]bool{closedId: true}
	search := &harnessTestSearch{result: &SearchToolResult{}}
	network.search = search
	world := newHarnessDesignTestWorld(t, network, nil, nil)
	for _, test := range []struct {
		args string
		row  string
	}{
		{args: `{"query":"x","repos":["` + mailboxId.String() + `"],"filters":{"path_prefix":"vault/"}}`, row: harnessGuardRowMailboxVault},
		{args: `{"query":"x","repos":["` + secretId.String() + `"]}`, row: harnessGuardRowSecret},
	} {
		_, err := world.call(t, HarnessToolSearch, test.args)
		if row := harnessDesignTestRow(t, err); row != test.row {
			t.Fatalf("%s: row %q", test.args, row)
		}
	}
	if _, err := world.call(t, HarnessToolSearch, `{"query":"x","repos":["`+closedId.String()+`"]}`); !errors.Is(err, errHarnessDesignNotAllowed) {
		t.Fatalf("an unreadable repo: %v", err)
	}
	if _, err := world.call(t, HarnessToolSearch, `{"query":"x","network":"`+testNetworkId.String()+`"}`); !errors.Is(err, errHarnessSearchArguments) ||
		strings.Contains(err.Error(), testNetworkId.String()) {
		t.Fatalf("an unknown argument: %v", err)
	}
	if len(search.envs) != 0 {
		t.Fatalf("a refused search reached the engine")
	}
}

// A hit opens only in the run whose search named it: evs_read by a file's hit reads what it names, a hit standing
// with its arguments is refused, and another run's hit id opens nothing.
func TestHarnessSearchHitOpensInItsRunOnly(t *testing.T) {
	network := newHarnessTestNetwork()
	repoId, repo := network.addRepo(protocol.RepoKind_REPO_KIND_GENERAL)
	repo.put("plan.md", "the plan", network.identity.SidecarId, &EvsPushProvenance{State: EvsProvenanceUnattributed})
	search := &harnessTestSearch{result: &SearchToolResult{}, sessionHits: map[Id]map[string]*SearchHitRef{}}
	network.search = search
	world := newHarnessDesignTestWorld(t, network, nil, nil)
	search.sessionHits[world.run.Id()] = map[string]*SearchHitRef{"h1": {RepoId: repoId, Path: "plan.md", DocKind: int(IndexDocFile)}}
	result, err := world.call(t, HarnessToolEvsRead, `{"hit":"h1"}`)
	if err != nil {
		t.Fatal(err)
	}
	out := &harnessEvsReadOut{}
	harnessDesignTestEnvelope(t, result, out)
	if out.Content != "the plan" || out.Path != "plan.md" {
		t.Fatalf("the hit's file: %+v", out)
	}
	if _, err := world.call(t, HarnessToolEvsRead, `{"hit":"h1","path":"plan.md"}`); !errors.Is(err, errHarnessHitAlone) {
		t.Fatalf("a hit with its arguments: %v", err)
	}
	other, err := NewHarnessRun(context.Background(), &HarnessRunArgs{RunId: NewId(), AgentId: NewId(), Runs: world.runs})
	if err != nil {
		t.Fatal(err)
	}
	world.run = other
	if _, err := world.call(t, HarnessToolEvsRead, `{"hit":"h1"}`); !errors.Is(err, errHarnessHitUnknown) {
		t.Fatalf("another run's hit: %v", err)
	}
}
