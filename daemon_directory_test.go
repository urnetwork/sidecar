//go:build !js && !ios && !android && !sdk_mobile_bind && !ios_extension

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What the directory's backends were asked, in order, standing in for RECORD's.
type testDirectoryBackends struct {
	stateLock sync.Mutex
	calls     []string
	taintPids []int
	taintErr  error
	items     []*DirectoryItem
}

func (self *testDirectoryBackends) record(call string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls = append(self.calls, call)
}

func (self *testDirectoryBackends) recorded() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.calls...)
}

func (self *testDirectoryBackends) backends() *DaemonDirectoryBackends {
	return &DaemonDirectoryBackends{
		List: func(ctx context.Context, sidecar *Sidecar, filter *DirectoryFilter) ([]*DirectoryItem, error) {
			self.record("list")
			return self.items, nil
		},
		TaintAncestors: func(ctx context.Context, sidecar *Sidecar, pid int) error {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.calls = append(self.calls, "taint")
			self.taintPids = append(self.taintPids, pid)
			return self.taintErr
		},
		Announce: func(ctx context.Context, sidecar *Sidecar, args *DirectoryRepoAnnounceArgs) (any, error) {
			if !args.Confirmed {
				return nil, errors.New("an announcement the person did not confirm")
			}
			self.record("announce")
			return &DaemonDirectoryAnnounceReply{}, nil
		},
	}
}

// A daemon hosting one network, its directory methods over fakes.
func newTestDirectoryDaemon(t *testing.T, fakes *testDirectoryBackends, backends *DaemonDirectoryBackends) (*Daemon, Id) {
	t.Helper()
	daemon := newDispatchTestDaemon(t)
	networkId := NewId()
	if err := daemon.AddSidecar(networkId, newSidecarBase(nil, cheapKeychainSettings())); err != nil {
		t.Fatal(err)
	}
	for _, method := range DaemonDirectoryMethods(daemon, backends) {
		if err := daemon.RegisterMethod(method); err != nil {
			t.Fatal(err)
		}
	}
	return daemon, networkId
}

// One request line in mode, from a caller whose process the system reports as pid.
func dispatchDirectoryTest(daemon *Daemon, mode string, pid int, line string) *daemonRpcResponse {
	hello := &DaemonHello{UrLocal: 1, Mode: mode, Version: "synthetic-version", PeerPid: int64(pid)}
	return daemon.dispatch([]byte(line), &daemonSession{hello: hello}, runUnbounded)
}

// D-CORE-13, §16.11's signing row: announcing, revoking, approving, denying, erasing and a wider claims value are
// Confirm methods, refused from mcp, hook and an unconfirmed control call before their backends see anything; a
// confirmed control call reaches them, and an act whose backend has not landed refuses, signing nothing.
func TestDirectoryActsRefusedFromMcp(t *testing.T) {
	fakes := &testDirectoryBackends{}
	daemon, _ := newTestDirectoryDaemon(t, fakes, fakes.backends())
	repoId, requestId := NewId(), NewId()
	acts := map[string]string{
		DaemonMethodDirectoryAnnounce:      `{"repo_id":"` + repoId.String() + `"}`,
		DaemonMethodDirectoryRevoke:        `{"repo_id":"` + repoId.String() + `"}`,
		DaemonMethodDirectoryApprove:       `{"request_id":"` + requestId.String() + `"}`,
		DaemonMethodDirectoryDeny:          `{"request_id":"` + requestId.String() + `","note":"synthetic"}`,
		DaemonMethodDirectoryErase:         `{"id":"` + requestId.String() + `"}`,
		DaemonMethodDirectoryClaimsConfirm: `{"claims":"auto"}`,
	}
	for _, method := range DaemonDirectoryMethods(daemon, nil) {
		_, act := acts[method.Name]
		if act != method.Confirm {
			t.Errorf("%s: Confirm %v", method.Name, method.Confirm)
		}
		if !method.Network {
			t.Errorf("%s acts on no network", method.Name)
		}
	}
	for name, params := range acts {
		for _, c := range []struct {
			mode      string
			confirmed bool
		}{
			{mode: DaemonModeMcp, confirmed: true},
			{mode: DaemonModeHook, confirmed: true},
			{mode: DaemonModeControl, confirmed: false},
		} {
			line := `{"jsonrpc":"2.0","id":1,"method":"` + name + `","params":` + params
			if c.confirmed {
				line += `,"ur_confirmed":true`
			}
			line += `}`
			if response := dispatchDirectoryTest(daemon, c.mode, 0, line); response.Error == nil || response.Error.Code != DaemonRpcConfirmationRequired {
				t.Errorf("%s from %s (confirmed %v): %+v", name, c.mode, c.confirmed, response.Error)
			}
		}
	}
	if calls := fakes.recorded(); len(calls) != 0 {
		t.Fatalf("a refused act reached its backend: %v", calls)
	}

	// confirmed from control: the announcement reaches its backend; the acts still to land refuse, signing nothing
	confirmed := func(name string) *daemonRpcResponse {
		return dispatchDirectoryTest(daemon, DaemonModeControl, 0, `{"jsonrpc":"2.0","id":2,"method":"`+name+`","params":`+acts[name]+`,"ur_confirmed":true}`)
	}
	if response := confirmed(DaemonMethodDirectoryAnnounce); response.Error != nil {
		t.Fatalf("a confirmed announcement: %+v", response.Error)
	}
	for _, name := range []string{DaemonMethodDirectoryRevoke, DaemonMethodDirectoryApprove, DaemonMethodDirectoryDeny, DaemonMethodDirectoryErase} {
		if response := confirmed(name); response.Error == nil || !strings.Contains(response.Error.Message, "not built yet") {
			t.Errorf("%s with no backend: %+v", name, response.Error)
		}
	}
	if calls := fakes.recorded(); len(calls) != 1 || calls[0] != "announce" {
		t.Fatalf("the backends saw %v", calls)
	}

	// a backend that lands is reached with the person's decision
	decided := []*DirectoryDecideArgs{}
	backends := fakes.backends()
	backends.Decide = func(ctx context.Context, sidecar *Sidecar, args *DirectoryDecideArgs) (any, error) {
		decided = append(decided, args)
		return nil, nil
	}
	withDecide, _ := newTestDirectoryDaemon(t, fakes, backends)
	if response := dispatchDirectoryTest(withDecide, DaemonModeControl, 0, `{"jsonrpc":"2.0","id":3,"method":"directory.deny","params":`+acts[DaemonMethodDirectoryDeny]+`,"ur_confirmed":true}`); response.Error != nil {
		t.Fatalf("a confirmed denial: %+v", response.Error)
	}
	if len(decided) != 1 || decided[0].Approve || decided[0].RequestId != requestId || decided[0].Note != "synthetic" {
		t.Fatalf("the decision: %+v", decided)
	}
}

// §5.8: a control-mode listing returns stubs, no prose, unless the call asks for untrusted text, and then first taints
// each run whose harness process is the caller's ancestor; a taint that fails fails the call and returns nothing.
func TestListingTaintsAncestorRun(t *testing.T) {
	announcement := &protocol.Announcement{
		Kind:  uint32(DirectoryAnnouncementKindRun),
		What:  &protocol.AnnounceWhat{Title: "synthetic-canary title", Description: "synthetic-canary description"},
		Where: &protocol.AnnounceWhere{Project: "billing-api", Branch: "main"},
	}
	fakes := &testDirectoryBackends{items: []*DirectoryItem{{
		Key:          DirectoryItemKey{Kind: DirectoryAnnouncementKindRun, AnnouncementId: NewId()},
		Announcement: announcement,
		Display:      DirectoryItemActive,
		Matches:      []string{"what.title"},
	}}}
	daemon, _ := newTestDirectoryDaemon(t, fakes, fakes.backends())
	const pid = 4242

	response := dispatchDirectoryTest(daemon, DaemonModeControl, pid, `{"jsonrpc":"2.0","id":1,"method":"directory.list","params":{"query":"canary"}}`)
	reply := &DaemonDirectoryListReply{}
	if response.Error != nil || json.Unmarshal(response.Result, reply) != nil || reply.Untrusted || len(reply.Items) != 1 {
		t.Fatalf("the stubs: %+v %s", response.Error, response.Result)
	}
	if strings.Contains(string(response.Result), "synthetic-canary") || reply.Withheld != 2 {
		t.Fatalf("a stub held prose, withheld %d: %s", reply.Withheld, response.Result)
	}
	stub := &protocol.Announcement{}
	if err := protojson.Unmarshal(reply.Items[0].Announcement, stub); err != nil || stub.GetWhere().GetProject() != "billing-api" ||
		len(reply.Items[0].Matches) != 1 || reply.Items[0].Matches[0] != "what.title" {
		t.Fatalf("a stub's identifier fields and match label: %v %+v", err, reply.Items[0])
	}
	if calls := fakes.recorded(); len(calls) != 1 || calls[0] != "list" {
		t.Fatalf("a stub listing tainted: %v", calls)
	}
	// the item the backend holds is left whole
	if announcement.GetWhat().GetTitle() == "" {
		t.Fatal("the stub emptied the fold's own item")
	}

	// untrusted text asked for: the caller's ancestor runs are tainted before any prose is returned
	response = dispatchDirectoryTest(daemon, DaemonModeHook, pid, `{"jsonrpc":"2.0","id":2,"method":"directory.list","params":{"untrusted":"include"}}`)
	if response.Error != nil || json.Unmarshal(response.Result, reply) != nil || !reply.Untrusted ||
		!strings.Contains(string(response.Result), "synthetic-canary") {
		t.Fatalf("an untrusted listing: %+v %s", response.Error, response.Result)
	}
	calls := fakes.recorded()
	if len(calls) != 3 || calls[1] != "list" || calls[2] != "taint" || len(fakes.taintPids) != 1 || fakes.taintPids[0] != pid {
		t.Fatalf("the taint: %v, pids %v", calls, fakes.taintPids)
	}

	// a caller whose process the system does not report gets no prose, whatever its hello says
	hello := &DaemonHello{UrLocal: 1, Mode: DaemonModeHook, Version: "synthetic-version", Pid: pid}
	response = daemon.dispatch([]byte(`{"jsonrpc":"2.0","id":5,"method":"directory.list","params":{"untrusted":"include"}}`), &daemonSession{hello: hello}, runUnbounded)
	if response.Error == nil || response.Result != nil || len(fakes.taintPids) != 1 {
		t.Fatalf("an unread caller got prose: %+v %s", response.Error, response.Result)
	}

	fakes.taintErr = errors.New("synthetic fsync failure")
	response = dispatchDirectoryTest(daemon, DaemonModeControl, pid, `{"jsonrpc":"2.0","id":3,"method":"directory.list","params":{"untrusted":"include"}}`)
	if response.Error == nil || response.Result != nil || strings.Contains(response.Error.Message, "synthetic-canary") {
		t.Fatalf("a failed taint answered: %+v %s", response.Error, response.Result)
	}

	// with no fakes, a network with no directory refuses
	plain, _ := newTestDirectoryDaemon(t, fakes, nil)
	if response := dispatchDirectoryTest(plain, DaemonModeControl, pid, `{"jsonrpc":"2.0","id":4,"method":"directory.list"}`); response.Error == nil ||
		!strings.Contains(response.Error.Message, ErrDirectoryNone.Error()) {
		t.Fatalf("a network with no directory: %+v", response.Error)
	}
}

// A gate that records what Authorize handed it and answers err.
type testAccessGate struct {
	actions []*SidecarAction
	err     error
}

func (self *testAccessGate) Authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error {
	self.actions = append(self.actions, action)
	return self.err
}

// §16.11's endorse row: a directory request passes §5.4's gate as a version-3 access_request, its stored bytes what
// the gate judges; any other kind or version, or bytes that say otherwise, is refused before a gate sees it, and while
// approvers know no version 3 its builder refuses every such action.
func TestAccessRequestPassesTheGate(t *testing.T) {
	sidecar := newSidecarBase(nil, cheapKeychainSettings())
	gate := &testAccessGate{}
	sidecar.InstallGate(gate)
	worker := NewId()
	// the worker alone in the clear, its port and the port's text sealed (QD-740)
	workerDst := "sidecar:" + strings.ReplaceAll(worker.String(), "-", "")
	action := &protocol.CanonicalAction{
		Kind:            uint32(SidecarActionAccessRequest),
		Version:         3,
		GrantDst:        []string{workerDst},
		GrantAllow:      []string{"dial"},
		TargetSidecarId: worker.Bytes(),
		Subject:         NewId().Bytes(),
		SealedDetail:    testSealActionDetail(&protocol.CanonicalActionDetail{TargetPort: 22, GrantDst: []string{workerDst + ":tcp:22"}}),
	}
	stored, err := proto.Marshal(action)
	if err != nil {
		t.Fatal(err)
	}
	runId, agentId := NewId(), NewId()
	if err := sidecar.AuthorizeAccessRequest(context.Background(), &StoredCanonicalAction{Action: action, Bytes: stored},
		SidecarRiskNormal, SidecarRiskHigh, &runId, &agentId, nil); err != nil {
		t.Fatal(err)
	}
	if len(gate.actions) != 1 || gate.actions[0].Kind != SidecarActionAccessRequest || string(gate.actions[0].Canonical) != string(stored) ||
		gate.actions[0].Risk != SidecarRiskHigh || *gate.actions[0].RunId != runId || *gate.actions[0].AgentId != agentId {
		t.Fatalf("the gate saw %+v", gate.actions)
	}

	// pending: approval_pending is raised with its id
	events := []SidecarEvent{}
	var eventsLock sync.Mutex
	sidecar.AddEventCallback(func(event SidecarEvent) {
		eventsLock.Lock()
		defer eventsLock.Unlock()
		events = append(events, event)
	})
	approvalId := NewId()
	gate.err = &ApprovalPendingError{ApprovalId: approvalId}
	pending := &ApprovalPendingError{}
	if err := sidecar.AuthorizeAccessRequest(context.Background(), &StoredCanonicalAction{Action: action, Bytes: stored},
		SidecarRiskNormal, SidecarRiskNormal, &runId, &agentId, nil); !errors.As(err, &pending) || pending.ApprovalId != approvalId {
		t.Fatalf("a pending request: %v", err)
	}

	gate.actions = nil
	other := proto.Clone(action).(*protocol.CanonicalAction)
	other.Kind = uint32(SidecarActionMail)
	otherBytes, _ := proto.Marshal(other)
	version1 := proto.Clone(action).(*protocol.CanonicalAction)
	version1.Version = 1
	version1Bytes, _ := proto.Marshal(version1)
	for name, refused := range map[string]*StoredCanonicalAction{
		"another kind":             {Action: other, Bytes: otherBytes},
		"version 1":                {Action: version1, Bytes: version1Bytes},
		"bytes that say otherwise": {Action: action, Bytes: otherBytes},
		"no bytes":                 {Action: action},
	} {
		if err := sidecar.AuthorizeAccessRequest(context.Background(), refused, SidecarRiskNormal, SidecarRiskNormal, nil, nil, nil); !errors.Is(err, ErrSidecarActionInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(gate.actions) != 0 {
		t.Fatalf("a refused action reached the gate: %+v", gate.actions)
	}

	// fail closed until approvers know version 3 (MCP-M6-01)
	if _, err := NewCanonicalAction(action); !CanonicalActionVersionKnown(3) && !errors.Is(err, ErrCanonicalActionVersionUnknown) {
		t.Fatalf("the builder made a version-3 action approvers cannot render: %v", err)
	}
}

// access_request, access_decided and directory_erasure name their request, and the erasure its repo, with only the
// outcomes §5.4 gives; anything else is refused and raises nothing.
func TestDirectoryEventsNameTheirRequest(t *testing.T) {
	sidecar := newSidecarBase(nil, cheapKeychainSettings())
	received := make(chan SidecarEvent, 8)
	sidecar.AddEventCallback(func(event SidecarEvent) {
		received <- event
	})
	requestId, repoId := NewId(), NewId()
	if err := sidecar.RaiseAccessRequest(requestId); err != nil {
		t.Fatal(err)
	}
	if event := <-received; event.Kind != SidecarEventAccessRequest || *event.RequestId != requestId {
		t.Fatalf("access_request: %+v", event)
	}
	for _, outcome := range []string{SidecarAccessDecidedApproved, SidecarAccessDecidedDenied, SidecarAccessDecidedCancelled, SidecarAccessDecidedExpired} {
		if err := sidecar.RaiseAccessDecided(requestId, outcome); err != nil {
			t.Fatal(err)
		}
		if event := <-received; event.Kind != SidecarEventAccessDecided || *event.RequestId != requestId || event.Outcome != outcome {
			t.Fatalf("access_decided: %+v", event)
		}
	}
	if err := sidecar.RaiseDirectoryErasure(repoId, requestId, SidecarDirectoryErasurePending); err != nil {
		t.Fatal(err)
	}
	if event := <-received; event.Kind != SidecarEventDirectoryErasure || *event.RepoId != repoId || *event.RequestId != requestId || event.Outcome != "pending" {
		t.Fatalf("directory_erasure: %+v", event)
	}
	for name, err := range map[string]error{
		"no request":         sidecar.RaiseAccessRequest(Id{}),
		"another outcome":    sidecar.RaiseAccessDecided(requestId, "pending"),
		"no repo":            sidecar.RaiseDirectoryErasure(Id{}, requestId, SidecarDirectoryErasureDone),
		"an erasure outcome": sidecar.RaiseDirectoryErasure(repoId, requestId, SidecarAccessDecidedApproved),
	} {
		if !errors.Is(err, ErrSidecarEventInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	select {
	case event := <-received:
		t.Fatalf("a refused event was raised: %+v", event)
	default:
	}
}
