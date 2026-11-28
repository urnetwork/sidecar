//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

package conformance

// CTEST-M12-03's replays of Codex's transcripts at its current and previous pins against the gateway in process
// (DESIGN-COMPUTE §18's gateway row, §8.3): a T2 Sidecar (sidecartest.Net's AddSidecar) hosting the root's gateway, with
// computetest.ScriptedModel behind INFER's own router, a grant made for codex and a run handle's token per session.
// Each answer holds to Codex's profile; each session's calls are recorded into a run of their own; the hosted
// web_search tool never reaches the model; and a request the gateway refuses reaches no model. The live run is
// TestConformanceLiveCodex, which reads open on a host with no codex binary.

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/computetest"
)

// A gateway over one T2 Sidecar with the scripted model behind its router, closed at the test's end.
func newTestCodexTarget(t *testing.T) (*GatewayTarget, *computetest.ScriptedModel) {
	t.Helper()
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	laptop, err := net.AddSidecar("laptop", nil)
	if err != nil {
		t.Fatal(err)
	}
	model, err := computetest.NewScriptedModel(nil)
	if err != nil {
		t.Fatal(err)
	}
	router, err := model.Router(nil)
	if err != nil {
		t.Fatal(err)
	}
	target, err := NewGatewayTarget(t.Context(), &GatewayTargetArgs{
		Sidecar:        laptop.Sidecar(),
		NetworkId:      laptop.NetworkId(),
		Router:         router,
		Harness:        HarnessCodex,
		StateDirectory: t.TempDir(),
		Script: func(ctx context.Context, session *TranscriptSession, request *TranscriptRequest) error {
			if turn := ScriptedTurnOf(request.Model); turn != nil {
				return model.Script(turn)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(target.Close)
	return target, model
}

// Replays the Codex transcript of role, and holds what the gateway did around the answers.
func testConformanceReplaysCodex(t *testing.T, role string) {
	transcripts, err := LoadTranscripts("testdata", HarnessCodex)
	if err != nil {
		t.Fatal(err)
	}
	transcript := TranscriptOfRole(transcripts, role)
	if transcript == nil {
		t.Fatalf("no %s Codex transcript", role)
	}
	target, model := newTestCodexTarget(t)
	report, err := Run(context.Background(), transcript, target.Target())
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range report.Failures() {
		t.Error(failure)
	}
	t.Logf("codex %s (%s): %d requests replayed", transcript.Manifest.Version, transcript.Manifest.Pin, len(report.Requests))

	// a request the gateway refuses reaches no model, and every scripted turn was taken
	modelled := 0
	for _, session := range transcript.Sessions {
		for _, request := range session.Requests {
			if request.Model != nil {
				modelled += 1
			}
		}
	}
	calls := model.Calls()
	if len(calls) != modelled || model.Remaining() != 0 {
		t.Fatalf("the model took %d calls, %d turns left, for %d modelled requests", len(calls), model.Remaining(), modelled)
	}
	// the hosted tools the transcript offers never reach the model (§21.7)
	dropped := []string{}
	for _, session := range transcript.Sessions {
		for _, request := range session.Requests {
			dropped = append(dropped, request.Expect.DroppedTools...)
		}
	}
	for _, call := range calls {
		for _, tool := range call.Request.Tools {
			if slices.Contains(dropped, tool.Name) {
				t.Errorf("the model received hosted tool %q", tool.Name)
			}
		}
	}

	// each session's calls are recorded into one run of its own, bound by its handle
	recorded := target.Recorded()
	sessionRunIds := map[string]sidecar.Id{}
	runSessions := map[sidecar.Id]string{}
	recordedCount := 0
	for _, session := range transcript.Sessions {
		handle := target.SessionHandle(session.Id)
		for _, call := range recorded {
			if handle == nil || call.Handle != handle.Key() {
				continue
			}
			recordedCount += 1
			if runId, ok := sessionRunIds[session.Id]; ok && runId != call.RunId {
				t.Errorf("session %s recorded into two runs", session.Id)
			}
			sessionRunIds[session.Id] = call.RunId
			if other, ok := runSessions[call.RunId]; ok && other != session.Id {
				t.Errorf("sessions %s and %s recorded into one run", other, session.Id)
			}
			runSessions[call.RunId] = session.Id
			if call.End == nil {
				t.Errorf("a call of session %s never ended its record", session.Id)
			}
		}
	}
	if recordedCount != modelled {
		t.Errorf("%d calls recorded, %d modelled", recordedCount, modelled)
	}
	// a later turn sends back the gateway's own reasoning blob, and the model receives the earlier turn's reasoning
	// from it, not the summary Codex kept beside it (§8.5's reasoning across turns)
	modelledIndex := 0
	roundTrips := 0
	for _, session := range transcript.Sessions {
		requestReasoning := map[string]string{}
		for _, request := range session.Requests {
			if request.Model == nil {
				continue
			}
			call := calls[modelledIndex]
			modelledIndex += 1
			requestReasoning[request.Name] = strings.Join(request.Model.Reasoning, "")
			body := string(request.Body)
			for name, reasoning := range requestReasoning {
				if !strings.Contains(body, transcriptPlaceholderPrefix+name+transcriptPlaceholderSuffix) {
					continue
				}
				roundTrips += 1
				found := slices.ContainsFunc(call.Request.Messages, func(message *sidecar.InferMessage) bool {
					return message.Role == sidecar.InferRoleAssistant && message.Reasoning == reasoning
				})
				if !found {
					t.Errorf("%s/%s: the model did not receive %s's reasoning back from the gateway's blob", session.Id, request.Name, name)
				}
			}
		}
	}
	if roundTrips == 0 {
		t.Error("no request sent back a reasoning blob")
	}
}

func TestConformanceReplaysCodexCurrent(t *testing.T) {
	testConformanceReplaysCodex(t, TranscriptRoleCurrent)
}

func TestConformanceReplaysCodexPrevious(t *testing.T) {
	testConformanceReplaysCodex(t, TranscriptRolePrevious)
}

// The live run against the same gateway, where UR_CONFORMANCE_HARNESS names a codex binary (§14.10's per-release
// run): it reads open on a host with none, which is never a pass, and so does not pass here.
func TestConformanceLiveCodex(t *testing.T) {
	target, model := newTestCodexTarget(t)
	token, err := target.Token(context.Background(), &TranscriptSession{Id: "0d0c0de0-0000-4000-8000-00000000ffff"})
	if err != nil {
		t.Fatal(err)
	}
	if err := model.Script(&computetest.ScriptedTurn{Text: []string{"Hello from the scripted model."}, Usage: &sidecar.InferUsage{InputTokens: 10, OutputTokens: 6}}); err != nil {
		t.Fatal(err)
	}
	result := NewLiveHarness(&LiveHarnessArgs{
		Harness:   HarnessCodex,
		BaseUrl:   target.BaseUrl(),
		Token:     token,
		Model:     computetest.ScriptedModelDefaultName,
		Prompt:    "Say hello.",
		Directory: t.TempDir(),
	}).Run(context.Background())
	switch result.Result {
	case LiveResultOpen:
		t.Skipf("open, never passed: %s", result.Reason)
	case LiveResultPass:
		t.Logf("codex %s passed against the gateway", result.Version)
	default:
		t.Fatalf("codex %s: %s\n%s", result.Version, result.Reason, result.Output)
	}
}
