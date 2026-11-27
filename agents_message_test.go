//go:build !ios_extension && !sidecar_http

// AgentMessage v1 (§20.7, R2-05) against testdata/agents/message/vectors.json, which an implementation apart from this
// one wrote: each message's bytes read and written back the same, each refusal refused naming no value, a kind-24 id
// derived from its effect key, a Harness run's from its run and tool call, so a resumed run repeats it, and a support
// notice's thread and id the same on every device.

package sidecar

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// The vectors' file.
type testAgentMessageVectors struct {
	Ids []struct {
		EffectKey  string `json:"effect_key"`
		RunId      string `json:"run_id"`
		ToolCallId string `json:"tool_call_id"`
		Id         string `json:"id"`
	} `json:"ids"`
	Support []struct {
		Product string `json:"product"`
		Entry   string `json:"entry"`
		Seq     uint32 `json:"seq"`
		Thread  string `json:"thread"`
		Id      string `json:"id"`
	} `json:"support"`
	Messages []struct {
		Why   string `json:"why"`
		Bytes string `json:"bytes"`
	} `json:"messages"`
	Refused []struct {
		Why   string `json:"why"`
		Bytes string `json:"bytes"`
	} `json:"refused"`
}

func readTestAgentMessageVectors(t *testing.T) *testAgentMessageVectors {
	t.Helper()
	data, err := os.ReadFile("testdata/agents/message/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	vectors := &testAgentMessageVectors{}
	if err := json.Unmarshal(data, vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func TestAgentMessageVectors(t *testing.T) {
	vectors := readTestAgentMessageVectors(t)
	settings := DefaultSkillSettings()
	for _, vector := range vectors.Messages {
		message, err := ParseAgentMessage([]byte(vector.Bytes), settings)
		if err != nil {
			t.Errorf("%s: %v", vector.Why, err)
			continue
		}
		encoded, err := EncodeAgentMessage(message, settings)
		if err != nil {
			t.Errorf("%s: %v", vector.Why, err)
			continue
		}
		if string(encoded) != vector.Bytes {
			t.Errorf("%s: written back as\n%s\nnot\n%s", vector.Why, encoded, vector.Bytes)
		}
	}
	for _, vector := range vectors.Refused {
		_, err := ParseAgentMessage([]byte(vector.Bytes), settings)
		if !errors.Is(err, ErrAgentMessageInvalid) {
			t.Errorf("%s: %v", vector.Why, err)
			continue
		}
		if strings.Contains(err.Error(), "é") || strings.Contains(err.Error(), "act on this") {
			t.Errorf("%s: the refusal names a value: %s", vector.Why, err)
		}
	}
	// a body past 32 KiB, which no vector carries whole
	message, err := ParseAgentMessage([]byte(vectors.Messages[0].Bytes), settings)
	if err != nil {
		t.Fatal(err)
	}
	message.Body = strings.Repeat("x", settings.BodyByteCount+1)
	if _, err := EncodeAgentMessage(message, settings); !errors.Is(err, ErrAgentMessageInvalid) {
		t.Errorf("a body past its bound: %v", err)
	}
	message.Body = strings.Repeat("x", settings.BodyByteCount)
	if _, err := EncodeAgentMessage(message, settings); err != nil {
		t.Errorf("a body at its bound: %v", err)
	}
}

func TestMessageIdDerivedFromEffectKey(t *testing.T) {
	vectors := readTestAgentMessageVectors(t)
	for _, vector := range vectors.Ids {
		if vector.EffectKey == "" {
			continue
		}
		key, err := hex.DecodeString(vector.EffectKey)
		if err != nil {
			t.Fatal(err)
		}
		if got := AgentMessageIdForEffect(key).String(); got != vector.Id {
			t.Errorf("effect key %s: %s, want %s", vector.EffectKey, got, vector.Id)
		}
	}
	for _, vector := range vectors.Support {
		if got := AgentSupportThreadId(vector.Product, vector.Entry).String(); got != vector.Thread {
			t.Errorf("support thread %s: %s, want %s", vector.Entry, got, vector.Thread)
		}
		if got := AgentSupportNoticeId(vector.Product, vector.Entry, vector.Seq).String(); got != vector.Id {
			t.Errorf("support notice %s/%d: %s, want %s", vector.Entry, vector.Seq, got, vector.Id)
		}
	}
	// random ids differ
	a, err := NewAgentMessageId()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewAgentMessageId()
	if err != nil || a == b {
		t.Fatalf("two random ids: %s %s %v", a, b, err)
	}
}

func TestMessageIdRepeatsOnResume(t *testing.T) {
	vectors := readTestAgentMessageVectors(t)
	for _, vector := range vectors.Ids {
		if vector.RunId == "" {
			continue
		}
		decoded, err := hex.DecodeString(vector.RunId)
		if err != nil || len(decoded) != len(Id{}) {
			t.Fatalf("a run id: %v", err)
		}
		runId := Id(decoded)
		first := AgentMessageIdForCall(runId, vector.ToolCallId)
		// a resumed run repeats the call, so the id repeats
		if again := AgentMessageIdForCall(runId, vector.ToolCallId); again != first || first.String() != vector.Id {
			t.Errorf("run %s call %s: %s then %s, want %s", vector.RunId, vector.ToolCallId, first, again, vector.Id)
		}
		if other := AgentMessageIdForCall(runId, vector.ToolCallId+"x"); other == first {
			t.Errorf("another call of the run took the same id")
		}
	}
	args := &AgentSendArgs{RunId: testConfigId("run"), ToolCallId: "call_7"}
	first, err := agentSendMessageId(args)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := agentSendMessageId(args); again != first {
		t.Fatalf("a send's id did not repeat: %s %s", first, again)
	}
	thread, id, ok := ParseAgentMessagePath(AgentMessagePath(AgentThreadId(testConfigId("thread")), first))
	if !ok || id != first || thread != AgentThreadId(testConfigId("thread")) {
		t.Fatalf("a message path read back: %s %s %t", thread, id, ok)
	}
	for _, path := range []string{"inbox/x/y.json", "inbox/" + first.String() + ".json", "notes/" + first.String() + "/" + first.String() + ".json"} {
		if _, _, ok := ParseAgentMessagePath(path); ok {
			t.Errorf("%s read as a message path", path)
		}
	}
}
