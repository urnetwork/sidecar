//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension && !windows

package sidecar

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// GW-M12-03's reasoning blob (DESIGN-COMPUTE §8.5's reasoning across turns, §24.8): sealed under the network's key,
// naming the node that recorded the reasoning; opened only under that key; a foreign or forged blob ignored; and its
// text, not an edited summary's, given back to the model.

// A blob opens under its key alone and gives its node and text back; a foreign blob, OpenAI's form, a cut one and one
// under another key are ignored.
func TestReasoningBlobSealOpen(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, gatewayKeyByteCount)
	nodeId := NewId()
	blob, err := (&GatewayReasoningBlob{NodeId: nodeId, Text: "earlier reasoning"}).Seal(key, &testGatewayCounter{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(blob, gatewayReasoningBlobPrefix) || strings.Contains(blob, "earlier reasoning") {
		t.Fatalf("the blob %q", blob)
	}
	opened, ok := OpenGatewayReasoningBlob(key, blob)
	if !ok || opened.NodeId != nodeId || opened.Text != "earlier reasoning" {
		t.Fatalf("opened %+v %v", opened, ok)
	}
	other := bytes.Repeat([]byte{0x22}, gatewayKeyByteCount)
	for _, foreign := range []string{
		"gAAAAABsynthetic-openai-form",
		blob[:len(blob)-4],
		strings.Replace(blob, gatewayReasoningBlobPrefix, "urgw2.", 1),
		"",
	} {
		if _, ok := OpenGatewayReasoningBlob(key, foreign); ok {
			t.Errorf("a foreign blob opened: %q", foreign)
		}
	}
	if _, ok := OpenGatewayReasoningBlob(other, blob); ok {
		t.Error("a blob opened under another network's key")
	}
}

// The gateway's own blob round-trips: a turn's reasoning item carries it, and the next turn, carrying the item back,
// gives the model the blob's text as its earlier reasoning, even where the harness edited the summary; a reasoning item
// with a blob from anywhere else, or none, gives the model nothing, and is not recorded.
func TestReasoningBlobRoundTripAndForeignIgnored(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	world.router.script(&testGatewayTurn{reasoning: []string{"I should list ", "the files."}, text: []string{"Listing."}})
	first := world.serve(gatewayResponsesFront{}, testGatewayCodexBody(true), nil)
	events := testGatewayEvents(t, first.Body.String())
	var reasoningItem map[string]any
	for _, event := range events {
		if item, _ := event.data["item"].(map[string]any); event.name == "response.output_item.done" && item["type"] == "reasoning" {
			reasoningItem = item
		}
	}
	blob, _ := reasoningItem["encrypted_content"].(string)
	if blob == "" {
		t.Fatalf("no blob: %v", reasoningItem)
	}
	opened, ok := OpenGatewayReasoningBlob(world.front.key, blob)
	if !ok || opened.Text != "I should list the files." || opened.NodeId == (Id{}) {
		t.Fatalf("the blob opens to %+v %v", opened, ok)
	}
	_, items, _ := world.recorder.snapshot()
	recordedNode := Id{}
	recordedNode[15] = 1
	if opened.NodeId != recordedNode || bytes.Contains(items[0], []byte("encrypted_content")) {
		t.Errorf("the blob names %s, the recorder answered %s for %s", opened.NodeId, recordedNode, items[0])
	}

	turnTwo := func(reasoning map[string]any) []byte {
		encoded, _ := json.Marshal(reasoning)
		return []byte(strings.Replace(testGatewayCodexBody(true), `"input":[`, `"input":[`+string(encoded)+`,`+
			`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Listing."}]},`, 1))
	}
	edited := map[string]any{"type": "reasoning", "id": "rs_whatever", "encrypted_content": blob,
		"summary": []any{map[string]any{"type": "summary_text", "text": "an edited summary"}}}
	foreign := map[string]any{"type": "reasoning", "id": "rs_foreign", "encrypted_content": "gAAAAABsynthetic",
		"summary": []any{map[string]any{"type": "summary_text", "text": "someone else's reasoning"}}}
	world.router.script(&testGatewayTurn{text: []string{"two"}}, &testGatewayTurn{text: []string{"three"}})
	if answer := world.serve(gatewayResponsesFront{}, string(turnTwo(edited)), nil); answer.Code != http.StatusOK {
		t.Fatalf("%d %s", answer.Code, answer.Body.String())
	}
	if answer := world.serve(gatewayResponsesFront{}, string(turnTwo(foreign)), nil); answer.Code != http.StatusOK {
		t.Fatalf("%d %s", answer.Code, answer.Body.String())
	}
	requests := world.router.inferred()
	assistantOf := func(request *InferRequest) *InferMessage {
		for _, message := range request.Messages {
			if message.Role == InferRoleAssistant {
				return message
			}
		}
		return nil
	}
	if assistant := assistantOf(requests[1]); assistant == nil || assistant.Reasoning != "I should list the files." {
		t.Errorf("the gateway's blob gave %+v", assistant)
	}
	if assistant := assistantOf(requests[2]); assistant == nil || assistant.Reasoning != "" {
		t.Errorf("a foreign blob gave %+v", assistant)
	}
	begins, _, _ := world.recorder.snapshot()
	if !bytes.Contains(begins[1].Body, []byte("I should list the files.")) || bytes.Contains(begins[1].Body, []byte("an edited summary")) {
		t.Errorf("the recorded body is not what the model received: %s", begins[1].Body)
	}
	if bytes.Contains(begins[2].Body, []byte("someone else's reasoning")) {
		t.Errorf("a foreign reasoning item was recorded: %s", begins[2].Body)
	}
}

// A keychain's key is drawn once, kept, and read back the same; two first uses at once draw one; a key of the wrong
// length is refused, never used.
func TestGatewayKeyDrawnOnce(t *testing.T) {
	secrets := &testGatewaySecrets{values: map[string][]byte{}}
	drawLock := &sync.Mutex{}
	keys := make(chan []byte, 8)
	wait := sync.WaitGroup{}
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			key, err := gatewayKeyOf(secrets, drawLock, gatewayKeyReasoning, &testGatewayCounter{})
			if err != nil {
				t.Error(err)
				return
			}
			keys <- key
		}()
	}
	wait.Wait()
	close(keys)
	var first []byte
	for key := range keys {
		if first == nil {
			first = key
		}
		if len(key) != gatewayKeyByteCount || !bytes.Equal(key, first) {
			t.Errorf("two keys: %x %x", key, first)
		}
	}
	if secrets.puts != 1 {
		t.Errorf("%d draws were kept", secrets.puts)
	}
	secrets.values[gatewayKeyReasoning] = []byte("short")
	if _, err := gatewayKeyOf(secrets, drawLock, gatewayKeyReasoning, &testGatewayCounter{}); !errors.Is(err, ErrGatewayKeyUnavailable) {
		t.Errorf("a short key: %v", err)
	}
}

// Secrets a test reads.
type testGatewaySecrets struct {
	stateLock sync.Mutex
	values    map[string][]byte
	puts      int
}

func (self *testGatewaySecrets) Get(name string) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	value, ok := self.values[name]
	if !ok {
		return nil, ErrSidecarStoreAbsent
	}
	return bytes.Clone(value), nil
}

func (self *testGatewaySecrets) Put(name string, value []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.values[name] = bytes.Clone(value)
	self.puts++
	return nil
}

func (self *testGatewaySecrets) Delete(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.values, name)
	return nil
}

func (self *testGatewaySecrets) List(prefix string) ([]string, error) {
	return nil, nil
}
