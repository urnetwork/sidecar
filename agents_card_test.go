//go:build !ios_extension && !sidecar_http

// An agent's card (§20.5): testdata's vectors read or refused, a card written and read back field for field, the me
// card's shape, and the bounds held as settings.

package sidecar

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestAgentCardVectors(t *testing.T) {
	settings := DefaultSkillSettings()
	data, err := testAgentsCardFiles.ReadFile("testdata/agents/card/cards.json")
	if err != nil {
		t.Fatal(err)
	}
	vectors := []struct {
		Label string `json:"label"`
		Valid bool   `json:"valid"`
		Card  string `json:"card"`
	}{}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors {
		card, err := ParseAgentCard([]byte(vector.Card), settings)
		if vector.Valid != (err == nil) {
			t.Errorf("%s: %v", vector.Label, err)
			continue
		}
		if !vector.Valid {
			if !errors.Is(err, ErrAgentCardInvalid) {
				t.Errorf("%s: %v is no ErrAgentCardInvalid", vector.Label, err)
			}
			continue
		}
		// a card reads back from its own bytes as it read
		encoded, err := EncodeAgentCard(card, settings)
		if err != nil {
			t.Errorf("%s: %v", vector.Label, err)
			continue
		}
		again, err := ParseAgentCard(encoded, settings)
		if err != nil || *again != *card {
			t.Errorf("%s: read back as %+v, %v", vector.Label, again, err)
		}
	}
}

func TestAgentCardRoundTrip(t *testing.T) {
	settings := DefaultSkillSettings()
	started := time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC)
	card := &AgentCard{
		Name: "limiter-fix", AgentId: testConfigId("agent"), SidecarId: testConfigId("sidecar"), Host: "laptop",
		Harness: "claude-code 2.1.300", Model: "chutes-model-tee-high", AgentRepo: testConfigId("repo"), Started: started,
		Parent: "orchestrator",
	}
	data, err := EncodeAgentCard(card, settings)
	if err != nil {
		t.Fatal(err)
	}
	read, err := ParseAgentCard(data, settings)
	if err != nil || *read != *card || read.Person() || read.IsRetired() {
		t.Fatalf("read back as %+v, %v", read, err)
	}
	// §20.5's field order, as the design writes the card
	want := `{"v":1,"name":"limiter-fix","agent_id":"` + agentCardIdText(card.AgentId) + `","sidecar_id":"` + agentCardIdText(card.SidecarId) +
		`","host":"laptop","harness":"claude-code 2.1.300","model":"chutes-model-tee-high","agent_repo":"` + agentCardIdText(card.AgentRepo) +
		`","started":"2026-12-01T10:00:00Z","parent":"orchestrator"}` + "\n"
	if string(data) != want {
		t.Fatalf("encoded as %s", data)
	}
	// the me card names the member alone
	me := &AgentCard{Name: AgentNameMe, MemberId: testConfigId("member"), Started: started}
	if data, err := EncodeAgentCard(me, settings); err != nil {
		t.Fatal(err)
	} else if read, err := ParseAgentCard(data, settings); err != nil || !read.Person() || read.MemberId != me.MemberId {
		t.Fatalf("the me card read back as %+v, %v", read, err)
	}
	// a card that would not read back is refused before it is written
	for _, bad := range []*AgentCard{
		{Name: "a", Started: started},
		{Name: "a", AgentId: testConfigId("agent"), SidecarId: testConfigId("sidecar"), MemberId: testConfigId("member"), Started: started},
		{Name: "a", AgentId: testConfigId("agent"), SidecarId: testConfigId("sidecar"), Harness: string(make([]byte, settings.CardFieldMaxByteCount+1)), Started: started},
	} {
		if _, err := EncodeAgentCard(bad, settings); !errors.Is(err, ErrAgentCardInvalid) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	// the card's bound is a setting
	small := DefaultSkillSettings()
	small.CardMaxByteCount = 32
	if _, err := ParseAgentCard(data, small); !errors.Is(err, ErrAgentCardInvalid) {
		t.Fatalf("past a smaller bound: %v", err)
	}
}
