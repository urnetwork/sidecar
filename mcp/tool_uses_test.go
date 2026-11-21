//go:build !js && !ios && !android && !sdk_mobile_bind

// mail_send's uses at the tool framework and the catalog (owner decision 613, QD-1071; §16.5, §16.6's multi-use row):
// a tool whose spec takes uses lists an optional integer of at least 1 beside network, which its handler reads apart
// from its input (McpUses), 0 where the call names none; a count out of shape is refused with the constant text, and
// so is uses on a tool that takes none; only a tool that files an outward action may take it, and an input may not
// name it itself; and the catalog holds §16.5 to one such tool, mail_send, every other O tool filing one use.

package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// What test_templated answers: the uses its call named.
type testUsesOut struct {
	Uses uint32 `json:"uses"`
}

// Registers test_templated, an O tool taking uses, which answers the count its handler read.
func addTestUsesTool(catalog *McpCatalog) {
	AddTool(catalog, &McpToolSpec[testToolIn]{
		Name: "test_templated", Tier: McpTierOutward, MultiUse: true, Description: "acts outward, asking uses",
		Access: func(call *McpCall, in *testToolIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *testToolIn, result *McpResult) (*testUsesOut, error) {
		result.SetSource("test:templated")
		return &testUsesOut{Uses: McpUses(ctx)}, nil
	})
}

// A tool taking uses hands its handler the count the call names, 0 for none, apart from its input; uses out of shape,
// or on a tool that takes none, is refused with the constant text before any handler runs.
func TestToolUsesReachTheHandler(t *testing.T) {
	env := newTestToolEnvWith(t, addTestUsesTool)
	conn := env.conn("2025-06-18")
	for _, c := range []struct {
		arguments map[string]any
		want      uint32
	}{
		{arguments: map[string]any{"text": "a"}, want: 0},
		{arguments: map[string]any{"text": "a", "uses": 1}, want: 1},
		{arguments: map[string]any{"text": "a", "uses": 3}, want: 3},
		{arguments: map[string]any{"text": "a", "uses": 4294967295}, want: 4294967295},
	} {
		envelope := testEnvelopeOf(t, env.callTool(conn, "2025-06-18", "test_templated", c.arguments))
		out := &testUsesOut{}
		if err := json.Unmarshal(envelope.Data, out); err != nil || out.Uses != c.want {
			t.Errorf("%v: uses %d, %v", c.arguments, out.Uses, err)
		}
	}
	for _, uses := range []any{0, -2, 1.5, "3", 4294967296, nil, true} {
		wantMcpError(t, env.callTool(conn, "2025-06-18", "test_templated", map[string]any{"text": "a", "uses": uses}), McpCodeInvalidArguments, "do not fit")
	}
	for _, name := range []string{"test_act", "test_write", "test_read"} {
		wantMcpError(t, env.callTool(conn, "2025-06-18", name, map[string]any{"text": "a", "uses": 3}), McpCodeInvalidArguments, "do not fit")
	}
}

// The tool list names uses on the tool that takes it alone: an optional integer of at least 1.
func TestToolListNamesUsesWhereTaken(t *testing.T) {
	env := newTestToolEnvWith(t, addTestUsesTool)
	listed := env.conn("2025-06-18").call("tools/list", map[string]any{})
	if listed.Error != nil {
		t.Fatal(listed.Error.Message)
	}
	tools := struct {
		Tools []struct {
			Name        string `json:"name"`
			InputSchema struct {
				Properties map[string]struct {
					Type    string   `json:"type"`
					Minimum *float64 `json:"minimum"`
				} `json:"properties"`
				Required []string `json:"required"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}{}
	if err := json.Unmarshal(listed.Result, &tools); err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, tool := range tools.Tools {
		uses, named := tool.InputSchema.Properties["uses"]
		if tool.Name != "test_templated" {
			if named {
				t.Errorf("%s lists uses", tool.Name)
			}
			continue
		}
		seen = true
		if !named || uses.Type != "integer" || uses.Minimum == nil || *uses.Minimum != 1 {
			t.Errorf("test_templated's uses %+v", uses)
		}
		for _, required := range tool.InputSchema.Required {
			if required == "uses" {
				t.Error("uses is required")
			}
		}
	}
	if !seen {
		t.Error("test_templated is not listed")
	}
}

// Only a tool that files an outward action takes uses, and the wrapper alone names it: a read or a plain write taking
// it, or an input naming it, panics at registration; an O tool and a W tool that may act take it.
func TestAddToolHoldsUsesToOutwardTools(t *testing.T) {
	catalog := NewMcpCatalog(sidecar.DefaultSidecarSettings().Mcp, nil, nil)
	none := func(call *McpCall, in *testToolIn) ([]McpAccess, error) { return nil, nil }
	echo := func(ctx context.Context, call *McpCall, in *testToolIn, result *McpResult) (*testToolOut, error) {
		return nil, nil
	}
	panics := func(name string, add func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s did not panic", name)
			}
		}()
		add()
	}
	panics("a read taking uses", func() {
		AddTool(catalog, &McpToolSpec[testToolIn]{Name: "r", Tier: McpTierRead, MultiUse: true, Description: "d", Access: none}, echo)
	})
	panics("a plain write taking uses", func() {
		AddTool(catalog, &McpToolSpec[testToolIn]{Name: "w", Tier: McpTierWrite, MultiUse: true, Description: "d", Access: none}, echo)
	})
	type usesIn struct {
		Uses uint32 `json:"uses"`
	}
	panics("an input naming uses", func() {
		AddTool(catalog, &McpToolSpec[usesIn]{Name: "u", Tier: McpTierOutward, MultiUse: true, Description: "d",
			Access: func(call *McpCall, in *usesIn) ([]McpAccess, error) { return nil, nil }},
			func(ctx context.Context, call *McpCall, in *usesIn, result *McpResult) (*testToolOut, error) {
				return nil, nil
			})
	})
	AddTool(catalog, &McpToolSpec[testToolIn]{Name: "o", Tier: McpTierOutward, MultiUse: true, Description: "d", Access: none}, echo)
	AddTool(catalog, &McpToolSpec[testToolIn]{Name: "a", Tier: McpTierWrite, MayAct: true, MultiUse: true, Description: "d", Access: none}, echo)
}

// §16.5 gives uses to mail_send alone (owner decision 613): its row is the one that takes it, a mail_send registered
// without uses fails the catalog, and so does any other tool registered with it.
func TestCatalogHoldsUsesToMailSend(t *testing.T) {
	multiUse := []string{}
	for _, design := range mcpCatalogDesign {
		if design.multiUse {
			multiUse = append(multiUse, design.name)
			if design.tier != McpTierOutward && !design.mayAct {
				t.Errorf("%s takes uses and files no outward action", design.name)
			}
		}
	}
	if len(multiUse) != 1 || multiUse[0] != "mail_send" {
		t.Errorf("the tools taking uses: %v", multiUse)
	}

	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	server := newTestMcpServer(newFakeMcpDaemon(), clock)
	none := func(call *McpCall, in *testToolIn) ([]McpAccess, error) { return nil, nil }
	echo := func(ctx context.Context, call *McpCall, in *testToolIn, result *McpResult) (*testToolOut, error) {
		return &testToolOut{}, nil
	}
	without := NewMcpCatalog(server.settings.Mcp, clock, nil)
	AddTool(without, &McpToolSpec[testToolIn]{Name: "mail_send", Tier: McpTierWrite, MayAct: true, Description: "sends", Access: none}, echo)
	AddTool(without, &McpToolSpec[testToolIn]{Name: "dns_set", Tier: McpTierOutward, MultiUse: true, Description: "sets", Access: none}, echo)
	err := checkMcpCatalog(without)
	if err == nil || !strings.Contains(err.Error(), "mail_send takes no uses") || !strings.Contains(err.Error(), "dns_set takes uses") {
		t.Errorf("mail_send without uses and dns_set with them: %v", err)
	}

	with := NewMcpCatalog(server.settings.Mcp, clock, nil)
	AddTool(with, &McpToolSpec[testToolIn]{Name: "mail_send", Tier: McpTierWrite, MayAct: true, MultiUse: true, Description: "sends", Access: none}, echo)
	// the other design names go unregistered here, which the check names; mail_send's uses it does not
	if err := checkMcpCatalog(with); err != nil && strings.Contains(err.Error(), "mail_send takes") {
		t.Errorf("mail_send with uses: %v", err)
	}
}
