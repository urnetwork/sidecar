//go:build !js && !ios && !android && !sdk_mobile_bind

// BAL-M12-20's compute tools over MCP: they join the daemon's catalog only once §16.5's design table names them
// (CSURF-M11-02's rows, CONTRACTS C-29), both R and the catalog check passing with them; compute_spend refuses a
// session on any device but the person's consented one with its constant text, before the compute client is asked;
// a network with no compute answers unavailable; and neither tool takes an argument it does not name.

package mcp

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A network whose compute host answers as the test sets: whether it is the consented device, and no compute client,
// counting each time one is asked.
type fakeMcpComputeNetwork struct {
	*fakeMcpNetwork
	consented   bool
	clientAsked int
}

func (self *fakeMcpComputeNetwork) ComputeClient() (*sidecar.ComputeClient, error) {
	self.clientAsked += 1
	return nil, sidecar.ErrComputeClientClosed
}

func (self *fakeMcpComputeNetwork) ComputeConsentedDevice() (bool, error) {
	return self.consented, nil
}

func (self *fakeMcpComputeNetwork) ComputeBudgetLeft(ctx context.Context, agentId sidecar.Id) (*sidecar.ComputeBudgetLeft, error) {
	return nil, nil
}

var _ sidecar.ComputeToolHost = (*fakeMcpComputeNetwork)(nil)

// The two join the daemon's catalog only once the design table names them: not now, and with the rows, both at R,
// the catalog check passing.
func TestComputeToolsJoinTheCatalogOnceDesigned(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	server := newTestMcpServer(newFakeMcpDaemon(), clock)
	names := NewDaemonMcpCatalog(server, nil).Names()
	if mcpComputeToolsDesigned() != (slices.Contains(names, mcpToolComputeBalance) && slices.Contains(names, mcpToolComputeSpend)) {
		t.Fatalf("designed %t, the catalog %v", mcpComputeToolsDesigned(), names)
	}
	if slices.Contains(names, mcpToolComputeBalance) != slices.Contains(names, mcpToolComputeSpend) {
		t.Fatalf("one of the two registered: %v", names)
	}
	saved := mcpCatalogDesign
	t.Cleanup(func() { mcpCatalogDesign = saved })
	if !mcpComputeToolsDesigned() {
		mcpCatalogDesign = append(slices.Clone(saved),
			mcpCatalogDesignTool{name: mcpToolComputeBalance, tier: McpTierRead, owner: "BAL-M12-20"},
			mcpCatalogDesignTool{name: mcpToolComputeSpend, tier: McpTierRead, owner: "BAL-M12-20"})
	}
	catalog := NewDaemonMcpCatalog(server, nil)
	if err := checkMcpCatalog(catalog); err != nil {
		t.Error(err)
	}
	if names := catalog.Names(); !slices.Contains(names, mcpToolComputeBalance) || !slices.Contains(names, mcpToolComputeSpend) {
		t.Errorf("with the rows, the catalog %v", names)
	}
}

// compute_spend refuses a session on a device that is not the person's consented one, its text constant, before any
// compute client is asked; on the consented device a network whose compute is not running answers unavailable, as
// compute_balance does, and a network with no compute host is unavailable too. A breakdown no route takes is refused.
func TestComputeSpendOnlyOnTheConsentedDevice(t *testing.T) {
	ctx := context.Background()
	network := &fakeMcpComputeNetwork{fakeMcpNetwork: &fakeMcpNetwork{}}
	call := &McpCall{NetworkId: sidecar.NewId(), Network: network}
	if _, err := mcpComputeSpend(ctx, call, &mcpComputeSpendIn{By: "model"}); !errors.Is(err, errMcpComputeNotConsentedDevice) || network.clientAsked != 0 {
		t.Fatalf("not the consented device: %v, the client asked %d times", err, network.clientAsked)
	}
	network.consented = true
	if _, err := mcpComputeSpend(ctx, call, &mcpComputeSpendIn{By: "model"}); !errors.Is(err, errMcpComputeUnavailable) || network.clientAsked != 1 {
		t.Errorf("no compute client: %v, asked %d", err, network.clientAsked)
	}
	if _, err := mcpComputeBalance(ctx, call); !errors.Is(err, errMcpComputeUnavailable) {
		t.Errorf("the balance with no compute client: %v", err)
	}
	if _, err := mcpComputeSpend(ctx, call, &mcpComputeSpendIn{By: "sidecar"}); !errors.Is(err, errMcpComputeArguments) {
		t.Errorf("a breakdown by sidecar: %v", err)
	}
	plain := &McpCall{NetworkId: sidecar.NewId(), Network: &fakeMcpNetwork{}}
	if _, err := mcpComputeBalance(ctx, plain); !errors.Is(err, errMcpComputeUnavailable) {
		t.Errorf("a network with no compute: %v", err)
	}
	if _, err := mcpComputeSpend(ctx, nil, &mcpComputeSpendIn{}); !errors.Is(err, errMcpComputeUnavailable) {
		t.Errorf("no call: %v", err)
	}
}
