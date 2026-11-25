//go:build !js && !ios && !android && !sdk_mobile_bind

// MCP's socket_listen waits for the grant its approval activates in the network's config
// (sidecar.SocketListenGrantArgs.Config; socket_listen_grant.go's landed row, whose wait and naming
// kept_action_followups_test.go in the root holds at the real gate): the daemon's tool network hands the config client
// its grant filer's engine follows, and with none a nil config, never a nil client, so a fresh grant's use is
// uncertain rather than a call on nothing. Synthetic values only.

package mcp

import (
	"testing"

	"github.com/urnetwork/sidecar"
)

// The tool network's config is the client the network was built with, and nil, as an interface, with none.
func TestSocketListenWaitsInTheNetworksConfig(t *testing.T) {
	engine := sidecar.NewAclEngine(sidecar.NewId(), nil, nil, nil)
	client := &sidecar.ConfigClient{}
	var held mcpSocketGrantConfig = &mcpSidecarNetwork{engine: engine, config: client}
	if config := held.socketListenConfig(); config != sidecar.AclGrantConfig(client) {
		t.Errorf("the network's config: %v", config)
	}
	var none mcpSocketGrantConfig = &mcpSidecarNetwork{engine: engine}
	if config := none.socketListenConfig(); config != nil {
		t.Errorf("a network with no config client handed %#v", config)
	}
}
