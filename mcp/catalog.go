//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.5's catalog (D-MCP-3): McpCatalog holds every tool registered through AddTool, one static table that
// McpServer.Install puts on each go-sdk Server before any session starts, so every session lists the same tools and
// the list never changes. Each tool's owner registers its tools from its own file, through registerMcpTools at init,
// as cli/'s commands register (C-21), so no later task edits this file's code to add one, and NewDaemonMcpCatalog
// makes the daemon's catalog from every registration linked into the build.
//
// mcpCatalogDesign is §16.5's table: each name, its tier, whether a W tool may act outward, and the task that owns
// it (MCP.md's "who builds which tool"). mcpCatalogUnbuilt names the ones whose owners have not landed: the catalog
// test fails when a design name is neither registered nor listed there, or registered while still listed, so a gap
// between plans shows as a failing test, never as a missing tool. An owner that lands its tools removes them from
// the list in the same change.
//
// Safe for concurrent use; registration happens before serving.

package mcp

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/urnetwork/sidecar"
)

// One registered tool: its go-sdk definition and the wrapped handler.
type mcpCatalogTool struct {
	tool    *gomcp.Tool
	tier    McpTier
	mayAct  bool
	handler gomcp.ToolHandler
}

// The tools a daemon serves.
type McpCatalog struct {
	settings *sidecar.SidecarMcpSettings
	clock    sidecar.Clock
	// nil records nothing
	sink McpCallSink

	stateLock sync.Mutex
	tools     map[string]*mcpCatalogTool
	installed bool
}

// An empty catalog on settings and clock, its W calls going to sink, nil for none.
func NewMcpCatalog(settings *sidecar.SidecarMcpSettings, clock sidecar.Clock, sink McpCallSink) *McpCatalog {
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	return &McpCatalog{settings: settings, clock: clock, sink: sink, tools: map[string]*mcpCatalogTool{}}
}

// Adds one tool. Panics on a name taken, or after the catalog is installed, since the tool list is static.
func (self *McpCatalog) add(tool *mcpCatalogTool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.installed {
		panic(fmt.Sprintf("mcp.AddTool %q: the catalog is installed, and the tool list is static", tool.tool.Name))
	}
	if _, taken := self.tools[tool.tool.Name]; taken {
		panic(fmt.Sprintf("mcp.AddTool %q: the name is taken", tool.tool.Name))
	}
	self.tools[tool.tool.Name] = tool
}

// The tools, by name.
func (self *McpCatalog) sorted() []*mcpCatalogTool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	tools := make([]*mcpCatalogTool, 0, len(self.tools))
	for _, tool := range self.tools {
		tools = append(tools, tool)
	}
	slices.SortFunc(tools, func(a *mcpCatalogTool, b *mcpCatalogTool) int { return strings.Compare(a.tool.Name, b.tool.Name) })
	return tools
}

// Every registered tool's name and tier, by name.
func (self *McpCatalog) Names() []string {
	names := []string{}
	for _, tool := range self.sorted() {
		names = append(names, tool.tool.Name)
	}
	return names
}

// Puts every tool on server's go-sdk Servers, made already or later, and closes the catalog to more tools.
func (self *McpCatalog) Install(server *McpServer) {
	tools := func() []*mcpCatalogTool {
		self.stateLock.Lock()
		self.installed = true
		self.stateLock.Unlock()
		return self.sorted()
	}()
	server.Install(func(server *gomcp.Server) {
		for _, tool := range tools {
			server.AddTool(tool.tool, tool.handler)
		}
	})
}

// What a registration gets: the catalog, and the daemon's server for what its tools read of it.
type McpToolRegistration func(catalog *McpCatalog, server *McpServer)

// The registrations linked into this build, in the order their files' init ran.
var mcpToolRegistrations struct {
	stateLock     sync.Mutex
	registrations []McpToolRegistration
}

// Adds a tool owner's registration, which NewDaemonMcpCatalog runs. Call from the owner's file's init.
func registerMcpTools(registration McpToolRegistration) {
	mcpToolRegistrations.stateLock.Lock()
	defer mcpToolRegistrations.stateLock.Unlock()
	mcpToolRegistrations.registrations = append(mcpToolRegistrations.registrations, registration)
}

// The daemon's catalog: every registration linked into the build, on server's settings and clock, its W calls going
// to sink, nil for none. Install it on server before serving.
func NewDaemonMcpCatalog(server *McpServer, sink McpCallSink) *McpCatalog {
	catalog := NewMcpCatalog(server.settings.Mcp, server.clock, sink)
	registrations := func() []McpToolRegistration {
		mcpToolRegistrations.stateLock.Lock()
		defer mcpToolRegistrations.stateLock.Unlock()
		return slices.Clone(mcpToolRegistrations.registrations)
	}()
	for _, registration := range registrations {
		registration(catalog, server)
	}
	return catalog
}

// One §16.5 tool: its tier, whether a W tool may run an outward action, and the task that owns it.
type mcpCatalogDesignTool struct {
	name   string
	tier   McpTier
	mayAct bool
	owner  string
}

// §16.5's table, by its rows (MCP.md's "who builds which tool"; C-14, C-15).
var mcpCatalogDesign = []mcpCatalogDesignTool{
	{name: "evs_repos", tier: McpTierRead, owner: "MCP-M3-13"},
	{name: "evs_list", tier: McpTierRead, owner: "MCP-M3-13"},
	{name: "evs_history", tier: McpTierRead, owner: "MCP-M3-13"},
	{name: "evs_read", tier: McpTierRead, owner: "MCP-M3-13"},
	{name: "evs_drop_preview", tier: McpTierRead, owner: "MCP-M10-01"},
	{name: "evs_write", tier: McpTierWrite, mayAct: true, owner: "MCP-M3-13"},
	{name: "evs_delete", tier: McpTierWrite, mayAct: true, owner: "MCP-M3-13"},
	{name: "mail_list", tier: McpTierRead, owner: "MCP-M7-01"},
	{name: "mail_read", tier: McpTierRead, owner: "MCP-M7-01"},
	{name: "mail_send", tier: McpTierWrite, mayAct: true, owner: "MCP-M7-01"},
	{name: "mail_aliases", tier: McpTierRead, owner: "MCP-M7-01"},
	{name: "mail_alias_create", tier: McpTierOutward, owner: "MCP-M7-01"},
	{name: "mail_alias_delete", tier: McpTierOutward, owner: "MCP-M7-01"},
	{name: "socket_list", tier: McpTierRead, owner: "SOCK-M5-14"},
	{name: "socket_status", tier: McpTierRead, owner: "SOCK-M5-14"},
	{name: "socket_listen", tier: McpTierOutward, owner: "SOCK-M5-14"},
	{name: "socket_unlisten", tier: McpTierWrite, owner: "SOCK-M5-14"},
	{name: "tls_publish", tier: McpTierOutward, owner: "TLS-M5-23"},
	{name: "tls_unpublish", tier: McpTierWrite, owner: "TLS-M5-23"},
	{name: "bridge_list", tier: McpTierRead, owner: "MCP-M4-01"},
	{name: "bridge_forward", tier: McpTierOutward, owner: "MCP-M4-01"},
	{name: "bridge_expose", tier: McpTierOutward, owner: "MCP-M4-01"},
	{name: "bridge_close", tier: McpTierWrite, owner: "MCP-M4-01"},
	{name: "dns_records", tier: McpTierRead, owner: "MCP-M5-01"},
	{name: "dns_set", tier: McpTierOutward, owner: "MCP-M5-01"},
	{name: "dns_delete", tier: McpTierOutward, owner: "MCP-M5-01"},
	{name: "team_members", tier: McpTierRead, owner: "MCP-M3-14"},
	{name: "team_agents", tier: McpTierRead, owner: "MCP-M3-14"},
	{name: "acl_grants", tier: McpTierRead, owner: "MCP-M3-14"},
	{name: "acl_check", tier: McpTierRead, owner: "MCP-M3-14"},
	{name: "record_query", tier: McpTierRead, owner: "RECORD-M3-09"},
	{name: "run_coverage", tier: McpTierRead, owner: "RECORD-M3-09"},
	{name: "approval_status", tier: McpTierRead, owner: "RECORD-M3-09"},
	{name: "record_append", tier: McpTierWrite, owner: "RECORD-M3-09"},
	{name: "directory_list", tier: McpTierRead, owner: "RECORD-M6-22"},
	{name: "directory_requests", tier: McpTierRead, owner: "RECORD-M6-22"},
	{name: "directory_request", tier: McpTierOutward, owner: "RECORD-M6-22"},
	{name: "run_restore", tier: McpTierWrite, mayAct: true, owner: "MCP-M3-22"},
	{name: "search", tier: McpTierRead, owner: "SEARCH-M10-29"},
	{name: "search_agents", tier: McpTierRead, owner: "SEARCH-M10-29"},
	{name: "search_status", tier: McpTierRead, owner: "SEARCH-M10-29"},
}

// The design names whose owners have not landed their tools: every one, at MCP-M3-12. An owner removes its names
// in the change that registers them.
var mcpCatalogUnbuilt = []string{
	"evs_repos", "evs_list", "evs_history", "evs_read", "evs_drop_preview", "evs_write", "evs_delete",
	"mail_list", "mail_read", "mail_send", "mail_aliases", "mail_alias_create", "mail_alias_delete",
	"tls_publish", "tls_unpublish",
	"bridge_list", "bridge_forward", "bridge_expose", "bridge_close",
	"dns_records", "dns_set", "dns_delete",
	"team_members", "team_agents", "acl_grants", "acl_check",
	"record_query", "run_coverage", "approval_status", "record_append",
	"directory_list", "directory_requests", "directory_request",
	"run_restore",
	"search", "search_agents", "search_status",
}

// Holds a catalog to §16.5: every registered tool a design name with its tier and hints, and every design name
// registered or still unbuilt, never both. The catalog test runs it on the daemon's catalog.
func checkMcpCatalog(catalog *McpCatalog) error {
	registered := map[string]*mcpCatalogTool{}
	for _, tool := range catalog.sorted() {
		registered[tool.tool.Name] = tool
	}
	designNames := map[string]bool{}
	errs := []string{}
	for _, design := range mcpCatalogDesign {
		designNames[design.name] = true
		tool, isRegistered := registered[design.name]
		unbuilt := slices.Contains(mcpCatalogUnbuilt, design.name)
		switch {
		case isRegistered && unbuilt:
			errs = append(errs, fmt.Sprintf("%s is registered and still listed unbuilt", design.name))
		case !isRegistered && !unbuilt:
			errs = append(errs, fmt.Sprintf("%s (%s) is neither registered nor listed unbuilt", design.name, design.owner))
		case isRegistered:
			openWorld := design.tier == McpTierOutward || design.mayAct
			annotations := tool.tool.Annotations
			if tool.tier != design.tier || tool.mayAct != design.mayAct || annotations == nil ||
				annotations.ReadOnlyHint != (design.tier == McpTierRead) || annotations.OpenWorldHint == nil || *annotations.OpenWorldHint != openWorld {
				errs = append(errs, fmt.Sprintf("%s is not %s with its hints", design.name, design.tier))
			}
		}
	}
	for name := range registered {
		if !designNames[name] {
			errs = append(errs, fmt.Sprintf("%s is no §16.5 tool", name))
		}
	}
	for _, name := range mcpCatalogUnbuilt {
		if !designNames[name] {
			errs = append(errs, fmt.Sprintf("%s is listed unbuilt and is no §16.5 tool", name))
		}
	}
	if 0 < len(errs) {
		slices.Sort(errs)
		return fmt.Errorf("the catalog differs from §16.5: %s", strings.Join(errs, "; "))
	}
	return nil
}
