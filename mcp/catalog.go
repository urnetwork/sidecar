//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.5's catalog (D-MCP-3): McpCatalog holds every tool registered through AddTool, one static table that
// McpServer.Install puts on each go-sdk Server before any session starts, so every session lists the same tools and
// the list never changes. Each tool's owner registers its tools from its own file, through registerMcpTools at init,
// as cli/'s commands register (C-21), so no later task edits this file's code to add one, and NewDaemonMcpCatalog
// makes the daemon's catalog from every registration linked into the build.
//
// mcpCatalogDesign is §16.5's table: each name, its tier, whether a W tool may act outward, whether it takes uses,
// and the task that owns it (MCP.md's "who builds which tool"), with DESIGN-COMPUTE §15.2's rows added to it at their
// tiers (CSURF-M11-02). mcpCatalogUnbuilt names the ones whose owners have not landed: the catalog test fails when a
// design name is neither registered nor listed there, so a gap between plans shows as a failing test, never as a
// missing tool. A §16.5 owner that lands its tools removes them from the list in the same change, and one registered
// while still listed fails. §15.2's rows are the one exception (CONTRACTS C-29): no compute area edits this file, so a
// compute tool registered and still listed passes, and the review phase prunes the list. Every registered tool is held
// to its row, listed or not. A registered evs or search tool that reports nothing to McpGuard fails it as well
// (mcpCatalogGuarded), since §16.6's repo rows judge only what a tool reports, and so does a tool whose uses differ from
// its row: mail_send takes uses and every other tool none (owner decision 613), so an agent asks for a template
// through mail_send alone and every other O tool files one use.
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
	tool   *gomcp.Tool
	tier   McpTier
	mayAct bool
	// whether it takes uses (McpToolSpec.MultiUse)
	multiUse bool
	// whether it reports what a call reaches to McpGuard (McpToolSpec.Targets)
	targeted bool
	handler  gomcp.ToolHandler
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
	// the search the search tools reach, which Install hands the server for hit arguments (tools_hit.go); nil for
	// a catalog with no search tool
	searchOf mcpSearchOfFunction
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

// Notes the search the catalog's search tools reach, which a hit argument resolves through.
func (self *McpCatalog) setSearchOf(searchOf mcpSearchOfFunction) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.searchOf = searchOf
}

// Puts every tool on server's go-sdk Servers, made already or later, and closes the catalog to more tools; the
// search its search tools reach becomes the one server's hit arguments resolve through.
func (self *McpCatalog) Install(server *McpServer) {
	tools, searchOf := func() ([]*mcpCatalogTool, mcpSearchOfFunction) {
		self.stateLock.Lock()
		self.installed = true
		searchOf := self.searchOf
		self.stateLock.Unlock()
		return self.sorted(), searchOf
	}()
	if searchOf != nil {
		server.setSearchOf(searchOf)
	}
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

// One §16.5 tool: its tier, whether a W tool may run an outward action, whether it takes uses, the task that owns it,
// and whether it is one of DESIGN-COMPUTE §15.2's rows, which may stay listed unbuilt once registered (CONTRACTS C-29).
type mcpCatalogDesignTool struct {
	name     string
	tier     McpTier
	mayAct   bool
	multiUse bool
	owner    string
	compute  bool
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
	// mail_send(..., uses?): the one tool an agent asks for a template by (owner decision 613), its handler handing
	// McpUses to MailSendArgs.Uses
	{name: "mail_send", tier: McpTierWrite, mayAct: true, multiUse: true, owner: "MCP-M7-01"},
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

	// DESIGN-COMPUTE §15.2's rows, added to §16.5's catalog with its tiers (CSURF-M11-02), each owned by its area's
	// tool task and none taking uses (owner decision 613). A tool §15.2 makes W, and O by kind 24 or 26 in a tainted
	// run or for a write, may act: enclave_exec, agent_send, agent_broadcast and service_call. enclave_stop is W, refused
	// in a tainted session; enclave_start is O, a kind 19. External harnesses get models through the gateway, so there is
	// no models_list or inference tool; there is no web_fetch (Q-FETCH-5), no connection_request, which only a person in
	// the apps or at the terminal answers (Q-CONN-12), no tool for checkout, auto-renew, refunds or promotion codes
	// (§14.3), and none that acknowledges a disclosure (D-CSURF-1): catalog_compute_test.go holds the table to that.
	{name: "compute_balance", tier: McpTierRead, owner: "BAL-M12-20", compute: true},
	{name: "compute_spend", tier: McpTierRead, owner: "BAL-M12-20", compute: true},
	{name: "enclave_list", tier: McpTierRead, owner: "ENC-M14-29", compute: true},
	{name: "enclave_status", tier: McpTierRead, owner: "ENC-M14-29", compute: true},
	{name: "enclave_create", tier: McpTierOutward, owner: "ENC-M14-29", compute: true},
	{name: "enclave_stop", tier: McpTierWrite, owner: "ENC-M14-29", compute: true},
	{name: "enclave_start", tier: McpTierOutward, owner: "ENC-M14-29", compute: true},
	{name: "enclave_delete", tier: McpTierOutward, owner: "ENC-M14-29", compute: true},
	{name: "enclave_exec", tier: McpTierWrite, mayAct: true, owner: "ENC-M14-29", compute: true},
	// §20.10's tiers
	{name: "agent_register", tier: McpTierWrite, owner: "SKILL-M11-07", compute: true},
	{name: "agent_summary", tier: McpTierWrite, owner: "SKILL-M11-07", compute: true},
	{name: "agent_list", tier: McpTierRead, owner: "SKILL-M11-07", compute: true},
	{name: "agent_find", tier: McpTierRead, owner: "SKILL-M11-07", compute: true},
	{name: "agent_send", tier: McpTierWrite, mayAct: true, owner: "SKILL-M11-07", compute: true},
	{name: "agent_broadcast", tier: McpTierWrite, mayAct: true, owner: "SKILL-M11-07", compute: true},
	{name: "agent_inbox", tier: McpTierRead, owner: "SKILL-M11-07", compute: true},
	{name: "agent_close", tier: McpTierWrite, owner: "SKILL-M11-07", compute: true},
	// the only web search external harnesses get, since the gateway serves none (§21.7, Q-SRCH-7); its name stays
	// web_search beside `ur web-search` (compute-plan-ur-search-collision, QD-1382)
	{name: "web_search", tier: McpTierRead, owner: "SRCH-M13-11", compute: true},
	{name: "listeners_list", tier: McpTierRead, owner: "LSTN-M13-15", compute: true},
	{name: "calendar_list", tier: McpTierRead, owner: "MAILCAL-M13-11", compute: true},
	{name: "calendar_add", tier: McpTierOutward, owner: "MAILCAL-M13-11", compute: true},
	{name: "calendar_update", tier: McpTierOutward, owner: "MAILCAL-M13-11", compute: true},
	{name: "calendar_delete", tier: McpTierOutward, owner: "MAILCAL-M13-11", compute: true},
	{name: "connections_list", tier: McpTierRead, owner: "CONN-M13-10", compute: true},
	{name: "service_call", tier: McpTierWrite, mayAct: true, owner: "CONN-M13-10", compute: true},
	// §28.4's, which the support switch registers (tools_support.go)
	{name: "support_send", tier: McpTierOutward, owner: "support-skill", compute: true},
	{name: "support_list", tier: McpTierRead, owner: "support-skill", compute: true},
	{name: "support_read", tier: McpTierRead, owner: "support-skill", compute: true},
}

// The design names whose owners have not landed their tools: every one, at MCP-M3-12. A §16.5 owner removes its names
// in the change that registers them, and none of those is left. DESIGN-COMPUTE §15.2's stay here, registered or not,
// until the review phase prunes them (CONTRACTS C-29).
var mcpCatalogUnbuilt = []string{
	// BAL-M12-20's, which register once their rows are here (tools_compute.go)
	"compute_balance", "compute_spend",
	"enclave_list", "enclave_status", "enclave_create", "enclave_stop", "enclave_start", "enclave_delete", "enclave_exec",
	// SKILL-M11-07's, which register once their rows are here (tools_agents.go)
	"agent_register", "agent_summary", "agent_list", "agent_find", "agent_send", "agent_broadcast", "agent_inbox",
	"agent_close",
	"web_search",
	"listeners_list",
	"calendar_list", "calendar_add", "calendar_update", "calendar_delete",
	"connections_list", "service_call",
	// registered only once the release's support switch is on, at G-SUP-service (DESIGN-COMPUTE §28.21)
	"support_send", "support_list", "support_read",
}

// Whether a §16.5 tool is an evs or a search tool, the classes §16.6's refused table names: each reports what a call
// reaches (McpToolSpec.Targets), so no repo row, a mailbox's vault/ family's among them (QD-673), rests on a tool
// remembering to ask. A Targets that reaches no repo for a call naming none, as evs_repos', is one; a nil one is not.
func mcpCatalogGuarded(name string) bool {
	return strings.HasPrefix(name, "evs_") || name == "search" || strings.HasPrefix(name, "search_")
}

// Holds a catalog to §16.5: every registered tool a design name with its tier, hints and uses, every evs and search
// tool reporting its targets to McpGuard, and every design name registered or still unbuilt, never both but for
// §15.2's compute rows (CONTRACTS C-29). The catalog test runs it on the daemon's catalog.
func checkMcpCatalog(catalog *McpCatalog) error {
	return checkMcpCatalogAgainst(catalog, mcpCatalogDesign, mcpCatalogUnbuilt)
}

// checkMcpCatalog over a design table and its unbuilt names, which a test plants.
func checkMcpCatalogAgainst(catalog *McpCatalog, designTable []mcpCatalogDesignTool, unbuiltNames []string) error {
	registered := map[string]*mcpCatalogTool{}
	for _, tool := range catalog.sorted() {
		registered[tool.tool.Name] = tool
	}
	designNames := map[string]bool{}
	errs := []string{}
	for _, design := range designTable {
		designNames[design.name] = true
		tool, isRegistered := registered[design.name]
		unbuilt := slices.Contains(unbuiltNames, design.name)
		switch {
		case isRegistered && unbuilt && !design.compute:
			errs = append(errs, fmt.Sprintf("%s is registered and still listed unbuilt", design.name))
		case !isRegistered && !unbuilt:
			errs = append(errs, fmt.Sprintf("%s (%s) is neither registered nor listed unbuilt", design.name, design.owner))
		}
		if !isRegistered {
			continue
		}
		// a registered tool is held to its row whether or not it is still listed
		openWorld := design.tier == McpTierOutward || design.mayAct
		annotations := tool.tool.Annotations
		if tool.tier != design.tier || tool.mayAct != design.mayAct || annotations == nil ||
			annotations.ReadOnlyHint != (design.tier == McpTierRead) || annotations.OpenWorldHint == nil || *annotations.OpenWorldHint != openWorld {
			errs = append(errs, fmt.Sprintf("%s is not %s with its hints", design.name, design.tier))
		}
		if mcpCatalogGuarded(design.name) && !tool.targeted {
			errs = append(errs, fmt.Sprintf("%s reports nothing to the guard", design.name))
		}
		switch {
		case design.multiUse && !tool.multiUse:
			errs = append(errs, fmt.Sprintf("%s takes no uses, which §16.5 gives it (owner decision 613; McpToolSpec.MultiUse)", design.name))
		case !design.multiUse && tool.multiUse:
			errs = append(errs, fmt.Sprintf("%s takes uses, which §16.5 gives mail_send alone (owner decision 613)", design.name))
		}
	}
	for name := range registered {
		if !designNames[name] {
			errs = append(errs, fmt.Sprintf("%s is no §16.5 tool", name))
		}
	}
	for _, name := range unbuiltNames {
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
