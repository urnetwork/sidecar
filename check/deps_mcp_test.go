//go:build sidecar_check

// D-MCP-1's case of §4.7's deps row, which TestDeps runs: go-sdk, which mcp/ links, reaches ur alone, never sdk's
// builds, gomobile's or wasm's. dependencies.yml's go-sdk row names the cli leg alone, so legModuleFindings already
// fails a client leg that links it; this reads every shipped leg's closure for the module itself, so the case holds
// even if that row's legs were widened by mistake.

package check

import (
	"testing"
)

// go-sdk's module.
const mcpSdkModulePath = "github.com/modelcontextprotocol/go-sdk"

// Each shipped leg other than ur's that links a go-sdk package.
func (self *repository) mcpSdkLegFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	for _, leg := range self.shippedLegs() {
		if leg.class == classCli {
			continue
		}
		for _, listed := range self.closure(t, leg) {
			if listed.Module != nil && underPath(listed.Module.Path, mcpSdkModulePath) {
				findings = append(findings, findingf("%s links %s, which only ur may (D-MCP-1)", leg.name, listed.ImportPath))
				break
			}
		}
	}
	return findings
}

// A client package importing go-sdk fails, even with its row widened to every leg.
func TestDepsFailsOnGoSdkInAClientLeg(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64", "cli linux/amd64")
	fixture.writeSibling("gosdk/go.mod", "module "+mcpSdkModulePath+"\n\ngo 1.27.4\n")
	fixture.writeSibling("gosdk/mcp/mcp.go", "package mcp\n")
	fixture.requireLocal(mcpSdkModulePath, "v1.7.0", "gosdk")
	fixture.write("planted.go", "package sidecar\n\nimport _ \""+mcpSdkModulePath+"/mcp\"\n")
	wantFindings(t, fixture.open().mcpSdkLegFindings(t),
		"root linux/amd64 links "+mcpSdkModulePath+"/mcp, which only ur may (D-MCP-1)")
}
