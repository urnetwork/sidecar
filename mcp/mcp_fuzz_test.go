//go:build !js && !ios && !android && !sdk_mobile_bind

// FuzzMcpArguments (§22.6): whatever arguments arrive, no answer, an error's text or a result's bytes, carries the
// daemon's credential in any encoding the matcher knows. The seeds run with every go test; the long campaign is the
// review phase's.

package mcp

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// A tool's wrapped handler called as go-sdk calls it, inside call.
func testToolHandle(t testing.TB, catalog *McpCatalog, call *McpCall, name string, arguments []byte) (*gomcp.CallToolResult, error) {
	catalog.stateLock.Lock()
	tool := catalog.tools[name]
	catalog.stateLock.Unlock()
	if tool == nil {
		t.Fatalf("no tool %s", name)
	}
	ctx := context.WithValue(context.Background(), mcpCallContextKey{}, call)
	return tool.handler(ctx, &gomcp.CallToolRequest{Params: &gomcp.CallToolParamsRaw{Name: name, Arguments: arguments}})
}

// A tool's wrapped handler inside env's bound call on its tool network.
func (self *testToolEnv) handle(t testing.TB, name string, arguments []byte) (*gomcp.CallToolResult, error) {
	session := self.server.newSession(self.claude.RelayHello("builder"))
	call := self.hookTestEnv.call(session)
	call.Network = self.tools
	return testToolHandle(t, self.catalog, call, name, arguments)
}

func FuzzMcpArguments(f *testing.F) {
	credential := string(testToolCredential)
	for _, seed := range []string{
		`{"text":"` + credential + `"}`,
		`{"text":"x","secret":"` + credential + `"}`,
		`{"text":["` + credential + `"]}`,
		`{"text":"` + hex.EncodeToString(testToolCredential) + `"}`,
		`{"text":"` + base64.StdEncoding.EncodeToString(testToolCredential) + `"}`,
		`{"size":"` + credential + `"}`,
		`{"text":"plain"}`,
		`not json ` + credential,
		`[` + credential + `]`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, arguments string) {
		env := newTestToolEnv(t)
		forms := []string{
			credential, hex.EncodeToString(testToolCredential), strings.ToUpper(hex.EncodeToString(testToolCredential)),
			base64.StdEncoding.EncodeToString(testToolCredential), base64.RawURLEncoding.EncodeToString(testToolCredential),
		}
		for _, name := range []string{"test_read", "test_fail", "test_fail_mcp", "test_untrusted"} {
			result, err := env.handle(t, name, []byte(arguments))
			answer := ""
			if err != nil {
				answer = err.Error()
				if wire, marshalErr := json.Marshal(err); marshalErr == nil {
					answer += string(wire)
				}
			}
			if result != nil {
				encoded, _ := json.Marshal(result)
				answer += string(encoded)
			}
			for _, form := range forms {
				if strings.Contains(answer, form) {
					t.Fatalf("%s answered the credential for %q: %s", name, arguments, answer)
				}
			}
		}
	})
}
