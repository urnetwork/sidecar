//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// The local profile's files, which IC-7 holds to: nothing in them starts a process or opens a socket.
var harnessLocalProfileFiles = []string{
	"harness_workspace.go",
	"harness_tool_files.go",
	"harness_tool_grep.go",
	"harness_git_path.go",
}

// IC-7 over the local profile's files' code: none imports os/exec, net, a socket or process package, or syscall, and
// none calls os.StartProcess, so no file tool can start a process or open a socket; a syscall trace on each desktop OS
// is the review phase's (§18's Harness row).
func TestHarnessLocalProfileImportsNoProcessOrSocket(t *testing.T) {
	refusedImports := map[string]bool{
		"os/exec": true, "syscall": true, "net": true, "net/http": true, "net/rpc": true, "plugin": true,
		"golang.org/x/sys/unix": true, "golang.org/x/sys/windows": true, "github.com/urnetwork/connect": true,
	}
	refusedCalls := map[string]bool{"os.StartProcess": true, "syscall.Exec": true, "syscall.ForkExec": true,
		"syscall.StartProcess": true, "os.Pipe": true}
	fileSet := token.NewFileSet()
	for _, name := range harnessLocalProfileFiles {
		file, err := parser.ParseFile(fileSet, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			path, _ := strconv.Unquote(spec.Path.Value)
			if refusedImports[path] {
				t.Errorf("%s imports %s", name, path)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := selector.X.(*ast.Ident); ok && refusedCalls[pkg.Name+"."+selector.Sel.Name] {
				t.Errorf("%s calls %s.%s", name, pkg.Name, selector.Sel.Name)
			}
			return true
		})
	}
}
