//go:build sidecar_check

// A small monoroot on disk: this repository's shape with sibling modules of the real names, so a
// fixture goes through the real rules, the real leg table and the real go command, and resolves
// entirely through local replaces. A planted violation is then one write away from a clean tree,
// and TestFixtureIsClean shows the clean tree passes, so what a planted test finds is what it
// planted. Text may use @module@ and the other tokens in fixtureTokens, which keeps first-party
// paths out of quoted strings for the release's sed.

package check

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

const (
	fixtureMitLicense = "Copyright (c) 2026 Example\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software.\n"
	fixtureMplLicense = "This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.\n"
	fixtureApache     = "Apache License\nVersion 2.0, January 2004\n"
)

// What a fixture's text may spell with a token.
var fixtureTokens = strings.NewReplacer(
	"@module@", sidecarBasePath,
	"@connect@", connectBasePath,
	"@glog@", glogBasePath,
	"@server@", serverBasePath,
	"@sdk@", sdkBasePath,
	"@sn@", snBasePath,
	"@proxy@", urnetworkPrefix+"proxy",
	"@userwireguard@", urnetworkPrefix+"userwireguard",
)

// §4.7's replaces, from the root module.
const fixtureSiblingReplaces = `
replace @connect@ => ../connect

replace github.com/pion/sctp => ../connect/sctp

replace @glog@ => ../glog

replace gvisor.dev/gvisor => ../gvisor
`

// The same, repeated one level up in a nested module.
const fixtureNestedReplaces = `
replace @connect@ => ../../connect

replace github.com/pion/sctp => ../../connect/sctp

replace @glog@ => ../../glog

replace gvisor.dev/gvisor => ../../gvisor
`

// What connect brings, which every module on a connect leg lists.
const fixtureIndirectRequires = `
require (
	github.com/pion/sctp v1.0.0 // indirect
	@glog@ v0.0.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gvisor.dev/gvisor v0.0.0-20260909230408-9b1144b679cb // indirect
)
`

// Each module the clean tree links, and protobuf for the tests that plant protos.
const fixtureDependencies = `# a fixture's dependencies.yml
modules:
  - module: @connect@
    spdx: MPL-2.0
    reason: the fixture's connect
    leg: [client, engine, cli, test]
  - module: github.com/pion/sctp
    spdx: MIT
    reason: the fixture's sctp fork
    leg: [client, engine, cli, test]
  - module: @glog@
    spdx: Apache-2.0
    reason: the fixture's glog
    leg: [client, engine, cli, test]
  - module: gvisor.dev/gvisor
    spdx: Apache-2.0
    reason: the fixture's gvisor
    leg: [client, engine, cli, test]
  - module: google.golang.org/protobuf
    spdx: BSD-3-Clause
    reason: planted protos link it
    leg: [client, engine, cli, test]
    planned: true
`

// The clean tree, by path from the fixture's top. sidecar/ is the checkout; the rest are siblings.
var fixtureFiles = map[string]string{
	"connect/go.mod":               "module @connect@\n\ngo 1.27.3\n\nrequire (\n\t@glog@ v0.0.0\n\tgithub.com/pion/sctp v1.0.0\n\tgvisor.dev/gvisor v0.0.0-20260909230408-9b1144b679cb\n)\n",
	"connect/LICENSE":              fixtureMplLicense,
	"connect/connect.go":           "package connect\n\nimport (\n\t_ \"@glog@\"\n\t_ \"github.com/pion/sctp\"\n\t_ \"gvisor.dev/gvisor/pkg/tcpip\"\n)\n\nfunc Connect() {}\n",
	"connect/protocol/protocol.go": "package protocol\n\nfunc Frame() {}\n",
	"connect/sctp/go.mod":          "module github.com/pion/sctp\n\ngo 1.27.3\n",
	"connect/sctp/LICENSE":         fixtureMitLicense,
	"connect/sctp/sctp.go":         "package sctp\n",
	"glog/go.mod":                  "module @glog@\n\ngo 1.27.3\n",
	"glog/LICENSE":                 fixtureApache,
	"glog/glog.go":                 "package glog\n",
	"gvisor/go.mod":                "module gvisor.dev/gvisor\n\ngo 1.27.3\n",
	"gvisor/LICENSE":               fixtureApache,
	"gvisor/pkg/tcpip/tcpip.go":    "package tcpip\n",

	"sdk/dependency_boundary_test.go": "package sdk\n\nvar messagingBoundaryLegs = []messagingBoundaryLeg{\n\t{name: \"root linux/amd64\", environment: []string{\"GOOS=linux\", \"GOARCH=amd64\"}},\n}\n",
	"sdk/go.mod":                      "module @sdk@\n\ngo 1.27.3\n\nrequire golang.org/x/text v0.43.0\n",
	"sdk/sdk.go":                      "package sdk\n",
	"sdk/build/Makefile":              "build_ios:\n\tgomobile bind -tags sdk_mobile_bind,ios_extension\n",
	"sdk/cgo/Makefile":                "build:\n\tgo build -buildmode=c-shared\n",
	"sdk/js/Makefile":                 "build:\n\tGOOS=js GOARCH=wasm go build\n",
	"sdk/js/go.mod":                   "module @sdk@/js\n\ngo 1.27.3\n\nrequire golang.org/x/text v0.43.0\n",
	"sdk/cgo/go.mod":                  "module @sdk@/cgo\n\ngo 1.27.3\n\nrequire golang.org/x/text v0.43.0\n",
	"sdk/build/go.mod":                "module @sdk@/build\n\ngo 1.27.3\n\nrequire golang.org/x/text v0.43.0\n",
	"server/go.mod":                   "module @server@\n\ngo 1.27.3\n",
	"server/model/model.go":           "package model\n",
	"server/cli/api/Makefile":         "build:\n\tgo build\n",
	"sn/go.mod":                       "module @sn@\n\ngo 1.27.3\n",
	"sn/sn.go":                        "package sn\n",
	"proxy/go.mod":                    "module @proxy@\n\ngo 1.27.3\n",
	"proxy/proxy.go":                  "package proxy\n",

	"sidecar/go.mod":             "module @module@\n\ngo 1.27.3\n\ntool google.golang.org/protobuf/cmd/protoc-gen-go\n\nrequire @connect@ v0.0.0\n" + fixtureIndirectRequires + fixtureSiblingReplaces,
	"sidecar/dependencies.yml":   fixtureDependencies,
	"sidecar/sidecar.go":         "package sidecar\n\nfunc Sidecar() {}\n",
	"sidecar/connect_require.go": "//go:build !sidecar_http\n\npackage sidecar\n\nimport _ \"@connect@\"\n",
	"sidecar/testhook.go":        "//go:build !sidecar_testhooks\n\npackage sidecar\n\nfunc testHookSecret(kind string, secret []byte) {}\n\nfunc testHookBarrier(name string, key string) {}\n",
	"sidecar/testhook_enabled.go": `//go:build sidecar_testhooks

package sidecar

type TestHooks struct{}

func SetTestHooks(hooks *TestHooks) {}

func TestHookSecret(kind string, secret []byte) {
	testHookSecret(kind, secret)
}

func TestHookBarrier(name string, key string) {
	testHookBarrier(name, key)
}

func testHookSecret(kind string, secret []byte) {
	println(kind)
}

func testHookBarrier(name string, key string) {
	println(name)
}
`,
	"sidecar/protocol/doc.go":        "package protocol\n",
	"sidecar/protocol/bridge/doc.go": "package bridge\n",

	"sidecar/cli/go.mod": "module @module@/cli\n\ngo 1.27.3\n\nrequire (\n\t@module@ v0.0.0\n\t@module@/smtpproof v0.0.0\n)\n\nrequire @connect@ v0.0.0 // indirect\n" + fixtureIndirectRequires +
		"\nreplace @module@ => ..\n\nreplace @module@/smtpproof => ../smtpproof\n" + fixtureNestedReplaces,
	"sidecar/cli/main.go": "package main\n\nimport (\n\t_ \"@module@\"\n\t_ \"@module@/smtpproof\"\n)\n\nfunc main() {}\n",

	"sidecar/smtpproof/go.mod": "module @module@/smtpproof\n\ngo 1.27.3\n\nreplace @module@ => ..\n" + fixtureNestedReplaces,
	"sidecar/smtpproof/doc.go": "package smtpproof\n",

	"sidecar/mlsinterop/go.mod": "module @module@/mlsinterop\n\ngo 1.27.3\n\nreplace @module@ => ..\n" + fixtureNestedReplaces,
	"sidecar/mlsinterop/doc.go": "package mlsinterop\n",
}

// A fixture on disk, with what a test can do to it.
type fixture struct {
	t         testing.TB
	directory string
	// the rule settings a test may change before opening
	settings *checkSettings
	legs     []*buildLeg
}

// The real root module's go.sum, which covers protobuf for a fixture. Read once.
var realGoSum = sync.OnceValues(func() ([]byte, error) {
	return os.ReadFile(filepath.Join("..", "go.sum"))
})

// Writes the clean tree.
func newFixture(t testing.TB) *fixture {
	t.Helper()
	self := &fixture{
		t:         t,
		directory: t.TempDir(),
		settings:  defaultCheckSettings(),
		legs:      defaultBuildLegs(),
	}
	// a fixture's connect is not the sibling that fills the exception's row, and one the fixture
	// never lists would be reported as a stale exception
	self.settings.licenseExceptions = map[string]licenseException{}
	for name, content := range fixtureFiles {
		self.writeSibling(name, content)
	}
	goSum, err := realGoSum()
	if err != nil {
		t.Fatal(err)
	}
	for _, module := range []string{"sidecar", "sidecar/cli", "sidecar/smtpproof", "sidecar/mlsinterop"} {
		self.writeSibling(module+"/go.sum", string(goSum))
	}
	return self
}

// Writes a file from the fixture's top, after the tokens.
func (self *fixture) writeSibling(name string, content string) {
	self.t.Helper()
	fullPath := filepath.Join(self.directory, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
		self.t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte(fixtureTokens.Replace(content)), 0o600); err != nil {
		self.t.Fatal(err)
	}
}

// Writes a file in the checkout, which is where nearly every violation is planted.
func (self *fixture) write(name string, content string) {
	self.t.Helper()
	self.writeSibling("sidecar/"+name, content)
}

// Removes a file in the checkout.
func (self *fixture) remove(name string) {
	self.t.Helper()
	if err := os.Remove(filepath.Join(self.directory, "sidecar", filepath.FromSlash(name))); err != nil {
		self.t.Fatal(err)
	}
}

// Edits a file in the checkout with one exact replacement, which must apply.
func (self *fixture) edit(name string, old string, new string) {
	self.t.Helper()
	fullPath := filepath.Join(self.directory, "sidecar", filepath.FromSlash(name))
	data, err := os.ReadFile(fullPath)
	if err != nil {
		self.t.Fatal(err)
	}
	old = fixtureTokens.Replace(old)
	if !strings.Contains(string(data), old) {
		self.t.Fatalf("%s holds no %q", name, old)
	}
	if err := os.WriteFile(fullPath, []byte(strings.Replace(string(data), old, fixtureTokens.Replace(new), 1)), 0o600); err != nil {
		self.t.Fatal(err)
	}
}

// Adds a require and a sibling replace to the root module, for a module the fixture provides.
func (self *fixture) requireLocal(modulePath string, version string, target string) {
	self.t.Helper()
	data, err := os.ReadFile(filepath.Join(self.directory, "sidecar", "go.mod"))
	if err != nil {
		self.t.Fatal(err)
	}
	self.write("go.mod", string(data)+"\nrequire "+modulePath+" "+version+"\n\nreplace "+modulePath+" => ../"+target+"\n")
}

// Keeps only the named legs, for a test about one of them: each leg costs a go list.
func (self *fixture) keepLegs(names ...string) {
	self.t.Helper()
	legs := []*buildLeg{}
	for _, leg := range self.legs {
		if slices.Contains(names, leg.name) {
			legs = append(legs, leg)
		}
	}
	if len(legs) != len(names) {
		self.t.Fatalf("legs %v are not all in the table", names)
	}
	self.legs = legs
}

// A repository over the fixture as it stands.
func (self *fixture) open() *repository {
	self.t.Helper()
	repository, err := openRepository(filepath.Join(self.directory, "sidecar"), self.settings, self.legs)
	if err != nil {
		self.t.Fatal(err)
	}
	repository.report = self.t.Logf
	return repository
}

// Fails unless findings are exactly as many as wants, each holding its want in the same order.
func wantFindings(t testing.TB, findings []string, wants ...string) {
	t.Helper()
	if len(findings) != len(wants) {
		t.Errorf("%d findings, want %d:\n%s", len(findings), len(wants), strings.Join(findings, "\n"))
		return
	}
	for index, want := range wants {
		if !strings.Contains(findings[index], fixtureTokens.Replace(want)) {
			t.Errorf("finding %d lacks %q:\n%s", index, want, findings[index])
		}
	}
}
