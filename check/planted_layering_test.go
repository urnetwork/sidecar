//go:build sidecar_check

// The layering row's planted violations, and the imports each rule must still allow.

package check

import (
	"testing"
)

func TestLayeringFailsOnTheRootImportingDevice(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("device/device.go", "package device\n")
	fixture.write("planted.go", "package sidecar\n\nimport _ \"@module@/device\"\n")
	wantFindings(t, fixture.open().rootImportFindings(t), "planted.go:3: the root imports @module@/device")
}

// No leg compiles this file, so only the syntax rule can see it.
func TestLayeringFailsOnAnImportNoLegCompiles(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("planted.go", "//go:build never_set\n\npackage sidecar\n\nimport mcp \"@module@/mcp\"\n\nvar _ = mcp.Name\n")
	wantFindings(t, fixture.open().rootImportFindings(t), "planted.go:5: the root imports @module@/mcp")
}

// CODESTYLE: an internal test file is the package, and obeys its rule.
func TestLayeringFailsOnAnInternalTestImport(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("device/device.go", "package device\n")
	fixture.write("planted_test.go", "package sidecar\n\nimport _ \"@module@/device\"\n")
	wantFindings(t, fixture.open().rootImportFindings(t), "planted_test.go:3: the root imports @module@/device")
}

// CODESTYLE: an external test package is a separately compiled consumer.
func TestLayeringAllowsAnExternalTestImport(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("device/device.go", "package device\n")
	fixture.write("planted_test.go", "package sidecar_test\n\nimport _ \"@module@/device\"\n")
	wantFindings(t, fixture.open().rootImportFindings(t))
}

// CODESTYLE: non-test files and mismatched package names cannot claim that boundary.
func TestLayeringFailsOnANonTestFileClaimingTheExternalPackage(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("planted.go", "//go:build never_set\n\npackage sidecar_test\n\nimport _ \"@module@/device\"\n")
	fixture.write("other_test.go", "//go:build never_set\n\npackage other_test\n\nimport _ \"@module@/mcp\"\n")
	wantFindings(t, fixture.open().rootImportFindings(t),
		"other_test.go:5: the root imports @module@/mcp",
		"planted.go:5: the root imports @module@/device")
}

func TestLayeringFailsOnProtocolImportingTheRoot(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("protocol/planted.go", "package protocol\n\nimport _ \"@module@\"\n")
	wantFindings(t, fixture.open().protocolImportFindings(t), "protocol/planted.go:3: protocol imports @module@")
}

func TestLayeringFailsOnProtocolImportingConnect(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("protocol/planted.go", "package protocol\n\nimport _ \"@connect@/protocol\"\n")
	wantFindings(t, fixture.open().protocolImportFindings(t), "protocol/planted.go:3: protocol imports @connect@/protocol")
}

func TestLayeringFailsOnBridgeImportingProtocol(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("protocol/bridge/planted.go", "//go:build never_set\n\npackage bridge\n\nimport _ \"@module@/protocol\"\n")
	wantFindings(t, fixture.open().protocolImportFindings(t), "protocol/bridge/planted.go:5: protocol/bridge imports @module@/protocol")
}

// By whole path elements: protobuf's own module, not whatever starts with its name.
func TestLayeringFailsOnANameThatOnlySharesProtobufsPrefix(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("protocol/bridge/planted.go", "//go:build never_set\n\npackage bridge\n\nimport _ \"google.golang.org/protobufx/proto\"\n")
	wantFindings(t, fixture.open().protocolImportFindings(t), "protocol/bridge imports google.golang.org/protobufx/proto")
}

func TestLayeringAllowsProtocolOverBridgeAndProtobuf(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("protocol/planted.go", "//go:build never_set\n\npackage protocol\n\nimport (\n\t_ \"fmt\"\n\n\t_ \"@module@/protocol/bridge\"\n\t_ \"google.golang.org/protobuf/proto\"\n)\n")
	fixture.write("protocol/bridge/planted.go", "//go:build never_set\n\npackage bridge\n\nimport (\n\t_ \"crypto/ed25519\"\n\n\t_ \"google.golang.org/protobuf/proto\"\n)\n")
	wantFindings(t, fixture.open().protocolImportFindings(t))
}

func TestLayeringFailsOnTheRootImportingAnEngine(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("evsservice/engine.go", "package evsservice\n")
	fixture.write("planted.go", "package sidecar\n\nimport _ \"@module@/evsservice\"\n")
	wantFindings(t, fixture.open().clientEngineImportFindings(t), "the client package . imports @module@/evsservice")
}

// Every package starts out a client, so a new one is bound the day it appears.
func TestLayeringFailsOnANewPackageImportingAnEngine(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("evsservice/store/store.go", "package store\n")
	fixture.write("newthing/thing.go", "package newthing\n\nimport _ \"@module@/evsservice/store\"\n")
	wantFindings(t, fixture.open().clientEngineImportFindings(t), "the client package newthing imports @module@/evsservice/store")
}

func TestLayeringFailsOnCliImportingAnEngine(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("gkmservice/engine.go", "package gkmservice\n")
	fixture.write("cli/planted.go", "package main\n\nimport _ \"@module@/gkmservice\"\n")
	wantFindings(t, fixture.open().clientEngineImportFindings(t), "the client package cli imports @module@/gkmservice")
}

// §22.4's T2 hosts engines in sidecartest, and §4.4 lets a service reach a peer.
func TestLayeringAllowsEnginesAndSidecartestToImportEngines(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("evsservice/engine.go", "package evsservice\n")
	fixture.write("gkmservice/engine.go", "package gkmservice\n\nimport _ \"@module@/evsservice\"\n")
	fixture.write("sidecartest/net.go", "package sidecartest\n\nimport _ \"@module@/evsservice\"\n")
	wantFindings(t, fixture.open().clientEngineImportFindings(t))
}

// Each import here is allowed on its own, and the closure still reaches an engine.
// An engine ships in server, so it may link a peer, but sidecartest's fakes reach no release at all.
func TestLayeringFailsOnAnEngineLinkingSidecartest(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("engines linux/amd64")
	fixture.write("sidecartest/net.go", "package sidecartest\n")
	fixture.write("evsservice/engine.go", "package evsservice\n\nimport _ \"@module@/sidecartest\"\n")
	wantFindings(t, fixture.open().legEngineFindings(t), "engines linux/amd64 links @module@/sidecartest")
}

func TestLayeringFailsOnAnEngineThroughSidecartest(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("cli linux/amd64")
	fixture.write("evsservice/engine.go", "package evsservice\n")
	fixture.write("sidecartest/net.go", "package sidecartest\n\nimport _ \"@module@/evsservice\"\n")
	fixture.write("mcp/mcp.go", "package mcp\n\nimport _ \"@module@/sidecartest\"\n")
	fixture.write("cli/planted.go", "package main\n\nimport _ \"@module@/mcp\"\n")
	wantFindings(t, fixture.open().legEngineFindings(t),
		"cli linux/amd64 links @module@/evsservice",
		"cli linux/amd64 links @module@/sidecartest")
}

func TestLayeringFailsOnDeviceImportingTheRoot(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("device/planted.go", "package device\n\nimport _ \"@module@\"\n")
	wantFindings(t, fixture.open().deviceImportFindings(t), "device/planted.go:3: device imports @module@")
}

func TestLayeringFailsOnDeviceImportingProtocol(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("device/planted.go", "package device\n\nimport _ \"@module@/protocol\"\n")
	wantFindings(t, fixture.open().deviceImportFindings(t), "device imports @module@/protocol")
}

// §4.4 binds device's hook files as well: under the tag it keeps an installer of its own (testhook.go),
// so a tagged file there has no reason to reach the root.
func TestLayeringFailsOnDevicesTaggedHookFileImportingTheRoot(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("device/device.go", "package device\n\nimport (\n\t_ \"@connect@\"\n\t_ \"@module@/protocol/bridge\"\n)\n")
	fixture.write("device/testhook_enabled.go", "//go:build sidecar_testhooks\n\npackage device\n\nimport _ \"@module@\"\n")
	wantFindings(t, fixture.open().deviceImportFindings(t), "device/testhook_enabled.go:5: device imports @module@")
}

func TestLayeringFailsOnAParentImportingItsChild(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("mcp/mcp.go", "package mcp\n\nimport _ \"@module@/mcp/tools\"\n")
	fixture.write("mcp/tools/tools.go", "package tools\n")
	wantFindings(t, fixture.open().parentImportFindings(t), "mcp imports its child @module@/mcp/tools")
}

func TestLayeringFailsOnAPbGoOutsideProtocol(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("mcp/record.pb.go", "package mcp\n")
	wantFindings(t, fixture.open().protoHomeFindings(t), "mcp/record.pb.go: generated protobuf outside protocol and protocol/bridge")
}
