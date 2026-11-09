//go:build sidecar_check

// X9's planted violations, one per clause of x9_test.go. The fixture's connect is a git checkout whose
// main is the clean tree (fixture_test.go), so a plant written to its working tree is HEAD against main,
// as a connect track's change is against connect's main. Protos build with the real protoc.

package check

import (
	"slices"
	"strings"
	"testing"
)

// The rules' reports, captured.
func x9Reports(repository *repository) *[]string {
	reports := []string{}
	repository.report = func(format string, arguments ...any) {
		reports = append(reports, findingf(format, arguments...))
	}
	return &reports
}

// A test file in the fixture's connect declaring each named test.
func plantConnectTests(fixture *fixture, file string, names ...string) {
	source := strings.Builder{}
	source.WriteString("package connect\n\nimport \"testing\"\n")
	for _, name := range names {
		source.WriteString("\nfunc " + name + "(t *testing.T) {}\n")
	}
	fixture.writeSibling("connect/"+file, source.String())
}

func TestX9FailsOnAnExportedReservedRegistration(t *testing.T) {
	fixture := newFixture(t)
	fixture.writeSibling("connect/subprotocol.go", "package connect\n\nfunc RegisterReservedSubprotocol(id uint16) {}\n")
	wantFindings(t, fixture.open().x9ShapeFindings(t), "C1: connect exports RegisterReservedSubprotocol")
}

func TestX9FailsOnAFilterOption(t *testing.T) {
	fixture := newFixture(t)
	fixture.writeSibling("connect/subprotocol.go", `package connect

type SubprotocolListenerOption struct{}

func WithSubprotocolControlSource() SubprotocolListenerOption {
	return SubprotocolListenerOption{}
}

func WithSubprotocolMaxByteCount(byteCount int) SubprotocolListenerOption {
	return SubprotocolListenerOption{}
}
`)
	wantFindings(t, fixture.open().x9ShapeFindings(t), "C2: connect's WithSubprotocolMaxByteCount makes a SubprotocolListenerOption")
}

func TestX9FailsOnAJsCarrier(t *testing.T) {
	fixture := newFixture(t)
	fixture.writeSibling("connect/transport_ws_js.go", "package connect\n\n// A browser WebSocket carrier.\nfunc dialBrowserSocket() {}\n")
	wantFindings(t, fixture.open().x9ShapeFindings(t), "C4: connect's transport_ws_js.go is a js carrier")
}

func TestX9FailsOnATunForwarder(t *testing.T) {
	fixture := newFixture(t)
	fixture.writeSibling("connect/tun_forward.go", "package connect\n\nfunc NewTunForwarder() {}\n")
	wantFindings(t, fixture.open().x9ShapeFindings(t), "C6b: connect declares NewTunForwarder")
}

func TestX9FailsOnACallerLaneKey(t *testing.T) {
	fixture := newFixture(t)
	fixture.writeSibling("connect/transfer.go", "package connect\n\ntype TransferOptions struct {\n\tAck     bool\n\tLaneKey uint32\n}\n")
	wantFindings(t, fixture.open().x9ShapeFindings(t), "C7: TransferOptions.LaneKey is a caller lane key")
}

// URmessage's push value is on connect's main and is not X8's, so only a value main lacks fails.
func TestX9FailsOnAPushMessageType(t *testing.T) {
	fixture := newFixture(t)
	fixture.writeSibling("connect/protocol/frame.proto", "syntax = \"proto3\";\npackage bringyour;\n\nenum MessageType {\n    TransferPack = 0;\n    MessageServerPush = 1002;\n}\n")
	fixture.commitConnect("a MessageType with URmessage's push")
	wantFindings(t, fixture.open().x9ShapeFindings(t))

	fixture.writeSibling("connect/protocol/frame.proto", "syntax = \"proto3\";\npackage bringyour;\n\nenum MessageType {\n    TransferPack = 0;\n    MessageServerPush = 1002;\n    SidecarPush = 40;\n}\n")
	wantFindings(t, fixture.open().x9ShapeFindings(t), "C10: bringyour.MessageType.SidecarPush is a push MessageType")
}

func TestX9FailsOnAGvisorFreeJsTag(t *testing.T) {
	fixture := newFixture(t)
	fixture.writeSibling("connect/connect.go", "//go:build !js\n\n"+fixtureFiles["connect/connect.go"])
	wantFindings(t, fixture.open().x9ShapeFindings(t), "C17: connect's connect.go imports gVisor and is left out of the js build")

	fixture.writeSibling("connect/connect.go", "//go:build !connect_without_gvisor\n\n"+fixtureFiles["connect/connect.go"])
	wantFindings(t, fixture.open().x9ShapeFindings(t), "C17: connect's connect.go imports gVisor under a build constraint")
}

// A plant of one proto at main, then another at HEAD.
func plantConnectProto(t *testing.T, mainProto string, headProto string) *fixture {
	t.Helper()
	fixture := newFixture(t)
	fixture.writeSibling("connect/protocol/transfer.proto", "syntax = \"proto3\";\npackage bringyour;\n\n"+mainProto)
	fixture.commitConnect("connect's protocol at main")
	fixture.writeSibling("connect/protocol/transfer.proto", "syntax = \"proto3\";\npackage bringyour;\n\n"+headProto)
	return fixture
}

func TestX9FailsOnARenumberedField(t *testing.T) {
	fixture := plantConnectProto(t, "message Seal {\n    bytes source = 1;\n}\n", "message Seal {\n    bytes source = 2;\n}\n")
	wantFindings(t, fixture.open().x9ProtoFindings(t), "connect's HEAD renumbers field bringyour.Seal.source from 1 to 2")
}

func TestX9FailsOnARetypedField(t *testing.T) {
	fixture := plantConnectProto(t, "message Seal {\n    bytes source = 1;\n}\n", "message Seal {\n    string source = 1;\n}\n")
	wantFindings(t, fixture.open().x9ProtoFindings(t), "connect's HEAD retypes field bringyour.Seal.source = 1")
}

func TestX9FailsOnARemovedEnumValue(t *testing.T) {
	fixture := plantConnectProto(t, "enum ProvideMode {\n    None = 0;\n    Network = 1;\n}\n", "enum ProvideMode {\n    None = 0;\n}\n")
	wantFindings(t, fixture.open().x9ProtoFindings(t), "connect's HEAD removes enum value bringyour.ProvideMode.Network = 1")
}

func TestX9FailsOnARemovedMessage(t *testing.T) {
	fixture := plantConnectProto(t, "message Seal {\n    bytes source = 1;\n}\n\nmessage Old {\n}\n", "message Seal {\n    bytes source = 1;\n}\n")
	wantFindings(t, fixture.open().x9ProtoFindings(t), "connect's HEAD removes message bringyour.Old")
}

// Additive is what D-REPO-5 allows: a new field, value, message and enum pass.
func TestX9AllowsAnAddedField(t *testing.T) {
	fixture := plantConnectProto(t,
		"message Seal {\n    bytes source = 1;\n}\n\nenum ProvideMode {\n    None = 0;\n}\n",
		"message Seal {\n    bytes source = 1;\n    bytes source_subject_client_id = 2;\n}\n\nmessage Window {\n}\n\nenum ProvideMode {\n    None = 0;\n    Service = 6;\n}\n\nenum Kind {\n    Unset = 0;\n}\n")
	wantFindings(t, fixture.open().x9ProtoFindings(t))
}

// With nothing to compare against, the rule cannot show anything additive, so it fails.
func TestX9FailsWithoutConnectsMain(t *testing.T) {
	fixture := newFixture(t)
	fixture.gitConnect("branch", "-m", "main", "trunk")
	wantFindings(t, fixture.open().x9ProtoFindings(t), "has no main branch")
}

func TestX9FailsOnC18BeforeC13(t *testing.T) {
	fixture := newFixture(t)
	fixture.writeSibling("connect/ip_egress_hook.go", "package connect\n\ntype EgressHook interface{}\n\ntype LocalUserNatSettings struct {\n\tFriendsAndFamilyEgress bool\n}\n")
	wantFindings(t, fixture.open().x9OrderFindings(t), "C18's marker FriendsAndFamilyEgress is in connect before C13's source_subject_client_id")

	fixture.writeSibling("connect/protocol/transfer.proto", "syntax = \"proto3\";\npackage bringyour;\n\nmessage StoredContract {\n    bytes source_subject_client_id = 1;\n}\n")
	wantFindings(t, fixture.open().x9OrderFindings(t))
}

func TestX9FailsOnConnectRequiringSidecar(t *testing.T) {
	fixture := newFixture(t)
	fixture.writeSibling("connect/go.mod", fixtureFiles["connect/go.mod"]+"\nrequire @module@ v0.0.0\n")
	wantFindings(t, fixture.open().x9ConnectRequireFindings(t), "connect's go.mod requires @module@")
}

// A branch build reports a landed marker with no default-off test, and passes.
func TestX9ReportsAMarkerWithNoDefaultOffTest(t *testing.T) {
	fixture := newFixture(t)
	fixture.writeSibling("connect/ip_mux_upgrade.go", "package connect\n\ntype UpgradeMux struct{}\n\nfunc (self *UpgradeMux) SetLocalZone() {}\n")
	repository := fixture.open()
	reports := x9Reports(repository)
	wantFindings(t, repository.x9DefaultOffReport(t))
	if !slices.ContainsFunc(*reports, func(line string) bool {
		return strings.Contains(line, "C14's marker SetLocalZone is in connect, and its default-off test TestUpgradeMuxLocalZoneNilKeepsTodaysBehavior is not in connect's tests")
	}) {
		t.Errorf("the report %v does not name C14's missing test", *reports)
	}
}

func TestX9ReadyForMainRefusesAMarkerWithNoDefaultOffTest(t *testing.T) {
	fixture := newFixture(t)
	fixture.writeSibling("connect/ip_mux_upgrade.go", "package connect\n\ntype UpgradeMux struct{}\n\nfunc (self *UpgradeMux) SetLocalZone() {}\n")
	wantFindings(t, fixture.open().x9ReadyForMainFindings(t, 0), "C14's marker SetLocalZone is in connect, and its default-off test")

	plantConnectTests(fixture, "ip_mux_upgrade_local_zone_test.go", "TestUpgradeMuxLocalZoneNilKeepsTodaysBehavior")
	wantFindings(t, fixture.open().x9ReadyForMainFindings(t, 0))
}

// §4.17: C19's sweep passes in connect's own tests before connect's main.
func TestX9ReadyForMainRefusesC19WithoutItsSweep(t *testing.T) {
	fixture := newFixture(t)
	fixture.writeSibling("connect/transfer_peer_window.go", "package connect\n\ntype Client struct{}\n\nfunc (self *Client) SetPeerWindowAccounting() {}\n")
	plantConnectTests(fixture, "transfer_peer_window_test.go", "TestPeerWindowOffReportsAreIdentical", "TestPeerWindowUnmarkedPairIsUnchanged")
	wantFindings(t, fixture.open().x9ReadyForMainFindings(t, 0), "C19's marker SetPeerWindowAccounting is in connect without FS-125's sweep")

	plantConnectTests(fixture, "transfer_peer_window_sweep_test.go")
	wantFindings(t, fixture.open().x9ReadyForMainFindings(t, 0), "C19's marker SetPeerWindowAccounting is in connect without FS-125's sweep")

	plantConnectTests(fixture, "transfer_peer_window_sweep_test.go", "TestFs125WindowSweepDown")
	wantFindings(t, fixture.open().x9ReadyForMainFindings(t, 0))
}

// Plants C3, C11 and C12, which M1 lands, with their default-off tests where they need one.
func plantM1ConnectRows(fixture *fixture) {
	fixture.writeSibling("connect/subprotocol.go", "package connect\n\ntype SubprotocolListenerOption struct{}\n\nfunc WithSubprotocolControlSource() SubprotocolListenerOption {\n\treturn SubprotocolListenerOption{}\n}\n")
	plantConnectTests(fixture, "subprotocol_source_test.go", "TestSourceRuleOptInsAreOffByDefault", "TestSubprotocolControlSourceDroppedWithoutOptIn", "TestDefaultClientP2pRouteAcceptsAnySource")
	fixture.writeSibling("connect/api/bringyour.yml", "paths:\n  /sidecar/bind:\n    post: {}\n")
	fixture.writeSibling("connect/SUBPROTOCOL.md", "The sidecar's one subprotocol is 21842.\n")
}

// A renamed marker reads as a row not landed, so a row due by the gate fails.
func TestX9ReadyForMainRefusesARowDueWithNoMarker(t *testing.T) {
	fixture := newFixture(t)
	plantM1ConnectRows(fixture)
	fixture.writeSibling("connect/transfer.go", "package connect\n\ntype Peer struct{}\n\nfunc (self Peer) VerifiedClientKey() {}\n")
	wantFindings(t, fixture.open().x9ReadyForMainFindings(t, 1), "C15 is due by M1")
	wantFindings(t, fixture.open().x9ReadyForMainFindings(t, 0))
}

func TestX9ReadyForMainPassesAReadyConnect(t *testing.T) {
	fixture := newFixture(t)
	plantM1ConnectRows(fixture)
	fixture.writeSibling("connect/transfer.go", "package connect\n\ntype Peer struct{}\n\nfunc (self Peer) VerifiedClientPublicKey() {}\n")
	plantConnectTests(fixture, "transfer_peer_client_key_test.go", "TestPeerVerifiedClientKeyIsOffByDefault")
	wantFindings(t, fixture.open().x9ReadyForMainFindings(t, 1))
	wantFindings(t, fixture.open().x9ReadyForMainFindings(t, 4), "C5 is due by M4", "C6a is due by M4", "C8 is due by M4", "C13 is due by M4", "C14 is due by M4", "C16 is due by M4")
}
