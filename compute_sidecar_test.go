//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Each compute component's settings as CARCH-M11-01 creates them (DESIGN-COMPUTE §3.3, CONTRACTS C-38): its field on
// SidecarSettings, its type and the file its area fills.
var testComputeSettingsComponents = []struct {
	field    string
	typeName string
	file     string
}{
	{field: "Harness", typeName: "HarnessSettings", file: "harness_settings.go"},
	{field: "Session", typeName: "SessionSettings", file: "session_settings.go"},
	{field: "Infer", typeName: "InferSettings", file: "infer_settings.go"},
	{field: "Attest", typeName: "AttestSettings", file: "attest_settings.go"},
	{field: "Disclosure", typeName: "ComputeDisclosureSettings", file: "disclosure_settings.go"},
	{field: "Budget", typeName: "BudgetSettings", file: "budget_settings.go"},
	{field: "ModelsKey", typeName: "ModelsKeySettings", file: "models_settings.go"},
	{field: "ComputePolicy", typeName: "ComputePolicySettings", file: "acl_compute_settings.go"},
	{field: "Compute", typeName: "ComputeClientSettings", file: "compute_client_settings.go"},
	{field: "Gateway", typeName: "GatewaySettings", file: "gateway_settings.go"},
	{field: "Enclave", typeName: "EnclaveSettings", file: "enclave_settings.go"},
	{field: "Ssh", typeName: "SshSettings", file: "ssh_settings.go"},
	{field: "Git", typeName: "GitSettings", file: "git_settings.go"},
	{field: "Skill", typeName: "SkillSettings", file: "skill_settings.go"},
	{field: "WebSearch", typeName: "WebSearchSettings", file: "websearch_settings.go"},
	{field: "Fetch", typeName: "FetchSettings", file: "fetch_settings.go"},
	{field: "Calendar", typeName: "CalendarSettings", file: "calendar_settings.go"},
	{field: "Oauth", typeName: "OauthSettings", file: "oauth_settings.go"},
	{field: "Listeners", typeName: "ListenersSettings", file: "listeners_settings.go"},
	{field: "Safety", typeName: "SafetySettings", file: "safety_settings.go"},
	{field: "Support", typeName: "SupportSettings", file: "support_settings.go"},
}

// Every compute component's settings is a field of the defaults, set, of its own type, and survives a JSON round trip
// under its field's name, which is the name apps and the sdk read.
func TestDefaultSidecarSettingsHasEveryComputeComponent(t *testing.T) {
	settings := reflect.ValueOf(DefaultSidecarSettings()).Elem()
	encoded := map[string]any{}
	for _, c := range testComputeSettingsComponents {
		field := settings.FieldByName(c.field)
		if !field.IsValid() {
			t.Errorf("SidecarSettings has no %s", c.field)
			continue
		}
		if field.Kind() != reflect.Pointer || field.Type().Elem().Name() != c.typeName {
			t.Errorf("SidecarSettings.%s is a %s, want *%s", c.field, field.Type(), c.typeName)
			continue
		}
		if field.IsNil() {
			t.Errorf("SidecarSettings.%s is nil by default", c.field)
			continue
		}
		encoded[c.field] = field.Interface()
	}
	data, err := json.Marshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &SidecarSettings{}
	if err := json.Unmarshal(data, decoded); err != nil {
		t.Fatal(err)
	}
	decodedValue := reflect.ValueOf(decoded).Elem()
	for _, c := range testComputeSettingsComponents {
		got := decodedValue.FieldByName(c.field)
		if !got.IsValid() || got.IsNil() || !reflect.DeepEqual(got.Interface(), settings.FieldByName(c.field).Interface()) {
			t.Errorf("%s did not survive a JSON round trip: %s", c.field, data)
		}
	}
	// a default validates with the rest, so no host has to fill a compute field it does not use
	valid := validSidecarSettings()
	if err := valid.validate(); err != nil {
		t.Errorf("the defaults with their compute settings: %v", err)
	}
}

// Every compute settings file is its area's, off the legs that run no compute, and holds its type; the stand-in is on
// exactly those legs (owner decision 197; DESIGN-COMPUTE §15.4).
func TestComputeSettingsFilesStayOffTheLegsWithoutCompute(t *testing.T) {
	legTags := []map[string]bool{
		{"ios_extension": true, "sdk_mobile_bind": true, "ios": true},
		{"sidecar_http": true, "js": true, "wasm": true},
	}
	builds := func(expression constraint.Expr, tags map[string]bool) bool {
		return expression.Eval(func(tag string) bool { return tags[tag] })
	}
	read := func(name string) (constraint.Expr, *ast.File) {
		syntax, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		for _, group := range syntax.Comments {
			for _, comment := range group.List {
				if constraint.IsGoBuild(comment.Text) {
					expression, err := constraint.Parse(comment.Text)
					if err != nil {
						t.Fatal(err)
					}
					return expression, syntax
				}
			}
		}
		t.Fatalf("%s has no build line", name)
		return nil, nil
	}
	for _, c := range testComputeSettingsComponents {
		expression, syntax := read(c.file)
		for _, tags := range legTags {
			if builds(expression, tags) {
				t.Errorf("%s builds on a leg without compute (%v)", c.file, tags)
			}
		}
		if !builds(expression, map[string]bool{}) {
			t.Errorf("%s does not build on a leg with compute", c.file)
		}
		if syntax.Scope.Lookup(c.typeName) == nil || syntax.Scope.Lookup("Default"+c.typeName) == nil {
			t.Errorf("%s does not declare %s and its default", c.file, c.typeName)
		}
	}
	expression, syntax := read("sidecar_compute_leg.go")
	for _, tags := range legTags {
		if !builds(expression, tags) {
			t.Errorf("the stand-in does not build where compute does not (%v)", tags)
		}
	}
	if builds(expression, map[string]bool{}) {
		t.Error("the stand-in builds beside the compute files")
	}
	for _, c := range testComputeSettingsComponents {
		if syntax.Scope.Lookup(c.typeName) == nil || syntax.Scope.Lookup("Default"+c.typeName) == nil {
			t.Errorf("the stand-in does not declare %s and its default", c.typeName)
		}
	}
}

// Package-level numeric constants and variables in a settings file, which QD-702 forbids: every limit is a field, its
// default set in the Default function. A declaration is numeric when its type is a number's, or its value holds a
// numeric literal or iota, or, in a const block, an earlier spec of the block was, since a bare name repeats it.
func testComputeSettingsConstantFindings(t *testing.T, fileNames []string) []string {
	t.Helper()
	numericTypes := []string{
		"int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64", "uintptr",
		"float32", "float64", "complex64", "complex128", "byte", "rune", "Duration",
	}
	numeric := func(node ast.Node) bool {
		found := false
		ast.Inspect(node, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.BasicLit:
				found = found || typed.Kind == token.INT || typed.Kind == token.FLOAT || typed.Kind == token.IMAG || typed.Kind == token.CHAR
			case *ast.Ident:
				found = found || typed.Name == "iota" || slices.Contains(numericTypes, typed.Name)
			case *ast.SelectorExpr:
				found = found || slices.Contains(numericTypes, typed.Sel.Name)
			}
			return !found
		})
		return found
	}
	findings := []string{}
	for _, fileName := range fileNames {
		fileSet := token.NewFileSet()
		syntax, err := parser.ParseFile(fileSet, fileName, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range syntax.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok || (genDecl.Tok != token.CONST && genDecl.Tok != token.VAR) {
				continue
			}
			blockNumeric := false
			for _, spec := range genDecl.Specs {
				valueSpec := spec.(*ast.ValueSpec)
				specNumeric := (valueSpec.Type != nil && numeric(valueSpec.Type)) ||
					slices.ContainsFunc(valueSpec.Values, func(value ast.Expr) bool { return numeric(value) })
				if genDecl.Tok == token.CONST {
					specNumeric = specNumeric || (blockNumeric && len(valueSpec.Values) == 0)
					blockNumeric = blockNumeric || specNumeric
				}
				if !specNumeric {
					continue
				}
				for _, name := range valueSpec.Names {
					findings = append(findings, fmt.Sprintf("%s:%d: %s %s is a package-level number: make it a field with its default in the Default function (QD-702)",
						filepath.Base(fileName), fileSet.Position(name.Pos()).Line, genDecl.Tok, name.Name))
				}
			}
		}
	}
	return findings
}

// QD-702 over the compute settings files: no package-level numeric constant or variable, so every limit an area adds
// is a field with its default in its Default function.
func TestComputeSettingsHaveNoConstants(t *testing.T) {
	fileNames := []string{}
	for _, c := range testComputeSettingsComponents {
		fileNames = append(fileNames, c.file)
	}
	for _, finding := range testComputeSettingsConstantFindings(t, fileNames) {
		t.Error(finding)
	}
}

// The rule finds what it is for, and passes what QD-702 lets stay: an identifier's string, a sentinel error.
func TestComputeSettingsConstantRuleFindsAPlantedNumber(t *testing.T) {
	directory := t.TempDir()
	planted := filepath.Join(directory, "harness_settings.go")
	source := `package sidecar

import (
	"errors"
	"time"
)

const harnessAgentCount = 8

var harnessTimeout = 30 * time.Second

var harnessInterval time.Duration

const (
	harnessModeLocal harnessMode = iota
	harnessModeRemote
)

const harnessName = "harness"

var errHarnessClosed = errors.New("closed")

type harnessMode int
`
	if err := os.WriteFile(planted, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	findings := testComputeSettingsConstantFindings(t, []string{planted})
	want := []string{"harnessAgentCount", "harnessTimeout", "harnessInterval", "harnessModeLocal", "harnessModeRemote"}
	if len(findings) != len(want) {
		t.Fatalf("%d findings, want %d:\n%s", len(findings), len(want), strings.Join(findings, "\n"))
	}
	for index, name := range want {
		if !strings.Contains(findings[index], " "+name+" ") {
			t.Errorf("finding %d lacks %s: %s", index, name, findings[index])
		}
	}
}

// A component the tests construct: its name, and the record it writes to.
type testComputeComponent struct {
	name   string
	record func(event string)
}

// Records its close.
func (self *testComputeComponent) close() {
	self.record("close " + self.name)
}

// Another component type, for the type check.
type testOtherComputeComponent struct{}

// What happened, in order, across goroutines.
type testComputeRecorder struct {
	stateLock sync.Mutex
	events    []string
}

func (self *testComputeRecorder) record(event string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, event)
}

func (self *testComputeRecorder) all() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.events)
}

// A registration whose constructor records itself and builds a component that records its close, or fails with err.
func testComputeRegistration(recorder *testComputeRecorder, name string, err error) *sidecarComputeRegistration {
	return newSidecarComputeRegistration(name, func(sidecar *Sidecar) (*testComputeComponent, error) {
		recorder.record("construct " + name)
		if err != nil {
			return nil, err
		}
		return &testComputeComponent{name: name, record: recorder.record}, nil
	}, (*testComputeComponent).close)
}

// A Sidecar with nothing started, for the components alone.
func testComputeSidecar() *Sidecar {
	return newSidecarBase(&testSidecarHost{}, DefaultSidecarSettings())
}

// On a fake registration set: each constructs in order, one whose constructor fails or builds nothing leaves its
// surface refusing with the named error, and close runs once, in reverse, over only those that constructed.
func TestComputeComponentsConstructInOrderAndCloseInReverse(t *testing.T) {
	recorder := &testComputeRecorder{}
	failure := errors.New("planted failure")
	registrations := []*sidecarComputeRegistration{
		testComputeRegistration(recorder, "first", nil),
		testComputeRegistration(recorder, "failing", failure),
		newSidecarComputeRegistration("empty", func(sidecar *Sidecar) (*testComputeComponent, error) {
			recorder.record("construct empty")
			return nil, nil
		}, (*testComputeComponent).close),
		testComputeRegistration(recorder, "last", nil),
	}
	sidecar := testComputeSidecar()
	if _, err := sidecarComputeComponent[testComputeComponent](sidecar, "first"); !errors.Is(err, ErrComputeComponentUnavailable) {
		t.Errorf("a component before the sidecar started: %v", err)
	}
	components := newSidecarComputeComponents(sidecar, registrations)
	sidecar.compute.Store(components)
	if want := []string{"construct first", "construct failing", "construct empty", "construct last"}; !slices.Equal(recorder.all(), want) {
		t.Errorf("constructed %v, want %v", recorder.all(), want)
	}

	for _, name := range []string{"first", "last"} {
		component, err := sidecarComputeComponent[testComputeComponent](sidecar, name)
		if err != nil || component == nil || component.name != name {
			t.Errorf("%s: %v, %v", name, component, err)
		}
	}
	component, err := sidecarComputeComponent[testComputeComponent](sidecar, "failing")
	if component != nil || !errors.Is(err, ErrComputeComponentUnavailable) || !errors.Is(err, failure) || !strings.Contains(err.Error(), "failing") {
		t.Errorf("a failed constructor's surface: %v, %v", component, err)
	}
	component, err = sidecarComputeComponent[testComputeComponent](sidecar, "empty")
	if component != nil || !errors.Is(err, ErrComputeComponentUnavailable) || !errors.Is(err, errComputeComponentNil) {
		t.Errorf("a constructor that built nothing: %v, %v", component, err)
	}
	component, err = sidecarComputeComponent[testComputeComponent](sidecar, "unregistered")
	if component != nil || !errors.Is(err, ErrComputeComponentUnavailable) {
		t.Errorf("an unregistered component: %v, %v", component, err)
	}
	other, err := sidecarComputeComponent[testOtherComputeComponent](sidecar, "first")
	if other != nil || !errors.Is(err, ErrComputeComponentUnavailable) {
		t.Errorf("a component asked for as another type: %v, %v", other, err)
	}

	sidecar.closeComputeComponents()
	sidecar.closeComputeComponents()
	want := []string{"construct first", "construct failing", "construct empty", "construct last", "close last", "close first"}
	if !slices.Equal(recorder.all(), want) {
		t.Errorf("events %v, want %v", recorder.all(), want)
	}
	component, err = sidecarComputeComponent[testComputeComponent](sidecar, "first")
	if component != nil || !errors.Is(err, ErrComputeComponentUnavailable) || !errors.Is(err, ErrSidecarClosed) {
		t.Errorf("a component after close: %v, %v", component, err)
	}
}

// A registration twice under one name, with no name or with no constructor is a build error.
func TestRegisterComputeComponentRefusesABadRegistration(t *testing.T) {
	registrations := sidecarComputeRegistrations
	t.Cleanup(func() {
		sidecarComputeRegistrations = registrations
	})
	sidecarComputeRegistrations = []*sidecarComputeRegistration{}
	panics := func(register func()) (panicked bool) {
		defer func() {
			panicked = recover() != nil
		}()
		register()
		return false
	}
	construct := func(sidecar *Sidecar) (*testComputeComponent, error) {
		return &testComputeComponent{}, nil
	}
	if panics(func() { registerComputeComponent("planted", construct, nil) }) || len(sidecarComputeRegistrations) != 1 {
		t.Fatal("a good registration was refused")
	}
	if !panics(func() { registerComputeComponent("planted", construct, nil) }) {
		t.Error("a name registered twice")
	}
	if !panics(func() { registerComputeComponent("", construct, nil) }) {
		t.Error("an empty name registered")
	}
	if !panics(func() { registerComputeComponent[testComputeComponent]("unconstructed", nil, nil) }) {
		t.Error("a registration with no constructor")
	}
	if len(sidecarComputeRegistrations) != 1 {
		t.Errorf("%d registrations", len(sidecarComputeRegistrations))
	}
}

// A host component that records its close beside the compute components'.
type testComputeHostComponent struct {
	record func(event string)
}

func (self *testComputeHostComponent) Name() string {
	return "bridge"
}

func (self *testComputeHostComponent) Attach(env *SidecarEnv) error {
	return nil
}

func (self *testComputeHostComponent) Close() {
	self.record("close host")
}

// On a running Sidecar: the registered components are constructed by the time NewSidecar returns, after the host's
// components were added, and close in reverse as the run loop ends, after its generation and before the host's.
func TestComputeComponentsLiveAndCloseWithTheSidecar(t *testing.T) {
	recorder := &testComputeRecorder{}
	registrations := sidecarComputeRegistrations
	t.Cleanup(func() {
		sidecarComputeRegistrations = registrations
	})
	sidecarComputeRegistrations = append(slices.Clone(registrations),
		testComputeRegistration(recorder, "test-first", nil),
		testComputeRegistration(recorder, "test-second", nil),
	)

	instance, enrollment := newTestEnrolledInstance(t)
	platform := newTestSidecarPlatform()
	host := &testComputeHostComponent{record: recorder.record}
	sidecar, err := NewSidecar(context.Background(), &testSidecarHost{store: instance.Store(&enrollment.networkId)}, []SidecarComponent{host}, testSidecarSettings(platform))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"construct test-first", "construct test-second"}; !slices.Equal(recorder.all(), want) {
		t.Errorf("constructed %v, want %v", recorder.all(), want)
	}
	for _, name := range []string{"test-first", "test-second"} {
		if component, err := sidecarComputeComponent[testComputeComponent](sidecar, name); err != nil || component.name != name {
			t.Errorf("%s: %v, %v", name, component, err)
		}
	}
	platform.connected.Set(true)
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateOnline, 1))

	ctx, cancel := context.WithTimeout(context.Background(), sidecarTestTimeout)
	defer cancel()
	if err := sidecar.CloseAndWait(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{"construct test-first", "construct test-second", "close test-second", "close test-first", "close host"}
	if !slices.Equal(recorder.all(), want) {
		t.Errorf("events %v, want %v", recorder.all(), want)
	}
	if _, err := sidecarComputeComponent[testComputeComponent](sidecar, "test-first"); !errors.Is(err, ErrSidecarClosed) {
		t.Errorf("a component after the sidecar closed: %v", err)
	}
}
