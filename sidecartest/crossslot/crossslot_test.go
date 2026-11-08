package crossslot

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// The functions a planted file declares whose names start with prefix.
func plantedFunctions(t *testing.T, prefix string) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join("testdata", "planted", "planted.go"), nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && strings.HasPrefix(function.Name.Name, prefix) {
			names = append(names, function.Name.Name)
		}
	}
	return names
}

func plantedFindings(t *testing.T) []*Finding {
	t.Helper()
	findings, err := Check(".", "./testdata/planted")
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

// Every planted violation is caught, once, and each good call passes: a lint that refused everything
// would fail the second half, and one that passed everything the first.
func TestPlantedCallsReadAsTheirNamesSay(t *testing.T) {
	findingCounts := map[string]int{}
	for _, finding := range plantedFindings(t) {
		findingCounts[finding.Function] += 1
	}
	for _, name := range plantedFunctions(t, "bad") {
		if findingCounts[name] != 1 {
			t.Errorf("%s: %d findings", name, findingCounts[name])
		}
	}
	for _, name := range plantedFunctions(t, "good") {
		if findingCounts[name] != 0 {
			t.Errorf("%s: %d findings", name, findingCounts[name])
		}
	}
}

func TestAScriptNamingItsOwnKeysIsFound(t *testing.T) {
	messages := []string{}
	for _, finding := range plantedFindings(t) {
		if finding.Function == "" {
			messages = append(messages, finding.Message)
		}
	}
	slices.Sort(messages)
	want := []string{
		"DEL names key KEYS[1] .. ':old', which is not from KEYS",
		"GET names key 'prefix:' .. ARGV[1], which is not from KEYS",
		"SET names key 'literal', which is not from KEYS",
		"a script's Source must be a constant",
	}
	if !slices.Equal(messages, want) {
		t.Errorf("messages %q", messages)
	}
}

func TestAFindingSaysWhereAndWhich(t *testing.T) {
	for _, finding := range plantedFindings(t) {
		if finding.Function != "badTwoClients" {
			continue
		}
		text := finding.String()
		if !strings.Contains(text, "planted.go:") || !strings.Contains(text, "{scp_<self.clientId>}ack, {scp_<self.otherId>}ack") {
			t.Errorf("%s", text)
		}
		return
	}
	t.Error("no finding")
}

// A loop's keys are read again as another pass, so a tag from the loop is two tags, not one shared.
func TestALoopsPassReadsAsAnotherValue(t *testing.T) {
	for _, finding := range plantedFindings(t) {
		if finding.Function != "badATagFromTheLoop" {
			continue
		}
		if !strings.Contains(finding.Message, "{scp_<clientId>}tok, {scp_<clientId on another pass>}tok") {
			t.Errorf("%s", finding)
		}
		return
	}
	t.Error("no finding")
}

// A package that does not build is an error, never a pass.
func TestAPackageThatDoesNotLoadIsNoPass(t *testing.T) {
	if findings, err := Check(".", "./testdata/no-such-package"); err == nil {
		t.Errorf("findings %v", findings)
	}
}

func TestScriptKeyProblems(t *testing.T) {
	for _, c := range []struct {
		source   string
		problems int
	}{
		{source: `return redis.call('GET', KEYS[1])`, problems: 0},
		{source: `redis.call("SET", KEYS[1], ARGV[1])`, problems: 0},
		{source: "local a = KEYS[1]\nlocal b = KEYS[2]\nredis.call('GET', a)\nredis.call('DEL', b)", problems: 0},
		{source: `redis.call('TIME')`, problems: 0},
		{source: `redis.call('XGROUP', 'CREATE', KEYS[1], 'g', '$')`, problems: 0},
		{source: `redis.call('GET', 'literal')`, problems: 1},
		{source: `redis.call('GET', "literal")`, problems: 1},
		{source: `redis.pcall('GET', KEYS[1] .. 'x')`, problems: 1},
		{source: "local a = KEYS[1] .. 'x'\nredis.call('GET', a)", problems: 1},
		{source: `redis.call('GET', ARGV[1])`, problems: 1},
		{source: `redis.call('GET', 'a' .. KEYS[1])`, problems: 1},
		{source: "local a = 'x'\nredis.call('GET', a)", problems: 1},
		// every key position, not the first alone
		{source: "redis.call('DEL', KEYS[1], 'literal')", problems: 1},
		{source: "redis.call('MGET', KEYS[1], ARGV[1])", problems: 1},
		{source: "redis.call('RENAME', KEYS[1], ARGV[1])", problems: 1},
		{source: "redis.call('DEL', KEYS[1], KEYS[2])", problems: 0},
		{source: "redis.call('MSET', KEYS[1], ARGV[1], KEYS[2], ARGV[2])", problems: 0},
		{source: "redis.call('MSET', KEYS[1], ARGV[1], 'literal', ARGV[2])", problems: 1},
		{source: "redis.call('SET', KEYS[1], redis.call('GET', 'literal'))", problems: 1},
		{source: "redis.call('DEL', unpack(KEYS))", problems: 0},
		// commands with a subcommand or a keyword before their keys
		{source: "redis.call('XGROUP', 'CREATE', 'literal', 'g', '$')", problems: 1},
		{source: "redis.call('XINFO', 'STREAM', 'literal')", problems: 1},
		{source: "redis.call('OBJECT', 'ENCODING', KEYS[1])", problems: 0},
		{source: "redis.call('XREADGROUP', 'GROUP', 'g', 'c', 'COUNT', 1, 'STREAMS', KEYS[1], '>')", problems: 0},
		{source: "redis.call('XREAD', 'STREAMS', 'literal', '0')", problems: 1},
		{source: "redis.call('XREAD', 'COUNT', 1)", problems: 1},
		// locals and loops
		{source: "local k = KEYS[1]\nk = ARGV[1]\nredis.call('GET', k)", problems: 1},
		{source: "local k = KEYS[1]\nlocal x, k = 1, ARGV[1]\nredis.call('GET', k)", problems: 1},
		{source: "for _, key in ipairs(KEYS) do redis.call('DEL', key) end", problems: 0},
		{source: "KEYS[1] = ARGV[1]\nredis.call('GET', KEYS[1])", problems: 1},
		// what it cannot read
		{source: "local command = 'GET'\nredis.call(command, 'literal')", problems: 1},
		{source: "local call = redis.call\ncall('GET', 'literal')", problems: 1},
		{source: "redis.call('EVAL', 'return 1', 0)", problems: 1},
		// a comment is no call
		{source: "-- redis.call('GET', 'literal')\nredis.call('GET', KEYS[1])", problems: 0},
		{source: "--[[ redis.call('GET', 'literal') ]]\nredis.call('GET', KEYS[1])", problems: 0},
	} {
		if got := len(scriptKeyProblems(c.source)); got != c.problems {
			t.Errorf("%s: %d problems: %v", c.source, got, scriptKeyProblems(c.source))
		}
	}
}

// What the rule below walks must be this module's code, or its passing says nothing.
func TestTheModuleWalkReachesTheCodeItGuards(t *testing.T) {
	packages, err := modulePackages(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	root := reflect.TypeFor[sidecar.RedisScript]().PkgPath()
	for _, want := range []string{root, root + "/device", root + "/protocol"} {
		if !slices.Contains(packages, want) {
			t.Errorf("%s is not walked: %v", want, packages)
		}
	}
	for _, importPath := range packages {
		if strings.HasPrefix(importPath, root+"/sidecartest") || strings.HasPrefix(importPath, root+"/check") {
			t.Errorf("%s breaks the rule on purpose, and is walked", importPath)
		}
	}
}

// The rule on this module: every engine and client package as it stands. make check runs this, so a
// call that breaks it stops the build (§22.4).
func TestThisModuleKeepsTheRule(t *testing.T) {
	findings, err := CheckModule(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		t.Error(finding)
	}
}
