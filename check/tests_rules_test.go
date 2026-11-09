//go:build sidecar_check

// The test rules connect/CODESTYLE.md:200-217 states and nothing else checks (TEST-M0-05; R-TEST-1,
// D-TEST-1, I-13), over every module's tests, nested ones included:
//
//   - real time is no proof: no time.Sleep in a test, and a timer of time's (After, NewTimer,
//     NewTicker, Tick, AfterFunc) only as a guard whose firing fails the test, the bound that stops a
//     broken test from hanging. A short negative timeout, a timer whose firing is the pass, is the
//     ordering CODESTYLE forbids as a proof; a timeout on the fake clock is no timer of time's and is
//     allowed.
//   - t.Run only where the subtest boundary is the point: a test that runs a subtest expected to fail
//     and reads its result. A t.Run whose result is dropped is a positive subtest, which CODESTYLE
//     makes a top-level test or a table loop.
//   - test data is synthetic: no globally routable address outside 192.0.2.0/24, 198.51.100.0/24,
//     203.0.113.0/24 and 2001:db8::/32, and no hostname outside .example, .invalid, .test and
//     localhost, RFC 2606's example.com, example.net and example.org among them, in a test's string
//     literals, with a dated list of exceptions for names the design fixes as format constants.
//
// Each exception is listed in the settings with the day it was granted and why, and one that matches
// nothing any more fails, so the lists only shrink.

package check

import (
	"go/ast"
	"go/token"
	"net/netip"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// One listed exception to a test rule, keyed by file and what it names.
type testRuleException struct {
	// the day it was granted, yyyy-mm-dd
	since string
	why   string
}

// A file's name in its package, the root's files bare, for an exception's key: it reads the same on a
// release branch.
func testRuleFileKey(file *sourceFile) string {
	if file.packageName == "." {
		return filepath.Base(file.path)
	}
	return path.Join(file.packageName, filepath.Base(file.path))
}

// The names time is imported under in a file, aliases included.
func timeImportNames(file *ast.File) map[string]bool {
	names := map[string]bool{}
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil || importPath != "time" {
			continue
		}
		name := "time"
		if spec.Name != nil {
			name = spec.Name.Name
		}
		names[name] = true
	}
	return names
}

// time's functions that start a real timer.
var realTimerFunctionNames = map[string]bool{
	"After": true, "NewTimer": true, "NewTicker": true, "Tick": true, "AfterFunc": true,
}

// Whether a statement list fails the test it runs in: a call of testing's Fatal, Fatalf, FailNow,
// Error, Errorf or Fail, of panic, or a return of an error made on the spot. Statements nested in an if
// or a block count.
func failsTheTest(statements []ast.Stmt) bool {
	fails := false
	for _, statement := range statements {
		ast.Inspect(statement, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.FuncLit:
				return false
			case *ast.CallExpr:
				switch function := value.Fun.(type) {
				case *ast.SelectorExpr:
					switch function.Sel.Name {
					case "Fatal", "Fatalf", "FailNow", "Error", "Errorf", "Fail":
						fails = true
					}
				case *ast.Ident:
					if function.Name == "panic" {
						fails = true
					}
				}
			case *ast.ReturnStmt:
				for _, result := range value.Results {
					if call, ok := result.(*ast.CallExpr); ok {
						if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
							if packageIdent, ok := selector.X.(*ast.Ident); ok &&
								((packageIdent.Name == "errors" && selector.Sel.Name == "New") ||
									(packageIdent.Name == "fmt" && selector.Sel.Name == "Errorf")) {
								fails = true
							}
						}
					}
				}
			}
			return !fails
		})
	}
	return fails
}

// A select clause that receives from what matches, and whether its body fails the test.
type receiveClause struct {
	clause *ast.CommClause
	fails  bool
}

// Every select clause in body receiving from an expression that matches.
func receiveClauses(body ast.Node, matches func(ast.Expr) bool) []receiveClause {
	clauses := []receiveClause{}
	ast.Inspect(body, func(node ast.Node) bool {
		clause, ok := node.(*ast.CommClause)
		if !ok || clause.Comm == nil {
			return true
		}
		var received ast.Expr
		switch comm := clause.Comm.(type) {
		case *ast.ExprStmt:
			received = comm.X
		case *ast.AssignStmt:
			if len(comm.Rhs) == 1 {
				received = comm.Rhs[0]
			}
		}
		unary, ok := received.(*ast.UnaryExpr)
		if !ok || unary.Op != token.ARROW || !matches(unary.X) {
			return true
		}
		clauses = append(clauses, receiveClause{clause: clause, fails: failsTheTest(clause.Body)})
		return true
	})
	return clauses
}

// One finding of a test rule, with the key its exception would be listed under.
type testRuleFinding struct {
	key     string
	finding string
}

// time.Sleep anywhere in a test, and a real timer anywhere but a guard that fails the test.
func (self *repository) realTimeWaits(t testing.TB) []testRuleFinding {
	t.Helper()
	findings := []testRuleFinding{}
	for _, file := range self.sourceFiles(t) {
		if !file.isTest {
			continue
		}
		timeNames := timeImportNames(file.syntax)
		if len(timeNames) == 0 {
			continue
		}
		isTimeFunction := func(expression ast.Expr, names map[string]bool) (string, bool) {
			selector, ok := expression.(*ast.SelectorExpr)
			if !ok || !names[selector.Sel.Name] {
				return "", false
			}
			packageIdent, ok := selector.X.(*ast.Ident)
			if !ok || !timeNames[packageIdent.Name] {
				return "", false
			}
			return selector.Sel.Name, true
		}
		report := func(node ast.Node, name string, why string) {
			findings = append(findings, testRuleFinding{
				key: testRuleFileKey(file) + " time." + name,
				finding: findingf("%s:%d: time.%s %s", self.displayPath(file.path),
					file.fileSet.Position(node.Pos()).Line, name, why),
			})
		}
		for _, declaration := range file.syntax.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				ast.Inspect(declaration, func(node ast.Node) bool {
					if selector, ok := node.(*ast.SelectorExpr); ok {
						if name, ok := isTimeFunction(selector, map[string]bool{"Sleep": true}); ok {
							report(selector, name, "waits in real time; move a fake clock or wait on a barrier")
						}
					}
					return true
				})
				continue
			}
			// the guard timers in this function: those received only by clauses that fail the test
			guards := map[ast.Node]bool{}
			for _, clause := range receiveClauses(function.Body, func(received ast.Expr) bool {
				call, ok := received.(*ast.CallExpr)
				if !ok {
					return false
				}
				_, ok = isTimeFunction(call.Fun, map[string]bool{"After": true, "Tick": true})
				return ok
			}) {
				if clause.fails {
					guards[clause.clause.Comm] = true
				}
			}
			// a timer held in a variable is a guard when every clause receiving it fails the test
			ast.Inspect(function.Body, func(node ast.Node) bool {
				assign, ok := node.(*ast.AssignStmt)
				if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
					return true
				}
				call, ok := assign.Rhs[0].(*ast.CallExpr)
				if !ok {
					return true
				}
				if _, ok := isTimeFunction(call.Fun, map[string]bool{"After": true, "Tick": true}); !ok {
					return true
				}
				if ident, ok := assign.Lhs[0].(*ast.Ident); ok {
					clauses := receiveClauses(function.Body, func(received ast.Expr) bool {
						other, ok := received.(*ast.Ident)
						return ok && other.Name == ident.Name
					})
					guard := 0 < len(clauses)
					for _, clause := range clauses {
						guard = guard && clause.fails
					}
					if guard {
						guards[call] = true
					}
				}
				return true
			})
			ast.Inspect(function.Body, func(node ast.Node) bool {
				switch value := node.(type) {
				case *ast.CommClause:
					if guards[value.Comm] {
						// the guard's own timer, inside its receive
						return false
					}
				case *ast.CallExpr:
					if guards[value] {
						return false
					}
				case *ast.SelectorExpr:
					if name, ok := isTimeFunction(value, map[string]bool{"Sleep": true}); ok {
						report(value, name, "waits in real time; move a fake clock or wait on a barrier")
					} else if name, ok := isTimeFunction(value, realTimerFunctionNames); ok {
						report(value, name, "starts a real timer that is no failing guard: a timeout whose firing passes is a negative proof; use a barrier or the fake clock, or fail the test when it fires")
					}
				}
				return true
			})
		}
	}
	return findings
}

// A t.Run whose result nothing reads: a positive subtest.
func (self *repository) positiveSubtests(t testing.TB) []testRuleFinding {
	t.Helper()
	findings := []testRuleFinding{}
	for _, file := range self.sourceFiles(t) {
		if !file.isTest {
			continue
		}
		testingNames := map[string]bool{}
		for _, spec := range file.syntax.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil || importPath != "testing" {
				continue
			}
			name := "testing"
			if spec.Name != nil {
				name = spec.Name.Name
			}
			testingNames[name] = true
		}
		if len(testingNames) == 0 {
			continue
		}
		ast.Inspect(file.syntax, func(node ast.Node) bool {
			function, ok := node.(*ast.FuncDecl)
			if !ok || function.Body == nil || function.Type.Params == nil {
				return true
			}
			// the function's *testing.T parameters
			tNames := map[string]bool{}
			for _, field := range function.Type.Params.List {
				star, ok := field.Type.(*ast.StarExpr)
				if !ok {
					continue
				}
				selector, ok := star.X.(*ast.SelectorExpr)
				if !ok || selector.Sel.Name != "T" {
					continue
				}
				if packageIdent, ok := selector.X.(*ast.Ident); ok && testingNames[packageIdent.Name] {
					for _, name := range field.Names {
						tNames[name.Name] = true
					}
				}
			}
			ast.Inspect(function.Body, func(inner ast.Node) bool {
				statement, ok := inner.(*ast.ExprStmt)
				if !ok {
					return true
				}
				call, ok := statement.X.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || selector.Sel.Name != "Run" {
					return true
				}
				if receiver, ok := selector.X.(*ast.Ident); ok && tNames[receiver.Name] {
					findings = append(findings, testRuleFinding{
						key: testRuleFileKey(file) + " " + function.Name.Name,
						finding: findingf("%s:%d: %s runs a subtest and drops its result: a positive case is a top-level test or a table loop, and t.Run is for a subtest expected to fail, whose result the test reads",
							self.displayPath(file.path), file.fileSet.Position(call.Pos()).Line, function.Name.Name),
					})
				}
				return true
			})
			return false
		})
	}
	return findings
}

// An IPv4 or IPv6 literal inside a string, as test data writes one.
var (
	ipv4CandidatePattern = regexp.MustCompile(`(?:^|[^0-9.])((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?:$|[^0-9.])`)
	ipv6CandidatePattern = regexp.MustCompile(`[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}`)
)

// The documentation ranges CODESTYLE allows, RFC 9637's 3fff::/20 beside them, and the special-purpose
// ranges no host routes to, which a test may use to stand for their kind: loopback, private, shared,
// link-local, benchmarking, multicast and reserved space.
var testAllowedPrefixes = func() []netip.Prefix {
	prefixes := []netip.Prefix{}
	for _, text := range []string{
		"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
		"3fff::/20", "::/8", "64:ff9b::/96", "100::/64", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		prefixes = append(prefixes, netip.MustParsePrefix(text))
	}
	return prefixes
}()

// IPv6's global unicast, 2000::/3, built rather than written, so this file's own literals stay synthetic.
var globalUnicastPrefix = netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20}), 3)

// Whether an address stands for a real host: global unicast outside every allowed range.
func routableTestAddress(address netip.Addr) bool {
	address = address.Unmap()
	for _, prefix := range testAllowedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	if address.Is6() {
		// global unicast; the rest is reserved
		return globalUnicastPrefix.Contains(address)
	}
	return true
}

// A hostname as test data writes one: a whole literal that is a name, a URL's host, an address's
// domain, or a host with a port.
var (
	hostnamePattern     = regexp.MustCompile(`^(?i)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z]\.?$`)
	urlHostPattern      = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://(?:[^/@\s]*@)?([^/:\s?#"]+)`)
	emailDomainPattern  = regexp.MustCompile(`(?i)^[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})$`)
	hostPortPattern     = regexp.MustCompile(`(?i)^([a-z0-9.-]+\.[a-z]{2,}):[0-9]{1,5}$`)
	goFileNamePattern   = regexp.MustCompile(`(?i)\.(go|sh|md|yml|yaml|json|txt|proto|tla|cfg|mod|sum|pem|key|crt|der|bin|gz|zip|tar|eml|html|js|wasm|py|toml|lock|log|out|csv|tsv|xml|svg|png|jpg|ur|trace)$`)
	allowedHostSuffixes = []string{".example", ".invalid", ".test", ".localhost", ".example.com", ".example.net", ".example.org"}
	allowedHostNames    = []string{"localhost", "example.com", "example.net", "example.org", "example", "invalid", "test"}
)

// The hostnames a string literal's value holds, by the forms above.
func literalHostnames(value string) []string {
	hosts := []string{}
	if hostnamePattern.MatchString(value) && !goFileNamePattern.MatchString(value) && strings.Contains(value, ".") {
		hosts = append(hosts, value)
	}
	for _, match := range urlHostPattern.FindAllStringSubmatch(value, -1) {
		hosts = append(hosts, match[1])
	}
	if match := emailDomainPattern.FindStringSubmatch(value); match != nil {
		hosts = append(hosts, match[1])
	}
	if match := hostPortPattern.FindStringSubmatch(value); match != nil {
		hosts = append(hosts, match[1])
	}
	return hosts
}

// The top-level domains a real host is found under, generic and the commonest country codes. A dotted
// name under none of them is a barrier, a method or a file, not a host: evs.head_cas.before,
// webauthn.create, snapshot.ndjson.
var realTopLevelDomains = map[string]bool{
	"com": true, "net": true, "org": true, "io": true, "dev": true, "app": true, "co": true, "ai": true,
	"gov": true, "edu": true, "mil": true, "int": true, "info": true, "biz": true, "xyz": true,
	"me": true, "tv": true, "gg": true, "ly": true, "to": true, "cc": true, "us": true, "uk": true,
	"de": true, "fr": true, "jp": true, "cn": true, "ru": true, "eu": true, "ca": true, "au": true,
	"nl": true, "ch": true, "se": true, "no": true, "fi": true, "dk": true, "it": true, "es": true,
	"pl": true, "br": true, "kr": true, "be": true, "at": true, "nz": true, "ie": true,
}

// Whether a hostname is synthetic: under a reserved name, an address, or no real top-level domain.
func syntheticHostname(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return true
	}
	if slices.Contains(allowedHostNames, host) {
		return true
	}
	for _, suffix := range allowedHostSuffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return !realTopLevelDomains[host[strings.LastIndex(host, ".")+1:]]
}

// The file that lists the exceptions, which must name each value it lets through.
const testDataExceptionsFile = "check/settings_test.go"

// A routable address or a real hostname in a test's string literal.
func (self *repository) unsyntheticTestData(t testing.TB) []testRuleFinding {
	t.Helper()
	findings := []testRuleFinding{}
	for _, file := range self.sourceFiles(t) {
		if !file.isTest || testRuleFileKey(file) == testDataExceptionsFile {
			continue
		}
		ast.Inspect(file.syntax, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				return true
			}
			line := file.fileSet.Position(literal.Pos()).Line
			add := func(what string, why string) {
				findings = append(findings, testRuleFinding{
					key:     testRuleFileKey(file) + " " + what,
					finding: findingf("%s:%d: %s %s", self.displayPath(file.path), line, what, why),
				})
			}
			for _, match := range ipv4CandidatePattern.FindAllStringSubmatch(value, -1) {
				if address, err := netip.ParseAddr(match[1]); err == nil && routableTestAddress(address) {
					add(match[1], "is a routable address: use 192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24")
				}
			}
			for _, candidate := range ipv6CandidatePattern.FindAllString(value, -1) {
				if strings.Count(candidate, ":") < 2 {
					continue
				}
				if address, err := netip.ParseAddr(candidate); err == nil && routableTestAddress(address) {
					add(candidate, "is a routable address: use 2001:db8::/32")
				}
			}
			for _, host := range literalHostnames(value) {
				if !syntheticHostname(host) {
					add(strings.ToLower(strings.TrimSuffix(host, ".")), "is a real hostname: use .example, .invalid or .test")
				}
			}
			return true
		})
	}
	return findings
}

// The findings no exception lists.
func unlistedTestRuleFindings(findings []testRuleFinding, exceptions map[string]testRuleException) []string {
	unlisted := []string{}
	for _, finding := range findings {
		if _, listed := exceptions[finding.key]; !listed {
			unlisted = append(unlisted, finding.finding)
		}
	}
	return unlisted
}

func (self *repository) realTimeWaitFindings(t testing.TB) []string {
	return unlistedTestRuleFindings(self.realTimeWaits(t), self.settings.realTimeWaitExceptions)
}

func (self *repository) positiveSubtestFindings(t testing.TB) []string {
	return unlistedTestRuleFindings(self.positiveSubtests(t), nil)
}

func (self *repository) testDataFindings(t testing.TB) []string {
	return unlistedTestRuleFindings(self.unsyntheticTestData(t), self.settings.testDataExceptions)
}

// Each listed exception still matches a finding in this checkout and says when and why, so the lists
// only shrink.
func TestTestRuleExceptionsAllStillMatch(t *testing.T) {
	repository := openThisCheckout(t)
	for _, list := range []struct {
		name       string
		findings   []testRuleFinding
		exceptions map[string]testRuleException
	}{
		{name: "real-time waits", findings: repository.realTimeWaits(t), exceptions: repository.settings.realTimeWaitExceptions},
		{name: "test data", findings: repository.unsyntheticTestData(t), exceptions: repository.settings.testDataExceptions},
	} {
		matched := map[string]bool{}
		for _, finding := range list.findings {
			matched[finding.key] = true
		}
		keys := []string{}
		for key := range list.exceptions {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			exception := list.exceptions[key]
			if !matched[key] {
				t.Errorf("the %s rule's exception %q (since %s) matches nothing: remove it", list.name, key, exception.since)
			}
			if exception.since == "" || exception.why == "" {
				t.Errorf("the %s rule's exception %q has no date or no reason", list.name, key)
			}
		}
	}
}
