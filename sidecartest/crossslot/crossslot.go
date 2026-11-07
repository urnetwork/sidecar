// §22.4's static lint: a call naming two or more Redis keys names them under one hash tag every key
// carries, by sidecar.RedisKeysShareTag, read from the source. FakeRedis applies the same rule at run
// time, and T3 runs every script and multi-key call against 3 masters. This one sees a call no test
// reached, and it runs in make check, as this package's test.
//
// A call is a method named as a multi-key sidecar.Redis method with that method's signature, so a
// narrower interface an engine declares for itself is held too (host_redis.go lets it). Keys are read
// as far as source shows them: constants, +, fmt.Sprintf, a local's assignments and appends, and a
// builder whose body is one return, followed into its arguments. What cannot be read stands as a value
// of its own, compared by how it reads, so {scp_<clientId>}ack beside {scp_<clientId>}tok share a tag
// and {scp_<clientId>}ack beside {scp_<otherId>}tok do not. A list the lint cannot follow at all is a
// finding: a check that cannot see a call has not passed it.
//
// A RedisScript is held to its own rule too: a package-level value, whose Source reads every key from
// KEYS and builds none, or the slot check proves nothing (host_redis.go).

package crossslot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar"
)

// Marks a value the lint cannot read, around how it reads. No key holds this byte, and a tag holding a
// value keeps it, so two tags are equal only if they read the same.
const unknownMark = "\x00"

// How deep one key's builders are followed. 8: a builder calling a builder is the most a family has,
// and this only stops a recursive one.
const builderDepth = 8

// What a call broke, and where.
type Finding struct {
	// file:line:column.
	Position string
	// The function it is in, empty at package level.
	Function string
	Message  string
}

func (self *Finding) String() string {
	return fmt.Sprintf("%s: %s", self.Position, self.Message)
}

// The fields of go list -json this reads.
type listedPackage struct {
	ImportPath string
	Name       string
	Dir        string
	GoFiles    []string
	Export     string
	DepOnly    bool
	Error      *struct{ Err string }
}

// What one package's files say.
type sourcePackage struct {
	files []*ast.File
	info  *types.Info
	types *types.Package
}

// A function a key may be built by.
type sourceFunction struct {
	declaration *ast.FuncDecl
	source      *sourcePackage
}

type lint struct {
	fileset *token.FileSet
	// By types.Func's full name, which is the same however a package was imported.
	functions map[string]*sourceFunction
	findings  []*Finding
}

// Where a key is being read: a function's body, with what each of its parameters holds when a call was
// followed into it.
type readScope struct {
	source   *sourcePackage
	function *ast.FuncDecl
	bindings map[types.Object]string
	depth    int
}

// Every finding in the packages of a module that go list's patterns name, run from directory, in file
// order. Each package must build: one that does not is an error, not a pass.
func Check(directory string, patterns ...string) ([]*Finding, error) {
	listed, exports, err := listPackages(directory, patterns)
	if err != nil {
		return nil, err
	}
	self := &lint{fileset: token.NewFileSet(), functions: map[string]*sourceFunction{}}
	compilerImporter := importer.ForCompiler(self.fileset, "gc", func(path string) (io.ReadCloser, error) {
		export, ok := exports[path]
		if !ok {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		return os.Open(export)
	})
	sources := make([]*sourcePackage, 0, len(listed))
	for _, listedPackage := range listed {
		source, err := self.load(listedPackage, compilerImporter)
		if err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}
	for _, source := range sources {
		for _, file := range source.files {
			self.checkFile(source, file)
		}
	}
	slices.SortFunc(self.findings, func(a *Finding, b *Finding) int {
		return strings.Compare(a.Position, b.Position)
	})
	return self.findings, nil
}

// Every finding in a module's own engines and client code. A module with no multi-key call yet has none
// to find, which says nothing about one written tomorrow.
func CheckModule(directory string) ([]*Finding, error) {
	packages, err := modulePackages(directory)
	if err != nil {
		return nil, err
	}
	return Check(directory, packages...)
}

// All of a module's packages but sidecartest and check, whose suites and fixtures break the rule on
// purpose.
func modulePackages(directory string) ([]string, error) {
	command := exec.Command("go", "list", "-f", "{{.ImportPath}}", "./...")
	command.Dir = directory
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("go list: %w", err)
	}
	modulePath := reflect.TypeFor[sidecar.RedisScript]().PkgPath()
	packages := []string{}
	for _, importPath := range strings.Fields(string(output)) {
		relative := strings.TrimPrefix(strings.TrimPrefix(importPath, modulePath), "/")
		first, _, _ := strings.Cut(relative, "/")
		if first != "sidecartest" && first != "check" {
			packages = append(packages, importPath)
		}
	}
	return packages, nil
}

// The packages patterns name, and where every package they need keeps its export data.
func listPackages(directory string, patterns []string) ([]*listedPackage, map[string]string, error) {
	args := append([]string{"list", "-e", "-export", "-deps", "-json=ImportPath,Name,Dir,GoFiles,Export,DepOnly,Error"}, patterns...)
	command := exec.Command("go", args...)
	command.Dir = directory
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("go list: %w: %s", err, stderr.String())
	}
	listed := []*listedPackage{}
	exports := map[string]string{}
	decoder := json.NewDecoder(bytes.NewReader(output))
	for decoder.More() {
		item := &listedPackage{}
		if err := decoder.Decode(item); err != nil {
			return nil, nil, err
		}
		if item.Error != nil {
			return nil, nil, fmt.Errorf("%s: %s", item.ImportPath, item.Error.Err)
		}
		if item.Export != "" {
			exports[item.ImportPath] = item.Export
		}
		if !item.DepOnly {
			listed = append(listed, item)
		}
	}
	return listed, exports, nil
}

func (self *lint) load(listed *listedPackage, compilerImporter types.Importer) (*sourcePackage, error) {
	source := &sourcePackage{
		info: &types.Info{
			Types:      map[ast.Expr]types.TypeAndValue{},
			Uses:       map[*ast.Ident]types.Object{},
			Defs:       map[*ast.Ident]types.Object{},
			Selections: map[*ast.SelectorExpr]*types.Selection{},
		},
	}
	for _, name := range listed.GoFiles {
		file, err := parser.ParseFile(self.fileset, filepath.Join(listed.Dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		source.files = append(source.files, file)
	}
	checked, err := (&types.Config{Importer: compilerImporter}).Check(listed.ImportPath, self.fileset, source.files, source.info)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", listed.ImportPath, err)
	}
	source.types = checked
	for _, file := range source.files {
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if object, ok := source.info.Defs[function.Name].(*types.Func); ok {
				self.functions[object.FullName()] = &sourceFunction{declaration: function, source: source}
			}
		}
	}
	return source, nil
}

func (self *lint) report(position token.Pos, function *ast.FuncDecl, message string) {
	name := ""
	if function != nil {
		name = function.Name.Name
	}
	self.findings = append(self.findings, &Finding{
		Position: self.fileset.Position(position).String(),
		Function: name,
		Message:  message,
	})
}

func (self *lint) checkFile(source *sourcePackage, file *ast.File) {
	for _, declaration := range file.Decls {
		function, _ := declaration.(*ast.FuncDecl)
		ast.Inspect(declaration, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.CallExpr:
				self.checkCall(source, function, typed)
			case *ast.CompositeLit:
				self.checkScript(source, function, typed)
			}
			return true
		})
	}
}

// One of sidecar.Redis's multi-key methods.
type multiKeyMethod struct {
	// Which argument holds the keys.
	keysArgument int
	// How many arguments it takes.
	argumentCount int
}

// What §22.4's rule covers, with each arity read from the interface, so one that changes is followed.
var multiKeyMethods = func() map[string]*multiKeyMethod {
	redis := reflect.TypeFor[sidecar.Redis]()
	methods := map[string]*multiKeyMethod{}
	for name, keysArgument := range map[string]int{"GetMany": 1, "Delete": 1, "RunScript": 2} {
		method, ok := redis.MethodByName(name)
		if !ok {
			panic("sidecar.Redis has no " + name)
		}
		methods[name] = &multiKeyMethod{keysArgument: keysArgument, argumentCount: method.Type.NumIn()}
	}
	return methods
}()

// Whether call is one of them. A name alone is not enough, so a blob cluster's Delete of one key goes
// by: the keys argument must be a []string and the call must have the method's arity.
func (self *lint) multiKeyCall(source *sourcePackage, call *ast.CallExpr) *multiKeyMethod {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	method, ok := multiKeyMethods[selector.Sel.Name]
	if !ok || len(call.Args) != method.argumentCount {
		return nil
	}
	selection, ok := source.info.Selections[selector]
	if !ok || selection.Kind() != types.MethodVal {
		return nil
	}
	signature, ok := selection.Obj().Type().(*types.Signature)
	if !ok {
		return nil
	}
	keysType := signature.Params().At(method.keysArgument).Type()
	slice, ok := keysType.(*types.Slice)
	if !ok {
		return nil
	}
	if basic, ok := slice.Elem().(*types.Basic); !ok || basic.Kind() != types.String {
		return nil
	}
	return method
}

func (self *lint) checkCall(source *sourcePackage, function *ast.FuncDecl, call *ast.CallExpr) {
	method := self.multiKeyCall(source, call)
	if method == nil {
		return
	}
	scope := &readScope{source: source, function: function}
	keys, ok := self.readKeys(call.Args[method.keysArgument], scope)
	if !ok {
		self.report(call.Pos(), function, "cannot read this call's keys: name them where it can see them")
		return
	}
	if !sidecar.RedisKeysShareTag(keys) || slices.ContainsFunc(keys, valueBeforeTag) {
		self.report(call.Pos(), function, fmt.Sprintf("keys %s share no hash tag", printKeys(keys)))
	}
}

// Whether something unread comes before a key's first brace, which could then hold a brace of its own.
func valueBeforeTag(key string) bool {
	mark := strings.Index(key, unknownMark)
	return 0 <= mark && mark < strings.Index(key, "{")
}

func printKeys(keys []string) string {
	printed := make([]string, 0, len(keys))
	for _, key := range keys {
		parts := strings.Split(key, unknownMark)
		for index := 1; index < len(parts); index += 2 {
			parts[index] = "<" + parts[index] + ">"
		}
		printed = append(printed, strings.Join(parts, ""))
	}
	return strings.Join(printed, ", ")
}

// The object an identifier names, or nil.
func (self *readScope) object(identifier *ast.Ident) types.Object {
	if object := self.source.info.Uses[identifier]; object != nil {
		return object
	}
	return self.source.info.Defs[identifier]
}

// Reads a list of keys. false means it cannot be followed, and nothing can be said of it.
func (self *lint) readKeys(expression ast.Expr, scope *readScope) ([]string, bool) {
	switch typed := ast.Unparen(expression).(type) {
	case *ast.CompositeLit:
		keys := make([]string, 0, len(typed.Elts))
		for _, element := range typed.Elts {
			if pair, ok := element.(*ast.KeyValueExpr); ok {
				element = pair.Value
			}
			keys = append(keys, self.readKey(element, scope))
		}
		return keys, true
	case *ast.Ident:
		if typed.Name == "nil" {
			return nil, true
		}
		return self.readKeysVariable(typed, scope)
	case *ast.CallExpr:
		if isBuiltin(typed, "append", scope) {
			return self.readAppend(typed, scope)
		}
		if body, inner := self.builder(typed, scope); body != nil {
			return self.readKeys(body, inner)
		}
	}
	return nil, false
}

func isBuiltin(call *ast.CallExpr, name string, scope *readScope) bool {
	identifier, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok || identifier.Name != name {
		return false
	}
	_, builtin := scope.object(identifier).(*types.Builtin)
	return builtin
}

// append(list, key, key) or append(list, keys...).
func (self *lint) readAppend(call *ast.CallExpr, scope *readScope) ([]string, bool) {
	keys, ok := self.readKeys(call.Args[0], scope)
	if !ok {
		return nil, false
	}
	if call.Ellipsis.IsValid() {
		rest, ok := self.readKeys(call.Args[1], scope)
		if !ok {
			return nil, false
		}
		return append(keys, rest...), true
	}
	for _, argument := range call.Args[1:] {
		keys = append(keys, self.readKey(argument, scope))
	}
	return keys, true
}

// A local list, from every assignment to it in its function. An append in a loop may run any number
// of times, so its key counts twice: the rule holds for two keys whatever the loop does.
func (self *lint) readKeysVariable(identifier *ast.Ident, scope *readScope) ([]string, bool) {
	object := scope.object(identifier)
	if object == nil || scope.function == nil || scope.function.Body == nil {
		return nil, false
	}
	if _, parameter := scope.bindings[object]; parameter {
		return nil, false
	}
	keys := []string{}
	readable := true
	assigned := false
	loops := 0
	stack := []ast.Node{}
	ast.Inspect(scope.function.Body, func(node ast.Node) bool {
		if node == nil {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			switch top.(type) {
			case *ast.ForStmt, *ast.RangeStmt:
				loops -= 1
			}
			return true
		}
		stack = append(stack, node)
		switch typed := node.(type) {
		case *ast.ForStmt, *ast.RangeStmt:
			loops += 1
		case *ast.ValueSpec:
			for index, name := range typed.Names {
				if scope.object(name) == object && index < len(typed.Values) {
					assigned = true
					read, ok := self.readKeys(typed.Values[index], scope)
					readable = readable && ok
					keys = append(keys, read...)
				}
			}
		case *ast.AssignStmt:
			for index, target := range typed.Lhs {
				name, ok := ast.Unparen(target).(*ast.Ident)
				if !ok || scope.object(name) != object {
					continue
				}
				assigned = true
				if len(typed.Rhs) != len(typed.Lhs) {
					readable = false
					continue
				}
				value := ast.Unparen(typed.Rhs[index])
				if call, ok := value.(*ast.CallExpr); ok {
					if isBuiltin(call, "make", scope) {
						continue
					}
					if isBuiltin(call, "append", scope) {
						if first, ok := ast.Unparen(call.Args[0]).(*ast.Ident); ok && scope.object(first) == object {
							// the list so far is what the other assignments read
							added, ok := self.readAppendTail(call, scope)
							readable = readable && ok
							keys = append(keys, added...)
							if 0 < loops {
								keys = append(keys, added...)
							}
							continue
						}
					}
				}
				read, ok := self.readKeys(value, scope)
				readable = readable && ok
				keys = append(keys, read...)
			}
		}
		return true
	})
	if !assigned || !readable {
		return nil, false
	}
	return keys, true
}

// What an append to a list adds, without the list.
func (self *lint) readAppendTail(call *ast.CallExpr, scope *readScope) ([]string, bool) {
	if call.Ellipsis.IsValid() {
		return self.readKeys(call.Args[1], scope)
	}
	keys := []string{}
	for _, argument := range call.Args[1:] {
		keys = append(keys, self.readKey(argument, scope))
	}
	return keys, true
}

// The one return of the function call reaches, and the scope to read it in: its parameters bound to
// what the call passed. nil when it is no such function, or the depth is spent.
func (self *lint) builder(call *ast.CallExpr, scope *readScope) (ast.Expr, *readScope) {
	if builderDepth <= scope.depth {
		return nil, nil
	}
	var callee *types.Func
	var receiver ast.Expr
	switch typed := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		callee, _ = scope.object(typed).(*types.Func)
	case *ast.SelectorExpr:
		if selection, ok := scope.source.info.Selections[typed]; ok {
			callee, _ = selection.Obj().(*types.Func)
			receiver = typed.X
		} else {
			callee, _ = scope.object(typed.Sel).(*types.Func)
		}
	}
	if callee == nil {
		return nil, nil
	}
	function := self.functions[callee.FullName()]
	if function == nil || function.declaration.Body == nil || len(function.declaration.Body.List) != 1 {
		return nil, nil
	}
	returned, ok := function.declaration.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 1 {
		return nil, nil
	}
	inner := &readScope{
		source:   function.source,
		function: function.declaration,
		bindings: map[types.Object]string{},
		depth:    scope.depth + 1,
	}
	bind := func(names []*ast.Ident, value string) {
		for _, name := range names {
			inner.bindings[inner.object(name)] = value
		}
	}
	if receiver != nil && function.declaration.Recv != nil {
		for _, field := range function.declaration.Recv.List {
			bind(field.Names, self.readKey(receiver, scope))
		}
	}
	index := 0
	for _, field := range function.declaration.Type.Params.List {
		for _, name := range field.Names {
			if len(call.Args) <= index {
				return nil, nil
			}
			bind([]*ast.Ident{name}, self.readKey(call.Args[index], scope))
			index += 1
		}
	}
	return returned.Results[0], inner
}

// One key, as literal text with what it cannot read marked. Never fails: what it cannot read reads as
// itself.
func (self *lint) readKey(expression ast.Expr, scope *readScope) string {
	if value := scope.source.info.Types[expression].Value; value != nil && value.Kind() == constant.String {
		return constant.StringVal(value)
	}
	switch typed := ast.Unparen(expression).(type) {
	case *ast.BinaryExpr:
		if typed.Op == token.ADD {
			return self.readKey(typed.X, scope) + self.readKey(typed.Y, scope)
		}
	case *ast.CallExpr:
		if formatted, ok := self.readSprintf(typed, scope); ok {
			return formatted
		}
		if body, inner := self.builder(typed, scope); body != nil {
			return self.readKey(body, inner)
		}
	case *ast.Ident:
		object := scope.object(typed)
		if bound, ok := scope.bindings[object]; ok {
			return bound
		}
		if value := self.onlyAssignment(typed, scope); value != nil {
			return self.readKey(value, scope)
		}
	}
	return unknown(self.spell(expression, scope))
}

// A value by how it reads. A brace in that spelling is source text and no tag, so it goes.
func unknown(spelling string) string {
	return unknownMark + strings.NewReplacer("{", "(", "}", ")").Replace(spelling) + unknownMark
}

// How a value reads where it is used: a bound parameter as what it was called with, so one builder
// called from two places compares by its callers' values.
func (self *lint) spell(expression ast.Expr, scope *readScope) string {
	switch typed := ast.Unparen(expression).(type) {
	case *ast.Ident:
		if bound, ok := scope.bindings[scope.object(typed)]; ok {
			return strings.ReplaceAll(bound, unknownMark, "")
		}
	case *ast.SelectorExpr:
		return self.spell(typed.X, scope) + "." + typed.Sel.Name
	case *ast.CallExpr:
		if len(typed.Args) == 0 {
			return self.spell(typed.Fun, scope) + "()"
		}
	}
	return types.ExprString(expression)
}

// The value of a local assigned exactly once, where it is declared, or nil.
func (self *lint) onlyAssignment(identifier *ast.Ident, scope *readScope) ast.Expr {
	object := scope.object(identifier)
	if object == nil || scope.function == nil || scope.function.Body == nil {
		return nil
	}
	var value ast.Expr
	count := 0
	ast.Inspect(scope.function.Body, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for index, target := range assign.Lhs {
			name, ok := ast.Unparen(target).(*ast.Ident)
			if !ok || scope.object(name) != object {
				continue
			}
			count += 1
			if len(assign.Rhs) == len(assign.Lhs) {
				value = assign.Rhs[index]
			}
		}
		return true
	})
	if count != 1 {
		return nil
	}
	return value
}

// A verb, as fmt.Sprintf reads one, in a key's format.
var formatVerb = regexp.MustCompile(`%[-+# 0]*[0-9]*(?:\.[0-9]+)?[a-zA-Z%]`)

// fmt.Sprintf with a constant format, each verb reading its argument as a key part would. A verb with
// flags or a width pads what it reads, so that stands as a value of its own.
func (self *lint) readSprintf(call *ast.CallExpr, scope *readScope) (string, bool) {
	selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Sprintf" || len(call.Args) == 0 {
		return "", false
	}
	callee, ok := scope.object(selector.Sel).(*types.Func)
	if !ok || callee.Pkg() == nil || callee.Pkg().Path() != "fmt" {
		return "", false
	}
	format := scope.source.info.Types[call.Args[0]].Value
	if format == nil || format.Kind() != constant.String {
		return "", false
	}
	arguments := call.Args[1:]
	text := constant.StringVal(format)
	var read strings.Builder
	position := 0
	argument := 0
	for _, span := range formatVerb.FindAllStringIndex(text, -1) {
		read.WriteString(text[position:span[0]])
		position = span[1]
		verb := text[span[0]:span[1]]
		if verb == "%%" {
			read.WriteByte('%')
			continue
		}
		if len(arguments) <= argument {
			return "", false
		}
		if len(verb) == 2 {
			read.WriteString(self.readKey(arguments[argument], scope))
		} else {
			read.WriteString(unknown(verb + " of " + self.spell(arguments[argument], scope)))
		}
		argument += 1
	}
	read.WriteString(text[position:])
	return read.String(), true
}

// Commands whose first argument is no key: a subcommand, a keyword or a channel.
var keylessCommands = []string{
	"CLUSTER", "COMMAND", "CONFIG", "ECHO", "FUNCTION", "INFO", "MEMORY", "OBJECT", "PING", "PUBLISH",
	"SCRIPT", "SPUBLISH", "TIME", "XGROUP", "XINFO", "XREAD", "XREADGROUP",
}

var (
	scriptCall = regexp.MustCompile(`redis\.p?call\(\s*['"]([A-Za-z]+)['"]\s*(?:,\s*([^,)]*))?`)
	// KEYS[1], and nothing built on it
	scriptKey = regexp.MustCompile(`^KEYS\[[A-Za-z0-9_]+\]$`)
	// local key = KEYS[1], at the end of its line or before a ;
	scriptKeyLocal = regexp.MustCompile(`(?m)local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*KEYS\[[A-Za-z0-9_]+\]\s*(?:;|$)`)
)

// The key argument a script's command names, wrong unless it comes straight from KEYS.
func scriptKeyProblems(source string) []string {
	locals := []string{}
	for _, match := range scriptKeyLocal.FindAllStringSubmatch(source, -1) {
		locals = append(locals, match[1])
	}
	problems := []string{}
	for _, match := range scriptCall.FindAllStringSubmatch(source, -1) {
		command, key := strings.ToUpper(match[1]), strings.TrimSpace(match[2])
		if key == "" || slices.Contains(keylessCommands, command) {
			continue
		}
		if !scriptKey.MatchString(key) && !slices.Contains(locals, key) {
			problems = append(problems, fmt.Sprintf("%s names key %s, which is not from KEYS", command, key))
		}
	}
	return problems
}

// A sidecar.RedisScript literal: a package-level value, with a Source this can read.
func (self *lint) checkScript(source *sourcePackage, function *ast.FuncDecl, literal *ast.CompositeLit) {
	named, ok := source.info.Types[literal].Type.(*types.Named)
	if !ok {
		return
	}
	script := reflect.TypeFor[sidecar.RedisScript]()
	if named.Obj().Name() != script.Name() || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != script.PkgPath() {
		return
	}
	if function != nil {
		self.report(literal.Pos(), function, "a script is a package-level value, never built per call")
	}
	for _, element := range literal.Elts {
		pair, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if name, ok := pair.Key.(*ast.Ident); !ok || name.Name != "Source" {
			continue
		}
		value := source.info.Types[pair.Value].Value
		if value == nil || value.Kind() != constant.String {
			self.report(pair.Pos(), function, "a script's Source must be a constant")
			continue
		}
		for _, problem := range scriptKeyProblems(constant.StringVal(value)) {
			self.report(pair.Pos(), function, problem)
		}
	}
}
