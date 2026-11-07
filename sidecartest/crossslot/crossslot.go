// §22.4's static lint: a call naming two or more Redis keys names them under one hash tag every key
// carries, by sidecar.RedisKeysShareTag, read from the source. FakeRedis applies the same rule at run
// time, and §22.4 has T3 run every script and multi-key call against 3 masters, which is built with T3.
// This one sees a call no test reached, and it runs in make check, as this package's test.
//
// A call is a method named as a multi-key sidecar.Redis method, with its arity and a []string of keys,
// so a narrower interface an engine declares for itself is held too (host_redis.go lets it). Keys are read
// as far as source shows them: constants, +, fmt.Sprintf, a local's writes, and a builder whose body is
// one return, followed into its arguments. What cannot be read stands as a value of its own, compared
// by how it reads, so {scp_<clientId>}ack beside {scp_<clientId>}tok share a tag and {scp_<clientId>}ack
// beside {scp_<otherId>}tok do not. A list the lint cannot follow at all is a finding: a check that
// cannot see a call has not passed it.
//
// A local list holds every key any write gave it, an element set by index included, since a write may
// replace any key it held. A list used in any way that could change it out of sight cannot be followed:
// passed to a call, aliased, sliced, its address taken, or made with a length, whose elements are keys
// nobody named. A write in a loop or a function literal that does not also hold the list's declaration
// runs any number of times, so its keys are read again as another pass, where whatever a pass may
// change reads as a value of its own: a name declared or written in the loop, a field written in it, or
// a call made in it. A local written more than once reads as a different value at each read. What this
// still takes on trust is a field or package value that a call changes, which the walk does not follow.
//
// A RedisScript is held to its own rule too: a package-level value, whose Source reads every key from
// KEYS and builds none, or the slot check proves nothing (host_redis.go). Every key position of every
// command is checked, from a table of where each command keeps its keys, and a command this does not
// list, or cannot read, is a finding.

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
	"maps"
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
	// The lists being read, shared by every scope one call's read reaches, so a list built from a list
	// built from it cannot be followed, rather than followed without end.
	reading map[types.Object]bool
	// Non-nil when this read stands for another pass of a loop.
	pass *loopPass
}

// Another pass of the loops around a write to a list: what may read differently from the first pass.
type loopPass struct {
	loops []ast.Node
	// A builder called on the pass: all of it runs again, so every call in it may answer differently.
	everywhere bool
	// Names declared or written in the loops.
	varying map[types.Object]bool
	// Fields written in the loops, by how they read.
	varyingFields map[string]bool
}

func within(node ast.Node, outer ast.Node) bool {
	return outer.Pos() <= node.Pos() && node.End() <= outer.End()
}

// Whether expression may read differently on another pass than on the first.
func (self *readScope) varies(expression ast.Expr) bool {
	if self.pass == nil {
		return false
	}
	varies := false
	ast.Inspect(expression, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.CallExpr:
			if self.source.info.Types[typed.Fun].IsType() {
				// a conversion, which varies only with what it converts
				break
			}
			if self.pass.everywhere || slices.ContainsFunc(self.pass.loops, func(loop ast.Node) bool { return within(typed, loop) }) {
				varies = true
			}
		case *ast.SelectorExpr:
			if self.pass.varyingFields[types.ExprString(typed)] {
				varies = true
			}
		case *ast.Ident:
			if object := self.object(typed); object != nil && self.pass.varying[object] {
				varies = true
			}
		}
		return !varies
	})
	return varies
}

// Whether object is a variable of this scope's function: a parameter, a result or a local.
func (self *readScope) declares(object types.Object) bool {
	_, variable := object.(*types.Var)
	return variable && self.function != nil && self.function.Pos() <= object.Pos() && object.Pos() < self.function.End()
}

// The pass of loop, on top of whatever pass scope already reads: every name declared in it, every
// name or field written in it, by assignment, range, ++, -- or address.
func (self *lint) loopPass(loop ast.Node, scope *readScope) *loopPass {
	pass := &loopPass{loops: []ast.Node{loop}, varying: map[types.Object]bool{}, varyingFields: map[string]bool{}}
	if scope.pass != nil {
		pass.loops = append(pass.loops, scope.pass.loops...)
		pass.everywhere = scope.pass.everywhere
		maps.Copy(pass.varying, scope.pass.varying)
		maps.Copy(pass.varyingFields, scope.pass.varyingFields)
	}
	written := func(target ast.Expr) {
		for {
			switch typed := ast.Unparen(target).(type) {
			case *ast.Ident:
				if object := scope.object(typed); object != nil {
					pass.varying[object] = true
				}
				return
			case *ast.SelectorExpr:
				pass.varyingFields[types.ExprString(typed)] = true
				return
			case *ast.IndexExpr:
				target = typed.X
			case *ast.StarExpr:
				target = typed.X
			default:
				return
			}
		}
	}
	ast.Inspect(loop, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.Ident:
			if object := scope.source.info.Defs[typed]; object != nil {
				pass.varying[object] = true
			}
		case *ast.AssignStmt:
			for _, target := range typed.Lhs {
				written(target)
			}
		case *ast.IncDecStmt:
			written(typed.X)
		case *ast.RangeStmt:
			if typed.Key != nil {
				written(typed.Key)
			}
			if typed.Value != nil {
				written(typed.Value)
			}
		case *ast.UnaryExpr:
			if typed.Op == token.AND {
				written(typed.X)
			}
		}
		return true
	})
	return pass
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
	scope := &readScope{source: source, function: function, reading: map[types.Object]bool{}}
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
		if isBuiltin(typed, "make", scope) {
			// empty only when made with no length: an element made empty is a key nobody named
			if len(typed.Args) < 2 {
				return nil, false
			}
			if length := scope.source.info.Types[typed.Args[1]].Value; length != nil && length.Kind() == constant.Int && constant.Sign(length) == 0 {
				return []string{}, true
			}
			return nil, false
		}
		if body, inner := self.builder(typed, scope); body != nil {
			return self.readKeys(body, inner)
		}
	}
	return nil, false
}

// Whether expression is object, by name.
func isObject(expression ast.Expr, object types.Object, scope *readScope) bool {
	identifier, ok := ast.Unparen(expression).(*ast.Ident)
	return ok && scope.object(identifier) == object
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

// A local list, from every write to it in its function, each use of it read as the file header says.
func (self *lint) readKeysVariable(identifier *ast.Ident, scope *readScope) ([]string, bool) {
	object := scope.object(identifier)
	if object == nil || scope.function == nil || scope.function.Body == nil || scope.reading[object] {
		return nil, false
	}
	if _, parameter := scope.bindings[object]; parameter {
		return nil, false
	}
	jumps := false
	ast.Inspect(scope.function.Body, func(node ast.Node) bool {
		if branch, ok := node.(*ast.BranchStmt); ok && branch.Tok == token.GOTO {
			jumps = true
		}
		return !jumps
	})
	if jumps {
		// a goto may run any write again, where the walk cannot see
		return nil, false
	}
	scope.reading[object] = true
	defer delete(scope.reading, object)

	keys := []string{}
	readable := true
	assigned := false
	// What a write gives, and again as another pass of the outermost loop around it that is not also
	// around the list's declaration.
	add := func(stack []ast.Node, read func(scope *readScope) ([]string, bool)) {
		written, ok := read(scope)
		readable = readable && ok
		keys = append(keys, written...)
		for _, node := range stack {
			switch node.(type) {
			case *ast.ForStmt, *ast.RangeStmt, *ast.FuncLit:
				if node.Pos() <= object.Pos() && object.Pos() < node.End() {
					// a list declared in the loop starts again on each pass
					continue
				}
				passScope := *scope
				passScope.pass = self.loopPass(node, scope)
				again, ok := read(&passScope)
				readable = readable && ok
				keys = append(keys, again...)
				return
			}
		}
	}
	stack := []ast.Node{}
	ast.Inspect(scope.function.Body, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if use, ok := node.(*ast.Ident); ok && scope.object(use) == object {
			parent := stack[len(stack)-1]
			var grandparent ast.Node
			if 2 <= len(stack) {
				grandparent = stack[len(stack)-2]
			}
			switch typed := parent.(type) {
			case *ast.ValueSpec:
				index := slices.Index(typed.Names, use)
				switch {
				case index < 0:
					// its value given to another
					readable = false
				case len(typed.Values) == 0:
					assigned = true
				case len(typed.Values) == len(typed.Names):
					assigned = true
					add(stack, func(scope *readScope) ([]string, bool) { return self.readKeys(typed.Values[index], scope) })
				default:
					readable = false
				}
			case *ast.AssignStmt:
				index := slices.Index(typed.Lhs, ast.Expr(use))
				if index < 0 {
					// its value given to another
					readable = false
					break
				}
				assigned = true
				if (typed.Tok != token.ASSIGN && typed.Tok != token.DEFINE) || len(typed.Lhs) != len(typed.Rhs) {
					readable = false
					break
				}
				value := ast.Unparen(typed.Rhs[index])
				if call, ok := value.(*ast.CallExpr); ok && isBuiltin(call, "append", scope) && isObject(call.Args[0], object, scope) {
					// the list so far is what the other writes read
					add(stack, func(scope *readScope) ([]string, bool) { return self.readAppendTail(call, scope) })
					break
				}
				add(stack, func(scope *readScope) ([]string, bool) { return self.readKeys(value, scope) })
			case *ast.IndexExpr:
				if typed.X != ast.Expr(use) {
					readable = false
					break
				}
				switch outer := grandparent.(type) {
				case *ast.AssignStmt:
					index := slices.Index(outer.Lhs, ast.Expr(typed))
					if index < 0 {
						// an element read
						break
					}
					if outer.Tok != token.ASSIGN || len(outer.Lhs) != len(outer.Rhs) {
						readable = false
						break
					}
					add(stack, func(scope *readScope) ([]string, bool) { return []string{self.readKey(outer.Rhs[index], scope)}, true })
				case *ast.UnaryExpr:
					if outer.Op == token.AND {
						readable = false
					}
				case *ast.IncDecStmt:
					readable = false
				}
			case *ast.CallExpr:
				method := self.multiKeyCall(scope.source, typed)
				switch {
				case isBuiltin(typed, "len", scope), isBuiltin(typed, "cap", scope):
				case isBuiltin(typed, "append", scope) && typed.Ellipsis.IsValid() && typed.Args[len(typed.Args)-1] == ast.Expr(use):
					// its keys copied out
				case isBuiltin(typed, "append", scope) && typed.Args[0] == ast.Expr(use):
					// only appending to itself; any other append may share its array
					outer, ok := grandparent.(*ast.AssignStmt)
					index := -1
					if ok {
						index = slices.Index(outer.Rhs, ast.Expr(typed))
					}
					if index < 0 || len(outer.Lhs) != len(outer.Rhs) || !isObject(outer.Lhs[index], object, scope) {
						readable = false
					}
				case method != nil && typed.Args[method.keysArgument] == ast.Expr(use):
				default:
					readable = false
				}
			case *ast.RangeStmt:
				if typed.X != ast.Expr(use) {
					// written by the range
					readable = false
				}
			case *ast.BinaryExpr:
				// compared, as with nil
			default:
				readable = false
			}
		}
		stack = append(stack, node)
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
		reading:  scope.reading,
	}
	if scope.pass != nil && (scope.pass.everywhere || slices.ContainsFunc(scope.pass.loops, func(loop ast.Node) bool { return within(call, loop) })) {
		// called on each pass, so whatever it calls may answer differently
		inner.pass = &loopPass{everywhere: true}
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
	return self.unread("", expression, scope)
}

// A value by how it reads. A brace in that spelling is source text and no tag, so it goes.
func unknown(spelling string) string {
	return unknownMark + strings.NewReplacer("{", "(", "}", ")").Replace(spelling) + unknownMark
}

// A value this cannot read, by how it reads after prefix. On another pass, what may differ from the
// first pass reads as another value.
func (self *lint) unread(prefix string, expression ast.Expr, scope *readScope) string {
	spelling := prefix + self.spell(expression, scope)
	if scope.varies(expression) {
		spelling += " on another pass"
	}
	return unknown(spelling)
}

// How a value reads where it is used: a bound parameter as what it was called with, so one builder
// called from two places compares by its callers' values.
func (self *lint) spell(expression ast.Expr, scope *readScope) string {
	switch typed := ast.Unparen(expression).(type) {
	case *ast.Ident:
		object := scope.object(typed)
		if bound, ok := scope.bindings[object]; ok {
			return strings.ReplaceAll(bound, unknownMark, "")
		}
		if _, count := self.writes(object, scope); object != nil && scope.declares(object) && count != 1 {
			// written more than once, so another read may find another value
			position := self.fileset.Position(typed.Pos())
			return fmt.Sprintf("%s at %d:%d", typed.Name, position.Line, position.Column)
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

// The value of a local written exactly once, by a plain declaration or assignment, or nil.
func (self *lint) onlyAssignment(identifier *ast.Ident, scope *readScope) ast.Expr {
	value, count := self.writes(scope.object(identifier), scope)
	if count != 1 {
		return nil
	}
	return value
}

// How many times scope's function writes object, and the value of the last write when that write is
// a plain one. A write is a declaration, with a value or without, an assignment of any kind, a range
// clause, ++ or --, or taking its address, which may write it anywhere and so counts as two. A
// parameter or result, of the function or of a function literal in it, is written once by its call.
func (self *lint) writes(object types.Object, scope *readScope) (ast.Expr, int) {
	if object == nil || scope.function == nil {
		return nil, 0
	}
	var value ast.Expr
	count := 0
	parameters := func(lists ...*ast.FieldList) {
		for _, list := range lists {
			if list == nil {
				continue
			}
			for _, field := range list.List {
				for _, name := range field.Names {
					if scope.object(name) == object {
						count += 1
						value = nil
					}
				}
			}
		}
	}
	parameters(scope.function.Recv, scope.function.Type.Params, scope.function.Type.Results)
	if scope.function.Body == nil {
		return nil, count
	}
	ast.Inspect(scope.function.Body, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.FuncLit:
			parameters(typed.Type.Params, typed.Type.Results)
		case *ast.ValueSpec:
			for index, name := range typed.Names {
				if scope.object(name) != object {
					continue
				}
				count += 1
				value = nil
				if len(typed.Values) == len(typed.Names) {
					value = typed.Values[index]
				}
			}
		case *ast.AssignStmt:
			for index, target := range typed.Lhs {
				if !isObject(target, object, scope) {
					continue
				}
				count += 1
				value = nil
				if (typed.Tok == token.ASSIGN || typed.Tok == token.DEFINE) && len(typed.Lhs) == len(typed.Rhs) {
					value = typed.Rhs[index]
				}
			}
		case *ast.RangeStmt:
			if (typed.Key != nil && isObject(typed.Key, object, scope)) || (typed.Value != nil && isObject(typed.Value, object, scope)) {
				count += 1
				value = nil
			}
		case *ast.IncDecStmt:
			if isObject(typed.X, object, scope) {
				count += 1
				value = nil
			}
		case *ast.UnaryExpr:
			if typed.Op == token.AND && isObject(typed.X, object, scope) {
				count += 2
				value = nil
			}
		}
		return true
	})
	return value, count
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
			read.WriteString(self.unread(verb+" of ", arguments[argument], scope))
		}
		argument += 1
	}
	read.WriteString(text[position:])
	return read.String(), true
}

// Where a command keeps its keys among its arguments after its name, counting from 1, as COMMAND INFO
// gives them: first to last, every step, a last of -1 running to the end. The zero value names none.
type scriptKeySpec struct {
	first int
	last  int
	step  int
}

var (
	noKeys        = scriptKeySpec{}
	firstKey      = scriptKeySpec{first: 1, last: 1, step: 1}
	firstTwoKeys  = scriptKeySpec{first: 1, last: 2, step: 1}
	everyKey      = scriptKeySpec{first: 1, last: -1, step: 1}
	everyOtherKey = scriptKeySpec{first: 1, last: -1, step: 2}
	secondKey     = scriptKeySpec{first: 2, last: 2, step: 1}
	keysAfterOne  = scriptKeySpec{first: 2, last: -1, step: 1}
)

// Every command a script may call, with where its keys are. A command missing here is a finding, so a
// script using a new one adds it here, with its keys as COMMAND INFO gives them.
var scriptCommandKeys = func() map[string]scriptKeySpec {
	specs := map[string]scriptKeySpec{}
	set := func(spec scriptKeySpec, commands ...string) {
		for _, command := range commands {
			specs[command] = spec
		}
	}
	set(noKeys, "CLUSTER", "COMMAND", "CONFIG", "ECHO", "FUNCTION", "INFO", "PING", "PUBLISH", "SCRIPT", "SPUBLISH", "TIME")
	set(firstKey,
		"APPEND", "BITCOUNT", "BITFIELD", "BITFIELD_RO", "BITPOS", "DECR", "DECRBY", "DUMP", "EXPIRE", "EXPIREAT",
		"EXPIRETIME", "GET", "GETBIT", "GETDEL", "GETEX", "GETRANGE", "GETSET", "HDEL", "HEXISTS", "HEXPIRE",
		"HEXPIREAT", "HEXPIRETIME", "HGET", "HGETALL", "HGETDEL", "HGETEX", "HINCRBY", "HINCRBYFLOAT", "HKEYS",
		"HLEN", "HMGET", "HMSET", "HPERSIST", "HPEXPIRE", "HPEXPIREAT", "HPEXPIRETIME", "HPTTL", "HRANDFIELD",
		"HSCAN", "HSET", "HSETEX", "HSETNX", "HSTRLEN", "HTTL", "HVALS", "INCR", "INCRBY", "INCRBYFLOAT",
		"LINDEX", "LINSERT", "LLEN", "LPOP", "LPOS", "LPUSH", "LPUSHX", "LRANGE", "LREM", "LSET", "LTRIM",
		"PERSIST", "PEXPIRE", "PEXPIREAT", "PEXPIRETIME", "PFADD", "PSETEX", "PTTL", "RESTORE", "RPOP", "RPUSH",
		"RPUSHX", "SADD", "SCARD", "SET", "SETBIT", "SETEX", "SETNX", "SETRANGE", "SISMEMBER", "SMEMBERS",
		"SMISMEMBER", "SPOP", "SRANDMEMBER", "SREM", "SSCAN", "STRLEN", "TTL", "TYPE", "XACK", "XADD",
		"XAUTOCLAIM", "XCLAIM", "XDEL", "XLEN", "XPENDING", "XRANGE", "XREVRANGE", "XSETID", "XTRIM", "ZADD",
		"ZCARD", "ZCOUNT", "ZINCRBY", "ZLEXCOUNT", "ZMSCORE", "ZPOPMAX", "ZPOPMIN", "ZRANDMEMBER", "ZRANGE",
		"ZRANGEBYLEX", "ZRANGEBYSCORE", "ZRANK", "ZREM", "ZREMRANGEBYLEX", "ZREMRANGEBYRANK",
		"ZREMRANGEBYSCORE", "ZREVRANGE", "ZREVRANGEBYLEX", "ZREVRANGEBYSCORE", "ZREVRANK", "ZSCAN", "ZSCORE",
	)
	set(firstTwoKeys, "COPY", "LMOVE", "RENAME", "RENAMENX", "RPOPLPUSH", "SMOVE", "ZRANGESTORE")
	set(everyKey,
		"DEL", "EXISTS", "MGET", "PFCOUNT", "PFMERGE", "SDIFF", "SDIFFSTORE", "SINTER", "SINTERSTORE", "SUNION",
		"SUNIONSTORE", "TOUCH", "UNLINK",
	)
	set(everyOtherKey, "MSET", "MSETNX")
	set(keysAfterOne, "BITOP")
	return specs
}()

// Commands whose first argument is a subcommand, with where each subcommand keeps its keys.
var scriptSubcommandKeys = map[string]map[string]scriptKeySpec{
	"MEMORY": {"DOCTOR": noKeys, "HELP": noKeys, "MALLOC-STATS": noKeys, "PURGE": noKeys, "STATS": noKeys, "USAGE": secondKey},
	"OBJECT": {"ENCODING": secondKey, "FREQ": secondKey, "HELP": noKeys, "IDLETIME": secondKey, "REFCOUNT": secondKey},
	"XGROUP": {
		"CREATE": secondKey, "CREATECONSUMER": secondKey, "DELCONSUMER": secondKey, "DESTROY": secondKey,
		"HELP": noKeys, "SETID": secondKey,
	},
	"XINFO": {"CONSUMERS": secondKey, "GROUPS": secondKey, "HELP": noKeys, "STREAM": secondKey},
}

var (
	// redis.call or redis.pcall, however spaced
	scriptCallName = regexp.MustCompile(`\bredis\s*\.\s*p?call\b`)
	// KEYS[1] or KEYS[i], and nothing built on it
	scriptKey = regexp.MustCompile(`^KEYS\[[A-Za-z0-9_]+\]$`)
	// all of KEYS at once
	scriptAllKeys = regexp.MustCompile(`^(?:table\s*\.\s*)?unpack\(\s*KEYS\s*\)$`)
	// local key = KEYS[1], at the end of its line or before a ;
	scriptKeyLocal = regexp.MustCompile(`(?m)\blocal\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*KEYS\[[A-Za-z0-9_]+\]\s*(?:;|$)`)
	// for _, key in ipairs(KEYS) do
	scriptKeyLoop = regexp.MustCompile(`\bfor\s+[A-Za-z_][A-Za-z0-9_]*\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s+in\s+ipairs\(\s*KEYS\s*\)`)
	// a write to KEYS or one of its entries
	scriptKeysWrite = regexp.MustCompile(`\bKEYS\s*(?:\[[^\]]*\])?\s*=(?:[^=]|$)`)
	// a string literal, as a command's name is written
	scriptLiteral = regexp.MustCompile(`^(?:'([^'\\]*)'|"([^"\\]*)")$`)
)

// Where a Lua string starting at start ends, past its closing quote.
func luaStringEnd(source string, start int) int {
	quote := source[start]
	for index := start + 1; index < len(source); index += 1 {
		switch source[index] {
		case '\\':
			index += 1
		case quote, '\n':
			return index + 1
		}
	}
	return len(source)
}

// The level of a long bracket opening at start, as [[ or [==[, and false when none does.
func luaLongOpen(source string, start int) (int, bool) {
	level := 0
	for index := start + 1; index < len(source); index += 1 {
		switch source[index] {
		case '=':
			level += 1
		case '[':
			return level, source[start] == '['
		default:
			return 0, false
		}
	}
	return 0, false
}

// Where a long bracket of level opening at start ends, past its close.
func luaLongEnd(source string, start int, level int) int {
	closing := "]" + strings.Repeat("=", level) + "]"
	if end := strings.Index(source[start:], closing); 0 <= end {
		return start + end + len(closing)
	}
	return len(source)
}

// source with every comment blanked to spaces, lines kept, so what is read after is code and strings.
func luaWithoutComments(source string) string {
	code := []byte(source)
	for index := 0; index < len(source); {
		switch {
		case source[index] == '\'' || source[index] == '"':
			index = luaStringEnd(source, index)
		case source[index] == '[':
			if level, ok := luaLongOpen(source, index); ok {
				index = luaLongEnd(source, index, level)
			} else {
				index += 1
			}
		case strings.HasPrefix(source[index:], "--"):
			end := len(source)
			if level, ok := luaLongOpen(source, index+2); ok {
				end = luaLongEnd(source, index+2, level)
			} else if newline := strings.IndexByte(source[index:], '\n'); 0 <= newline {
				end = index + newline
			}
			for blank := index; blank < end; blank += 1 {
				if code[blank] != '\n' {
					code[blank] = ' '
				}
			}
			index = end
		default:
			index += 1
		}
	}
	return string(code)
}

// The arguments of the call whose ( is at open, each as its source text, and false when its ) is
// missing.
func luaArguments(code string, open int) ([]string, bool) {
	arguments := []string{}
	depth := 0
	start := open + 1
	for index := open + 1; index < len(code); {
		character := code[index]
		switch character {
		case '\'', '"':
			index = luaStringEnd(code, index)
			continue
		case '[':
			if level, ok := luaLongOpen(code, index); ok {
				index = luaLongEnd(code, index, level)
				continue
			}
			depth += 1
		case '(', '{':
			depth += 1
		case ')', ']', '}':
			if 0 < depth {
				depth -= 1
				break
			}
			if character != ')' {
				return nil, false
			}
			if last := strings.TrimSpace(code[start:index]); last != "" || 0 < len(arguments) {
				arguments = append(arguments, last)
			}
			return arguments, true
		case ',':
			if depth == 0 {
				arguments = append(arguments, strings.TrimSpace(code[start:index]))
				start = index + 1
			}
		}
		index += 1
	}
	return nil, false
}

// The arguments of command that are keys, from its arguments after its name. false: a command or a
// subcommand this does not know, or keys it cannot find.
func scriptCommandKeyArguments(command string, arguments []string) ([]string, bool) {
	spec, ok := scriptCommandKeys[command]
	switch {
	case command == "XREAD" || command == "XREADGROUP":
		// the first half of what follows STREAMS
		for index, argument := range arguments {
			if word, isLiteral := scriptLiteralWord(argument); isLiteral && word == "STREAMS" {
				streams := arguments[index+1:]
				if len(streams) == 0 || len(streams)%2 != 0 {
					return nil, false
				}
				return streams[:len(streams)/2], true
			}
		}
		return nil, false
	case scriptSubcommandKeys[command] != nil:
		if len(arguments) == 0 {
			return nil, false
		}
		subcommand, isLiteral := scriptLiteralWord(arguments[0])
		spec, ok = scriptSubcommandKeys[command][subcommand]
		if !isLiteral || !ok {
			return nil, false
		}
	case !ok:
		return nil, false
	}
	keys := []string{}
	if spec.step <= 0 {
		return keys, true
	}
	last := spec.last
	if last < 0 {
		last = len(arguments)
	}
	for position := spec.first; position <= min(last, len(arguments)); position += spec.step {
		keys = append(keys, arguments[position-1])
	}
	return keys, true
}

// A string literal's text, upper case, and false for anything else.
func scriptLiteralWord(argument string) (string, bool) {
	match := scriptLiteral.FindStringSubmatch(argument)
	if match == nil {
		return "", false
	}
	return strings.ToUpper(match[1] + match[2]), true
}

// Every key a script's commands name that does not come straight from KEYS: KEYS[n], all of KEYS by
// unpack, or a local given one and never written again. A call this cannot read, a command whose keys
// it does not know, and a write to KEYS are problems too. A local of the same name in an inner function
// reads as the same local.
func scriptKeyProblems(source string) []string {
	code := luaWithoutComments(source)
	problems := []string{}
	if scriptKeysWrite.MatchString(code) {
		problems = append(problems, "the script writes KEYS")
	}
	declarations := map[string]int{}
	for _, match := range scriptKeyLocal.FindAllStringSubmatch(code, -1) {
		declarations[match[1]] += 1
	}
	for _, match := range scriptKeyLoop.FindAllStringSubmatch(code, -1) {
		declarations[match[1]] += 0
	}
	keyLocals := []string{}
	for name, count := range declarations {
		// each declaration from KEYS is one write, and any other write makes it no key
		written := regexp.MustCompile(`(?m)(?:^|[^A-Za-z0-9_.])` + regexp.QuoteMeta(name) + `\s*(?:,\s*[A-Za-z_][A-Za-z0-9_.]*\s*)*=(?:[^=]|$)`)
		if len(written.FindAllStringIndex(code, -1)) == count {
			keyLocals = append(keyLocals, name)
		}
	}
	fromKeys := func(argument string) bool {
		return scriptKey.MatchString(argument) || scriptAllKeys.MatchString(argument) || slices.Contains(keyLocals, argument)
	}
	for _, span := range scriptCallName.FindAllStringIndex(code, -1) {
		open := span[1] + len(code[span[1]:]) - len(strings.TrimLeft(code[span[1]:], " \t\r\n"))
		if len(code) <= open || code[open] != '(' {
			problems = append(problems, "redis.call is used other than as a call, so its keys cannot be read")
			continue
		}
		arguments, ok := luaArguments(code, open)
		if !ok || len(arguments) == 0 {
			problems = append(problems, "a call this cannot read")
			continue
		}
		command, isLiteral := scriptLiteralWord(arguments[0])
		if !isLiteral {
			problems = append(problems, fmt.Sprintf("a call whose command %s is no literal, so its keys cannot be read", arguments[0]))
			continue
		}
		keys, ok := scriptCommandKeyArguments(command, arguments[1:])
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: this lint does not know where its keys are", command))
			continue
		}
		for _, key := range keys {
			if !fromKeys(key) {
				problems = append(problems, fmt.Sprintf("%s names key %s, which is not from KEYS", command, key))
			}
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
