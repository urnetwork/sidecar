// §22.6's last line, "crashers become seeds and regression tests" (TEST-M1-10): a crasher a fuzzing run found
// moves into its target's corpus, testdata/fuzz/<target>/ under the target's package, where every go test, and so
// every test.sh, runs it as a seed (owner decision 101), and the regression test that reproduces it on its own is
// named beside it in testdata/fuzz/<target>.crashers, one "<entry> <test>" line a crasher. check/'s registry rule
// fails a list line whose entry is not in the corpus or whose test the package does not declare, so a crasher is
// both or make check says which half is missing.
//
// The list sits beside the corpus directory, not in it: go test reads every file in testdata/fuzz/<target>/ as a
// corpus entry and fails on one that is not, and skips only directories.
//
// Entries are named as go test names the ones it writes, by the first 16 hex digits of their bytes' SHA-256, so a
// crasher already in place keeps its name and one moved in twice is one entry.
//
// A corpus file is go test's encoding, "go test fuzz v1" and then one Go expression a value; DecodeCrasher reads
// the forms go test writes, so a regression test runs the exact input, and EncodeCrasher writes them. Nothing
// here is safe to run against one target from two processes at once.

package sidecartest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// go test's corpus header, the first line of every entry.
const crasherCorpusHeader = "go test fuzz v1"

// Where a package keeps its targets' corpora, and the suffix of a target's crasher list beside its directory.
const (
	crasherCorpusDirectory = "testdata/fuzz"
	crasherListSuffix      = ".crashers"
)

var (
	crasherTargetPattern = regexp.MustCompile(`^Fuzz[A-Z0-9_][A-Za-z0-9_]*$`)
	crasherTestPattern   = regexp.MustCompile(`^Test[A-Z0-9_][A-Za-z0-9_]*$`)
	crasherEntryPattern  = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// One crasher a target's list names.
type Crasher struct {
	Target string
	// The corpus file's name.
	Entry string
	// Where the corpus file is.
	Path string
	// The test that reproduces it on its own.
	RegressionTest string
}

// The corpus file's values, in the order the fuzz function takes them.
func (self *Crasher) Values() ([]any, error) {
	data, err := os.ReadFile(self.Path)
	if err != nil {
		return nil, err
	}
	return DecodeCrasher(data)
}

// go test's name for an entry with these bytes.
func crasherEntryName(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:16]
}

// Moves the crasher at crasherPath into target's corpus under packageDirectory and lists it there with
// regressionTest, the test that reproduces it on its own. Returns the entry's path. A crasher already in the
// corpus stays where it is and is listed. Refuses what is not a corpus file, a name that is no target or no test,
// an entry of that name holding other bytes, and an entry listed already under another test; nothing is moved
// then.
func CrasherSeed(packageDirectory string, target string, crasherPath string, regressionTest string) (string, error) {
	if !crasherTargetPattern.MatchString(target) {
		return "", fmt.Errorf("%q names no fuzz target", target)
	}
	if !crasherTestPattern.MatchString(regressionTest) {
		return "", fmt.Errorf("%q names no test", regressionTest)
	}
	data, err := os.ReadFile(crasherPath)
	if err != nil {
		return "", err
	}
	if _, err := DecodeCrasher(data); err != nil {
		return "", fmt.Errorf("%s is no corpus file go test can run: %w", crasherPath, err)
	}
	entry := crasherEntryName(data)
	corpusDirectory := filepath.Join(packageDirectory, filepath.FromSlash(crasherCorpusDirectory), target)
	entryPath := filepath.Join(corpusDirectory, entry)
	listPath := filepath.Join(packageDirectory, filepath.FromSlash(crasherCorpusDirectory), target+crasherListSuffix)

	listed, err := readCrasherList(listPath)
	if err != nil {
		return "", err
	}
	if test, ok := listed[entry]; ok && test != regressionTest {
		return "", fmt.Errorf("%s is listed already with the regression test %s", entry, test)
	}
	existing, err := os.ReadFile(entryPath)
	switch {
	case err == nil && !bytes.Equal(existing, data):
		return "", fmt.Errorf("%s holds other bytes than %s", entryPath, crasherPath)
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return "", err
	case err != nil:
		if err := os.MkdirAll(corpusDirectory, 0o755); err != nil {
			return "", err
		}
		if err := writeFileAtomically(entryPath, data); err != nil {
			return "", err
		}
	}

	listed[entry] = regressionTest
	var list strings.Builder
	for _, name := range slices.Sorted(maps.Keys(listed)) {
		fmt.Fprintf(&list, "%s %s\n", name, listed[name])
	}
	if err := writeFileAtomically(listPath, []byte(list.String())); err != nil {
		return "", err
	}

	// the move's last half: the crasher leaves where it was found, unless that was the corpus
	source, sourceErr := filepath.Abs(crasherPath)
	destination, destinationErr := filepath.Abs(entryPath)
	if sourceErr != nil || destinationErr != nil {
		return "", errors.Join(sourceErr, destinationErr)
	}
	if source != destination {
		if err := os.Remove(crasherPath); err != nil {
			return "", err
		}
	}
	return entryPath, nil
}

// The crashers target's list under packageDirectory names, in entry order, or none when it has no list.
func Crashers(packageDirectory string, target string) ([]*Crasher, error) {
	if !crasherTargetPattern.MatchString(target) {
		return nil, fmt.Errorf("%q names no fuzz target", target)
	}
	listed, err := readCrasherList(filepath.Join(packageDirectory, filepath.FromSlash(crasherCorpusDirectory), target+crasherListSuffix))
	if err != nil {
		return nil, err
	}
	crashers := []*Crasher{}
	for entry, test := range listed {
		crashers = append(crashers, &Crasher{
			Target:         target,
			Entry:          entry,
			Path:           filepath.Join(packageDirectory, filepath.FromSlash(crasherCorpusDirectory), target, entry),
			RegressionTest: test,
		})
	}
	slices.SortFunc(crashers, func(a *Crasher, b *Crasher) int {
		return strings.Compare(a.Entry, b.Entry)
	})
	return crashers, nil
}

// A crasher list's lines, entry to test; empty when there is no list.
func readCrasherList(listPath string) (map[string]string, error) {
	data, err := os.ReadFile(listPath)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	listed := map[string]string{}
	for index, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || !crasherEntryPattern.MatchString(fields[0]) || !crasherTestPattern.MatchString(fields[1]) {
			return nil, fmt.Errorf("%s:%d: %q is not an entry and its regression test", listPath, index+1, line)
		}
		if _, ok := listed[fields[0]]; ok {
			return nil, fmt.Errorf("%s:%d: %s is listed twice", listPath, index+1, fields[0])
		}
		listed[fields[0]] = fields[1]
	}
	return listed, nil
}

// Writes data to path through a file beside it, so a reader sees the old bytes or the new.
func writeFileAtomically(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		os.Remove(file.Name())
		return err
	}
	if err := os.Chmod(file.Name(), 0o644); err != nil {
		os.Remove(file.Name())
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		os.Remove(file.Name())
		return err
	}
	return nil
}

// values in go test's corpus encoding, as go test writes an entry. A value of a type a fuzz function cannot take
// is refused.
func EncodeCrasher(values ...any) ([]byte, error) {
	if len(values) == 0 {
		return nil, errors.New("a corpus entry holds at least one value")
	}
	var encoded bytes.Buffer
	encoded.WriteString(crasherCorpusHeader + "\n")
	for _, value := range values {
		switch typed := value.(type) {
		case int, int8, int16, int64, uint, uint16, uint32, uint64, bool:
			fmt.Fprintf(&encoded, "%T(%v)\n", typed, typed)
		case float32:
			if math.IsNaN(float64(typed)) && math.Float32bits(typed) != math.Float32bits(float32(math.NaN())) {
				fmt.Fprintf(&encoded, "math.Float32frombits(0x%x)\n", math.Float32bits(typed))
			} else {
				fmt.Fprintf(&encoded, "%T(%v)\n", typed, typed)
			}
		case float64:
			if math.IsNaN(typed) && math.Float64bits(typed) != math.Float64bits(math.NaN()) {
				fmt.Fprintf(&encoded, "math.Float64frombits(0x%x)\n", math.Float64bits(typed))
			} else {
				fmt.Fprintf(&encoded, "%T(%v)\n", typed, typed)
			}
		case string:
			fmt.Fprintf(&encoded, "string(%q)\n", typed)
		case rune:
			if utf8.ValidRune(typed) {
				fmt.Fprintf(&encoded, "rune(%q)\n", typed)
			} else {
				fmt.Fprintf(&encoded, "int32(%v)\n", typed)
			}
		case byte:
			fmt.Fprintf(&encoded, "byte(%q)\n", typed)
		case []byte:
			fmt.Fprintf(&encoded, "[]byte(%q)\n", typed)
		default:
			return nil, fmt.Errorf("a fuzz function takes no %T", value)
		}
	}
	return encoded.Bytes(), nil
}

// A corpus entry's values, read as go test reads them: each line one conversion of a literal, []byte and string
// from a quoted string, byte and rune from a character or an integer, the integer types from an integer, bool
// from true or false, and the float types from a number, Inf or NaN, or math.Float64frombits and
// math.Float32frombits of their bits.
func DecodeCrasher(data []byte) ([]any, error) {
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 || lines[0] != crasherCorpusHeader {
		return nil, fmt.Errorf("the first line is not %q", crasherCorpusHeader)
	}
	values := []any{}
	for index, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		value, err := decodeCrasherValue(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", index+2, err)
		}
		values = append(values, value)
	}
	if len(values) == 0 {
		return nil, errors.New("no value")
	}
	return values, nil
}

// One line's value.
func decodeCrasherValue(line string) (any, error) {
	expression, err := parser.ParseExpr(line)
	if err != nil {
		return nil, err
	}
	call, ok := expression.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || call.Ellipsis != token.NoPos {
		return nil, fmt.Errorf("%q is not one conversion", line)
	}
	argument := call.Args[0]
	switch function := call.Fun.(type) {
	case *ast.ArrayType:
		element, ok := function.Elt.(*ast.Ident)
		if function.Len != nil || !ok || (element.Name != "byte" && element.Name != "uint8") {
			return nil, fmt.Errorf("%q converts to no type a fuzz function takes", line)
		}
		text, err := crasherString(argument)
		if err != nil {
			return nil, err
		}
		return []byte(text), nil
	case *ast.SelectorExpr:
		packageIdent, ok := function.X.(*ast.Ident)
		if !ok || packageIdent.Name != "math" {
			return nil, fmt.Errorf("%q calls no function go test writes", line)
		}
		literal, ok := argument.(*ast.BasicLit)
		if !ok || literal.Kind != token.INT {
			return nil, fmt.Errorf("%q takes no integer", line)
		}
		switch function.Sel.Name {
		case "Float64frombits":
			bits, err := strconv.ParseUint(literal.Value, 0, 64)
			if err != nil {
				return nil, err
			}
			return math.Float64frombits(bits), nil
		case "Float32frombits":
			bits, err := strconv.ParseUint(literal.Value, 0, 32)
			if err != nil {
				return nil, err
			}
			return math.Float32frombits(uint32(bits)), nil
		}
		return nil, fmt.Errorf("%q calls no function go test writes", line)
	case *ast.Ident:
		return decodeCrasherConversion(function.Name, argument, line)
	}
	return nil, fmt.Errorf("%q converts to no type a fuzz function takes", line)
}

// A conversion to typeName of argument.
func decodeCrasherConversion(typeName string, argument ast.Expr, line string) (any, error) {
	switch typeName {
	case "string":
		return crasherString(argument)
	case "bool":
		ident, ok := argument.(*ast.Ident)
		if !ok || (ident.Name != "true" && ident.Name != "false") {
			return nil, fmt.Errorf("%q is no bool", line)
		}
		return ident.Name == "true", nil
	case "byte", "uint8":
		number, err := crasherCharacterOrInteger(argument, 8, false)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", line, err)
		}
		return byte(number), nil
	case "rune", "int32":
		number, err := crasherCharacterOrInteger(argument, 32, true)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", line, err)
		}
		return rune(number), nil
	case "int", "int8", "int16", "int64":
		bitSizes := map[string]int{"int": strconv.IntSize, "int8": 8, "int16": 16, "int64": 64}
		text, err := crasherSignedLiteral(argument, token.INT)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", line, err)
		}
		number, err := strconv.ParseInt(text, 0, bitSizes[typeName])
		if err != nil {
			return nil, err
		}
		switch typeName {
		case "int":
			return int(number), nil
		case "int8":
			return int8(number), nil
		case "int16":
			return int16(number), nil
		}
		return number, nil
	case "uint", "uint16", "uint32", "uint64":
		bitSizes := map[string]int{"uint": strconv.IntSize, "uint16": 16, "uint32": 32, "uint64": 64}
		literal, ok := argument.(*ast.BasicLit)
		if !ok || literal.Kind != token.INT {
			return nil, fmt.Errorf("%q is no unsigned integer", line)
		}
		number, err := strconv.ParseUint(literal.Value, 0, bitSizes[typeName])
		if err != nil {
			return nil, err
		}
		switch typeName {
		case "uint":
			return uint(number), nil
		case "uint16":
			return uint16(number), nil
		case "uint32":
			return uint32(number), nil
		}
		return number, nil
	case "float32", "float64":
		bitSize := 64
		if typeName == "float32" {
			bitSize = 32
		}
		text, err := crasherFloatText(argument)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", line, err)
		}
		number, err := strconv.ParseFloat(text, bitSize)
		if err != nil {
			return nil, err
		}
		if typeName == "float32" {
			return float32(number), nil
		}
		return number, nil
	}
	return nil, fmt.Errorf("%q converts to no type a fuzz function takes", line)
}

// A quoted string literal's text.
func crasherString(argument ast.Expr) (string, error) {
	literal, ok := argument.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", errors.New("no quoted string")
	}
	return strconv.Unquote(literal.Value)
}

// An integer literal's text with its sign, for a literal of kind.
func crasherSignedLiteral(argument ast.Expr, kind token.Token) (string, error) {
	sign := ""
	if unary, ok := argument.(*ast.UnaryExpr); ok && (unary.Op == token.SUB || unary.Op == token.ADD) {
		sign = unary.Op.String()
		argument = unary.X
	}
	literal, ok := argument.(*ast.BasicLit)
	if !ok || literal.Kind != kind {
		return "", errors.New("no number")
	}
	return sign + literal.Value, nil
}

// A character or integer literal's value, within bitSize bits, signed or not.
func crasherCharacterOrInteger(argument ast.Expr, bitSize int, signed bool) (int64, error) {
	if literal, ok := argument.(*ast.BasicLit); ok && literal.Kind == token.CHAR {
		text, err := strconv.Unquote(literal.Value)
		if err != nil {
			return 0, err
		}
		character, size := utf8.DecodeRuneInString(text)
		if size != len(text) {
			return 0, errors.New("more than one character")
		}
		// a byte's quoted form is one byte, which may be no valid UTF-8 on its own
		if character == utf8.RuneError && len(text) == 1 {
			return int64(text[0]), nil
		}
		if !signed && character >= 1<<bitSize {
			return 0, errors.New("a character past the type's range")
		}
		return int64(character), nil
	}
	text, err := crasherSignedLiteral(argument, token.INT)
	if err != nil {
		return 0, err
	}
	if signed {
		return strconv.ParseInt(text, 0, bitSize)
	}
	number, err := strconv.ParseUint(text, 0, bitSize)
	return int64(number), err
}

// A float's text: a number, +Inf, -Inf or NaN, each with its sign.
func crasherFloatText(argument ast.Expr) (string, error) {
	sign := ""
	if unary, ok := argument.(*ast.UnaryExpr); ok && (unary.Op == token.SUB || unary.Op == token.ADD) {
		sign = unary.Op.String()
		argument = unary.X
	}
	switch value := argument.(type) {
	case *ast.Ident:
		if value.Name == "Inf" || value.Name == "NaN" {
			return sign + value.Name, nil
		}
	case *ast.BasicLit:
		if value.Kind == token.FLOAT || value.Kind == token.INT {
			return sign + value.Value, nil
		}
	}
	return "", errors.New("no float")
}
