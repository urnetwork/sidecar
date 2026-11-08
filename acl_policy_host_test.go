//go:build !js

// What needs a file system, which the sidecar_http Worker has none of: go's fuzz corpus reader, and
// DESIGN.md. acl_policy_test.go runs the corpus's seeds on every leg through embed.
//
// And what is too heavy for that leg: a heap that grows by megabytes leaves the runtime a timer armed
// when the program ends, which wasm_exec.js answers by throwing, so the leg's run fails with every test
// passed. Nothing here depends on the leg: these are sizes of Go values, the same in wasm's 64-bit
// words, and the seeds' allocation bound is what that leg keeps.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// Where DESIGN.md is from the root package. A release branch keeps it at the repository's top, beside
// the module moved into v2026/ (§4.9), so there it sits one directory further up.
var testAclDesignPaths = []string{"DESIGN.md", "../DESIGN.md"}

// The design's example domain, and what test data writes for it (CODESTYLE's test data rule).
const (
	testAclDesignDomain  = "acme.com"
	testAclFixtureDomain = "acme.example"
)

var testAclHujsonFence = regexp.MustCompile("(?ms)^```hujson\n(.*?)^```$")

// Every fenced HuJSON block in DESIGN.md: §8.5's worked example and implicit document, and §16.11's
// directory rule.
func testAclDesignHujson(t *testing.T) []string {
	t.Helper()
	design, err := os.ReadFile(testAclDesignPaths[0])
	if errors.Is(err, os.ErrNotExist) {
		design, err = os.ReadFile(testAclDesignPaths[1])
	}
	if err != nil {
		t.Fatalf("this test needs the design beside the module: %v", err)
	}
	blocks := []string{}
	for _, match := range testAclHujsonFence.FindAllStringSubmatch(string(design), -1) {
		blocks = append(blocks, match[1])
	}
	return blocks
}

// The two fixtures are §8.5's blocks, so the design cannot move away from what these tests parse.
func TestAclPolicyFixturesAreTheDesigns(t *testing.T) {
	blocks := testAclDesignHujson(t)
	if len(blocks) != 3 {
		t.Fatalf("%d hujson blocks in the design", len(blocks))
	}
	for i, name := range []string{"worked_example.hujson", "implicit_document.hujson"} {
		want := strings.ReplaceAll(blocks[i], testAclDesignDomain, testAclFixtureDomain)
		if got := string(testAclPolicyFixture(t, name)); got != want {
			t.Errorf("%s is not the design's block:\n%s", name, want)
		}
	}
}

// §16.11's block is the implicit document's last rule, as §8.5 says the directory's default rule is.
func TestAclPolicyDirectoryRuleIsTheImplicitDocuments(t *testing.T) {
	blocks := testAclDesignHujson(t)
	if len(blocks) != 3 {
		t.Fatalf("%d hujson blocks in the design", len(blocks))
	}
	directory := testParseAclPolicy(t, []byte(`{"requests": [`+blocks[2]+`]}`)).Requests[0]
	implicit := testParseAclPolicy(t, testAclPolicyFixture(t, "implicit_document.hujson"))
	last := implicit.Requests[len(implicit.Requests)-1]
	if got, want := testAclRequestText(directory), testAclRequestText(last); got != want {
		t.Errorf("§16.11 reads %s, and §8.5 %s", got, want)
	}
}

// A requests rule's every value, for comparing two of them in a failure anyone can read.
func testAclRequestText(request AclRequest) string {
	parts := []string{}
	for _, selector := range request.Src {
		parts = append(parts, selector.String())
	}
	for _, resource := range request.Dst {
		parts = append(parts, resource.String())
	}
	for _, action := range request.Allow {
		parts = append(parts, action.String())
	}
	for _, selector := range request.Approver {
		parts = append(parts, selector.String())
	}
	for _, evidence := range request.Evidence {
		parts = append(parts, string(evidence))
	}
	parts = append(parts, request.MaxExpiry.String())
	return strings.Join(parts, " ")
}

// What a parsed policy may keep, as a multiple of its source: the same worst source measures 33x, one
// AclResource per four bytes of text.
const testAclPolicyRetainedFactor = 40

// Memory stays a fixed multiple of the source (§22.6) on the shapes that spend most per source byte.
// A multiple does not depend on the size, so these run at a quarter of the bound to stay quick, and
// the worst of them runs once at the bound itself.
func TestParseAclPolicyMemoryIsBounded(t *testing.T) {
	const byteCount = aclPolicySourceMaxByteCount / 4
	fillTo := func(size int, prefix string, item string, suffix string) []byte {
		count := (size - len(prefix) - len(suffix)) / (len(item) + 1)
		return []byte(prefix + strings.Repeat(item+",", count) + suffix)
	}
	fill := func(prefix string, item string, suffix string) []byte {
		return fillTo(byteCount, prefix, item, suffix)
	}
	rule := `{"src":["tag:a"],"dst":["*"],"allow":["dial"]}`
	for name, source := range map[string][]byte{
		"a dst of bare stars":   fill(`{"grants":[{"src":["tag:a"],"allow":["dial"],"dst":[`, `"*"`, `]}]}`),
		"the same at the bound": fillTo(aclPolicySourceMaxByteCount, `{"grants":[{"src":["tag:a"],"allow":["dial"],"dst":[`, `"*"`, `]}]}`),
		"a src of tags":         fill(`{"grants":[{"dst":["*"],"allow":["dial"],"src":[`, `"tag:a"`, `]}]}`),
		"a group of emails":     fill(`{"groups":{"group:a":[`, `"a@b"`, `]}}`),
		"an allow of stars":     fill(`{"grants":[{"src":["tag:a"],"dst":["*"],"allow":[`, `"*"`, `]}]}`),
		"an ip of stars":        fill(`{"grants":[{"src":["tag:a"],"dst":["*"],"allow":["dial"],"ip":[`, `"*"`, `]}]}`),
		"many rules":            fill(`{"grants":[`, rule, `]}`),
		"many checks":           fill(`{"tests":[{"src":"tag:a","accept":[`, `"*#dial:1"`, `]}]}`),
		"many hosts": []byte(`{"hosts":{` + strings.Join(func() []string {
			hosts := make([]string, 0, byteCount/24)
			for i := range byteCount / 24 {
				hosts = append(hosts, fmt.Sprintf(`"h%d":"192.0.2.1"`, i))
			}
			return hosts
		}(), ",") + `}}`),
		"a comment": []byte(`{/*` + strings.Repeat(" ", byteCount-6) + `*/}`),
		"one long note": []byte(`{"grants":[{"src":["tag:a"],"dst":["*"],"allow":["dial"],"note":"` +
			strings.Repeat("a", byteCount-80) + `"}]}`),
	} {
		if aclPolicySourceMaxByteCount < len(source) {
			t.Fatalf("%s: %d bytes", name, len(source))
		}
		var policy *AclPolicy
		var err error
		var before runtime.MemStats
		var after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		allocatedByteCount := testAclPolicyAllocatedByteCount(func() {
			policy, err = ParseAclPolicy(source)
		})
		runtime.GC()
		runtime.ReadMemStats(&after)
		retainedByteCount := int64(after.HeapAlloc) - int64(before.HeapAlloc)
		runtime.KeepAlive(policy)
		t.Logf("%s: %d B source, allocated %.1fx, retained %.1fx", name, len(source),
			float64(allocatedByteCount)/float64(len(source)), float64(retainedByteCount)/float64(len(source)))
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if bound := testAclPolicyAllocationBound(source); bound < allocatedByteCount {
			t.Errorf("%s: %d B allocated for %d B of source, over %d B", name, allocatedByteCount, len(source), bound)
		}
		if bound := int64(testAclPolicyRetainedFactor * len(source)); bound < retainedByteCount {
			t.Errorf("%s: %d B kept for %d B of source, over %d B", name, retainedByteCount, len(source), bound)
		}
	}
}

// Exactly the bound passes, and a byte past it is refused before any work. The bound is §8.8's 4 MiB,
// written out here and not read from the constant, since every reader must refuse the same heads: a
// constant moved by a byte fails this.
func TestParseAclPolicySourceBound(t *testing.T) {
	const byteCount = 4 * 1024 * 1024
	shell := `{"grants": []}`
	fits := append([]byte(shell), bytes.Repeat([]byte(" "), byteCount-len(shell))...)
	if _, err := ParseAclPolicy(fits); err != nil {
		t.Errorf("at the bound: %v", err)
	}
	over := append(fits, ' ')
	_, err := ParseAclPolicy(over)
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("past the bound: %v", err)
	}
	if !errors.Is(err, ErrAclPolicyInvalid) {
		t.Errorf("%v", err)
	}
}

// Nesting is refused past encoding/json's own limit and at the size bound as it is below them, with no
// parser reached.
func TestParseAclPolicyRefusesNestingAtTheBound(t *testing.T) {
	for _, source := range [][]byte{
		[]byte(`{"grants": ` + strings.Repeat("[", 100_000) + strings.Repeat("]", 100_000) + `}`),
		[]byte(strings.Repeat(`{"a":`, 100_000) + "1" + strings.Repeat("}", 100_000)),
		[]byte(strings.Repeat("[", aclPolicySourceMaxByteCount)),
		[]byte(strings.Repeat("[", aclPolicySourceMaxByteCount/2) + strings.Repeat("]", aclPolicySourceMaxByteCount/2)),
		[]byte(strings.Repeat(`{"a":`, aclPolicySourceMaxByteCount/5)),
	} {
		_, err := ParseAclPolicy(source)
		if err == nil || !errors.Is(err, ErrAclPolicyInvalid) || !strings.Contains(err.Error(), "nested too deep") {
			t.Errorf("%.40s: %v", source, err)
		}
	}
}

// Decoding is total and memory-bounded on anything (§22.6). Seeds in testdata/fuzz run in every
// test.sh.
func FuzzParseAclPolicy(f *testing.F) {
	f.Fuzz(testAclPolicySourceHolds)
}
