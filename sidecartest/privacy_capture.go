// §22.7's privacy harness, its core: what must never reach a server and where to look for it. A test
// plants canaries in every user field, testHookSecret hands over every key a sidecar creates, derives
// or unwraps, and a test may forbid a value it chose; the capture points (privacy_handler.go,
// privacy_frame.go, privacy_sources.go) and the stores hold what servers saw; and Scan looks for every
// needle in every capture, raw and encoded, and in every view decompression and decoding open
// (privacy_scan.go, privacy_encode.go, privacy_decompress.go). Zero findings is the pass.
//
// A value a server may see is declared against its row of §2.8's list, and passes only while that row
// exists (I-18). mx-4's listener input, §2.8's one exception, is excluded by its class and nothing
// broader.
//
// Safe for concurrent use.

package sidecartest

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"

	"github.com/urnetwork/connect"
)

// §22.7: canaries are 32 random bytes.
const canaryByteCount = 32

// A secret shorter than this would turn up by chance in any hash or ciphertext once encoded, so the
// scan refuses it, as a finding, rather than search for it or drop it.
const privacySecretMinByteCount = 16

// The shortest value the scan can look for at all: its prefilter reads 8 bytes at a time.
const privacyValueMinByteCount = 8

// A canary's text: lower-case RFC 4648 base32 with no padding, 52 characters for 32 bytes, which a DNS
// label, a path, a local part and a query all hold, and which a product's lower-casing leaves alone.
var canaryTextEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// Where a value was captured: one of §22.7's capture points, CC1 to CC4, and the path within it. A
// class names a path a real bug would take, so sidecar_leaktest can put a canary through it
// (leak_enabled.go). A bare point, "CC4", is still a class, for an item a test adds by hand.
type PrivacyClass string

// The capture point: CC1, CC2, CC3 or CC4.
func (self PrivacyClass) Point() string {
	point, _, _ := strings.Cut(string(self), "/")
	return point
}

// Whether the class names a capture point.
func (self PrivacyClass) Valid() bool {
	switch self.Point() {
	case "CC1", "CC2", "CC3", "CC4":
		return true
	}
	return false
}

// The classes the harness captures through. Each names the path a real bug would take into it.
const (
	// An engine's handler, request and response alike (§22.7's CC1).
	PrivacyClassHandler PrivacyClass = "CC1/handler"
	// mxedge's report and role-mail listener input at rpt.bringyour.com, §2.8's one exception (mx-4):
	// captured, and never scanned.
	PrivacyClassMx4Input PrivacyClass = "CC1/mx-4"
	// A TransferFrame through the exchange (CC2).
	PrivacyClassFrame PrivacyClass = "CC2/frame"
	// An object in a metadata or segment cluster: its key, body and metadata (CC3).
	PrivacyClassObject PrivacyClass = "CC3/object"
	// A Redis key and its value (CC3).
	PrivacyClassRedis PrivacyClass = "CC3/redis"
	// A sidecar Postgres row, at T3 (CC3).
	PrivacyClassPostgres PrivacyClass = "CC3/postgres"
	// A usage batch a meter sent (CC3).
	PrivacyClassUsage PrivacyClass = "CC3/usage"
	// A task request (CC3).
	PrivacyClassTask PrivacyClass = "CC3/task"
	// A log line (CC4).
	PrivacyClassLog PrivacyClass = "CC4/log"
	// A metric's name, help and label values (CC4).
	PrivacyClassMetric PrivacyClass = "CC4/metric"
	// A push hint's topic and body (CC4).
	PrivacyClassHint PrivacyClass = "CC4/hint"
	// A process's environment (CC4).
	PrivacyClassEnv PrivacyClass = "CC4/env"
	// A hook's payload or answer (CC4).
	PrivacyClassHook PrivacyClass = "CC4/hook"
	// An MCP tool's result (CC4).
	PrivacyClassMcp PrivacyClass = "CC4/mcp"
)

// One thing the scan reads.
type PrivacyItem struct {
	Class PrivacyClass
	// What it is, so a finding says where: "redis {x}y", "object head/a/_", "log".
	Name string
	Body []byte
	// When set, read in place of Body: a large object streams through the scan.
	Open func() (io.ReadCloser, error)
}

// What a needle is.
const (
	privacyNeedleCanary     = "canary"
	privacyNeedleCanaryText = "canary text"
	privacyNeedleSecret     = "secret"
	privacyNeedleValue      = "value"
)

type privacyNeedle struct {
	// the canary's kind, the secret's kind, or the value's label
	label string
	kind  string
	body  []byte
}

// A canary, key or forbidden value where it must not be, or a secret the scan refused to look for.
type PrivacyFinding struct {
	// The canary's kind, the secret's kind or the value's label.
	Needle string
	// canary, canary text, secret or value; refused for a secret too short to look for.
	NeedleKind string
	Class      PrivacyClass
	// The item it was in: "redis {x}y", "log".
	Source string
	// Where, in the view it was found in.
	Offset int64
	// How it was encoded: raw, hex, base64, base64url, base32, base32hex, percent, utf-16le, utf-16be.
	Form string
	// The views opened to find it, outermost first: "gzip > quoted-printable". Empty: the item itself.
	View string
}

func (self *PrivacyFinding) String() string {
	if self.NeedleKind == privacyNeedleRefused {
		return fmt.Sprintf("%s %s: %s", self.NeedleKind, self.Needle, self.Form)
	}
	where := self.Source
	if self.View != "" {
		where += " through " + self.View
	}
	return fmt.Sprintf("%s %s in %s %s at %d as %s", self.NeedleKind, self.Needle, self.Class, where, self.Offset, self.Form)
}

// A finding's NeedleKind for a secret the scan refused.
const privacyNeedleRefused = "refused"

// A value a server may see, by §2.8's row: hits of its kind in its class pass.
type privacyDeclaration struct {
	rowId string
	kind  string
	class PrivacyClass
}

type PrivacyCapture struct {
	stateLock    sync.Mutex
	needles      []*privacyNeedle
	refusals     []*PrivacyFinding
	items        []*PrivacyItem
	sources      []func() []*PrivacyItem
	declarations []*privacyDeclaration
	// built from needles when Scan first needs it, and again when needles change
	matcher            *privacyMatcher
	matcherNeedleCount int
}

func NewPrivacyCapture() *PrivacyCapture {
	return &PrivacyCapture{}
}

func newCanaryBytes() []byte {
	body := make([]byte, canaryByteCount)
	if _, err := rand.Read(body); err != nil {
		panic(err)
	}
	return body
}

// A fresh canary of kind: 32 random bytes, for a field that holds bytes, such as a file's contents or a
// mail body. Every form of them is looked for.
func (self *PrivacyCapture) Canary(kind string) []byte {
	body := newCanaryBytes()
	self.addNeedle(&privacyNeedle{label: kind, kind: privacyNeedleCanary, body: bytes.Clone(body)})
	return body
}

// A fresh canary of kind for a text field, a path, a name, a message or a query: 32 random bytes as 52
// lower-case base32 characters. The bytes and the text are both looked for, each in every form.
func (self *PrivacyCapture) CanaryText(kind string) string {
	body := newCanaryBytes()
	text := canaryTextEncoding.EncodeToString(body)
	// the text first: it is also the bytes' base32, and a finding at one offset names the text
	self.addNeedle(&privacyNeedle{label: kind, kind: privacyNeedleCanaryText, body: []byte(text)})
	self.addNeedle(&privacyNeedle{label: kind, kind: privacyNeedleCanary, body: body})
	return text
}

// testHookSecret's sink: every key created, derived or unwrapped is looked for from now on. One under
// 16 bytes is refused, and the refusal is a finding, so a test cannot pass with a key it never
// searched for.
func (self *PrivacyCapture) AddSecret(kind string, secret []byte) {
	if len(secret) < privacySecretMinByteCount {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.refusals = append(self.refusals, &PrivacyFinding{
			Needle:     kind,
			NeedleKind: privacyNeedleRefused,
			Form:       fmt.Sprintf("a %d-byte secret is under %d bytes, so its encodings turn up by chance: give the hook the key itself", len(secret), privacySecretMinByteCount),
		})
		return
	}
	self.addNeedle(&privacyNeedle{label: kind, kind: privacyNeedleSecret, body: bytes.Clone(secret)})
}

// A value the test chose that no capture may hold: an address, a name (I-13). Looked for in every form
// at 16 bytes and over; a shorter one raw alone, upper or lower case, since its encodings turn up by
// chance. Under 8 bytes it cannot be looked for at all, and the refusal is a finding.
func (self *PrivacyCapture) Forbid(label string, value []byte) {
	if len(value) < privacyValueMinByteCount {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.refusals = append(self.refusals, &PrivacyFinding{
			Needle:     label,
			NeedleKind: privacyNeedleRefused,
			Form:       fmt.Sprintf("a %d-byte value is under the scan's %d", len(value), privacyValueMinByteCount),
		})
		return
	}
	self.addNeedle(&privacyNeedle{label: label, kind: privacyNeedleValue, body: bytes.Clone(value)})
}

func (self *PrivacyCapture) addNeedle(needle *privacyNeedle) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.needles = append(self.needles, needle)
}

// Declares that a server may see kind's canaries in class, as row rowId of §2.8's list says: a hit
// that matches passes. A row the list does not hold, or holds withdrawn, is an error, and declares
// nothing, so a value with no row still fails the scan (I-18).
func (self *PrivacyCapture) Declare(rowId string, kind string, class PrivacyClass) error {
	if !class.Valid() {
		return fmt.Errorf("declare %s: %q is no capture class", rowId, class)
	}
	list, err := LoadMetadataList()
	if err != nil {
		return fmt.Errorf("declare %s: %w", rowId, err)
	}
	row := list.Row(rowId)
	if row == nil {
		return fmt.Errorf("declare %s: §2.8's list has no such row", rowId)
	}
	if !row.Live() {
		return fmt.Errorf("declare %s: the row is withdrawn", rowId)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.declarations = append(self.declarations, &privacyDeclaration{rowId: rowId, kind: kind, class: class})
	return nil
}

// Anything a test or a harness captured. class must name a capture point.
func (self *PrivacyCapture) Add(class PrivacyClass, source string, body []byte) {
	self.AddItem(&PrivacyItem{Class: class, Name: source, Body: body})
}

// As Add, with an item.
func (self *PrivacyCapture) AddItem(item *PrivacyItem) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.items = append(self.items, item)
}

// A source read at each scan, for what changes as a test runs: a store's contents, an edge's records.
// Each item it returns names its own class and source.
func (self *PrivacyCapture) AddSource(source func() []*PrivacyItem) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.sources = append(self.sources, source)
}

// CC2: one frame through the exchange. It is copied, since the sender's pool owns the original.
func (self *PrivacyCapture) AddFrame(source connect.Id, destination connect.Id, frame []byte) {
	self.Add(PrivacyClassFrame, fmt.Sprintf("frame %s to %s", source, destination), bytes.Clone(frame))
}

// How many items of a class the capture holds now, so a test can see the scan had something to read.
// A bare point counts every class under it.
func (self *PrivacyCapture) ItemCount(class PrivacyClass) int {
	count := 0
	for _, item := range self.snapshot() {
		if item.Class == class || (class == PrivacyClass(class.Point()) && item.Class.Point() == string(class)) {
			count += 1
		}
	}
	return count
}

func (self *PrivacyCapture) snapshot() []*PrivacyItem {
	var items []*PrivacyItem
	var sources []func() []*PrivacyItem
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		items = slices.Clone(self.items)
		sources = slices.Clone(self.sources)
	}()
	for _, source := range sources {
		items = append(items, source()...)
	}
	return items
}

// Every needle found where it must not be, and every secret refused. Zero findings is the pass
// (§22.7). A hit a declaration covers is not a finding, and mx-4's listener input is never read.
func (self *PrivacyCapture) Scan() []*PrivacyFinding {
	var matcher *privacyMatcher
	var refusals []*PrivacyFinding
	var declarations []*privacyDeclaration
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.matcher == nil || self.matcherNeedleCount != len(self.needles) {
			self.matcher = newPrivacyMatcher(self.needles)
			self.matcherNeedleCount = len(self.needles)
		}
		matcher = self.matcher
		refusals = slices.Clone(self.refusals)
		declarations = slices.Clone(self.declarations)
	}()
	findings := slices.Clone(refusals)
	declared := func(finding *PrivacyFinding) bool {
		return slices.ContainsFunc(declarations, func(declaration *privacyDeclaration) bool {
			return declaration.kind == finding.Needle && declaration.class == finding.Class
		})
	}
	for _, item := range self.snapshot() {
		if item.Class == PrivacyClassMx4Input {
			continue
		}
		for _, finding := range matcher.scanItem(item) {
			if !declared(finding) {
				findings = append(findings, finding)
			}
		}
	}
	return findings
}
