// §22.7's privacy harness, the part that exists before any engine does: canaries and hooked keys, and
// a scan of what the stores, the exchange and the logs hold, raw and encoded, which must find neither.
// CC1's engine handlers, CC3's Postgres and CC4's edge records join as their owners add sources with
// AddSource. Safe for concurrent use.

package sidecartest

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"mime/quotedprintable"
	"net/url"
	"slices"
	"strings"
	"sync"
	"unicode/utf16"

	"github.com/urnetwork/connect"
)

// §22.7: canaries are 32 random bytes.
const canaryByteCount = 32

// One thing a scan looked in, named so a hit says where.
type PrivacyItem struct {
	// CC1, CC2, CC3 or CC4.
	Class string
	Name  string
	Body  []byte
}

// A canary or key found where it must not be.
type PrivacyHit struct {
	// The canary's label, or the key's kind.
	Needle string
	Class  string
	Name   string
	// How it was encoded when found.
	Form string
}

func (self *PrivacyHit) String() string {
	return fmt.Sprintf("%s in %s %s as %s", self.Needle, self.Class, self.Name, self.Form)
}

type privacyNeedle struct {
	label string
	body  []byte
}

type PrivacyCapture struct {
	stateLock sync.Mutex
	needles   []*privacyNeedle
	items     []*PrivacyItem
	sources   []func() []*PrivacyItem
}

func NewPrivacyCapture() *PrivacyCapture {
	return &PrivacyCapture{}
}

// A fresh canary for a user field, as its 64 hex characters, since most fields are text. Both those
// characters and the 32 bytes they spell are scanned for.
func (self *PrivacyCapture) Canary(label string) string {
	body := make([]byte, canaryByteCount)
	if _, err := rand.Read(body); err != nil {
		panic(err)
	}
	text := hex.EncodeToString(body)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.needles = append(self.needles,
		&privacyNeedle{label: label, body: body},
		&privacyNeedle{label: label + " as text", body: []byte(text)},
	)
	return text
}

// testHookSecret's sink: every key created, derived or unwrapped is scanned for from now on.
func (self *PrivacyCapture) AddSecret(kind string, secret []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.needles = append(self.needles, &privacyNeedle{label: kind, body: bytes.Clone(secret)})
}

// CC2: one frame through the exchange. It is copied, since the sender's pool owns the original.
func (self *PrivacyCapture) AddFrame(source connect.Id, destination connect.Id, frame []byte) {
	self.AddItem(&PrivacyItem{Class: "CC2", Name: fmt.Sprintf("%s to %s", source, destination), Body: bytes.Clone(frame)})
}

// Anything a test or an engine's harness captured: a log line, an MCP result, a handler's body.
func (self *PrivacyCapture) AddItem(item *PrivacyItem) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.items = append(self.items, item)
}

// A source read at each scan, for what changes as a test runs: a store's contents.
func (self *PrivacyCapture) AddSource(source func() []*PrivacyItem) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.sources = append(self.sources, source)
}

// How many items of a class the capture holds now, so a test can see the scan had something to read.
func (self *PrivacyCapture) ItemCount(class string) int {
	count := 0
	for _, item := range self.snapshot() {
		if item.Class == class {
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

// Base64's or base32's bytes for needle inside something longer: the encoder's alignment depends on
// where the needle fell, so each offset has its own form, with the partly-filled edges dropped.
func alignedForms(encode func(body []byte) string, groupByteCount int, groupCharCount int, needle []byte) []string {
	forms := []string{}
	for offset := 0; offset < groupByteCount; offset += 1 {
		padded := append(make([]byte, offset), needle...)
		encoded := strings.TrimRight(encode(padded), "=")
		start := (offset*groupCharCount + groupByteCount - 1) / groupByteCount
		end := len(encoded) - groupCharCount
		if start < end {
			forms = append(forms, encoded[start:end])
		}
	}
	return forms
}

func needleForms(needle []byte) map[string][][]byte {
	forms := map[string][][]byte{"raw": {needle}}
	addText := func(form string, texts ...string) {
		for _, text := range texts {
			forms[form] = append(forms[form], []byte(text))
		}
	}
	addText("hex", hex.EncodeToString(needle), strings.ToUpper(hex.EncodeToString(needle)))
	addText("base64", alignedForms(base64.StdEncoding.EncodeToString, 3, 4, needle)...)
	addText("base64url", alignedForms(base64.URLEncoding.EncodeToString, 3, 4, needle)...)
	addText("base32", alignedForms(base32.StdEncoding.EncodeToString, 5, 8, needle)...)
	addText("base32hex", alignedForms(base32.HexEncoding.EncodeToString, 5, 8, needle)...)

	var quoted bytes.Buffer
	writer := quotedprintable.NewWriter(&quoted)
	writer.Binary = true
	writer.Write(needle)
	writer.Close()
	// a haystack loses its soft line breaks before matching, so this form has none either
	addText("quoted-printable", strings.ReplaceAll(quoted.String(), "=\r\n", ""))

	addText("percent", url.QueryEscape(string(needle)), url.PathEscape(string(needle)), strings.ToLower(url.QueryEscape(string(needle))))

	wide := utf16.Encode([]rune(string(needle)))
	bigEndian := make([]byte, 0, 2*len(wide))
	littleEndian := make([]byte, 0, 2*len(wide))
	for _, unit := range wide {
		bigEndian = append(bigEndian, byte(unit>>8), byte(unit))
		littleEndian = append(littleEndian, byte(unit), byte(unit>>8))
	}
	forms["utf-16"] = [][]byte{bigEndian, littleEndian}
	return forms
}

// The body and everything it decompresses to, since a leak inside a gzip stream is a leak.
func decompressedViews(body []byte) [][]byte {
	views := [][]byte{body}
	readAll := func(reader io.Reader, err error) {
		if err != nil {
			return
		}
		if decoded, err := io.ReadAll(io.LimitReader(reader, 64*1024*1024)); err == nil && 0 < len(decoded) {
			views = append(views, decoded)
		}
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(body))
	readAll(gzipReader, err)
	zlibReader, err := zlib.NewReader(bytes.NewReader(body))
	readAll(zlibReader, err)
	readAll(flate.NewReader(bytes.NewReader(body)), nil)
	return views
}

// Every place a canary or key turned up. Zero hits is the pass (§22.7).
func (self *PrivacyCapture) Scan() []*PrivacyHit {
	var needles []*privacyNeedle
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		needles = slices.Clone(self.needles)
	}()
	needleFormBodies := make([]map[string][][]byte, len(needles))
	for index, needle := range needles {
		needleFormBodies[index] = needleForms(needle.body)
	}
	hits := []*PrivacyHit{}
	for _, item := range self.snapshot() {
		for _, view := range decompressedViews(item.Body) {
			view = bytes.ReplaceAll(view, []byte("=\r\n"), nil)
			view = bytes.ReplaceAll(view, []byte("=\n"), nil)
			for index, needle := range needles {
				for form, bodies := range needleFormBodies[index] {
					if slices.ContainsFunc(bodies, func(body []byte) bool { return 0 < len(body) && bytes.Contains(view, body) }) {
						hits = append(hits, &PrivacyHit{Needle: needle.label, Class: item.Class, Name: item.Name, Form: form})
					}
				}
			}
		}
	}
	return hits
}
