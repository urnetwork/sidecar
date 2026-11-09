// The scan: one pass over each view of each item looking for every pattern of every needle at once,
// linear in the bytes read with the patterns fixed, so T3's sweep over every object in every cluster
// stays a single read. At each offset the 8 bytes there, as they are and folded to lower case, go
// through a bitset of the patterns' first 8 bytes, and only a hit there compares a pattern whole: the
// prefilter costs a few operations a byte, and a false hit costs one comparison.
//
// A stream carries the last bytes of each chunk into the next, so a needle split across a chunk
// boundary is found as if the bytes had come at once.

package sidecartest

import (
	"bytes"
	"encoding/binary"
	"io"
	"slices"
	"strings"
)

// The prefilter's bitset: 2^20 bits, 128 KiB, so thousands of patterns leave it sparse.
const (
	privacyPrefilterBits  = 20
	privacyPrefilterWords = (1 << privacyPrefilterBits) / 64
)

// How much of a stream is read at a time.
const privacyStreamChunkByteCount = 1024 * 1024

type privacyPrefilter struct {
	bits     []uint64
	patterns map[uint64][]*privacyPattern
}

func newPrivacyPrefilter() *privacyPrefilter {
	return &privacyPrefilter{bits: make([]uint64, privacyPrefilterWords), patterns: map[uint64][]*privacyPattern{}}
}

func privacyPrefilterIndex(key uint64) uint64 {
	return (key * 0x9e3779b97f4a7c15) >> (64 - privacyPrefilterBits)
}

func (self *privacyPrefilter) add(pattern *privacyPattern) {
	key := binary.LittleEndian.Uint64(pattern.body)
	index := privacyPrefilterIndex(key)
	self.bits[index/64] |= 1 << (index % 64)
	self.patterns[key] = append(self.patterns[key], pattern)
}

func (self *privacyPrefilter) mayHold(key uint64) bool {
	index := privacyPrefilterIndex(key)
	return self.bits[index/64]&(1<<(index%64)) != 0
}

// The 8 bytes of key with each ASCII upper-case letter made lower case, every byte at once: a byte's
// low seven bits plus 0x3f carry into its top bit exactly when they are 'A' or above, plus 0x25 when
// they are past 'Z', and no byte carries into the next.
func foldUint64(key uint64) uint64 {
	const ones = 0x0101010101010101
	const highs = 0x8080808080808080
	low := key & (0x7f * ones)
	atLeastA := low + (0x80-'A')*ones
	pastZ := low + (0x80-'Z'-1)*ones
	upper := atLeastA &^ pastZ &^ key & highs
	return key | upper>>2
}

func hasPrefixFolded(body []byte, folded []byte) bool {
	if len(body) < len(folded) {
		return false
	}
	for index, b := range folded {
		c := body[index]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != b {
			return false
		}
	}
	return true
}

// Every pattern of a set of needles.
type privacyMatcher struct {
	exact  *privacyPrefilter
	folded *privacyPrefilter
	// the longest pattern, which a stream keeps that many bytes back for
	maxByteCount int
	decode       *privacyDecodeSettings
}

// A matcher for needles, leaving out the patterns of withoutForms, which only a mutant sets.
func newPrivacyMatcher(needles []*privacyNeedle, withoutForms []string) *privacyMatcher {
	matcher := &privacyMatcher{
		exact:  newPrivacyPrefilter(),
		folded: newPrivacyPrefilter(),
		decode: defaultPrivacyDecodeSettings(),
	}
	for _, needle := range needles {
		for _, pattern := range needlePatterns(needle) {
			if slices.Contains(withoutForms, pattern.form) {
				continue
			}
			if pattern.folded {
				matcher.folded.add(pattern)
			} else {
				matcher.exact.add(pattern)
			}
			matcher.maxByteCount = max(matcher.maxByteCount, len(pattern.body))
		}
	}
	return matcher
}

// Each pattern found in view at a start offset in [from, to), with view's offset in its source.
func (self *privacyMatcher) scanRange(view []byte, from int, to int, emit func(pattern *privacyPattern, offset int)) {
	to = min(to, len(view)-privacyValueMinByteCount+1)
	for offset := from; offset < to; offset += 1 {
		key := binary.LittleEndian.Uint64(view[offset:])
		if self.exact.mayHold(key) {
			for _, pattern := range self.exact.patterns[key] {
				if bytes.HasPrefix(view[offset:], pattern.body) {
					emit(pattern, offset)
				}
			}
		}
		if folded := foldUint64(key); self.folded.mayHold(folded) {
			for _, pattern := range self.folded.patterns[folded] {
				if hasPrefixFolded(view[offset:], pattern.body) {
					emit(pattern, offset)
				}
			}
		}
	}
}

// Every needle in one item, through every view its body opens.
func (self *privacyMatcher) scanItem(item *PrivacyItem) []*PrivacyFinding {
	findings := []*PrivacyFinding{}
	// one finding a needle, view and offset: a canary's text is its bytes' base32 too
	type findingKey struct {
		label  string
		view   string
		offset int64
	}
	seen := map[findingKey]bool{}
	emit := func(views []string) func(pattern *privacyPattern, offset int64) {
		return func(pattern *privacyPattern, offset int64) {
			key := findingKey{label: pattern.needle.label, view: strings.Join(views, " > "), offset: offset}
			if seen[key] {
				return
			}
			seen[key] = true
			findings = append(findings, &PrivacyFinding{
				Needle:     pattern.needle.label,
				NeedleKind: pattern.needle.kind,
				Class:      item.Class,
				Source:     item.Name,
				Offset:     offset,
				Form:       pattern.form,
				View:       strings.Join(views, " > "),
			})
		}
	}
	if item.Open != nil {
		reader, err := item.Open()
		if err != nil {
			findings = append(findings, &PrivacyFinding{Needle: item.Name, NeedleKind: privacyNeedleRefused, Class: item.Class, Source: item.Name, Form: "the item could not be opened, so nothing in it was read: " + err.Error()})
			return findings
		}
		defer reader.Close()
		// the head of a stream is kept for its views; the rest streams past
		head, err := self.scanStream(reader, self.decode.MaxViewByteCount, emit(nil))
		if err != nil {
			findings = append(findings, &PrivacyFinding{Needle: item.Name, NeedleKind: privacyNeedleRefused, Class: item.Class, Source: item.Name, Form: "reading the item failed, so the rest of it was not read: " + err.Error()})
		}
		if head != nil {
			self.scanViews(head, 1, nil, emit)
		}
		return findings
	}
	self.scanView(item.Body, 0, nil, emit)
	return findings
}

// view itself, then each view it opens, to the decode settings' depth.
func (self *privacyMatcher) scanView(view []byte, depth int, views []string, emit func(views []string) func(pattern *privacyPattern, offset int64)) {
	found := emit(views)
	self.scanRange(view, 0, len(view), func(pattern *privacyPattern, offset int) {
		found(pattern, int64(offset))
	})
	self.scanViews(view, depth+1, views, emit)
}

func (self *privacyMatcher) scanViews(view []byte, depth int, views []string, emit func(views []string) func(pattern *privacyPattern, offset int64)) {
	if self.decode.MaxDepth < depth {
		return
	}
	for _, opened := range openPrivacyViews(view, self.decode) {
		self.scanView(opened.body, depth, append(append([]string{}, views...), opened.name), emit)
	}
}

// Scans a stream chunk by chunk, keeping the last maxByteCount-1 bytes of each for the next, so what
// spans a boundary is found. Returns the stream's first keepByteCount bytes when it held no more, for
// its views, else nil.
func (self *privacyMatcher) scanStream(reader io.Reader, keepByteCount int, emit func(pattern *privacyPattern, offset int64)) ([]byte, error) {
	carry := max(self.maxByteCount-1, privacyValueMinByteCount-1)
	buffer := make([]byte, 0, carry+privacyStreamChunkByteCount)
	var bufferOffset int64
	var head []byte
	whole := true
	chunk := make([]byte, privacyStreamChunkByteCount)
	for {
		n, err := reader.Read(chunk)
		if 0 < n {
			if whole && len(head)+n <= keepByteCount {
				head = append(head, chunk[:n]...)
			} else {
				whole = false
				head = nil
			}
			buffer = append(buffer, chunk[:n]...)
			// every offset that a pattern of the longest length still fits after
			scanTo := len(buffer) - carry
			if 0 < scanTo {
				self.scanRange(buffer, 0, scanTo, func(pattern *privacyPattern, offset int) {
					emit(pattern, bufferOffset+int64(offset))
				})
				bufferOffset += int64(scanTo)
				buffer = append(buffer[:0], buffer[scanTo:]...)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	self.scanRange(buffer, 0, len(buffer), func(pattern *privacyPattern, offset int) {
		emit(pattern, bufferOffset+int64(offset))
	})
	if !whole {
		return nil, nil
	}
	return head, nil
}
