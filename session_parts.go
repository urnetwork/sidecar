//go:build !ios_extension && !sidecar_http

// DESIGN-COMPUTE §24.5's large parts (CTXH-M11-03; D-CTXH-3, Q-CTXH-8): an item whose recorded form passes
// SessionItemByteCount keeps its largest strings apart, each a part named in the node by its RFC 6901 pointer and, at
// that pointer in the item, by its reference, {pointer, sha256, size} (session_format.go), until the item fits. A
// part's bytes are the string's UTF-8 bytes, kept whole in session_blob pieces of at most BlobByteCount, at most
// SessionBlobPieceCount of them, so up to SessionPartWholeByteCount; past it, or past the run-hour budget, the part
// goes by hash and size alone, omitted, and the run's coverage counts oversize. An item that holds more than
// SessionPartCount parts' worth past the cap is refused, so nothing is sealed past what a reader takes.
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/urnetwork/sidecar/protocol"
)

// A part's media type: its bytes are the UTF-8 text the string held.
const sessionPartMediaType = "text/plain; charset=utf-8"

// One part cut from an item: the node's SessionPart, and its bytes where they are kept whole, nil where omitted.
type sessionPartCut struct {
	part    *protocol.SessionPart
	content []byte
}

// One string of an item, by its pointer.
type sessionItemString struct {
	pointer string
	value   string
}

// Every string of value with its pointer, objects' members in key order, so a cut is the same every time.
func sessionItemStrings(value any, pointer string, strings *[]*sessionItemString) {
	switch typed := value.(type) {
	case string:
		*strings = append(*strings, &sessionItemString{pointer: pointer, value: typed})
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			sessionItemStrings(typed[key], pointer+"/"+SessionPointerEscape(key), strings)
		}
	case []any:
		for index, element := range typed {
			sessionItemStrings(element, fmt.Sprintf("%s/%d", pointer, index), strings)
		}
	}
}

// Cuts value's largest strings into parts until its RFC 8785 form fits SessionItemByteCount, answering the item as
// recorded and the parts in the order cut. keepWhole says whether a part of size bytes may be kept whole, the run-hour
// budget's word; a part past SessionPartWholeByteCount never is. An item that does not fit within SessionPartCount
// parts is refused.
func sessionCutParts(value any, settings *RecordBodySettings, keepWhole func(size uint64) bool) ([]byte, []*sessionPartCut, error) {
	item, err := sessionCanonical(value)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: an item that is no JSON: %v", ErrSessionNodeRefused, err)
	}
	if len(item) <= settings.SessionItemByteCount {
		return item, nil, nil
	}
	candidates := []*sessionItemString{}
	sessionItemStrings(value, "", &candidates)
	// the largest first; a string no larger than its reference saves nothing
	slices.SortStableFunc(candidates, func(a *sessionItemString, b *sessionItemString) int { return len(b.value) - len(a.value) })
	cuts := []*sessionPartCut{}
	for _, candidate := range candidates {
		if len(item) <= settings.SessionItemByteCount {
			break
		}
		if settings.SessionPartCount <= len(cuts) {
			break
		}
		content := []byte(candidate.value)
		digest := sha256.Sum256(content)
		part := &protocol.SessionPart{Pointer: candidate.pointer, Sha256: digest[:], Size: uint64(len(content)), MediaType: sessionPartMediaType}
		ref := SessionPartRefOf(part)
		if len(candidate.value) <= len(ref.Pointer)+len(ref.Sha256)+32 || !utf8.ValidString(candidate.value) {
			continue
		}
		if err := SessionPointerSet(value, candidate.pointer, ref); err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrSessionNodeRefused, err)
		}
		cut := &sessionPartCut{part: part}
		if part.GetSize() <= settings.SessionPartWholeByteCount && keepWhole(part.GetSize()) {
			cut.content = content
		} else {
			part.Omitted = true
		}
		cuts = append(cuts, cut)
		if item, err = sessionCanonical(value); err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrSessionNodeRefused, err)
		}
	}
	if settings.SessionItemByteCount < len(item) {
		return nil, nil, fmt.Errorf("%w: an item of %d bytes past its cap in %d parts", ErrSessionNodeRefused, len(item), len(cuts))
	}
	return item, cuts, nil
}

// A part's bytes in pieces of at most pieceByteCount, in order.
func sessionPartPieces(content []byte, pieceByteCount int) [][]byte {
	pieces := [][]byte{}
	for start := 0; start < len(content); start += pieceByteCount {
		pieces = append(pieces, content[start:min(start+pieceByteCount, len(content))])
	}
	if len(pieces) == 0 {
		pieces = append(pieces, []byte{})
	}
	return pieces
}

// The pointers of cuts, for an error or a log: never a part's bytes.
func sessionPartPointers(cuts []*sessionPartCut) string {
	pointers := []string{}
	for _, cut := range cuts {
		pointers = append(pointers, cut.part.GetPointer())
	}
	return strings.Join(pointers, ", ")
}
