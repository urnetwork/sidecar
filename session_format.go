//go:build !ios_extension

// DESIGN-COMPUTE §24.5's session format (CTXH-M11-01, D-CTXH-1, D-CTXH-10): what a node's two hashes cover and what a
// reader checks of a node, a part and a blob before it trusts their place in a run's tree. record_body.go holds a
// node's shape and caps, which every reader checks at step 5; this file holds what a session reader checks over a
// run's nodes once it has their bodies (CTXH-M11-04's SessionReader), and what the journal makes (CTXH-M11-03).
//
//	item     the node's item as recorded: the Harness's Pi v3 entry or the gateway's API item, RFC 8785 JSON, after
//	         redaction and stubs, each part's value replaced at its RFC 6901 pointer by its reference,
//	         {"pointer": <the pointer>, "sha256": <64 lowercase hex>, "size": <bytes>}, so the item holds its parts by
//	         their hashes and a pruned blob leaves it whole
//	item     item_sha256 = SHA-256(item), the item as recorded; a same_as node's is the node's it names, its own item
//	         and parts empty
//	chain    chain_sha256 = SHA-256(the parent's chain_sha256 || item_sha256), a root's parent counting as 32 zero
//	         bytes, so a node's chain hash names its whole path: the gateway's prefix match (§24.8) and a rebuild's walk
//	         both rest on it
//	part     each part's bytes are the string its pointer held, UTF-8, in up to eight session_blob pieces in index order,
//	         whose concatenation is size bytes hashing to sha256; an omitted part, past 64 MiB, has no pieces
//
// Node ids are 16 random bytes, never derived from content, so two runs that hold the same item share nothing a
// server could match (D-CTXH-2).
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A node whose hashes, same_as or part references do not hold: a reader alarms on it as on any body that fails its
	// rules, and a rebuild reads it as an integrity fault (§24.6's check row).
	ErrSessionNodeInvalid = errors.New("session node invalid")
	// A part's pieces that are not its own, in its order, or whose bytes do not hash to it.
	ErrSessionPartInvalid = errors.New("session part invalid")
)

// What stands at a part's pointer in a recorded item, and in a request as request_sha256 covers it (§24.5).
type SessionPartRef struct {
	Pointer string `json:"pointer"`
	// lowercase hex
	Sha256 string `json:"sha256"`
	Size   uint64 `json:"size"`
}

// The reference a part leaves in its item.
func SessionPartRefOf(part *protocol.SessionPart) *SessionPartRef {
	return &SessionPartRef{Pointer: part.GetPointer(), Sha256: hex.EncodeToString(part.GetSha256()), Size: part.GetSize()}
}

// item_sha256 of an item as recorded (see the file header's item row).
func sessionItemSha256(item []byte) [sha256.Size]byte {
	return sha256.Sum256(item)
}

// chain_sha256 of a node whose item hashes to itemSha256 under a parent whose chain hash is parentChainSha256, nil or
// empty for a root, which counts as 32 zero bytes.
func sessionChainSha256(parentChainSha256 []byte, itemSha256 []byte) [sha256.Size]byte {
	digest := sha256.New()
	if len(parentChainSha256) == 0 {
		digest.Write(make([]byte, sha256.Size))
	} else {
		digest.Write(parentChainSha256)
	}
	digest.Write(itemSha256)
	var chain [sha256.Size]byte
	digest.Sum(chain[:0])
	return chain
}

// What a node is checked against: its parent's chain hash, and the node its same_as names.
type SessionNodeCheckArgs struct {
	// The parent's chain_sha256, nil for a root. A node whose parent this reader has not read, an erased one or another
	// run's it has not opened, cannot have its chain checked: ParentUnread says so, and the check leaves the chain alone.
	ParentChainSha256 []byte
	ParentUnread      bool
	// The earlier node of the run that same_as names, nil for a node with an item of its own.
	SameAs *protocol.SessionEntryBody
}

// Holds a node to the format: its shape and caps (record_body.go), its item to item_sha256 or its same_as node's, its
// chain hash to its parent's, and each part's reference in its item to the part. ErrSessionNodeInvalid otherwise.
func SessionNodeCheck(node *protocol.SessionEntryBody, args *SessionNodeCheckArgs) error {
	if node == nil {
		return fmt.Errorf("%w: no node", ErrSessionNodeInvalid)
	}
	if err := recordSessionEntryValidate(node); err != nil {
		return fmt.Errorf("%w: %w", ErrSessionNodeInvalid, err)
	}
	if args == nil {
		args = &SessionNodeCheckArgs{}
	}
	isRoot := len(node.GetParentNodeId()) == 0
	if isRoot && len(args.ParentChainSha256) != 0 {
		return fmt.Errorf("%w: a root checked against a parent", ErrSessionNodeInvalid)
	}
	if len(node.GetSameAs()) != 0 {
		sameAs := args.SameAs
		if sameAs == nil || !bytes.Equal(sameAs.GetNodeId(), node.GetSameAs()) {
			return fmt.Errorf("%w: a same_as node checked without the node it names", ErrSessionNodeInvalid)
		}
		if !bytes.Equal(sameAs.GetItemSha256(), node.GetItemSha256()) || len(sameAs.GetSameAs()) != 0 {
			return fmt.Errorf("%w: a same_as node whose item is not the one it names", ErrSessionNodeInvalid)
		}
	} else {
		itemSha256 := sessionItemSha256(node.GetItem())
		if !bytes.Equal(itemSha256[:], node.GetItemSha256()) {
			return fmt.Errorf("%w: an item that does not hash to its item_sha256", ErrSessionNodeInvalid)
		}
		if err := sessionPartRefsCheck(node.GetItem(), node.GetParts()); err != nil {
			return err
		}
	}
	if !isRoot && args.ParentUnread {
		return nil
	}
	if !isRoot && len(args.ParentChainSha256) != sha256.Size {
		return fmt.Errorf("%w: a node's parent chain of %d bytes", ErrSessionNodeInvalid, len(args.ParentChainSha256))
	}
	chain := sessionChainSha256(args.ParentChainSha256, node.GetItemSha256())
	if !bytes.Equal(chain[:], node.GetChainSha256()) {
		return fmt.Errorf("%w: a chain hash that is not its parent's and its item's", ErrSessionNodeInvalid)
	}
	return nil
}

// Holds each part's pointer in item to the part's own reference, each pointer once.
func sessionPartRefsCheck(item []byte, parts []*protocol.SessionPart) error {
	if len(parts) == 0 {
		return nil
	}
	value, err := sessionItemDecode(item)
	if err != nil {
		return err
	}
	pointers := map[string]bool{}
	for _, part := range parts {
		if pointers[part.GetPointer()] {
			return fmt.Errorf("%w: two parts at one pointer", ErrSessionNodeInvalid)
		}
		pointers[part.GetPointer()] = true
		at, err := SessionPointerGet(value, part.GetPointer())
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSessionNodeInvalid, err)
		}
		ref, ok := sessionPartRefFrom(at)
		if !ok || *ref != *SessionPartRefOf(part) {
			return fmt.Errorf("%w: a part whose reference in its item is not its own", ErrSessionNodeInvalid)
		}
	}
	return nil
}

// The item decoded for a pointer's walk, numbers kept as written.
func sessionItemDecode(item []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(item))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("%w: an item that is no JSON: %v", ErrSessionNodeInvalid, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: bytes after an item's value", ErrSessionNodeInvalid)
	}
	return value, nil
}

// A decoded value as a part reference: an object of exactly pointer, sha256 and size.
func sessionPartRefFrom(value any) (*SessionPartRef, bool) {
	object, ok := value.(map[string]any)
	if !ok || len(object) != 3 {
		return nil, false
	}
	pointer, pointerOk := object["pointer"].(string)
	digest, digestOk := object["sha256"].(string)
	sizeNumber, sizeOk := object["size"].(json.Number)
	if !pointerOk || !digestOk || !sizeOk {
		return nil, false
	}
	size, err := strconv.ParseUint(sizeNumber.String(), 10, 64)
	if err != nil {
		return nil, false
	}
	return &SessionPartRef{Pointer: pointer, Sha256: digest, Size: size}, true
}

// The reference tokens of an RFC 6901 pointer, unescaped: "~1" is "/" and "~0" is "~".
func sessionPointerTokens(pointer string) ([]string, error) {
	if !RecordSessionPointerValid(pointer) {
		return nil, fmt.Errorf("%q is no pointer into an item", pointer)
	}
	tokens := strings.Split(pointer[1:], "/")
	for i, token := range tokens {
		tokens[i] = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
	}
	return tokens, nil
}

// A reference token escaped for a pointer.
func SessionPointerEscape(token string) string {
	return strings.ReplaceAll(strings.ReplaceAll(token, "~", "~0"), "/", "~1")
}

// The value pointer names in value, decoded JSON (UseNumber), or an error where it names none: an object's member by
// its name, an array's element by a decimal index with no leading zero (RFC 6901 section 4).
func SessionPointerGet(value any, pointer string) (any, error) {
	tokens, err := sessionPointerTokens(pointer)
	if err != nil {
		return nil, err
	}
	at := value
	for _, token := range tokens {
		switch typed := at.(type) {
		case map[string]any:
			next, ok := typed[token]
			if !ok {
				return nil, fmt.Errorf("pointer %q names no member", pointer)
			}
			at = next
		case []any:
			index, ok := sessionPointerIndex(token)
			if !ok || len(typed) <= index {
				return nil, fmt.Errorf("pointer %q names no element", pointer)
			}
			at = typed[index]
		default:
			return nil, fmt.Errorf("pointer %q passes a value that holds none", pointer)
		}
	}
	return at, nil
}

// Sets the value pointer names in value, decoded JSON, to replacement: the member or element must exist.
func SessionPointerSet(value any, pointer string, replacement any) error {
	tokens, err := sessionPointerTokens(pointer)
	if err != nil {
		return err
	}
	parent := value
	if 1 < len(tokens) {
		parent, err = SessionPointerGet(value, "/"+strings.Join(sessionPointerEscapeAll(tokens[:len(tokens)-1]), "/"))
		if err != nil {
			return err
		}
	}
	last := tokens[len(tokens)-1]
	switch typed := parent.(type) {
	case map[string]any:
		if _, ok := typed[last]; !ok {
			return fmt.Errorf("pointer %q names no member", pointer)
		}
		typed[last] = replacement
	case []any:
		index, ok := sessionPointerIndex(last)
		if !ok || len(typed) <= index {
			return fmt.Errorf("pointer %q names no element", pointer)
		}
		typed[index] = replacement
	default:
		return fmt.Errorf("pointer %q passes a value that holds none", pointer)
	}
	return nil
}

// Each token escaped.
func sessionPointerEscapeAll(tokens []string) []string {
	escaped := make([]string, 0, len(tokens))
	for _, token := range tokens {
		escaped = append(escaped, SessionPointerEscape(token))
	}
	return escaped
}

// An array index as RFC 6901 writes it: "0", or digits with no leading zero.
func sessionPointerIndex(token string) (int, bool) {
	if token == "" || (1 < len(token) && token[0] == '0') {
		return 0, false
	}
	index, err := strconv.Atoi(token)
	if err != nil || index < 0 || strconv.Itoa(index) != token {
		return 0, false
	}
	return index, true
}

// A part's bytes from its pieces: one piece an entry the part names, in its order, each naming the part's hash, its
// index and the part's piece count, and their concatenation size bytes hashing to the part's sha256. ErrSessionPartInvalid
// for anything else, and for an omitted part, which has no pieces.
func SessionPartAssemble(part *protocol.SessionPart, pieces []*protocol.SessionBlobBody) ([]byte, error) {
	if part == nil || part.GetOmitted() {
		return nil, fmt.Errorf("%w: an omitted part has no pieces", ErrSessionPartInvalid)
	}
	count := len(part.GetBlobEntryIds())
	if len(pieces) != count || count == 0 {
		return nil, fmt.Errorf("%w: %d pieces of a part in %d", ErrSessionPartInvalid, len(pieces), count)
	}
	assembled := make([]byte, 0, part.GetSize())
	for index, piece := range pieces {
		if err := recordSessionBlobValidate(piece); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrSessionPartInvalid, err)
		}
		if !bytes.Equal(piece.GetPartSha256(), part.GetSha256()) || int(piece.GetIndex()) != index || int(piece.GetCount()) != count {
			return nil, fmt.Errorf("%w: piece %d is not this part's in its place", ErrSessionPartInvalid, index)
		}
		if uint64(len(assembled))+uint64(len(piece.GetContent())) > part.GetSize() {
			return nil, fmt.Errorf("%w: pieces past the part's size", ErrSessionPartInvalid)
		}
		assembled = append(assembled, piece.GetContent()...)
	}
	digest := sha256.Sum256(assembled)
	if uint64(len(assembled)) != part.GetSize() || !bytes.Equal(digest[:], part.GetSha256()) {
		return nil, fmt.Errorf("%w: pieces that are not the part's bytes", ErrSessionPartInvalid)
	}
	return assembled, nil
}

// The parts of a recorded item put back: each part's reference at its pointer replaced by its bytes as a JSON string,
// from partBytes by pointer, and the item canonicalized again (RFC 8785). A pointer partBytes lacks keeps its
// reference, which a rebuild reads as a pruned or omitted part (§24.6).
func SessionItemRestore(item []byte, parts []*protocol.SessionPart, partBytes map[string][]byte) ([]byte, error) {
	if len(parts) == 0 {
		return bytes.Clone(item), nil
	}
	value, err := sessionItemDecode(item)
	if err != nil {
		return nil, err
	}
	for _, part := range slices.Clone(parts) {
		content, ok := partBytes[part.GetPointer()]
		if !ok {
			continue
		}
		if err := SessionPointerSet(value, part.GetPointer(), string(content)); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrSessionNodeInvalid, err)
		}
	}
	restored, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSessionNodeInvalid, err)
	}
	return CanonicalJson(restored)
}
