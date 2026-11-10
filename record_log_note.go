// RECORD.md section 10.2's checkpoint, on every leg: a c2sp.org/tlog-checkpoint note, signed as c2sp.org/signed-note
// says, and the cosignatures witnesses add to it (c2sp.org/tlog-cosignature).
//
//	body        origin, the tree's size in decimal and its root in standard base64, a line each, and no extension line
//	signed      the body, an empty line, then a line a signature: an em dash, a space, the key's name, a space, and
//	            base64 of its 4-byte key id and the signature
//	key id      SHA-256(name || 0x0A || type || public key)[:4]
//	log key     type 0x01, Ed25519 over the body, the key's name the origin
//	cosignature type 0x04, Ed25519 over "cosignature/v1" || 0x0A || "time " || seconds || 0x0A || the body, the line's
//	            signature being the time as 8 big-endian bytes and then the 64-byte signature
//	vkey        name, '+', the key id in hex, '+', base64 of the type byte and the public key
//
// ML-DSA-44 cosignatures (type 0x06), which c2sp.org/tlog-checkpoint recommends, have no verifier here yet: a line
// under such a key verifies under nothing and counts for nothing, so a quorum that needs one is not met (RECORD.md
// section 10.2's cosign row leaves the code to M6's entry).
//
// Everything here is pure, so the offline verifier needs nothing else, and safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The note formats' values.
const (
	recordLogOriginPrefix = "ur.io/recurd/log/"
	// c2sp.org/signed-note's signature types
	RecordLogKeyTypeEd25519        = 0x01
	RecordLogKeyTypeCosignatureV1  = 0x04
	RecordLogKeyTypeCosignMlDsa44  = 0x06
	recordLogKeyIdByteCount        = 4
	recordLogCosignatureHeader     = "cosignature/v1\n"
	recordLogCosignatureTimePrefix = "time "
	recordLogSignaturePrefix       = "— "
	// c2sp.org/signed-note bounds a note's signature lines
	recordLogNoteSignatureCount = 100
	// a note here holds three lines and its signatures: far under this
	recordLogNoteByteCount = 64 * 1024
)

var (
	// A note, a signature line or a verifier key that does not parse.
	ErrRecordLogNote = errors.New("record log note invalid")
	// A note or a cosignature that no given key signed.
	ErrRecordLogNoteUnsigned = errors.New("record log note not signed by a given key")
)

// The log's origin (LogSettingsBody.origin): a name, never dialed.
func RecordLogOrigin(logId Id) string {
	return recordLogOriginPrefix + hex.EncodeToString(logId[:])
}

// A key that verifies signature lines: a log's or a witness's.
type RecordLogVerifierKey struct {
	Name      string
	KeyId     [recordLogKeyIdByteCount]byte
	Type      byte
	PublicKey []byte
}

// SHA-256(name || 0x0A || type || public key)[:4].
func recordLogKeyId(name string, keyType byte, publicKey []byte) [recordLogKeyIdByteCount]byte {
	hash := sha256.New()
	hash.Write([]byte(name))
	hash.Write([]byte{'\n', keyType})
	hash.Write(publicKey)
	return [recordLogKeyIdByteCount]byte(hash.Sum(nil)[:recordLogKeyIdByteCount])
}

// Whether name can be a key's: not empty, no space, no plus and nothing unprintable (c2sp.org/signed-note).
func recordLogKeyNameValid(name string) bool {
	if name == "" || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if unicode.IsSpace(r) || r == '+' || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// A verifier key of a name, a type and a public key.
func NewRecordLogVerifierKey(name string, keyType byte, publicKey []byte) (*RecordLogVerifierKey, error) {
	if !recordLogKeyNameValid(name) {
		return nil, fmt.Errorf("%w: a key name", ErrRecordLogNote)
	}
	if (keyType == RecordLogKeyTypeEd25519 || keyType == RecordLogKeyTypeCosignatureV1) && len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: an Ed25519 key of %d bytes", ErrRecordLogNote, len(publicKey))
	}
	return &RecordLogVerifierKey{Name: name, KeyId: recordLogKeyId(name, keyType, publicKey), Type: keyType, PublicKey: bytes.Clone(publicKey)}, nil
}

// Parses a vkey, holding its key id to its name, type and key.
func ParseRecordLogVerifierKey(vkey string) (*RecordLogVerifierKey, error) {
	name, rest, ok := strings.Cut(vkey, "+")
	keyIdText, keyText, ok2 := strings.Cut(rest, "+")
	if !ok || !ok2 {
		return nil, fmt.Errorf("%w: a verifier key is name+id+key", ErrRecordLogNote)
	}
	keyId, err := hex.DecodeString(keyIdText)
	keyBytes, err2 := base64.StdEncoding.DecodeString(keyText)
	if err != nil || err2 != nil || len(keyId) != recordLogKeyIdByteCount || len(keyBytes) < 2 {
		return nil, fmt.Errorf("%w: a verifier key's id or key", ErrRecordLogNote)
	}
	key, err := NewRecordLogVerifierKey(name, keyBytes[0], keyBytes[1:])
	if err != nil {
		return nil, err
	}
	if key.KeyId != [recordLogKeyIdByteCount]byte(keyId) {
		return nil, fmt.Errorf("%w: a verifier key whose id is not its key's", ErrRecordLogNote)
	}
	return key, nil
}

// The key as a vkey.
func (self *RecordLogVerifierKey) String() string {
	return self.Name + "+" + hex.EncodeToString(self.KeyId[:]) + "+" + base64.StdEncoding.EncodeToString(append([]byte{self.Type}, self.PublicKey...))
}

// One signature line of a note.
type RecordLogNoteSignature struct {
	Name  string
	KeyId [recordLogKeyIdByteCount]byte
	// What follows the key id: a log key's 64 bytes, or a cosignature's 8-byte time and 64 bytes.
	Signature []byte
}

// The line as a note carries it, newline included.
func (self *RecordLogNoteSignature) line() []byte {
	return []byte(recordLogSignaturePrefix + self.Name + " " + base64.StdEncoding.EncodeToString(append(bytes.Clone(self.KeyId[:]), self.Signature...)) + "\n")
}

// A checkpoint as parsed.
type RecordLogNote struct {
	Origin string
	Size   uint64
	Root   [sha256.Size]byte
	// The signed text: the three lines, each with its newline.
	Body       []byte
	Signatures []*RecordLogNoteSignature
}

// The checkpoint's body: what a log key and every cosignature sign.
func RecordLogNoteBody(origin string, size uint64, root [sha256.Size]byte) []byte {
	return []byte(origin + "\n" + strconv.FormatUint(size, 10) + "\n" + base64.StdEncoding.EncodeToString(root[:]) + "\n")
}

// Signature lines as given, one a line: a witness's answer, or a cosigned row's lines.
func ParseRecordLogSignatureLines(lines []byte) ([]*RecordLogNoteSignature, error) {
	signatures := []*RecordLogNoteSignature{}
	if len(lines) == 0 {
		return signatures, nil
	}
	if recordLogNoteByteCount < len(lines) || lines[len(lines)-1] != '\n' || !utf8.Valid(lines) {
		return nil, fmt.Errorf("%w: signature lines", ErrRecordLogNote)
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(lines), "\n"), "\n") {
		rest, ok := strings.CutPrefix(line, recordLogSignaturePrefix)
		name, encoded, ok2 := strings.Cut(rest, " ")
		if !ok || !ok2 || !recordLogKeyNameValid(name) {
			return nil, fmt.Errorf("%w: a signature line", ErrRecordLogNote)
		}
		signature, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(signature) <= recordLogKeyIdByteCount {
			return nil, fmt.Errorf("%w: a signature line's signature", ErrRecordLogNote)
		}
		signatures = append(signatures, &RecordLogNoteSignature{
			Name: name, KeyId: [recordLogKeyIdByteCount]byte(signature[:recordLogKeyIdByteCount]), Signature: signature[recordLogKeyIdByteCount:],
		})
	}
	if recordLogNoteSignatureCount < len(signatures) {
		return nil, fmt.Errorf("%w: %d signature lines", ErrRecordLogNote, len(signatures))
	}
	return signatures, nil
}

// Parses a signed checkpoint: exactly the three lines c2sp.org/tlog-checkpoint names, no extension line, an empty
// line, and at least one signature line. Nothing is verified.
func ParseRecordLogNote(note []byte) (*RecordLogNote, error) {
	if recordLogNoteByteCount < len(note) || !utf8.Valid(note) {
		return nil, fmt.Errorf("%w: a note of %d bytes", ErrRecordLogNote, len(note))
	}
	split := bytes.Index(note, []byte("\n\n"))
	if split < 0 {
		return nil, fmt.Errorf("%w: no signature block", ErrRecordLogNote)
	}
	body := note[:split+1]
	lines := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
	if len(lines) != 3 || lines[0] == "" {
		return nil, fmt.Errorf("%w: a checkpoint of %d lines", ErrRecordLogNote, len(lines))
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil || strconv.FormatUint(size, 10) != lines[1] {
		return nil, fmt.Errorf("%w: a checkpoint's size", ErrRecordLogNote)
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(root) != sha256.Size {
		return nil, fmt.Errorf("%w: a checkpoint's root", ErrRecordLogNote)
	}
	signatures, err := ParseRecordLogSignatureLines(note[split+2:])
	if err != nil {
		return nil, err
	}
	if len(signatures) == 0 {
		return nil, fmt.Errorf("%w: no signature", ErrRecordLogNote)
	}
	return &RecordLogNote{Origin: lines[0], Size: size, Root: [sha256.Size]byte(root), Body: bytes.Clone(body), Signatures: signatures}, nil
}

// Signs a checkpoint with a log key, whose name is the origin: the note a checkpoint entry holds.
func SignRecordLogNote(origin string, size uint64, root [sha256.Size]byte, logKey ed25519.PrivateKey) ([]byte, error) {
	publicKey, ok := logKey.Public().(ed25519.PublicKey)
	if !ok || len(logKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: a log key", ErrRecordLogNote)
	}
	key, err := NewRecordLogVerifierKey(origin, RecordLogKeyTypeEd25519, publicKey)
	if err != nil {
		return nil, err
	}
	body := RecordLogNoteBody(origin, size, root)
	signature := &RecordLogNoteSignature{Name: origin, KeyId: key.KeyId, Signature: ed25519.Sign(logKey, body)}
	return append(append(body, '\n'), signature.line()...), nil
}

// The bytes a cosignature at timeSeconds signs over a checkpoint's body.
func recordLogCosignedBytes(body []byte, timeSeconds uint64) []byte {
	return append([]byte(recordLogCosignatureHeader+recordLogCosignatureTimePrefix+strconv.FormatUint(timeSeconds, 10)+"\n"), body...)
}

// A witness's cosignature line over a checkpoint's body at timeSeconds: what a witness answers, and a test's witness
// makes.
func RecordLogCosign(body []byte, name string, witnessKey ed25519.PrivateKey, timeSeconds uint64) ([]byte, error) {
	publicKey, ok := witnessKey.Public().(ed25519.PublicKey)
	if !ok || len(witnessKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: a witness key", ErrRecordLogNote)
	}
	key, err := NewRecordLogVerifierKey(name, RecordLogKeyTypeCosignatureV1, publicKey)
	if err != nil {
		return nil, err
	}
	signature := binary.BigEndian.AppendUint64(nil, timeSeconds)
	signature = append(signature, ed25519.Sign(witnessKey, recordLogCosignedBytes(body, timeSeconds))...)
	return (&RecordLogNoteSignature{Name: name, KeyId: key.KeyId, Signature: signature}).line(), nil
}

// Whether the line is key's signature over body: a log key's over the body itself, or a witness's cosignature, whose
// time, in Unix seconds, is answered. A line under another name or key id is ErrRecordLogNoteUnsigned, and so is one
// under a key type with no verifier here.
func (self *RecordLogVerifierKey) Verify(body []byte, signature *RecordLogNoteSignature) (uint64, error) {
	if signature.Name != self.Name || signature.KeyId != self.KeyId {
		return 0, ErrRecordLogNoteUnsigned
	}
	switch self.Type {
	case RecordLogKeyTypeEd25519:
		if len(signature.Signature) == ed25519.SignatureSize && ed25519.Verify(self.PublicKey, body, signature.Signature) {
			return 0, nil
		}
	case RecordLogKeyTypeCosignatureV1:
		if len(signature.Signature) == 8+ed25519.SignatureSize {
			timeSeconds := binary.BigEndian.Uint64(signature.Signature[:8])
			if ed25519.Verify(self.PublicKey, recordLogCosignedBytes(body, timeSeconds), signature.Signature[8:]) {
				return timeSeconds, nil
			}
		}
	default:
		return 0, fmt.Errorf("%w: no verifier for key type %#x", ErrRecordLogNoteUnsigned, self.Type)
	}
	return 0, fmt.Errorf("%w: a signature that does not verify under %s", ErrRecordLogNote, self.Name)
}

// Whether one of the note's signature lines is key's and verifies: nil, with a cosignature's time. A line that names
// the key and does not verify is an error, never passed over for another.
func (self *RecordLogNote) SignedBy(key *RecordLogVerifierKey) (uint64, error) {
	for _, signature := range self.Signatures {
		timeSeconds, err := key.Verify(self.Body, signature)
		if errors.Is(err, ErrRecordLogNoteUnsigned) {
			continue
		}
		return timeSeconds, err
	}
	return 0, ErrRecordLogNoteUnsigned
}
