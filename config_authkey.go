// The auth key string a person holds, client side (§7.8, D-TEAM-5, D-TEAM-22):
//
//	ur-authkey-<id>-<secret>[#<base64url(AuthKeyBundle)>]
//
// QR codes and MDM carry the same string. ur-authkey-<id>-<secret> is the bearer, the only part
// enrollment sends: <id> is the key's 16-byte id and <secret> 32 random bytes, each lowercase RFC 4648
// base32 with no padding, so neither holds a - and the bearer splits once, as server's
// model.ParseAuthKeyBearer reads it (team-m1-authkey-and-admin-event-encodings.md). The #<bundle> of a
// pre-approved key is client-only, like an invite's fragment: the genesis hash, the head the creating
// device stood at, and a Delegation's signing and reader seeds. It is split off before anything else
// runs, so no request, log or MCP result can carry it: CheckAuthKeyBody refuses a request body holding
// its prefix before anything is sent, and RedactAuthKey covers both parts wherever the string may print.
//
// Erasing a bundle protects only this device: every other copy of the string keeps both seeds, so it
// admits until its Delegation ends and reads until its key drops (§7.9's delegation row, §10.5).
//
// Nothing here names a connect type, so it builds on every leg. Errors never repeat any of the text
// they refuse.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The auth key string's format values (§7.8).
const (
	authKeyPrefix = "ur-authkey-"
	// Starts the client-only bundle: the bundle's prefix, which no request body may hold.
	authKeyBundleSeparator = "#"
	// An API key's prefix, which never enrolls (D-CORE-7).
	authKeyApiKeyPrefix = "urn_"
	authKeyIdByteCount  = 16
	// The secret's 32 random bytes.
	authKeySecretByteCount = 32
	authKeyBundleVersion   = 1
	// A seed's bytes: the Delegation's Ed25519 seed and its X-Wing reader seed (§10.5).
	authKeySeedByteCount = 32
	// A keyed tag id's bytes (§7.9).
	authKeyTagIdByteCount = 16
	// The longest string ParseAuthKey reads. A bundle is about 200 B, and this leaves room for a
	// Delegation holding many tags, so the bound only stops a decoder from reading garbage whole.
	authKeyMaxByteCount = 16 * 1024
	// What RedactAuthKey shows in place of what it covers.
	authKeyRedacted = "[redacted]"
	// The separator as JSON may escape it, lowercase.
	authKeyBundleSeparatorJsonEscape = `\u0023`
)

// Lowercase RFC 4648 base32 without padding, as server writes a key's id and secret.
var authKeyEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

var (
	// The string is not an auth key, or its bundle does not decode. Nothing of the string is in the
	// error.
	ErrAuthKeyMalformed = errors.New("not an auth key")
	// A urn_ API key, which never enrolls (D-CORE-7).
	ErrAuthKeyIsApiKey = errors.New("an API key does not enroll")
	// A request body holding a bundle's prefix: refused before anything is sent (§7.8).
	ErrAuthKeyBundleInBody = errors.New("a request body holds an auth key's client-only bundle")
)

// An auth key as ParseAuthKey split it: the bearer enrollment sends, and the client-only bundle of a
// pre-approved key. Printing one with %v or %#v shows neither. Not safe for concurrent use with Erase.
type AuthKey struct {
	bearer string
	bundle *AuthKeyBundle
}

// ur-authkey-<id>-<secret>, the only part of the key any request carries (§7.8). It is a credential:
// it goes to SidecarApi.Enroll and nowhere else (I-7).
func (self *AuthKey) Bearer() string {
	return self.bearer
}

// The client-only bundle, or nil for a key that is not pre-approved.
func (self *AuthKey) Bundle() *AuthKeyBundle {
	return self.bundle
}

// Drops the bearer and zeroes the bundle's seeds, once the key has been used (§5.6's "used once, then
// erased"). A Go string cannot be zeroed in place, so the bearer's bytes stay until collected.
func (self *AuthKey) Erase() {
	self.bearer = ""
	if self.bundle != nil {
		self.bundle.Erase()
	}
}

// Says what it is and nothing it holds.
func (self *AuthKey) String() string {
	if self.bundle != nil {
		return "AuthKey{pre-approved}"
	}
	return "AuthKey{}"
}

// As String, for %#v.
func (self *AuthKey) GoString() string {
	return self.String()
}

// A pre-approved key's #<bundle>, decoded (§7.8). The seeds are secrets: a printed bundle shows none of
// it, and a holder zeroes them with Erase once used. Not safe for concurrent use with Erase.
type AuthKeyBundle struct {
	// A_0 = SHA-256(Signed Genesis), the anchor this key's network chains to (plan-TEAM-genesis-custody).
	GenesisSha256 []byte
	// The log position the creating device stood at (§7.9): version n and its chain digest A_n.
	HeadVersion  uint64
	HeadChain    []byte
	DelegationId Id
	// The Delegation's Ed25519 seed, which signs this daemon's own SidecarAdmit (§5.6, §7.9's scoped).
	DelegationSigningSeed []byte
	// The Delegation's X-Wing reader seed, the one part a daemon keeps (§10.5).
	DelegationReaderSeed []byte
	// The Delegation's keyed tag ids, 16 bytes each, never names (§7.9).
	TagIds [][]byte
}

// Zeroes both seeds.
func (self *AuthKeyBundle) Erase() {
	clear(self.DelegationSigningSeed)
	clear(self.DelegationReaderSeed)
}

// Says what it is and nothing it holds.
func (self *AuthKeyBundle) String() string {
	return "AuthKeyBundle{}"
}

// As String, for %#v.
func (self *AuthKeyBundle) GoString() string {
	return self.String()
}

// Splits the string a person holds into its bearer and, when there is one, its client-only bundle,
// before anything else reads it (D-TEAM-22). The bearer may be given with or without its ur-authkey-
// prefix, as server reads it, and Bearer answers it with the prefix. A urn_ API key is
// ErrAuthKeyIsApiKey; anything else that is not a key with exactly one well-formed part each side of a
// # is ErrAuthKeyMalformed. Neither error holds any of the text. Each seed, and the bearer, reaches
// testHookSecret as it is decoded.
func ParseAuthKey(text string) (*AuthKey, error) {
	if authKeyMaxByteCount < len(text) {
		return nil, ErrAuthKeyMalformed
	}
	bearerText, bundleText, hasBundle := strings.Cut(text, authKeyBundleSeparator)
	bearer, err := parseAuthKeyBearer(bearerText)
	if err != nil {
		return nil, err
	}
	testHookSecret("auth_key", []byte(bearer))
	authKey := &AuthKey{bearer: bearer}
	if !hasBundle {
		return authKey, nil
	}
	bundle, err := decodeAuthKeyBundle(bundleText)
	if err != nil {
		return nil, err
	}
	authKey.bundle = bundle
	return authKey, nil
}

// The canonical bearer, ur-authkey-<id>-<secret>, of text, given with or without its prefix.
func parseAuthKeyBearer(text string) (string, error) {
	if strings.HasPrefix(text, authKeyApiKeyPrefix) {
		return "", ErrAuthKeyIsApiKey
	}
	idText, secretText, found := strings.Cut(strings.TrimPrefix(text, authKeyPrefix), "-")
	if !found {
		return "", ErrAuthKeyMalformed
	}
	idBytes, idErr := authKeyEncoding.DecodeString(idText)
	secret, secretErr := authKeyEncoding.DecodeString(secretText)
	defer clear(secret)
	// a decoding that does not encode back to the text is one the server refuses too
	if idErr != nil || secretErr != nil || len(idBytes) != authKeyIdByteCount ||
		len(secret) != authKeySecretByteCount || authKeyEncoding.EncodeToString(idBytes) != idText ||
		authKeyEncoding.EncodeToString(secret) != secretText {
		return "", ErrAuthKeyMalformed
	}
	return authKeyPrefix + idText + "-" + secretText, nil
}

// The bundle text after #: canonical unpadded base64url of an AuthKeyBundle whose every field has its
// format's length, with no field this version does not know.
func decodeAuthKeyBundle(text string) (*AuthKeyBundle, error) {
	encoded, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil || base64.RawURLEncoding.EncodeToString(encoded) != text {
		return nil, ErrAuthKeyMalformed
	}
	message := &protocol.AuthKeyBundle{}
	if err := proto.Unmarshal(encoded, message); err != nil {
		return nil, ErrAuthKeyMalformed
	}
	defer func() {
		clear(message.DelegationSigningSeed)
		clear(message.DelegationReaderSeed)
		clear(encoded)
	}()
	head := message.GetHead()
	if message.GetVersion() != authKeyBundleVersion ||
		len(message.ProtoReflect().GetUnknown()) != 0 ||
		len(message.GetGenesisSha256()) != sha256.Size ||
		head == nil || len(head.ProtoReflect().GetUnknown()) != 0 ||
		head.GetVersion() < 1 || len(head.GetChain()) != sha256.Size ||
		len(message.GetDelegationId()) != authKeyIdByteCount ||
		len(message.GetDelegationSigningSeed()) != authKeySeedByteCount ||
		len(message.GetDelegationReaderSeed()) != authKeySeedByteCount {
		return nil, ErrAuthKeyMalformed
	}
	delegationId, err := IdFromBytes(message.GetDelegationId())
	if err != nil || delegationId == (Id{}) {
		return nil, ErrAuthKeyMalformed
	}
	tagIds := make([][]byte, 0, len(message.GetTagIds()))
	for _, tagId := range message.GetTagIds() {
		if len(tagId) != authKeyTagIdByteCount {
			return nil, ErrAuthKeyMalformed
		}
		for _, other := range tagIds {
			if bytes.Equal(other, tagId) {
				return nil, ErrAuthKeyMalformed
			}
		}
		tagIds = append(tagIds, bytes.Clone(tagId))
	}
	bundle := &AuthKeyBundle{
		GenesisSha256:         bytes.Clone(message.GetGenesisSha256()),
		HeadVersion:           head.GetVersion(),
		HeadChain:             bytes.Clone(head.GetChain()),
		DelegationId:          delegationId,
		DelegationSigningSeed: bytes.Clone(message.GetDelegationSigningSeed()),
		DelegationReaderSeed:  bytes.Clone(message.GetDelegationReaderSeed()),
		TagIds:                tagIds,
	}
	testHookSecret("delegation_signing_seed", bundle.DelegationSigningSeed)
	testHookSecret("delegation_reader_seed", bundle.DelegationReaderSeed)
	return bundle, nil
}

// The string a person holds for bearer and bundle, the reverse of ParseAuthKey. The creating device
// builds it once to show the person (§7.8), so it is a secret wherever it goes.
func formatAuthKey(bearer string, bundle *AuthKeyBundle) (string, error) {
	canonical, err := parseAuthKeyBearer(bearer)
	if err != nil {
		return "", err
	}
	if bundle == nil {
		return canonical, nil
	}
	message := &protocol.AuthKeyBundle{
		Version:               authKeyBundleVersion,
		GenesisSha256:         bundle.GenesisSha256,
		Head:                  &bridge.AuthPin{Version: bundle.HeadVersion, Chain: bundle.HeadChain},
		DelegationId:          bundle.DelegationId.Bytes(),
		DelegationSigningSeed: bundle.DelegationSigningSeed,
		DelegationReaderSeed:  bundle.DelegationReaderSeed,
		TagIds:                bundle.TagIds,
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return "", fmt.Errorf("%w: the bundle does not encode", ErrAuthKeyMalformed)
	}
	defer clear(encoded)
	text := canonical + authKeyBundleSeparator + base64.RawURLEncoding.EncodeToString(encoded)
	// a bundle ParseAuthKey would refuse is never handed to a person
	if _, err := decodeAuthKeyBundle(text[len(canonical)+1:]); err != nil {
		return "", err
	}
	return text, nil
}

// text with every auth key in it covered, bearer and bundle both, so a daemon log, `ur status` or an
// error can show neither (§7.8). An auth key here is ur-authkey- and what follows it up to the next
// space, quote or other character no key holds, # and its bundle included; it becomes
// ur-authkey-[redacted]. A text that is a bare bearer, <id>-<secret> with no prefix, or holds a # that
// no ur-authkey- precedes, is covered whole, since its parts cannot be told from the words around them.
func RedactAuthKey(text string) string {
	var out strings.Builder
	rest := text
	found := false
	for {
		at := strings.Index(rest, authKeyPrefix)
		if at < 0 {
			break
		}
		found = true
		out.WriteString(rest[:at])
		out.WriteString(authKeyPrefix + authKeyRedacted)
		rest = rest[at+len(authKeyPrefix):]
		end := 0
		for end < len(rest) && isAuthKeyCharacter(rest[end]) {
			end += 1
		}
		rest = rest[end:]
	}
	out.WriteString(rest)
	redacted := out.String()
	if strings.Contains(redacted, authKeyBundleSeparator) {
		// a bundle whose prefix went missing, or a bearer pasted beside its bundle
		return authKeyRedacted
	}
	if !found {
		if _, err := parseAuthKeyBearer(strings.TrimSpace(text)); err == nil {
			return authKeyRedacted
		}
	}
	return redacted
}

// Whether c may be part of an auth key string: base32's lowercase letters and digits, the - between id
// and secret, the # before a bundle, and base64url's letters, digits, - and _.
func isAuthKeyCharacter(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '#'
}

// Refuses a request body that holds a bundle's prefix, #, written as itself, as JSON's \u0023 or as a
// form's %23, before anything is sent (§7.8, D-TEAM-22). Every enrollment body passes through here, so
// a bundle cannot ride in another field, and nothing of the body is in the error.
func CheckAuthKeyBody(body []byte) error {
	if bytes.Contains(body, []byte(authKeyBundleSeparator)) ||
		bytes.Contains(bytes.ToLower(body), []byte(authKeyBundleSeparatorJsonEscape)) ||
		bytes.Contains(bytes.ToLower(body), []byte("%23")) {
		return ErrAuthKeyBundleInBody
	}
	return nil
}
