// §9.4's socket names on every leg: the grammar, the namespaces, and the token paths and seals that
// keep application names from the service. Readers recompile rows on the sidecar_http leg too (§18.10
// keeps ACL evaluation there), so this file names no connect type and carries no build tag.
// socket_address.go adds §9.9's SocketAddress, which does name one.
//
// Parsing goes byte by byte and never rune by rune, so only ASCII folds. strings.ToLower would fold
// U+212A, the Kelvin sign, into a "k", and two spellings would share a token path. Nothing is percent
// decoded. An error never repeats the name, which may be a private one (I-13).
//
// Stored state keys on the network id and never on a label or an alias (D-SOCK-1). The salt below and
// t_0 are that id, so a rename or a reclaim moves no token path.

package sidecar

import (
	"bytes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// Who a name belongs to (§9.4's table), which decides whether it may reach the service in the clear.
// The zero value is no namespace, what a refused name comes back with.
type SocketNamespace int

const (
	// Any other name, blinded.
	SocketNamespaceApplication SocketNamespace = iota + 1
	// tls/<port>/<host>, §13's, in the clear.
	SocketNamespaceTls
	// smtp/<port>/<host>, §15's, in the clear.
	SocketNamespaceSmtp
	// ur/<service>, the platform's, in the clear.
	SocketNamespacePlatform
	// share/<token>, 9.9's `ur share`, blinded.
	SocketNamespaceShare
	// A reserved first segment with no owner yet: c, sys, single characters and "_"-prefixed
	// segments. A name here parses, so a caller can tell why it stops, but it has no token path and
	// nothing may listen on it or dial it. A new owner needs a §9 amendment.
	SocketNamespaceReserved
)

// §9.4's formats, which every reader applies alike.
const (
	socketNameMaxByteCount    = 112
	socketNameMaxSegmentCount = 8
	socketSegmentMaxByteCount = 63
	// K_sock, K_tok and K_seal.
	socketKeyByteCount = 32
	// One t_i, so a token path is 16 B a segment.
	socketTokenByteCount = 16
	// nonce[24] || the name padded to 112 B, encrypted || a 16 B tag.
	socketSealByteCount = chacha20poly1305.NonceSizeX + socketNameMaxByteCount + chacha20poly1305.Overhead
	// 16 random bytes in lowercase base32 with no padding (9.9), since "=" is no segment byte.
	socketShareTokenByteCount = 26

	// What each form takes, on folded text.
	socketLabelBytes      = "abcdefghijklmnopqrstuvwxyz0123456789-"
	socketSegmentBytes    = socketLabelBytes + "_."
	socketShareTokenBytes = "abcdefghijklmnopqrstuvwxyz234567"

	socketTokenKeyInfo = "urnetwork-sidecar-v1/socket-token"
	socketSealKeyInfo  = "urnetwork-sidecar-v1/socket-seal"
)

var (
	errInvalidSocketName    = errors.New("invalid socket name")
	errInvalidSocketAddress = errors.New("invalid socket address")
	errInvalidSocketKey     = errors.New("invalid socket key")
	errSocketNameNotBlinded = errors.New("socket name has no token path")
)

// Whether a name here reaches the service only as a token path (D-SOCK-13).
func (self SocketNamespace) blinded() bool {
	return self == SocketNamespaceApplication || self == SocketNamespaceShare
}

// Lowercases ASCII and leaves every other byte for the grammar to refuse.
func foldSocketText(text string) string {
	folded := []byte(text)
	for index, c := range folded {
		if 'A' <= c && c <= 'Z' {
			folded[index] = c + ('a' - 'A')
		}
	}
	return string(folded)
}

// An LDH label on folded text: 1 to 63 letters, digits and hyphens, with no hyphen at either end.
func validSocketLabel(label string) bool {
	if label == "" || socketSegmentMaxByteCount < len(label) || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	return strings.Trim(label, socketLabelBytes) == ""
}

// §9.4's <host>: "@", one label or <label>.<scope>, and deeper is refused. A wildcard certificate
// covers one label and a Team scope one more (D-SOCK-2). The grammar takes the scope form from the
// start so that M6 changes no format; ValidateListen refuses it until then. smtp/ scopes one label
// only, mx.<scope>.
func validSocketHost(host string, smtp bool) bool {
	if host == "@" {
		return true
	}
	label, scope, scoped := strings.Cut(host, ".")
	if !validSocketLabel(label) {
		return false
	}
	if !scoped {
		return true
	}
	if smtp && label != "mx" {
		return false
	}
	return validSocketLabel(scope)
}

// Folds text and cuts it at each "/", refusing what §9.4's name and seg refuse: a seg is "@" alone, or
// 1 to 63 bytes of the set other than "." and "..". Empty text is refused here: only TokenPrefix has a
// use for no segments, and it says so itself.
func socketSegments(text string) ([]string, error) {
	if text == "" || socketNameMaxByteCount < len(text) {
		return nil, errInvalidSocketName
	}
	segments := strings.Split(foldSocketText(text), "/")
	if socketNameMaxSegmentCount < len(segments) {
		return nil, errInvalidSocketName
	}
	for _, segment := range segments {
		if segment == "@" {
			continue
		}
		if segment == "" || segment == "." || segment == ".." || socketSegmentMaxByteCount < len(segment) ||
			strings.Trim(segment, socketSegmentBytes) != "" {
			return nil, errInvalidSocketName
		}
	}
	return segments, nil
}

// What a folded first segment alone says. Whatever a reserved segment leads, it never reads as an
// application name, so only its owner reaches it.
func socketFirstSegmentNamespace(segment string) SocketNamespace {
	switch segment {
	case "tls":
		return SocketNamespaceTls
	case "smtp":
		return SocketNamespaceSmtp
	case "ur":
		return SocketNamespacePlatform
	case "share":
		return SocketNamespaceShare
	case "sys":
		return SocketNamespaceReserved
	}
	// "c" is one of these, retired with the invites it served (owner decision 86)
	if len(segment) == 1 || segment[0] == '_' {
		return SocketNamespaceReserved
	}
	return SocketNamespaceApplication
}

// A name's canonical form and its namespace, or a refusal. A reserved name is not a refusal here, so
// each caller must act on the namespace: only its owner may use a reserved first segment, and
// SocketNamespaceReserved has none.
//
// Each owner's form in §9.4's table is exact, so a deeper name is refused and never falls through to
// a shallower one (D-SOCK-2). A port is compared as text, so its one spelling is the only one, and a
// leading zero matches nothing.
func ParseSocketName(text string) (string, SocketNamespace, error) {
	segments, err := socketSegments(text)
	if err != nil {
		return "", 0, err
	}
	namespace := socketFirstSegmentNamespace(segments[0])
	formed := true
	switch namespace {
	case SocketNamespaceTls:
		formed = len(segments) == 3 && slices.Contains([]string{"443", "8443", "8883", "5671"}, segments[1]) &&
			validSocketHost(segments[2], false)
	case SocketNamespaceSmtp:
		formed = len(segments) == 3 && segments[1] == "25" && validSocketHost(segments[2], true)
	case SocketNamespacePlatform:
		formed = len(segments) == 2 && validSocketLabel(segments[1])
	case SocketNamespaceShare:
		formed = len(segments) == 2 && len(segments[1]) == socketShareTokenByteCount &&
			strings.Trim(segments[1], socketShareTokenBytes) == ""
	}
	if !formed {
		return "", 0, errInvalidSocketName
	}
	return strings.Join(segments, "/"), namespace, nil
}

// §9.4's address, cut at its first colon into a folded net, "" when there is none, and a canonical
// name. A name holds no colon, so a second one refuses. Whether net resolves, and whether a ur/ name
// may carry one, is resolution's to say (§12, §9.6). This is here, and not in socket_address.go, so
// the grammar runs on every leg.
func parseSocketAddressText(text string) (string, string, error) {
	networkLabel := ""
	nameText := text
	if before, after, found := strings.Cut(text, ":"); found {
		networkLabel = foldSocketText(before)
		if !validSocketLabel(networkLabel) {
			return "", "", errInvalidSocketAddress
		}
		nameText = after
	}
	name, _, err := ParseSocketName(nameText)
	if err != nil {
		return "", "", err
	}
	return networkLabel, name, nil
}

// What one network's K_sock yields (§9.4): K_tok for token paths and K_seal for seals. Immutable, so
// safe for concurrent use. Only clients hold these: no server receives or derives them (I-1).
type SocketKeys struct {
	networkId Id
	tokenKey  []byte
	sealAead  cipher.AEAD
}

// Derives both keys from the network's 32-byte K_sock.
func NewSocketKeys(networkId Id, socketKey []byte) (*SocketKeys, error) {
	if networkId == (Id{}) || len(socketKey) != socketKeyByteCount {
		return nil, errInvalidSocketKey
	}
	testHookSecret("K_sock", socketKey)
	tokenKey, err := hkdf.Key(sha256.New, socketKey, networkId.Bytes(), socketTokenKeyInfo, socketKeyByteCount)
	if err != nil {
		return nil, err
	}
	testHookSecret("K_tok", tokenKey)
	sealKey, err := hkdf.Key(sha256.New, socketKey, networkId.Bytes(), socketSealKeyInfo, socketKeyByteCount)
	if err != nil {
		return nil, err
	}
	testHookSecret("K_seal", sealKey)
	sealAead, err := chacha20poly1305.NewX(sealKey)
	if err != nil {
		return nil, err
	}
	return &SocketKeys{
		networkId: networkId,
		tokenKey:  tokenKey,
		sealAead:  sealAead,
	}, nil
}

// t_1 || ... || t_n over folded segments. Each t_i is a fixed 16 B, so what it joins to seg_i is
// unambiguous, and each hangs off the one before, so a whole-segment prefix of a name is a byte prefix
// of its path.
func (self *SocketKeys) tokenChain(segments []string) []byte {
	mac := hmac.New(sha256.New, self.tokenKey)
	path := make([]byte, 0, len(segments)*socketTokenByteCount)
	previous := self.networkId.Bytes()
	for _, segment := range segments {
		mac.Reset()
		mac.Write(previous)
		mac.Write([]byte(segment))
		previous = mac.Sum(nil)[:socketTokenByteCount]
		path = append(path, previous...)
	}
	return path
}

// name_token, what stands in for a blinded name everywhere a server sees it: §8's
// AclTarget.socket_tokens, §9.5's registrations, §16.11's RequestTarget.socket_token. An edge name has
// none, since its plaintext is its identity (D-SOCK-13), and neither has a reserved one.
func (self *SocketKeys) TokenPath(name string) ([]byte, error) {
	canonical, namespace, err := ParseSocketName(name)
	if err != nil {
		return nil, err
	}
	if !namespace.blinded() {
		return nil, errSocketNameNotBlinded
	}
	return self.tokenChain(strings.Split(canonical, "/")), nil
}

// The chain cut at a whole segment, for §8's socket_prefix: prefix is whole segments of a name, such
// as the literal text before a glob, so it need not be a whole name itself: "share" has no form of its
// own. "" is no segments, a prefix of every blinded name, and comes back empty.
func (self *SocketKeys) TokenPrefix(prefix string) ([]byte, error) {
	if prefix == "" {
		return []byte{}, nil
	}
	segments, err := socketSegments(prefix)
	if err != nil {
		return nil, err
	}
	if !socketFirstSegmentNamespace(segments[0]).blinded() {
		return nil, errSocketNameNotBlinded
	}
	return self.tokenChain(segments), nil
}

// network_id || name_token, what a seal is bound to.
func (self *SocketKeys) sealAssociatedData(nameToken []byte) []byte {
	return append(self.networkId.Bytes(), nameToken...)
}

// sealed_name, for listings: 152 B under a random nonce, so two seals of one name differ and a server
// holding both learns no more than it does from their one token path.
func (self *SocketKeys) Seal(name string) ([]byte, error) {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	// never fails: since Go 1.24 a broken system generator crashes the program instead
	cryptorand.Read(nonce)
	return self.sealWithNonce(name, nonce)
}

// Seal with its nonce given, which only fixed vectors have a reason to do.
func (self *SocketKeys) sealWithNonce(name string, nonce []byte) ([]byte, error) {
	canonical, namespace, err := ParseSocketName(name)
	if err != nil {
		return nil, err
	}
	if !namespace.blinded() {
		return nil, errSocketNameNotBlinded
	}
	nameToken := self.tokenChain(strings.Split(canonical, "/"))
	padded := make([]byte, socketNameMaxByteCount)
	copy(padded, canonical)
	sealed := make([]byte, chacha20poly1305.NonceSizeX, socketSealByteCount)
	copy(sealed, nonce)
	return self.sealAead.Seal(sealed, nonce, padded, self.sealAssociatedData(nameToken)), nil
}

// The name in a seal, dropped unless it re-derives nameToken. Anyone holding K_sock can seal anything,
// so the AEAD proves only that a holder wrote it: a name kept here is also canonical and blinded, and
// is the name that token stands for, so a listing never shows one name under another's token.
func (self *SocketKeys) Open(nameToken []byte, sealedName []byte) (string, bool) {
	if len(sealedName) != socketSealByteCount {
		return "", false
	}
	nonce := sealedName[:chacha20poly1305.NonceSizeX]
	ciphertext := sealedName[chacha20poly1305.NonceSizeX:]
	padded, err := self.sealAead.Open(nil, nonce, ciphertext, self.sealAssociatedData(nameToken))
	if err != nil {
		return "", false
	}
	nameBytes, padding, _ := bytes.Cut(padded, []byte{0})
	if len(bytes.Trim(padding, "\x00")) != 0 {
		return "", false
	}
	name := string(nameBytes)
	rederived, err := self.TokenPath(name)
	if err != nil || foldSocketText(name) != name || !hmac.Equal(rederived, nameToken) {
		return "", false
	}
	return name, true
}

// A lister's open (§9.4): the newest keys, then the previous. Being passed previous keys is what
// being inside a rotation's overlap means here, so a caller past the overlap passes nil, and a seal
// under the old key then opens under nothing. When the overlap ends is the key ring's to say.
func OpenSocketName(newestKeys *SocketKeys, previousKeys *SocketKeys, nameToken []byte, sealedName []byte) (string, bool) {
	for _, keys := range []*SocketKeys{newestKeys, previousKeys} {
		if keys == nil {
			continue
		}
		if name, ok := keys.Open(nameToken, sealedName); ok {
			return name, true
		}
	}
	return "", false
}
