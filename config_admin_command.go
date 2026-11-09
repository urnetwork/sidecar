// One-command admin tokens (§7.8's ur-cli row, D-TEAM-7): the command an admin token is bound to, and the bytes
// that bind it, shared by ur-cli and api so both compute one digest. An admin token's cmd claim is
//
//	cmd = base64url(SHA-256(method || 0x00 || path || 0x00 || JCS(body)))
//
// with JCS RFC 8785's JSON Canonicalization Scheme, base64url unpadded (RFC 4648 §5), method the request's
// uppercase method and path the request's path with no query. A command with no body hashes zero bytes in JCS's
// place. api recomputes cmd from the request it serves and refuses a mismatch, so a token consented for one command
// changes nothing else: another method, path or body, even one that differs only in a value, has another digest.
//
// The authorization request carries the command as one RFC 9396 authorization_details entry of type
// AdminCommandDetailsType, beside the consent code ur-cli shows in its terminal, which the consent page shows beside
// the command so the person can match the two (§7.8's consent row):
//
//	[{"type":"urn:ur:params:oauth:admin-command","method":"POST","path":"/network/auth-keys",
//	  "body":{...},"consent_code":"XXXX-XXXX"}]
//
// Every leg builds this file, so the bytes are equal wherever they are computed.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// Format values of the command and its consent.
const (
	// RFC 9396's type of the one authorization_details entry an ur-cli request carries.
	AdminCommandDetailsType = "urn:ur:params:oauth:admin-command"
	// The longest body a command may carry, before canonicalization.
	AdminCommandMaxBodyByteCount = 16 * 1024
	// The longest path.
	adminCommandMaxPathByteCount = 256
	// The consent code's alphabet: no 0, 1, I, L, O or U, so a person reads it back from a terminal and a
	// page without confusing two.
	adminConsentCodeAlphabet = "23456789ABCDEFGHJKMNPQRSTVWXYZ"
	// Characters on each side of the code's dash: 8 of 30 symbols, about 39 bits.
	adminConsentCodeHalfLength = 4
	// The deepest a canonicalized value nests.
	canonicalJsonMaxDepth = 64
)

// A body, a command or a consent code that does not meet this file's rules. The message names what was wrong,
// never a value, which may hold a credential.
var ErrAdminCommandInvalid = errors.New("admin command invalid")

// JSON text RFC 8785 cannot canonicalize: not one JSON value, a duplicate member name, a number that is not a
// finite double, or a string that is not valid UTF-8.
var ErrCanonicalJsonInvalid = errors.New("json cannot be canonicalized")

// The RFC 8785 canonical form of the one JSON value in input: members sorted by their names' UTF-16 code units, no
// whitespace, strings escaped as ECMAScript's JSON.stringify escapes them, and numbers written as ECMAScript's
// Number.prototype.toString writes a double. Refuses duplicate names (I-JSON, RFC 7493), numbers beyond a double,
// invalid UTF-8, and anything after the value.
func CanonicalJson(input []byte) ([]byte, error) {
	if !utf8.Valid(input) {
		return nil, fmt.Errorf("%w: not utf-8", ErrCanonicalJsonInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	out := &bytes.Buffer{}
	if err := canonicalJsonValue(decoder, out, 0); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: bytes after the value", ErrCanonicalJsonInvalid)
	}
	return out.Bytes(), nil
}

// Writes the next value of decoder in canonical form.
func canonicalJsonValue(decoder *json.Decoder, out *bytes.Buffer, depth int) error {
	if canonicalJsonMaxDepth < depth {
		return fmt.Errorf("%w: nested past %d", ErrCanonicalJsonInvalid, canonicalJsonMaxDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCanonicalJsonInvalid, err)
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			return canonicalJsonObject(decoder, out, depth)
		case '[':
			out.WriteByte('[')
			for i := 0; decoder.More(); i += 1 {
				if 0 < i {
					out.WriteByte(',')
				}
				if err := canonicalJsonValue(decoder, out, depth+1); err != nil {
					return err
				}
			}
			if _, err := decoder.Token(); err != nil {
				return fmt.Errorf("%w: %w", ErrCanonicalJsonInvalid, err)
			}
			out.WriteByte(']')
			return nil
		}
		return fmt.Errorf("%w: a stray delimiter", ErrCanonicalJsonInvalid)
	case string:
		canonicalJsonString(out, value)
	case json.Number:
		number, err := canonicalJsonNumber(value)
		if err != nil {
			return err
		}
		out.WriteString(number)
	case bool:
		if value {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case nil:
		out.WriteString("null")
	default:
		return fmt.Errorf("%w: an unknown token", ErrCanonicalJsonInvalid)
	}
	return nil
}

// Writes an object whose '{' decoder has read, its members sorted by their names' UTF-16 code units (RFC 8785
// §3.2.3), each value canonical.
func canonicalJsonObject(decoder *json.Decoder, out *bytes.Buffer, depth int) error {
	type member struct {
		name  string
		utf16 []uint16
		value []byte
	}
	members := []*member{}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("%w: %w", ErrCanonicalJsonInvalid, err)
		}
		name, ok := token.(string)
		if !ok {
			return fmt.Errorf("%w: a member name that is not a string", ErrCanonicalJsonInvalid)
		}
		if seen[name] {
			return fmt.Errorf("%w: a member name twice", ErrCanonicalJsonInvalid)
		}
		seen[name] = true
		value := &bytes.Buffer{}
		if err := canonicalJsonValue(decoder, value, depth+1); err != nil {
			return err
		}
		members = append(members, &member{name: name, utf16: utf16.Encode([]rune(name)), value: value.Bytes()})
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("%w: %w", ErrCanonicalJsonInvalid, err)
	}
	slices.SortFunc(members, func(a *member, b *member) int {
		return slices.Compare(a.utf16, b.utf16)
	})
	out.WriteByte('{')
	for i, m := range members {
		if 0 < i {
			out.WriteByte(',')
		}
		canonicalJsonString(out, m.name)
		out.WriteByte(':')
		out.Write(m.value)
	}
	out.WriteByte('}')
	return nil
}

// Writes s as ECMAScript's JSON.stringify does (RFC 8785 §3.2.2.2): a quote and a backslash escaped, the five
// controls with short escapes by their short forms, every other control below 0x20 as \u00xx in lowercase hex, and
// everything else as its own UTF-8.
func canonicalJsonString(out *bytes.Buffer, s string) {
	out.WriteByte('"')
	for i := 0; i < len(s); i += 1 {
		c := s[i]
		switch c {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if c < 0x20 {
				out.WriteString(`\u00`)
				out.WriteByte("0123456789abcdef"[c>>4])
				out.WriteByte("0123456789abcdef"[c&0xf])
			} else {
				out.WriteByte(c)
			}
		}
	}
	out.WriteByte('"')
}

// A JSON number as ECMAScript's Number.prototype.toString writes the double nearest it (RFC 8785 §3.2.2.3):
// the shortest digits that read back as that double, in plain notation from 1e-6 below 1e21 and in exponent
// notation outside that range, with -0 as 0.
func canonicalJsonNumber(number json.Number) (string, error) {
	value, err := strconv.ParseFloat(string(number), 64)
	if err != nil || math.IsInf(value, 0) || math.IsNaN(value) {
		return "", fmt.Errorf("%w: a number beyond a double", ErrCanonicalJsonInvalid)
	}
	return EcmaScriptNumber(value), nil
}

// ECMAScript's Number.prototype.toString for a finite double (ES2015 §7.1.12.1), which RFC 8785 writes numbers by.
func EcmaScriptNumber(value float64) string {
	if value == 0 {
		return "0"
	}
	sign := ""
	if value < 0 {
		sign = "-"
		value = -value
	}
	// d.ddddde±x: the shortest digits that round trip, and the decimal exponent
	scientific := strconv.FormatFloat(value, 'e', -1, 64)
	mantissa, exponentText, _ := strings.Cut(scientific, "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	exponent, _ := strconv.Atoi(exponentText)
	// value = 0.digits x 10^n, with k digits
	k := len(digits)
	n := exponent + 1
	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits
	}
	exponentSign := "+"
	scientificExponent := n - 1
	if scientificExponent < 0 {
		exponentSign = "-"
		scientificExponent = -scientificExponent
	}
	exponentDigits := strconv.Itoa(scientificExponent)
	if k == 1 {
		return sign + digits + "e" + exponentSign + exponentDigits
	}
	return sign + digits[:1] + "." + digits[1:] + "e" + exponentSign + exponentDigits
}

// One command an admin token may run: its method, its path, and its body, JSON or none.
type AdminCommand struct {
	// Uppercase, as the request carries it.
	Method string
	// The request's path: it starts with "/" and has no query or fragment.
	Path string
	// The body as sent, JSON, or empty for a command with none.
	Body []byte
}

// Whether the command meets this file's rules: an uppercase method, a path of printable ASCII starting with "/"
// and holding no query, fragment or whitespace, and a body within its bound that is one JSON value or empty.
func (self *AdminCommand) Validate() error {
	if self.Method == "" || 16 < len(self.Method) {
		return fmt.Errorf("%w: the method", ErrAdminCommandInvalid)
	}
	for i := 0; i < len(self.Method); i += 1 {
		if c := self.Method[i]; c < 'A' || 'Z' < c {
			return fmt.Errorf("%w: the method is not uppercase letters", ErrAdminCommandInvalid)
		}
	}
	if !strings.HasPrefix(self.Path, "/") || adminCommandMaxPathByteCount < len(self.Path) {
		return fmt.Errorf("%w: the path", ErrAdminCommandInvalid)
	}
	for i := 0; i < len(self.Path); i += 1 {
		if c := self.Path[i]; c <= ' ' || '~' < c || c == '?' || c == '#' {
			return fmt.Errorf("%w: the path holds a query, a fragment or a byte outside printable ascii", ErrAdminCommandInvalid)
		}
	}
	if AdminCommandMaxBodyByteCount < len(self.Body) {
		return fmt.Errorf("%w: a %d byte body", ErrAdminCommandInvalid, len(self.Body))
	}
	if 0 < len(self.Body) {
		if _, err := CanonicalJson(self.Body); err != nil {
			return fmt.Errorf("%w: the body: %w", ErrAdminCommandInvalid, err)
		}
	}
	return nil
}

// The command's cmd claim: base64url(SHA-256(method || 0x00 || path || 0x00 || JCS(body))), unpadded, with zero
// bytes in JCS's place for a command with no body.
func (self *AdminCommand) Digest() (string, error) {
	if err := self.Validate(); err != nil {
		return "", err
	}
	canonicalBody := []byte{}
	if 0 < len(self.Body) {
		var err error
		if canonicalBody, err = CanonicalJson(self.Body); err != nil {
			return "", fmt.Errorf("%w: the body: %w", ErrAdminCommandInvalid, err)
		}
	}
	hash := sha256.New()
	hash.Write([]byte(self.Method))
	hash.Write([]byte{0})
	hash.Write([]byte(self.Path))
	hash.Write([]byte{0})
	hash.Write(canonicalBody)
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil)), nil
}

// The digest of method, path and body: AdminCommand.Digest.
func AdminCommandDigest(method string, path string, body []byte) (string, error) {
	return (&AdminCommand{Method: method, Path: path, Body: body}).Digest()
}

// The one authorization_details entry an ur-cli authorization request carries (RFC 9396).
type AdminCommandDetails struct {
	Type   string          `json:"type"`
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body,omitempty"`
	// What ur-cli shows in its terminal and the consent page shows beside the command.
	ConsentCode string `json:"consent_code"`
}

// The command the entry names.
func (self *AdminCommandDetails) Command() *AdminCommand {
	return &AdminCommand{Method: self.Method, Path: self.Path, Body: []byte(self.Body)}
}

// The authorization_details parameter for one command and its consent code: a JSON array of one entry.
func FormatAdminCommandDetails(command *AdminCommand, consentCode string) (string, error) {
	if err := command.Validate(); err != nil {
		return "", err
	}
	if err := ValidateAdminConsentCode(consentCode); err != nil {
		return "", err
	}
	details := &AdminCommandDetails{
		Type:        AdminCommandDetailsType,
		Method:      command.Method,
		Path:        command.Path,
		ConsentCode: consentCode,
	}
	if 0 < len(command.Body) {
		canonicalBody, err := CanonicalJson(command.Body)
		if err != nil {
			return "", fmt.Errorf("%w: the body: %w", ErrAdminCommandInvalid, err)
		}
		details.Body = canonicalBody
	}
	formatted, err := json.Marshal([]*AdminCommandDetails{details})
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

// Reads an authorization_details parameter that must name exactly one admin command: a JSON array of one entry
// of AdminCommandDetailsType, with no member this file does not know, a valid command and a consent code.
func ParseAdminCommandDetails(authorizationDetails string) (*AdminCommandDetails, error) {
	if AdminCommandMaxBodyByteCount+1024 < len(authorizationDetails) {
		return nil, fmt.Errorf("%w: authorization_details too large", ErrAdminCommandInvalid)
	}
	decoder := json.NewDecoder(strings.NewReader(authorizationDetails))
	decoder.DisallowUnknownFields()
	detailsList := []*AdminCommandDetails{}
	if err := decoder.Decode(&detailsList); err != nil {
		return nil, fmt.Errorf("%w: authorization_details does not parse", ErrAdminCommandInvalid)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: bytes after authorization_details", ErrAdminCommandInvalid)
	}
	if len(detailsList) != 1 || detailsList[0] == nil {
		return nil, fmt.Errorf("%w: authorization_details names %d entries, not one", ErrAdminCommandInvalid, len(detailsList))
	}
	details := detailsList[0]
	if details.Type != AdminCommandDetailsType {
		return nil, fmt.Errorf("%w: another authorization_details type", ErrAdminCommandInvalid)
	}
	if err := details.Command().Validate(); err != nil {
		return nil, err
	}
	if err := ValidateAdminConsentCode(details.ConsentCode); err != nil {
		return nil, err
	}
	return details, nil
}

// A new consent code from random, as ur-cli shows it: two groups of four from an alphabet with no look-alikes.
func NewAdminConsentCode(random io.Reader) (string, error) {
	code := make([]byte, 0, 2*adminConsentCodeHalfLength+1)
	// a draw past the largest multiple of the alphabet's size is drawn again, so no symbol is likelier
	limit := 256 - 256%len(adminConsentCodeAlphabet)
	draw := make([]byte, 1)
	for len(code) < 2*adminConsentCodeHalfLength+1 {
		if len(code) == adminConsentCodeHalfLength {
			code = append(code, '-')
			continue
		}
		if _, err := io.ReadFull(random, draw); err != nil {
			return "", err
		}
		if limit <= int(draw[0]) {
			continue
		}
		code = append(code, adminConsentCodeAlphabet[int(draw[0])%len(adminConsentCodeAlphabet)])
	}
	return string(code), nil
}

// Whether code is a consent code's form: two groups of four of the alphabet, a dash between.
func ValidateAdminConsentCode(code string) error {
	if len(code) != 2*adminConsentCodeHalfLength+1 || code[adminConsentCodeHalfLength] != '-' {
		return fmt.Errorf("%w: the consent code's form", ErrAdminCommandInvalid)
	}
	for i := 0; i < len(code); i += 1 {
		if i == adminConsentCodeHalfLength {
			continue
		}
		if !strings.ContainsRune(adminConsentCodeAlphabet, rune(code[i])) {
			return fmt.Errorf("%w: the consent code's alphabet", ErrAdminCommandInvalid)
		}
	}
	return nil
}

// RFC 7638's thumbprint of an Ed25519 key as a DPoP proof's jwk names it (RFC 8037 §2):
// base64url(SHA-256({"crv":"Ed25519","kty":"OKP","x":<x>})), unpadded. An authorization request's dpop_jkt and an
// admin token's cnf.jkt hold it, and server's session.DpopKeyThumbprint computes the same.
func DpopKeyThumbprint(publicKey ed25519.PublicKey) string {
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(publicKey) + `"}`
	hash := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// A DPoP key ur-cli makes for one admin token and keeps in its own process alone (§7.8, RFC 9449): its thumbprint
// is the authorization request's dpop_jkt, so the code redeems only with its proof, and the token's cnf.jkt, so the
// token works only with it. Erase zeroes it once the command has run. Not safe for concurrent use.
type AdminDpopKey struct {
	// DpopKeyThumbprint of the public key.
	Thumbprint string
	privateKey ed25519.PrivateKey
	header     []byte
	now        func() time.Time
	random     io.Reader
}

// A new key from random, its proofs' iat read from now.
func NewAdminDpopKey(random io.Reader, now func() time.Time) (*AdminDpopKey, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(random, seed); err != nil {
		return nil, err
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	testHookSecret("AdminDpopKey", privateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return &AdminDpopKey{
		Thumbprint: DpopKeyThumbprint(publicKey),
		privateKey: privateKey,
		header:     dpopHeader(publicKey),
		now:        now,
		random:     random,
	}, nil
}

// A proof of a request by method to requestUrl presenting token: htu the url with no query or fragment, and ath
// over token, the admin token at the api or the code at the token endpoint.
func (self *AdminDpopKey) Sign(method string, requestUrl string, token string) (string, error) {
	if self.privateKey == nil {
		return "", fmt.Errorf("%w: the key was erased", errDpopProof)
	}
	if !isDpopMethod(method) {
		return "", fmt.Errorf("%w: the method is not an uppercase token", errDpopProof)
	}
	htu, err := dpopHtu(requestUrl)
	if err != nil {
		return "", err
	}
	jtiBytes := make([]byte, dpopJtiByteCount)
	if _, err := io.ReadFull(self.random, jtiBytes); err != nil {
		return "", fmt.Errorf("%w: no jti: %w", errDpopProof, err)
	}
	claims := dpopClaims(dpopAth(token), method, htu, self.now().Unix(), base64.RawURLEncoding.EncodeToString(jtiBytes))
	return dpopSign(self.privateKey, self.header, claims), nil
}

// Zeroes the private key, after which Sign refuses.
func (self *AdminDpopKey) Erase() {
	clear(self.privateKey)
	self.privateKey = nil
}
