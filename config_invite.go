//go:build !ios_extension

// A team's member invite, client side (§7.5, TEAM-M6-04; §8.5's invited clause, QD-072):
//
//	ur-invite-<invite_id>-<secret>[#<base64url(fragment)>]
//
// ur-invite-<invite_id>-<secret> is the bearer: what POST /network/member-invite answers and POST
// /network/member-invite-accept takes, <invite_id> 16 bytes and <secret> 32 random bytes, each lowercase RFC 4648
// base32 with no padding, as server's model reads it. The #<fragment> is client-only, like an auth key's bundle: the
// inviting device appends it, and no request, log or MCP result carries it. It holds what the invitee's first device
// trusts and proves with:
//
//	genesis   A_0 = SHA-256(Signed Genesis), the anchor the invitee's device refuses any other genesis by (§7.9)
//	pin       the authorization pin (n, A_n) the inviting device stood at; the device refuses a lower one
//	inviter   the inviting device's sidecar_id and Ed25519 identity key, which the invitee's device checks the
//	          admitting statements against
//	join      a one-time secret, 32 random bytes, that MACs the join request of the invitee's first device; the
//	          inviting device, an admin's, admits that device with SIDECAR_CAPABILITY_INVITED only once the MAC
//	          verifies, and refuses an ephemeral or read_only join, so the invite's consent goes to the member's
//	          first untagged device and never to an ephemeral one
//
// The fragment's bytes, version 1, 153 B, every field fixed-width so nothing is optional: u8 version || genesis_sha256
// (32) || u64be pin version || pin chain (32) || inviter sidecar_id (16) || inviter identity key (32) || join secret
// (32). A join's MAC is HMAC-SHA256(join secret, "urnetwork-sidecar-v1/invite-join" || 0x00 || network_id (16) ||
// invite_id (16) || sidecar_id (16) || identity key (32) || member_id (16)). The inviting device keeps the join secret
// until it admits under the invite; erasing its copy protects only it.
//
// RedactMemberInvite covers both parts wherever the string may print, and CheckMemberInviteBody refuses a request
// body that holds the fragment's prefix, as an auth key's bundle is kept out of requests. Errors never repeat any of
// the text they refuse. Not on the ios_extension leg, whose forwarding role joins no team.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The invite string's format values (§7.5).
const (
	memberInvitePrefix = "ur-invite-"
	// Starts the client-only fragment: its prefix, which no request body may hold.
	memberInviteFragmentSeparator = "#"
	// The fragment's format version.
	memberInviteFragmentVersion = 1
	// The bearer's secret and the fragment's join secret: 32 random bytes each.
	memberInviteSecretByteCount = 32
	// The fragment's fixed-width bytes: version, genesis, pin, inviter, join secret.
	memberInviteFragmentByteCount = 1 + sha256.Size + 8 + sha256.Size + 16 + ed25519.PublicKeySize + memberInviteSecretByteCount
	// The domain of a join's MAC.
	memberInviteJoinDomain = "urnetwork-sidecar-v1/invite-join"
	// What RedactMemberInvite shows in place of what it covers.
	memberInviteRedacted = "[redacted]"
)

// Lowercase RFC 4648 base32 without padding, as server writes an invite's id and secret.
var memberInviteEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// Tunables of invite parsing.
type MemberInviteSettings struct {
	// The longest string ParseMemberInvite reads: 1 KiB, room for the bearer and the fragment many times over, so
	// the bound only stops a decoder from reading garbage whole.
	MaxByteCount int
}

// The format's bounds.
func DefaultMemberInviteSettings() *MemberInviteSettings {
	return &MemberInviteSettings{
		MaxByteCount: 1024,
	}
}

var (
	// The string is not a member invite, or its fragment does not decode. Nothing of the string is in the error.
	ErrMemberInviteMalformed = errors.New("not a member invite")
	// A request body holding the fragment's prefix: refused before anything is sent (§7.5).
	ErrMemberInviteFragmentInBody = errors.New("a request body holds a member invite's client-only fragment")
	// A join whose MAC does not verify under the invite's join secret, or that names no device.
	ErrMemberInviteJoinRefused = errors.New("the join does not verify under the invite")
	// An ephemeral or read_only device's join, which the invite never admits: it stays unspent (§7.5, §8.5).
	ErrMemberInviteJoinEphemeral = errors.New("an ephemeral or read_only device does not join from an invite")
)

// A member invite as ParseMemberInvite split it: the bearer api takes, and the client-only fragment. Printing one
// shows neither.
type MemberInvite struct {
	bearer   string
	inviteId Id
	fragment *MemberInviteFragment
}

// ur-invite-<invite_id>-<secret>, the only part of the invite any request carries: a credential for joining, it goes
// to POST /network/member-invite-accept and nowhere else (I-7).
func (self *MemberInvite) Bearer() string {
	return self.bearer
}

// The invite's id, which the join MAC names.
func (self *MemberInvite) InviteId() Id {
	return self.inviteId
}

// The client-only fragment, nil for a bearer given alone.
func (self *MemberInvite) Fragment() *MemberInviteFragment {
	return self.fragment
}

// Drops the bearer and zeroes the fragment's join secret, once the invite is used.
func (self *MemberInvite) Erase() {
	self.bearer = ""
	if self.fragment != nil {
		self.fragment.Erase()
	}
}

// Says what it is and nothing it holds.
func (self *MemberInvite) String() string {
	if self.fragment != nil {
		return "MemberInvite{fragment}"
	}
	return "MemberInvite{}"
}

// As String, for %#v.
func (self *MemberInvite) GoString() string {
	return self.String()
}

// The fragment an inviting device appends (see the file header). The join secret is a secret: a printed fragment
// shows none of it.
type MemberInviteFragment struct {
	// A_0 = SHA-256(Signed Genesis).
	GenesisSha256 []byte
	// The authorization pin (n, A_n) the inviting device stood at.
	PinVersion uint64
	PinChain   []byte
	// The inviting device and its Ed25519 identity key.
	InviterSidecarId         Id
	InviterIdentityPublicKey []byte
	// The one-time secret that MACs the invitee's first device's join request.
	JoinSecret []byte
}

// Zeroes the join secret.
func (self *MemberInviteFragment) Erase() {
	clear(self.JoinSecret)
}

// Says what it is and nothing it holds.
func (self *MemberInviteFragment) String() string {
	return "MemberInviteFragment{}"
}

// As String, for %#v.
func (self *MemberInviteFragment) GoString() string {
	return self.String()
}

// The authorization pin the fragment names.
func (self *MemberInviteFragment) Pin() *bridge.AuthPin {
	return &bridge.AuthPin{Version: self.PinVersion, Chain: bytes.Clone(self.PinChain)}
}

// A fragment the inviting device makes for an invite: the network's genesis hash, the pin it stands at, itself and
// its identity key, and a fresh join secret, which reaches testHookSecret as it is drawn.
func NewMemberInviteFragment(genesisSha256 []byte, pin *bridge.AuthPin, inviterSidecarId Id, inviterIdentityPublicKey []byte) (*MemberInviteFragment, error) {
	if len(genesisSha256) != sha256.Size || pin == nil || pin.GetVersion() < 1 || len(pin.GetChain()) != sha256.Size ||
		inviterSidecarId == (Id{}) || len(inviterIdentityPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: a fragment needs a genesis, a pin past 0 and an inviter", ErrMemberInviteMalformed)
	}
	joinSecret := make([]byte, memberInviteSecretByteCount)
	// never fails: since Go 1.24 a broken system generator crashes the program instead
	cryptorand.Read(joinSecret)
	testHookSecret("invite_join_secret", joinSecret)
	return &MemberInviteFragment{
		GenesisSha256:            bytes.Clone(genesisSha256),
		PinVersion:               pin.GetVersion(),
		PinChain:                 bytes.Clone(pin.GetChain()),
		InviterSidecarId:         inviterSidecarId,
		InviterIdentityPublicKey: bytes.Clone(inviterIdentityPublicKey),
		JoinSecret:               joinSecret,
	}, nil
}

// The fragment's version-1 bytes.
func (self *MemberInviteFragment) encode() ([]byte, error) {
	if len(self.GenesisSha256) != sha256.Size || self.PinVersion < 1 || len(self.PinChain) != sha256.Size ||
		self.InviterSidecarId == (Id{}) || len(self.InviterIdentityPublicKey) != ed25519.PublicKeySize ||
		len(self.JoinSecret) != memberInviteSecretByteCount {
		return nil, fmt.Errorf("%w: a fragment of the wrong widths", ErrMemberInviteMalformed)
	}
	encoded := make([]byte, 0, memberInviteFragmentByteCount)
	encoded = append(encoded, memberInviteFragmentVersion)
	encoded = append(encoded, self.GenesisSha256...)
	encoded = binary.BigEndian.AppendUint64(encoded, self.PinVersion)
	encoded = append(encoded, self.PinChain...)
	encoded = append(encoded, self.InviterSidecarId.Bytes()...)
	encoded = append(encoded, self.InviterIdentityPublicKey...)
	encoded = append(encoded, self.JoinSecret...)
	return encoded, nil
}

// A fragment from its text: canonical unpadded base64url of exactly version 1's bytes.
func decodeMemberInviteFragment(text string) (*MemberInviteFragment, error) {
	encoded, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil || base64.RawURLEncoding.EncodeToString(encoded) != text || len(encoded) != memberInviteFragmentByteCount ||
		encoded[0] != memberInviteFragmentVersion {
		return nil, ErrMemberInviteMalformed
	}
	defer clear(encoded)
	at := 1
	take := func(count int) []byte {
		taken := bytes.Clone(encoded[at : at+count])
		at += count
		return taken
	}
	fragment := &MemberInviteFragment{GenesisSha256: take(sha256.Size)}
	fragment.PinVersion = binary.BigEndian.Uint64(take(8))
	fragment.PinChain = take(sha256.Size)
	inviterSidecarId, err := IdFromBytes(take(16))
	if err != nil || inviterSidecarId == (Id{}) || fragment.PinVersion < 1 {
		return nil, ErrMemberInviteMalformed
	}
	fragment.InviterSidecarId = inviterSidecarId
	fragment.InviterIdentityPublicKey = take(ed25519.PublicKeySize)
	fragment.JoinSecret = take(memberInviteSecretByteCount)
	testHookSecret("invite_join_secret", fragment.JoinSecret)
	return fragment, nil
}

// The canonical bearer of text, given with or without its prefix, and the invite's id.
func parseMemberInviteBearer(text string) (string, Id, error) {
	idText, secretText, found := strings.Cut(strings.TrimPrefix(text, memberInvitePrefix), "-")
	if !found {
		return "", Id{}, ErrMemberInviteMalformed
	}
	idBytes, idErr := memberInviteEncoding.DecodeString(idText)
	secret, secretErr := memberInviteEncoding.DecodeString(secretText)
	defer clear(secret)
	if idErr != nil || secretErr != nil || len(idBytes) != len(Id{}) || len(secret) != memberInviteSecretByteCount ||
		memberInviteEncoding.EncodeToString(idBytes) != idText || memberInviteEncoding.EncodeToString(secret) != secretText {
		return "", Id{}, ErrMemberInviteMalformed
	}
	inviteId, err := IdFromBytes(idBytes)
	if err != nil || inviteId == (Id{}) {
		return "", Id{}, ErrMemberInviteMalformed
	}
	return memberInvitePrefix + idText + "-" + secretText, inviteId, nil
}

// Splits the string a person received into its bearer and, when there is one, its client-only fragment, before
// anything else reads it: the bearer may be given with or without its ur-invite- prefix, and Bearer answers it with
// the prefix. Anything that is not exactly one well-formed part each side of a # is ErrMemberInviteMalformed, which
// holds none of the text. nil settings are the defaults. The bearer and the join secret reach testHookSecret as they
// are decoded.
func ParseMemberInvite(text string, settings *MemberInviteSettings) (*MemberInvite, error) {
	if settings == nil {
		settings = DefaultMemberInviteSettings()
	}
	if settings.MaxByteCount < len(text) {
		return nil, ErrMemberInviteMalformed
	}
	bearerText, fragmentText, hasFragment := strings.Cut(strings.TrimSpace(text), memberInviteFragmentSeparator)
	bearer, inviteId, err := parseMemberInviteBearer(bearerText)
	if err != nil {
		return nil, err
	}
	testHookSecret("member_invite", []byte(bearer))
	invite := &MemberInvite{bearer: bearer, inviteId: inviteId}
	if !hasFragment {
		return invite, nil
	}
	fragment, err := decodeMemberInviteFragment(fragmentText)
	if err != nil {
		return nil, err
	}
	invite.fragment = fragment
	return invite, nil
}

// The string a person is given for bearer and fragment, the reverse of ParseMemberInvite. The inviting device builds
// it once, to show or send to the invitee, so it is a secret wherever it goes.
func FormatMemberInvite(bearer string, fragment *MemberInviteFragment) (string, error) {
	canonical, _, err := parseMemberInviteBearer(bearer)
	if err != nil {
		return "", err
	}
	if fragment == nil {
		return canonical, nil
	}
	encoded, err := fragment.encode()
	if err != nil {
		return "", err
	}
	defer clear(encoded)
	return canonical + memberInviteFragmentSeparator + base64.RawURLEncoding.EncodeToString(encoded), nil
}

// What the invitee's first device asks to be admitted as, which its join MAC covers.
type MemberInviteJoin struct {
	NetworkId Id
	InviteId  Id
	// The joining device.
	SidecarId         Id
	IdentityPublicKey []byte
	// The member it joins as, the invitee's membership api made at the invite's accept.
	MemberId Id
	// The admission it asks for: an ephemeral or read_only one never joins from an invite.
	Ephemeral bool
	ReadOnly  bool
}

// The bytes a join's MAC covers, false for a join that names no device or member.
func memberInviteJoinBytes(join *MemberInviteJoin) ([]byte, bool) {
	if join == nil || join.NetworkId == (Id{}) || join.InviteId == (Id{}) || join.SidecarId == (Id{}) || join.MemberId == (Id{}) ||
		len(join.IdentityPublicKey) != ed25519.PublicKeySize {
		return nil, false
	}
	message := make([]byte, 0, len(memberInviteJoinDomain)+1+16*4+ed25519.PublicKeySize)
	message = append(message, memberInviteJoinDomain...)
	message = append(message, 0)
	message = append(message, join.NetworkId.Bytes()...)
	message = append(message, join.InviteId.Bytes()...)
	message = append(message, join.SidecarId.Bytes()...)
	message = append(message, join.IdentityPublicKey...)
	message = append(message, join.MemberId.Bytes()...)
	return message, true
}

// The MAC the invitee's first device sends with its join request. An ephemeral or read_only join gets none: the
// invite never admits one.
func (self *MemberInviteFragment) JoinMac(join *MemberInviteJoin) ([]byte, error) {
	if join != nil && (join.Ephemeral || join.ReadOnly) {
		return nil, ErrMemberInviteJoinEphemeral
	}
	message, ok := memberInviteJoinBytes(join)
	if !ok || len(self.JoinSecret) != memberInviteSecretByteCount {
		return nil, ErrMemberInviteJoinRefused
	}
	mac := hmac.New(sha256.New, self.JoinSecret)
	mac.Write(message)
	return mac.Sum(nil), nil
}

// What the inviting device checks before it admits the joining device with SIDECAR_CAPABILITY_INVITED (QD-072): the
// join is neither ephemeral nor read_only, and its MAC verifies under the invite's join secret. A refusal leaves the
// invite unspent.
func VerifyMemberInviteJoin(fragment *MemberInviteFragment, join *MemberInviteJoin, joinMac []byte) error {
	if join != nil && (join.Ephemeral || join.ReadOnly) {
		return ErrMemberInviteJoinEphemeral
	}
	if fragment == nil {
		return ErrMemberInviteJoinRefused
	}
	want, err := fragment.JoinMac(join)
	if err != nil {
		return err
	}
	if !hmac.Equal(want, joinMac) {
		return ErrMemberInviteJoinRefused
	}
	return nil
}

// text with every member invite in it covered, bearer and fragment both, as RedactAuthKey covers an auth key: an
// invite here is ur-invite- and what follows it up to the next character no invite holds, # and its fragment
// included; it becomes ur-invite-[redacted]. A text that is a bare bearer, or holds a # no ur-invite- precedes, is
// covered whole.
func RedactMemberInvite(text string) string {
	var out strings.Builder
	rest := text
	found := false
	for {
		at := strings.Index(rest, memberInvitePrefix)
		if at < 0 {
			break
		}
		found = true
		out.WriteString(rest[:at])
		out.WriteString(memberInvitePrefix + memberInviteRedacted)
		rest = rest[at+len(memberInvitePrefix):]
		end := 0
		for end < len(rest) && isAuthKeyCharacter(rest[end]) {
			end += 1
		}
		rest = rest[end:]
	}
	out.WriteString(rest)
	redacted := out.String()
	if strings.Contains(redacted, memberInviteFragmentSeparator) {
		// a fragment whose prefix went missing, or a bearer pasted beside its fragment
		return memberInviteRedacted
	}
	if !found {
		if _, _, err := parseMemberInviteBearer(strings.TrimSpace(text)); err == nil {
			return memberInviteRedacted
		}
	}
	return redacted
}

// Refuses a request body that holds the fragment's prefix, #, written as itself, as JSON's # or as a form's
// %23, before anything is sent, as CheckAuthKeyBody does for a bundle. Every accept body passes through here, and
// nothing of the body is in the error.
func CheckMemberInviteBody(body []byte) error {
	if CheckAuthKeyBody(body) != nil {
		return ErrMemberInviteFragmentInBody
	}
	return nil
}
