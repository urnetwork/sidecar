//go:build !ios_extension

// A team's member invite, client side (config_invite.go; TEAM-M6-04, §7.5, §8.5's invited clause): the string's two
// parts, the join MAC the inviting device checks, redaction and the request-body check, and FS-19's invite run on the
// test network.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A bearer as server's model writes one, for a fresh invite id and secret.
func testMemberInviteBearer(t testing.TB) (string, Id) {
	t.Helper()
	inviteId := NewId()
	secret := bytes.Repeat([]byte{7}, memberInviteSecretByteCount)
	return memberInvitePrefix + memberInviteEncoding.EncodeToString(inviteId.Bytes()) + "-" + memberInviteEncoding.EncodeToString(secret), inviteId
}

// A fragment of the test network's owner device at its tip.
func testMemberInviteFragment(t testing.TB, net *testConfigNet) *MemberInviteFragment {
	t.Helper()
	genesisSha256 := sha256.Sum256(net.signedGenesis)
	fragment, err := NewMemberInviteFragment(genesisSha256[:], net.log.Pin(), net.owner.sidecarId, net.owner.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	return fragment
}

// The string round-trips: the bearer, with or without its prefix, and the fragment's every field.
func TestMemberInviteStringRoundTrip(t *testing.T) {
	net := newTestConfigNet(t)
	bearer, inviteId := testMemberInviteBearer(t)
	fragment := testMemberInviteFragment(t, net)
	text, err := FormatMemberInvite(bearer, fragment)
	if err != nil {
		t.Fatal(err)
	}
	invite, err := ParseMemberInvite(text, nil)
	if err != nil {
		t.Fatal(err)
	}
	if invite.Bearer() != bearer || invite.InviteId() != inviteId {
		t.Fatalf("the bearer %q, id %s", invite.Bearer(), invite.InviteId())
	}
	parsed := invite.Fragment()
	if !bytes.Equal(parsed.GenesisSha256, fragment.GenesisSha256) || parsed.PinVersion != fragment.PinVersion ||
		!bytes.Equal(parsed.PinChain, fragment.PinChain) || parsed.InviterSidecarId != fragment.InviterSidecarId ||
		!bytes.Equal(parsed.InviterIdentityPublicKey, fragment.InviterIdentityPublicKey) || !bytes.Equal(parsed.JoinSecret, fragment.JoinSecret) {
		t.Fatal("the fragment did not round-trip")
	}
	if !net.log.State().OnChain(parsed.Pin()) {
		t.Error("the fragment's pin is not on the network's chain")
	}
	alone, err := ParseMemberInvite(strings.TrimPrefix(bearer, memberInvitePrefix), nil)
	if err != nil || alone.Bearer() != bearer || alone.Fragment() != nil {
		t.Fatalf("a bare bearer: %v", err)
	}
	if printed := invite.String() + invite.GoString() + parsed.String(); strings.Contains(printed, bearer) {
		t.Error("printing an invite shows its bearer")
	}
	invite.Erase()
	if invite.Bearer() != "" || !bytes.Equal(parsed.JoinSecret, make([]byte, memberInviteSecretByteCount)) {
		t.Error("Erase kept a secret")
	}
}

// Anything that is not one well-formed bearer and at most one well-formed fragment is refused, and no error repeats
// any of the text.
func TestMemberInviteMalformedStringsAreRefused(t *testing.T) {
	net := newTestConfigNet(t)
	bearer, _ := testMemberInviteBearer(t)
	fragment := testMemberInviteFragment(t, net)
	text, err := FormatMemberInvite(bearer, fragment)
	if err != nil {
		t.Fatal(err)
	}
	fragmentText := text[strings.Index(text, memberInviteFragmentSeparator)+1:]
	for name, malformed := range map[string]string{
		"empty":                  "",
		"no secret":              memberInvitePrefix + "abc",
		"an auth key":            "ur-authkey-" + strings.TrimPrefix(bearer, memberInvitePrefix),
		"a short fragment":       bearer + "#" + fragmentText[:20],
		"a padded fragment":      bearer + "#" + fragmentText + "==",
		"two fragments":          text + "#" + fragmentText,
		"an unknown version":     bearer + "#" + "Ag" + fragmentText[2:],
		"an upper-case bearer":   strings.ToUpper(bearer),
		"too long":               text + strings.Repeat("a", 2048),
		"a fragment with no key": bearer + "#",
	} {
		_, err := ParseMemberInvite(malformed, nil)
		if !errors.Is(err, ErrMemberInviteMalformed) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if 8 < len(malformed) && strings.Contains(err.Error(), malformed[len(malformed)-8:]) {
			t.Errorf("%s: the error repeats the text", name)
		}
	}
}

// The join MAC: what the invitee's first device sends verifies at the inviting device under the invite's secret, and
// nothing else does; an ephemeral or read_only join gets no MAC and is refused, leaving the invite unspent.
func TestMemberInviteJoinMac(t *testing.T) {
	net := newTestConfigNet(t)
	fragment := testMemberInviteFragment(t, net)
	device := net.device("invited laptop", testConfigId("invited member"))
	join := &MemberInviteJoin{
		NetworkId:         net.networkId,
		InviteId:          NewId(),
		SidecarId:         device.sidecarId,
		IdentityPublicKey: device.publicKey(),
		MemberId:          device.memberId,
	}
	mac, err := fragment.JoinMac(join)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMemberInviteJoin(fragment, join, mac); err != nil {
		t.Fatalf("the join: %v", err)
	}

	other := testMemberInviteFragment(t, net)
	if err := VerifyMemberInviteJoin(other, join, mac); !errors.Is(err, ErrMemberInviteJoinRefused) {
		t.Errorf("another invite's secret: %v", err)
	}
	for name, edit := range map[string]func(join *MemberInviteJoin){
		"another network": func(join *MemberInviteJoin) { join.NetworkId = NewId() },
		"another invite":  func(join *MemberInviteJoin) { join.InviteId = NewId() },
		"another device":  func(join *MemberInviteJoin) { join.SidecarId = NewId() },
		"another key":     func(join *MemberInviteJoin) { join.IdentityPublicKey = net.owner.publicKey() },
		"another member":  func(join *MemberInviteJoin) { join.MemberId = NewId() },
		"no device":       func(join *MemberInviteJoin) { join.SidecarId = Id{} },
	} {
		edited := *join
		edit(&edited)
		if err := VerifyMemberInviteJoin(fragment, &edited, mac); err == nil {
			t.Errorf("%s verifies", name)
		}
	}
	for name, edit := range map[string]func(join *MemberInviteJoin){
		"an ephemeral join": func(join *MemberInviteJoin) { join.Ephemeral = true },
		"a read_only join":  func(join *MemberInviteJoin) { join.ReadOnly = true },
	} {
		edited := *join
		edit(&edited)
		if _, err := fragment.JoinMac(&edited); !errors.Is(err, ErrMemberInviteJoinEphemeral) {
			t.Errorf("%s gets a MAC: %v", name, err)
		}
		if err := VerifyMemberInviteJoin(fragment, &edited, mac); !errors.Is(err, ErrMemberInviteJoinEphemeral) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Redaction covers both parts wherever the string prints, and a request body holding the fragment's prefix in any of
// its spellings is refused before it is sent; the bearer alone passes. The canary: the accept's body, built from the
// parsed invite, holds none of the fragment.
func TestMemberInviteFragmentNeverInARequest(t *testing.T) {
	net := newTestConfigNet(t)
	bearer, _ := testMemberInviteBearer(t)
	text, err := FormatMemberInvite(bearer, testMemberInviteFragment(t, net))
	if err != nil {
		t.Fatal(err)
	}
	fragmentText := text[strings.Index(text, memberInviteFragmentSeparator)+1:]
	line := "joining with " + text + " now"
	redacted := RedactMemberInvite(line)
	if strings.Contains(redacted, fragmentText) || strings.Contains(redacted, strings.TrimPrefix(bearer, memberInvitePrefix)) ||
		redacted != "joining with "+memberInvitePrefix+memberInviteRedacted+" now" {
		t.Fatalf("redacted %q", redacted)
	}
	if RedactMemberInvite(strings.TrimPrefix(bearer, memberInvitePrefix)) != memberInviteRedacted {
		t.Error("a bare bearer is not covered")
	}
	if RedactMemberInvite("a fragment alone #"+fragmentText) != memberInviteRedacted {
		t.Error("a fragment with no prefix is not covered")
	}

	invite, err := ParseMemberInvite(text, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"invite_bearer":"` + invite.Bearer() + `"}`)
	if err := CheckMemberInviteBody(body); err != nil || bytes.Contains(body, []byte(fragmentText)) {
		t.Fatalf("the accept's body: %v", err)
	}
	for _, refused := range []string{`{"invite_bearer":"` + text + `"}`, `{"x":"#"}`, "invite_bearer=a%23b"} {
		if err := CheckMemberInviteBody([]byte(refused)); !errors.Is(err, ErrMemberInviteFragmentInBody) {
			t.Errorf("%q: %v", refused, err)
		}
	}
}

// FS-19's invite run (M6): the inviting device refuses the member's ephemeral device's join, so the invite stays
// unspent and the device carries no invite; the member's next untagged device joins, the inviting device admits it
// with SIDECAR_CAPABILITY_INVITED, and §8.5's invited clause consents it; a device admitted under the member without
// the invite is not.
func TestMemberInviteConsentsTheNextUntaggedDevice(t *testing.T) {
	net := newTestConfigNet(t)
	memberId := testConfigId("invited member")
	net.admitMember(net.owner, memberId, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	fragment := testMemberInviteFragment(t, net)
	inviteId := NewId()
	joinOf := func(device testConfigDevice, ephemeral bool) *MemberInviteJoin {
		return &MemberInviteJoin{
			NetworkId:         net.networkId,
			InviteId:          inviteId,
			SidecarId:         device.sidecarId,
			IdentityPublicKey: device.publicKey(),
			MemberId:          memberId,
			Ephemeral:         ephemeral,
		}
	}

	ephemeral := net.device("invited ephemeral", memberId)
	if _, err := fragment.JoinMac(joinOf(ephemeral, true)); !errors.Is(err, ErrMemberInviteJoinEphemeral) {
		t.Fatalf("an ephemeral join: %v", err)
	}
	if err := VerifyMemberInviteJoin(fragment, joinOf(ephemeral, true), nil); !errors.Is(err, ErrMemberInviteJoinEphemeral) {
		t.Fatalf("the inviting device took an ephemeral join: %v", err)
	}

	laptop := net.device("invited laptop", memberId)
	mac, err := fragment.JoinMac(joinOf(laptop, false))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMemberInviteJoin(fragment, joinOf(laptop, false), mac); err != nil {
		t.Fatalf("the untagged join: %v", err)
	}
	net.admitDevice(net.owner, laptop, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	plain := net.device("admitted without the invite", memberId)
	net.admitDevice(net.owner, plain, 0)

	acl, err := net.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	if !acl.ConsentedFor(laptop.sidecarId, memberId) {
		t.Error("the invited device is not consented")
	}
	if acl.Consented(plain.sidecarId) {
		t.Error("a device admitted without the invite is consented")
	}
	net.everyReaderAgrees()
}
