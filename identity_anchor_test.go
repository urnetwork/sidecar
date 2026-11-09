package sidecar

// CORE-M2-01's internals: the anchor's record and its refusals, enrollment refusing a malformed anchor before
// anything is sent, and a pre-approved key's self-admission signed by the Delegation's key with only the reader seed
// kept.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// An anchor's record comes back as it went in, and one that is not one is a failure, never absence (D-CORE-15).
func TestAnchorRecordRoundTrip(t *testing.T) {
	genesis := sha256.Sum256([]byte("genesis"))
	chain := sha256.Sum256([]byte("head"))
	for _, anchor := range []*SidecarAnchor{
		{GenesisSha256: genesis[:], Head: &bridge.AuthPin{Version: 4, Chain: chain[:]}, Source: SidecarAnchorInvite},
		{GenesisSha256: genesis[:], Source: SidecarAnchorFirstUse},
	} {
		record, err := anchor.encode()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeSidecarAnchor(record)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Source != anchor.Source || !bytes.Equal(decoded.GenesisSha256, anchor.GenesisSha256) ||
			(anchor.Head == nil) != (decoded.Head == nil) || (anchor.Head != nil && !proto.Equal(anchor.Head, decoded.Head)) {
			t.Errorf("%+v came back %+v", anchor, decoded)
		}
	}
	for _, record := range [][]byte{nil, {1}, bytes.Repeat([]byte{0xff}, sidecarAnchorRecordByteCount)} {
		if _, err := decodeSidecarAnchor(record); !errors.Is(err, ErrSidecarStoreFailed) {
			t.Errorf("%x: %v", record, err)
		}
	}
	for _, anchor := range []*SidecarAnchor{
		{GenesisSha256: genesis[:31], Source: SidecarAnchorInvite},
		{GenesisSha256: genesis[:], Head: &bridge.AuthPin{Version: 0, Chain: chain[:]}, Source: SidecarAnchorInvite},
		{GenesisSha256: genesis[:], Head: &bridge.AuthPin{Version: 3, Chain: chain[:5]}, Source: SidecarAnchorInvite},
		{GenesisSha256: genesis[:], Source: 9},
	} {
		if _, err := anchor.encode(); !errors.Is(err, ErrSidecarAnchorMalformed) {
			t.Errorf("%+v: %v", anchor, err)
		}
	}
}

// A recorded anchor is the sidecar's for its life: the same bytes again pass, another anchor is refused.
func TestAnchorIsRecordedOnce(t *testing.T) {
	_, secrets := newIdentityTestSecrets(t, NewId())
	genesis := sha256.Sum256([]byte("genesis"))
	anchor := &SidecarAnchor{GenesisSha256: genesis[:], Source: SidecarAnchorInvite}
	if err := persistSidecarAnchor(secrets, anchor); err != nil {
		t.Fatal(err)
	}
	if err := persistSidecarAnchor(secrets, anchor); err != nil {
		t.Errorf("the same anchor again: %v", err)
	}
	other := sha256.Sum256([]byte("other"))
	if err := persistSidecarAnchor(secrets, &SidecarAnchor{GenesisSha256: other[:], Source: SidecarAnchorInvite}); !errors.Is(err, ErrSidecarAnchorMismatch) {
		t.Errorf("another anchor: %v", err)
	}
}

// A bundle, the Delegation's row naming it, and an identity, for a self-admission.
func testDelegationAdmitArgs(t *testing.T) (*sidecarDelegationAdmitArgs, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	readerSeed := make([]byte, 32)
	rand.Read(readerSeed)
	bundle := &AuthKeyBundle{
		DelegationId:          NewId(),
		DelegationSigningSeed: bytes.Clone(privateKey.Seed()),
		DelegationReaderSeed:  readerSeed,
		TagIds:                [][]byte{NewId().Bytes(), NewId().Bytes()},
	}
	identityKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chain := sha256.Sum256([]byte("at"))
	return &sidecarDelegationAdmitArgs{
		networkId: NewId(),
		identity:  &SidecarIdentity{SidecarId: NewId(), IdentityPublicKey: identityKey},
		bundle:    bundle,
		delegation: &bridge.DelegationRow{
			DelegationId: bundle.DelegationId.Bytes(),
			NotAfter:     1_900_000_000_000,
		},
		at:                  &bridge.AuthPin{Version: 12, Chain: chain[:]},
		statementNotAfterMs: 1_800_000_000_000,
		random:              rand.Reader,
	}, publicKey
}

// §5.6, §7.8, C-03: the daemon signs its own SidecarAdmit with the Delegation's key, carrying exactly its tags and its
// not_after, and keeps only the reader seed: the signing seed is erased whatever happens, and the bundle's reader
// seed is erased once kept.
func TestDelegationKeepsOnlyReaderSeed(t *testing.T) {
	args, delegationKey := testDelegationAdmitArgs(t)
	readerSeed := bytes.Clone(args.bundle.DelegationReaderSeed)
	signed, err := newDelegationSidecarAdmit(args)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(args.bundle.DelegationSigningSeed, make([]byte, 32)) {
		t.Error("the signing seed was not erased")
	}
	if err := bridge.VerifySigned(signed, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_SIDECAR_ADMIT, bridge.SignedKeyAlgEd25519, delegationKey); err != nil {
		t.Fatalf("the Delegation's signature: %v", err)
	}
	keyId := sha256.Sum256(delegationKey)
	if !bytes.Equal(signed.GetSignerId(), args.bundle.DelegationId.Bytes()) || !bytes.Equal(signed.GetKeyId(), keyId[:]) {
		t.Error("the signer is not the Delegation's")
	}
	admit := &protocol.SidecarAdmit{}
	if err := proto.Unmarshal(signed.GetBody(), admit); err != nil {
		t.Fatal(err)
	}
	if len(admit.GetTagIds()) != 2 || !bytes.Equal(admit.GetTagIds()[0], args.bundle.TagIds[0]) || len(admit.GetMemberId()) != 0 ||
		admit.GetNotAfter() != args.delegation.GetNotAfter() || !bytes.Equal(admit.GetSidecarId(), args.identity.SidecarId.Bytes()) ||
		admit.GetHeader().GetAt().GetVersion() != 12 || len(admit.GetHeader().GetNonce()) != configNonceByteCount {
		t.Errorf("the admission: %+v", admit)
	}

	_, secrets := newIdentityTestSecrets(t, args.networkId)
	if err := keepDelegationReaderKey(secrets, args.bundle); err != nil {
		t.Fatal(err)
	}
	kept, err := secrets.Get(sidecarDelegationReaderKeyRecordName)
	if err != nil || !bytes.Equal(kept, readerSeed) {
		t.Errorf("the reader seed kept: %v", err)
	}
	if !bytes.Equal(args.bundle.DelegationReaderSeed, make([]byte, 32)) {
		t.Error("the bundle's reader seed was not erased")
	}
	names, err := secrets.List("")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		value, _ := secrets.Get(name)
		if bytes.Contains(value, delegationKey) {
			t.Errorf("%s holds the Delegation's key", name)
		}
	}
}

// An ephemeral self-admission carries no not_after; a Delegation that ended, one the row does not name, or one with
// no not_after signs nothing, and its seed is erased all the same.
func TestDelegationAdmitRefusals(t *testing.T) {
	args, _ := testDelegationAdmitArgs(t)
	args.ephemeral = true
	signed, err := newDelegationSidecarAdmit(args)
	if err != nil {
		t.Fatal(err)
	}
	admit := &protocol.SidecarAdmit{}
	proto.Unmarshal(signed.GetBody(), admit)
	if admit.GetNotAfter() != 0 || !admit.GetEphemeral() {
		t.Errorf("ephemeral: %+v", admit)
	}

	for name, edit := range map[string]func(args *sidecarDelegationAdmitArgs){
		"ended":      func(args *sidecarDelegationAdmitArgs) { args.delegation.EndedAt = 3 },
		"another id": func(args *sidecarDelegationAdmitArgs) { args.delegation.DelegationId = NewId().Bytes() },
		"a 32-byte id": func(args *sidecarDelegationAdmitArgs) {
			// §10.5's d is SHA-256(Signed Delegation); a bundle's 16-byte id matches no such row
			id := sha256.Sum256(args.bundle.DelegationId.Bytes())
			args.delegation.DelegationId = id[:]
		},
		"no not_after": func(args *sidecarDelegationAdmitArgs) { args.delegation.NotAfter = 0 },
		"no tags":      func(args *sidecarDelegationAdmitArgs) { args.bundle.TagIds = nil },
	} {
		args, _ := testDelegationAdmitArgs(t)
		edit(args)
		if _, err := newDelegationSidecarAdmit(args); !errors.Is(err, ErrSidecarDelegationAdmit) {
			t.Errorf("%s: %v", name, err)
		}
		if !bytes.Equal(args.bundle.DelegationSigningSeed, make([]byte, 32)) {
			t.Errorf("%s: the signing seed was not erased", name)
		}
	}
}
