//go:build !ios_extension

// A Signed EvsReseed (§11.6, §11.13's re-seed row, §19.10; D-EVS-17): after a site loss, where every surviving copy of
// a ref ends below a reader's pin, a repo admin signs {repo, ref, version, C_v, incident} over the re-seeded head, and
// a reader that verifies it accepts the shorter history, shown as a loss (EvsVerifier.AcceptReseed). evs keeps the
// statement at reseed/<repo>/<ref> and serves it with the head (QD-725); it holds only what evs-29's row lists.
//
// The statement is a §6 Signed of purpose evs-reseed and type SIGNED_EVS_RESEED, by the admin's identity key. It is
// never re-signed: evs stores and serves the bytes it was sent. The reader's check, EvsVerifier.AcceptReseed, is on
// every leg (evs_verify.go); signing one and evs's parse of it are not the iOS extension's, so this file is off its
// leg.

package sidecar

import (
	"bytes"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A Signed EvsReseed as received, parsed and held to its shape. Its signature is Verify's.
type EvsReseedStatement struct {
	// The Signed bytes as received, which evs stores and a reader verifies.
	Bytes  []byte
	Signed *bridge.Signed
	Reseed *protocol.EvsReseed

	RepoId          Id
	RefId           Id
	SignerSidecarId Id
	// The re-seeded head: v and C_v.
	Version uint64
	Chain   [32]byte
}

// Whether signedBytes is a Signed of type SIGNED_EVS_RESEED: how POST .../reseed tells a Signed EvsReseed from a
// re-seeded Signed EvsPush before it parses either. Bytes that are no Signed are neither.
func EvsSignedIsReseed(signedBytes []byte) bool {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		return false
	}
	return bridge.SignedType(signed.GetType()) == bridge.SignedType_SIGNED_EVS_RESEED
}

// Parses a Signed EvsReseed of at most maxByteCount: its type, its ids' widths and its chain's. ErrEvsPushInvalid for
// anything else.
func ParseEvsReseedStatement(signedBytes []byte, maxByteCount int) (*EvsReseedStatement, error) {
	if len(signedBytes) == 0 || maxByteCount < len(signedBytes) {
		return nil, fmt.Errorf("%w: a reseed statement of %d bytes", ErrEvsPushInvalid, len(signedBytes))
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		return nil, fmt.Errorf("%w: a reseed statement that does not parse", ErrEvsPushInvalid)
	}
	if bridge.SignedType(signed.GetType()) != bridge.SignedType_SIGNED_EVS_RESEED {
		return nil, fmt.Errorf("%w: a statement of type %d as a reseed", ErrEvsPushInvalid, signed.GetType())
	}
	reseed := &protocol.EvsReseed{}
	if err := proto.Unmarshal(signed.GetBody(), reseed); err != nil {
		return nil, fmt.Errorf("%w: a reseed body that does not parse", ErrEvsPushInvalid)
	}
	repoId, err := IdFromBytes(reseed.GetRepoId())
	if err != nil {
		return nil, fmt.Errorf("%w: a reseed's repo id", ErrEvsPushInvalid)
	}
	refId, err := IdFromBytes(reseed.GetRefId())
	if err != nil {
		return nil, fmt.Errorf("%w: a reseed's ref id", ErrEvsPushInvalid)
	}
	signerId, err := IdFromBytes(signed.GetSignerId())
	if err != nil {
		return nil, fmt.Errorf("%w: a reseed's signer", ErrEvsPushInvalid)
	}
	chain, err := EvsChainFromBytes(reseed.GetChain())
	if err != nil {
		return nil, fmt.Errorf("%w: a reseed's chain of %d bytes", ErrEvsPushInvalid, len(reseed.GetChain()))
	}
	if reseed.GetVersion() == 0 {
		return nil, fmt.Errorf("%w: a reseed of no version", ErrEvsPushInvalid)
	}
	return &EvsReseedStatement{
		Bytes:           bytes.Clone(signedBytes),
		Signed:          signed,
		Reseed:          reseed,
		RepoId:          repoId,
		RefId:           refId,
		SignerSidecarId: signerId,
		Version:         reseed.GetVersion(),
		Chain:           chain,
	}, nil
}

// The statement's signature under its signer's identity key.
func (self *EvsReseedStatement) Verify(identityKey []byte) error {
	if len(identityKey) == 0 {
		return fmt.Errorf("%w: a reseed's signer with no identity key", ErrEvsStatementRefused)
	}
	if err := bridge.VerifySigned(self.Signed, evsReseedPurpose, bridge.SignedType_SIGNED_EVS_RESEED, bridge.SignedKeyAlgEd25519, identityKey); err != nil {
		return fmt.Errorf("%w: a reseed's signature: %w", ErrEvsStatementRefused, err)
	}
	return nil
}

// Signs an EvsReseed over the re-seeded head (version, chain) of refId for the recovery incidentId names, as a repo
// admin's device does (§19.10's repos row). The bytes are what POST .../reseed takes as its statement.
func SignEvsReseed(sign EvsSignFunction, repoId Id, refId Id, version uint64, chain [32]byte, incidentId []byte) ([]byte, error) {
	if sign == nil {
		return nil, fmt.Errorf("%w: no signer", ErrEvsPushInvalid)
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsReseed{
		RepoId:     repoId.Bytes(),
		RefId:      refId.Bytes(),
		Version:    version,
		Chain:      bytes.Clone(chain[:]),
		IncidentId: bytes.Clone(incidentId),
	})
	if err != nil {
		return nil, err
	}
	signed, err := sign(evsReseedPurpose, bridge.SignedType_SIGNED_EVS_RESEED, body, nil)
	if err != nil {
		return nil, err
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(signed)
}

// Whether sidecarId is one of repoId's admins in state, as §11.8's refs table and a reseed's signer rule read it; false
// for a repo the state does not hold.
func EvsRepoAdminIn(state GkmAuthView, repoId Id, sidecarId Id) bool {
	if state == nil {
		return false
	}
	repo := state.Repo(repoId)
	return repo != nil && evsRepoAdmin(state, repo, sidecarId)
}
