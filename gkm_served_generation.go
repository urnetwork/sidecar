// A statement's gen/<g> as a group that a re-form may have made holds it (plan-KEYS-reform-ladder rules 3 and 8 as
// QD-074 decided them; §10.8's bytes and pins rows), the rows evs's resolution (evsservice's generation_resolve.go)
// and a VPN component's Forwarder (bridge_forward_keys.go) share. A re-form draws a new group and carries the old
// ladder into it byte for byte, so gen/<k> of a re-formed group, k at or below its form's generation, holds the Signed
// GenRotate of the group k was claimed in, naming that group:
//
//	own      gen/<g> naming the group it is read in: the group's own claim, as before any re-form
//	carried  gen/<g> naming another group: a ladder's, taken where the GroupForm that makes the group it is read in
//	         re-forms another group at a generation of g or more, and the statement names the repo
//
// Each is verified under its signer's identity key as ParseGenRotate verifies one. Who may rotate at its state is
// §10.9's rotation checks', which neither caller runs here, and who may sign the form is §10.6's, which members judge
// before they adopt a group (gkm_reform.go). A member's GkmGroupClient.parseServedGeneration holds served statements
// to the same rows over the form its keychain adopted.
//
// Pure, on every leg.

package sidecar

import (
	"bytes"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The group a gen/ object's statement names, unverified: which row it falls under.
func GkmGenerationNamedGroup(objectBytes []byte) (Id, error) {
	signed := &bridge.Signed{}
	rotate := &protocol.GenRotate{}
	if err := proto.Unmarshal(objectBytes, signed); err != nil {
		return Id{}, fmt.Errorf("%w: gen object: %w", ErrGkmMalformed, err)
	}
	if err := proto.Unmarshal(signed.GetBody(), rotate); err != nil {
		return Id{}, fmt.Errorf("%w: GenRotate: %w", ErrGkmMalformed, err)
	}
	groupId, err := IdFromBytes(rotate.GetGroupId())
	if err != nil {
		return Id{}, fmt.Errorf("%w: gen object names no group", ErrGkmMalformed)
	}
	return groupId, nil
}

// gen/<generation> as groupId holds it, verified under its signer's identity key: the group's own statement, or the
// one a re-form's ladder carried, naming the group it was claimed in (the file's rows). formMaking answers the repo's
// GroupForm that makes groupId, nil for none, and is asked only for a statement of another group. ErrGkmMalformed for
// a statement of another group that no re-form carries there, or of another repo; what ParseGenRotate refuses is
// refused.
func GkmParseServedGeneration(objectBytes []byte, repoId Id, groupId Id, generation uint64, formMaking func() (*GkmGroupFormFacts, error), identityKey GkmIdentityKeyFunction) (*GkmGeneration, error) {
	namedGroupId, err := GkmGenerationNamedGroup(objectBytes)
	if err != nil {
		return nil, err
	}
	if namedGroupId == groupId {
		return ParseGenRotate(objectBytes, groupId, generation, identityKey)
	}
	var form *GkmGroupFormFacts
	if formMaking != nil {
		if form, err = formMaking(); err != nil {
			return nil, err
		}
	}
	if form == nil || form.GroupId != groupId || form.PreviousGroupId == (Id{}) || form.Generation < generation {
		return nil, fmt.Errorf("%w: gen/%d of another group, which no re-form of the repo carries", ErrGkmMalformed, generation)
	}
	parsed, err := ParseGenRotate(objectBytes, namedGroupId, generation, identityKey)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(parsed.Rotate.GetRepoId(), repoId.Bytes()) {
		return nil, fmt.Errorf("%w: a re-formed group's gen/%d of another repo", ErrGkmMalformed, generation)
	}
	return parsed, nil
}
