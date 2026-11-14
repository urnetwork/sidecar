// The directory group's hint audience (KEYS-M6-01; §10.6's pending changes, KeyPackages and late wraps rows, §10.9's
// Directory group hints row; owner decisions 113, 182). Every sidecar of a team but read_only ones writes the team
// directory, so a hint to all its writers would start a rotation at each, and each rotation stages about 1.3 KB a
// wrapped reader. In the directory group gkm therefore hints:
//
//	pending       when an entry shrinks or grows the key holders, and every PendingHintInterval while the gate is
//	              closed: the signer of the statement the hint answers, first, then the config writers
//	first upload  a sidecar's first KeyPackage upload: the sidecars that signed its admission, first, then the
//	              config writers
//	late wraps    wrap-pending for a late ask and for a GroupInfo a resyncing device wants: the config writers,
//	              and once the ask is LateAskWidenAge old the other holders as in any group
//
// The signer acts at once and the config writers after 15 s plus jitter (the client's PendingCommitDelay); a writer no
// hint reaches rotates only for a push the gate refuses, after its own random wait (sidecar/gkm_directory.go).
//
// A signer that is no sidecar, a recovery key's hash or a Delegation's id, is hinted nothing: no client holds its
// topic.

package gkmservice

import (
	"slices"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Whether a repo's group is a team directory's.
func gkmDirectoryRepo(repo *protocol.AclRepo) bool {
	return repo != nil && repo.GetKind() == protocol.RepoKind_REPO_KIND_DIRECTORY
}

// Who a hint about the directory group goes to: the statement's signers in their order, then the config writers in
// theirs, each once.
func GkmDirectoryHintAudience(signerIds []sidecar.Id, configWriterIds []sidecar.Id) []sidecar.Id {
	audience := make([]sidecar.Id, 0, len(signerIds)+len(configWriterIds))
	for _, sidecarId := range signerIds {
		if !slices.Contains(audience, sidecarId) {
			audience = append(audience, sidecarId)
		}
	}
	for _, sidecarId := range configWriterIds {
		if !slices.Contains(audience, sidecarId) {
			audience = append(audience, sidecarId)
		}
	}
	return audience
}

// The sidecars among the signers of a sidecar's admission, in the row's order: who seats it in the directory group
// at once (§10.9's Add row). A signer of another form names no sidecar and is passed over.
func GkmAdmissionSignerIds(row *bridge.SidecarRow) []sidecar.Id {
	signerIds := []sidecar.Id{}
	for _, signer := range row.GetAdmissionSigners() {
		signerId, err := sidecar.IdFromBytes(signer)
		if err != nil || slices.Contains(signerIds, signerId) {
			continue
		}
		signerIds = append(signerIds, signerId)
	}
	return signerIds
}

// Who a first KeyPackage upload's pending hint about a repo goes to at a state and time (§10.6's KeyPackages row):
// hintWriterIds, the repo's writers, or in the directory group, where hintWriterIds are the config's writers, the
// standing sidecars that signed the uploader's admission and then those.
func GkmFirstUploadAudience(view sidecar.GkmAuthView, repoId sidecar.Id, uploaderId sidecar.Id, hintWriterIds []sidecar.Id, now time.Time) []sidecar.Id {
	if view == nil || !gkmDirectoryRepo(view.Repo(repoId)) {
		return hintWriterIds
	}
	signerIds := []sidecar.Id{}
	for _, signerId := range GkmAdmissionSignerIds(view.SidecarRow(uploaderId)) {
		if standing := sidecar.GkmSidecarStandingAt(view, signerId, now); standing != nil && !standing.Revoked {
			signerIds = append(signerIds, signerId)
		}
	}
	return GkmDirectoryHintAudience(signerIds, hintWriterIds)
}
