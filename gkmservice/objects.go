// §10.6's object families: the one place gkm builds each of its keys, in QD-442's forms, which
// testdata/gkm/wrap_paths.json pins: epochs, generations and seqs as 20 decimal digits, zero-padded, seqs from 1;
// group, repo, member and sidecar ids as 32 lowercase hex characters with no dashes (sidecar.EvsKeyId's form); a
// KeyPackageRef as 64; c8, k8 and b8 as 16. Keys carry opaque ids only (I-13).
//
// The families a delivery or a generation names, gen/<g>, wrap/... and recovery/..., the root builds
// (gkm_paths.go), since the client and evs build them too; this file names them beside the rest.
//
// No key prefixes another as a path, since MinIO stores an object as a directory and lists it without descending
// (§11.3): every group id is 32 hex characters, which none of repo, kp, rk, welcome or recovery is, and a claim is
// <ref>.claim beside <ref>, never under it.
//
// Group objects live on the cluster place/<repo_id> names, and per-sidecar ones (kp/, rk/, welcome/<sidecar_id>/)
// on the first cluster, beside place/ (§10.6's placement row).

package gkmservice

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/urnetwork/sidecar"
)

// The families' prefixes.
const (
	gkmKeyPrefix                = "gkm/"
	gkmFormKeyPrefix            = "gkm/repo/"
	gkmKeyPackageKeyPrefix      = "gkm/kp/"
	gkmReaderKeyKeyPrefix       = "gkm/rk/"
	gkmWelcomePointerKeyPrefix  = "gkm/welcome/"
	gkmRecoveryKeyPrefix        = "gkm/recovery/"
	gkmKeyPackageClaimKeySuffix = ".claim"
	// evs's repo/<repo>, which gkm rereads before each write (§10.6's checks row). evsservice.RepoKey builds the same
	// key, which store_test.go pins, since this package does not link evs.
	gkmEvsRepoKeyPrefix = "repo/"
)

// A KeyPackageRef's bytes: RFC 9420 §5.2's RefHash under 0x0010's SHA-256.
const gkmKeyPackageRefByteCount = 32

// An epoch, generation or seq in a key: 20 decimal digits, so keys of one family sort as numbers.
func gkmKeyNumber(number uint64) string {
	return fmt.Sprintf("%020d", number)
}

// The number a 20-digit key segment names, or false.
func parseGkmKeyNumber(segment string) (uint64, bool) {
	if len(segment) != 20 {
		return 0, false
	}
	number := uint64(0)
	for i := 0; i < len(segment); i += 1 {
		c := segment[i]
		if c < '0' || '9' < c {
			return 0, false
		}
		digit := uint64(c - '0')
		if (^uint64(0)-digit)/10 < number {
			return 0, false
		}
		number = number*10 + digit
	}
	return number, true
}

// repo/<repo_id>: evs's state of a repo, on its cluster.
func GkmEvsRepoKey(repoId sidecar.Id) string {
	return gkmEvsRepoKeyPrefix + sidecar.EvsKeyId(repoId)
}

// gkm/repo/<repo_id>/: a repo's GroupForms, by LIST.
func GkmFormPrefix(repoId sidecar.Id) string {
	return gkmFormKeyPrefix + sidecar.EvsKeyId(repoId) + "/"
}

// gkm/repo/<repo_id>/<seq>: one GroupForm, Signed, seq from 1.
func GkmFormKey(repoId sidecar.Id, seq uint64) string {
	return GkmFormPrefix(repoId) + gkmKeyNumber(seq)
}

// gkm/<group_id>/: every object of a group, by LIST.
func GkmGroupPrefix(groupId sidecar.Id) string {
	return gkmKeyPrefix + sidecar.EvsKeyId(groupId) + "/"
}

// gkm/<group_id>/epoch/: a group's epochs, by LIST.
func GkmEpochPrefix(groupId sidecar.Id) string {
	return GkmGroupPrefix(groupId) + "epoch/"
}

// gkm/<group_id>/epoch/<n>: epoch n's object, a GkmEpochObject.
func GkmEpochKey(groupId sidecar.Id, epoch uint64) string {
	return GkmEpochPrefix(groupId) + gkmKeyNumber(epoch)
}

// gkm/<group_id>/gen/: a group's generations, by LIST.
func GkmGenerationPrefix(groupId sidecar.Id) string {
	return GkmGroupPrefix(groupId) + "gen/"
}

// gkm/<group_id>/gen/<g>: the Signed GenRotate, where generation g exists and nowhere else (D-KEYS-15).
func GkmGenerationKey(groupId sidecar.Id, generation uint64) string {
	return sidecar.GkmGenerationPath(groupId, generation)
}

// gkm/<group_id>/group-info: the pointer at 16 leaves or fewer, else the sealed GroupInfo.
func GkmGroupInfoKey(groupId sidecar.Id) string {
	return GkmGroupPrefix(groupId) + "group-info"
}

// gkm/<group_id>/welcome/<n>: epoch n's Welcome, its MLSMessage bytes.
func GkmWelcomeKey(groupId sidecar.Id, epoch uint64) string {
	return GkmGroupPrefix(groupId) + "welcome/" + gkmKeyNumber(epoch)
}

// gkm/<group_id>/wrap/<g>/: every delivery of generation g, by LIST.
func GkmWrapGenerationPrefix(groupId sidecar.Id, generation uint64) string {
	return GkmGroupPrefix(groupId) + "wrap/" + gkmKeyNumber(generation) + "/"
}

// gkm/recovery/<member_id>/: a member's recovery wraps, on each cluster.
func GkmRecoveryMemberPrefix(memberId sidecar.Id) string {
	return gkmRecoveryKeyPrefix + sidecar.EvsKeyId(memberId) + "/"
}

// A KeyPackageRef in a key: 64 lowercase hex characters, or an error for any other length.
func gkmRefKey(ref []byte) (string, error) {
	if len(ref) != gkmKeyPackageRefByteCount {
		return "", fmt.Errorf("%w: a KeyPackageRef of %d bytes", sidecar.ErrGkmMalformed, len(ref))
	}
	return hex.EncodeToString(ref), nil
}

// gkm/kp/<sidecar_id>/: a sidecar's KeyPackages and claims, by LIST, on the first cluster.
func GkmKeyPackagePrefix(sidecarId sidecar.Id) string {
	return gkmKeyPackageKeyPrefix + sidecar.EvsKeyId(sidecarId) + "/"
}

// gkm/kp/<sidecar_id>/<ref>: a one-time or last-resort KeyPackage, its MLSMessage bytes.
func GkmKeyPackageKey(sidecarId sidecar.Id, ref []byte) (string, error) {
	refKey, err := gkmRefKey(ref)
	if err != nil {
		return "", err
	}
	return GkmKeyPackagePrefix(sidecarId) + refKey, nil
}

// gkm/kp/<sidecar_id>/<ref>.claim: a claim of that KeyPackage, a GkmKeyPackageClaim.
func GkmKeyPackageClaimKey(sidecarId sidecar.Id, ref []byte) (string, error) {
	key, err := GkmKeyPackageKey(sidecarId, ref)
	if err != nil {
		return "", err
	}
	return key + gkmKeyPackageClaimKeySuffix, nil
}

// What one key LIST finds under a sidecar's kp/ prefix names: its ref, and whether it is the ref's claim. false for
// a key in no form this family writes.
func parseGkmKeyPackageListKey(prefix string, key string) (ref []byte, claim bool, ok bool) {
	rest, found := strings.CutPrefix(key, prefix)
	if !found {
		return nil, false, false
	}
	rest, claim = strings.CutSuffix(rest, gkmKeyPackageClaimKeySuffix)
	if len(rest) != 2*gkmKeyPackageRefByteCount || strings.ToLower(rest) != rest {
		return nil, false, false
	}
	ref, err := hex.DecodeString(rest)
	if err != nil {
		return nil, false, false
	}
	return ref, claim, true
}

// gkm/rk/<sidecar_id>: a sidecar's current ReaderKey, a Signed, on the first cluster.
func GkmReaderKeyKey(sidecarId sidecar.Id) string {
	return gkmReaderKeyKeyPrefix + sidecar.EvsKeyId(sidecarId)
}

// gkm/welcome/<sidecar_id>/: a sidecar's Welcome pointers, by LIST, on the first cluster.
func GkmWelcomePointerPrefix(sidecarId sidecar.Id) string {
	return gkmWelcomePointerKeyPrefix + sidecar.EvsKeyId(sidecarId) + "/"
}

// gkm/welcome/<sidecar_id>/<ref>: a pointer {group_id, n} to the Welcome that joins the sidecar under that
// KeyPackage.
func GkmWelcomePointerKey(sidecarId sidecar.Id, ref []byte) (string, error) {
	refKey, err := gkmRefKey(ref)
	if err != nil {
		return "", err
	}
	return GkmWelcomePointerPrefix(sidecarId) + refKey, nil
}

// The ref a key under a sidecar's welcome/ prefix names, or false.
func parseGkmWelcomePointerKey(prefix string, key string) ([]byte, bool) {
	rest, found := strings.CutPrefix(key, prefix)
	if !found || len(rest) != 2*gkmKeyPackageRefByteCount || strings.ToLower(rest) != rest {
		return nil, false
	}
	ref, err := hex.DecodeString(rest)
	if err != nil {
		return nil, false
	}
	return ref, true
}
