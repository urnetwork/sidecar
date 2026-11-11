// Ref ids (§11.6's ref ids row): what evs sees in place of every ref name, naming head/<repo>/<ref> and
// log/<repo>/<ref>/<n>. A named ref's id is HMAC-SHA256(K_ref, "ref" || ref name bytes)[:16], keyed from RK_1 for
// the repo's life, so any reader derives main's, and a removed holder can test guessed names for as long (§11.5).
// Two refs have public ids instead: a depositor's own deposit ref, the first 16 bytes of SHA-256(repo_id ||
// sidecar_id), which evs checks a depositor against; and the repo's erasure ref, the first 16 bytes of
// SHA-256("UR evs 1.0 erasure" || repo_id), which no writer can squat by choosing a name (plan-EVS1-ref-name-bytes#3).
//
// A ref's name bytes (plan-EVS1-ref-name-bytes#1 and #2) are <b> for git's refs/heads/<b>, the whole refs/tags/<t>
// for a tag, and the bare name for every other ref: main, ur/<sidecar_id>/…, ur/index, ur/lfs and cards. So git's
// main branch and a file-mode main are one ref, of one mode. <sidecar_id> inside a name is Id.String(), and a
// conflict ref's time is UTC yyyymmddThhmmssZ. The local tier's refusals of reserved branch names before any evs
// write are its own (EVS1-M2-33, EVS1-M2-34); what is here keeps the mapping from git's names one to one.
//
// On every leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"
)

// What a named ref's HMAC input starts with, and the erasure ref's hash input (§11.6,
// plan-EVS1-ref-name-bytes#3).
const (
	evsRefIdLabel        = "ref"
	evsErasureRefIdLabel = "UR evs 1.0 erasure"
)

// The ref name forms plan-EVS1-ref-name-bytes fixes.
const (
	evsGitBranchPrefix = "refs/heads/"
	evsGitTagPrefix    = "refs/tags/"
	// A sidecar's own refs: ur/<sidecar_id>/…
	evsOwnedRefPrefix = "ur/"
	// The local conflict refs under a sidecar's own, ur/<sidecar_id>/conflicts/<ref>/<time> (§11.11).
	evsConflictRefInfix = "/conflicts/"
	// <time> in a conflict ref's name, which git allows in a ref.
	evsConflictTimeLayout = "20060102T150405Z"
	// Id.String()'s 8-4-4-4-12 form.
	evsSidecarIdTextLength = 36
)

// A git ref that does not map to an evs ref name.
var ErrEvsRefNameInvalid = errors.New("evs ref name invalid")

// HMAC-SHA256(K_ref, "ref" || refName)[:16], refName being the ref's name bytes (above).
func EvsRefId(refKey *EvsRefKey, refName []byte) (Id, error) {
	if err := refKey.checkHeld(); err != nil {
		return Id{}, err
	}
	if len(refName) == 0 {
		return Id{}, fmt.Errorf("%w: an empty ref name", ErrEvsRefNameInvalid)
	}
	mac := hmac.New(sha256.New, refKey.key)
	mac.Write([]byte(evsRefIdLabel))
	mac.Write(refName)
	return Id(mac.Sum(nil)[:16]), nil
}

// The first 16 bytes of SHA-256(repo_id || sidecar_id): the deposit ref sidecarId writes in repoId, which evs checks
// a depositor's token against and any reader derives.
func EvsDepositRefId(repoId Id, sidecarId Id) Id {
	digest := sha256.New()
	digest.Write(repoId.Bytes())
	digest.Write(sidecarId.Bytes())
	return Id(digest.Sum(nil)[:16])
}

// The first 16 bytes of SHA-256("UR evs 1.0 erasure" || repo_id): the repo's one erasure ref, whose id no name maps
// to, so evs refuses any other ref kind there and an erasure ref kind anywhere else (409 REF_MODE).
func EvsErasureRefId(repoId Id) Id {
	digest := sha256.New()
	digest.Write([]byte(evsErasureRefIdLabel))
	digest.Write(repoId.Bytes())
	return Id(digest.Sum(nil)[:16])
}

// The ref name bytes of a git ref that reaches evs: <b> for refs/heads/<b> and refs/tags/<t> whole. Only branches
// and tags reach evs (§11.11's receive row), so any other ref is refused, as is a branch whose short name starts
// with refs/, which would name the same ref as a tag or another branch. The error never repeats the name.
func EvsGitRefName(gitRef string) ([]byte, error) {
	switch {
	case strings.HasPrefix(gitRef, evsGitBranchPrefix):
		branch := gitRef[len(evsGitBranchPrefix):]
		if branch == "" || strings.HasPrefix(branch, "refs/") {
			return nil, fmt.Errorf("%w: a branch whose short name is empty or starts with refs/", ErrEvsRefNameInvalid)
		}
		return []byte(branch), nil
	case strings.HasPrefix(gitRef, evsGitTagPrefix):
		if len(gitRef) == len(evsGitTagPrefix) {
			return nil, fmt.Errorf("%w: a tag with no name", ErrEvsRefNameInvalid)
		}
		return []byte(gitRef), nil
	default:
		return nil, fmt.Errorf("%w: only branches and tags reach evs", ErrEvsRefNameInvalid)
	}
}

// The git ref a ref name stands for in a mount: refs/tags/<t> for a tag's name, else refs/heads/<name>.
func EvsGitRefOfName(refName []byte) string {
	if bytes.HasPrefix(refName, []byte(evsGitTagPrefix)) {
		return string(refName)
	}
	return evsGitBranchPrefix + string(refName)
}

// ur/<sidecar_id>/<rest>: a ref of sidecarId's own, an owned ref (§11.8's refs table).
func EvsOwnedRefName(sidecarId Id, rest string) []byte {
	return []byte(evsOwnedRefPrefix + sidecarId.String() + "/" + rest)
}

// ur/<sidecar_id>/conflicts/<ref>/<time>, the local conflict ref for refName at at, in UTC (§11.11's restart row).
func EvsConflictRefName(sidecarId Id, refName []byte, at time.Time) []byte {
	conflictRefName := EvsOwnedRefName(sidecarId, "")
	conflictRefName = conflictRefName[:len(conflictRefName)-1]
	conflictRefName = append(conflictRefName, evsConflictRefInfix...)
	conflictRefName = append(conflictRefName, refName...)
	conflictRefName = append(conflictRefName, '/')
	return append(conflictRefName, at.UTC().Format(evsConflictTimeLayout)...)
}

// The sidecar an owned ref's name says owns it, ur/<sidecar_id>/…, and false for any other name, which replaying
// readers check against the head's owner_sidecar_id (plan-EVS1-ref-name-bytes#3).
func EvsOwnedRefOwner(refName []byte) (Id, bool) {
	if !bytes.HasPrefix(refName, []byte(evsOwnedRefPrefix)) {
		return Id{}, false
	}
	rest := refName[len(evsOwnedRefPrefix):]
	if len(rest) <= evsSidecarIdTextLength || rest[evsSidecarIdTextLength] != '/' {
		return Id{}, false
	}
	sidecarId, err := ParseId(string(rest[:evsSidecarIdTextLength]))
	if err != nil || sidecarId.String() != string(rest[:evsSidecarIdTextLength]) {
		return Id{}, false
	}
	return sidecarId, true
}

// A ref name's bound: git's own for a ref's path, which a loose ref's file name must keep within. A format bound, not
// a tunable.
const EvsRefNameMaxByteCount = 4096

// A sealed ref name's bound, payload section 15's: a name at its bound with the seal's nonce and tag.
const EvsSealedRefNameMaxByteCount = EvsRefNameMaxByteCount + evsSealOverhead

// The label a sealed ref name's AAD starts with (DESIGN-DETAILS 8.2.2's sections row).
const evsRefNameAadLabel = "UR evs 1.0 ref name"

// "UR evs 1.0 ref name" || repo_id || ref_id.
func evsRefNameAad(repoId Id, refId Id) []byte {
	aad := make([]byte, 0, len(evsRefNameAadLabel)+32)
	aad = append(aad, evsRefNameAadLabel...)
	aad = append(aad, repoId.Bytes()...)
	return append(aad, refId.Bytes()...)
}

// A creating push's payload section 15: refName sealed alone under manifestKey, manifest_g of the push's generation,
// which evs copies into the head's sealed_ref_name and a reader opens with EvsOpenRefName.
func EvsSealRefName(manifestKey *EvsManifestKey, refId Id, refName []byte) ([]byte, error) {
	if err := manifestKey.checkHeld(); err != nil {
		return nil, err
	}
	if len(refName) == 0 || EvsRefNameMaxByteCount < len(refName) {
		return nil, fmt.Errorf("%w: a ref name of %d bytes", ErrEvsRefNameInvalid, len(refName))
	}
	return evsSeal(manifestKey.key, refName, evsRefNameAad(manifestKey.repoId, refId))
}

// A head's sealed ref name opened under manifestKey, manifest_g of the creating push's generation: ErrEvsSealInvalid
// for one that does not open, or opens to no name.
func EvsOpenRefName(manifestKey *EvsManifestKey, refId Id, sealed []byte) ([]byte, error) {
	if err := manifestKey.checkHeld(); err != nil {
		return nil, err
	}
	refName, err := evsOpen(manifestKey.key, sealed, evsRefNameAad(manifestKey.repoId, refId))
	if err != nil {
		return nil, err
	}
	if len(refName) == 0 || EvsRefNameMaxByteCount < len(refName) {
		return nil, fmt.Errorf("%w: a sealed ref name of %d bytes", ErrEvsSealInvalid, len(refName))
	}
	return refName, nil
}
