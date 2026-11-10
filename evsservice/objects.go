// §11.8's object families: the one place each key is built, so every family keeps the keys row's rules. No key
// prefixes another (§11.3: MinIO stores an object as a directory and lists it without descending), so an entry
// ends in .e beside its children's directory, a map, spidx, hold or drops key ends in /_, pidx/ keys under a ref
// have fixed lengths and no dropscan/ name prefixes another. Keys carry opaque ids and tokens only, never names
// (I-13), in plan-EVS1-format-bytes#9's forms: repo, ref, slot, parcel, container and job ids as 32 lowercase hex
// characters with no dashes (sidecar.EvsKeyId), segment ids as the lowercase hex of their 32 bytes, tokens as 26
// lowercase base32 characters, and versions, epochs, page numbers and parts in decimal, zero-padded to 20 digits.
//
// place/ lives in the root (evs_repo_place.go), since gkm resolves it too, and hold/ is api's (host_hold.go). Every
// metadata family here lives on the repo's own cluster, which place/ names; seg/, pack/ and dropscan/ on the
// segment cluster.

package evsservice

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// Each family's prefix, as §11.8's objects table names it.
const (
	repoKeyPrefix     = "repo/"
	headKeyPrefix     = "head/"
	logKeyPrefix      = "log/"
	batchKeyPrefix    = "pb/"
	indexKeyPrefix    = "idx/"
	slotKeyPrefix     = "slot/"
	parcelKeyPrefix   = "hp/"
	pathMapKeyPrefix  = "pmap/"
	pidxKeyPrefix     = "pidx/"
	spidxKeyPrefix    = "spidx/"
	dropsKeyPrefix    = "drops/"
	segmentKeyPrefix  = "seg/"
	packKeyPrefix     = "pack/"
	dropscanKeyPrefix = "dropscan/"
)

// The endings the keys row gives, so no key prefixes another.
const (
	// An index entry, beside the directory of its children's keys.
	indexEntryKeySuffix = ".e"
	// A map part, an spidx/ page and a repo's drops/ table.
	leafKeySuffix = "/_"
)

// A version, epoch, page or part in a key: 20 decimal digits, so keys of one family sort as numbers.
func keyNumber(number uint64) string {
	return fmt.Sprintf("%020d", number)
}

// repo/<repo>: kind, owner, state and deletion id, format, sealed name (§11.12).
func RepoKey(repoId sidecar.Id) string {
	return sidecar.EvsRepoObjectKey(repoId)
}

// head/<repo>/<ref>: the commit point.
func HeadKey(repoId sidecar.Id, refId sidecar.Id) string {
	return HeadRepoPrefix(repoId) + sidecar.EvsKeyId(refId)
}

// head/<repo>/: every ref's head, by LIST.
func HeadRepoPrefix(repoId sidecar.Id) string {
	return headKeyPrefix + sidecar.EvsKeyId(repoId) + "/"
}

// log/<repo>/<ref>/<n>: versions 64n to 64n+63.
func LogPageKey(repoId sidecar.Id, refId sidecar.Id, page uint64) string {
	return logKeyPrefix + sidecar.EvsKeyId(repoId) + "/" + sidecar.EvsKeyId(refId) + "/" + keyNumber(page)
}

// The UTC time a batch minute names: minutes since the Unix epoch.
func batchMinuteTime(minute uint32) time.Time {
	return time.Unix(int64(minute)*60, 0).UTC()
}

// The batch minute holding at: minutes since the Unix epoch, UTC.
func BatchMinute(at time.Time) uint32 {
	return uint32(at.Unix() / 60)
}

// pb/<yyyymmddhh>/<mm>/: one minute's batches, which evacuation walks.
func BatchMinutePrefix(minute uint32) string {
	at := batchMinuteTime(minute)
	return batchKeyPrefix + at.Format("2006010215") + "/" + at.Format("04") + "/"
}

// pb/<yyyymmddhh>/<mm>/<instance>-<seq>: the UTC hour and minute the batch opened, the process's random 32-bit id
// and its counter within that minute, each 8 lowercase hex digits (§11.8's batches).
func BatchKey(minute uint32, instance uint32, seq uint32) string {
	return BatchMinutePrefix(minute) + fmt.Sprintf("%08x-%08x", instance, seq)
}

// idx/<repo>/<ref>/<p>/: path epoch p's entries of one ref.
func IndexEpochPrefix(repoId sidecar.Id, refId sidecar.Id, epoch uint64) string {
	return indexKeyPrefix + sidecar.EvsKeyId(repoId) + "/" + sidecar.EvsKeyId(refId) + "/" + keyNumber(epoch) + "/"
}

// idx/<repo>/<ref>/<p>/<t1>/.../<tn>.e: the entry of a token path in path epoch p (§11.7's keys row). An empty
// path has no entry, so it builds the epoch's prefix alone, which no caller writes to.
func IndexEntryKey(repoId sidecar.Id, refId sidecar.Id, epoch uint64, tokenPath sidecar.EvsTokenPath) string {
	return IndexEpochPrefix(repoId, refId, epoch) + tokenPath.KeyString() + indexEntryKeySuffix
}

// idx/<repo>/<ref>/<p>/<t1>/.../<tn>/: where the entries below a directory sit, so a LIST by it lists a subtree.
// The empty path gives the epoch's own prefix.
func IndexChildrenPrefix(repoId sidecar.Id, refId sidecar.Id, epoch uint64, tokenPath sidecar.EvsTokenPath) string {
	if len(tokenPath) == 0 {
		return IndexEpochPrefix(repoId, refId, epoch)
	}
	return IndexEpochPrefix(repoId, refId, epoch) + tokenPath.KeyString() + "/"
}

// The token path an idx/ key names, under its epoch's prefix: the inverse of IndexEntryKey, for a LIST's keys.
func IndexEntryTokenPath(epochPrefix string, key string) (sidecar.EvsTokenPath, error) {
	rest, ok := strings.CutPrefix(key, epochPrefix)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not under %s", sidecar.ErrEvsTokenInvalid, key, epochPrefix)
	}
	rest, ok = strings.CutSuffix(rest, indexEntryKeySuffix)
	if !ok || rest == "" {
		return nil, fmt.Errorf("%w: %s is no entry", sidecar.ErrEvsTokenInvalid, key)
	}
	components := strings.Split(rest, "/")
	tokenPath := make(sidecar.EvsTokenPath, len(components))
	for i, component := range components {
		token, err := sidecar.ParseEvsToken(component)
		if err != nil {
			return nil, err
		}
		tokenPath[i] = token
	}
	if sidecar.EvsTokenPathMaxLength < len(tokenPath) {
		return nil, fmt.Errorf("%w: %d components", sidecar.ErrEvsTokenInvalid, len(tokenPath))
	}
	return tokenPath, nil
}

// slot/<repo>/<slot_id>: up to 64 sealed object keys.
func SlotKey(repoId sidecar.Id, slotId sidecar.Id) string {
	return slotKeyPrefix + sidecar.EvsKeyId(repoId) + "/" + sidecar.EvsKeyId(slotId)
}

// hp/<repo>/<parcel_id>: a small repo's records older than 24 h (§11.13).
func ParcelKey(repoId sidecar.Id, parcelId sidecar.Id) string {
	return parcelKeyPrefix + sidecar.EvsKeyId(repoId) + "/" + sidecar.EvsKeyId(parcelId)
}

// pmap/<repo>/<ref>/<p>/<map>/<part>/_: a Signed EvsPathMap part, <map> its path_map_sha256 in lowercase hex.
func PathMapKey(repoId sidecar.Id, refId sidecar.Id, epoch uint64, mapSha256 []byte, part uint32) string {
	return PathMapPrefix(repoId, refId, epoch, mapSha256) + keyNumber(uint64(part)) + leafKeySuffix
}

// pmap/<repo>/<ref>/<p>/<map>/: every part of one map.
func PathMapPrefix(repoId sidecar.Id, refId sidecar.Id, epoch uint64, mapSha256 []byte) string {
	return pathMapKeyPrefix + sidecar.EvsKeyId(repoId) + "/" + sidecar.EvsKeyId(refId) + "/" + keyNumber(epoch) + "/" +
		hex.EncodeToString(mapSha256) + "/"
}

// pidx/<repo>/<ref>/<v_first>-<id>: a pack's or parcel's records and log pages for one ref, fixed in length.
func PidxKey(repoId sidecar.Id, refId sidecar.Id, firstVersion uint64, containerId sidecar.Id) string {
	return PidxRefPrefix(repoId, refId) + keyNumber(firstVersion) + "-" + sidecar.EvsKeyId(containerId)
}

// pidx/<repo>/<ref>/: one ref's container entries, by LIST.
func PidxRefPrefix(repoId sidecar.Id, refId sidecar.Id) string {
	return pidxKeyPrefix + sidecar.EvsKeyId(repoId) + "/" + sidecar.EvsKeyId(refId) + "/"
}

// spidx/<repo>/<n>/_: reserved, offsets of segments in a pack (§11.13).
func SpidxKey(repoId sidecar.Id, page uint64) string {
	return spidxKeyPrefix + sidecar.EvsKeyId(repoId) + "/" + keyNumber(page) + leafKeySuffix
}

// drops/<repo>/_: the repo's drop table (format 2).
func DropsKey(repoId sidecar.Id) string {
	return dropsKeyPrefix + sidecar.EvsKeyId(repoId) + leafKeySuffix
}

// seg/<repo>/<segment_id>: one segment, its id the SHA-256 of its bytes. On the segment cluster.
func SegmentKey(repoId sidecar.Id, segmentId [32]byte) string {
	return segmentKeyPrefix + sidecar.EvsKeyId(repoId) + "/" + hex.EncodeToString(segmentId[:])
}

// pack/<repo>/<pack_id>: records and log pages older than 24 h. On the segment cluster.
func PackKey(repoId sidecar.Id, packId sidecar.Id) string {
	return packKeyPrefix + sidecar.EvsKeyId(repoId) + "/" + sidecar.EvsKeyId(packId)
}

// dropscan/<repo>/<id>/<f>: a drop job's or dry run's file, f one of snap, cand, mark, del or held, none a prefix
// of another. On the segment cluster.
func DropscanKey(repoId sidecar.Id, jobId sidecar.Id, file string) string {
	return dropscanKeyPrefix + sidecar.EvsKeyId(repoId) + "/" + sidecar.EvsKeyId(jobId) + "/" + file
}
