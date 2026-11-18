//go:build !ios_extension

// An erasure's wait on one index ref (§11.13's wait and limit rows; §11.14's bound and limit rows; §5.4's erasure event;
// owner decision 146; FS-78, FS-112; DESIGN-DETAILS 15.2.5 and 15.2.11; SEARCH-M10-17): what is left of its rewrites and
// when the last pair commits at the storage limit or while the network is spent.
//
//	objects   an erasure's work on the ref is its rekey objects, one file version each CLOSURE writes: one staged
//	          record where the rewrite is within StagedMaxByteCount (16 KiB, a slot), else one ?closure=1 upload at
//	          its padded size, at most ClosureUploadMaxByteCount (1,088 KiB, a shard or a large entry); one message is
//	          several when its text spans 1 MiB chunks, a backfill or late companion push copied it, a merge left it
//	          in an absorbed slot or a hold kept an earlier version, so no fixed wait a message holds
//	pairs     CLOSURE and ERASE pairs take whole objects in path order, each pair at most PairByteCount and, once a
//	          429 named the eraser's allowance A and what it had used, at most what is left of it that UTC day
//	finish    with B closure bytes left when the allowance first refuses, each UTC day from the next 00:00 takes whole
//	          objects up to A, so each day but its last takes more than A - ClosureUploadMaxByteCount, and the last
//	          pair commits after at most the ⌈B / (A - 1,088 KiB)⌉-th 00:00 UTC that follows, plus one PacingTurn an
//	          upload of that day; the finish here is that day count as the pairs fill them, which never passes the
//	          bound; zero below the limit, where nothing waits
//	re-entry  a run card's re-entry adds payload and waits as builds do, holding back no file of its erasure: it is
//	          tried again at least every ReentryRetryInterval, and the event shows waiting with the cards left
//
// Closure bytes are counted as the files' plaintext lengths, which a record's frame and an upload's padding lengthen a
// little; the finish reads the same lengths as the pairs do, so the two agree on the fake clock (FS-112's within one
// turn). Package-level functions are safe for concurrent use.

package sidecar

import (
	"time"
)

// One rekey object: one file version a CLOSURE writes.
type indexRekeyObject struct {
	path      string
	byteCount int64
	// A staged record, which spends no upload and no pacing turn; else a ?closure=1 upload.
	staged bool
}

// The rekey object a rewrite of byteCount bytes is.
func indexNewRekeyObject(path string, byteCount int, settings *IndexEraseSettings) *indexRekeyObject {
	return &indexRekeyObject{path: path, byteCount: int64(byteCount), staged: byteCount <= settings.StagedMaxByteCount}
}

// The closure bytes of objects.
func indexRekeyByteCount(objects []*indexRekeyObject) int64 {
	byteCount := int64(0)
	for _, object := range objects {
		byteCount += object.byteCount
	}
	return byteCount
}

// The first 00:00 UTC strictly after now.
func indexNextUtcMidnight(now time.Time) time.Time {
	utc := now.UTC()
	return time.Date(utc.Year(), utc.Month(), utc.Day(), 0, 0, 0, 0, time.UTC).Add(24 * time.Hour)
}

// The days objects take from the next 00:00 UTC on at allowance a day, each day whole objects in order while they fit
// it (a day takes at least one, whatever its size), and the uploads of the last day: what the pairs do at the limit.
func indexRekeyDays(objects []*indexRekeyObject, allowance int64) (int, int) {
	if len(objects) == 0 {
		return 0, 0
	}
	days := 1
	dayByteCount := int64(0)
	uploads := 0
	for _, object := range objects {
		if 0 < dayByteCount && allowance < dayByteCount+object.byteCount {
			days += 1
			dayByteCount = 0
			uploads = 0
		}
		dayByteCount += object.byteCount
		if !object.staged {
			uploads += 1
		}
	}
	return days, uploads
}

// §11.13's bound on the days: ⌈B / (A - ClosureUploadMaxByteCount)⌉, the object count where A leaves no room past one
// upload.
func indexRekeyDayBound(objects []*indexRekeyObject, allowance int64, settings *IndexEraseSettings) int {
	perDay := allowance - settings.ClosureUploadMaxByteCount
	if perDay <= 0 {
		return len(objects)
	}
	byteCount := indexRekeyByteCount(objects)
	return int((byteCount + perDay - 1) / perDay)
}

// When the last pair over objects commits, its allowance having refused at now with allowance a UTC day: the last
// day's 00:00 UTC plus a pacing turn for each upload of that day. Zero for no object.
func indexEraseFinish(now time.Time, objects []*indexRekeyObject, allowance int64, settings *IndexEraseSettings) time.Time {
	days, uploads := indexRekeyDays(objects, allowance)
	if days == 0 {
		return time.Time{}
	}
	return indexNextUtcMidnight(now).Add(time.Duration(days-1)*24*time.Hour + time.Duration(uploads)*settings.PacingTurn)
}

// The objects the next pair takes, in order: whole objects while they stay within byteCount, at least one.
func indexPairObjectCount(objects []*indexRekeyObject, byteCount int64) int {
	taken := int64(0)
	for index, object := range objects {
		if 0 < index && byteCount < taken+object.byteCount {
			return index
		}
		taken += object.byteCount
	}
	return len(objects)
}

// What a 429 or a quota refusal of a CLOSURE says of the eraser's allowance: when to try again, and, where it names
// them, the day's allowance and what of it is used.
type indexEraseAllowance struct {
	retryAfter time.Duration
	// 0 where the refusal names none.
	limit int64
	used  int64
}

// The allowance a refusal states, and false for any other error.
func indexEraseAllowanceOf(err error) (*indexEraseAllowance, bool) {
	refusal, ok := indexRefusalOf(err)
	if !ok || refusal.kind != indexRefusalRetry && refusal.kind != indexRefusalQuota {
		return nil, false
	}
	allowance := &indexEraseAllowance{retryAfter: refusal.retryAfter}
	if refusal.quota != nil {
		allowance.limit = refusal.quota.Limit
		allowance.used = refusal.quota.Used
		if allowance.retryAfter == 0 {
			allowance.retryAfter = time.Duration(refusal.quota.RetryAfterMs) * time.Millisecond
		}
	}
	return allowance, true
}

// The erasure's state while its pairs wait on the allowance: the objects and bytes left, the refusal's next try and
// the finish. allowance is the refusal's, or PairByteCount, the floor, where it names none.
func indexEraseWaiting(erasureId Id, now time.Time, objects []*indexRekeyObject, refused *indexEraseAllowance, settings *IndexEraseSettings) *SidecarErasure {
	allowance := refused.limit
	if allowance <= 0 {
		allowance = settings.PairByteCount
	}
	return &SidecarErasure{
		ErasureId:   erasureId,
		State:       SidecarErasureWaiting,
		ObjectsLeft: int64(len(objects)),
		BytesLeft:   indexRekeyByteCount(objects),
		NextTry:     now.Add(refused.retryAfter),
		Finish:      indexEraseFinish(now, objects, allowance, settings),
	}
}

// The state of a re-entry a quota refused: waiting, the cards left to enter as objects, tried again in
// ReentryRetryInterval, with no finish, since a re-entry waits for the network to be under the limit and not spent.
func indexReenterWaiting(erasureId Id, now time.Time, cardCount int, settings *IndexEraseSettings) *SidecarErasure {
	return &SidecarErasure{
		ErasureId:   erasureId,
		State:       SidecarErasureWaiting,
		ObjectsLeft: int64(cardCount),
		NextTry:     now.Add(settings.ReentryRetryInterval),
	}
}
