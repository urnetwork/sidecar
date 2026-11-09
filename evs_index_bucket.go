// Buckets (§11.14's Buckets block; D-EVS-45): UTC windows of a repo's W days, which every device computes alike from
// signed push times and the bucket windows its files keep, so no device's clock decides where an entry goes. Bucket S
// holds UTC days [S, S+W), counted from 1970-01-01. The first starts at ⌊day/W⌋·W and each next where the newest ends,
// whole empty windows skipped; W is fixed when a bucket is created and kept in its files, so a changed W applies from
// the next bucket. An entry goes to the bucket of its push's signed time_ms, or to the newest bucket already holding an
// entry of its document where that is newer, so clock skew at a boundary never leaves a newer version in an older
// bucket. Latest is the window holding today and the one before it; an older bucket is expired, and stays searched
// until its roll-up lands.
//
// Only an age reads a clock, and that clock is the caller's: a reader 10 minutes skewed places every entry where an
// exact one does.

package sidecar

import (
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A day, the unit buckets count in.
const indexDayMs = 24 * 60 * 60 * 1000

// How far a push's signed time_ms may sit from evs's clock (§11.6's time check), a fact of evs. Two writers' pushes in
// one order may carry times twice this apart, which bounds how far an entry sits outside its bucket's window.
const indexTimeSkew = 10 * time.Minute

// The team directory's windows (§11.14's directory row; owner decision 171): 7 days when settings name none, 7-90.
const (
	indexDirectoryDefaultWindowDays = 7
	indexDirectoryMaxWindowDays     = 90
)

// One bucket's window: UTC days [startDay, startDay + days).
type indexBucketWindow struct {
	startDay uint32
	days     uint32
}

// The first day past the window.
func (self indexBucketWindow) endDay() uint32 {
	return self.startDay + self.days
}

// Whether the window holds day.
func (self indexBucketWindow) holds(day uint32) bool {
	return self.startDay <= day && day < self.endDay()
}

// The UTC day of a time in ms, counted from 1970-01-01. evs keeps signed times within 10 minutes of its clock, so none
// is before the epoch, and one that were would read as day 0.
func indexDayOf(timeMs int64) uint32 {
	if timeMs < 0 {
		return 0
	}
	return uint32(timeMs / indexDayMs)
}

// The window a new bucket takes for an entry on day, the buckets being ascending and disjoint: the first at ⌊day/W⌋·W,
// a later one where the newest ends with whole empty windows of W skipped. Only for a day at or past the newest's end.
func indexNewBucketWindow(buckets []indexBucketWindow, windowDays uint32, day uint32) indexBucketWindow {
	if len(buckets) == 0 {
		return indexBucketWindow{startDay: day / windowDays * windowDays, days: windowDays}
	}
	end := buckets[len(buckets)-1].endDay()
	return indexBucketWindow{startDay: end + (day-end)/windowDays*windowDays, days: windowDays}
}

// The bucket an entry of a push signed at signedTimeMs goes to when no newer bucket holds its document, among buckets
// ascending and disjoint, windowDays being the W a new one takes; created says the push creates it, as the first
// writer into a window does. A day at or past the newest's end opens a new bucket; a day a bucket holds is that
// bucket's. A day no bucket holds and before the newest's end, which only a clock skewed at a boundary gives, goes to
// the newest bucket starting at or before it, else the first: the reading SearchOracle takes (search_oracle.go), since
// no window can open behind the newest.
func indexBucketFor(buckets []indexBucketWindow, windowDays uint32, signedTimeMs int64) (indexBucketWindow, bool) {
	day := indexDayOf(signedTimeMs)
	if len(buckets) == 0 || buckets[len(buckets)-1].endDay() <= day {
		return indexNewBucketWindow(buckets, windowDays, day), true
	}
	chosen := buckets[0]
	for _, bucket := range buckets {
		if bucket.startDay <= day {
			chosen = bucket
		}
	}
	return chosen, false
}

// The bucket one entry goes to: the push's own, or held, the newest bucket already holding an entry of its document,
// where that is newer. held is nil where no bucket holds the document.
func indexBucketForEntry(pushBucket indexBucketWindow, held *indexBucketWindow) indexBucketWindow {
	if held != nil && pushBucket.startDay < held.startDay {
		return *held
	}
	return pushBucket
}

// A bucket's age at a reader's now (§11.14's latest row).
type indexBucketAge int

const (
	// The window holding today, or a later one a clock ahead of the reader's opened.
	indexBucketCurrent indexBucketAge = iota + 1
	// The window just before today's.
	indexBucketPrevious
	// Older than both: searched until its roll-up lands, and rolled up oldest first.
	indexBucketExpired
)

// Each bucket's age at nowMs, by index, buckets ascending and disjoint and windowDays the W a new one would take.
// Today's window is the bucket holding today; or, past the newest, the one an entry signed now would open; or, a
// reader's clock being behind the newest bucket's start, the newest. Latest is that window and the one ending where it
// starts, which is no bucket when the window before today's was empty and skipped.
func indexBucketAges(buckets []indexBucketWindow, windowDays uint32, nowMs int64) []indexBucketAge {
	ages := make([]indexBucketAge, len(buckets))
	if len(buckets) == 0 {
		return ages
	}
	today := indexDayOf(nowMs)
	newest := buckets[len(buckets)-1]
	currentStart := newest.startDay
	switch {
	case newest.endDay() <= today:
		currentStart = indexNewBucketWindow(buckets, windowDays, today).startDay
	case newest.startDay <= today:
	default:
		for _, bucket := range buckets {
			if bucket.holds(today) {
				currentStart = bucket.startDay
			}
		}
	}
	for index, bucket := range buckets {
		switch {
		case currentStart < bucket.endDay():
			ages[index] = indexBucketCurrent
		case bucket.endDay() == currentStart:
			ages[index] = indexBucketPrevious
		default:
			ages[index] = indexBucketExpired
		}
	}
	return ages
}

// The W a new bucket takes under settings, which a reader has already checked: 30 days when none is set, 7 in the team
// directory (owner decision 171).
func indexEffectiveWindowDays(settings *protocol.IndexSettings, repoKind protocol.RepoKind) uint32 {
	if repoKind == protocol.RepoKind_REPO_KIND_DIRECTORY && (settings == nil || settings.WindowDays == 0) {
		return indexDirectoryDefaultWindowDays
	}
	return indexWindowDays(settings)
}

// Refuses settings a repo of this kind does not take: the format's 0 or 7-365 anywhere, and in the team directory a
// window past 90 days or the index off, which it refuses (§11.14's directory row; owner decision 171).
func indexCheckSettingsForKind(settings *protocol.IndexSettings, repoKind protocol.RepoKind) error {
	if err := indexCheckSettings(settings); err != nil {
		return err
	}
	if repoKind == protocol.RepoKind_REPO_KIND_DIRECTORY {
		if settings.Off {
			return indexMalformed("the team directory's index turned off")
		}
		if indexDirectoryMaxWindowDays < settings.WindowDays {
			return indexMalformed("a team directory window past 90 days")
		}
	}
	return nil
}
