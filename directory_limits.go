//go:build !ios_extension

// §16.11's request limits (RECORD-M6-18; D-MCP-30's limits row, D-QUOTA-11): §20.4's sidecar_abuse keys, which the
// requesting daemon and the directory's readers both read through QuotaLimits (GET /sidecar/limits), so a §21
// tightening reaches both:
//
//	directory_requests_pending   20   one requester's pending requests
//	directory_requests_per_day   50   one requester's requests in a day
//	directory_requests_per_run    5   one run's requests
//	directory_target_pending    100   one target's pending requests, the older showing first
//
// The daemon refuses a filing past one, and a reader ignores what is past one with an over_limit alarm. A key the
// limits do not carry reads 0, which refuses (§20.5's not included), and limits that cannot be read refuse too: no
// limit is ever assumed. -1 is none. Both apply the limits only while the answer's enforced is true: while
// enforce_sidecar_limits is off every one reads none, so the daemon files past them and a reader shows what is past
// them, dark as api's refusals are (§20.5; owner decision 520), the limits still read so that an answer that does
// not come still refuses. The request's own times are a DirectoryRequestSettings' fields.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// §20.4's keys.
const (
	DirectoryLimitRequestsPending = "directory_requests_pending"
	DirectoryLimitRequestsPerDay  = "directory_requests_per_day"
	DirectoryLimitRequestsPerRun  = "directory_requests_per_run"
	DirectoryLimitTargetPending   = "directory_target_pending"
)

var (
	// A request past one of §16.11's limits: nothing was filed.
	ErrDirectoryRequestLimit = errors.New("directory request limit")
	// The limits could not be read, so no request is filed and no other sidecar's request is shown.
	ErrDirectoryLimitsUnavailable = errors.New("directory limits unavailable")
)

// Which limit refused, and where it stood.
type DirectoryLimitError struct {
	Key   string
	Limit int64
	Used  int64
}

// Names the key and its numbers, nothing of the request.
func (self *DirectoryLimitError) Error() string {
	return fmt.Sprintf("%s: %s %d of %d", ErrDirectoryRequestLimit, self.Key, self.Used, self.Limit)
}

// ErrDirectoryRequestLimit.
func (self *DirectoryLimitError) Unwrap() error {
	return ErrDirectoryRequestLimit
}

// A request's times and the windows its limits count over.
type DirectoryRequestSettings struct {
	// not_after when the filer names none: 7 d.
	RequestExpiry time.Duration
	// The longest not_after a filer may ask: 30 d.
	RequestMaxExpiry time.Duration
	// How long past not_after a notice and a decision's journal row are kept, and past which any writer may remove
	// the notice: 1 d.
	NoticeGrace time.Duration
	// The window directory_requests_per_day counts over.
	DayWindow time.Duration
	// A RepoGrant's expiry for a sidecar subject whose request asked none: 30 d. A member subject's asks none.
	SidecarGrantExpiry time.Duration
	// How far ahead of this device's clock a decision's or a notice's time may stand before it is not taken.
	ClockSkew time.Duration
}

// The defaults, a fresh value each call.
func DefaultDirectoryRequestSettings() *DirectoryRequestSettings {
	return &DirectoryRequestSettings{
		RequestExpiry:      DirectoryRequestDefaultExpiry,
		RequestMaxExpiry:   DirectoryRequestMaxExpiry,
		NoticeGrace:        DirectoryNoticeGrace,
		DayWindow:          24 * time.Hour,
		SidecarGrantExpiry: 30 * 24 * time.Hour,
		ClockSkew:          DirectoryClockSkew,
	}
}

// §16.11's four limits as read once.
type directoryLimits struct {
	requestsPending int64
	requestsPerDay  int64
	requestsPerRun  int64
	targetPending   int64
}

// Reads the limits through read, GET /sidecar/limits's seam: ErrDirectoryLimitsUnavailable for none bound or an answer
// that did not come, 0 for a key an enforced answer does not carry, and none for every key while it is not enforced.
func directoryLimitsOf(ctx context.Context, read func(ctx context.Context) (*QuotaLimits, error)) (*directoryLimits, error) {
	if read == nil {
		return nil, fmt.Errorf("%w: nothing reads them here", ErrDirectoryLimitsUnavailable)
	}
	limits, err := read(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDirectoryLimitsUnavailable, err)
	}
	if limits == nil {
		return nil, fmt.Errorf("%w: no limits answered", ErrDirectoryLimitsUnavailable)
	}
	return &directoryLimits{
		requestsPending: quotaLocalLimit(limits, DirectoryLimitRequestsPending),
		requestsPerDay:  quotaLocalLimit(limits, DirectoryLimitRequestsPerDay),
		requestsPerRun:  quotaLocalLimit(limits, DirectoryLimitRequestsPerRun),
		targetPending:   quotaLocalLimit(limits, DirectoryLimitTargetPending),
	}, nil
}

// Whether one more fits under limit with used taken: -1 is none, and 0 fits nothing.
func directoryLimitFits(limit int64, used int64) bool {
	return limit < 0 || used < limit
}

// The refusal of one more under key, nil when it fits.
func directoryLimitCheck(key string, limit int64, used int64) error {
	if directoryLimitFits(limit, used) {
		return nil
	}
	return &DirectoryLimitError{Key: key, Limit: limit, Used: used}
}
