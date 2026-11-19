//go:build !sidecar_http && !ios_extension

// §14.4's retry schedule (plan-SMTP-small-readings#9; SMTP-M9-08): a send that fails is tried again first 30 min
// after its message was created, the interval doubling to 4 h and then every 4 h, and given up with a DSN 5 days
// after creation. HALTED, QUOTA and TRY_LATER, and KEYS's KeysRetryTimeout, honor the wait the edge or the
// settings give and still end at 5 days. A held send never reports failed while it holds.
//
// The schedule is anchored at the message's creation time, so it is a function of that time and now alone: a
// sender that restarts, or a second prover host that takes the entry over, computes the same next try with no
// state of its own.
//
// Units (§14.7): a message's retries that reach MAIL spend at most RetryUnitsPerMessagePerDay connection units a
// UTC day, past which the message waits for the next UTC day. SmtpRetryUnits counts them in memory, by effect key
// and day, so a restart forgets today's count and a message may spend that many again (a reading: the design
// keeps the count nowhere a restart would read).
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"sync"
	"time"
)

// The schedule, under one sender's settings. Immutable, so safe for concurrent use.
type SmtpRetryPolicy struct {
	settings *SmtpSenderSettings
}

// The schedule under settings, which must have passed validate.
func NewSmtpRetryPolicy(settings *SmtpSenderSettings) *SmtpRetryPolicy {
	return &SmtpRetryPolicy{settings: settings}
}

// When a message created at createTime is given up: RetryGiveUpTimeout after it.
func (self *SmtpRetryPolicy) GiveUpTime(createTime time.Time) time.Time {
	return createTime.Add(self.settings.RetryGiveUpTimeout)
}

// The next try after a failure at now: the schedule's first slot after now, and true; or the give-up time and
// false once no slot is left before it, when the message ends with a DSN.
func (self *SmtpRetryPolicy) Next(createTime time.Time, now time.Time) (time.Time, bool) {
	giveUpTime := self.GiveUpTime(createTime)
	slot := createTime
	interval := self.settings.RetryFirstTimeout
	for {
		slot = slot.Add(interval)
		if !giveUpTime.After(slot) {
			return giveUpTime, false
		}
		if slot.After(now) {
			return slot, true
		}
		interval = min(2*interval, self.settings.RetryMaxTimeout)
	}
}

// The next try of a send held at now for wait, HALTED's, QUOTA's or TRY_LATER's retry_after_ms or KEYS's
// timeout: now plus wait, the schedule's next slot when wait is not positive, and false past the give-up time.
func (self *SmtpRetryPolicy) Hold(createTime time.Time, now time.Time, wait time.Duration) (time.Time, bool) {
	if wait <= 0 {
		return self.Next(createTime, now)
	}
	next := now.Add(wait)
	if giveUpTime := self.GiveUpTime(createTime); !giveUpTime.After(next) {
		return giveUpTime, false
	}
	return next, true
}

// The start of the UTC day after now's, when a message that spent its retry units today may try again.
func smtpNextUtcDay(now time.Time) time.Time {
	year, month, day := now.UTC().Date()
	return time.Date(year, month, day+1, 0, 0, 0, 0, time.UTC)
}

// One message's retry units in one UTC day.
type smtpRetryDayUnits struct {
	day   time.Time
	count int
}

// The connection units each message's retries spent today, by effect key. Safe for concurrent use.
type SmtpRetryUnits struct {
	settings *SmtpSenderSettings

	stateLock sync.Mutex
	units     map[string]smtpRetryDayUnits
}

// Empty counts under settings, which must have passed validate.
func NewSmtpRetryUnits(settings *SmtpSenderSettings) *SmtpRetryUnits {
	return &SmtpRetryUnits{settings: settings, units: map[string]smtpRetryDayUnits{}}
}

// The UTC day now falls in, as a time.
func smtpUtcDay(now time.Time) time.Time {
	year, month, day := now.UTC().Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

// Whether the message may spend one more retry unit today, and if not, when it may.
func (self *SmtpRetryUnits) Allows(effectKey []byte, now time.Time) (bool, time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	units, ok := self.units[string(effectKey)]
	if !ok || !units.day.Equal(smtpUtcDay(now)) || units.count < self.settings.RetryUnitsPerMessagePerDay {
		return true, time.Time{}
	}
	return false, smtpNextUtcDay(now)
}

// Counts one retry unit spent at now, and forgets the days before it.
func (self *SmtpRetryUnits) Spend(effectKey []byte, now time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	day := smtpUtcDay(now)
	for key, units := range self.units {
		if units.day.Before(day) {
			delete(self.units, key)
		}
	}
	units := self.units[string(effectKey)]
	if !units.day.Equal(day) {
		units = smtpRetryDayUnits{day: day}
	}
	units.count += 1
	self.units[string(effectKey)] = units
}
