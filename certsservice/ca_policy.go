// §13.8's order policy, pure on the times it is given, so a fake clock moves every rule (D-TLS-7):
//
//   - A new set, one no certificate was ever issued for, spends one unit of <root>'s budget at the CA
//     that orders it, under a cap below the CA's own (budget.go).
//   - A repeated set, at a CA whose duplicate-certificate limit the rule models, gets RepeatSetCount
//     orders refilling one per RepeatSetRefill, with no overrides; spent there, it moves to the next CA.
//   - An ARI renewal, or an order replacing a live certificate, skips every limit and every hold: it
//     goes to the CA of the certificate it replaces.
//   - A CA's Retry-After holds every order a limit counts until its time, and the next CA is tried; a
//     renewal or a revocation goes on.
//   - Failed authorizations hold a name inside LE's 5 per identifier per hour.
//
// A CA is chosen in the sidecar's order: LE, GTS, ZeroSSL, or for an ephemeral sidecar GTS, ZeroSSL, LE.

package certsservice

import (
	"slices"
	"time"
)

// A CA certs orders from, as network_tls_cert.ca holds it.
type CertsCa string

const (
	// Let's Encrypt, the tlsserver profile.
	CertsCaLetsEncrypt CertsCa = "letsencrypt"
	// Google Trust Services, with EAB.
	CertsCaGts CertsCa = "gts"
	// ZeroSSL, with EAB.
	CertsCaZeroSsl CertsCa = "zerossl"
)

func (self CertsCa) valid() bool {
	return self == CertsCaLetsEncrypt || self == CertsCaGts || self == CertsCaZeroSsl
}

// Which limits an order meets.
type CertsOrderKind string

const (
	// No certificate was ever issued for its set: <root>'s budget.
	CertsOrderNewSet CertsOrderKind = "new_set"
	// Its set had a certificate: the repeated-set rule.
	CertsOrderRepeatSet CertsOrderKind = "repeat_set"
	// It replaces a live certificate of its set: no limit.
	CertsOrderRenewal CertsOrderKind = "renewal"
)

// Why an order waits, a closed set of words a log and a metric may carry.
type CertsWaitReason string

const (
	// The new-set budget of every CA it may use is spent.
	CertsWaitBudget CertsWaitReason = "budget"
	// The repeated-set rule holds it at every CA that has the rule, and no other CA is open.
	CertsWaitRepeatSet CertsWaitReason = "repeat_set"
	// A CA's Retry-After holds it, and no other CA is open.
	CertsWaitCaHold CertsWaitReason = "ca_hold"
	// One of its names failed authorization too often within the hour.
	CertsWaitNameHold CertsWaitReason = "name_hold"
	// Its CSR no longer parses, or its predecessor's CA is unknown: it fails rather than waits.
	CertsWaitUnusable CertsWaitReason = "unusable"
)

// When the repeated-set rule next lets an order through, given the times of the set's earlier orders at
// one CA: a bucket of count that starts full and refills one per refill, each order taking one (LE's
// duplicate-certificate limit). fits is true when an order at now fits, and at is when one will.
func certsRepeatSetNext(orderTimes []time.Time, now time.Time, count int, refill time.Duration) (fits bool, at time.Time) {
	times := slices.Clone(orderTimes)
	slices.SortFunc(times, func(a time.Time, b time.Time) int { return a.Compare(b) })
	// the bucket as a level in refill units, so nothing rounds
	full := time.Duration(count) * refill
	level := full
	var last time.Time
	for index, orderTime := range times {
		if 0 < index {
			level = min(full, level+orderTime.Sub(last))
		}
		level -= refill
		last = orderTime
	}
	if 0 < len(times) {
		level = min(full, level+now.Sub(last))
	}
	if refill <= level {
		return true, now
	}
	return false, now.Add(refill - level)
}

// Whether a name with these failed authorizations holds at now, and until when: count failures inside
// window hold it until the oldest of the newest count leaves the window.
func certsNameHeldUntil(failureTimes []time.Time, now time.Time, count int, window time.Duration) (held bool, until time.Time) {
	recent := []time.Time{}
	for _, failureTime := range failureTimes {
		if now.Sub(failureTime) < window {
			recent = append(recent, failureTime)
		}
	}
	if len(recent) < count {
		return false, time.Time{}
	}
	slices.SortFunc(recent, func(a time.Time, b time.Time) int { return a.Compare(b) })
	return true, recent[len(recent)-count].Add(window)
}

// Whether a CA's hold, if it has one, still stands at now.
func certsCaHeld(holdUntil time.Time, now time.Time) bool {
	return !holdUntil.IsZero() && now.Before(holdUntil)
}
