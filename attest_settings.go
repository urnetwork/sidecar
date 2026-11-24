//go:build !ios_extension && !sidecar_http

// Attestation's settings, DESIGN-COMPUTE §5's, which ATTEST's tasks fill. Every limit, size, count, time, interval,
// threshold, retry or budget the component reads is a field here, its default set only in DefaultAttestSettings,
// protocol and format limits included; only identifiers stay constants (QD-702). The struct is created empty by the
// compute skeleton (CARCH-M11-01, CONTRACTS C-38), so no later task edits settings.go: SidecarSettings holds it, and
// DefaultSidecarSettings sets it from DefaultAttestSettings.
//
// The policy's parse limits are format limits: the pipeline that builds a policy (ATTEST-M12-02) reads the same
// fields, so a policy it signs is one every device parses. Changing one is a format change, never made on one side.
//
// Only the legs that run compute build this file. The forwarding leg, which runs only IP and port forwarding (owner
// decision 197), and the page Worker's sidecar_http leg, which gets no compute surface (DESIGN-COMPUTE §15.4), declare
// an empty stand-in instead (sidecar_compute_leg.go).

package sidecar

import (
	"time"
)

// DESIGN-COMPUTE §5, attestation and the signed compute policy.
type AttestSettings struct {
	// §5.4's compute-policy.json. The largest document a parse reads, in bytes: 1 MiB, a reading, since §5.4 sets
	// none: some thirty times what the launch's providers, profiles and §2.8's disclosure texts in a few locales take.
	// A larger one is refused before it is decoded. Non-positive refuses every policy.
	PolicyMaxByteCount int
	// The largest detached signature, <version>.json.sig, a parse reads, in bytes: 16 KiB, a reading: an armored
	// SSHSIG carrying an OpenSSH certificate of a 4096-bit RSA key takes under 4 KiB. Non-positive refuses every
	// signature.
	SignatureMaxByteCount int
	// The deepest the policy's JSON nests, objects and arrays counted alike: 32, a reading, three times the deepest
	// line §5.4 gives, so the search and services lines, which their owners decode, have room. Deeper is refused.
	PolicyMaxDepth int
	// The most members one object or entries one array of the policy holds: 4096, a reading, room for a revocation
	// list of chip identities and GPU serials a year of incidents could fill. More is refused, never cut.
	PolicyMaxListCount int
	// The longest string the policy holds, in bytes: 8 KiB, a reading: a disclosure's list item is a few plain
	// sentences (§2.8), well under 1 KiB in version 1's texts. Longer is refused, never cut.
	PolicyMaxStringByteCount int
	// The longest identifier the policy holds, in bytes: 256, a reading, room for a Hugging Face model id with its
	// revision: provider, profile and disclosure ids, model parts and provider model ids, locales, hosts, registers
	// and advisories. Longer is refused, never cut.
	PolicyMaxIdByteCount int
	// The longest grace a disclosure entry may carry, in days: 14, §2.8's grace, which the policy's signers may set
	// to 0 and no higher. A longer grace is refused, so no policy carries an old acknowledgment further than §2.8
	// lets it.
	DisclosureGraceMaxDays int
	// The longest an OpenSSH certificate of the compute-policy key or the staging key may be valid, from its
	// valid_after to its valid_before: a year, 366 days so a leap year's fits, as §5.4 has the release key certify
	// the key "for a year". A certificate valid longer, or forever, is refused. Non-positive refuses every one.
	CertificateMaxValidity time.Duration
	// The fewest bits an RSA key that signs a policy may have: 3072, a reading, NIST's floor past 2030 for keys that
	// last a year; Ed25519 and ECDSA keys, a hardware token's usual kinds, are not counted in bits. A smaller RSA key
	// is refused.
	RsaMinBitCount int
	// The largest state file the store reads back, in bytes: 4 MiB, room for a policy of PolicyMaxByteCount and its
	// signature as base64 with what the store keeps beside them. A larger one is dropped as unreadable.
	StateMaxByteCount int

	// §5.4's freshness tickets (ATTEST-M12-01). The largest ticket file, <day>.bin, a parse reads, in bytes: 16 KiB,
	// a reading: a ticket is under 100 bytes beside its armored signature, which SignatureMaxByteCount bounds.
	// Non-positive refuses every ticket.
	TicketMaxByteCount int
	// The longest window a ticket may carry, not_before to not_after: 72 hours, §5.4's, which a device enforces
	// whatever a signed ticket claims. Shorter refuses more; non-positive refuses every ticket.
	TicketMaxWindow time.Duration
	// The longest a batch may run from its sitting to its expiry: 14 days, §5.4's, which bounds how long a withheld
	// revocation lasts if the ticket host is taken too (IC-9). Non-positive refuses every ticket.
	TicketBatchMaxLifetime time.Duration
	// How far ahead of its not_before a ticket may arrive before the gate raises an alarm: an hour, §5.4's, past which
	// only a leak from the ticket host or a wrong clock explains it. An early ticket is refused whatever this is.
	TicketEarlyAlarm time.Duration
	// How long a staging build's policy stays current after the device first took it, whatever its not_after says: 7
	// days, §5.4's (D-ATTEST-8). Production builds do not read it.
	StagingPolicyLifetime time.Duration
	// The serving paths policies and tickets are fetched from, each <base>/<version>.json, its .sig and
	// <base>/tickets/<day>.bin (QD-1379): ur.io's, https://ur.io/compute/policy/v1 (§5.4's Distribution), and any
	// mirror after it. The signature is what is trusted, so a mirror widens nothing. Empty fetches nothing.
	FetchBaseUrls []string
	// The longest one fetch of one file takes: 30 s, a reading, room for a policy of PolicyMaxByteCount on a slow link.
	// Non-positive leaves a fetch to its caller's context alone.
	FetchTimeout time.Duration
	// The least time between two fetches a lapse asks for: a minute, a reading, so a burst of refused calls costs one
	// fetch (connect/CODESTYLE.md's retry budget). Non-positive lets each lapse ask one.
	FetchMinInterval time.Duration
	// How often the fetcher's own schedule runs once remote work has been asked for: 6 hours, a reading, four a
	// ticket's day, so a released ticket or a revocation's reaches a running device within hours, well inside the 72
	// hours §5.4 bounds. Non-positive runs no schedule, leaving fetches to the gate's refreshes.
	FetchInterval time.Duration
	// The most policy versions one fetch takes, one after another: 16, a reading, about four months of weekly
	// versions, so a device back from a long absence catches up in one pass and a hostile source cannot hold it in
	// one forever. Non-positive fetches no policy.
	FetchMaxPolicySteps int
}

// The component's defaults, the only place one is set.
func DefaultAttestSettings() *AttestSettings {
	return &AttestSettings{
		PolicyMaxByteCount:       1024 * 1024,
		SignatureMaxByteCount:    16 * 1024,
		PolicyMaxDepth:           32,
		PolicyMaxListCount:       4096,
		PolicyMaxStringByteCount: 8 * 1024,
		PolicyMaxIdByteCount:     256,
		DisclosureGraceMaxDays:   14,
		CertificateMaxValidity:   366 * 24 * time.Hour,
		RsaMinBitCount:           3072,
		StateMaxByteCount:        4 * 1024 * 1024,
		TicketMaxByteCount:       16 * 1024,
		TicketMaxWindow:          72 * time.Hour,
		TicketBatchMaxLifetime:   14 * 24 * time.Hour,
		TicketEarlyAlarm:         time.Hour,
		StagingPolicyLifetime:    7 * 24 * time.Hour,
		FetchBaseUrls:            []string{"https://ur.io/compute/policy/v1"},
		FetchTimeout:             30 * time.Second,
		FetchMinInterval:         time.Minute,
		FetchInterval:            6 * time.Hour,
		FetchMaxPolicySteps:      16,
	}
}
