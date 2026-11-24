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
	}
}
