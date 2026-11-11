//go:build !ios_extension

// A vault entry's one-time auth (§15.8, R-MAIL-4; MAIL-M8-02): RFC 6238's TOTP, which is RFC 4226 §5's HOTP over the
// count of period-second steps since the Unix epoch (T0 = 0), under HMAC-SHA-1, HMAC-SHA-256 or HMAC-SHA-512 as the
// entry's totp names. A writer sets every field of a VaultTotp (MAIL-FORMAT.md), so one that leaves a field out is
// refused rather than defaulted: 6 to 8 digits (RFC 4226 §5.3), a positive period, a secret of at least one byte. The
// secret is the HMAC key: it reaches testHookSecret before its first use and never a log or an error (I-7).
//
// MAIL-M8-03's OneTimeCodes merges these with i/'s one_time_code. On every leg but the extension's. Package-level
// functions are safe for concurrent use.

package sidecar

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A VaultTotp no code comes from: a field left out or out of RFC 4226's range. The error names no value.
var ErrMailTotpInvalid = errors.New("mail totp invalid")

// RFC 4226 §5.3's code lengths, and a secret's bound: format values.
const (
	mailTotpMinDigitCount = 6
	mailTotpMaxDigitCount = 8
	// RFC 4226 §4's R6 asks 128 bits and recommends 160; sites hand out 80, so any non-empty key up to this is taken.
	mailTotpSecretMaxByteCount = 1024
)

// The code for at, and when it stops being the code: the end of at's period, after which the next period's holds.
func MailTotpCode(totp *protocol.VaultTotp, at time.Time) (string, time.Time, error) {
	if err := mailTotpCheck(totp); err != nil {
		return "", time.Time{}, err
	}
	unixSeconds := at.Unix()
	if unixSeconds < 0 {
		return "", time.Time{}, fmt.Errorf("%w: a time before the epoch", ErrMailTotpInvalid)
	}
	period := uint64(totp.GetPeriod())
	counter := uint64(unixSeconds) / period
	if math.MaxInt64/period < counter+1 {
		return "", time.Time{}, fmt.Errorf("%w: a time past the last period", ErrMailTotpInvalid)
	}
	var newHash func() hash.Hash
	switch totp.GetAlgorithm() {
	case protocol.VaultTotpAlgorithm_VAULT_TOTP_SHA1:
		newHash = sha1.New
	case protocol.VaultTotpAlgorithm_VAULT_TOTP_SHA256:
		newHash = sha256.New
	case protocol.VaultTotpAlgorithm_VAULT_TOTP_SHA512:
		newHash = sha512.New
	}
	secret := totp.GetSecret()
	testHookSecret("vault_totp_secret", secret)
	mac := hmac.New(newHash, secret)
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac.Write(message[:])
	sum := mac.Sum(nil)
	// RFC 4226 §5.4's dynamic truncation: 31 bits at the offset the last byte's low nibble names
	offset := sum[len(sum)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1)
	for range totp.GetDigits() {
		modulus *= 10
	}
	code := fmt.Sprintf("%0*d", totp.GetDigits(), truncated%modulus)
	validUntil := time.Unix(int64((counter+1)*period), 0).UTC()
	return code, validUntil, nil
}

// ErrMailTotpInvalid unless every field is set and in range.
func mailTotpCheck(totp *protocol.VaultTotp) error {
	if totp == nil {
		return fmt.Errorf("%w: none", ErrMailTotpInvalid)
	}
	switch totp.GetAlgorithm() {
	case protocol.VaultTotpAlgorithm_VAULT_TOTP_SHA1, protocol.VaultTotpAlgorithm_VAULT_TOTP_SHA256, protocol.VaultTotpAlgorithm_VAULT_TOTP_SHA512:
	default:
		return fmt.Errorf("%w: algorithm %d", ErrMailTotpInvalid, totp.GetAlgorithm())
	}
	if totp.GetDigits() < mailTotpMinDigitCount || mailTotpMaxDigitCount < totp.GetDigits() {
		return fmt.Errorf("%w: %d digits", ErrMailTotpInvalid, totp.GetDigits())
	}
	if totp.GetPeriod() == 0 {
		return fmt.Errorf("%w: no period", ErrMailTotpInvalid)
	}
	if len(totp.GetSecret()) == 0 || mailTotpSecretMaxByteCount < len(totp.GetSecret()) {
		return fmt.Errorf("%w: a secret of %d bytes", ErrMailTotpInvalid, len(totp.GetSecret()))
	}
	return nil
}
