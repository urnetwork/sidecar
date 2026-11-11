// MAIL-M8-02's one-time auth: RFC 6238's and RFC 4226's vectors from testdata/mail/totp.yml, embedded so the Worker
// leg runs them too, and the refusals of a VaultTotp a writer did not fill.

package sidecar

import (
	_ "embed"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// Embedded so a Worker, which has no file system, runs these too.
//
//go:embed testdata/mail/totp.yml
var mailTotpVectorsYaml string

// Reads totp.yml's one shape, a list of flat items under vectors:, and stops on any other line: the root links no
// YAML parser, and a line this skipped would be a vector that never ran.
func parseMailTotpVectors(t *testing.T) []map[string]string {
	t.Helper()
	items := []map[string]string{}
	inVectors := false
	for number, line := range strings.Split(mailTotpVectorsYaml, "\n") {
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case line == "vectors:":
			inVectors = true
			continue
		case !inVectors:
			t.Fatalf("totp.yml line %d: outside vectors:", number+1)
		}
		text, isItem := strings.CutPrefix(line, "  - ")
		if !isItem {
			var ok bool
			if text, ok = strings.CutPrefix(line, "    "); !ok || len(items) == 0 {
				t.Fatalf("totp.yml line %d: not an item's line", number+1)
			}
		} else {
			items = append(items, map[string]string{})
		}
		key, value, ok := strings.Cut(text, ": ")
		if !ok || key == "" {
			t.Fatalf("totp.yml line %d: not a key and value", number+1)
		}
		item := items[len(items)-1]
		if _, repeated := item[key]; repeated {
			t.Fatalf("totp.yml line %d: %s repeated", number+1, key)
		}
		item[key] = strings.Trim(value, `"`)
	}
	return items
}

// A vector's number, which must parse.
func mailTotpVectorNumber(t *testing.T, item map[string]string, key string) uint64 {
	t.Helper()
	number, err := strconv.ParseUint(item[key], 10, 64)
	if err != nil {
		t.Fatalf("%s: %s: %v", item["name"], key, err)
	}
	return number
}

// A VaultTotp every field of which is set, as a writer leaves one.
func testMailTotp(secret string) *protocol.VaultTotp {
	return &protocol.VaultTotp{Secret: []byte(secret), Algorithm: protocol.VaultTotpAlgorithm_VAULT_TOTP_SHA1, Digits: 6, Period: 30}
}

// Every code RFC 6238's Appendix B and RFC 4226's Appendix D publish, with the end of each period, under all three
// HMACs and both code lengths.
func TestMailTotpCodeMatchesTheRfcVectors(t *testing.T) {
	algorithms := map[string]protocol.VaultTotpAlgorithm{
		"sha1":   protocol.VaultTotpAlgorithm_VAULT_TOTP_SHA1,
		"sha256": protocol.VaultTotpAlgorithm_VAULT_TOTP_SHA256,
		"sha512": protocol.VaultTotpAlgorithm_VAULT_TOTP_SHA512,
	}
	items := parseMailTotpVectors(t)
	if len(items) != 28 {
		t.Fatalf("%d vectors, not RFC 6238's 18 and RFC 4226's 10", len(items))
	}
	for _, item := range items {
		algorithm, ok := algorithms[item["algorithm"]]
		if !ok {
			t.Fatalf("%s: algorithm %q", item["name"], item["algorithm"])
		}
		secret, err := hex.DecodeString(item["secret"])
		if err != nil {
			t.Fatalf("%s: %v", item["name"], err)
		}
		totp := &protocol.VaultTotp{
			Secret: secret, Algorithm: algorithm,
			Digits: uint32(mailTotpVectorNumber(t, item, "digits")), Period: uint32(mailTotpVectorNumber(t, item, "period")),
		}
		at := time.Unix(int64(mailTotpVectorNumber(t, item, "time")), 0)
		code, validUntil, err := MailTotpCode(totp, at)
		if err != nil {
			t.Errorf("%s: %v", item["name"], err)
			continue
		}
		if code != item["code"] {
			t.Errorf("%s: code %s, the RFC's %s", item["name"], code, item["code"])
		}
		if want := time.Unix(int64(mailTotpVectorNumber(t, item, "valid_until")), 0); !validUntil.Equal(want) {
			t.Errorf("%s: valid until %v, not %v", item["name"], validUntil, want)
		}
	}
}

// One code holds for its whole period and the next period's differs; the time a code holds until is the next one's
// start, in UTC.
func TestMailTotpCodeHoldsForItsPeriod(t *testing.T) {
	totp := testMailTotp("a synthetic totp secret")
	start := time.Unix(1793923200, 0)
	first, validUntil, err := MailTotpCode(totp, start)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Unix(1793923200+30, 0).UTC(); !validUntil.Equal(want) || validUntil.Location() != time.UTC {
		t.Fatalf("valid until %v", validUntil)
	}
	last, _, err := MailTotpCode(totp, start.Add(29*time.Second+999*time.Millisecond))
	if err != nil || last != first {
		t.Fatalf("the period's last moment: %s, not %s: %v", last, first, err)
	}
	next, nextUntil, err := MailTotpCode(totp, validUntil)
	if err != nil || next == first || !nextUntil.Equal(validUntil.Add(30*time.Second)) {
		t.Fatalf("the next period: %s until %v: %v", next, nextUntil, err)
	}
	if len(first) != 6 || strings.Trim(first, "0123456789") != "" {
		t.Fatalf("code %q is not six digits", first)
	}
}

// A VaultTotp with a field left out, or out of RFC 4226's range, gives no code, and its error names no secret.
func TestMailTotpCodeRefusesATotpAWriterDidNotFill(t *testing.T) {
	const secret = "a canary totp secret 5b0c"
	cases := []struct {
		name   string
		mutate func(totp *protocol.VaultTotp)
		at     time.Time
	}{
		{name: "no algorithm", mutate: func(totp *protocol.VaultTotp) {
			totp.Algorithm = protocol.VaultTotpAlgorithm_VAULT_TOTP_ALGORITHM_UNSPECIFIED
		}},
		{name: "an unknown algorithm", mutate: func(totp *protocol.VaultTotp) { totp.Algorithm = 99 }},
		{name: "no digits", mutate: func(totp *protocol.VaultTotp) { totp.Digits = 0 }},
		{name: "five digits", mutate: func(totp *protocol.VaultTotp) { totp.Digits = 5 }},
		{name: "nine digits", mutate: func(totp *protocol.VaultTotp) { totp.Digits = 9 }},
		{name: "no period", mutate: func(totp *protocol.VaultTotp) { totp.Period = 0 }},
		{name: "no secret", mutate: func(totp *protocol.VaultTotp) { totp.Secret = nil }},
		{name: "a secret past its bound", mutate: func(totp *protocol.VaultTotp) {
			totp.Secret = []byte(strings.Repeat(secret, 64))
		}},
		{name: "a time before the epoch", at: time.Unix(-1, 0)},
	}
	for _, c := range cases {
		totp := testMailTotp(secret)
		if c.mutate != nil {
			c.mutate(totp)
		}
		at := c.at
		if at.IsZero() {
			at = time.Unix(1793923200, 0)
		}
		code, _, err := MailTotpCode(totp, at)
		if !errors.Is(err, ErrMailTotpInvalid) || code != "" {
			t.Errorf("%s: %q, %v", c.name, code, err)
			continue
		}
		if strings.Contains(err.Error(), "canary") {
			t.Errorf("%s: the error names the secret", c.name)
		}
	}
	if _, _, err := MailTotpCode(nil, time.Unix(1793923200, 0)); !errors.Is(err, ErrMailTotpInvalid) {
		t.Errorf("no totp: %v", err)
	}
}

// The edges RFC 4226 §5.3 allows, 6 and 8 digits, and a 1 s and a long period, all give codes of their length.
func TestMailTotpCodeTakesTheRangeItAllows(t *testing.T) {
	for _, digits := range []uint32{6, 7, 8} {
		for _, period := range []uint32{1, 30, 86400} {
			totp := testMailTotp("a synthetic totp secret")
			totp.Digits, totp.Period = digits, period
			code, validUntil, err := MailTotpCode(totp, time.Unix(1793923201, 0))
			if err != nil || len(code) != int(digits) || validUntil.Unix()%int64(period) != 0 {
				t.Errorf("%d digits at a %d s period: %q until %v: %v", digits, period, code, validUntil, err)
			}
		}
	}
}
