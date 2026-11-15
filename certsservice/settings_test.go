// The CA's numbers in certs' settings as Let's Encrypt's rate-limits and profiles pages gave them, read
// 2026-11-15 (QD-784), and an order's give-up age cut to its CA's order lifetime.
package certsservice

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// LE's tlsserver profile with its 8 h order lifetime, the budget's 40 under LE's 50 a registered domain
// in 7 days, an exact set's 5 with one back each 34 h, 4 failed authorizations under LE's 5 an hour, no
// order lifetime assumed for GTS or ZeroSSL, and a day's give-up age, which LE's lifetime cuts.
func TestDefaultsHoldTheCasNumbers(t *testing.T) {
	settings := DefaultCertsSettings()
	letsEncrypt := settings.Cas[CertsCaLetsEncrypt]
	if letsEncrypt.Profile != "tlsserver" || letsEncrypt.OrderLifetime != 8*time.Hour {
		t.Errorf("LE's profile %q, order lifetime %v", letsEncrypt.Profile, letsEncrypt.OrderLifetime)
	}
	if letsEncrypt.BudgetCap != 40 || letsEncrypt.BudgetWindow != 7*24*time.Hour || !letsEncrypt.RepeatSetLimited {
		t.Errorf("LE's budget %d in %v, repeated sets limited %v", letsEncrypt.BudgetCap, letsEncrypt.BudgetWindow, letsEncrypt.RepeatSetLimited)
	}
	if settings.RepeatSetCount != 5 || settings.RepeatSetRefill != 34*time.Hour {
		t.Errorf("repeated set %d, one back each %v", settings.RepeatSetCount, settings.RepeatSetRefill)
	}
	if settings.FailedAuthorizationCount != 4 || settings.FailedAuthorizationWindow != time.Hour {
		t.Errorf("failed authorizations %d in %v", settings.FailedAuthorizationCount, settings.FailedAuthorizationWindow)
	}
	gts := settings.Cas[CertsCaGts]
	if gts.BudgetCap != 90 || gts.BudgetWindow != time.Hour || gts.OrderLifetime != 0 || gts.Profile != "" {
		t.Errorf("GTS %+v", gts)
	}
	if zeroSsl := settings.Cas[CertsCaZeroSsl]; zeroSsl.BudgetCap != 0 || zeroSsl.OrderLifetime != 0 {
		t.Errorf("ZeroSSL %+v", zeroSsl)
	}
	if settings.OrderGiveUpAge != 24*time.Hour {
		t.Errorf("give-up age %v", settings.OrderGiveUpAge)
	}
	if settings.RenewalLifetimeFraction != 2.0/3.0 {
		t.Errorf("renewal fraction %v", settings.RenewalLifetimeFraction)
	}
}

// An order's give-up age is OrderGiveUpAge cut to its CA's order lifetime: LE's 8 h by default, a
// shorter lifetime moving it down and a longer one leaving OrderGiveUpAge, while a CA with no lifetime,
// or no settings, keeps OrderGiveUpAge.
func TestOrderGiveUpAgeFollowsTheCasOrderLifetime(t *testing.T) {
	cases := []struct {
		letsEncryptLifetime time.Duration
		giveUpAge           time.Duration
		ca                  CertsCa
		want                time.Duration
	}{
		{letsEncryptLifetime: 8 * time.Hour, giveUpAge: 24 * time.Hour, ca: CertsCaLetsEncrypt, want: 8 * time.Hour},
		{letsEncryptLifetime: 2 * time.Hour, giveUpAge: 24 * time.Hour, ca: CertsCaLetsEncrypt, want: 2 * time.Hour},
		{letsEncryptLifetime: 48 * time.Hour, giveUpAge: 24 * time.Hour, ca: CertsCaLetsEncrypt, want: 24 * time.Hour},
		{letsEncryptLifetime: 8 * time.Hour, giveUpAge: time.Hour, ca: CertsCaLetsEncrypt, want: time.Hour},
		{letsEncryptLifetime: 0, giveUpAge: 24 * time.Hour, ca: CertsCaLetsEncrypt, want: 24 * time.Hour},
		{letsEncryptLifetime: 2 * time.Hour, giveUpAge: 24 * time.Hour, ca: CertsCaGts, want: 24 * time.Hour},
		{letsEncryptLifetime: 2 * time.Hour, giveUpAge: 24 * time.Hour, ca: CertsCaZeroSsl, want: 24 * time.Hour},
		{letsEncryptLifetime: 2 * time.Hour, giveUpAge: 24 * time.Hour, ca: CertsCa("unlisted"), want: 24 * time.Hour},
	}
	for _, c := range cases {
		settings := DefaultCertsSettings()
		settings.Cas[CertsCaLetsEncrypt].OrderLifetime = c.letsEncryptLifetime
		settings.OrderGiveUpAge = c.giveUpAge
		if got := settings.orderGiveUpAge(c.ca); got != c.want {
			t.Errorf("%s with LE's lifetime %v and give-up age %v: %v, want %v", c.ca, c.letsEncryptLifetime, c.giveUpAge, got, c.want)
		}
	}
}

// A negative order lifetime is refused by name; zero, a lifetime not known here, passes.
func TestValidateRefusesANegativeOrderLifetime(t *testing.T) {
	settings := DefaultCertsSettings()
	settings.RootDomain = "root.example"
	settings.Cas[CertsCaLetsEncrypt].OrderLifetime = 0
	if err := settings.Validate(); err != nil {
		t.Fatalf("no lifetime: %v", err)
	}
	settings.Cas[CertsCaLetsEncrypt].OrderLifetime = -time.Second
	if err := settings.Validate(); !errors.Is(err, ErrCertsSettingsRefused) || !strings.Contains(err.Error(), "OrderLifetime") {
		t.Fatalf("a negative lifetime: %v", err)
	}
}
