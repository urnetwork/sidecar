// The CA's numbers in certs' settings as Let's Encrypt's rate-limits and profiles pages gave them, read
// 2026-11-15 (QD-784), an order's give-up age cut to its CA's order lifetime, and a failing name's backoff
// at a CA (QD-857).
package certsservice

import (
	"errors"
	"math"
	"slices"
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

// dns's refusal past dns_challenges_per_name_hour holds a name an hour when its 429 names no
// Retry-After, the cap's window (QD-1204), and a hold that is not positive is refused by name.
func TestNameWritesHoldDefaultsToTheCapsWindow(t *testing.T) {
	settings := DefaultCertsSettings()
	if settings.NameWritesHold != time.Hour {
		t.Fatalf("NameWritesHold %v", settings.NameWritesHold)
	}
	settings.RootDomain = "root.example"
	settings.NameWritesHold = 0
	if err := settings.Validate(); !errors.Is(err, ErrCertsSettingsRefused) || !strings.Contains(err.Error(), "NameWritesHold") {
		t.Fatalf("a hold of nothing: %v", err)
	}
}

// DESIGN-DETAILS 17.2.8's failure backoff, the owner's answer to how long a failing URnetwork-zone name
// waits at a CA (QD-857): 30 min after its first failure there, doubling with each one after, a day from
// the seventh on and no further however many come, each kept 8 d past its time.
func TestFailureBackoffDoublesToADayAndNoFurther(t *testing.T) {
	settings := DefaultCertsSettings()
	if settings.FailureBackoff != 30*time.Minute || settings.FailureBackoffMax != 24*time.Hour || settings.FailureBackoffRetention != 8*24*time.Hour {
		t.Fatalf("backoff %v to %v, kept %v", settings.FailureBackoff, settings.FailureBackoffMax, settings.FailureBackoffRetention)
	}
	for index, want := range []time.Duration{
		30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour, 8 * time.Hour, 16 * time.Hour, 24 * time.Hour, 24 * time.Hour,
	} {
		if got := settings.failureBackoffWait(index + 1); got != want {
			t.Errorf("failure %d waits %v, want %v", index+1, got, want)
		}
	}
	// a count past any doubling a duration holds stops at the cap rather than overflowing
	for _, failureCount := range []int{64, 1_000_000, math.MaxInt} {
		if got := settings.failureBackoffWait(failureCount); got != 24*time.Hour {
			t.Errorf("failure %d waits %v", failureCount, got)
		}
	}
	// a count below one waits as the first
	if got := settings.failureBackoffWait(0); got != 30*time.Minute {
		t.Errorf("no failure waits %v", got)
	}
	// a cap that is no doubling of the start still holds
	settings.FailureBackoffMax = 45 * time.Minute
	if got := settings.failureBackoffWait(2); got != 45*time.Minute {
		t.Errorf("the second failure under a 45 min cap waits %v", got)
	}
	// and a cap near the longest duration there is never overflows the doubling
	if got := certsFailureBackoffWait(math.MaxInt, time.Nanosecond, math.MaxInt64); got != math.MaxInt64 {
		t.Errorf("under the longest cap: %v", got)
	}
	if got := certsFailureBackoffWait(63, time.Nanosecond, math.MaxInt64); got != time.Duration(1)<<62 {
		t.Errorf("the 63rd failure from a nanosecond: %v", got)
	}
}

// A backoff that would hold nothing, or one longer than its own cap, is refused by name.
func TestValidateRefusesABackoffThatHoldsNothing(t *testing.T) {
	for name, change := range map[string]func(settings *CertsSettings){
		"FailureBackoff is not positive":                  func(settings *CertsSettings) { settings.FailureBackoff = 0 },
		"FailureBackoffMax is not positive":               func(settings *CertsSettings) { settings.FailureBackoffMax = -time.Second },
		"FailureBackoffRetention":                         func(settings *CertsSettings) { settings.FailureBackoffRetention = 0 },
		"FailureBackoff is longer than FailureBackoffMax": func(settings *CertsSettings) { settings.FailureBackoff = 25 * time.Hour },
	} {
		settings := DefaultCertsSettings()
		settings.RootDomain = "root.example"
		change(settings)
		if err := settings.Validate(); !errors.Is(err, ErrCertsSettingsRefused) || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A name's backoff holds its orders at its own CA alone, until its time and not at it, and a set waits for
// the latest of its names' times.
func TestNameBackoffHoldsAtItsCaUntilItsTime(t *testing.T) {
	backoffs := []*CertsNameBackoff{
		{Name: "a.root.example", Ca: CertsCaLetsEncrypt, FailureCount: 1, NextOrderTime: testPolicyStart.Add(time.Hour)},
		{Name: "*.a.root.example", Ca: CertsCaLetsEncrypt, FailureCount: 2, NextOrderTime: testPolicyStart.Add(2 * time.Hour)},
		{Name: "a.root.example", Ca: CertsCaGts, FailureCount: 1, NextOrderTime: testPolicyStart.Add(3 * time.Hour)},
	}
	for _, c := range []struct {
		ca   CertsCa
		at   time.Time
		want time.Time
	}{
		{ca: CertsCaLetsEncrypt, at: testPolicyStart, want: testPolicyStart.Add(2 * time.Hour)},
		{ca: CertsCaLetsEncrypt, at: testPolicyStart.Add(90 * time.Minute), want: testPolicyStart.Add(2 * time.Hour)},
		{ca: CertsCaLetsEncrypt, at: testPolicyStart.Add(2*time.Hour - time.Nanosecond), want: testPolicyStart.Add(2 * time.Hour)},
		{ca: CertsCaLetsEncrypt, at: testPolicyStart.Add(2 * time.Hour), want: time.Time{}},
		{ca: CertsCaGts, at: testPolicyStart.Add(2 * time.Hour), want: testPolicyStart.Add(3 * time.Hour)},
		{ca: CertsCaZeroSsl, at: testPolicyStart, want: time.Time{}},
	} {
		if got := certsNameBackoffUntil(backoffs, c.ca, c.at); !got.Equal(c.want) {
			t.Errorf("%s at %v: %v, want %v", c.ca, c.at.Sub(testPolicyStart), got, c.want)
		}
	}
	if got := certsNameBackoffUntil(nil, CertsCaLetsEncrypt, testPolicyStart); !got.IsZero() {
		t.Errorf("no backoff holds until %v", got)
	}
}

// A failure counts against the names of the order the CA refused, or all of them when it refused none of
// them, and never against a name the order does not hold.
func TestRefusedNamesAreTheOrdersOwn(t *testing.T) {
	csrNames := []string{"*.a.root.example", "a.root.example"}
	for _, c := range []struct {
		refused []string
		want    []string
	}{
		{refused: []string{"a.root.example"}, want: []string{"a.root.example"}},
		{refused: []string{"a.root.example", "*.a.root.example"}, want: csrNames},
		{refused: []string{"b.root.example", "*.a.root.example"}, want: []string{"*.a.root.example"}},
		{refused: []string{"b.root.example"}, want: csrNames},
		{refused: nil, want: csrNames},
	} {
		if got := certsRefusedNames(csrNames, c.refused); !slices.Equal(got, c.want) {
			t.Errorf("refused %v: %v, want %v", c.refused, got, c.want)
		}
	}
}
