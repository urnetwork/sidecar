// §13.8's policy rules, pure on the times they are given (TLS-M5-14): the repeated-set bucket at exactly
// its count and its 34 h refill, a name's hold inside LE's 5 per identifier per hour, a CA's hold, and
// the settings that carry them.
package certsservice

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var testPolicyStart = time.Date(2026, time.November, 2, 9, 0, 0, 0, time.UTC)

// Five orders at once fit, the sixth does not, and it fits exactly 34 h after the fifth; the bucket then
// gives one per 34 h, never a burst back.
func TestRepeatSetAllowsFiveThenOnePer34Hours(t *testing.T) {
	settings := DefaultCertsSettings()
	count, refill := settings.RepeatSetCount, settings.RepeatSetRefill
	if count != 5 || refill != 34*time.Hour {
		t.Fatalf("§13.8 gives 5 refilling one per 34 h, not %d per %v", count, refill)
	}
	orders := []time.Time{}
	for index := range count {
		fits, _ := certsRepeatSetNext(orders, testPolicyStart, count, refill)
		if !fits {
			t.Fatalf("order %d of %d refused", index+1, count)
		}
		orders = append(orders, testPolicyStart)
	}
	fits, at := certsRepeatSetNext(orders, testPolicyStart, count, refill)
	if fits || !at.Equal(testPolicyStart.Add(refill)) {
		t.Fatalf("the sixth: fits %t, at %s", fits, at)
	}
	if fits, _ := certsRepeatSetNext(orders, testPolicyStart.Add(refill-time.Nanosecond), count, refill); fits {
		t.Fatal("the sixth fits a nanosecond before the refill")
	}
	if fits, _ := certsRepeatSetNext(orders, testPolicyStart.Add(refill), count, refill); !fits {
		t.Fatal("the sixth does not fit at the refill")
	}
	orders = append(orders, testPolicyStart.Add(refill))
	fits, at = certsRepeatSetNext(orders, testPolicyStart.Add(refill), count, refill)
	if fits || !at.Equal(testPolicyStart.Add(2*refill)) {
		t.Fatalf("the seventh: fits %t, at %s", fits, at)
	}
	// a week of quiet fills the bucket to five again, and no further
	later := testPolicyStart.Add(30 * 24 * time.Hour)
	for index := range count {
		if fits, _ := certsRepeatSetNext(orders, later, count, refill); !fits {
			t.Fatalf("after a month, order %d refused", index+1)
		}
		orders = append(orders, later)
	}
	if fits, _ := certsRepeatSetNext(orders, later, count, refill); fits {
		t.Fatal("a month's quiet filled the bucket past five")
	}
}

// The order the orders come in changes nothing.
func TestRepeatSetReadsTimesInAnyOrder(t *testing.T) {
	ordered := []time.Time{testPolicyStart, testPolicyStart.Add(time.Hour), testPolicyStart.Add(2 * time.Hour)}
	shuffled := []time.Time{ordered[2], ordered[0], ordered[1]}
	now := testPolicyStart.Add(3 * time.Hour)
	fitsA, atA := certsRepeatSetNext(ordered, now, 3, 34*time.Hour)
	fitsB, atB := certsRepeatSetNext(shuffled, now, 3, 34*time.Hour)
	if fitsA != fitsB || !atA.Equal(atB) {
		t.Fatalf("%t %s and %t %s", fitsA, atA, fitsB, atB)
	}
}

// Four failures inside the hour hold a name until the oldest of them leaves it; three do not, and
// failures older than the hour count for nothing.
func TestNameHoldsInsideLetsEncryptsFivePerHour(t *testing.T) {
	settings := DefaultCertsSettings()
	count, window := settings.FailedAuthorizationCount, settings.FailedAuthorizationWindow
	if 5 <= count || window != time.Hour {
		t.Fatalf("a hold at %d per %v is not inside LE's 5 per hour", count, window)
	}
	failures := []time.Time{
		testPolicyStart.Add(-2 * time.Hour),
		testPolicyStart,
		testPolicyStart.Add(10 * time.Minute),
		testPolicyStart.Add(20 * time.Minute),
	}
	now := testPolicyStart.Add(30 * time.Minute)
	if held, _ := certsNameHeldUntil(failures, now, count, window); held {
		t.Fatal("three failures inside the hour hold the name")
	}
	failures = append(failures, testPolicyStart.Add(25*time.Minute))
	held, until := certsNameHeldUntil(failures, now, count, window)
	if !held || !until.Equal(testPolicyStart.Add(window)) {
		t.Fatalf("four failures: held %t until %s", held, until)
	}
	if held, _ := certsNameHeldUntil(failures, testPolicyStart.Add(window), count, window); held {
		t.Fatal("still held once the oldest failure left the hour")
	}
}

// A hold stands until its time and not at it.
func TestCaHoldEndsAtItsTime(t *testing.T) {
	until := testPolicyStart.Add(time.Hour)
	if !certsCaHeld(until, until.Add(-time.Nanosecond)) || certsCaHeld(until, until) || certsCaHeld(time.Time{}, testPolicyStart) {
		t.Fatal("a hold's edges")
	}
}

// D-TLS-7's orders: LE, then GTS, then ZeroSSL; an ephemeral sidecar GTS, then ZeroSSL, ahead of LE.
// LE's new-set cap sits below its 50 per 7 days, and LE alone carries the repeated-set rule.
func TestDefaultsHoldTheDesignsChoices(t *testing.T) {
	settings := DefaultCertsSettings()
	if order := settings.caOrder(false); len(order) != 3 || order[0] != CertsCaLetsEncrypt || order[1] != CertsCaGts || order[2] != CertsCaZeroSsl {
		t.Errorf("order %v", order)
	}
	if order := settings.caOrder(true); len(order) != 3 || order[0] != CertsCaGts || order[1] != CertsCaZeroSsl || order[2] != CertsCaLetsEncrypt {
		t.Errorf("ephemeral order %v", order)
	}
	letsEncrypt := settings.Cas[CertsCaLetsEncrypt]
	if 50 <= letsEncrypt.BudgetCap || letsEncrypt.BudgetWindow != 7*24*time.Hour || letsEncrypt.Profile != "tlsserver" || !letsEncrypt.RepeatSetLimited {
		t.Errorf("LE %+v", letsEncrypt)
	}
	if settings.Cas[CertsCaGts].RepeatSetLimited || settings.Cas[CertsCaZeroSsl].RepeatSetLimited || settings.Cas[CertsCaZeroSsl].BudgetCap != 0 {
		t.Error("only LE carries the repeated-set rule, and ZeroSSL has no cap")
	}
	if settings.RowRetention != 30*24*time.Hour || settings.BudgetTtl != 7*24*time.Hour {
		t.Errorf("rows %v, budget %v", settings.RowRetention, settings.BudgetTtl)
	}
}

// The defaults carry no production name, so a host that sets none cannot start, and each rule that
// would go unenforced is refused by name.
func TestValidateRefusesWhatLeavesARuleUnenforced(t *testing.T) {
	valid := func() *CertsSettings {
		settings := DefaultCertsSettings()
		settings.RootDomain = "root.example"
		return settings
	}
	if err := valid().Validate(); err != nil {
		t.Fatal(err)
	}
	if err := DefaultCertsSettings().Validate(); !errors.Is(err, ErrCertsSettingsRefused) {
		t.Fatalf("no root: %v", err)
	}
	for name, change := range map[string]func(settings *CertsSettings){
		"RootDomain":               func(settings *CertsSettings) { settings.RootDomain = "Root.Example" },
		"order is empty":           func(settings *CertsSettings) { settings.CaOrder = nil },
		"listed twice":             func(settings *CertsSettings) { settings.CaOrder = []CertsCa{CertsCaGts, CertsCaGts} },
		"has no settings":          func(settings *CertsSettings) { delete(settings.Cas, CertsCaZeroSsl) },
		"budget":                   func(settings *CertsSettings) { settings.Cas[CertsCaGts].BudgetWindow = 0 },
		"BudgetTtl is shorter":     func(settings *CertsSettings) { settings.BudgetTtl = time.Hour },
		"RepeatSetCount":           func(settings *CertsSettings) { settings.RepeatSetCount = 0 },
		"FailedAuthorizationCount": func(settings *CertsSettings) { settings.FailedAuthorizationCount = 0 },
		"RowRetention":             func(settings *CertsSettings) { settings.RowRetention = 0 },
		"CallTimeout":              func(settings *CertsSettings) { settings.CallTimeout = -time.Second },
	} {
		settings := valid()
		change(settings)
		err := settings.Validate()
		if !errors.Is(err, ErrCertsSettingsRefused) || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// An id carries the clock's millisecond, so an order's time and the policy's agree on a fake clock, and
// two ids of one millisecond still differ.
func TestCertIdsCarryTheClocksTime(t *testing.T) {
	at := testPolicyStart.Add(1234 * time.Millisecond)
	a, b := certsNewId(at), certsNewId(at)
	if !certsIdTime(a).Equal(at) || !certsIdTime(b).Equal(at) || a == b {
		t.Fatalf("%s and %s at %s", a, b, at)
	}
}
