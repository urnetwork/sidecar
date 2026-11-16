// The pure half of Team custom-domain certificates (TLS-M6-05; DESIGN-DETAILS 17.2.8, 17.2.11, 17.6): the replayed
// bucket's level and wait, never above a reference bucket fed the same spends; the failure backoff; the renew time
// spread across the ARI window over 10,000 ids; the custom branch's CSR test; and the settings' refusals.

package certsservice_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	mathrand "math/rand/v2"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
)

func TestCertsCustomBucketLevelAndWait(t *testing.T) {
	now := time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)
	set := certsservice.CertsCustomBucket{Capacity: 5, Refill: 34 * time.Hour}
	// empty start: a window with no spends is full
	if level := set.Level(nil, now); level != 5 {
		t.Fatalf("no spends: %v", level)
	}
	// four spends at once leave one; two are needed, one refill away
	spends := []time.Time{now, now, now, now}
	if level := set.Level(spends, now); level != 1 {
		t.Fatalf("four spends: %v", level)
	}
	if wait := set.Wait(spends, now, 2); wait != 34*time.Hour {
		t.Fatalf("the wait for two: %v", wait)
	}
	if wait := set.Wait(spends, now, 1); wait != 0 {
		t.Fatalf("the wait for one: %v", wait)
	}
	// the replay starts empty at the window's start, now − 5 × 34 h, so a refill later the burst still reads one: the
	// window's start moved by the refill the level would have gained (17.2.8: never above the truth)
	if level := set.Level(spends, now.Add(34*time.Hour)); level != 1 {
		t.Fatalf("a refill on: %v", level)
	}
	// a spend exactly at the window's start has left it, which is open there
	if level := set.Level(spends, now.Add(5*34*time.Hour)); level != 5 {
		t.Fatalf("a window on: %v", level)
	}
	if level := set.Level(spends, now.Add(30*24*time.Hour)); level != 5 {
		t.Fatalf("long after: %v", level)
	}
	// spread spends, one each refill: the empty start has the replay spend each token as it comes, so the level stays
	// at one where a bucket full at the window's start would hold four (question tls-m6-04-custom-bucket-empty-start)
	spread := []time.Time{now.Add(-3 * 34 * time.Hour), now.Add(-2 * 34 * time.Hour), now.Add(-34 * time.Hour), now}
	if level := set.Level(spread, now); level != 1 {
		t.Fatalf("spread spends: %v", level)
	}
	// spends outside the window count for nothing
	if level := set.Level([]time.Time{now.Add(-6 * 34 * time.Hour)}, now); level != 5 {
		t.Fatalf("an old spend: %v", level)
	}
}

// A reference bucket, full long before the window and fed the same spends, never holds less than the replay: the
// replay starts empty at the window's start, so it never counts more than the truth.
func TestCertsCustomBucketNeverAboveTheTruth(t *testing.T) {
	random := mathrand.New(mathrand.NewPCG(1, 2))
	bucket := certsservice.CertsCustomBucket{Capacity: 5, Refill: time.Hour}
	start := time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)
	for round := range 2000 {
		spends := []time.Time{}
		reference := float64(bucket.Capacity)
		at := start
		for range random.IntN(12) {
			step := time.Duration(random.IntN(int(3*time.Hour/time.Minute))) * time.Minute
			reference = min(float64(bucket.Capacity), reference+float64(step)/float64(bucket.Refill))
			at = at.Add(step)
			// the CA refuses a spend it cannot afford, so the truth never goes below empty
			if 1 <= reference {
				reference -= 1
				spends = append(spends, at)
			}
		}
		end := at.Add(time.Duration(random.IntN(180)) * time.Minute)
		reference = min(float64(bucket.Capacity), reference+float64(end.Sub(at))/float64(bucket.Refill))
		if level := bucket.Level(spends, end); reference+1e-9 < level {
			t.Fatalf("round %d: the replay holds %v, the truth %v", round, level, reference)
		}
	}
}

func TestCertsCustomFailureBackoffDoublesToItsCap(t *testing.T) {
	settings := certsservice.DefaultCertsCustomSettings()
	now := time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)
	failures := []time.Time{}
	want := []time.Duration{30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour, 8 * time.Hour, 16 * time.Hour, 24 * time.Hour, 24 * time.Hour}
	for index, backoff := range want {
		failures = append(failures, now)
		if wait := settings.FailureWait(failures, now); wait != backoff {
			t.Errorf("after %d failures: %v, want %v", index+1, wait, backoff)
		}
	}
	if wait := settings.FailureWait(nil, now); wait != 0 {
		t.Errorf("no failure: %v", wait)
	}
}

func TestCertsCustomRenewTimeSpreadsAcrossTheWindow(t *testing.T) {
	start := time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(48 * time.Hour)
	buckets := make([]int, 8)
	for range 10000 {
		row := &sidecar.TlsCertRecord{CertId: sidecar.NewId(), AriWindowStart: start, AriWindowEnd: end}
		at := certsservice.CertsCustomRenewTime(row, 2.0/3.0)
		if at.Before(start) || !at.Before(end) {
			t.Fatalf("%v outside the window", at)
		}
		buckets[int(at.Sub(start)*8/end.Sub(start))] += 1
	}
	for index, count := range buckets {
		// 1,250 each when uniform; a fifth either way is far outside chance for a hash
		if count < 1000 || 1500 < count {
			t.Errorf("an eighth of the window %d holds %d of 10,000", index, count)
		}
	}
	// no window: two thirds of the validity
	row := &sidecar.TlsCertRecord{CertId: sidecar.NewId(), NotBefore: start, NotAfter: start.Add(45 * 24 * time.Hour)}
	if at := certsservice.CertsCustomRenewTime(row, 2.0/3.0); !at.Equal(start.Add(30 * 24 * time.Hour)) {
		t.Errorf("with no window: %v", at)
	}
}

func TestCertsCustomCsrHostTakesOneNameUnderNoRoot(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr := func(names ...string) []byte {
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	if host, custom := certsservice.CertsCustomCsrHost(csr("www.customer.example"), []string{testRoot}); !custom || host != "www.customer.example" {
		t.Fatalf("a custom host: %q, %v", host, custom)
	}
	for _, der := range [][]byte{
		csr("*.net1."+testRoot, "net1."+testRoot),
		csr("net1." + testRoot),
		csr("www.customer.example", "api.customer.example"),
		csr("*.customer.example"),
		{1, 2, 3},
	} {
		if _, custom := certsservice.CertsCustomCsrHost(der, []string{testRoot}); custom {
			t.Errorf("a CSR read as custom")
		}
	}
}

func TestCertsCustomSettingsRefuseWhatLeavesARuleUnenforced(t *testing.T) {
	if err := certsservice.DefaultCertsCustomSettings().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(settings *certsservice.CertsCustomSettings){
		func(settings *certsservice.CertsCustomSettings) { settings.LockLease = 0 },
		func(settings *certsservice.CertsCustomSettings) { settings.SetReserve = settings.SetCap },
		func(settings *certsservice.CertsCustomSettings) { settings.HoldMax = settings.HoldDefault - 1 },
		func(settings *certsservice.CertsCustomSettings) { settings.LapseWarnFraction = 0.9 },
		func(settings *certsservice.CertsCustomSettings) { settings.ChainMaxCount = 0 },
	} {
		settings := certsservice.DefaultCertsCustomSettings()
		change(settings)
		if err := settings.Validate(); err == nil {
			t.Errorf("a refused value passed: %+v", settings)
		}
	}
}
