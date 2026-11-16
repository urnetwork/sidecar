// §14.7's scripts (SMTP-M9-11): the twins agree with what the Lua is held to on fixed vectors
// (RunSmtpQuotaScriptSuite, which a real Redis runs on the Lua itself), and every script and call keeps
// §22.4's CROSSSLOT rule, one hash tag a call.

package smtpedgeservice_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/crossslot"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

func TestQuotaScriptTwinsRunTheSuite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	redis := sidecartest.NewFakeRedis(ctx, clock, nil, nil, nil)
	defer redis.Close()
	sidecartest.RegisterSmtpQuotaScripts(redis)
	sidecartest.RunSmtpQuotaScriptSuite(t, &sidecartest.SmtpQuotaScriptTarget{Redis: redis, Now: clock.Now})
	if violations := redis.Violations(); len(violations) != 0 {
		t.Fatalf("CROSSSLOT: %v", violations)
	}
}

func TestQuotaScriptsPassTheCrossslotLint(t *testing.T) {
	findings, err := crossslot.Check(".", ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		t.Errorf("CROSSSLOT: %s", finding)
	}
	// each family is one tag, so a network's counters share a slot and two networks' never need to
	for _, script := range []*sidecar.RedisScript{
		smtpedgeservice.SmtpQuotaReserveScript, smtpedgeservice.SmtpQuotaDebitScript, smtpedgeservice.SmtpQuotaCloseScript,
		smtpedgeservice.SmtpQuotaHaltScript, smtpedgeservice.SmtpHourCountScript, smtpedgeservice.SmtpHourUncountScript,
	} {
		if strings.Contains(script.Source, "KEYS[2]") {
			t.Errorf("%s names a second key", script.Name)
		}
	}
}
