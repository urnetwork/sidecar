// smtpedgeservice's quota scripts on a Redis: the twins on FakeRedis at T2, the Lua on a real Redis
// wherever one is hosted, through the same cases, so the twins stay what the Lua does (D-TEST-2; §14.7's
// "fake and Lua agree on fixed vectors"). Each case runs on keys of its own under a tag of the run's own,
// and judges what the scripts answer and the counts they leave, never a day's number or a time, which
// differ between a fake clock and a real one.

package sidecartest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// Where the suite runs.
type SmtpQuotaScriptTarget struct {
	Redis sidecar.Redis
	// The time the target's scripts read as TIME: the fake's clock, or real time.
	Now func() time.Time
}

// One reserve script answer.
type smtpQuotaSuiteReserve struct {
	code       int64
	retryMs    int64
	reason     string
	burstField string
}

// The limits a case reserves under: a Pro day, unless a case changes one.
type smtpQuotaSuiteLimits struct {
	connectionsPerDay    int64
	recipientsPerDay     int64
	recipientsPerMessage int64
	messageBytes         int64
	bytesPerDay          int64
	burst                int64
	burstWindowMs        int64
	concurrent           int64
}

func defaultSmtpQuotaSuiteLimits() smtpQuotaSuiteLimits {
	return smtpQuotaSuiteLimits{
		connectionsPerDay:    200,
		recipientsPerDay:     1000,
		recipientsPerMessage: 50,
		messageBytes:         25 * 1024 * 1024,
		bytesPerDay:          1024 * 1024 * 1024,
		burst:                50,
		burstWindowMs:        10 * 60 * 1000,
		concurrent:           4,
	}
}

// One case's key and calls.
type smtpQuotaSuiteCase struct {
	ctx    context.Context
	target *SmtpQuotaScriptTarget
	key    string
}

func (self *smtpQuotaSuiteCase) reserve(member string, label string, recipients int64, messageBytes int64, limits smtpQuotaSuiteLimits) (*smtpQuotaSuiteReserve, error) {
	reply, err := self.target.Redis.RunScript(self.ctx, smtpedgeservice.SmtpQuotaReserveScript, []string{self.key}, []string{
		member, label, strconv.FormatInt(recipients, 10), strconv.FormatInt(messageBytes, 10),
		strconv.FormatInt(limits.connectionsPerDay, 10), strconv.FormatInt(limits.recipientsPerDay, 10),
		strconv.FormatInt(limits.recipientsPerMessage, 10), strconv.FormatInt(limits.messageBytes, 10),
		strconv.FormatInt(limits.bytesPerDay, 10), strconv.FormatInt(limits.burst, 10),
		strconv.FormatInt(limits.burstWindowMs, 10), strconv.FormatInt(limits.concurrent, 10),
		strconv.FormatInt((5 * time.Minute).Milliseconds(), 10), strconv.FormatInt((48 * time.Hour).Milliseconds(), 10),
	})
	if err != nil {
		return nil, err
	}
	if reply.Kind != sidecar.RedisReplyArray || len(reply.Replies) != 5 {
		return nil, fmt.Errorf("a reserve reply of shape %+v", reply)
	}
	return &smtpQuotaSuiteReserve{
		code:       reply.Replies[0].Integer,
		retryMs:    reply.Replies[1].Integer,
		reason:     string(reply.Replies[3].Bulk),
		burstField: string(reply.Replies[4].Bulk),
	}, nil
}

// The day a reserve counts on, as the script computes it from the target's clock.
func (self *smtpQuotaSuiteCase) day() string {
	return strconv.FormatInt(self.target.Now().UnixMilli()/86400000, 10)
}

func (self *smtpQuotaSuiteCase) integer(script *sidecar.RedisScript, keys []string, args ...string) (int64, error) {
	reply, err := self.target.Redis.RunScript(self.ctx, script, keys, args)
	if err != nil {
		return 0, err
	}
	if reply.Kind != sidecar.RedisReplyInteger {
		return 0, fmt.Errorf("a reply of shape %+v", reply)
	}
	return reply.Integer, nil
}

func (self *smtpQuotaSuiteCase) debit(member string, recipients int64) (int64, error) {
	return self.integer(smtpedgeservice.SmtpQuotaDebitScript, []string{self.key}, member, self.day(), strconv.FormatInt(recipients, 10),
		strconv.FormatInt((5*time.Minute).Milliseconds(), 10), strconv.FormatInt((48*time.Hour).Milliseconds(), 10))
}

func (self *smtpQuotaSuiteCase) close(member string, bytes int64) error {
	_, err := self.integer(smtpedgeservice.SmtpQuotaCloseScript, []string{self.key}, member, self.day(), strconv.FormatInt(bytes, 10),
		strconv.FormatInt((48*time.Hour).Milliseconds(), 10))
	return err
}

func (self *smtpQuotaSuiteCase) halt(field string, end time.Time) (int64, error) {
	return self.integer(smtpedgeservice.SmtpQuotaHaltScript, []string{self.key}, field, strconv.FormatInt(end.UnixMilli(), 10),
		strconv.FormatInt((48*time.Hour).Milliseconds(), 10))
}

func (self *smtpQuotaSuiteCase) field(field string) (string, error) {
	value, _, err := self.target.Redis.HashGet(self.ctx, self.key, field)
	return string(value), err
}

// Reserves and expects the answer's code and reason.
func (self *smtpQuotaSuiteCase) expect(member string, label string, recipients int64, messageBytes int64, limits smtpQuotaSuiteLimits, code int64, reason string) (*smtpQuotaSuiteReserve, error) {
	got, err := self.reserve(member, label, recipients, messageBytes, limits)
	if err != nil {
		return nil, err
	}
	if got.code != code || got.reason != reason {
		return nil, fmt.Errorf("reserve of %s answered %d %q, want %d %q", member, got.code, got.reason, code, reason)
	}
	return got, nil
}

// The suite's cases, each returning its first failure.
var smtpQuotaSuiteCases = []struct {
	name string
	run  func(c *smtpQuotaSuiteCase) error
}{
	{name: "a reservation within every limit takes a burst token", run: func(c *smtpQuotaSuiteCase) error {
		got, err := c.expect("m1", "", 3, 1000, defaultSmtpQuotaSuiteLimits(), 1, "")
		if err != nil {
			return err
		}
		if got.burstField == "" {
			return fmt.Errorf("no burst field named")
		}
		if value, err := c.field(got.burstField); err != nil || value != "1" {
			return fmt.Errorf("burst field holds %q, %v", value, err)
		}
		if member, err := c.field("cc:m1"); err != nil || member != c.day()+":3:0" {
			return fmt.Errorf("member holds %q, %v", member, err)
		}
		return nil
	}},
	{name: "the per-message caps refuse and take no burst token", run: func(c *smtpQuotaSuiteCase) error {
		limits := defaultSmtpQuotaSuiteLimits()
		limits.burst = 1
		if _, err := c.expect("m1", "", limits.recipientsPerMessage+1, 1, limits, 3, "recipients_per_message"); err != nil {
			return err
		}
		if _, err := c.expect("m2", "", 1, limits.messageBytes+1, limits, 3, "message_bytes"); err != nil {
			return err
		}
		// the one token is still there
		_, err := c.expect("m3", "", 1, 1, limits, 1, "")
		return err
	}},
	{name: "concurrency counts live members and heals when one ends", run: func(c *smtpQuotaSuiteCase) error {
		limits := defaultSmtpQuotaSuiteLimits()
		limits.concurrent = 1
		if _, err := c.expect("m1", "", 1, 1, limits, 1, ""); err != nil {
			return err
		}
		if _, err := c.expect("m2", "", 1, 1, limits, 3, "concurrent_connections"); err != nil {
			return err
		}
		if err := c.close("m1", 0); err != nil {
			return err
		}
		_, err := c.expect("m3", "", 1, 1, limits, 1, "")
		return err
	}},
	{name: "a debit counts once", run: func(c *smtpQuotaSuiteCase) error {
		if _, err := c.expect("m1", "", 4, 1, defaultSmtpQuotaSuiteLimits(), 1, ""); err != nil {
			return err
		}
		for i, want := range []int64{1, 0} {
			if got, err := c.debit("m1", 4); err != nil || got != want {
				return fmt.Errorf("debit %d answered %d, %v", i, got, err)
			}
		}
		if connections, err := c.field("c:" + c.day()); err != nil || connections != "1" {
			return fmt.Errorf("connections %q, %v", connections, err)
		}
		if recipients, err := c.field("r:" + c.day()); err != nil || recipients != "4" {
			return fmt.Errorf("recipients %q, %v", recipients, err)
		}
		if member, err := c.field("cc:m1"); err != nil || member != c.day()+":4:1" {
			return fmt.Errorf("member holds %q, %v", member, err)
		}
		return nil
	}},
	{name: "the day's connections count debits and live reservations", run: func(c *smtpQuotaSuiteCase) error {
		limits := defaultSmtpQuotaSuiteLimits()
		limits.connectionsPerDay = 2
		if _, err := c.expect("m1", "", 1, 1, limits, 1, ""); err != nil {
			return err
		}
		if _, err := c.debit("m1", 1); err != nil {
			return err
		}
		if err := c.close("m1", 100); err != nil {
			return err
		}
		if _, err := c.expect("m2", "", 1, 1, limits, 1, ""); err != nil {
			return err
		}
		got, err := c.expect("m3", "", 1, 1, limits, 3, "connections_per_day")
		if err != nil {
			return err
		}
		if got.retryMs <= 0 || 24*60*60*1000 < got.retryMs {
			return fmt.Errorf("retry %d ms, not until tomorrow", got.retryMs)
		}
		// a reservation returned unused frees its unit
		if err := c.close("m2", 0); err != nil {
			return err
		}
		_, err = c.expect("m4", "", 1, 1, limits, 1, "")
		return err
	}},
	{name: "the day's recipients count reservations", run: func(c *smtpQuotaSuiteCase) error {
		limits := defaultSmtpQuotaSuiteLimits()
		limits.recipientsPerDay = 10
		if _, err := c.expect("m1", "", 6, 1, limits, 1, ""); err != nil {
			return err
		}
		if _, err := c.expect("m2", "", 5, 1, limits, 3, "recipients_per_day"); err != nil {
			return err
		}
		_, err := c.expect("m3", "", 4, 1, limits, 1, "")
		return err
	}},
	{name: "the day's bytes refuse once passed, at close", run: func(c *smtpQuotaSuiteCase) error {
		limits := defaultSmtpQuotaSuiteLimits()
		limits.bytesPerDay = 1000
		if _, err := c.expect("m1", "", 1, 1, limits, 1, ""); err != nil {
			return err
		}
		if err := c.close("m1", 1500); err != nil {
			return err
		}
		if bytes, err := c.field("b:" + c.day()); err != nil || bytes != "1500" {
			return fmt.Errorf("bytes %q, %v", bytes, err)
		}
		_, err := c.expect("m2", "", 1, 1, limits, 3, "bytes_per_day")
		return err
	}},
	{name: "the burst refuses past its window's tokens", run: func(c *smtpQuotaSuiteCase) error {
		limits := defaultSmtpQuotaSuiteLimits()
		limits.burst = 2
		for _, member := range []string{"m1", "m2"} {
			if _, err := c.expect(member, "", 1, 1, limits, 1, ""); err != nil {
				return err
			}
		}
		got, err := c.expect("m3", "", 1, 1, limits, 3, "burst")
		if err != nil {
			return err
		}
		if got.retryMs <= 0 || limits.burstWindowMs < got.retryMs {
			return fmt.Errorf("retry %d ms, past the window", got.retryMs)
		}
		return nil
	}},
	{name: "a network's halt and a label's", run: func(c *smtpQuotaSuiteCase) error {
		end := c.target.Now().Add(time.Hour)
		if written, err := c.halt("h:otter-4821", end); err != nil || written != 1 {
			return fmt.Errorf("label halt written %d, %v", written, err)
		}
		if _, err := c.expect("m1", "otter-4821", 1, 1, defaultSmtpQuotaSuiteLimits(), 2, "label_halt"); err != nil {
			return err
		}
		if _, err := c.expect("m2", "heron-1234", 1, 1, defaultSmtpQuotaSuiteLimits(), 1, ""); err != nil {
			return err
		}
		if written, err := c.halt("h", end); err != nil || written != 1 {
			return fmt.Errorf("network halt written %d, %v", written, err)
		}
		if written, err := c.halt("h", end.Add(-time.Minute)); err != nil || written != 0 {
			return fmt.Errorf("an earlier halt written %d, %v", written, err)
		}
		if written, err := c.halt("h", c.target.Now().Add(-time.Minute)); err != nil || written != 0 {
			return fmt.Errorf("an ended halt written %d, %v", written, err)
		}
		got, err := c.expect("m3", "", 1, 1, defaultSmtpQuotaSuiteLimits(), 2, "halt")
		if err != nil {
			return err
		}
		if got.retryMs <= 0 || time.Hour.Milliseconds() < got.retryMs {
			return fmt.Errorf("retry %d ms, past the halt", got.retryMs)
		}
		return nil
	}},
	{name: "an hour counter refuses past its cap and takes back", run: func(c *smtpQuotaSuiteCase) error {
		counter := c.key + "h"
		for i, want := range [][2]int64{{1, 1}, {1, 2}, {0, 2}} {
			reply, err := c.target.Redis.RunScript(c.ctx, smtpedgeservice.SmtpHourCountScript, []string{counter}, []string{"2", "7200000"})
			if err != nil {
				return err
			}
			if reply.Kind != sidecar.RedisReplyArray || len(reply.Replies) != 2 || reply.Replies[0].Integer != want[0] || reply.Replies[1].Integer != want[1] {
				return fmt.Errorf("count %d answered %+v, want %v", i, reply, want)
			}
		}
		if got, err := c.integer(smtpedgeservice.SmtpHourUncountScript, []string{counter}); err != nil || got != 1 {
			return fmt.Errorf("uncount answered %d, %v", got, err)
		}
		return nil
	}},
}

// Runs every case on target, each on keys of its own.
func RunSmtpQuotaScriptSuite(t *testing.T, target *SmtpQuotaScriptTarget) {
	t.Helper()
	runOctets := make([]byte, 4)
	rand.Read(runOctets)
	run := hex.EncodeToString(runOctets)
	for i, suiteCase := range smtpQuotaSuiteCases {
		c := &smtpQuotaSuiteCase{ctx: t.Context(), target: target, key: fmt.Sprintf("{smqsuite_%s_%d}", run, i)}
		if err := suiteCase.run(c); err != nil {
			t.Errorf("%s: %v", suiteCase.name, err)
		}
	}
}
