package redissuite

import (
	"context"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

func TestFakeRedisConforms(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	redis := sidecartest.NewFakeRedis(t.Context(), clock, nil, nil, nil)
	t.Cleanup(redis.Close)
	Run(t, &Target{
		Redis:          redis,
		Pass:           clock.Advance,
		RegisterScript: redis.RegisterScript,
		EventTimeout:   10 * time.Second,
		PassBlockedRead: func(ctx context.Context, start func()) {
			timerCount := len(clock.PendingTimers())
			start()
			if err := clock.AwaitTimers(ctx, timerCount+1); err != nil {
				t.Error(err)
				return
			}
			clock.Advance(1 * time.Second)
		},
	})
	// the cross-slot cases break the rule on purpose, three times, and nothing else may
	if violations := redis.Violations(); len(violations) != 3 {
		t.Errorf("violations %v", violations)
	}
}
