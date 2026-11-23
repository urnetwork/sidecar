package evsservice

// QD-702's bounds: each ceiling or floor a design argument rests on is an EvsSettings field at the design's value,
// which Validate holds the setting it bounds to and requires positive.

import (
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// Each bound's default is the design's value, and the defaults validate.
func TestEvsSettingsBoundsAreTheDesignsValues(t *testing.T) {
	settings := DefaultEvsSettings()
	bounds := []struct {
		name  string
		value time.Duration
		want  time.Duration
	}{
		{name: "RepoCacheMaxTtl", value: settings.RepoCacheMaxTtl, want: 5 * time.Second},
		{name: "HeadCacheMaxServeAge", value: settings.HeadCacheMaxServeAge, want: 10 * time.Minute},
		{name: "FoldMaxStaleDeadline", value: settings.FoldMaxStaleDeadline, want: 15 * time.Second},
		{name: "FoldMinCollectMargin", value: settings.FoldMinCollectMargin, want: 150 * time.Millisecond},
		{name: "PushMaxStepSevenWindow", value: settings.PushMaxStepSevenWindow, want: 5 * time.Second},
		{name: "PushMinFenceMargin", value: settings.PushMinFenceMargin, want: 100 * time.Millisecond},
		{name: "CopyMaxHeadRereadInterval", value: settings.CopyMaxHeadRereadInterval, want: 5 * time.Second},
		{name: "SlotMinSettleAge", value: settings.SlotMinSettleAge, want: sidecar.BlobUnmodifiedSlack + time.Second},
	}
	for _, bound := range bounds {
		if bound.value != bound.want {
			t.Errorf("%s %s, want %s", bound.name, bound.value, bound.want)
		}
	}
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
}

// A setting past its ceiling or below its floor is refused, a bound lowered under its setting holds it, and a bound
// that is not positive is refused.
func TestEvsSettingsRefuseASettingPastItsBound(t *testing.T) {
	cases := []struct {
		name   string
		adjust func(settings *EvsSettings)
	}{
		{name: "repo/ cached past its ceiling", adjust: func(settings *EvsSettings) { settings.RepoCacheTtl = settings.RepoCacheMaxTtl + time.Millisecond }},
		{name: "a lowered repo/ ceiling", adjust: func(settings *EvsSettings) { settings.RepoCacheMaxTtl = settings.RepoCacheTtl - time.Millisecond }},
		{name: "a head served past its ceiling", adjust: func(settings *EvsSettings) {
			settings.HeadCacheServeAge = settings.HeadCacheMaxServeAge + time.Millisecond
		}},
		{name: "a fold deadline past its ceiling", adjust: func(settings *EvsSettings) {
			settings.FoldStaleDeadline = settings.FoldMaxStaleDeadline + time.Millisecond
		}},
		{name: "a collect margin below its floor", adjust: func(settings *EvsSettings) {
			settings.FoldCollectMargin = settings.FoldMinCollectMargin - time.Millisecond
		}},
		{name: "step 7's window past its ceiling", adjust: func(settings *EvsSettings) {
			settings.PushStepSevenWindow = settings.PushMaxStepSevenWindow + time.Millisecond
		}},
		{name: "a fence margin below its floor", adjust: func(settings *EvsSettings) { settings.PushFenceMargin = settings.PushMinFenceMargin - time.Millisecond }},
		{name: "a copy's reread past its ceiling", adjust: func(settings *EvsSettings) {
			settings.CopyHeadRereadInterval = settings.CopyMaxHeadRereadInterval + time.Millisecond
		}},
		{name: "a slot's settle age below its floor", adjust: func(settings *EvsSettings) { settings.SlotSettleAge = settings.SlotMinSettleAge - time.Millisecond }},
		{name: "no repo/ ceiling", adjust: func(settings *EvsSettings) { settings.RepoCacheMaxTtl = 0 }},
		{name: "no head ceiling", adjust: func(settings *EvsSettings) { settings.HeadCacheMaxServeAge = 0 }},
		{name: "no fold deadline ceiling", adjust: func(settings *EvsSettings) { settings.FoldMaxStaleDeadline = 0 }},
		{name: "no collect floor", adjust: func(settings *EvsSettings) { settings.FoldMinCollectMargin = 0 }},
		{name: "no step 7 ceiling", adjust: func(settings *EvsSettings) { settings.PushMaxStepSevenWindow = 0 }},
		{name: "no fence floor", adjust: func(settings *EvsSettings) { settings.PushMinFenceMargin = 0 }},
		{name: "no copy ceiling", adjust: func(settings *EvsSettings) { settings.CopyMaxHeadRereadInterval = 0 }},
		{name: "no settle floor", adjust: func(settings *EvsSettings) { settings.SlotMinSettleAge = 0 }},
	}
	for _, c := range cases {
		settings := DefaultEvsSettings()
		c.adjust(settings)
		if err := settings.Validate(); !errors.Is(err, ErrEvsSettings) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
