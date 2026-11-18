// §6.6's values after each semicolon, and the protocol's maximums over what a host adjusts. The desktop's
// values are TestDefaultProtocolSettingsMatchDesign's.

package sidecar

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMobileProtocolSettingsMatchDesign(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	ApplyMobileSidecarProtocolSettings(settings)

	// the desktop's, with §6.6's nine mobile values written over it, so a value this leaves alone or one
	// it should not touch both fail
	want := DefaultSidecarProtocolSettings()
	want.ReassemblyPeerCount = 4
	want.ReassemblyPeerByteCount = 512 * 1024
	want.ReassemblyProcessByteCount = 2 * 1024 * 1024
	want.IdempotencyPeerByteCount = 64 * 1024
	want.IdempotencyProcessByteCount = 512 * 1024
	want.StreamMinWindowByteCount = 64 * 1024
	want.StreamMaxWindowByteCount = 256 * 1024
	want.StreamPeerCreditByteCount = 1024 * 1024
	want.StreamProcessCreditByteCount = 8 * 1024 * 1024
	if *settings != *want {
		t.Errorf("%+v, want %+v", *settings, *want)
	}
}

// §6.7's windows and the caps have to hold together on a phone as on a desktop, inside §18.4's smallest
// budget, Android's 16 MiB.
func TestMobileProtocolBoundsAreConsistent(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	ApplyMobileSidecarProtocolSettings(settings)

	if settings.StreamMaxWindowByteCount < settings.StreamMinWindowByteCount {
		t.Errorf("stream window %d to %d", settings.StreamMinWindowByteCount, settings.StreamMaxWindowByteCount)
	}
	if settings.StreamPeerCreditByteCount < settings.StreamMinWindowByteCount {
		t.Errorf("peer credit %d under a stream's minimum window", settings.StreamPeerCreditByteCount)
	}
	if settings.StreamProcessCreditByteCount < settings.StreamPeerCreditByteCount {
		t.Errorf("process credit %d under a peer's", settings.StreamProcessCreditByteCount)
	}
	if settings.ReassemblyPeerByteCount < settings.ReassemblyMaxBodyByteCount {
		t.Errorf("a peer's %d B cannot hold one body of %d B", settings.ReassemblyPeerByteCount, settings.ReassemblyMaxBodyByteCount)
	}
	if settings.ReassemblyProcessByteCount < settings.ReassemblyPeerByteCount {
		t.Errorf("process reassembly %d under a peer's", settings.ReassemblyProcessByteCount)
	}
	processByteCount := settings.ReassemblyProcessByteCount + settings.IdempotencyProcessByteCount +
		settings.StreamProcessCreditByteCount
	if 16*1024*1024 < processByteCount {
		t.Errorf("the caps take %d B", processByteCount)
	}
}

func TestDefaultProtocolSettingsAreFreshEachCall(t *testing.T) {
	adjusted := DefaultSidecarProtocolSettings()
	ApplyMobileSidecarProtocolSettings(adjusted)
	if DefaultSidecarProtocolSettings().ReassemblyPeerCount != 8 {
		t.Error("an adjustment reached the next default")
	}
	if *DefaultSidecarSettings().ProtocolSettings != *DefaultSidecarProtocolSettings() {
		t.Error("two sources of a default")
	}
}

func TestProtocolMaximumsAreHeld(t *testing.T) {
	cases := []struct {
		field  string
		adjust func(settings *SidecarSettings, past int64)
	}{
		{
			field: "ProtocolSettings.DefaultCallTimeout",
			adjust: func(settings *SidecarSettings, past int64) {
				settings.ProtocolSettings.DefaultCallTimeout = MaxCallTimeout + time.Duration(past)
			},
		},
		{
			field: "ProtocolSettings.ReassemblyMaxBodyByteCount",
			adjust: func(settings *SidecarSettings, past int64) {
				settings.ProtocolSettings.ReassemblyMaxBodyByteCount = MaxReassemblyBodyByteCount + past
			},
		},
		{
			field: "StreamChunkByteCount",
			adjust: func(settings *SidecarSettings, past int64) {
				settings.StreamChunkByteCount = MaxStreamDataByteCount + int(past)
			},
		},
	}
	for _, c := range cases {
		atMaximum := validSidecarSettings()
		c.adjust(atMaximum, 0)
		if err := atMaximum.validate(); err != nil {
			t.Errorf("%s at its maximum: %v", c.field, err)
		}
		pastMaximum := validSidecarSettings()
		c.adjust(pastMaximum, 1)
		err := pastMaximum.validate()
		if !errors.Is(err, errInvalidSettings) || !strings.Contains(err.Error(), c.field) {
			t.Errorf("%s past its maximum: %v", c.field, err)
		}
	}
}
