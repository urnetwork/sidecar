//go:build !ios_extension

// The host's conditions as search's policy reads them (§18.4's conditions row; §18.7; D-SDK-23; QD-158;
// SEARCH-M10-20): unmetered, charging and low power, which the host reports through Sidecar.SetSearchConditions, and
// whether the app is in the foreground or a page Worker's tab visible, which it reports through
// SetSearchForeground. The Go core reads no platform API: a condition not yet reported, or one the browser hides,
// counts as metered and not charging, and an unreported foreground as background; a daemon host reports none and
// counts as unmetered and charging, so its background windows and syncs run whenever it does.
//
// On every leg but ios_extension, which runs no search: no connect type. A value, safe to copy.

package sidecar

// What the host last reported.
type SearchConditions struct {
	Unmetered bool
	Charging  bool
	LowPower  bool
	// Whether the host reported the three above. Unreported reads metered, not charging and not in low power.
	Reported bool
	// The app is in the foreground, or a page Worker's tab is visible. Unreported reads background.
	Foreground bool
	// A ur daemon host, which reports none: unreported, it counts as unmetered and charging.
	DaemonHost bool
}

// The conditions of a Sidecar's reports: the three conditions as SetSearchConditions left them, the foreground as
// SetSearchForeground did, and whether the host is a daemon (Search.RemoteServe, which only daemon hosts set).
func searchConditionsOf(reported SidecarSearchConditions, foreground bool, daemonHost bool) SearchConditions {
	return SearchConditions{
		Unmetered:  reported.Unmetered,
		Charging:   reported.Charging,
		LowPower:   reported.LowPower,
		Reported:   reported.Reported,
		Foreground: foreground,
		DaemonHost: daemonHost,
	}
}

// Whether the link counts as metered: as reported, else metered, but unmetered on a daemon host.
func (self SearchConditions) Metered() bool {
	if self.Reported {
		return !self.Unmetered
	}
	return !self.DaemonHost
}

// Whether the device counts as charging: as reported, else not, but charging on a daemon host.
func (self SearchConditions) OnCharge() bool {
	if self.Reported {
		return self.Charging
	}
	return self.DaemonHost
}

// Whether Low Power Mode or power saving pauses background index work: only as reported.
func (self SearchConditions) Paused() bool {
	return self.Reported && self.LowPower
}
