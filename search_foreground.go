//go:build !ios_extension

// The host's foreground (SEARCH-M10-33; QD-158, plan-SEARCH-foreground-signal; §18.7's foreground row; D-SDK-23,
// D-SDK-27): an app reports at start and on each lifecycle change whether it is in the foreground, a page Worker's
// key-origin frame whether its tab is visible, and a daemon host never reports, so an unreported state reads background.
// sdk's SidecarSearch.SetForeground wraps it.
//
// What follows it: remote search's requester (search_remote_warm.go), which feeds each generation's dispatcher
// (Subprotocol.SetForeground) and names the warm pairs at each move into the foreground; and search's policy and
// background sync, which read it through SearchConditions.Foreground where the host builds them (searchConditionsOf).
//
// On every leg but the forwarding one: no connect type. Safe for concurrent use.

package sidecar

// Reports whether the app is in the foreground, or a page Worker's tab visible.
func (self *Sidecar) SetSearchForeground(foreground bool) {
	self.searchOf().foreground.Set(foreground)
}

// The foreground as last reported, false before any report, and a channel closed at its next change.
func (self *Sidecar) SearchForeground() (bool, chan struct{}) {
	return self.searchOf().foreground.Get()
}
