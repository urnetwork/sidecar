//go:build !sidecar_http && !ios_extension

// Remote search's mode and notice answers (SEARCH-M10-33; §18.4's setting and notice rows; D-SDK-26; DESIGN-DETAILS
// 7.2.3): what the asker reads of §5.9's search.state at every step that builds a request.
//
//	mode     on (the default), own (this member's indexers only) or off (the fallback only), per device and network;
//	         Sidecar.SetSearchRemote sets it, never MCP
//	notice   before the first request to another member's device, the app names that member (a tagged device: its
//	         sponsor), the device and the repos; until it is answered those repos are searched on the phone. Allow
//	         records the answer, and the repos waiting on it go back to the plan; refuse ("Only my devices") sets the
//	         mode to own in the same write, which ends every leg to an indexer that is not own at the search's next
//	         step. Never for own indexers, so never in a personal network or one with none designated. A nil member
//	         clears every answer ("reset notices")
//
// A state that cannot be read, locked or failed, reads mode off and no answer: no remote search, no other member's
// indexer asked (fail closed).

package sidecar

// The network's remote mode, off where search.state cannot be read.
func (self *SearchRemoteClient) mode() string {
	mode, err := self.args.State.Mode()
	if err != nil || !isSearchRemoteMode(mode) {
		return SearchRemoteOff
	}
	return mode
}

// The notice's answer for memberId: answered and allowed only where search.state says so.
func (self *SearchRemoteClient) answer(memberId Id) (allow bool, answered bool) {
	allow, answered, err := self.args.State.Answer(memberId)
	if err != nil {
		return false, false
	}
	return allow, answered
}
