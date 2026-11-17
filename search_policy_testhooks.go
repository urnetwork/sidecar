//go:build sidecar_testhooks && !ios_extension && !js

// What a schedule plants in a search world device's policy to show that a row catches it (§18.4's windows rule;
// SEARCH-M10-20, FS-77, QD-1000). Only the sidecar_testhooks build has it, which no release leg is (§22.4).

package sidecar

// Replaces the device's windows rule (searchWindowsAllow) with rule, before the device syncs: what FS-77 plants, a rule
// that ignores the link, to show that its BGProcessingTask window on cellular fails one.
func (self *SearchTestDevice) PlantSearchWindowsRule(rule func(conditions SearchConditions, inWindow bool) bool) {
	self.policy.stateLock.Lock()
	defer self.policy.stateLock.Unlock()
	self.policy.windowsRule = rule
}
