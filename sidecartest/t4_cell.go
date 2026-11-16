// T4's surrogate cells for the sidecar module's tests (§22.4's T4, §22.9's Memory, size row; SDK-M8-15): the harness
// is sidecartest/t4cell, which imports only the standard library so sdk's tests take it on alone; these names are its,
// for cells written beside sidecartest's fakes (SEARCH-M10-38's phone cells among them).

package sidecartest

import (
	"github.com/urnetwork/sidecar/sidecartest/t4cell"
)

// See t4cell.Profile, t4cell.Row and t4cell.Cell.
type (
	T4CellProfile = t4cell.Profile
	T4CellRow     = t4cell.Row
	T4Cell        = t4cell.Cell
)

// The surrogate profiles, and the figure a row's budget holds.
const (
	T4ProfileIos32    = t4cell.ProfileIos32
	T4ProfileAndroid  = t4cell.ProfileAndroid
	T4CellHoldsPeak   = t4cell.HoldsPeak
	T4CellHoldsSteady = t4cell.HoldsSteady
)

// See t4cell.Ios32Profile.
func T4Ios32Profile() *T4CellProfile {
	return t4cell.Ios32Profile()
}

// See t4cell.AndroidProfile.
func T4AndroidProfile() *T4CellProfile {
	return t4cell.AndroidProfile()
}

// See t4cell.NewCell.
func NewT4Cell(profile *T4CellProfile) *T4Cell {
	return t4cell.NewCell(profile)
}
