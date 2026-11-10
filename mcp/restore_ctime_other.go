//go:build !darwin && !linux && !js && !ios && !android && !sdk_mobile_bind

// A file's change time where this build does not read one: Windows' ChangeTime needs GetFileInformationByHandleEx,
// which is not built yet, so every base there is not exact, the closed direction for restore (RV2).

package mcp

import (
	"os"
)

// Reports no change time.
func restoreChangeTimeNs(info os.FileInfo) (int64, bool) {
	return 0, false
}
