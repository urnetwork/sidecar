// The dialog's half of the bridge to private fixtures: see export_test.go. A file of its own, so the
// dialog's tests stand without the engine's.

package mxedgeservice

type (
	Dialog     = mxDialog
	DialogStep = mxDialogStep
)

const (
	DialogMaxByteCount     = mxDialogMaxByteCount
	DialogMaxLineByteCount = mxDialogMaxLineByteCount
	EhloNameMaxByteCount   = mxEhloNameMaxByteCount

	DialogStepRead  = mxDialogStepRead
	DialogStepTls   = mxDialogStepTls
	DialogStepQuit  = mxDialogStepQuit
	DialogStepClose = mxDialogStepClose
	DialogStepReset = mxDialogStepReset
)

// A dialog on settings' replies.
func NewDialog(settings *MxEdgeSettings, askRecent func() bool, bannerRefused bool) *Dialog {
	return newMxDialog(newMxDialogReplies(settings), askRecent, bannerRefused)
}

// The last EHLO or HELO name.
func (self *mxDialog) EhloName() string {
	return self.ehloName
}

// How much the dialog holds: its buffer's whole size, whatever a sender sent.
func (self *mxDialog) BufferByteCount() int {
	return len(self.buffer)
}
