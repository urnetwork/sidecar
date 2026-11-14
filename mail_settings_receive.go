//go:build !sidecar_http && !ios_extension

// MailSettings' receiver part on the legs a receiver's parts build on (MAIL-M7-17): the receiver, its sessions and
// deposits, and its reception-time checks. The page Worker's leg has none (mail_settings_receive_http.go).

package sidecar

// A receiver's settings.
type MailReceiveSettings struct {
	// Whether this device runs a receiver once policy grants it the listen on smtp/25/mx (§15.5, §15.6): a desktop,
	// NAS or VPS daemon does, which keeps it up while mail is on; an app's host sets it false until a remote-mode
	// desktop app's SetReceiverEnabled designates its daemon (§18.5).
	Enabled  bool
	Receiver *MailReceiverSettings
	Session  *MailSessionSettings
	Auth     *MailAuthSettings
}

// The receiver's defaults: on, as a daemon runs.
func defaultMailReceiveSettings() *MailReceiveSettings {
	return &MailReceiveSettings{
		Enabled:  true,
		Receiver: DefaultMailReceiverSettings(),
		Session:  DefaultMailSessionSettings(),
		Auth:     DefaultMailAuthSettings(),
	}
}

// §15.7's values for a host that runs on a phone (§18.4): 2 deposits at once, and no receiver unless the app opts in,
// since an app receives only while it is open (owner decision 197).
func ApplyMobileMailSettings(settings *MailSettings) {
	if settings == nil || settings.Receive == nil {
		return
	}
	settings.Receive.Enabled = false
	if settings.Receive.Session != nil {
		ApplyMobileMailSessionSettings(settings.Receive.Session)
	}
}
