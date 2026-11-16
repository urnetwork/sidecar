// The bridge the gkm fake of the group flows' external tests reaches GkmApi's answer mapping through, so an answer a
// test plants reads exactly as the client reads one off its transport, the lb's 502 or 504 among them (QD-876).
// Tests only.

package sidecar

import (
	"net/http"
)

// The error GkmApi gives an answer of status that is no success, with header and body as gkm or the lb sent them.
func GkmAnswerError(status int, header http.Header, body []byte) error {
	return gkmErrorOfAnswer("a fake gkm's route", status, header, body)
}
