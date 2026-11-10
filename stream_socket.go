//go:build !sidecar_http && !ios_extension

// The join of §9's socketStream seam (socket_stream.go, SOCK-M5-09) to §6's streams (CONTRACTS.md C-16): a
// SubprotocolStream is already that seam's net.Conn with CloseWrite and Reset, so this only renames a
// reset, *StreamResetError, as the seam's *socketStreamResetError, which SocketConn turns into §9.9's
// ECONNRESET. A listener's admission (SOCK-M5-11) hands it the stream its accept function took, and a
// dialer (SOCK-M5-12) the one OpenStream answered.

package sidecar

import (
	"errors"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// socketStream over a SubprotocolStream.
type subprotocolSocketStream struct {
	stream *SubprotocolStream
}

var _ socketStream = (*subprotocolSocketStream)(nil)

// The seam over stream, which it then owns.
func newSubprotocolSocketStream(stream *SubprotocolStream) socketStream {
	return &subprotocolSocketStream{stream: stream}
}

// A stream's error as the seam names it: a reset as *socketStreamResetError, anything else as it was.
func socketStreamErrorOf(err error) error {
	var resetErr *StreamResetError
	if errors.As(err, &resetErr) {
		return &socketStreamResetError{Code: resetErr.Code, Local: resetErr.Local}
	}
	return err
}

// See socketStream.
func (self *subprotocolSocketStream) Read(b []byte) (int, error) {
	n, err := self.stream.Read(b)
	return n, socketStreamErrorOf(err)
}

// See socketStream.
func (self *subprotocolSocketStream) Write(b []byte) (int, error) {
	n, err := self.stream.Write(b)
	return n, socketStreamErrorOf(err)
}

// See socketStream.
func (self *subprotocolSocketStream) CloseWrite() error {
	return socketStreamErrorOf(self.stream.CloseWrite())
}

// See socketStream.
func (self *subprotocolSocketStream) Close() error {
	return socketStreamErrorOf(self.stream.Close())
}

// See socketStream.
func (self *subprotocolSocketStream) Reset(code protocol.StreamResetCode) error {
	return socketStreamErrorOf(self.stream.Reset(code))
}

// See socketStream.
func (self *subprotocolSocketStream) SetReadDeadline(t time.Time) error {
	return self.stream.SetReadDeadline(t)
}

// See socketStream.
func (self *subprotocolSocketStream) SetWriteDeadline(t time.Time) error {
	return self.stream.SetWriteDeadline(t)
}
