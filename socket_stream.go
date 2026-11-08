//go:build !sidecar_http

// socketStream: the one §6 stream a SocketConn runs on, opened by a dialer or accepted by a listener. It
// is the seam between §9 and §6 (SOCK.md's seam table): listeners and dialers build and test on an
// in-memory pipe (socket_stream_fake_test.go), and once §6's streams land (PROTO-M5-02) a thin adapter
// over Subprotocol.OpenStream and Listen satisfies it, whose SubprotocolStream is already a net.Conn with
// CloseWrite. Nothing here sends a frame itself.
//
// What every implementation keeps, which is §6.7's stream as a byte stream:
//
//   - Read returns io.EOF, plain, once the peer's StreamClose and every byte before it have been read.
//   - Close sends StreamClose and stops reading: the peer reads io.EOF, what it still sends is dropped
//     with its credit returned, and this end's Read and Write then return net.ErrClosed.
//   - CloseWrite sends StreamClose and reads on.
//   - Reset sends StreamReset with its code, and both ends' Reads and Writes then return a
//     *socketStreamResetError, as they do when the peer resets.
//   - Deadlines are net.Conn's: absolute, local to this end, os.ErrDeadlineExceeded once passed, and the
//     stream survives them, so clearing one lets I/O go on.
//
// Safe for concurrent use, as net.Conn is.

package sidecar

import (
	"fmt"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// One §6 stream as a SocketConn uses it. See the file header for what each method keeps.
type socketStream interface {
	Read(b []byte) (int, error)
	Write(b []byte) (int, error)
	// StreamClose of this end's direction. Reads go on.
	CloseWrite() error
	// StreamClose, and this end stops reading.
	Close() error
	// StreamReset with code: both directions end now.
	Reset(code protocol.StreamResetCode) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// What a stream's Read or Write returns once the stream was reset, by either end.
type socketStreamResetError struct {
	Code protocol.StreamResetCode
	// This end sent the reset.
	Local bool
}

// The code, and which end reset.
func (self *socketStreamResetError) Error() string {
	if self.Local {
		return fmt.Sprintf("stream reset here: %s", self.Code)
	}
	return fmt.Sprintf("stream reset by the peer: %s", self.Code)
}
