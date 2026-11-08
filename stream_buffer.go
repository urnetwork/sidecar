// A stream's receive buffer (§6.7's credit row): the bytes received and not yet read, in order. Stream
// bytes go here, never to §5's component queues, because they cannot be dropped and skipped
// (connect/CODESTYLE.md:123). Its bound is the window its stream committed: streamState never appends
// past max_offset, so the buffer holds at most max_offset minus consumed_offset.
//
// No connect type appears here, so the file builds on every leg. Not safe for concurrent use: its
// stream holds it.

package sidecar

// Bytes received and not yet read, in arrival order.
type streamBuffer struct {
	// each StreamData's accepted bytes, copied, the first partly read
	chunks [][]byte
	// how much of chunks[0] the reader has taken
	readIndex int
	byteCount int64
}

// Keeps a copy of data, which the caller may reuse on return.
func (self *streamBuffer) append(data []byte) {
	if len(data) == 0 {
		return
	}
	chunk := make([]byte, len(data))
	copy(chunk, data)
	self.chunks = append(self.chunks, chunk)
	self.byteCount += int64(len(data))
}

// Moves up to len(p) bytes into p, oldest first, and answers how many.
func (self *streamBuffer) read(p []byte) int {
	n := 0
	for n < len(p) && 0 < len(self.chunks) {
		copied := copy(p[n:], self.chunks[0][self.readIndex:])
		n += copied
		self.readIndex += copied
		if self.readIndex == len(self.chunks[0]) {
			self.chunks[0] = nil
			self.chunks = self.chunks[1:]
			self.readIndex = 0
		}
	}
	self.byteCount -= int64(n)
	return n
}

// The bytes held.
func (self *streamBuffer) len() int64 {
	return self.byteCount
}

// Drops every byte held, as a reset or a reject does, and answers how many.
func (self *streamBuffer) discard() int64 {
	byteCount := self.byteCount
	self.chunks = nil
	self.readIndex = 0
	self.byteCount = 0
	return byteCount
}
