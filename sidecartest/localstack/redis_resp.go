// RESP2, the wire between this client and a node: https://redis.io/docs/latest/develop/reference/protocol-spec/.
// RESP2 and not 3, since a script's reply and a subscription read the same in it, and production's
// nodes speak it too.

package localstack

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// The first byte of each reply kind.
const (
	redisSimple  byte = '+'
	redisFailure byte = '-'
	redisInteger byte = ':'
	redisBulk    byte = '$'
	redisArray   byte = '*'
)

// A node's proto-max-bulk-len: format, not tuning, and what stops a corrupt length allocating.
const redisBulkMaxByteCount = 512 * 1024 * 1024

// One reply. A nil bulk or array has nilValue set.
type redisValue struct {
	kind byte
	// Set for a nil bulk or a nil array.
	nilValue bool
	// redisSimple, redisFailure and redisBulk.
	text []byte
	// redisInteger.
	integer int64
	// redisArray, in order.
	values []*redisValue
}

// A command as RESP's array of bulk strings, binary safe.
func appendRedisCommand(buffer []byte, args [][]byte) []byte {
	buffer = fmt.Appendf(buffer, "*%d\r\n", len(args))
	for _, arg := range args {
		buffer = fmt.Appendf(buffer, "$%d\r\n", len(arg))
		buffer = append(buffer, arg...)
		buffer = append(buffer, '\r', '\n')
	}
	return buffer
}

// One line, without its CRLF.
func readRedisLine(reader *bufio.Reader) ([]byte, error) {
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return nil, fmt.Errorf("resp line %q has no crlf", line)
	}
	return line[:len(line)-2], nil
}

// One reply, reading exactly its bytes, so the next reply starts where this one stopped.
func readRedisValue(reader *bufio.Reader) (*redisValue, error) {
	line, err := readRedisLine(reader)
	if err != nil {
		return nil, err
	}
	if len(line) == 0 {
		return nil, errors.New("an empty resp line")
	}
	kind, rest := line[0], line[1:]
	switch kind {
	case redisSimple, redisFailure:
		return &redisValue{kind: kind, text: rest}, nil
	case redisInteger:
		integer, err := strconv.ParseInt(string(rest), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("resp integer %q: %w", rest, err)
		}
		return &redisValue{kind: kind, integer: integer}, nil
	case redisBulk:
		byteCount, err := strconv.ParseInt(string(rest), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("resp bulk length %q: %w", rest, err)
		}
		if byteCount == -1 {
			return &redisValue{kind: kind, nilValue: true}, nil
		}
		if byteCount < 0 || redisBulkMaxByteCount < byteCount {
			return nil, fmt.Errorf("resp bulk length %d", byteCount)
		}
		body := make([]byte, byteCount+2)
		if _, err := io.ReadFull(reader, body); err != nil {
			return nil, err
		}
		if body[byteCount] != '\r' || body[byteCount+1] != '\n' {
			return nil, errors.New("a resp bulk with no crlf after it")
		}
		return &redisValue{kind: kind, text: body[:byteCount]}, nil
	case redisArray:
		count, err := strconv.ParseInt(string(rest), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("resp array length %q: %w", rest, err)
		}
		if count == -1 {
			return &redisValue{kind: kind, nilValue: true}, nil
		}
		if count < 0 {
			return nil, fmt.Errorf("resp array length %d", count)
		}
		values := make([]*redisValue, 0, min(count, 1024))
		for range count {
			value, err := readRedisValue(reader)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		return &redisValue{kind: kind, values: values}, nil
	}
	return nil, fmt.Errorf("resp kind %q", kind)
}
