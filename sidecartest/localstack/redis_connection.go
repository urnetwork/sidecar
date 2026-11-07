// One socket to one node. Only one caller holds a connection at a time, which the pool in redis.go
// keeps, so nothing here locks.

package localstack

import (
	"bufio"
	"context"
	"errors"
	"net"
	"time"
)

type redisConnection struct {
	address string
	conn    net.Conn
	reader  *bufio.Reader
	// Set once a round trip failed partway: its reply may still arrive, so nothing else may read here.
	broken bool
}

func dialRedis(ctx context.Context, address string, timeout time.Duration) (*redisConnection, error) {
	if err := CheckStackAddress(address); err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	return &redisConnection{address: address, conn: conn, reader: bufio.NewReader(conn)}, nil
}

func (self *redisConnection) close() {
	self.broken = true
	self.conn.Close()
}

// Sends each command and reads as many replies, under one deadline: timeout, or ctx's when sooner.
// Cancelling ctx ends the wait. A failure breaks the connection, and a caller writing cannot tell
// whether a command ran (host_redis.go).
func (self *redisConnection) roundTrip(ctx context.Context, timeout time.Duration, commands ...[][]byte) ([]*redisValue, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := self.conn.SetDeadline(deadline); err != nil {
		self.close()
		return nil, err
	}
	stopWatching := context.AfterFunc(ctx, func() {
		self.conn.SetDeadline(time.Unix(1, 0))
	})
	values, err := func() ([]*redisValue, error) {
		var buffer []byte
		for _, command := range commands {
			buffer = appendRedisCommand(buffer, command)
		}
		if _, err := self.conn.Write(buffer); err != nil {
			return nil, err
		}
		values := make([]*redisValue, 0, len(commands))
		for range commands {
			value, err := readRedisValue(self.reader)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		return values, nil
	}()
	if !stopWatching() {
		// a cancel raced the reply, and may yet land on this socket's next user
		self.broken = true
	}
	if err != nil {
		self.close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, errors.Join(ctxErr, err)
		}
		return nil, err
	}
	return values, nil
}
