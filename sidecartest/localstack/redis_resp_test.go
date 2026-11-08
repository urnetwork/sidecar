package localstack

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func readerOf(text string) *bufio.Reader {
	return bufio.NewReader(strings.NewReader(text))
}

func TestACommandIsAnArrayOfBinarySafeBulks(t *testing.T) {
	got := appendRedisCommand(nil, redisArgs("SET", "{a}k", []byte{0, '\r', '\n', 0xff}))
	want := "*3\r\n$3\r\nSET\r\n$4\r\n{a}k\r\n$4\r\n\x00\r\n\xff\r\n"
	if string(got) != want {
		t.Errorf("%q", got)
	}
}

func TestEveryReplyKindReads(t *testing.T) {
	stream := readerOf("+OK\r\n-ERR no\r\n:-42\r\n$4\r\na\r\nb\r\n$0\r\n\r\n$-1\r\n*-1\r\n*2\r\n:1\r\n*1\r\n$1\r\nx\r\n")
	read := func() *redisValue {
		value, err := readRedisValue(stream)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	if value := read(); value.kind != redisSimple || string(value.text) != "OK" {
		t.Errorf("simple %+v", value)
	}
	if value := read(); value.kind != redisFailure || string(value.text) != "ERR no" {
		t.Errorf("failure %+v", value)
	}
	if value := read(); value.kind != redisInteger || value.integer != -42 {
		t.Errorf("integer %+v", value)
	}
	// a bulk holds what a line would end on
	if value := read(); value.kind != redisBulk || !bytes.Equal(value.text, []byte("a\r\nb")) {
		t.Errorf("bulk %+v", value)
	}
	if value := read(); value.nilValue || len(value.text) != 0 {
		t.Errorf("an empty bulk is not nil: %+v", value)
	}
	if value := read(); !value.nilValue {
		t.Errorf("nil bulk %+v", value)
	}
	if value := read(); !value.nilValue {
		t.Errorf("nil array %+v", value)
	}
	value := read()
	if len(value.values) != 2 || value.values[0].integer != 1 || string(value.values[1].values[0].text) != "x" {
		t.Errorf("array %+v", value)
	}
}

func TestACorruptReplyFailsRatherThanMisread(t *testing.T) {
	for _, text := range []string{
		"",
		"\r\n",
		"?what\r\n",
		"+no crlf\n",
		":not a number\r\n",
		"$x\r\n",
		"$-2\r\n",
		"$536870913\r\n",
		"$1\r\nab\r\n",
		"$3\r\na",
		"*x\r\n",
		"*-2\r\n",
		"*2\r\n:1\r\n",
	} {
		if value, err := readRedisValue(readerOf(text)); err == nil {
			t.Errorf("%q read as %+v", text, value)
		}
	}
}
