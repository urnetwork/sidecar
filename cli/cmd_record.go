// ur record (RECORD.md sections 9 to 11, §16.16): a person's commands on the record of agent work. Each part keeps to
// its own cmd_record_<part>.go and registers itself with registerUrRecordPart at init, in any order, so a task adds
// a part without touching this file (C-21):
//
//	ur record log        the verifiable log: on, off, checkpoint, status   (cmd_record_log.go)
//	ur record disclose   a disclosure packet for someone outside the log   (cmd_record_disclose.go)
//	ur record open       the author's openings of its vault entries        (cmd_record_disclose.go)
//	ur record verify     the offline verifier of a packet                  (cmd_record_disclose.go)
//	ur record export     canonical lines, OCSF or OTel, to a file or stdout (cmd_record_export.go)
//	ur record erase      a log admin's erasure of entries by key destruction (cmd_record_erase.go)
//
// None of it is an MCP tool. A part that discloses, opens, exports or erases bodies runs only from a command a person
// confirmed on the terminal, and its daemon method refuses a caller with a harness process among its ancestors.

package main

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/docopt/docopt-go"
)

// One part of ur record: the word after `ur record` that selects it, its docopt usage lines, and what runs it.
type urRecordPart struct {
	word  string
	usage []string
	run   func(ctx context.Context, cli *urCli, options docopt.Opts) error
}

// Every part, by registration. Written only by registerUrRecordPart, at init.
var urRecordParts []*urRecordPart

// Adds a part, registering `ur record` at the first and rebuilding its usage at each, so init order does not matter.
func registerUrRecordPart(part *urRecordPart) {
	if part == nil || part.word == "" || part.run == nil || slices.ContainsFunc(urRecordParts, func(held *urRecordPart) bool { return held.word == part.word }) {
		panic("ur record part registered twice or without a run")
	}
	urRecordParts = append(urRecordParts, part)
	command := urCommands["record"]
	if command == nil {
		command = &urCommand{
			name:    "record",
			summary: "the record of agent work: its verifiable log, disclosure packets, the offline verifier and exports",
			run:     runUrRecord,
		}
		registerUrCommand(command)
	}
	lines := []string{}
	for _, held := range urRecordParts {
		lines = append(lines, held.usage...)
	}
	slices.Sort(lines)
	command.usage = strings.Join(lines, "\n")
}

// Runs the part the first word names.
func runUrRecord(ctx context.Context, cli *urCli, options docopt.Opts) error {
	for _, part := range urRecordParts {
		if urOptionBool(options, part.word) {
			return part.run(ctx, cli, options)
		}
	}
	return errors.New("ur record takes a part: log, disclose, open, verify, export or erase")
}

// A docopt option's value, empty when absent.
func urOptionString(options docopt.Opts, key string) string {
	value, _ := options.String(key)
	return value
}

// A repeated docopt option's values.
func urOptionStrings(options docopt.Opts, key string) []string {
	values, _ := options[key].([]string)
	return values
}
