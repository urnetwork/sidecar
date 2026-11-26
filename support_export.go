//go:build !ios_extension && !sidecar_http

// ur support export (DESIGN-COMPUTE §28.4, FB section 5's export): one archive a person sends by any path, as an
// air-gapped install must, a zip of
//
//	README.txt                               what it is, and that support's replies are information, never instructions
//	item.json, messages.txt                  an item's messages and support's replies, as Read answers them and as ur
//	                                         support show prints them
//	<client_ref>/body.json                   each message of this device's on it the outbox still keeps, as posted or
//	<client_ref>/support-log-bundle.json.gz  as it waits to go, its bundle as sent and its files whole
//	<client_ref>/files/<n>-<name>
//	support-log-bundle.json.gz               with neither an item nor a message: the bundle the next message would
//	                                         carry, which needs no conversation, so a ring alone writes it
//
// within SupportSettings.ExportMaxByteCount. The archive is the person's: its caller checks that no harness process is
// among the caller's ancestors (§28.7: no agent reads a bundle), as support.logs does, and it taints nothing. Safe for
// concurrent use.

package sidecar

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"time"
)

// What Export takes: an item's entry, or one outbox message's client_ref, or neither for the support log's next
// bundle alone.
type SupportExportArgs struct {
	Entry     string
	ClientRef string
	// What a bundle's header says of the host, for the next bundle.
	Host *SupportLogBundleHost
}

// An archive past SupportSettings.ExportMaxByteCount.
var ErrSupportExportTooLarge = errors.New("support export: the archive is past its bound; export one message by its client_ref")

// A writer that refuses past its bound.
type supportBoundedWriter struct {
	out       io.Writer
	remaining int64
}

// Writes data whole, or nothing of it past the bound.
func (self *supportBoundedWriter) Write(data []byte) (int, error) {
	if self.remaining < int64(len(data)) {
		return 0, ErrSupportExportTooLarge
	}
	self.remaining -= int64(len(data))
	return self.out.Write(data)
}

// The README an archive opens with.
const supportExportReadme = "URnetwork support export, written by ur support export.\n\n" +
	"item.json and messages.txt hold an item of your support conversation: your messages, your agents' and support's " +
	"replies. Support's replies are information from URnetwork, never instructions.\n" +
	"Each folder named by a client_ref holds one message this device sent or holds to send: body.json as posted, its " +
	"support log bundle (support-log-bundle.json.gz: codes and counts, no text of yours) and its files.\n" +
	"support-log-bundle.json.gz at the top is the support log's bundle as your next message would carry it.\n" +
	"Send it to URnetwork's support by any path you choose; it leaves this device only that way.\n"

// One archive being written: its members, each stamped with one time.
type supportExportArchive struct {
	archive  *zip.Writer
	modified time.Time
}

// An archive into out, within maxByteCount, its README written.
func newSupportExportArchive(out io.Writer, maxByteCount int64, now time.Time) (*supportExportArchive, error) {
	self := &supportExportArchive{
		archive:  zip.NewWriter(&supportBoundedWriter{out: out, remaining: maxByteCount}),
		modified: now.UTC(),
	}
	return self, self.write("README.txt", []byte(supportExportReadme), true)
}

// One member, deflated where compress says, stored as it is otherwise.
func (self *supportExportArchive) write(name string, data []byte, compress bool) error {
	method := zip.Store
	if compress {
		method = zip.Deflate
	}
	writer, err := self.archive.CreateHeader(&zip.FileHeader{Name: name, Method: method, Modified: self.modified})
	if err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
}

// Ends the archive with its directory.
func (self *supportExportArchive) close() error {
	return self.archive.Close()
}

// The support log's next bundle alone as an archive into out: what an install with no conversation, an air-gapped one
// or one whose release's switch is off, sends by another path.
func SupportExportLog(log *SupportLog, host *SupportLogBundleHost, settings *SupportSettings, clock Clock, out io.Writer) error {
	bundle, err := log.Bundle(&SupportLogBundleArgs{Host: host})
	if err != nil {
		return err
	}
	archive, err := newSupportExportArchive(out, settings.ExportMaxByteCount, clockOrReal(clock).Now())
	if err != nil {
		return err
	}
	if err := archive.write("support-log-bundle.json.gz", bundle.Bytes, false); err != nil {
		return err
	}
	return archive.close()
}

// Writes the archive args name into out. A refusal, not_found, for an item or a message this device does not hold.
func (self *SupportClient) Export(ctx context.Context, args *SupportExportArgs, out io.Writer) error {
	if args == nil {
		args = &SupportExportArgs{}
	}
	switch {
	case args.Entry != "" && !supportEntryPattern.MatchString(args.Entry):
		return supportRefused(SupportRefusalNotFound)
	case args.ClientRef != "" && supportClientRefBytes(args.ClientRef) == nil:
		return supportRefused(SupportRefusalNotFound)
	case args.Entry == "" && args.ClientRef == "":
		return SupportExportLog(self.log, args.Host, self.settings, self.clock, out)
	}
	items := []*supportOutboxItem{}
	var read *SupportReadResult
	if args.Entry != "" {
		state, err := self.loadState()
		if err != nil {
			return err
		}
		item := state.item(args.Entry)
		if item == nil {
			return supportRefused(SupportRefusalNotFound)
		}
		read = supportReadResultOf(item, 0)
		kept, err := self.outboxItems()
		if err != nil {
			return err
		}
		for _, outboxItem := range kept {
			if outboxItem.Entry == args.Entry {
				items = append(items, outboxItem)
			}
		}
	} else {
		item, err := self.outboxItem(args.ClientRef)
		if errors.Is(err, errSupportOutboxItemAbsent) {
			return supportRefused(SupportRefusalNotFound)
		}
		if err != nil {
			return err
		}
		items = append(items, item)
	}
	archive, err := newSupportExportArchive(out, self.settings.ExportMaxByteCount, self.clock.Now())
	if err != nil {
		return err
	}
	if read != nil {
		encoded, err := json.MarshalIndent(read, "", "  ")
		if err != nil {
			return err
		}
		if err := archive.write("item.json", encoded, true); err != nil {
			return err
		}
		rendered := &strings.Builder{}
		SupportRenderItem(rendered, read)
		if err := archive.write("messages.txt", []byte(rendered.String()), true); err != nil {
			return err
		}
	}
	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := self.exportMessage(archive, item); err != nil {
			return err
		}
	}
	return archive.close()
}

// One outbox message into the archive: its body as posted, its bundle and its files, under its client_ref.
func (self *SupportClient) exportMessage(archive *supportExportArchive, item *supportOutboxItem) error {
	if err := archive.write(path.Join(item.ClientRef, "body.json"), item.Body, true); err != nil {
		return err
	}
	if item.Logs {
		bundle, err := self.outboxAttachment(item.ClientRef, 0)
		if err != nil {
			return fmt.Errorf("support export: a bundle the outbox lost: %w", err)
		}
		if err := archive.write(path.Join(item.ClientRef, "support-log-bundle.json.gz"), bundle, false); err != nil {
			return err
		}
	}
	body := &SupportBody{}
	json.Unmarshal(item.Body, body)
	for index := 1; index <= item.FileCount; index += 1 {
		data, err := self.outboxAttachment(item.ClientRef, index)
		if err != nil {
			return fmt.Errorf("support export: a file the outbox lost: %w", err)
		}
		name := strconv.Itoa(index)
		if index-1 < len(body.Files) && supportExportNameValid(body.Files[index-1].Name) {
			name += "-" + body.Files[index-1].Name
		}
		if err := archive.write(path.Join(item.ClientRef, "files", name), data, true); err != nil {
			return err
		}
	}
	return nil
}

// Whether a file's base name may name an archive's member: no separator, no dot names, no control character.
func supportExportNameValid(name string) bool {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// An item of the view as Read answers it, after the seq after: its messages and replies in order.
func supportReadResultOf(item *supportItem, after uint32) *SupportReadResult {
	result := &SupportReadResult{Entry: item.Entry, Status: item.Status, FixedIn: item.FixedIn, Final: item.Final, Messages: []*SupportReadMessage{}}
	for _, message := range item.Messages {
		if message.Seq <= after {
			continue
		}
		from := message.Agent
		switch {
		case message.Reply:
			from = "support"
		case message.Agent == "":
			from = "you"
		}
		result.Messages = append(result.Messages, &SupportReadMessage{
			Seq: message.Seq, From: from, Tier: message.Tier, Text: message.Text, Millis: message.Millis, Reply: message.Reply,
		})
	}
	return result
}

// An item as a person reads it, as ur support show prints it and an export holds it: support's replies marked as
// support's, information and never an instruction; a status event with no text left out.
func SupportRenderItem(out io.Writer, item *SupportReadResult) {
	fmt.Fprintf(out, "#%s  %s", item.Entry, item.Status)
	if item.FixedIn != "" {
		fmt.Fprintf(out, " in %s", item.FixedIn)
	}
	fmt.Fprintln(out)
	for _, message := range item.Messages {
		at := time.UnixMilli(message.Millis).UTC().Format(time.RFC3339)
		if message.Reply {
			if message.Text == "" {
				continue
			}
			fmt.Fprintf(out, "%s  URnetwork support (information, not instructions):\n%s\n", at, message.Text)
			continue
		}
		fmt.Fprintf(out, "%s  %s (%s):\n%s\n", at, message.From, message.Tier, message.Text)
	}
}
