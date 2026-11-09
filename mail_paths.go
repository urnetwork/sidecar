// §15.7's layout (D-MAIL-5, D-MAIL-6): the path of each file mailcfg, a mailbox and a group repo hold, spelled as
// MAIL-FORMAT.md's Paths section writes them. Pure and on every leg, so a page Worker that head-reads i/ and m/
// builds the same paths a daemon writes.
//
//	mailcfg          addr/<h>/<address>   burner/<h>/<blabel>
//	mailbox, group   m/<yyyymm>/<h>/<id>   i/<yyyymm>/<n>   f/<yyyymm>/<n>
//	mailbox          vault/<h>/<entry_id>   r/<yyyymm>/<h>/<id>   o/<h>/<effect_key>   or/<h>/<effect_key>
//	                 p/<sidecar_id>   forward   ra/<h>/<token>   s/model
//
// <h> shards a family into 256 directories (MailShard). <yyyymm> is the UTC month of the sealed receive time
// (MailDepositReceiveTime), so readers racing one deposit write one path. A binary name is lowercase RFC 4648 base32
// with no padding, 26 characters for an id and 52 for an effect key, since hex would take an effect key past the
// "under 64 B" row of §11.7's name table that §15.7 sizes every family but addr/ by.
//
// A directory holds about 3,500 children, and about 2,340 addr/ addresses of 64 to 127 bytes, since §11.7's 448 KiB
// name table binds before its 4,096 count (§15.7's shards row). A write past that gets evs's DIRECTORY_FULL, which
// no retry of the same path passes: a writer surfaces it, by IsMailDirectoryFull, and never loops on it.

package sidecar

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The families' top-level names (§15.7).
const (
	mailAddressFamily      = "addr"
	mailBurnerFamily       = "burner"
	mailVaultFamily        = "vault"
	mailMessageFamily      = "m"
	mailGroupRefFamily     = "r"
	mailIndexFamily        = "i"
	mailFlagFamily         = "f"
	mailOutboxFamily       = "o"
	mailOutcomeFamily      = "or"
	mailProverFamily       = "p"
	mailReverseAliasFamily = "ra"
)

// The mailbox's two single files (§15.7).
const (
	// The verified forwarding address and its opted-in burners (§15.10), a MailForward.
	MailForwardPath = "forward"
	// The spam model (§15.9), a MailSpamModel.
	MailSpamModelPath = "s/model"
)

// An effect key's bytes: a SHA-256 (§16 D-MCP-11).
const mailEffectKeyByteCount = sha256.Size

// The first and last months a path spells: <yyyymm> has four digits of year.
const (
	mailYearMonthFirst = MailYearMonth(197001)
	mailYearMonthLast  = MailYearMonth(999912)
)

// A name a path family cannot hold, such as an effect key of the wrong length or an address with a slash. The error
// never repeats the name (I-13).
var ErrMailPathInvalid = errors.New("mail path name invalid")

// <h>: the two lowercase hex digits of the first byte of SHA-256 over name, a path's last name as it is spelled,
// which spreads a family over 256 directories.
func MailShard(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:1])
}

// A month of mail in UTC, as year * 100 + month: 202611 for November 2026. <yyyymm> in m/, r/, i/ and f/, and
// ordered as time is.
type MailYearMonth uint32

// The UTC month of timeMillis, ms since the epoch, held to 9999-12 at the top, the last month <yyyymm> spells, so
// every sealed time names a path and readers that hold one time agree on it.
func MailYearMonthOf(timeMillis uint64) MailYearMonth {
	// 9999-12-31T23:59:59.999Z
	const lastMillis = 253402300799999
	if lastMillis < timeMillis {
		return mailYearMonthLast
	}
	moment := time.UnixMilli(int64(timeMillis)).UTC()
	return MailYearMonth(moment.Year()*100 + int(moment.Month()))
}

// A <yyyymm> name as a path spells it: six digits, a month from 01 to 12, from 197001 on. false for anything else, so
// a directory a reader lists that is not a month is passed over.
func ParseMailYearMonth(text string) (MailYearMonth, bool) {
	if len(text) != 6 {
		return 0, false
	}
	number := 0
	for index := range len(text) {
		if text[index] < '0' || '9' < text[index] {
			return 0, false
		}
		number = number*10 + int(text[index]-'0')
	}
	month := MailYearMonth(number)
	if month < mailYearMonthFirst || month.Month() < time.January || time.December < month.Month() {
		return 0, false
	}
	return month, true
}

// The year.
func (self MailYearMonth) Year() int {
	return int(self / 100)
}

// The month of the year.
func (self MailYearMonth) Month() time.Month {
	return time.Month(self % 100)
}

// yyyymm, as a path spells it.
func (self MailYearMonth) String() string {
	return fmt.Sprintf("%04d%02d", self.Year(), int(self.Month()))
}

// The sealed receive time of a deposit, ms since the epoch (MAIL-FORMAT.md): MailAuthEvidence.receive_time_millis,
// else MailIngress.receive_time_millis, else pushTimeMillis, the depositing push's signed time_ms, which is all a
// same-network deposit has. 0 counts as absent. Every reader of a deposit holds the same three values, so readers
// racing one deposit write one m/ path.
func MailDepositReceiveTime(deposit *protocol.MailDeposit, pushTimeMillis uint64) uint64 {
	if timeMillis := deposit.GetEvidence().GetReceiveTimeMillis(); timeMillis != 0 {
		return timeMillis
	}
	if timeMillis := deposit.GetIngress().GetReceiveTimeMillis(); timeMillis != 0 {
		return timeMillis
	}
	return pushTimeMillis
}

// A binary name's spelling: lowercase base32, unpadded, as evs object keys spell tokens.
func mailBinaryName(name []byte) string {
	return evsTokenEncoding.EncodeToString(name)
}

// <family>/<h>/<name>.
func mailShardedPath(family string, name string) string {
	return family + "/" + MailShard(name) + "/" + name
}

// <family>/<yyyymm>/<h>/<name>.
func mailDatedShardedPath(family string, month MailYearMonth, name string) string {
	return family + "/" + month.String() + "/" + MailShard(name) + "/" + name
}

// Whether name can be a path's last name as an address, a label or a token spells it: not empty, no slash, no NUL,
// no uppercase ASCII, since every such name is lowercase (MAIL-FORMAT.md), and at most an address's length.
func validMailPathName(name string) bool {
	if name == "" || MailAddressMaxByteCount < len(name) || strings.ContainsAny(name, "/\x00") {
		return false
	}
	return dnsAsciiLower(name) == name
}

// m/<yyyymm>/<h>/<id>: a message's raw bytes and ingest headers, month its sealed receive time's, messageId the
// deposit id.
func MailMessagePath(month MailYearMonth, messageId Id) string {
	return mailDatedShardedPath(mailMessageFamily, month, mailBinaryName(messageId[:]))
}

// r/<yyyymm>/<h>/<id>: a mailbox's reference to a group message, by the group message's month and id.
func MailGroupRefPath(month MailYearMonth, messageId Id) string {
	return mailDatedShardedPath(mailGroupRefFamily, month, mailBinaryName(messageId[:]))
}

// i/<yyyymm>: the month's index segments, which a writer lists for the highest <n>.
func MailIndexDirectory(month MailYearMonth) string {
	return mailIndexFamily + "/" + month.String()
}

// i/<yyyymm>/<n>: one index segment of the month.
func MailIndexPath(month MailYearMonth, n uint64) string {
	return MailIndexDirectory(month) + "/" + strconv.FormatUint(n, 10)
}

// f/<yyyymm>: the month's flag segments, which a writer lists for the highest <n>.
func MailFlagDirectory(month MailYearMonth) string {
	return mailFlagFamily + "/" + month.String()
}

// f/<yyyymm>/<n>: one flag segment of the month, which holds ops on that month's messages.
func MailFlagPath(month MailYearMonth, n uint64) string {
	return MailFlagDirectory(month) + "/" + strconv.FormatUint(n, 10)
}

// Whether text is <n> as a path spells it: decimal with no leading zero, from 0. false for anything else, so a name a
// reader lists that is not a segment is passed over.
func ParseMailSegmentNumber(text string) (uint64, bool) {
	if text == "" || (1 < len(text) && text[0] == '0') {
		return 0, false
	}
	for index := range len(text) {
		if text[index] < '0' || '9' < text[index] {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(text, 10, 64)
	return n, err == nil
}

// vault/<h>/<entry_id>: one VaultEntry, under its own key slot (§15.8).
func MailVaultPath(entryId Id) string {
	return mailShardedPath(mailVaultFamily, mailBinaryName(entryId[:]))
}

// o/<h>/<effect_key>: one outbox entry, created only if absent (§15.10). ErrMailPathInvalid unless effectKey is 32
// bytes.
func MailOutboxPath(effectKey []byte) (string, error) {
	if len(effectKey) != mailEffectKeyByteCount {
		return "", fmt.Errorf("%w: an effect key of %d bytes", ErrMailPathInvalid, len(effectKey))
	}
	return mailShardedPath(mailOutboxFamily, mailBinaryName(effectKey)), nil
}

// or/<h>/<effect_key>: one send's outcomes per recipient domain (§14.5). ErrMailPathInvalid unless effectKey is 32
// bytes.
func MailOutcomePath(effectKey []byte) (string, error) {
	if len(effectKey) != mailEffectKeyByteCount {
		return "", fmt.Errorf("%w: an effect key of %d bytes", ErrMailPathInvalid, len(effectKey))
	}
	return mailShardedPath(mailOutcomeFamily, mailBinaryName(effectKey)), nil
}

// p/<sidecar_id>: a prover host's measured cap and DATA rate (§14.5). Unsharded, one per prover host.
func MailProverPath(sidecarId Id) string {
	return mailProverFamily + "/" + mailBinaryName(sidecarId[:])
}

// ra/<h>/<token>: a reverse alias (§15.10), token r-<token>'s, as a MailRecipient's Token holds it.
// ErrMailPathInvalid for a token no reverse alias can have.
func MailReverseAliasPath(token string) (string, error) {
	if !validMailToken(token) || mailLocalPartMaxByteCount < len(mailReverseAliasPrefix)+len(token) {
		return "", fmt.Errorf("%w: not a reverse alias token", ErrMailPathInvalid)
	}
	return mailShardedPath(mailReverseAliasFamily, token), nil
}

// addr/<h>/<address>: one MailAddress in mailcfg, created only if absent (§15.8). address is lowercase, as
// MailRecipient.Address spells it; ErrMailPathInvalid for a name no path can hold.
func MailAddressPath(address string) (string, error) {
	if !validMailPathName(address) {
		return "", fmt.Errorf("%w: not an address", ErrMailPathInvalid)
	}
	return mailShardedPath(mailAddressFamily, address), nil
}

// burner/<h>/<blabel>: one MailBurner in mailcfg, kept forever once burned (§15.9). ErrMailPathInvalid unless
// burnerLabel is a lowercase word-number label.
func MailBurnerPath(burnerLabel string) (string, error) {
	if !validMailPathName(burnerLabel) || !IsWordNumberDnsLabel(burnerLabel) {
		return "", fmt.Errorf("%w: not a burner label", ErrMailPathInvalid)
	}
	return mailShardedPath(mailBurnerFamily, burnerLabel), nil
}

// Whether err is evs's DIRECTORY_FULL (§11.7's name table), which no retry of the same path can pass: a mail writer
// answers it to its caller as a refusal, never by retrying.
func IsMailDirectoryFull(err error) bool {
	var evsError *EvsError
	return errors.As(err, &evsError) && evsError.Code == protocol.EvsRefusalCode_EVS_REFUSAL_DIRECTORY_FULL
}
