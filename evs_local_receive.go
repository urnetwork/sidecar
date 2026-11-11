//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// The receive path (DESIGN-DETAILS 8.2.8, 8.2.9, 8.5; EVS1-M2-36): stock git pushes to a mount's bare repository, and
// the daemon answers each ref update after evs does, through the pre-receive and proc-receive hooks
// (evs_local_hook.go).
//
//	pre-receive    refuses the whole push, printing why, for an update of a ref outside refs/heads/ and refs/tags/;
//	               one bringing a new commit (8.2.3's C) whose committer is no client of this sidecar, printing
//	               both config values and naming `ur evs import`; and a new commit or tree that is not canonical, a
//	               tree the reader refuses or a blob over 2 GiB. It reads the quarantined objects.
//	proc-receive   git's protocol, version 1 and no atomic, each update answered on its own, ReceiveRefCount at once
//
//	a shared ref   refused before any evs write as `ng <r> <reason>`: a name only branches and tags reach, a reserved
//	               name (erasure, ur/index, ur/lfs), another sidecar's owned ref, a standing tag, a tag of a
//	               non-commit, anything but a deletion of a ref stopped at a refused version; then P_r within
//	               ReceiveWaitTimeout (else busy); under L_r settle, the local ref held to old (else
//	               non-fast-forward), the journal's RECEIVED, and (b, E) read; publish, journaling each attempt SENT
//	               before its first POST; then `ok` once the push id is in the history and the local ref moved,
//	               `non-fast-forward` only when the tip moved and no attempt is in the history, `remote outcome
//	               pending` with the outcome unknown, `busy` past ReceiveWaitTimeout with nothing live, `too slow` at
//	               ReceivePublishTimeout, and `<CODE>` otherwise
//	an owned ref   ur/<this sidecar>/...: accepted at once: the journal's RECEIVED, git update-ref new old, LOCAL, ok;
//	               then the queue, QueueFirstDelay after and once per QueueInterval, one push for everything queued;
//	               a final refusal holds the queue until the local ref moves or `ur evs retry`. A ref under
//	               ur/<this sidecar>/import/ takes only its deletion, refused before the journal as `import helper`
//	restart        stale git lock files removed; journals read; RECEIVED settled (shared deleted; owned moved when its
//	               local ref is still old, then LOCAL); settle where applied_tip is not the tip; resolve for each SENT
//	               (evs_local_journal.go); a conflict branch with no journal queued; then listeners open
//
// SEGMENT_GONE, 429 and GATE_CLOSED never reach git as non-fast-forward; `ok` comes only after the local ref moved;
// each ref reports its own status and `git push --atomic` fails before any write (receive.advertiseAtomic false). No
// statement is sent again after a restart.
//
// Desktop legs only. Safe for concurrent use.

package sidecar

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The largest blob a new commit may bring (DESIGN-DETAILS 8.2.8's pre-receive row): §11.19's file bound.
const evsLocalReceiveBlobMaxByteCount = 2 * 1024 * 1024 * 1024

// The refs only the local tier names, never a client (plan-EVS1-ref-name-bytes#3(2)).
var evsLocalReservedBranchNames = [][]byte{[]byte("erasure"), []byte("ur/index"), []byte("ur/lfs")}

// The zero oid git names none by.
const evsGitZeroOidText = "0000000000000000000000000000000000000000"

// One mount's receive path and owned refs' queue.
type EvsGitReceiver struct {
	mounts   *EvsMounts
	mount    *EvsLocalRepo
	client   *EvsClient
	repo     *EvsRepo
	engine   *EvsGitSyncEngine
	settings *EvsSettings
	clock    Clock

	stateLock sync.Mutex
	// each owned ref's next push time, and the queue loop's wake
	queueDue    map[Id]time.Time
	queueWakeup chan struct{}
	// the last push the queue made per ref, which QueueInterval spaces
	queuedAt map[Id]time.Time
}

// The receiver of mount.
func newEvsGitReceiver(mounts *EvsMounts, mount *EvsLocalRepo) *EvsGitReceiver {
	self := &EvsGitReceiver{
		mounts: mounts, mount: mount, client: mounts.client, repo: mounts.client.Repo(mount.RepoId), engine: mount.sync,
		settings: mounts.client.settings, clock: mounts.client.clock, queueDue: map[Id]time.Time{},
		queueWakeup: make(chan struct{}, 1), queuedAt: map[Id]time.Time{},
	}
	mount.sync.setQueueWake(func(refId Id) { self.queue(refId, 0) })
	return self
}

// This sidecar's clients, whose commits a push may carry as new: the host's Sidecar.ClientIds, else this client.
func (self *EvsGitReceiver) ownClient() func(clientId Id) bool {
	clientIds := []Id{self.client.args.Identity().ClientId}
	if lookup := self.mounts.ownClients(); lookup != nil {
		if listed, err := lookup(); err == nil {
			clientIds = listed
		}
	}
	return func(clientId Id) bool {
		return slices.Contains(clientIds, clientId)
	}
}

// pre-receive: see the file header. It answers the hook's exit code.
func (self *EvsGitReceiver) preReceive(ctx context.Context, session *EvsGitReceiveSession, header *EvsGitHookHeader, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	refuse := func(format string, values ...any) int {
		fmt.Fprintf(stderr, "ur: "+format+"\n", values...)
		return 1
	}
	env, err := self.mount.quarantineEnvironment(header)
	if err != nil {
		return refuse("%v", err)
	}
	objects, err := self.mount.objectsWith(ctx, env)
	if err != nil {
		return refuse("the pushed objects cannot be read: %v", err)
	}
	defer objects.Close()
	own := self.ownClient()
	identity := self.client.args.Identity()
	scanner := bufio.NewScanner(stdin)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 {
			return refuse("pre-receive read an update it cannot parse")
		}
		oldText, newText, gitRef := fields[0], fields[1], fields[2]
		if !strings.HasPrefix(gitRef, evsGitBranchPrefix) && !strings.HasPrefix(gitRef, evsGitTagPrefix) {
			return refuse("%s is no branch or tag: only refs/heads/ and refs/tags/ reach evs", gitRef)
		}
		if newText == evsGitZeroOidText {
			continue
		}
		newOid, err := evsGitOidDecodeHex([]byte(newText))
		if err != nil {
			return refuse("%s: an update to no oid", gitRef)
		}
		peeled, _, err := evsGitPeel(ctx, objects, newOid)
		if err != nil {
			return refuse("%s: %v", gitRef, err)
		}
		args := []string{"rev-list", "--topo-order", "--reverse", peeled.String(), "--not"}
		if oldText != evsGitZeroOidText {
			args = append(args, oldText)
		}
		args = append(args, "--glob="+evsLocalEvsRefPrefix+"*")
		out, err := self.mount.git.RunWith(ctx, &EvsGitRunArgs{Dir: self.mount.BareDir, Args: args, Env: env})
		if err != nil {
			return refuse("%s: the pushed history cannot be walked", gitRef)
		}
		for _, line := range strings.Fields(string(out)) {
			oid, err := evsGitOidDecodeHex([]byte(line))
			if err != nil {
				return refuse("%s: rev-list answered no oid", gitRef)
			}
			sealed, _, err := evsGitSealCommit(ctx, objects, oid)
			if err != nil {
				return refuse("%s: commit %s: %v", gitRef, oid, err)
			}
			if err := evsGitCheckNewCommit(oid, sealed, own); err != nil {
				decoded, decodeErr := EvsGitCommitDecode(sealed.GetObject())
				found := "unreadable"
				if decodeErr == nil {
					found = string(decoded.Committer)
				}
				label := session.Mount.AgentLabel
				return refuse("%s: %v\n  its committer is %s\n  this sidecar's is: git config committer.name '%s' and git config committer.email '%s'\n"+
					"  history by others goes in with ur evs import", gitRef, err, found, label, SidecarCommitterEmail(identity.ClientId))
			}
			for _, change := range sealed.GetChanges() {
				if len(change.GetGitOid()) == 0 || change.GetMode() == EvsGitModeGitlink {
					continue
				}
				size, err := objects.size(EvsGitOid(change.GetGitOid()))
				if err != nil {
					return refuse("%s: commit %s names a blob it does not bring", gitRef, oid)
				}
				if evsLocalReceiveBlobMaxByteCount < size {
					return refuse("%s: commit %s brings a blob of %d bytes, past 2 GiB", gitRef, oid, size)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return refuse("pre-receive's input: %v", err)
	}
	return 0
}

// A mount's objects read through one cat-file --batch and one --batch-check with env added: the quarantine's for a
// hook. The caller closes it.
type evsLocalHookObjects struct {
	*EvsLocalObjects
	check   *EvsGitProcess
	checked *bufio.Reader
}

// Starts the readers.
func (self *EvsLocalRepo) objectsWith(ctx context.Context, env []string) (*evsLocalHookObjects, error) {
	process, err := self.git.StartWith(ctx, self.BareDir, env, "cat-file", "--batch")
	if err != nil {
		return nil, err
	}
	check, err := self.git.StartWith(ctx, self.BareDir, env, "cat-file", "--batch-check")
	if err != nil {
		process.Close()
		return nil, err
	}
	return &evsLocalHookObjects{
		EvsLocalObjects: &EvsLocalObjects{process: process, reader: bufio.NewReaderSize(process.Stdout, 64*1024)},
		check:           check, checked: bufio.NewReader(check.Stdout),
	}, nil
}

// Ends both readers.
func (self *evsLocalHookObjects) Close() error {
	self.check.Close()
	return self.EvsLocalObjects.Close()
}

// An object's size, by --batch-check.
func (self *evsLocalHookObjects) size(oid EvsGitOid) (int64, error) {
	if _, err := io.WriteString(self.check.Stdin, oid.String()+"\n"); err != nil {
		return 0, err
	}
	line, err := self.checked.ReadString('\n')
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(line)
	if len(fields) != 3 || fields[0] != oid.String() {
		return 0, ErrEvsGitObjectMissing
	}
	var size int64
	if _, err := fmt.Sscan(fields[2], &size); err != nil {
		return 0, err
	}
	return size, nil
}

// One update proc-receive was given.
type evsGitReceiveCommand struct {
	gitRef string
	old    *EvsGitOid
	new    *EvsGitOid
}

// proc-receive: git's protocol (gitprotocol-common's pkt-lines; githooks(5)'s proc-receive): the version, the
// commands, each answered on its own, ReceiveRefCount at once, then every status in the commands' order.
func (self *EvsGitReceiver) procReceive(ctx context.Context, session *EvsGitReceiveSession, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	fail := func(format string, values ...any) int {
		fmt.Fprintf(stderr, "ur: "+format+"\n", values...)
		return 1
	}
	reader := NewEvsPktLineReader(stdin)
	write := func(lines ...EvsPktLine) error {
		for _, line := range lines {
			encoded, err := line.Encode()
			if err != nil {
				return err
			}
			if _, err := stdout.Write(encoded); err != nil {
				return err
			}
		}
		return nil
	}
	readUntilFlush := func() ([][]byte, error) {
		lines := [][]byte{}
		for {
			line, err := reader.Next()
			if err != nil {
				return nil, err
			}
			if line.Kind == EvsPktLineFlush {
				return lines, nil
			}
			lines = append(lines, bytes.Clone(line.Text()))
		}
	}
	versions, err := readUntilFlush()
	if err != nil || len(versions) == 0 || !bytes.HasPrefix(versions[0], []byte("version=1")) {
		return fail("proc-receive's version negotiation failed")
	}
	// version 1 and no capability: no push-options, no atomic
	if err := write(EvsPktLine{Kind: EvsPktLineData, Payload: []byte("version=1\n")}, EvsPktLine{Kind: EvsPktLineFlush}); err != nil {
		return fail("proc-receive's version line: %v", err)
	}
	lines, err := readUntilFlush()
	if err != nil {
		return fail("proc-receive's commands: %v", err)
	}
	commands := []*evsGitReceiveCommand{}
	for _, line := range lines {
		fields := strings.Fields(string(line))
		if len(fields) != 3 {
			return fail("proc-receive read a command it cannot parse")
		}
		command := &evsGitReceiveCommand{gitRef: fields[2]}
		for i, text := range fields[:2] {
			if text == evsGitZeroOidText {
				continue
			}
			oid, err := evsGitOidDecodeHex([]byte(text))
			if err != nil {
				return fail("proc-receive read a command with no oid")
			}
			if i == 0 {
				command.old = &oid
			} else {
				command.new = &oid
			}
		}
		commands = append(commands, command)
	}
	statuses := make([]string, len(commands))
	slots := make(chan struct{}, max(1, self.settings.ReceiveRefCount))
	wait := sync.WaitGroup{}
	for i, command := range commands {
		wait.Add(1)
		slots <- struct{}{}
		go func() {
			defer wait.Done()
			defer func() { <-slots }()
			statuses[i] = self.receive(ctx, session, command)
		}()
	}
	wait.Wait()
	answer := []EvsPktLine{}
	for _, status := range statuses {
		answer = append(answer, EvsPktLine{Kind: EvsPktLineData, Payload: []byte(status + "\n")})
	}
	answer = append(answer, EvsPktLine{Kind: EvsPktLineFlush})
	if err := write(answer...); err != nil {
		return fail("proc-receive's report: %v", err)
	}
	return 0
}

// One update's answer, "ok <ref>" or "ng <ref> <reason>": see the file header.
func (self *EvsGitReceiver) receive(ctx context.Context, session *EvsGitReceiveSession, command *evsGitReceiveCommand) string {
	ng := func(reason string) string {
		return "ng " + command.gitRef + " " + reason
	}
	refName, err := EvsGitRefName(command.gitRef)
	if err != nil {
		return ng("only branches and tags reach evs, and no branch named refs/...")
	}
	for _, reserved := range evsLocalReservedBranchNames {
		if bytes.Equal(refName, reserved) {
			return ng("a ref only the daemon names")
		}
	}
	sidecarId := self.client.args.Identity().SidecarId
	owned := false
	if ownerId, ok := EvsOwnedRefOwner(refName); ok {
		if ownerId != sidecarId {
			return ng("another sidecar's ref")
		}
		owned = true
	} else if bytes.HasPrefix(refName, []byte(evsOwnedRefPrefix)) {
		return ng("a ref under ur/ that names no sidecar")
	}
	if _, _, _, ok := ParseEvsImportHelperRefName(refName); ok && command.new != nil {
		return ng("import helper")
	}
	refId, err := self.repo.resolveRefId(ctx, refName, nil)
	if err != nil {
		return ng("the repo's keys are not held")
	}
	record, err := self.engine.GitRef(ctx, refId)
	if err != nil {
		return ng("the ref's state cannot be read")
	}
	if record.StuckAt != 0 && command.new != nil {
		return ng(fmt.Sprintf("ref refused at version %d", record.StuckAt))
	}
	if command.new != nil {
		if strings.HasPrefix(command.gitRef, evsGitTagPrefix) && (record.Tip != nil || command.old != nil) {
			return ng("tag exists")
		}
		objects, err := self.mount.Objects(ctx)
		if err != nil {
			return ng("the pushed objects cannot be read")
		}
		_, _, err = evsGitPeel(ctx, objects, *command.new)
		objects.Close()
		if err != nil {
			return ng("tag of a non-commit")
		}
	}
	if owned {
		return self.receiveOwned(ctx, refId, refName, command)
	}
	return self.receiveShared(ctx, session, refId, refName, record, command)
}

// The test hook at the receive path's points (publish.sent, publish.answer, receive.local), nil outside tests: an
// error stops the update there, as a kill would.
var evsLocalReceiveKillHook func(point string) error

// The receive path's barriers (DESIGN-DETAILS 8.6), keyed <repo>:<ref>.
const (
	evsLocalBarrierPublishSent   = "evs.local.publish.sent"
	evsLocalBarrierPublishAnswer = "evs.local.publish.answer"
	evsLocalBarrierReceiveLocal  = "evs.local.receive.local"
	evsLocalBarrierQueueSend     = "evs.local.queue.send"
)

// A shared ref's receive: see the file header.
func (self *EvsGitReceiver) receiveShared(ctx context.Context, session *EvsGitReceiveSession, refId Id, refName []byte, record *EvsGitRef, command *evsGitReceiveCommand) string {
	ng := func(reason string) string {
		return "ng " + command.gitRef + " " + reason
	}
	releaseUpkeep, err := self.mount.locks.LockUpkeepShared(ctx)
	if err != nil {
		return ng("busy")
	}
	defer releaseUpkeep()
	waitCtx, cancelWait := context.WithTimeout(ctx, self.settings.ReceiveWaitTimeout)
	releasePublish, err := self.mount.locks.LockPublish(waitCtx, refId)
	cancelWait()
	if err != nil {
		return ng("busy")
	}
	defer releasePublish()
	// an attempt a restart left SENT is resolved first: its update is open until it is
	if err := self.resolve(ctx, refId); err != nil && self.client.log.V(1).Enabled() {
		self.client.log.Infof("[evs]resolve of repo %s ref %s: %v", self.mount.RepoId, refId, err)
	}
	var update *EvsJournalUpdate
	reason := ""
	err = self.withApply(ctx, refId, func() error {
		ref, err := self.engine.state.gitRef(refId)
		if err != nil {
			return err
		}
		if _, err := self.engine.settleWithLock(ctx, ref); err != nil {
			return err
		}
		local, err := self.mount.localRef(ctx, EvsGitRefOfName(refName))
		if err != nil {
			return err
		}
		journal, err := self.engine.state.journal(refId)
		if err != nil {
			return err
		}
		switch {
		case !evsOidEqual(local, command.old):
			reason = "non-fast-forward"
		case ref.StuckAt == 0 && !evsOidEqual(ref.Tip, command.old):
			reason = "non-fast-forward"
		case 0 < len(journal.Updates):
			reason = "remote outcome pending"
		}
		if reason != "" {
			return nil
		}
		journal.RefName = refName
		update = journal.add(command.old, command.new, EvsJournalReceived, EvsJournalKindReceive, self.clock.Now())
		*record = *ref
		return self.engine.state.writeJournal(refId, journal)
	})
	if err != nil {
		return ng("the ref's state cannot be read")
	}
	if reason != "" {
		return ng(reason)
	}
	old := record.Tip
	if record.StuckAt != 0 {
		// a stopped ref's deletion is built on the head's version with no old tip (8.5)
		old = nil
	}
	publishCtx, cancelPublish := context.WithTimeout(ctx, self.settings.ReceivePublishTimeout)
	defer cancelPublish()
	sent := false
	result, err := EvsLocalPublish(publishCtx, &EvsLocalPublishArgs{
		Mount: self.mount, Repo: self.repo, RefName: refName, Old: old, New: command.new,
		BaseVersion: record.Version, BaseChain: record.Chain, Deleted: record.Deleted, LastTip: record.LastTip,
		Base: record.Base, State: self.engine, OwnClient: self.ownClient(),
		OnAttempt: func(attempt *EvsGitPublishAttempt) error {
			sent = true
			if err := self.journalAttempt(ctx, refId, attempt); err != nil {
				return err
			}
			testHookBarrier(evsLocalBarrierPublishSent, self.engine.barrierKey(refId))
			return evsLocalKilled(evsLocalReceiveKillHook, "publish.sent")
		},
	})
	testHookBarrier(evsLocalBarrierPublishAnswer, self.engine.barrierKey(refId))
	if killErr := evsLocalKilled(evsLocalReceiveKillHook, "publish.answer"); killErr != nil {
		return ng("killed")
	}
	if err != nil {
		return self.answerRefusal(ctx, refId, update, command, err, sent, publishCtx)
	}
	// committed: applied through replay, which settles; ok once the history holds it and the local ref moved
	deadline := self.clock.Now().Add(self.settings.ReceiveWaitTimeout)
	for {
		replayErr := self.engine.Replay(ctx, refId)
		ref, err := self.engine.GitRef(ctx, refId)
		if err == nil && replayErr == nil && result.Version <= ref.Version {
			local, err := self.mount.localRef(ctx, EvsGitRefOfName(refName))
			if err == nil && evsOidEqual(local, command.new) {
				return "ok " + command.gitRef
			}
		}
		if !self.clock.Now().Before(deadline) || ctx.Err() != nil {
			return ng("committed remotely, local update pending")
		}
		select {
		case <-ctx.Done():
			return ng("committed remotely, local update pending")
		case <-self.clock.After(self.settings.QueueInterval):
		}
	}
}

// A publish's error as git hears it (DESIGN-DETAILS 8.2.8's answers): non-fast-forward only when the tip moved and no
// attempt is in the history; an unknown outcome pending, the update kept SENT; busy for evs's waits; too slow at the
// publish bound; the code otherwise, the update deleted.
func (self *EvsGitReceiver) answerRefusal(ctx context.Context, refId Id, update *EvsJournalUpdate, command *evsGitReceiveCommand, err error, sent bool, publishCtx context.Context) string {
	ng := func(reason string) string {
		return "ng " + command.gitRef + " " + reason
	}
	drop := func() {
		self.withApply(ctx, refId, func() error {
			journal, err := self.engine.state.journal(refId)
			if err != nil {
				return err
			}
			journal.deleteUpdate(update.Seq)
			return self.engine.state.writeJournal(refId, journal)
		})
	}
	evsError, isEvs := EvsErrorOf(err)
	switch {
	case errors.Is(err, ErrEvsGitTipMoved):
		drop()
		return ng("non-fast-forward")
	case publishCtx.Err() != nil && ctx.Err() == nil:
		if sent {
			return ng("remote outcome pending")
		}
		drop()
		return ng("too slow")
	case isEvs && evsError.OutcomeUnknown:
		return ng("remote outcome pending")
	case isEvs && evsError.RefusesNothing():
		drop()
		return ng("busy")
	case isEvs:
		drop()
		return ng(strings.TrimPrefix(evsError.Code.String(), "EVS_REFUSAL_"))
	case errors.Is(err, ErrEvsDirectoryFull):
		drop()
		return ng("DIRECTORY_FULL")
	case errors.Is(err, ErrEvsGitUpdateInvalid), errors.Is(err, ErrEvsGitObjectInvalid), errors.Is(err, ErrEvsWriteInvalid):
		drop()
		return ng("refused: " + evsOneLine(err.Error()))
	case sent:
		// no answer to an attempt sent: the history decides, never this daemon (G7)
		return ng("remote outcome pending")
	default:
		drop()
		return ng("refused: " + evsOneLine(err.Error()))
	}
}

// An error's text on one line, as a status line carries it.
func evsOneLine(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

// Runs f under L_r.
func (self *EvsGitReceiver) withApply(ctx context.Context, refId Id, f func() error) error {
	release, err := self.mount.locks.LockApply(ctx, refId)
	if err != nil {
		return err
	}
	defer release()
	return f()
}

// Journals an attempt before its first POST (8.2.8's SENT row): its push id, statement hash, base and time, every
// update it covers SENT.
func (self *EvsGitReceiver) journalAttempt(ctx context.Context, refId Id, attempt *EvsGitPublishAttempt) error {
	return self.withApply(ctx, refId, func() error {
		journal, err := self.engine.state.journal(refId)
		if err != nil {
			return err
		}
		journal.addAttempt(&EvsJournalAttempt{
			PushId: attempt.PushId, StatementSha256: evsStatementHashText(attempt.StatementSha256),
			BaseVersion: attempt.BaseVersion, BaseChain: hex.EncodeToString(attempt.BaseChain[:]), Old: evsOidText(attempt.Old),
			New: evsOidText(attempt.New), TimeMs: attempt.TimeMs, Parts: attempt.Parts,
		})
		return self.engine.state.writeJournal(refId, journal)
	})
}

// An owned ref's receive (see the file header): accepted at once, its push queued.
func (self *EvsGitReceiver) receiveOwned(ctx context.Context, refId Id, refName []byte, command *evsGitReceiveCommand) string {
	ng := func(reason string) string {
		return "ng " + command.gitRef + " " + reason
	}
	answer := ""
	err := self.withApply(ctx, refId, func() error {
		journal, err := self.engine.state.journal(refId)
		if err != nil {
			return err
		}
		journal.RefName = refName
		update := journal.add(command.old, command.new, EvsJournalReceived, EvsJournalKindReceive, self.clock.Now())
		if err := self.engine.state.writeJournal(refId, journal); err != nil {
			return err
		}
		testHookBarrier(evsLocalBarrierReceiveLocal, self.engine.barrierKey(refId))
		if err := evsLocalKilled(evsLocalReceiveKillHook, "receive.local"); err != nil {
			return err
		}
		if err := self.mount.updateRefs(ctx, []string{evsUpdateRefLine(command.gitRef, command.new, command.old)}); err != nil {
			journal.deleteUpdate(update.Seq)
			answer = ng("non-fast-forward")
			return self.engine.state.writeJournal(refId, journal)
		}
		update.State = EvsJournalLocal
		answer = "ok " + command.gitRef
		return self.engine.state.writeJournal(refId, journal)
	})
	if err != nil {
		return ng("the ref's state cannot be written")
	}
	if strings.HasPrefix(answer, "ok ") {
		self.queue(refId, self.settings.QueueFirstDelay)
	}
	return answer
}

// Asks the queue to push refId after delay, at most once per QueueInterval.
func (self *EvsGitReceiver) queue(refId Id, delay time.Duration) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		due := self.clock.Now().Add(delay)
		if last, ok := self.queuedAt[refId]; ok && due.Before(last.Add(self.settings.QueueInterval)) {
			due = last.Add(self.settings.QueueInterval)
		}
		if held, ok := self.queueDue[refId]; !ok || due.Before(held) {
			self.queueDue[refId] = due
		}
	}()
	select {
	case self.queueWakeup <- struct{}{}:
	default:
	}
}

// The refs due now, and the time the next is due (zero for none).
func (self *EvsGitReceiver) dueQueue() ([]Id, time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	now := self.clock.Now()
	due := []Id{}
	next := time.Time{}
	for refId, at := range self.queueDue {
		if !at.After(now) {
			due = append(due, refId)
			delete(self.queueDue, refId)
			self.queuedAt[refId] = now
			continue
		}
		if next.IsZero() || at.Before(next) {
			next = at
		}
	}
	slices.SortFunc(due, func(a Id, b Id) int { return bytes.Compare(a[:], b[:]) })
	return due, next
}

// The queue's loop until ctx ends: each due owned ref pushed, and every SENT attempt asked again each
// JournalResolveInterval.
func (self *EvsGitReceiver) runQueue(ctx context.Context) error {
	resolveAt := self.clock.After(self.settings.JournalResolveInterval)
	for {
		due, next := self.dueQueue()
		for _, refId := range due {
			if err := self.publishQueued(ctx, refId); err != nil && ctx.Err() == nil {
				self.client.log.Warningf("[evs]the queue of repo %s ref %s: %v", self.mount.RepoId, refId, err)
				// tried again at the interval; a final refusal holds instead (publishQueued)
				self.queue(refId, self.settings.QueueInterval)
			}
		}
		var timer <-chan time.Time
		if !next.IsZero() {
			timer = self.clock.After(next.Sub(self.clock.Now()))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-self.queueWakeup:
		case <-timer:
		case <-resolveAt:
			resolveAt = self.clock.After(self.settings.JournalResolveInterval)
			self.resolveAll(ctx)
		}
	}
}

// The final refusals that hold an owned ref's queue until its local ref moves or `ur evs retry` (8.2.8's queue rows).
var evsLocalQueueHoldCodes = []protocol.EvsRefusalCode{
	protocol.EvsRefusalCode_EVS_REFUSAL_REF_MODE, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE,
	protocol.EvsRefusalCode_EVS_REFUSAL_VERSIONING, protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED,
}

// One push of an owned ref's queue (8.2.8's queue row): everything queued in one push from evs's tip to the local ref,
// FORCE when it does not descend.
func (self *EvsGitReceiver) publishQueued(ctx context.Context, refId Id) error {
	releaseUpkeep, err := self.mount.locks.LockUpkeepShared(ctx)
	if err != nil {
		return err
	}
	defer releaseUpkeep()
	releasePublish, err := self.mount.locks.LockPublish(ctx, refId)
	if err != nil {
		return err
	}
	defer releasePublish()
	if err := self.resolve(ctx, refId); err != nil {
		return err
	}
	var record *EvsGitRef
	var local *EvsGitOid
	var refName []byte
	skip := false
	err = self.withApply(ctx, refId, func() error {
		ref, err := self.engine.state.gitRef(refId)
		if err != nil {
			return err
		}
		journal, err := self.engine.state.journal(refId)
		if err != nil {
			return err
		}
		refName = journal.RefName
		if len(refName) == 0 {
			refName = ref.Name
		}
		if len(refName) == 0 {
			skip = true
			return nil
		}
		if local, err = self.mount.localRef(ctx, EvsGitRefOfName(refName)); err != nil {
			return err
		}
		if journal.HoldCode != "" {
			if journal.HoldLocal == evsOidText(local) {
				skip = true
				return nil
			}
			// the local ref moved: the hold goes
			journal.HoldCode, journal.HoldMs, journal.HoldLocal = "", 0, ""
			if err := self.engine.state.writeJournal(refId, journal); err != nil {
				return err
			}
		}
		if evsOidEqual(local, ref.Tip) || (local == nil && ref.Tip == nil) {
			skip = true
			return self.engine.dropCoveredWithLock(ctx, ref, journal)
		}
		record = ref
		return nil
	})
	if err != nil || skip {
		return err
	}
	testHookBarrier(evsLocalBarrierQueueSend, self.engine.barrierKey(refId))
	if err := evsLocalKilled(evsLocalReceiveKillHook, "queue.send"); err != nil {
		return err
	}
	result, err := EvsLocalPublish(ctx, &EvsLocalPublishArgs{
		Mount: self.mount, Repo: self.repo, RefName: refName, Old: record.Tip, New: local, BaseVersion: record.Version,
		BaseChain: record.Chain, Deleted: record.Deleted, LastTip: record.LastTip, Base: record.Base, State: self.engine,
		OwnClient: self.ownClient(),
		OnAttempt: func(attempt *EvsGitPublishAttempt) error {
			return self.journalAttempt(ctx, refId, attempt)
		},
	})
	if err == nil {
		_ = result
		return self.engine.Replay(ctx, refId)
	}
	if errors.Is(err, ErrEvsGitTipMoved) {
		// replay and settle: the rule keeps, follows or conflicts; then again
		if replayErr := self.engine.Replay(ctx, refId); replayErr != nil {
			return replayErr
		}
		self.queue(refId, self.settings.QueueInterval)
		return nil
	}
	if evsError, ok := EvsErrorOf(err); ok && slices.Contains(evsLocalQueueHoldCodes, evsError.Code) {
		return self.hold(ctx, refId, strings.TrimPrefix(evsError.Code.String(), "EVS_REFUSAL_"), local)
	}
	if errors.Is(err, ErrEvsDirectoryFull) || errors.Is(err, ErrEvsGitUpdateInvalid) {
		return self.hold(ctx, refId, evsOneLine(err.Error()), local)
	}
	return err
}

// Holds an owned ref's queue on a final refusal: `ur status` shows the code, and the queue waits for the local ref to
// move or `ur evs retry`; the commits stay on the local ref.
func (self *EvsGitReceiver) hold(ctx context.Context, refId Id, code string, local *EvsGitOid) error {
	return self.withApply(ctx, refId, func() error {
		journal, err := self.engine.state.journal(refId)
		if err != nil {
			return err
		}
		journal.HoldCode, journal.HoldMs, journal.HoldLocal = code, self.clock.Now().UnixMilli(), evsOidText(local)
		// what was sent is resolved from the history; the updates wait as LOCAL
		for _, update := range journal.Updates {
			update.State = EvsJournalLocal
		}
		journal.Attempts = nil
		return self.engine.state.writeJournal(refId, journal)
	})
}

// `ur evs retry` (DESIGN-DETAILS 8.7): every held queue of the mount released and pushed again; refName nil retries
// every one. It answers the refs it released.
func (self *EvsGitReceiver) Retry(ctx context.Context, refName []byte) ([][]byte, error) {
	refIds, err := self.engine.state.journalRefIds()
	if err != nil {
		return nil, err
	}
	released := [][]byte{}
	for _, refId := range refIds {
		name := []byte(nil)
		err := self.withApply(ctx, refId, func() error {
			journal, err := self.engine.state.journal(refId)
			if err != nil {
				return err
			}
			if journal.HoldCode == "" || (refName != nil && !bytes.Equal(journal.RefName, refName)) {
				return nil
			}
			journal.HoldCode, journal.HoldMs, journal.HoldLocal = "", 0, ""
			name = journal.RefName
			return self.engine.state.writeJournal(refId, journal)
		})
		if err != nil {
			return nil, err
		}
		if name != nil {
			released = append(released, name)
			self.queue(refId, 0)
		}
	}
	return released, nil
}

// The restart's receive steps (see the file header's restart row), the sync engine's own having run.
func (self *EvsGitReceiver) Start(ctx context.Context) error {
	refIds, err := self.engine.state.journalRefIds()
	if err != nil {
		return err
	}
	sidecarId := self.client.args.Identity().SidecarId
	for _, refId := range refIds {
		sent := false
		err := self.withApply(ctx, refId, func() error {
			journal, err := self.engine.state.journal(refId)
			if err != nil {
				return err
			}
			_, owned := EvsOwnedRefOwner(journal.RefName)
			changed := false
			for _, update := range slices.Clone(journal.Updates) {
				switch update.State {
				case EvsJournalReceived:
					changed = true
					if !owned {
						journal.deleteUpdate(update.Seq)
						continue
					}
					gitRef := EvsGitRefOfName(journal.RefName)
					local, err := self.mount.localRef(ctx, gitRef)
					if err != nil {
						return err
					}
					old, _ := evsOidOfText(update.Old)
					new, _ := evsOidOfText(update.New)
					if evsOidEqual(local, old) {
						if err := self.mount.updateRefs(ctx, []string{evsUpdateRefLine(gitRef, new, old)}); err != nil {
							journal.deleteUpdate(update.Seq)
							continue
						}
						update.State = EvsJournalLocal
					} else if !evsOidEqual(local, new) {
						journal.deleteUpdate(update.Seq)
					} else {
						update.State = EvsJournalLocal
					}
				case EvsJournalSent:
					sent = true
				}
			}
			if changed {
				return self.engine.state.writeJournal(refId, journal)
			}
			return nil
		})
		if err != nil {
			return err
		}
		if sent {
			if err := self.resolve(ctx, refId); err != nil && self.client.log.V(1).Enabled() {
				self.client.log.Infof("[evs]resolve of repo %s ref %s: %v", self.mount.RepoId, refId, err)
			}
		}
		self.queue(refId, 0)
	}
	// a conflict branch settle made before a crash took its queue entry
	branches, err := self.engine.ConflictBranches(ctx)
	if err != nil {
		return err
	}
	for _, branch := range branches {
		if owner, ok := EvsOwnedRefOwner(branch); !ok || owner != sidecarId {
			continue
		}
		refId, err := self.repo.resolveRefId(ctx, branch, nil)
		if err != nil {
			return err
		}
		if slices.Contains(refIds, refId) {
			continue
		}
		record, err := self.engine.GitRef(ctx, refId)
		if err != nil {
			return err
		}
		local, err := self.mount.localRef(ctx, evsGitBranchPrefix+string(branch))
		if err != nil {
			return err
		}
		if local == nil || evsOidEqual(local, record.Tip) {
			continue
		}
		if err := self.engine.queueConflict(ctx, &evsGitSettled{conflictRef: branch, conflictCommit: local}); err != nil {
			return err
		}
	}
	return nil
}

// Runs the mount: the sync engine's restart and loop, and the receive path's restart and queue, until ctx ends.
func (self *EvsLocalRepo) Run(ctx context.Context) error {
	if err := self.sync.Start(ctx); err != nil {
		self.sync.client.log.Warningf("[evs]the mount of repo %s did not start clean: %v", self.RepoId, err)
	}
	if err := self.receiver.Start(ctx); err != nil {
		self.sync.client.log.Warningf("[evs]the receive path of repo %s did not start clean: %v", self.RepoId, err)
	}
	queued := make(chan error, 1)
	go func() {
		queued <- self.receiver.runQueue(ctx)
	}()
	err := self.sync.Run(ctx)
	<-queued
	self.sync.unregisterIndexes()
	return err
}

// The receiver of the mount.
func (self *EvsLocalRepo) Receiver() *EvsGitReceiver {
	return self.receiver
}

// An import's attempt journaled before its first POST: an update of kind 3 SENT with it, so a restart resolves an
// import's push from the history as it does any other (DESIGN-DETAILS 8.2.8; a helper's DELETE included).
func (self *EvsGitReceiver) journalImportAttempt(ctx context.Context, refId Id, refName []byte, attempt *EvsGitPublishAttempt) error {
	return self.withApply(ctx, refId, func() error {
		journal, err := self.engine.state.journal(refId)
		if err != nil {
			return err
		}
		journal.RefName = refName
		open := false
		for _, update := range journal.Updates {
			open = open || (update.Kind == EvsJournalKindImport && update.New == evsOidText(attempt.New))
		}
		if !open {
			journal.add(attempt.Old, attempt.New, EvsJournalSent, EvsJournalKindImport, self.clock.Now())
		}
		journal.addAttempt(&EvsJournalAttempt{
			PushId: attempt.PushId, StatementSha256: evsStatementHashText(attempt.StatementSha256),
			BaseVersion: attempt.BaseVersion, BaseChain: hex.EncodeToString(attempt.BaseChain[:]), Old: evsOidText(attempt.Old),
			New: evsOidText(attempt.New), TimeMs: attempt.TimeMs, Parts: attempt.Parts,
		})
		return self.engine.state.writeJournal(refId, journal)
	})
}
