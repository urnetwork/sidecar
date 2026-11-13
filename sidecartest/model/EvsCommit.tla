----------------------------- MODULE EvsCommit -----------------------------
(***************************************************************************)
(* §22.8's model of evs's commit: the separate durable objects of §11.8 and *)
(* the processes that race over them, none joined by a transaction.         *)
(*                                                                          *)
(* Objects, one variable each: head (fence, refusal records, seal lease and *)
(* collect window included), batch records, packs and parcels with their    *)
(* pidx/ entries, idx/ entries, segments with their upload receipts, slots, *)
(* pmap, log pages, gen, epoch, repo, proj and rev.                         *)
(*                                                                          *)
(* Processes: writers (pushes, and on the git-mode ref the lease route,     *)
(* parts and seals), evs instances (each read its own step), segment GC,    *)
(* the shredder, two folders, the marker collector, the evacuator, the      *)
(* path-epoch mapper and copy job, and the remover. Overlay refs are        *)
(* FS-5's, so the model has none; format 2 adds variables at the marked     *)
(* places and changes none of these.                                        *)
(*                                                                          *)
(* What the model abstracts:                                                *)
(* - A window holds entries, and those are hist's: a head keeps winFrom,    *)
(*   the oldest version it holds, and an entry's fields come from hist,     *)
(*   since a version's entry never changes.                                 *)
(* - A head PUT is one step at its landing. An answer lost, or a write      *)
(*   that lands late but before the next request on its key (§19.6, which   *)
(*   StoreSettle.tla checks), is that step with a lost reply; one whose     *)
(*   drive commits stall holds the head (heldBy), which no request passes.  *)
(* - Time has two scales. hour counts long marks: 23, 24 and 25 h after an  *)
(*   upload are one, two and three marks, a statement's bound lasts at most *)
(*   one mark, and a batch evacuates three marks old. The short deadlines   *)
(*   are events: a job's write is live until its deadline passes, a window  *)
(*   moves open, settled, lapsed. Margins of clocks and milliseconds never  *)
(*   enter a state: the ASSUME below does their arithmetic over every       *)
(*   allowed offset, in the design's real numbers.                          *)
(* - One path is touched per push, its parent's delta beside it.            *)
(* - A statement lists only a slot it drew, so each slot object's origin    *)
(*   (DESIGN-DETAILS 14.2.2) is the one statement that lists it, and a      *)
(*   retoken here is a rebuild with new slots. details/EvsSlot.tla, this    *)
(*   model's companion, holds one slot id that several statements list:     *)
(*   another statement's object, the retoken's takeover, an ERASE's rewrite *)
(*   and a stalled evacuation run beside its successor.                     *)
(*                                                                          *)
(* Twin names a rule to break; a twin config sets it, and TLC must then     *)
(* refuse the model (run-tlc.sh). "none" is the design.                     *)
(*                                                                          *)
(* From M10 the module also holds §22.8's purge and drop extension, below   *)
(* the M2 part's processes: its own variables and stories, run by F2Run     *)
(* with the M2 part held still (F2Run = "none" runs the M2 part alone).     *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Writers,        \* the signers: model values
    Instances,      \* the evs processes, each also a folder: model values
    Segments,       \* segment ids: model values
    MaxVersion,     \* versions a ref may reach
    MaxPush,        \* statements signed in one behavior
    MaxAttempts,    \* attempts of one push id
    FoldTrigger,    \* 96 unfolded versions start a fold
    FoldSize,       \* 64 versions a fold, and a log page
    BaseRange,      \* 63: a file-mode base may trail the head by this much
    WindowLimit,    \* 127 window entries before a page-out
    WindowMax,      \* 255 while folds lag
    MaxGeneration,  \* generations claimed in one behavior
    MaxHour,        \* long marks in one behavior
    MaxRefused,     \* 8 refusal records a head holds
    MaxFaults,      \* lost requests, crashes and timeouts in one behavior
    Twin            \* "none", or the rule a twin config breaks

\* §11.7's and §11.8's margins are checked on the design's numbers, in ms, over every offset §19.6
\* allows a clock, instead of in any state. Times are relative to a window's CAS at 0, or a
\* statement's time_ms at 0; each offset is one process's clock less true time.
ClockBound == 50
Offsets == {0 - ClockBound, 0, ClockBound}
FoldDeadline == 15000
WindowMs == 30000
DeleteWait == 15300
DeleteLead == 50
ReopenWait == 150
FenceMargin == 100
RefusalSlack == 1000

\* The latest true time the store takes a fold's write, the fold's head read just before the CAS.
LastFoldWrite(fold, host) == FoldDeadline + fold - host

\* The earliest true time a DELETE issues, until_ms set by the opener's clock.
FirstDelete(opener, collector) == DeleteWait + opener - collector

\* The latest true time the store takes a DELETE, whose deadline is 50 ms before until_ms.
LastDelete(opener, host) == WindowMs + opener - DeleteLead - host

\* The earliest true time a fold that read the window writes over a covered marker.
FirstOverwrite(opener, fold) == WindowMs + opener + ReopenWait - fold

ASSUME
    /\ \A fold, host, opener, doer \in Offsets :
           LastFoldWrite(fold, host) < FirstDelete(opener, doer)
    /\ \A opener, host, fold \in Offsets :
           /\ LastDelete(opener, host) <= WindowMs + opener
           /\ LastDelete(opener, host) < FirstOverwrite(opener, fold)
    \* a fence ends every attempt that arrived before it in true time
    /\ \A fencer, arrival \in Offsets : arrival - fencer <= FenceMargin
    \* no attempt passes 5b once a refusal's record may drop
    /\ \A checker, dropper \in Offsets : 0 - checker < RefusalSlack - dropper
    /\ FoldSize <= FoldTrigger
    /\ BaseRange + 1 <= WindowLimit - FoldSize + 1
    /\ WindowLimit < WindowMax
    \* NoTailCheck, NoFenceRule and ResolveIgnoresPending stay for a finer model: at this one's hour
    \* marks and without tokens no invariant can see them broken (run-tlc.sh says why).
    /\ Twin \in {"none", "StaleHorizon", "UnrecordedRefusal", "CachedRefusal", "AnswerDeletes", "GcNoFence",
                 "GcNoSecondCheck", "EvacuateBeforeIndex", "PageOutUnfolded", "NoWindowWait",
                 "FoldIgnoresWindow", "VersionRestarts", "NoPinCheck", "PinFalls", "LadderFork",
                 "RestoreAfterShred", "GitPathCas", "NoFenceRule", "NoIfMatchFold", "NoTailCheck",
                 "EarlyRefusalDrop", "CopyOverwrites", "NoRetryLookup", "ResolveIgnoresPending",
                 "ReaderStaleHorizon",
                 \* the M10 part's
                 "PurgeNoAllowance", "PurgeIgnoresHold", "PurgeUnseen", "EvacDropsNewest",
                 "DropNoFence", "DropNoAgeCheck", "DropIgnoresHold"}

GitRef == "git"
FileRef == "file"
Refs == {GitRef, FileRef}

\* The ref's mode decides its commit condition; 1 ref in each mode.
GitMode(r) == r = GitRef

Dir == "D"      \* a directory
Child == "C"    \* a file in it
Leaf == "X"     \* a file beside it
Paths == {Dir, Child, Leaf}

\* Paths a change to p also reaches: a removal of the directory reaches its child.
Prefixes(p) == IF p = Child THEN {Dir} ELSE {}

NoSegment == "no segment"
NoPush == 0
PushIds == 1..MaxPush

\* Each long mark: under 23 h, 23 to 24, 24 to 25, past 25.
ReuploadStaleAge == 1
ReceiptAge == 2
OrphanAge == 3
EvacuateAge == 3
StatementMarks == 2

Max(a, b) == IF a >= b THEN a ELSE b

VARIABLES
    head,        \* head[r]
    batch,       \* pb/: the records stored, as [place, push, kind, at]
    pack,        \* pack/ and hp/: the containers, as [id, kind], one a record, id its place
    pidx,        \* pidx/: the containers an entry names, as [id, kind]
    idx,         \* idx[r][e][p]: the entry of p in path epoch e
    seg,         \* seg[s]: stored, and its LastModified mark
    slot,        \* slot[P]: "none", "stored" or "deleted", the new slot of push P, its origin P
    slotAt,      \* slotAt[P]: its LastModified mark
    pmap,        \* pmap[r]: the map parts uploaded, as [gen, source, at]
    log,         \* log[r]: pages written
    gen,         \* gen[g]: claimed generations, as [by, auth]
    epoch,       \* gkm's epoch objects, oldest first, as [by, gen]
    repo,        \* repo/: state and deletion id
    proj,        \* proj/: position n, and shrunkAt, the newest position that dropped a holder
    rev,         \* rev/: the revoked writers
    \* processes
    hour,        \* long marks passed
    faultsLeft,  \* faults a behavior may still suffer
    push,        \* statements, by id
    pushCount,   \* ids used
    attemptsMade, \* attemptsMade[P]
    att,         \* att[i]: the attempt instance i is running
    authView,    \* authView[i]: the newest position instance i's cache holds
    batchSeq,    \* batchSeq[i]: its counter
    foldJob,     \* foldJob[i]: its running fold
    foldedTo,    \* foldedTo[i][r]: what it folded and has not yet committed
    cache,       \* {evsh_}: the cached head of each ref
    heldBy,      \* heldBy[r]: the attempt whose stalled head PUT holds the key, or none
    leaseLive,   \* leaseLive[r]: until_ms of the head's lease is ahead
    blockLive,   \* blockLive[r]: block_until_ms is ahead
    window,      \* window[r]: "closed", "open", "settled": 11.7's collection window
    collector,   \* the collector's job
    evacuator,   \* the evacuator's job
    gc,          \* segment GC's job
    shred,       \* the shredder's job
    copyJob,     \* copyJob[r]: the path-epoch copy
    reader,      \* a head read or listing in progress
    \* ghosts: the oracle's record of what happened, which no process reads
    hist,        \* hist[r][u]: version u's push, changes, places, pins and epoch
    answers,     \* answers[P]: the answers clients received
    reclaimed,   \* pushes evacuation found dead and cleaned up
    gcDecided,   \* segments GC deleted
    readBad      \* a read served something other than the path's newest version

vars == <<head, batch, pack, pidx, idx, seg, slot, slotAt, pmap, log, gen, epoch, repo, proj, rev, hour,
          faultsLeft, push, pushCount, attemptsMade, att, authView, batchSeq, foldJob, foldedTo, cache, heldBy,
          leaseLive, blockLive, window, collector, evacuator, gc, shred, copyJob, reader, hist, answers,
          reclaimed, gcDecided, readBad>>

NoAttempt == [stage |-> "idle"]
NoJob == [stage |-> "idle"]
NoHolder == "none"

\* A path's state: an idx/ entry, a marker when gone, or what a replay of statements gives.
Never == [present |-> FALSE, ver |-> 0, gone |-> FALSE, at |-> 0, names |-> {}, namesAt |-> 0,
          state |-> "plain", etag |-> 0]

\* §11.8's head. An ETag is <<version, fence>>, so one never repeats; a head at version 0 is absent,
\* or the placeholder a refusal made, and reads treat both alike.
EmptyHead ==
    [version |-> 0, fence |-> 0, fenceMark |-> 0, fenceAt |-> 0, written |-> 0, foldedThrough |-> 0,
     winFrom |-> 1, auth |-> 1, gen |-> 1, pathEpoch |-> 1, sources |-> {}, dueGen |-> 0,
     dueBlocks |-> FALSE, lease |-> NoPush, refused |-> {},
     collectDone |-> 0, collectThrough |-> 0, windowOpen |-> FALSE]

Etag(h) == <<h.version, h.fence>>

WindowVersions(h) == h.winFrom..h.version

WindowSize(h) == Cardinality(WindowVersions(h))

Committed(r) == Len(hist[r])

\* Generation g, claimed.
Claimed(g) == g \in DOMAIN gen

NewestGeneration == CHOOSE g \in DOMAIN gen : \A x \in DOMAIN gen : x <= g

\* Path p's state after version u of ref r, on top of s, its state before: 11.7's fold and newest
\* rules in one place. A version s already holds changes nothing; a removal of a prefix is one of
\* p's versions, one past its last; a delta only touches a name table.
Step(r, p, s, u) ==
    LET cs == hist[r][u].changes
        own == {c \in cs : c.path = p /\ c.op \in {"write", "create", "remove"}}
        adds == {c \in cs : c.path = p /\ c.op = "add"}
        drops == {c \in cs : c.path = p /\ c.op = "drop"}
        cut == \E c \in cs : c.path \in Prefixes(p) /\ c.op = "remove"
    IN  CASE own # {} /\ u > s.at ->
                 LET c == CHOOSE x \in own : TRUE
                 IN  [s EXCEPT !.present = TRUE, !.ver = c.ver, !.gone = c.op = "remove", !.at = u,
                               !.names = {}, !.namesAt = u]
          [] (adds # {} \/ drops # {}) /\ u > s.namesAt ->
                 [s EXCEPT !.present = TRUE,
                           !.names = IF adds # {} THEN @ \cup {Child} ELSE @ \ {Child},
                           !.namesAt = u]
          [] cut /\ u > s.at /\ s.ver > 0 /\ ~s.gone ->
                 [s EXCEPT !.ver = @ + 1, !.gone = TRUE, !.at = u]
          [] OTHER -> s

RECURSIVE Replay(_, _, _, _, _)
\* s, then versions (from, to] of r.
Replay(r, p, s, from, to) ==
    IF from >= to THEN s ELSE Replay(r, p, Step(r, p, s, from + 1), from + 1, to)

\* The oracle: p's state through version u.
Truth(r, p, u) == Replay(r, p, Never, 0, u)

\* Absent: never written, removed, or a marker collected.
Exists(s) == s.ver > 0 /\ ~s.gone

\* Two reads of one path agree: an absent path has no version to serve.
SameRead(x, y) ==
    /\ Exists(x) = Exists(y)
    /\ Exists(x) => x.ver = y.ver
    /\ x.names = y.names

\* A commit's changes that a version's window entry shows.
ChangesPath(r, p, u) ==
    \E c \in hist[r][u].changes : c.path = p \/ c.path \in Prefixes(p)

\* Removal or delta of the directory after a push's base: 11.7's two-way check.
DirRemovedIn(r, from, to) ==
    \E u \in (from + 1)..to : \E c \in hist[r][u].changes : c.path = Dir /\ c.op = "remove"

DirDeltaIn(r, from, to) ==
    \E u \in (from + 1)..to : \E c \in hist[r][u].changes : c.path = Dir /\ c.op \in {"add", "drop"}

\* Paths created in (from, to], which a PATH_EPOCH's tail must cover.
CreatedIn(r, from, to) ==
    {c.path : c \in UNION {{x \in hist[r][u].changes : x.op = "create"} : u \in (from + 1)..to}}

\* A statement's change set, its parent's delta beside it.
ChangeSet(op, p, base, ver) ==
    {[path |-> p, op |-> op, base |-> base, ver |-> ver]} \cup
    (IF p = Child /\ op = "create" THEN {[path |-> Dir, op |-> "add", base |-> 0, ver |-> 0]}
     ELSE IF p = Child /\ op = "remove" THEN {[path |-> Dir, op |-> "drop", base |-> 0, ver |-> 0]}
     ELSE {})

\* 5b's bound: a statement passes nowhere past this, and its refusal record may then drop.
Lapsed(P) == hour >= push[P].time + StatementMarks

\* Any head write drops the records that lapsed.
LiveRefused(h) ==
    IF Twin = "EarlyRefusalDrop" THEN {} ELSE {x \in h.refused : ~Lapsed(x.push)}

\* The head's window names P at version u, or a log page does.
CommitVersions(r, P) == {u \in 1..Committed(r) : hist[r][u].push = P}

IsCommitted(P) == CommitVersions(push[P].ref, P) # {}

\* The newest position that shrank the holders, in a state as new as position n.
ShrunkAt(n) == IF n >= proj.shrunkAt THEN proj.shrunkAt ELSE 0

\* §10.6's predicate: the generation covers every shrink the state shows.
GatePasses(g, n) == Claimed(g) /\ gen[g].auth >= ShrunkAt(n)

ActiveRepo == repo.state = "active"

InitM2 ==
    /\ head = [r \in Refs |-> EmptyHead]
    /\ batch = {}
    /\ pack = {}
    /\ pidx = {}
    /\ idx = [r \in Refs |-> [e \in 1..MaxGeneration |-> [p \in Paths |-> Never]]]
    /\ seg = [s \in Segments |-> [stored |-> FALSE, at |-> 0]]
    /\ slot = [P \in PushIds |-> "none"]
    /\ slotAt = [P \in PushIds |-> 0]
    /\ pmap = [r \in Refs |-> {}]
    /\ log = [r \in Refs |-> {}]
    /\ gen = 1 :> [by |-> "genesis", auth |-> 1]
    /\ epoch = <<[by |-> "genesis", gen |-> 1]>>
    /\ repo = [state |-> "active", deletion |-> 0]
    /\ proj = [n |-> 1, shrunkAt |-> 0, kind |-> "none"]
    /\ rev = {}
    /\ hour = 0
    /\ faultsLeft = MaxFaults
    /\ push = [P \in PushIds |-> [status |-> "unsigned"]]
    /\ pushCount = 0
    /\ attemptsMade = [P \in PushIds |-> 0]
    /\ att = [i \in Instances |-> NoAttempt]
    /\ authView = [i \in Instances |-> 1]
    /\ batchSeq = [i \in Instances |-> 0]
    /\ foldJob = [i \in Instances |-> NoJob]
    /\ foldedTo = [i \in Instances |-> [r \in Refs |-> 0]]
    /\ cache = [r \in Refs |-> EmptyHead]
    /\ heldBy = [r \in Refs |-> NoHolder]
    /\ leaseLive = [r \in Refs |-> FALSE]
    /\ blockLive = [r \in Refs |-> FALSE]
    /\ window = [r \in Refs |-> "closed"]
    /\ collector = NoJob
    /\ evacuator = NoJob
    /\ gc = NoJob
    /\ shred = NoJob
    /\ copyJob = [r \in Refs |-> NoJob]
    /\ reader = NoJob
    /\ hist = [r \in Refs |-> <<>>]
    /\ answers = [P \in PushIds |-> [ok |-> {}, refused |-> FALSE]]
    /\ reclaimed = {}
    /\ gcDecided = {}
    /\ readBad = FALSE

(***************************************************************************)
(* Writers: statements and uploads. A client signs what it read at version *)
(* b, honestly but perhaps stale.                                          *)
(***************************************************************************)

\* Everything but the attempts, for the steps that touch only them.
heads == <<head, cache, heldBy, leaseLive, blockLive, window>>
stored == <<batch, pack, pidx, idx, seg, slot, slotAt, pmap, log>>
authority == <<gen, epoch, proj, rev>>
lifecycle == <<repo, shred>>
statements == <<hour, faultsLeft, push, pushCount, attemptsMade>>
instanceState == <<authView, batchSeq, foldJob, foldedTo>>
jobs == <<collector, evacuator, gc, copyJob, reader>>
oracle == <<hist, answers, reclaimed, gcDecided, readBad>>

OnlyAtt == UNCHANGED <<heads, stored, authority, lifecycle, statements, instanceState, jobs, oracle>>

\* A push is kept to the versions a ref has left, one spared for a due PATH_EPOCH.
PlainRoom(r) == Committed(r) < MaxVersion - 1

\* A stale base: one behind, or just past 5f's range.
StaleBases(r) ==
    LET v == head[r].version
    IN  {b \in {v - 1, v - BaseRange - 1} : b >= 0 /\ (GitMode(r) => b = v - 1)}

\* The version a change writes: 11.7's versions rule, as the client's read gives it.
NewVersion(op, st, b) ==
    CASE op = "create" -> IF Twin = "VersionRestarts" THEN 1 ELSE Max(b, st.ver) + 1
      [] OTHER -> st.ver + 1

\* The change is one a client could send from what it saw at b.
HonestChange(r, b, p, op) ==
    LET st == Truth(r, p, b)
    IN  CASE op = "write" -> p # Dir /\ Exists(st)
          [] op = "remove" -> Exists(st)
          [] op = "create" -> ~Exists(st) /\ (p = Child => Exists(Truth(r, Dir, b)))
          [] OTHER -> FALSE

Sign(w, r, b, p, op, s, newSlot, g, n, route) ==
    LET P == pushCount + 1
        st == Truth(r, p, b)
        ver == NewVersion(op, st, b)
    IN  /\ pushCount' = P
        /\ push' = [push EXCEPT ![P] =
               [status |-> IF s = NoSegment THEN "ready" ELSE "upload",
                writer |-> w, ref |-> r, base |-> b, kind |-> route,
                changes |-> ChangeSet(op, p, IF op = "create" THEN 0 ELSE st.ver, ver),
                seg |-> s, receipt |-> 0, newSlot |-> newSlot,
                gen |-> g, auth |-> n, pathEpoch |-> head[r].pathEpoch, epochTo |-> 0, map |-> 0,
                tail |-> {}, time |-> hour, parts |-> {}, leased |-> FALSE]]
        /\ UNCHANGED <<heads, stored, authority, lifecycle, hour, faultsLeft, attemptsMade, att, instanceState,
                       jobs, oracle>>

\* A client retries one push until it gets an answer, its attempts run out or its bound passes.
Answered(P) ==
    \/ push[P].status = "abandoned"
    \/ answers[P].ok # {}
    \/ answers[P].refused
    \/ attemptsMade[P] >= MaxAttempts
    \/ Lapsed(P)

Waiting(w) == \E P \in 1..pushCount : push[P].writer = w /\ ~Answered(P)

\* The statements a client may sign now, on the head it read at b; the checks come first, since most
\* choices fail them.
SignAt(bases) ==
    /\ pushCount < MaxPush
    /\ ActiveRepo
    /\ \E w \in {x \in Writers \ rev : ~Waiting(x)}, r \in {x \in Refs : PlainRoom(x)} :
           \E b \in bases[r], p \in Paths, op \in {"write", "create", "remove"} :
               /\ HonestChange(r, b, p, op)
               /\ \E s \in Segments \cup {NoSegment}, newSlot \in BOOLEAN, g \in DOMAIN gen, n \in 1..proj.n,
                     route \in IF GitMode(r) THEN {"push", "parts"} ELSE {"push"} :
                      Sign(w, r, b, p, op, s, newSlot, g, n, route)

SignFresh == SignAt([r \in Refs |-> {head[r].version}])

SignStale == SignAt([r \in Refs |-> StaleBases(r)])

\* 11.13's uploads: a receipt carries the stored object's LastModified; 23 h on, equal bytes are
\* refused and the client re-seals, a new push here.
Upload(P) ==
    LET s == push[P].seg
    IN  /\ push[P].status = "upload"
        /\ IF (seg[s].stored /\ hour - seg[s].at >= ReuploadStaleAge) \/ s \in gcDecided \/ ~ActiveRepo
           THEN /\ push' = [push EXCEPT ![P].status = "abandoned"]
                /\ UNCHANGED seg
           ELSE /\ seg' = [seg EXCEPT ![s] = IF @.stored THEN @ ELSE [stored |-> TRUE, at |-> hour]]
                /\ push' = [push EXCEPT ![P].status = "ready", ![P].receipt = seg'[s].at]
        /\ UNCHANGED <<heads, batch, pack, pidx, idx, slot, slotAt, pmap, log, authority, lifecycle, hour,
                       faultsLeft, pushCount, attemptsMade, att, instanceState, jobs, oracle>>

\* A route of push P that a client, or the lb's re-send, may send now.
Routes(P) ==
    IF push[P].status # "ready" THEN {}
    ELSE IF push[P].kind = "parts"
         THEN {"lease"} \cup (IF push[P].leased THEN {"part"} ELSE {})
              \cup (IF push[P].parts # {} THEN {"seal"} ELSE {})
         ELSE {"push"}

NewAttempt(P, route) ==
    [stage |-> "head", route |-> route, push |-> P, mustCluster |-> route = "seal", rerun |-> FALSE,
     hd |-> EmptyHead, cached |-> FALSE, hft |-> 0, ent |-> [p \in Paths |-> Never],
     todo |-> {}, progress |-> "cur", curSeen |-> Never, preSeen |-> Never,
     repoState |-> "none", authSeen |-> 0, place |-> <<>>, slotDone |-> FALSE, readAt |-> hour,
     arrival |-> head[push[P].ref].fenceMark, pageOut |-> FALSE]

\* An attempt reaches evs at any step, before or after another's answer.
Arrive(i, P) ==
    /\ att[i].stage = "idle"
    /\ attemptsMade[P] < MaxAttempts
    /\ \E route \in Routes(P) :
           att' = [att EXCEPT ![i] = NewAttempt(P, route)]
    /\ attemptsMade' = [attemptsMade EXCEPT ![P] = @ + 1]
    /\ UNCHANGED <<heads, stored, authority, lifecycle, hour, faultsLeft, push, pushCount, instanceState, jobs,
                   oracle>>

(***************************************************************************)
(* evs: steps 4 to 8 of a push, one GET a step.                             *)
(***************************************************************************)

Paths1(P) == {c.path : c \in push[P].changes}

\* Step 4's head: the verified cache only for a first read at or past the statement's base.
HeadSources(a, r) ==
    IF a.mustCluster \/ a.rerun \/ cache[r].version < push[a.push].base
    THEN {"cluster"}
    ELSE {"cluster", "cache"}

ReadHead(i) ==
    LET a == att[i]
        r == push[a.push].ref
    IN  /\ a.stage = "head"
        /\ heldBy[r] = NoHolder
        /\ \E src \in HeadSources(a, r) :
               LET h == IF src = "cache" THEN cache[r] ELSE head[r]
                   hft == IF a.rerun /\ Twin # "StaleHorizon" THEN a.hft ELSE h.foldedThrough
               IN  att' = [att EXCEPT ![i] =
                       [a EXCEPT !.hd = h, !.cached = src = "cache", !.hft = hft, !.readAt = hour,
                                 !.stage = IF a.route = "seal" \/ ~a.rerun THEN "repo" ELSE "check"]]
        /\ OnlyAtt

\* repo/ and the authorization state, from caches at most 5 s old: while a shred waits out its
\* first phase, a cached repo/ may still show active.
ReadRepo(i) ==
    LET a == att[i]
        r == push[a.push].ref
        paths == IF a.route \in {"push", "part"} THEN Paths1(a.push) ELSE {}
    IN  /\ a.stage = "repo"
        /\ \E seen \in {repo.state} \cup (IF shred.stage = "wait" THEN {"active"} ELSE {}) :
               att' = [att EXCEPT ![i] =
                   [a EXCEPT !.repoState = seen, !.authSeen = authView[i],
                             !.todo = paths, !.progress = "cur",
                             !.stage = IF paths = {} THEN "check" ELSE "entry"]]
        /\ OnlyAtt

\* 11.6's read rule over what the round's GETs found: a removed prefix means absent, a fresh one
\* too unless the path's own entry is fresh; else the current entry, else the newest source's.
Settled(cur, pre, src) ==
    CASE pre.present /\ pre.gone -> Never
      [] pre.present /\ pre.state = "fresh" /\ ~(cur.present /\ cur.state = "fresh") -> Never
      [] cur.present -> cur
      [] OTHER -> src

\* One GET of an entry round; a path with sources takes its prefix's HEAD and a GET per source.
ReadEntry(i, p) ==
    LET a == att[i]
        r == push[a.push].ref
        e == a.hd.pathEpoch
        sources == a.hd.sources
        done(st) == [a EXCEPT !.ent[p] = st, !.todo = a.todo \ {p}, !.progress = "cur",
                              !.stage = IF a.todo = {p} THEN "check" ELSE "entry"]
    IN  /\ a.stage = "entry"
        /\ p \in a.todo
        /\ CASE a.progress = "cur" ->
                    LET cur == idx[r][e][p]
                    IN  att' = [att EXCEPT ![i] =
                            IF sources = {} THEN done(cur)
                            ELSE [a EXCEPT !.curSeen = cur, !.progress = "pre"]]
             [] a.progress = "pre" ->
                    att' = [att EXCEPT ![i] =
                        [a EXCEPT !.preSeen = IF Prefixes(p) = {} THEN Never ELSE idx[r][e][Dir],
                                  !.progress = "src"]]
             [] a.progress = "src" ->
                    LET src == idx[r][CHOOSE x \in sources : TRUE][p]
                        st == Settled(a.curSeen, a.preSeen, src)
                    IN  att' = [att EXCEPT ![i] =
                            IF st.present \/ a.preSeen.gone THEN done(st)
                            ELSE [a EXCEPT !.progress = "again"]]
             [] a.progress = "again" ->
                    att' = [att EXCEPT ![i] = done(idx[r][e][p])]
        /\ OnlyAtt

\* 11.7's newest, over what the attempt read.
SeenPath(a, p) == Replay(push[a.push].ref, p, a.ent[p], a.hft, a.hd.version)

\* 5g on one change. 0 names the path absent, and a creation takes max(b, m) + 1.
PathCas(a, c) ==
    LET P == a.push
        s == SeenPath(a, c.path)
    IN  CASE c.op = "create" ->
                 /\ ~Exists(s)
                 /\ Twin = "VersionRestarts" \/ c.ver = Max(push[P].base, s.ver) + 1
          [] c.op \in {"write", "remove"} ->
                 /\ Exists(s)
                 /\ s.ver = c.base
          [] OTHER -> TRUE

\* 11.7's two-way check: a push removing D loses to a delta after its base, a push changing D to
\* D's removal.
DirectoryCas(a) ==
    LET r == push[a.push].ref
        b == push[a.push].base
    IN  \A c \in push[a.push].changes :
            /\ (c.path = Dir /\ c.op = "remove") => ~DirDeltaIn(r, b, a.hd.version)
            /\ (c.path = Dir /\ c.op \in {"add", "drop"}) => ~DirRemovedIn(r, b, a.hd.version)

\* A creation of the path, which an immediate epoch or a mapper's block stops.
Creates(P) == \E c \in push[P].changes : c.op = "create" \/ c.op = "add"

\* 5e for a PATH_EPOCH: a newer generation, its source still in the window, its tail covering every
\* later creation. These the head settles for good; its map's parts, below, it does not.
EpochSettledOk(a) ==
    LET P == a.push
        r == push[P].ref
        m == push[P].map
    IN  /\ push[P].epochTo > a.hd.pathEpoch
        /\ m >= a.hd.winFrom - 1
        /\ CreatedIn(r, m, a.hd.version) \subseteq push[P].tail \/ Twin = "NoTailCheck"

EpochMapOk(a) ==
    LET P == a.push
        r == push[P].ref
    IN  \E x \in pmap[r] : /\ x.gen = push[P].epochTo
                           /\ x.source = push[P].map
                           /\ hour - x.at < ReceiptAge

\* Step 5, as one verdict on what the attempt read:
\*   "committed", "recorded": 5a;  "fenced": the fence row;  "final": a refusal the head settles;
\*   "record": one that must be recorded first;  "busy": a 429 refusing nothing;
\*   "newer": the entry is past the head read, or the window lost versions after hft: read again;
\*   "pass".
Verdict(a, i) ==
    LET P == a.push
        st == push[P]
        r == st.ref
        h == a.hd
        lookup == IF Twin = "NoRetryLookup" THEN {u \in WindowVersions(h) : hist[r][u].push = P}
                  ELSE {u \in 1..h.version : hist[r][u].push = P}
        isEpoch == st.kind = "epoch"
        changes == IF a.route = "seal" THEN {} ELSE st.changes
        checkPaths == a.route \in {"push", "part"}
        needsTip == a.route # "part"
    IN  CASE lookup # {} -> "committed"
          [] \E x \in h.refused : x.push = P -> "recorded"
          [] a.route # "part" /\ h.fenceMark > a.arrival /\ Twin # "NoFenceRule" -> "fenced"
          \* 5b
          [] Lapsed(P) -> "record"
          \* 5c
          [] a.repoState \in {"shredding", "shredded"} -> "final"
          [] a.repoState = "deleted" -> "record"
          [] st.writer \in rev /\ a.authSeen >= proj.shrunkAt -> "record"
          \* 5d: a pin below the head's is settled for good, a failed predicate is not
          [] (st.gen < h.gen \/ st.auth < h.auth) /\ Twin # "PinFalls" -> "final"
          [] ~GatePasses(st.gen, a.authSeen) /\ Twin # "NoPinCheck" -> "record"
          \* 5e
          [] ~isEpoch /\ st.pathEpoch # h.pathEpoch -> "final"
          [] isEpoch /\ ~EpochSettledOk(a) -> "final"
          [] isEpoch /\ ~EpochMapOk(a) -> "record"
          [] isEpoch /\ h.version > Max(h.foldedThrough, foldedTo[i][r]) -> "busy"
          [] Creates(P) /\ (h.dueBlocks \/ blockLive[r]) -> "record"
          \* 5f
          [] needsTip /\ GitMode(r) /\ Twin # "GitPathCas" /\ st.base # h.version -> "final"
          [] needsTip /\ GitMode(r) /\ h.lease # NoPush /\ h.lease # P /\ leaseLive[r] -> "busy"
          [] needsTip /\ ~GitMode(r) /\ st.base < h.version - BaseRange -> "final"
          \* 5g reads entries against a horizon the window still covers
          [] checkPaths /\ \E p \in Paths1(P) : a.ent[p].at > h.version -> "newer"
          [] checkPaths /\ a.hft + 1 < h.winFrom -> "reread"
          [] checkPaths /\ ~(\A c \in changes : PathCas(a, c)) -> "final"
          [] checkPaths /\ ~DirectoryCas(a) -> "final"
          \* 5h
          [] st.seg # NoSegment /\ hour - st.receipt >= ReceiptAge -> "record"
          [] OTHER -> "pass"

\* End an attempt with what its client hears.
AnswerOk(P, u) == answers' = [answers EXCEPT ![P].ok = @ \cup {u}]
AnswerRefused(P) == answers' = [answers EXCEPT ![P].refused = TRUE]

\* Back to step 4, keeping nothing.
Restart(a) == [a EXCEPT !.stage = "head", !.rerun = FALSE, !.ent = [p \in Paths |-> Never]]

\* Back to a cluster head, keeping the entries and their horizon: 412 and unknown outcomes.
Reread(a) == [a EXCEPT !.stage = "head", !.rerun = TRUE, !.mustCluster = TRUE]

Check(i) ==
    LET a == att[i]
        P == a.push
        r == push[P].ref
        verdict == Verdict(a, i)
        refusesOnCache == a.cached /\ verdict \in {"final", "record"} /\ Twin # "CachedRefusal"
    IN  /\ a.stage = "check"
        /\ a.route # "lease"
        /\ IF refusesOnCache
           THEN /\ att' = [att EXCEPT ![i] = [Restart(a) EXCEPT !.mustCluster = TRUE]]
                /\ UNCHANGED answers
           ELSE CASE verdict = "committed" ->
                         /\ att' = [att EXCEPT ![i] = NoAttempt]
                         /\ AnswerOk(P, CHOOSE u \in CommitVersions(r, P) : TRUE)
                  [] verdict = "recorded" ->
                         /\ att' = [att EXCEPT ![i] = NoAttempt]
                         /\ AnswerRefused(P)
                  [] verdict \in {"fenced", "busy"} ->
                         /\ att' = [att EXCEPT ![i] = NoAttempt]
                         /\ UNCHANGED answers
                  [] verdict = "final" ->
                         /\ att' = [att EXCEPT ![i] = NoAttempt]
                         /\ AnswerRefused(P)
                  [] verdict = "record" ->
                         IF Twin = "UnrecordedRefusal"
                         THEN /\ att' = [att EXCEPT ![i] = NoAttempt]
                              /\ AnswerRefused(P)
                         ELSE /\ att' = [att EXCEPT ![i].stage = "refuse"]
                              /\ UNCHANGED answers
                  [] verdict = "newer" ->
                         /\ att' = [att EXCEPT ![i] = Reread(a)]
                         /\ UNCHANGED answers
                  [] verdict = "reread" ->
                         \* the reread head precedes these GETs, so its horizon holds
                         /\ att' = [att EXCEPT ![i] =
                                [a EXCEPT !.hft = a.hd.foldedThrough, !.todo = Paths1(P),
                                          !.progress = "cur", !.stage = "entry"]]
                         /\ UNCHANGED answers
                  [] OTHER ->
                         /\ att' = [att EXCEPT ![i].stage =
                                CASE a.place = <<>> -> "record"
                                  [] push[P].newSlot /\ ~a.slotDone -> "slot"
                                  [] OTHER -> "page"]
                         /\ UNCHANGED answers
        /\ UNCHANGED <<heads, stored, authority, lifecycle, statements, instanceState, jobs, hist,
                       reclaimed, gcDecided, readBad>>

\* The lease route: a head CAS raising only the fence, for the base version alone.
CheckLease(i) ==
    LET a == att[i]
        P == a.push
        r == push[P].ref
        h == a.hd
        recorded == \E x \in h.refused : x.push = P
        otherLease == h.lease # NoPush /\ h.lease # P /\ leaseLive[r]
    IN  /\ a.stage = "check"
        /\ a.route = "lease"
        /\ CASE recorded \/ h.version # push[P].base ->
                    /\ att' = [att EXCEPT ![i] = NoAttempt]
                    /\ AnswerRefused(P)
                    /\ UNCHANGED <<head, push, leaseLive>>
             [] otherLease ->
                    /\ att' = [att EXCEPT ![i] = NoAttempt]
                    /\ UNCHANGED <<answers, head, push, leaseLive>>
             [] h.lease = P /\ leaseLive[r] ->
                    /\ att' = [att EXCEPT ![i] = NoAttempt]
                    /\ push' = [push EXCEPT ![P].leased = TRUE]
                    /\ UNCHANGED <<answers, head, leaseLive>>
             [] Etag(head[r]) # Etag(h) \/ heldBy[r] # NoHolder ->
                    /\ att' = [att EXCEPT ![i] = Reread(a)]
                    /\ UNCHANGED <<answers, head, push, leaseLive>>
             [] OTHER ->
                    /\ head' = [head EXCEPT ![r].fence = @ + 1, ![r].lease = P,
                                            ![r].refused = LiveRefused(h)]
                    /\ leaseLive' = [leaseLive EXCEPT ![r] = TRUE]
                    /\ push' = [push EXCEPT ![P].leased = TRUE]
                    /\ att' = [att EXCEPT ![i] = NoAttempt]
                    /\ UNCHANGED answers
        /\ UNCHANGED <<cache, heldBy, blockLive, window, stored, authority, lifecycle, hour, faultsLeft,
                       pushCount, attemptsMade, instanceState, jobs, hist, reclaimed, gcDecided, readBad>>

\* outcomes' refuse row: one head CAS, raising the fence, before any answer. It lapses with the
\* statement's bound; past 8 live records evs answers 429, which refuses nothing.
RecordRefusal(i) ==
    LET a == att[i]
        P == a.push
        r == push[P].ref
        h == head[r]
    IN  /\ a.stage = "refuse"
        /\ heldBy[r] = NoHolder
        /\ CASE Etag(h) # Etag(a.hd) ->
                    /\ att' = [att EXCEPT ![i] = Reread(a)]
                    /\ UNCHANGED <<head, answers>>
             [] Cardinality(LiveRefused(h)) >= MaxRefused ->
                    /\ att' = [att EXCEPT ![i] = NoAttempt]
                    /\ UNCHANGED <<head, answers>>
             [] OTHER ->
                    /\ head' = [head EXCEPT ![r].fence = @ + 1,
                                            ![r].refused = LiveRefused(h) \cup {[push |-> P]}]
                    /\ att' = [att EXCEPT ![i] = NoAttempt]
                    /\ AnswerRefused(P)
        /\ UNCHANGED <<cache, heldBy, leaseLive, blockLive, window, stored, authority, lifecycle, statements,
                       instanceState, jobs, hist, reclaimed, gcDecided, readBad>>

\* Step 6: the record joins a batch and evs awaits its write. A part ends here, 200 {place}; a lost
\* answer leaves dead weight and the client posts it again.
WriteRecord(i) ==
    LET a == att[i]
        P == a.push
        seq == batchSeq[i] + 1
        place == <<i, seq>>
    IN  /\ a.stage = "record"
        /\ batchSeq' = [batchSeq EXCEPT ![i] = seq]
        /\ batch' = batch \cup {[place |-> place, push |-> P, kind |-> a.route, at |-> hour]}
        /\ IF a.route = "part"
           THEN /\ att' = [att EXCEPT ![i] = NoAttempt]
                /\ \/ push' = [push EXCEPT ![P].parts = @ \cup {place}]
                   \/ UNCHANGED push
           ELSE /\ att' = [att EXCEPT ![i] =
                       [a EXCEPT !.place = place, !.stage = IF push[P].newSlot THEN "slot" ELSE "page"]]
                /\ UNCHANGED push
        /\ UNCHANGED <<heads, pack, pidx, idx, seg, slot, slotAt, pmap, log, authority, lifecycle, hour,
                       faultsLeft, pushCount, attemptsMade, authView, foldJob, foldedTo, jobs, oracle>>

\* Step 6's slot round (DESIGN-DETAILS 14.2.3): created If-None-Match with the statement as the
\* object's origin; on a 412 the object of its own origin, with equal bytes, passes only while under
\* 23 h old, else SLOT_STALE, recorded; a 404 is the create again, so a late attempt stores anew what
\* evacuation deleted. Every slot here is its own statement's: the rows for another statement's
\* object and the takeover are details/EvsSlot.tla's.
WriteSlot(i) ==
    LET a == att[i]
        P == a.push
    IN  /\ a.stage = "slot"
        /\ IF slot[P] = "stored" /\ hour - slotAt[P] >= ReuploadStaleAge
           THEN /\ att' = [att EXCEPT ![i].stage = "refuse"]
                /\ UNCHANGED <<slot, slotAt>>
           ELSE /\ att' = [att EXCEPT ![i] = [a EXCEPT !.stage = "page", !.slotDone = TRUE]]
                /\ slot' = [slot EXCEPT ![P] = "stored"]
                /\ slotAt' = [slotAt EXCEPT ![P] = IF slot[P] = "stored" THEN @ ELSE hour]
        /\ UNCHANGED <<heads, batch, pack, pidx, idx, seg, pmap, log, authority, lifecycle, statements,
                       instanceState, jobs, oracle>>

\* The newest version of the window's oldest log page.
PageEnd(h) == ((h.winFrom \div FoldSize) + 1) * FoldSize - 1

\* Step 6's page-out: past the window limit, the oldest page leaves the head only once folded, and
\* its log page precedes the head. A fold that cannot finish in time pages nothing, up to the
\* window's maximum, then 429 FOLD_BEHIND. Step 7 issues within 5 s of step 4's reads, or they rerun.
PageOut(i) ==
    LET a == att[i]
        r == push[a.push].ref
        h == a.hd
        folded == Max(h.foldedThrough, foldedTo[i][r])
        needed == WindowSize(h) + 1 > WindowLimit
        canPage == PageEnd(h) <= folded \/ Twin = "PageOutUnfolded"
    IN  /\ a.stage = "page"
        /\ CASE hour > a.readAt + 1 ->
                    /\ att' = [att EXCEPT ![i] = Restart(a)]
                    /\ UNCHANGED log
             [] needed /\ canPage ->
                    /\ log' = [log EXCEPT ![r] = @ \cup {h.winFrom \div FoldSize}]
                    /\ att' = [att EXCEPT ![i] = [a EXCEPT !.pageOut = TRUE, !.stage = "put"]]
             [] WindowSize(h) + 1 > WindowMax ->
                    /\ att' = [att EXCEPT ![i] = NoAttempt]
                    /\ UNCHANGED log
             [] OTHER ->
                    /\ att' = [att EXCEPT ![i] = [a EXCEPT !.pageOut = FALSE, !.stage = "put"]]
                    /\ UNCHANGED log
        /\ UNCHANGED <<heads, batch, pack, pidx, idx, seg, slot, slotAt, pmap, authority, lifecycle, statements,
                       instanceState, jobs, oracle>>

\* 5 s passed before step 7 issued: steps 4 and 5 run again.
Timeout(i) ==
    /\ att[i].stage \in {"check", "record", "slot", "page", "entry", "repo"}
    /\ faultsLeft > 0
    /\ faultsLeft' = faultsLeft - 1
    /\ att' = [att EXCEPT ![i] = Restart(att[i])]
    /\ UNCHANGED <<heads, stored, authority, lifecycle, hour, push, pushCount, attemptsMade, instanceState,
                   jobs, oracle>>

\* The head after a commit, step 7's fields. A PATH_EPOCH makes its epoch current and lists the old
\* one first among the sources, and its process's fold sets the horizon.
Committing(h, a, i) ==
    LET P == a.push
        st == push[P]
        r == st.ref
        isEpoch == st.kind = "epoch"
        crossing == st.gen > h.gen
    IN  [h EXCEPT !.version = @ + 1, !.written = hour,
                  !.foldedThrough = IF isEpoch THEN h.version ELSE Max(@, foldedTo[i][r]),
                  !.winFrom = IF a.pageOut THEN PageEnd(h) + 1 ELSE @,
                  !.auth = st.auth, !.gen = st.gen, !.lease = NoPush,
                  !.refused = LiveRefused(h),
                  !.pathEpoch = IF isEpoch THEN st.epochTo ELSE @,
                  !.sources = IF isEpoch THEN @ \cup {h.pathEpoch} ELSE @,
                  !.dueGen = IF isEpoch THEN 0 ELSE IF crossing THEN st.gen ELSE @,
                  !.dueBlocks = IF isEpoch THEN FALSE
                                ELSE IF crossing THEN proj.kind = "immediate" ELSE @]

\* What the oracle keeps of version u.
CommitRecord(a) ==
    LET st == push[a.push]
    IN  [push |-> a.push, base |-> st.base, changes |-> st.changes,
         places |-> {a.place} \cup st.parts, gen |-> st.gen, auth |-> st.auth,
         genBy |-> gen[st.gen].by, pathEpoch |-> st.pathEpoch, view |-> a.authSeen,
         seg |-> st.seg, newSlot |-> st.newSlot, kind |-> st.kind, repoSeen |-> a.repoState]

\* Step 7's If-Match lands. The answer may be lost, which step 5a settles on any retry.
CommitPut(i) ==
    LET a == att[i]
        P == a.push
        r == push[P].ref
        h == head[r]
    IN  /\ a.stage = "put"
        /\ heldBy[r] = NoHolder
        /\ Etag(h) = Etag(a.hd)
        /\ head' = [head EXCEPT ![r] = Committing(h, a, i)]
        /\ hist' = [hist EXCEPT ![r] = Append(@, CommitRecord(a))]
        /\ blockLive' = [blockLive EXCEPT ![r] = IF push[P].kind = "epoch" THEN FALSE ELSE @]
        /\ leaseLive' = [leaseLive EXCEPT ![r] = FALSE]
        /\ \/ /\ att' = [att EXCEPT ![i] = NoAttempt]
              /\ AnswerOk(P, h.version + 1)
           \/ /\ att' = [att EXCEPT ![i] = Reread(a)]
              /\ UNCHANGED answers
        /\ UNCHANGED <<cache, heldBy, window, stored, authority, lifecycle, statements, instanceState, jobs,
                       reclaimed, gcDecided, readBad>>

\* A 412, or a PUT that never landed and whose answer never came: either way evs rereads the head.
PutFails(i) ==
    LET a == att[i]
        r == push[a.push].ref
    IN  /\ a.stage = "put"
        /\ heldBy[r] = NoHolder
        /\ Etag(head[r]) # Etag(a.hd) \/ faultsLeft > 0
        /\ faultsLeft' = IF Etag(head[r]) # Etag(a.hd) THEN faultsLeft ELSE faultsLeft - 1
        /\ att' = [att EXCEPT ![i] = Reread(a)]
        /\ UNCHANGED <<heads, stored, authority, lifecycle, hour, push, pushCount, attemptsMade, instanceState,
                       jobs, oracle>>

\* A PUT whose drive commits stall: no read or commit passes the head until §19.6 settles it.
PutStalls(i) ==
    LET a == att[i]
        r == push[a.push].ref
    IN  /\ a.stage = "put"
        /\ heldBy[r] = NoHolder
        /\ Etag(head[r]) = Etag(a.hd)
        /\ faultsLeft > 0
        /\ faultsLeft' = faultsLeft - 1
        /\ heldBy' = [heldBy EXCEPT ![r] = i]
        /\ att' = [att EXCEPT ![i].stage = "stalled"]
        /\ UNCHANGED <<head, cache, leaseLive, blockLive, window, stored, authority, lifecycle, hour, push,
                       pushCount, attemptsMade, instanceState, jobs, oracle>>

StallLands(r, i) ==
    LET a == att[i]
        P == a.push
    IN  /\ heldBy[r] = i
        /\ head' = [head EXCEPT ![r] = Committing(head[r], a, i)]
        /\ hist' = [hist EXCEPT ![r] = Append(@, CommitRecord(a))]
        /\ heldBy' = [heldBy EXCEPT ![r] = NoHolder]
        /\ leaseLive' = [leaseLive EXCEPT ![r] = FALSE]
        /\ blockLive' = [blockLive EXCEPT ![r] = IF push[P].kind = "epoch" THEN FALSE ELSE @]
        /\ att' = [att EXCEPT ![i] = Reread(a)]
        /\ UNCHANGED <<cache, window, stored, authority, lifecycle, statements, instanceState, jobs, answers,
                       reclaimed, gcDecided, readBad>>

StallReverts(r, i) ==
    /\ heldBy[r] = i
    /\ heldBy' = [heldBy EXCEPT ![r] = NoHolder]
    /\ att' = [att EXCEPT ![i] = Reread(att[i])]
    /\ UNCHANGED <<head, cache, leaseLive, blockLive, window, stored, authority, lifecycle, statements,
                   instanceState, jobs, oracle>>

\* Step 8's cache entry, written only if its version rises.
CachePut(r) ==
    /\ heldBy[r] = NoHolder
    /\ cache[r].version < head[r].version
    /\ cache' = [cache EXCEPT ![r] = head[r]]
    /\ UNCHANGED <<head, heldBy, leaseLive, blockLive, window, stored, authority, lifecycle, statements,
                   att, instanceState, jobs, oracle>>

\* A killed instance loses its memory; what it wrote stands, and its attempts' clients retry.
Crash(i) ==
    /\ att[i].stage # "stalled"
    /\ att[i].stage # "idle" \/ foldJob[i].stage # "idle"
    /\ faultsLeft > 0
    /\ faultsLeft' = faultsLeft - 1
    /\ att' = [att EXCEPT ![i] = NoAttempt]
    /\ foldJob' = [foldJob EXCEPT ![i] = NoJob]
    /\ foldedTo' = [foldedTo EXCEPT ![i] = [r \in Refs |-> 0]]
    /\ UNCHANGED <<heads, stored, authority, lifecycle, hour, push, pushCount, attemptsMade, authView, batchSeq,
                   jobs, oracle>>

(***************************************************************************)
(* Folds (11.7): two at once, run stale, duplicated or late.                *)
(***************************************************************************)

\* §11.13's skip: a P2 write rereads repo/ when issued, cached at most 5 s.
P2Allowed == repo.state \in {"active", "deleted"} \/ (repo.state = "shredding" /\ shred.stage = "wait")

FoldPaths(r, f, u) == {p \in Paths : \E x \in (f + 1)..u : ChangesPath(r, p, x)}

\* A fold is queued by the commit that needs it, or 10 min after the last commit, for the rest.
FoldQueue(i, r, u) ==
    LET h == head[r]
        f == Max(h.foldedThrough, foldedTo[i][r])
    IN  /\ foldJob[i].stage = "idle"
        /\ u > f
        /\ u = h.version \/ (h.version - f >= FoldTrigger /\ u = f + FoldSize)
        /\ foldJob' = [foldJob EXCEPT ![i] =
               [stage |-> "queued", ref |-> r, from |-> f, to |-> u, hv |-> 0, live |-> FALSE,
                sawWindow |-> FALSE, through |-> 0, fence |-> 0, pathEpoch |-> 0, sources |-> {},
                todo |-> {}, path |-> Dir, entry |-> Never, expect |-> 0]]
        /\ UNCHANGED <<heads, stored, authority, lifecycle, statements, att, authView, batchSeq, foldedTo,
                       jobs, oracle>>

\* The cluster read a fold relies on: it starts the write deadline, and a fold whose range another
\* folded stops here (11.7's stale row).
FoldRead(i) ==
    LET j == foldJob[i]
        r == j.ref
        h == head[r]
    IN  /\ j.stage = "queued"
        /\ heldBy[r] = NoHolder
        /\ P2Allowed
        /\ foldJob' = [foldJob EXCEPT ![i] =
               IF h.foldedThrough > j.from THEN NoJob
               ELSE [j EXCEPT !.stage = "get", !.hv = h.version, !.live = TRUE, !.fence = h.fence,
                              !.sawWindow = h.windowOpen /\ window[r] # "closed",
                              !.through = h.collectThrough, !.pathEpoch = h.pathEpoch,
                              !.sources = h.sources, !.todo = FoldPaths(r, j.from, j.to)]]
        /\ UNCHANGED <<heads, stored, authority, lifecycle, statements, att, authView, batchSeq, foldedTo,
                       jobs, oracle>>

\* GET an entry; the directory's marker goes before the LIST below it. While the head lists sources
\* an entry the current epoch lacks starts from its source's (11.7's epochs row).
FoldGet(i, p) ==
    LET j == foldJob[i]
        r == j.ref
        cur == idx[r][j.pathEpoch][p]
        base == IF cur.present \/ j.sources = {} THEN cur
                ELSE [idx[r][CHOOSE x \in j.sources : TRUE][p] EXCEPT !.etag = cur.etag]
    IN  /\ j.stage = "get"
        /\ p \in j.todo
        /\ Dir \in j.todo => p = Dir
        /\ foldJob' = [foldJob EXCEPT ![i] =
               [j EXCEPT !.stage = "put", !.path = p, !.entry = base, !.expect = cur.etag]]
        /\ UNCHANGED <<heads, stored, authority, lifecycle, statements, att, authView, batchSeq, foldedTo,
                       jobs, oracle>>

\* A path's state tag, written only while sources stand.
EntryState(j, e, target) ==
    CASE j.sources = {} -> "plain"
      [] target.gone -> "removed"
      [] Exists(e) -> "carried"
      [] OTHER -> "fresh"

\* PUT If-Match on the entry read; a 412 reads it again. An entry already holding the version, or a
\* file a newer window version replaces, is not written, and a fold that read an open window leaves
\* its covered markers alone until 150 ms past until_ms.
FoldPut(i) ==
    LET j == foldJob[i]
        r == j.ref
        p == j.path
        e == j.entry
        target == Replay(r, p, e, j.from, j.to)
        replaced == p # Dir /\ \E x \in (j.to + 1)..j.hv : ChangesPath(r, p, x)
        noChange == /\ target.ver = e.ver
                    /\ target.gone = e.gone
                    /\ target.at = e.at
                    /\ target.names = e.names
                    /\ target.namesAt = e.namesAt
        covered == /\ e.present
                   /\ e.gone
                   /\ j.sawWindow
                   /\ window[r] # "closed"
                   /\ e.at <= j.through
                   /\ Twin # "FoldIgnoresWindow"
        matched == idx[r][j.pathEpoch][p].etag = j.expect \/ Twin = "NoIfMatchFold"
        next == j.todo \ {p}
    IN  /\ j.stage = "put"
        /\ j.live
        /\ P2Allowed
        /\ CASE noChange \/ replaced ->
                    /\ foldJob' = [foldJob EXCEPT ![i] =
                           [j EXCEPT !.todo = next, !.stage = "get"]]
                    /\ UNCHANGED idx
             [] ~matched ->
                    /\ foldJob' = [foldJob EXCEPT ![i].stage = "get"]
                    /\ UNCHANGED idx
             [] ~covered ->
                    /\ idx' = [idx EXCEPT ![r][j.pathEpoch][p] =
                           [target EXCEPT !.present = TRUE, !.etag = idx[r][j.pathEpoch][p].etag + 1,
                                          !.state = EntryState(j, e, target)]]
                    /\ foldJob' = [foldJob EXCEPT ![i] =
                           [j EXCEPT !.todo = next, !.stage = "get"]]
             [] OTHER -> FALSE
        /\ UNCHANGED <<heads, batch, pack, pidx, seg, slot, slotAt, pmap, log, authority, lifecycle, statements,
                       att, authView, batchSeq, foldedTo, jobs, oracle>>

\* Every entry written: what it folded rides its next commit, which raises folded_through.
FoldDone(i) ==
    LET j == foldJob[i]
    IN  /\ j.stage = "get"
        /\ j.todo = {}
        /\ foldedTo' = [foldedTo EXCEPT ![i][j.ref] = Max(@, j.to)]
        /\ foldJob' = [foldJob EXCEPT ![i] = NoJob]
        /\ UNCHANGED <<heads, stored, authority, lifecycle, statements, att, authView, batchSeq, jobs, oracle>>

\* The write's deadline passes: 15 s after the read it relies on, the store takes none.
FoldExpires(i) ==
    /\ foldJob[i].stage \in {"get", "put"}
    /\ faultsLeft > 0
    /\ faultsLeft' = faultsLeft - 1
    /\ foldJob' = [foldJob EXCEPT ![i] = NoJob]
    /\ UNCHANGED <<heads, stored, authority, lifecycle, hour, push, pushCount, attemptsMade, att, authView,
                   batchSeq, foldedTo, jobs, oracle>>

(***************************************************************************)
(* The marker collector (11.7's collect row). A window opens by one head   *)
(* CAS; its settled step stands for the 15.3 s by which every write planned *)
(* on an older head has landed or never will, and lapsing for until_ms.    *)
(* The ASSUME above checks those two steps' margins.                        *)
(***************************************************************************)

\* Removals a base range past the horizon, which no push based before them can reach.
Collectable(r) ==
    LET h == head[r]
    IN  {u \in (h.collectDone + 1)..(h.foldedThrough - BaseRange - 1) :
            \E c \in hist[r][u].changes : c.op = "remove"}

CollectOpen(r) ==
    LET h == head[r]
    IN  /\ collector.stage = "idle"
        /\ window[r] = "closed"
        /\ heldBy[r] = NoHolder
        /\ h.sources = {}
        /\ repo.state = "active"
        /\ Collectable(r) # {}
        /\ LET through == CHOOSE u \in Collectable(r) : \A x \in Collectable(r) : x <= u
           IN  /\ head' = [head EXCEPT ![r].fence = @ + 1, ![r].refused = LiveRefused(h),
                                       ![r].windowOpen = TRUE, ![r].collectThrough = through]
               /\ collector' = [stage |-> "open", ref |-> r, through |-> through, fence |-> h.fence + 1,
                                todo |-> Paths, path |-> Dir]
        /\ window' = [window EXCEPT ![r] = "open"]
        /\ UNCHANGED <<cache, heldBy, leaseLive, blockLive, stored, authority, lifecycle, statements, att,
                       instanceState, evacuator, gc, copyJob, reader, oracle>>

\* Whether a job planned on an older head; its writes have landed or never will, here.
OlderPlan(j, r, fence) == j.stage \in {"get", "put"} /\ j.ref = r /\ j.fence < fence

CollectSettle ==
    LET r == collector.ref
    IN  /\ collector.stage = "open"
        /\ window[r] = "open"
        /\ window' = [window EXCEPT ![r] = "settled"]
        /\ collector' = [collector EXCEPT !.stage = "delete"]
        /\ foldJob' = [i \in Instances |->
               IF OlderPlan(foldJob[i], r, collector.fence) /\ Twin # "NoWindowWait"
               THEN NoJob ELSE foldJob[i]]
        /\ UNCHANGED <<head, cache, heldBy, leaseLive, blockLive, stored, authority, lifecycle, statements,
                       att, authView, batchSeq, foldedTo, evacuator, gc, copyJob, reader, oracle>>

\* GET each marker a window covers.
CollectGet(p) ==
    LET r == collector.ref
        e == idx[r][head[r].pathEpoch][p]
    IN  /\ collector.stage = "delete"
        /\ p \in collector.todo
        /\ window[r] = "settled"
        /\ collector' = IF e.present /\ e.gone /\ e.at <= collector.through
                        THEN [collector EXCEPT !.stage = "deleting", !.path = p]
                        ELSE [collector EXCEPT !.todo = @ \ {p}]
        /\ UNCHANGED <<heads, stored, authority, lifecycle, statements, att, instanceState, evacuator, gc,
                       copyJob, reader, oracle>>

\* The DELETE, which no precondition guards. Its deadline is 50 ms before until_ms.
CollectDelete ==
    LET r == collector.ref
        p == collector.path
        e == head[r].pathEpoch
    IN  /\ collector.stage = "deleting"
        /\ IF window[r] = "settled"
           THEN idx' = [idx EXCEPT ![r][e][p] = [Never EXCEPT !.etag = idx[r][e][p].etag + 1]]
           ELSE UNCHANGED idx
        /\ collector' = [collector EXCEPT !.stage = "delete", !.todo = @ \ {p}]
        /\ UNCHANGED <<heads, batch, pack, pidx, seg, slot, slotAt, pmap, log, authority, lifecycle, statements,
                       att, instanceState, evacuator, gc, copyJob, reader, oracle>>

\* Done rises only after every DELETE answered, by another such CAS.
CollectFinish ==
    LET r == collector.ref
        h == head[r]
    IN  /\ collector.stage = "delete"
        /\ collector.todo = {}
        /\ heldBy[r] = NoHolder
        /\ head' = [head EXCEPT ![r].fence = @ + 1, ![r].refused = LiveRefused(h),
                                ![r].collectDone = collector.through]
        /\ collector' = NoJob
        /\ UNCHANGED <<cache, heldBy, leaseLive, blockLive, window, stored, authority, lifecycle, statements,
                       att, instanceState, evacuator, gc, copyJob, reader, oracle>>

\* What the collector still does once until_ms passes: it only reports a pass it finished.
AfterLapse(c, r) ==
    IF c.stage = "idle" \/ c.ref # r \/ (c.stage = "delete" /\ c.todo = {}) THEN c ELSE NoJob

\* until_ms passes; a later window opens only past it. The collector stops with what it did.
WindowLapses(r) ==
    /\ window[r] # "closed"
    /\ window' = [window EXCEPT ![r] = "closed"]
    /\ collector' = AfterLapse(collector, r)
    /\ UNCHANGED <<head, cache, heldBy, leaseLive, blockLive, stored, authority, lifecycle, statements, att,
                   instanceState, evacuator, gc, copyJob, reader, oracle>>

(***************************************************************************)
(* The evacuator (11.13): batches over 25 h old.                            *)
(***************************************************************************)

\* §11.8's Resolve: the head window, then at most two log pages.
Resolution(rec) ==
    LET P == rec.push
        st == push[P]
        r == st.ref
        h == head[r]
        reach == IF GitMode(r) THEN st.base + 1 ELSE st.base + BaseRange + 1
        versions == {u \in CommitVersions(r, P) : u <= h.version}
    IN  CASE versions # {} ->
                 IF rec.place \in hist[r][CHOOSE u \in versions : TRUE].places
                 THEN "here" ELSE "elsewhere"
          [] h.version >= reach -> "dead"
          [] Lapsed(P) /\ h.fenceMark > 0 /\ h.fenceAt >= st.time + StatementMarks -> "dead"
          [] OTHER -> "pending"

EvacStart(rec) ==
    /\ evacuator.stage = "idle"
    /\ rec \in batch
    /\ hour - rec.at >= EvacuateAge
    /\ evacuator' = [stage |-> "resolve", rec |-> rec, resolution |-> "pending", kind |-> "pack"]
    /\ UNCHANGED <<heads, stored, authority, lifecycle, statements, att, instanceState, collector, gc,
                   copyJob, reader, oracle>>

EvacResolve ==
    LET rec == evacuator.rec
        r == push[rec.push].ref
        verdict == Resolution(rec)
    IN  /\ evacuator.stage = "resolve"
        /\ heldBy[r] = NoHolder
        /\ evacuator' =
               [evacuator EXCEPT
                   !.resolution = IF verdict = "pending" /\ Twin = "ResolveIgnoresPending" THEN "dead"
                                  ELSE verdict,
                   !.stage = CASE repo.state \in {"shredding", "shredded"} -> "drop"
                               [] verdict = "here" -> "container"
                               [] verdict = "pending" /\ Twin # "ResolveIgnoresPending" -> "fence"
                               [] OTHER -> "drop"]
        /\ UNCHANGED <<heads, stored, authority, lifecycle, statements, att, instanceState, collector, gc,
                       copyJob, reader, oracle>>

\* Pending: raise the ref's fence, one head CAS, then Resolve again.
EvacFence ==
    LET r == push[evacuator.rec.push].ref
    IN  /\ evacuator.stage = "fence"
        /\ heldBy[r] = NoHolder
        /\ head' = [head EXCEPT ![r].fence = @ + 1, ![r].fenceMark = @ + 1, ![r].fenceAt = hour,
                                ![r].refused = LiveRefused(head[r])]
        /\ evacuator' = [evacuator EXCEPT !.stage = "resolve"]
        /\ UNCHANGED <<cache, heldBy, leaseLive, blockLive, window, stored, authority, lifecycle, statements,
                       att, instanceState, collector, gc, copyJob, reader, oracle>>

\* Dead or duplicate: the record leaves its batch, the only cleanup. A dead record's slot goes only as
\* that record's own (DESIGN-DETAILS 14.2.5): a HEAD that finds the record's statement as its origin
\* and a LastModified the settle age has passed, then a DELETE naming that LastModified, which takes
\* that object alone. A mark is longer than the settle age, so a HEAD finds an object stored in its
\* own mark unsettled, and that slot stays: an attempt that slept since its record (14.5's leaks).
\* Here every slot is its own statement's, and nothing stores another object under a dead
\* statement's slot between the HEAD and the DELETE: its own late attempt's 412 leaves the object as
\* it was. So the two are one step, and a killed run sends no DELETE; details/EvsSlot.tla runs them
\* apart, with a stalled run beside its successor. EvacuatorSettings.DeleteDeadSlots, off in the
\* release that brings the origin (14.7), sends no DELETE at all, which only removes behaviors.
EvacDrop ==
    LET rec == evacuator.rec
        P == rec.push
        dead == evacuator.resolution = "dead"
        settled == slotAt[P] < hour
    IN  /\ evacuator.stage = "drop"
        /\ batch' = batch \ {rec}
        /\ slot' = [slot EXCEPT ![P] = IF dead /\ @ = "stored" /\ settled THEN "deleted" ELSE @]
        /\ reclaimed' = IF dead THEN reclaimed \cup {P} ELSE reclaimed
        /\ evacuator' = NoJob
        /\ UNCHANGED <<heads, pack, pidx, idx, seg, slotAt, pmap, log, authority, lifecycle, statements, att,
                       instanceState, collector, gc, copyJob, reader, hist, answers, gcDecided, readBad>>

\* A kept record goes to a pack or parcel; equal bytes on a rerun reuse it.
EvacContainer(kind) ==
    LET rec == evacuator.rec
    IN  /\ evacuator.stage = "container"
        /\ pack' = pack \cup {[id |-> rec.place, kind |-> kind]}
        /\ evacuator' = [evacuator EXCEPT !.stage = IF Twin = "EvacuateBeforeIndex" THEN "delete" ELSE "index",
                                          !.kind = kind]
        /\ UNCHANGED <<heads, batch, pidx, idx, seg, slot, slotAt, pmap, log, authority, lifecycle, statements,
                       att, instanceState, collector, gc, copyJob, reader, oracle>>

EvacIndex ==
    /\ evacuator.stage = "index"
    /\ pidx' = pidx \cup {[id |-> evacuator.rec.place, kind |-> evacuator.kind]}
    /\ evacuator' = [evacuator EXCEPT !.stage = "delete"]
    /\ UNCHANGED <<heads, batch, pack, idx, seg, slot, slotAt, pmap, log, authority, lifecycle, statements, att,
                   instanceState, collector, gc, copyJob, reader, oracle>>

\* I-EVS-7: only now.
EvacDelete ==
    /\ evacuator.stage = "delete"
    /\ batch' = batch \ {evacuator.rec}
    /\ evacuator' = NoJob
    /\ UNCHANGED <<heads, pack, pidx, idx, seg, slot, slotAt, pmap, log, authority, lifecycle, statements, att,
                   instanceState, collector, gc, copyJob, reader, oracle>>

\* A killed run restarts its minute; containers and entries already made stand.
EvacCrash ==
    /\ evacuator.stage # "idle"
    /\ faultsLeft > 0
    /\ faultsLeft' = faultsLeft - 1
    /\ evacuator' = NoJob
    /\ UNCHANGED <<heads, stored, authority, lifecycle, hour, push, pushCount, attemptsMade, att, instanceState,
                   collector, gc, copyJob, reader, oracle>>

\* A parcel gives way to a pack in three steps, the pack's entry before the parcel goes.
RepackPut(id) ==
    /\ [id |-> id, kind |-> "parcel"] \in pack
    /\ [id |-> id, kind |-> "pack"] \notin pack
    /\ pack' = pack \cup {[id |-> id, kind |-> "pack"]}
    /\ UNCHANGED <<heads, batch, pidx, idx, seg, slot, slotAt, pmap, log, authority, lifecycle, statements, att,
                   instanceState, jobs, oracle>>

RepackIndex(id) ==
    /\ [id |-> id, kind |-> "pack"] \in pack
    /\ [id |-> id, kind |-> "parcel"] \in pack
    /\ [id |-> id, kind |-> "pack"] \notin pidx
    /\ pidx' = pidx \cup {[id |-> id, kind |-> "pack"]}
    /\ UNCHANGED <<heads, batch, pack, idx, seg, slot, slotAt, pmap, log, authority, lifecycle, statements, att,
                   instanceState, jobs, oracle>>

RepackDrop(id) ==
    /\ [id |-> id, kind |-> "pack"] \in pidx
    /\ [id |-> id, kind |-> "parcel"] \in pack
    /\ pack' = pack \ {[id |-> id, kind |-> "parcel"]}
    /\ pidx' = pidx \ {[id |-> id, kind |-> "parcel"]}
    /\ UNCHANGED <<heads, batch, idx, seg, slot, slotAt, pmap, log, authority, lifecycle, statements, att,
                   instanceState, jobs, oracle>>

(***************************************************************************)
(* Segment GC (11.13's orphans).                                            *)
(***************************************************************************)

\* A committed push of the repo introduced it: what the nightly pass reads.
Introduced(s) == \E r \in Refs : \E u \in 1..Committed(r) : hist[r][u].seg = s

\* Refs the 25 h mark must fence: those written before LastModified + 24 h. A ref written since was
\* fenced by that write.
GcRefs(s) ==
    {r \in Refs : /\ head[r].version + head[r].fence > 0
                  /\ head[r].written < seg[s].at + ReceiptAge}

GcMark(s) ==
    /\ gc.stage = "idle"
    /\ seg[s].stored
    /\ hour - seg[s].at >= OrphanAge
    /\ ~Introduced(s)
    /\ gc' = [stage |-> "fence", seg |-> s, todo |-> IF Twin = "GcNoFence" THEN {} ELSE GcRefs(s)]
    /\ UNCHANGED <<heads, stored, authority, lifecycle, statements, att, instanceState, collector, evacuator,
                   copyJob, reader, oracle>>

\* One head CAS for each, at most one a day; it sets fence_ms for 11.8's fence row.
GcFence(r) ==
    /\ gc.stage = "fence"
    /\ r \in gc.todo
    /\ heldBy[r] = NoHolder
    /\ head' = [head EXCEPT ![r].fence = @ + 1, ![r].fenceMark = @ + 1, ![r].fenceAt = hour,
                            ![r].refused = LiveRefused(head[r])]
    /\ gc' = [gc EXCEPT !.todo = @ \ {r}]
    /\ UNCHANGED <<cache, heldBy, leaseLive, blockLive, window, stored, authority, lifecycle, statements, att,
                   instanceState, collector, evacuator, copyJob, reader, oracle>>

\* Past the store's deadline, the repo's commits since the first check, again.
GcCheck ==
    /\ gc.stage = "fence"
    /\ gc.todo = {}
    /\ gc' = IF Introduced(gc.seg) /\ Twin # "GcNoSecondCheck" THEN NoJob
             ELSE [gc EXCEPT !.stage = "delete"]
    /\ UNCHANGED <<heads, stored, authority, lifecycle, statements, att, instanceState, collector, evacuator,
                   copyJob, reader, oracle>>

GcDelete ==
    /\ gc.stage = "delete"
    /\ seg' = [seg EXCEPT ![gc.seg].stored = FALSE]
    /\ gcDecided' = gcDecided \cup {gc.seg}
    /\ gc' = NoJob
    /\ UNCHANGED <<heads, batch, pack, pidx, idx, slot, slotAt, pmap, log, authority, lifecycle, statements, att,
                   instanceState, collector, evacuator, copyJob, reader, hist, answers, reclaimed, readBad>>

\* An uncommitted map 25 h old goes by the same rule, fencing only its ref.
MapReclaim(r, m) ==
    /\ m \in pmap[r]
    /\ hour - m.at >= OrphanAge
    /\ head[r].pathEpoch < m.gen
    /\ heldBy[r] = NoHolder
    /\ head' = [head EXCEPT ![r].fence = @ + 1, ![r].fenceMark = @ + 1, ![r].fenceAt = hour,
                            ![r].refused = LiveRefused(head[r])]
    /\ pmap' = [pmap EXCEPT ![r] = @ \ {m}]
    /\ UNCHANGED <<cache, heldBy, leaseLive, blockLive, window, batch, pack, pidx, idx, seg, slot, slotAt, log,
                   authority, lifecycle, statements, att, instanceState, jobs, oracle>>

(***************************************************************************)
(* Lifecycle (11.12): every transition If-Match on repo/.                   *)
(***************************************************************************)

RepoDelete ==
    /\ repo.state = "active"
    /\ repo.deletion < 2
    /\ repo' = [repo EXCEPT !.state = "deleted", !.deletion = @ + 1]
    /\ UNCHANGED <<heads, stored, authority, shred, statements, att, instanceState, jobs, oracle>>

RepoRestore ==
    /\ repo.state = "deleted" \/ (Twin = "RestoreAfterShred" /\ repo.state = "shredding")
    /\ repo' = [repo EXCEPT !.state = "active"]
    /\ UNCHANGED <<heads, stored, authority, shred, statements, att, instanceState, jobs, oracle>>

\* restore and start race on one If-Match: exactly one wins. --now claims an active repo.
ShredClaim ==
    /\ repo.state \in {"active", "deleted"}
    /\ shred.stage = "idle"
    /\ repo' = [repo EXCEPT !.state = "shredding"]
    /\ shred' = [stage |-> "wait", deletion |-> repo.deletion]
    /\ UNCHANGED <<heads, stored, authority, statements, att, instanceState, jobs, oracle>>

\* Each step rereads repo/ and runs only under the job's deletion id.
ShredLive == repo.state = "shredding" /\ repo.deletion = shred.deletion

\* Phase 1: 20 s, so a push validated before the CAS has landed, or never will. Every attempt runs
\* steps 4 and 5 again, past the cached repo/, or it holds its head until §19.6 settles it.
ShredWait ==
    /\ shred.stage = "wait"
    /\ ShredLive
    /\ shred' = [shred EXCEPT !.stage = "keys"]
    /\ att' = [i \in Instances |->
           IF att[i].stage \in {"idle", "stalled"} THEN att[i] ELSE Restart(att[i])]
    /\ UNCHANGED <<heads, stored, authority, repo, statements, instanceState, jobs, oracle>>

\* Phase 2: keys first.
ShredKeys ==
    /\ shred.stage = "keys"
    /\ ShredLive
    /\ slot' = [P \in PushIds |-> IF slot[P] = "none" THEN "none" ELSE "deleted"]
    /\ shred' = [shred EXCEPT !.stage = "gkm"]
    /\ UNCHANGED <<heads, batch, pack, pidx, idx, seg, slotAt, pmap, log, authority, repo, statements, att,
                   instanceState, jobs, oracle>>

\* Phase 3: the group's objects.
ShredGkm ==
    /\ shred.stage = "gkm"
    /\ ShredLive
    /\ gen' = [g \in {} |-> 0]
    /\ epoch' = <<>>
    /\ shred' = [shred EXCEPT !.stage = "objects"]
    /\ UNCHANGED <<heads, stored, proj, rev, repo, statements, att, instanceState, jobs, oracle>>

\* The objects of phase 5, repeated by phase 6.
ClearedIdx == [r \in Refs |-> [e \in 1..MaxGeneration |-> [p \in Paths |-> Never]]]

ShredDeletes ==
    /\ head' = [r \in Refs |-> EmptyHead]
    /\ cache' = [r \in Refs |-> EmptyHead]
    /\ idx' = ClearedIdx
    /\ log' = [r \in Refs |-> {}]
    /\ pmap' = [r \in Refs |-> {}]
    /\ pack' = {}
    /\ pidx' = {}
    /\ seg' = [s \in Segments |-> [stored |-> FALSE, at |-> 0]]

\* Phase 5. A stalled head PUT holds its key, which this request waits for.
ShredObjects ==
    /\ shred.stage = "objects"
    /\ ShredLive
    /\ \A r \in Refs : heldBy[r] = NoHolder
    /\ ShredDeletes
    /\ shred' = [shred EXCEPT !.stage = "stragglers"]
    /\ UNCHANGED <<heldBy, leaseLive, blockLive, window, batch, slot, slotAt, authority, repo, statements, att,
                   instanceState, jobs, oracle>>

\* Phase 6: 10 min on no P2 or gkm write lands later, and a repeat takes what landed meanwhile.
ShredStragglers ==
    /\ shred.stage = "stragglers"
    /\ ShredLive
    /\ \A r \in Refs : heldBy[r] = NoHolder
    /\ ShredDeletes
    /\ slot' = [P \in PushIds |-> IF slot[P] = "none" THEN "none" ELSE "deleted"]
    /\ foldJob' = [i \in Instances |-> NoJob]
    /\ copyJob' = [r \in Refs |-> NoJob]
    /\ shred' = [shred EXCEPT !.stage = "tombstone"]
    /\ UNCHANGED <<heldBy, leaseLive, blockLive, window, batch, slotAt, authority, repo, statements, att,
                   authView, batchSeq, foldedTo, collector, evacuator, gc, reader, oracle>>

\* Phase 7.
ShredTombstone ==
    /\ shred.stage = "tombstone"
    /\ ShredLive
    /\ repo' = [repo EXCEPT !.state = "shredded"]
    /\ shred' = [shred EXCEPT !.stage = "done"]
    /\ UNCHANGED <<heads, stored, authority, statements, att, instanceState, jobs, oracle>>

(***************************************************************************)
(* The remover, the ladder and path epochs (§7.10, §10.5, 11.6).           *)
(***************************************************************************)

\* api stores the revocation at n', writing rev/ first; the gate closes as each evs learns it.
Remove(w, kind) ==
    /\ ActiveRepo
    /\ proj.shrunkAt = 0
    /\ rev' = rev \cup {w}
    /\ proj' = [n |-> proj.n + 1, shrunkAt |-> proj.n + 1, kind |-> kind]
    /\ UNCHANGED <<heads, stored, gen, epoch, lifecycle, statements, att, instanceState, jobs, oracle>>

\* api's notification, within 5 s, or evs's poll.
AuthRefresh(i) ==
    /\ authView[i] < proj.n
    /\ authView' = [authView EXCEPT ![i] = proj.n]
    /\ UNCHANGED <<heads, stored, authority, lifecycle, statements, att, batchSeq, foldJob, foldedTo, jobs, oracle>>

\* A REMOVE rotation: any writer claims gen/<g+1>, If-None-Match the only order there is.
Rotate(w) ==
    LET g == NewestGeneration + 1
    IN  /\ ActiveRepo
        /\ w \notin rev
        /\ proj.shrunkAt # 0
        /\ g <= MaxGeneration
        /\ gen' = gen @@ (g :> [by |-> w, auth |-> proj.n])
        /\ UNCHANGED <<heads, stored, epoch, proj, rev, lifecycle, statements, att, instanceState, jobs, oracle>>

\* A twin claim replaces the winner, which If-None-Match forbids.
RotateAgain(w) ==
    /\ Twin = "LadderFork"
    /\ ActiveRepo
    /\ w \notin rev
    /\ NewestGeneration > 1
    /\ gen[NewestGeneration].by # w
    /\ gen' = [gen EXCEPT ![NewestGeneration].by = w]
    /\ UNCHANGED <<heads, stored, epoch, proj, rev, lifecycle, statements, att, instanceState, jobs, oracle>>

\* epoch/<n>: created once n - 1 exists, its header the newest generation gkm read.
EpochCommit(w) ==
    /\ ActiveRepo
    /\ w \notin rev
    /\ Len(epoch) < MaxGeneration + 1
    /\ epoch' = Append(epoch, [by |-> w, gen |-> NewestGeneration])
    /\ UNCHANGED <<heads, stored, gen, proj, rev, lifecycle, statements, att, instanceState, jobs, oracle>>

\* The mapper uploads parts for the newest generation, bound to the head they cover.
MapUpload(r) ==
    /\ ActiveRepo
    /\ head[r].dueGen # 0
    /\ heldBy[r] = NoHolder
    /\ ~\E x \in pmap[r] : x.gen = head[r].dueGen /\ x.source = head[r].version
    /\ pmap' = [pmap EXCEPT ![r] = @ \cup {[gen |-> head[r].dueGen, source |-> head[r].version, at |-> hour]}]
    /\ UNCHANGED <<heads, batch, pack, pidx, idx, seg, slot, slotAt, log, authority, lifecycle, statements, att,
                   instanceState, jobs, oracle>>

\* A PATH_EPOCH statement on the head the mapper read, its tail built from the versions since.
EpochSign(w, r, m) ==
    LET P == pushCount + 1
        h == head[r]
    IN  /\ ActiveRepo
        /\ pushCount < MaxPush
        /\ w \notin rev
        /\ m \in pmap[r]
        /\ m.gen = h.dueGen
        /\ Committed(r) < MaxVersion
        /\ pushCount' = P
        /\ push' = [push EXCEPT ![P] =
               [status |-> "ready", writer |-> w, ref |-> r, base |-> h.version, kind |-> "epoch",
                changes |-> {}, seg |-> NoSegment, receipt |-> 0, newSlot |-> FALSE,
                gen |-> NewestGeneration, auth |-> proj.n, pathEpoch |-> h.pathEpoch, epochTo |-> m.gen,
                map |-> m.source, tail |-> CreatedIn(r, m.source, h.version), time |-> hour,
                parts |-> {}, leased |-> FALSE]]
        /\ UNCHANGED <<heads, stored, authority, lifecycle, hour, faultsLeft, attemptsMade, att, instanceState,
                       jobs, oracle>>

\* 10 min past due, a mapper may stop creation for a while, by one head CAS raising the fence.
Block(r) ==
    /\ head[r].dueGen # 0
    /\ ~blockLive[r]
    /\ heldBy[r] = NoHolder
    /\ head' = [head EXCEPT ![r].fence = @ + 1, ![r].refused = LiveRefused(head[r])]
    /\ blockLive' = [blockLive EXCEPT ![r] = TRUE]
    /\ UNCHANGED <<cache, heldBy, leaseLive, window, stored, authority, lifecycle, statements, att, instanceState,
                   jobs, oracle>>

BlockLapses(r) ==
    /\ blockLive[r]
    /\ blockLive' = [blockLive EXCEPT ![r] = FALSE]
    /\ UNCHANGED <<head, cache, heldBy, leaseLive, window, stored, authority, lifecycle, statements, att,
                   instanceState, jobs, oracle>>

LeaseLapses(r) ==
    /\ leaseLive[r]
    /\ leaseLive' = [leaseLive EXCEPT ![r] = FALSE]
    /\ UNCHANGED <<head, cache, heldBy, blockLive, window, stored, authority, lifecycle, statements, att,
                   instanceState, jobs, oracle>>

(***************************************************************************)
(* The path-epoch copy (11.6): children before their directory.             *)
(***************************************************************************)

CopyOrder == <<Child, Leaf, Dir>>

CopyStart(r) ==
    LET h == head[r]
    IN  /\ copyJob[r].stage = "idle"
        /\ h.sources # {}
        /\ heldBy[r] = NoHolder
        /\ P2Allowed
        /\ copyJob' = [copyJob EXCEPT ![r] =
               [stage |-> "get", ref |-> r, to |-> h.pathEpoch, from |-> CHOOSE x \in h.sources : TRUE,
                todo |-> CopyOrder, entry |-> Never, fence |-> h.fence]]
        /\ UNCHANGED <<heads, stored, authority, lifecycle, statements, att, instanceState, collector, evacuator,
                       gc, reader, oracle>>

\* The entry from the newest source holding it; nothing there, nothing to move.
CopyGet(r) ==
    LET j == copyJob[r]
        p == Head(j.todo)
        src == idx[r][j.from][p]
    IN  /\ j.stage = "get"
        /\ j.todo # <<>>
        /\ copyJob' = [copyJob EXCEPT ![r] =
               IF src.present THEN [j EXCEPT !.stage = "put", !.entry = src]
               ELSE [j EXCEPT !.todo = Tail(j.todo)]]
        /\ UNCHANGED <<heads, stored, authority, lifecycle, statements, att, instanceState, collector, evacuator,
                       gc, reader, oracle>>

\* PUT If-None-Match, carried; on 412 a file or a removed or fresh entry is done, and a carried
\* directory's rows are already current in the model, whose table has no tokens to translate.
CopyPut(r) ==
    LET j == copyJob[r]
        p == Head(j.todo)
        cur == idx[r][j.to][p]
    IN  /\ j.stage = "put"
        /\ P2Allowed
        /\ IF cur.present /\ Twin # "CopyOverwrites"
           THEN /\ copyJob' = [copyJob EXCEPT ![r].stage = "delete"]
                /\ UNCHANGED idx
           ELSE /\ idx' = [idx EXCEPT ![r][j.to][p] =
                       [j.entry EXCEPT !.state = "carried", !.etag = cur.etag + 1]]
                /\ copyJob' = [copyJob EXCEPT ![r].stage = "mark"]
        /\ UNCHANGED <<heads, batch, pack, pidx, seg, slot, slotAt, pmap, log, authority, lifecycle, statements,
                       att, instanceState, collector, evacuator, gc, reader, oracle>>

\* After each PUT it HEADs the path's prefixes; under a removed or fresh one, what it put becomes a
\* marker, If-Match on that PUT, so a newer entry stands.
CopyMark(r) ==
    LET j == copyJob[r]
        p == Head(j.todo)
        cur == idx[r][j.to][p]
        pre == IF Prefixes(p) = {} THEN Never ELSE idx[r][j.to][Dir]
        under == pre.present /\ (pre.gone \/ pre.state = "fresh")
    IN  /\ j.stage = "mark"
        /\ P2Allowed
        /\ IF under /\ cur.state = "carried" /\ ~cur.gone
           THEN idx' = [idx EXCEPT ![r][j.to][p] =
                    [cur EXCEPT !.gone = TRUE, !.ver = @ + 1, !.state = "removed", !.etag = @ + 1]]
           ELSE UNCHANGED idx
        /\ copyJob' = [copyJob EXCEPT ![r].stage = "delete"]
        /\ UNCHANGED <<heads, batch, pack, pidx, seg, slot, slotAt, pmap, log, authority, lifecycle, statements,
                       att, instanceState, collector, evacuator, gc, reader, oracle>>

\* A source goes only after its newest copy exists.
CopyDelete(r) ==
    LET j == copyJob[r]
        p == Head(j.todo)
    IN  /\ j.stage = "delete"
        /\ idx' = [idx EXCEPT ![r][j.from][p] = [Never EXCEPT !.etag = idx[r][j.from][p].etag + 1]]
        /\ copyJob' = [copyJob EXCEPT ![r] = [j EXCEPT !.stage = "get", !.todo = Tail(j.todo)]]
        /\ UNCHANGED <<heads, batch, pack, pidx, seg, slot, slotAt, pmap, log, authority, lifecycle, statements,
                       att, instanceState, collector, evacuator, gc, reader, oracle>>

\* Every source empty, a fence write drops them; an entry the map missed keeps its source listed.
CopyEnd(r) ==
    LET j == copyJob[r]
    IN  /\ j.stage = "get"
        /\ j.todo = <<>>
        /\ heldBy[r] = NoHolder
        /\ IF \A p \in Paths : ~idx[r][j.from][p].present
           THEN head' = [head EXCEPT ![r].fence = @ + 1, ![r].sources = @ \ {j.from},
                                     ![r].refused = LiveRefused(head[r])]
           ELSE UNCHANGED head
        /\ copyJob' = [copyJob EXCEPT ![r] = NoJob]
        /\ UNCHANGED <<cache, heldBy, leaseLive, blockLive, window, stored, authority, lifecycle, statements, att,
                       instanceState, collector, evacuator, gc, reader, oracle>>

(***************************************************************************)
(* A head read or listing (11.9), one GET a step, by 11.7's newest rule.    *)
(***************************************************************************)

ReadStart(r, p) ==
    /\ reader.stage = "idle"
    /\ repo.state = "active"
    /\ reader' = [stage |-> "head", ref |-> r, path |-> p, rerun |-> FALSE, hd |-> EmptyHead, hft |-> 0,
                  ent |-> Never, cur |-> Never, pre |-> Never]
    /\ UNCHANGED <<heads, stored, authority, lifecycle, statements, att, instanceState, collector, evacuator, gc,
                   copyJob, oracle>>

ReaderHead(src) ==
    LET r == reader.ref
        h == IF src = "cache" THEN cache[r] ELSE head[r]
    IN  /\ reader.stage = "head"
        /\ heldBy[r] = NoHolder
        /\ src = "cluster" \/ ~reader.rerun
        /\ reader' = [reader EXCEPT !.hd = h,
                                    !.hft = IF reader.rerun /\ Twin # "ReaderStaleHorizon" THEN @
                                            ELSE h.foldedThrough,
                                    !.stage = IF reader.rerun THEN "serve" ELSE "cur"]
        /\ UNCHANGED <<heads, stored, authority, lifecycle, statements, att, instanceState, collector, evacuator,
                       gc, copyJob, oracle>>

ReaderGet ==
    LET r == reader.ref
        p == reader.path
        h == reader.hd
        e == h.pathEpoch
        src == idx[r][CHOOSE x \in h.sources \cup {1} : TRUE][p]
    IN  /\ reader.stage \in {"cur", "pre", "src", "again"}
        /\ reader' =
               CASE reader.stage = "cur" /\ h.sources = {} ->
                        [reader EXCEPT !.ent = idx[r][e][p], !.stage = "serve"]
                 [] reader.stage = "cur" ->
                        [reader EXCEPT !.cur = idx[r][e][p], !.stage = "pre"]
                 [] reader.stage = "pre" ->
                        [reader EXCEPT !.pre = IF Prefixes(p) = {} THEN Never ELSE idx[r][e][Dir],
                                       !.stage = "src"]
                 [] reader.stage = "src" ->
                        LET st == Settled(reader.cur, reader.pre, src)
                        IN  IF st.present \/ reader.pre.gone
                            THEN [reader EXCEPT !.ent = st, !.stage = "serve"]
                            ELSE [reader EXCEPT !.stage = "again"]
                 [] OTHER ->
                        [reader EXCEPT !.ent = idx[r][e][p], !.stage = "serve"]
        /\ UNCHANGED <<heads, stored, authority, lifecycle, statements, att, instanceState, collector, evacuator,
                       gc, copyJob, oracle>>

\* A folded version past the head sends evs to a newer head; a window short of the horizon sends it
\* back to the entries; otherwise it serves, and the oracle compares.
ReaderServe ==
    LET r == reader.ref
        p == reader.path
        h == reader.hd
    IN  /\ reader.stage = "serve"
        /\ CASE reader.ent.at > h.version ->
                    /\ reader' = [reader EXCEPT !.stage = "head", !.rerun = TRUE]
                    /\ UNCHANGED readBad
             [] reader.hft + 1 < h.winFrom ->
                    /\ reader' = [reader EXCEPT !.hft = h.foldedThrough, !.stage = "cur"]
                    /\ UNCHANGED readBad
             [] OTHER ->
                    /\ reader' = NoJob
                    /\ readBad' = (readBad \/ ~SameRead(Replay(r, p, reader.ent, reader.hft, h.version),
                                                        Truth(r, p, h.version)))
        /\ UNCHANGED <<heads, stored, authority, lifecycle, statements, att, instanceState, collector, evacuator,
                       gc, copyJob, hist, answers, reclaimed, gcDecided>>

(***************************************************************************)
(* Time.                                                                    *)
(***************************************************************************)

\* A long mark passes, and with it every short timer, the store's request deadline among them: a step
\* 7 issued and not landed never will, and its attempt reads the head again (§19.6; 11.13's "every
\* adoption commits within 24 h of the upload, plus 5 s and the store's request deadline"). One whose
\* drive commits stalled holds its key (heldBy) until §19.6 settles it, as FS-59's does; only its
\* If-Match and the fence stand in its way.
Tick ==
    /\ hour < MaxHour
    /\ hour' = hour + 1
    /\ leaseLive' = [r \in Refs |-> FALSE]
    /\ blockLive' = [r \in Refs |-> FALSE]
    /\ window' = [r \in Refs |-> "closed"]
    /\ authView' = [i \in Instances |-> proj.n]
    /\ att' = [i \in Instances |-> IF att[i].stage = "put" THEN Reread(att[i]) ELSE att[i]]
    /\ foldJob' = [i \in Instances |-> IF foldJob[i].stage \in {"get", "put"} THEN NoJob ELSE foldJob[i]]
    /\ collector' = IF collector.stage = "idle" THEN collector
                    ELSE AfterLapse(collector, collector.ref)
    /\ UNCHANGED <<head, cache, heldBy, stored, authority, lifecycle, faultsLeft, push, pushCount, attemptsMade,
                   batchSeq, foldedTo, evacuator, gc, copyJob, reader, oracle>>

\* A twin's answer-time cleanup: 11.8 forbids it.
AnswerCleans(P) ==
    /\ Twin = "AnswerDeletes"
    /\ answers[P].refused
    /\ slot[P] = "stored"
    /\ slot' = [slot EXCEPT ![P] = "deleted"]
    /\ UNCHANGED <<heads, batch, pack, pidx, idx, seg, slotAt, pmap, log, authority, lifecycle, statements, att,
                   instanceState, jobs, oracle>>

EvsStep(i) ==
    \/ ReadHead(i)
    \/ ReadRepo(i)
    \/ \E p \in Paths : ReadEntry(i, p)
    \/ Check(i)
    \/ CheckLease(i)
    \/ RecordRefusal(i)
    \/ WriteRecord(i)
    \/ WriteSlot(i)
    \/ PageOut(i)
    \/ CommitPut(i)

FoldStep(i) ==
    \/ FoldRead(i)
    \/ \E p \in Paths : FoldGet(i, p)
    \/ FoldPut(i)
    \/ FoldDone(i)

CopyStep(r) ==
    \/ CopyStart(r)
    \/ CopyGet(r)
    \/ CopyPut(r)
    \/ CopyMark(r)
    \/ CopyDelete(r)
    \/ CopyEnd(r)

CollectStep ==
    \/ CollectSettle
    \/ \E p \in Paths : CollectGet(p)
    \/ CollectDelete
    \/ CollectFinish

EvacStep ==
    \/ EvacResolve
    \/ EvacFence
    \/ EvacDrop
    \/ \E kind \in {"pack", "parcel"} : EvacContainer(kind)
    \/ EvacIndex
    \/ EvacDelete

ShredStep ==
    \/ ShredWait
    \/ ShredKeys
    \/ ShredGkm
    \/ ShredObjects
    \/ ShredStragglers
    \/ ShredTombstone

NextM2 ==
    \/ SignFresh
    \/ SignStale
    \/ \E P \in PushIds : push[P].status = "upload" /\ Upload(P)
    \/ \E i \in Instances :
           \/ \E P \in 1..pushCount : Arrive(i, P)
           \/ EvsStep(i)
           \/ Timeout(i)
           \/ PutFails(i)
           \/ PutStalls(i)
           \/ Crash(i)
           \/ AuthRefresh(i)
           \/ \E r \in Refs, u \in 1..MaxVersion : FoldQueue(i, r, u)
           \/ FoldStep(i)
           \/ FoldExpires(i)
    \/ \E r \in Refs :
           \/ \E i \in Instances : StallLands(r, i) \/ StallReverts(r, i)
           \/ CachePut(r)
           \/ CollectOpen(r)
           \/ WindowLapses(r)
           \/ MapUpload(r)
           \/ \E w \in Writers, m \in pmap[r] : EpochSign(w, r, m)
           \/ \E m \in pmap[r] : MapReclaim(r, m)
           \/ Block(r)
           \/ BlockLapses(r)
           \/ LeaseLapses(r)
           \/ CopyStep(r)
           \/ GcFence(r)
           \/ \E p \in Paths : ReadStart(r, p)
    \/ CollectStep
    \/ \E rec \in batch : EvacStart(rec)
    \/ EvacStep
    \/ EvacCrash
    \/ \E id \in {c.id : c \in pack} : RepackPut(id) \/ RepackIndex(id) \/ RepackDrop(id)
    \/ \E s \in Segments : GcMark(s)
    \/ GcCheck
    \/ GcDelete
    \/ RepoDelete
    \/ RepoRestore
    \/ ShredClaim
    \/ ShredStep
    \/ \E w \in Writers :
           \/ \E kind \in {"immediate", "batched"} : Remove(w, kind)
           \/ Rotate(w)
           \/ RotateAgain(w)
           \/ EpochCommit(w)
    \/ \E src \in {"cluster", "cache"} : ReaderHead(src)
    \/ ReaderGet
    \/ ReaderServe
    \/ Tick
    \/ \E P \in PushIds : AnswerCleans(P)

(***************************************************************************)
(* M10: versionless versions, the purge and dropped history (§11.7,        *)
(* §11.13). §22.8's model row adds, from M10, versionless versions, kind-5 *)
(* and staged content and holds as variables and the purger and the sweep  *)
(* as processes, TLC checking I-EVS-9, I-EVS-10, FI-16 and FI-17 (the purge *)
(* runs); then DROP pushes, the citation fence and the drop job, a hold    *)
(* placer and ender, and writers that copy across refs, rename, re-upload  *)
(* a candidate's bytes and write after a drop, beside the purge's          *)
(* processes, TLC checking I-EVS-15, FI-27 and I-EVS-1 and that every      *)
(* executing drop ends (the drop runs).                                     *)
(*                                                                          *)
(* This part keeps variables of its own. F2Run picks a run: "none" runs the *)
(* M2 part above alone, and any other run holds the M2 part at its start,   *)
(* so neither's states multiply the other's. What the part abstracts:      *)
(* - A push is its validation, steps 4 and 5 over the head it reads, and   *)
(*   its step 7, an If-Match on that head, which lands before the next     *)
(*   minute passes or never (§19.6's request deadline and settle rule,     *)
(*   which StoreSettle.tla checks). The M2 part checks the steps between;  *)
(*   here a refused or dead push leaves only what it uploaded.             *)
(* - Writers sign the run's story, F2Story, in order, each statement taken  *)
(*   by whichever instance validates it; one whose checks fail is refused  *)
(*   and the story goes on. What races is the rest: other statements' late *)
(*   step 7s, lost answers, crashes, the purger, holds, evacuation and the  *)
(*   drop job.                                                              *)
(* - A ref version changes one path, a path and its rename source, or a    *)
(*   directory and the files below it, and a path's lineage is one path on *)
(*   one ref: token paths and epochs are the M2 part's.                     *)
(* - Short times are events. A minute passes: every version and queued     *)
(*   candidate list is past the readers' 60 s allowance, every hold has    *)
(*   reached every 5 s cache, every step 7 in flight has landed or never   *)
(*   will, and a drop whose window ended has waited out its 25 min. A long *)
(*   mark passes a minute too, and ages objects by 11.13's 23, 24 and 25 h *)
(*   rules, which the M2 part's marks name.                                 *)
(***************************************************************************)

CONSTANTS
    F2Run,        \* "none", or an M10 run: a purge story or a drop story (F2Story)
    F2MaxHour,    \* long marks in one behavior of an M10 run
    F2MaxFaults,  \* lost answers, crashes and lapsed job leases in one behavior of an M10 run
    F2MaxHolds    \* holds placed in one behavior of an M10 run

F2PurgeRuns == {"purgeA", "purgeB", "purgeC", "purgeD", "purgeE"}
F2DropRuns == {"dropA", "dropB", "dropC"}

ASSUME
    /\ F2Run \in {"none"} \cup F2PurgeRuns \cup F2DropRuns
    /\ F2MaxHour \in Nat /\ F2MaxFaults \in Nat /\ F2MaxHolds \in Nat

F2Mode == CASE F2Run = "none" -> "off"
            [] F2Run \in F2PurgeRuns -> "purge"
            [] OTHER -> "drop"

\* Each run's refs, paths and objects. "D" is a directory and "X" a file below it; in the drop runs
\* "R" is X's rename source and "Y" a reuse copy on the second file-mode ref, "G" the git-mode ref.
F2FileRefs == IF F2Mode = "drop" THEN {"A", "B"} ELSE {"A"}
F2GitRefs == IF F2Mode = "drop" THEN {"G"} ELSE {}
F2Refs == F2FileRefs \cup F2GitRefs
F2Paths == IF F2Mode = "drop" THEN {"R", "X", "Y"} ELSE {"D", "X", "Y"}
F2Dir == "D"
F2Below == {"X"}
F2Segs == CASE F2Run \in {"purgeA", "dropA", "dropB"} -> {"s1", "s2", "s3"}
            [] F2Run \in {"purgeB", "purgeC", "purgeE", "dropC"} -> {"s1", "s2"}
            [] F2Run = "purgeD" -> {"s1"}
            [] OTHER -> {}
F2Slots == CASE F2Run = "purgeC" -> {"k1", "k2"}
             [] F2Run \in {"dropA", "dropB"} -> {"k1"}
             [] OTHER -> {}
F2Ids == F2Segs \cup F2Slots

\* A statement: an operation on a path of a ref. A write's arg names its content: "dir" a directory;
\* "k1" a fresh kind-1 upload, "k1slot" with a fresh slot beside it; "k5", "staged" and "rekey"
\* versionless content, a fresh kind-5 upload, a staged segment or a kind-5 upload under a fresh slot;
\* "same" the previous version's content unchanged; "on" versioning turned on, adopting the previous
\* version's kind-5 segments as kind 1. A copy and an adopt name a source version, the newest or the
\* one before it: a copy reuses its kind-1 content, and an adopt re-uploads its bytes for a receipt.
St(op, r, p, arg) == [op |-> op, ref |-> r, path |-> p, arg |-> arg]
Src(r, p, at) == [ref |-> r, path |-> p, at |-> at]

\* Each run is one story, small enough for breadth-first search; together they cover §22.8's list: a
\* versionless path through an overwrite, a staged version, a rename, a removal, a directory removal
\* listing it or not, versioning turned on, and a hold (every run may place one); and drops of a
\* written or a removed boundary, a rename source, a reuse copy on the second file-mode ref and on
\* the git-mode ref, a late step 7 against the fence, a re-upload of a candidate's bytes, a write
\* after the drop, and a cancel.
F2Story ==
    CASE F2Run = "purgeA" ->
             \* an overwrite, then a staged version and its replacement
             << St("write", "A", "X", "k5"), St("write", "A", "X", "staged"), St("write", "A", "X", "k5") >>
      [] F2Run = "purgeB" ->
             \* a version citing its predecessor's segment, a rename, an overwrite and a removal
             << St("write", "A", "X", "k5"), St("write", "A", "X", "same"), St("rename", "A", "Y", "X"),
                St("write", "A", "Y", "k5"), St("remove", "A", "Y", "") >>
      [] F2Run = "purgeC" ->
             \* a slot-keyed repo: a fresh slot, then a directory removal not listing X
             << St("write", "A", "D", "dir"), St("write", "A", "X", "k5"), St("write", "A", "X", "rekey"),
                St("rmdir", "A", "D", "unlisted") >>
      [] F2Run = "purgeD" ->
             \* a directory removal listing X
             << St("write", "A", "D", "dir"), St("write", "A", "X", "k5"), St("rmdir", "A", "D", "listed") >>
      [] F2Run = "purgeE" ->
             \* versioning turned on adopts the kind-5 segment as kind 1, kept for good
             << St("write", "A", "X", "k5"), St("write", "A", "X", "on"), St("write", "A", "X", "k5") >>
      [] F2Run = "dropA" ->
             \* X renamed from R, a copy on B of X's first version (the segment R shares), and the DROP of
             \* X's versions: the copy, validated before the fence, may land after it
             << St("write", "A", "R", "k1"), St("rename", "A", "X", "R"), St("write", "A", "X", "k1slot"),
                St("copy", "B", "Y", Src("A", "X", "prev")), St("drop", "A", "X", "written") >>
      [] F2Run = "dropB" ->
             \* after the DROP, a copy onto the git-mode ref of a listed version, which the fence refuses,
             \* and a re-upload of a candidate's bytes, written to Y on B
             << St("write", "A", "X", "k1slot"), St("write", "A", "X", "k1"), St("drop", "A", "X", "written"),
                St("copy", "G", "Y", Src("A", "X", "prev")), St("adopt", "B", "Y", Src("A", "X", "prev")) >>
      [] F2Run = "dropC" ->
             \* a removed boundary, X written again after the drop, and a cancel
             << St("write", "A", "X", "k1"), St("remove", "A", "X", ""), St("drop", "A", "X", "removed"),
                St("write", "A", "X", "k1"), St("cancel", "A", "X", "") >>
      [] OTHER -> << >>

NoSlot == "no slot"
\* Records of one shape each, since TLC compares no record with a string.
NoSrc == [ref |-> "none", u |-> 0, path |-> "none"]
NoDropPlan == [path |-> "none", list |-> {}, through |-> 0]

VARIABLES
    vh,         \* vh[r]: ref r's committed versions, oldest first
    store,      \* store[x]: object x, [where: "seg", "batch" or "none", at: its LastModified mark, made]
    holds,      \* the holds placed, in order: [keeps: what existed at placement, state]
    hour2,      \* long marks passed
    faults2,    \* faults a behavior may still suffer
    next2,      \* the story's next statement
    att2,       \* att2[i]: idle, a validated push awaiting its step 7, or one whose answer was lost
    queue,      \* queue[i]: the candidate lists instance i holds in memory
    swept,      \* the versions <<r, u>> whose record evacuation resolved
    collected,  \* the directory removals whose markers' carried content the collection deleted
    dt,         \* the drop table: the repo's drop and its job's checkpoint
    jobLease,   \* the drop job's owner, or "none"
    bad2        \* ghost: a deletion broke the rule I-EVS-9 or I-EVS-15 names

f2vars == <<vh, store, holds, hour2, faults2, next2, att2, queue, swept, collected, dt, jobLease, bad2>>

NoDrop == [state |-> "none", ref |-> "none", u |-> 0, path |-> "none", list |-> {}, through |-> 0,
           seq |-> 0, ended |-> FALSE, waited |-> FALSE, phase |-> "none", cands |-> {}, marks |-> {},
           todo |-> {}, young |-> {}, vAt |-> 0, deleting |-> FALSE, why |-> "none"]

InitF2 ==
    /\ vh = [r \in F2Refs |-> << >>]
    /\ store = [x \in F2Ids |-> [where |-> "none", at |-> 0, made |-> FALSE]]
    /\ holds = << >>
    /\ hour2 = 0
    /\ faults2 = F2MaxFaults
    /\ next2 = 1
    /\ att2 = [i \in Instances |-> [stage |-> "idle"]]
    /\ queue = [i \in Instances |-> {}]
    /\ swept = {}
    /\ collected = {}
    /\ dt = NoDrop
    /\ jobLease = "none"
    /\ bad2 = FALSE

\* The versions of the run, as <<r, u>>.
F2Versions == UNION {{<<r, u>> : u \in 1..Len(vh[r])} : r \in F2Refs}

F2Touch(r, u, p) == \E c \in vh[r][u].changes : c.path = p

\* p's lineage on r through ref version n, and its newest version there, 0 if none.
F2Lin(r, p, n) == {u \in 1..n : F2Touch(r, u, p)}

F2Last(r, p, n) ==
    IF F2Lin(r, p, n) = {} THEN 0 ELSE CHOOSE u \in F2Lin(r, p, n) : \A x \in F2Lin(r, p, n) : x <= u

F2Chg(r, u, p) == CHOOSE c \in vh[r][u].changes : c.path = p

\* p's newest change through n, which only a caller that knows p has one evaluates.
F2NewestChg(r, p, n) == F2Chg(r, F2Last(r, p, n), p)

\* p is written through n: its newest version writes it.
F2Written(r, p, n) == F2Last(r, p, n) # 0 /\ F2NewestChg(r, p, n).op = "write"

\* What a change names: its locators' ids, and its slot.
CIds(c) == {l.id : l \in c.locs} \cup (IF c.slot = NoSlot THEN {} ELSE {c.slot})

KindIds(c, kinds) == {l.id : l \in {y \in c.locs : y.kind \in kinds}}

\* The purge's part of a versionless version: its kind-5 and staged segments and its slot.
VlIds(c) == IF c.vl THEN KindIds(c, {"k5", "staged"}) \cup (IF c.slot = NoSlot THEN {} ELSE {c.slot}) ELSE {}

F2Present(x) == store[x].where # "none"

\* A version of p replaced by a later one, and that replacement past the readers' allowance.
F2Replaced(r, u, p) == \E u2 \in (u + 1)..Len(vh[r]) : F2Touch(r, u2, p)

F2ReplacedAged(r, u, p) ==
    LET later == {u2 \in (u + 1)..Len(vh[r]) : F2Touch(r, u2, p)}
    IN  later # {} /\ vh[r][CHOOSE u2 \in later : \A x \in later : u2 <= x].aged

RECURSIVE F2SumLen(_)
F2SumLen(refs) == IF refs = {} THEN 0
                  ELSE LET r == CHOOSE x \in refs : TRUE IN Len(vh[r]) + F2SumLen(refs \ {r})

\* Versions committed over every ref: a commit's place in one order of them all.
F2Total == F2SumLen(F2Refs)

\* The drop lists the version, and has executed: its job reached its deletes.
F2Listed(r, u, p) == dt.state # "none" /\ r = dt.ref /\ p = dt.path /\ u \in dt.list
F2Executed == dt.deleting \/ dt.state \in {"executing", "done", "held"}

\* What every live version names: one no executing, held or done drop lists (11.13's mark).
F2LiveIds ==
    UNION {UNION {CIds(c) : c \in {y \in vh[v[1]][v[2]].changes :
                                     y.op = "write" /\ ~(F2Executed /\ F2Listed(v[1], v[2], y.path))}} :
           v \in F2Versions}

\* What the holds every 5 s cache shows keep: what existed at their placement.
F2HoldKept == UNION {holds[h].keeps : h \in {x \in DOMAIN holds : holds[x].state = "visible"}}

F2HoldStands == \E h \in DOMAIN holds : holds[h].state \in {"placed", "visible"}

\* The lowest unused id of each kind, "none" when none is left.
F2FreshSeg == IF \E x \in F2Segs : ~store[x].made THEN CHOOSE x \in F2Segs : ~store[x].made ELSE "none"
F2FreshSlot == IF \E x \in F2Slots : ~store[x].made THEN CHOOSE x \in F2Slots : ~store[x].made ELSE "none"

Loc(x, kind) == [id |-> x, kind |-> kind]

Chg(p, op, vl, locs, fslot, src) ==
    [path |-> p, op |-> op, vl |-> vl, locs |-> locs, slot |-> fslot, listed |-> TRUE, src |-> src]

Plan(ok, chgs, objs) == [ok |-> ok, chgs |-> chgs, objs |-> objs, drop |-> NoDropPlan, cancel |-> FALSE]

\* The source version a copy or an adopt names, through the head of its ref: 0 if none.
F2SrcAt(s) ==
    LET lin == F2Lin(s.ref, s.path, Len(vh[s.ref]))
        newest == F2Last(s.ref, s.path, Len(vh[s.ref]))
        older == lin \ {newest}
    IN  CASE lin = {} -> 0
          [] s.at = "newest" -> newest
          [] older = {} -> 0
          [] OTHER -> CHOOSE u \in older : \A x \in older : x <= u

\* 5h's citation fence: from a DROP's commit, no push cites a version it lists as a base, a deleted
\* path or a reuse source; a cancel lifts nothing.
F2Fenced(r, u, p) == F2Listed(r, u, p) /\ Twin # "DropNoFence"

\* A write's content, from p's newest version through n.
F2WritePlan(r, p, n, kind) ==
    LET has == F2Written(r, p, n)
        prev == F2NewestChg(r, p, n)
        fseg == F2FreshSeg
        fslot == F2FreshSlot
    IN  CASE kind = "dir" ->
                 Plan(TRUE, {Chg(p, "write", FALSE, {}, NoSlot, NoSrc)}, {})
          [] kind = "k1" ->
                 Plan(fseg # "none", {Chg(p, "write", FALSE, {Loc(fseg, "k1")}, NoSlot, NoSrc)}, {<<fseg, "seg">>})
          [] kind = "k1slot" ->
                 Plan(fseg # "none" /\ fslot # "none", {Chg(p, "write", FALSE, {Loc(fseg, "k1")}, fslot, NoSrc)},
                      {<<fseg, "seg">>, <<fslot, "seg">>})
          [] kind \in {"k5", "staged", "rekey"} ->
                 \* a slot-keyed repo keeps a versionless path's one key in a slot its versions reuse
                 LET keep == has /\ prev.vl /\ prev.slot # NoSlot /\ kind # "rekey"
                     vslot == IF F2Slots = {} THEN NoSlot ELSE IF keep THEN prev.slot ELSE fslot
                     newSlot == F2Slots # {} /\ ~keep
                     lk == IF kind = "staged" THEN "staged" ELSE "k5"
                 IN  Plan(fseg # "none" /\ vslot # "none" /\ r \in F2FileRefs,
                          {Chg(p, "write", TRUE, {Loc(fseg, lk)}, vslot, NoSrc)},
                          {<<fseg, IF kind = "staged" THEN "batch" ELSE "seg">>} \cup
                          (IF newSlot THEN {<<vslot, "seg">>} ELSE {}))
          [] kind \in {"same", "on"} /\ ~has -> Plan(FALSE, {}, {})
          [] kind = "same" ->
                 \* kind-5 segments are cited in turn; a staged record is staged again, as a new segment
                 LET staged == KindIds(prev, {"staged"}) # {}
                     locs == {l \in prev.locs : l.kind # "staged"} \cup (IF staged THEN {Loc(fseg, "staged")} ELSE {})
                 IN  IF staged /\ fseg = "none" THEN Plan(FALSE, {}, {})
                     ELSE Plan(TRUE, {Chg(p, "write", prev.vl, locs, prev.slot, NoSrc)},
                               IF staged THEN {<<fseg, "batch">>} ELSE {})
          [] kind = "on" ->
                 IF ~prev.vl THEN Plan(FALSE, {}, {})
                 ELSE Plan(TRUE,
                           {Chg(p, "write", FALSE, {Loc(l.id, "k1") : l \in {y \in prev.locs : y.kind \in {"k5", "k1"}}},
                                prev.slot, NoSrc)},
                           {})
          [] OTHER -> Plan(FALSE, {}, {})

\* Steps 4 and 5 of a statement on the head of r at n: whether it passes, and what it changes and stores.
F2Plan(st, n) ==
    LET r == st.ref
        p == st.path
        has == F2Written(r, p, n)
        fseg == F2FreshSeg
    IN  CASE st.op = "write" -> F2WritePlan(r, p, n, st.arg)
          [] st.op = "rename" ->
                 LET q == st.arg
                     uq == F2Last(r, q, n)
                     qc == F2NewestChg(r, q, n)
                     staged == KindIds(qc, {"staged"}) # {}
                     locs == {l \in qc.locs : l.kind # "staged"} \cup (IF staged THEN {Loc(fseg, "staged")} ELSE {})
                 IN  IF ~F2Written(r, q, n) \/ has THEN Plan(FALSE, {}, {})
                     ELSE Plan(~F2Fenced(r, uq, q) /\ (staged => fseg # "none"),
                               {Chg(q, "remove", qc.vl, {}, NoSlot, NoSrc),
                                Chg(p, "write", qc.vl, locs, qc.slot, [ref |-> r, u |-> uq, path |-> q])},
                               IF staged THEN {<<fseg, "batch">>} ELSE {})
          [] st.op = "remove" ->
                 IF ~has THEN Plan(FALSE, {}, {})
                 ELSE Plan(TRUE, {Chg(p, "remove", F2NewestChg(r, p, n).vl, {}, NoSlot, NoSrc)}, {})
          [] st.op = "rmdir" ->
                 \* the client lists each versionless file below as a file removal, or the fold carries
                 \* what it names in the file's marker
                 LET below == {x \in F2Below : F2Written(r, x, n)}
                 IN  Plan(has,
                          {Chg(p, "remove", FALSE, {}, NoSlot, NoSrc)} \cup
                          {[Chg(x, "remove", F2NewestChg(r, x, n).vl, {}, NoSlot, NoSrc) EXCEPT
                                !.listed = (st.arg = "listed")] : x \in below},
                          {})
          [] st.op \in {"copy", "adopt"} ->
                 LET s == st.arg
                     u2 == F2SrcAt(s)
                     sc == F2Chg(s.ref, u2, s.path)
                     k1 == KindIds(sc, {"k1"})
                     x == CHOOSE y \in k1 : TRUE
                 IN  IF u2 = 0 THEN Plan(FALSE, {}, {})
                     ELSE IF sc.op # "write" \/ k1 = {} THEN Plan(FALSE, {}, {})
                     ELSE IF st.op = "copy"
                     \* a reuse cites the source's kind-1 content, never a kind-5 segment (a copy re-uploads)
                     THEN Plan(~F2Fenced(s.ref, u2, s.path),
                               {Chg(p, "write", FALSE, {Loc(l, "k1") : l \in k1}, sc.slot,
                                    [ref |-> s.ref, u |-> u2, path |-> s.path])},
                               {})
                     \* equal bytes over 23 h old get SEGMENT_STALE; absent ones are stored anew
                     ELSE IF F2Present(x) /\ hour2 - store[x].at >= ReuploadStaleAge
                     THEN Plan(FALSE, {}, {})
                     ELSE Plan(TRUE, {Chg(p, "write", FALSE, {Loc(x, "k1")}, NoSlot, NoSrc)},
                               IF F2Present(x) THEN {} ELSE {<<x, "seg">>})
          [] st.op = "drop" ->
                 \* VERSIONING for a versionless head; the list is the lineage below through_version, the
                 \* DROP's own write (1) or the standing removal (2)
                 LET lin == F2Lin(r, p, n)
                     last == F2Last(r, p, n)
                     written == st.arg = "written"
                 IN  IF r \notin F2FileRefs \/ dt.state # "none" \/ lin = {} THEN Plan(FALSE, {}, {})
                     ELSE IF F2NewestChg(r, p, n).vl \/ (written /\ (~has \/ fseg = "none")) \/ (~written /\ has)
                     THEN Plan(FALSE, {}, {})
                     ELSE [Plan(TRUE,
                                IF written THEN {Chg(p, "write", FALSE, {Loc(fseg, "k1")}, NoSlot, NoSrc)} ELSE {},
                                IF written THEN {<<fseg, "seg">>} ELSE {})
                           EXCEPT !.drop = [path |-> p, list |-> IF written THEN lin ELSE lin \ {last},
                                            through |-> IF written THEN n + 1 ELSE last]]
          [] st.op = "cancel" ->
                 \* DROP_STATE for a cancel of no pending drop, or past its window
                 [Plan(dt.state = "pending" /\ dt.ref = r /\ ~dt.ended, {}, {}) EXCEPT !.cancel = TRUE]
          [] OTHER -> Plan(FALSE, {}, {})

\* Step 5's candidates (11.13's purge row): the purge's part of each versionless version the push
\* replaces or lists, less all the push's versions name. A file below a removed directory that the push
\* did not list goes in its marker instead, for the collection.
F2Cands(r, n, chgs) ==
    (UNION {VlIds(F2NewestChg(r, c.path, n)) : c \in {y \in chgs : y.listed /\ F2Written(r, y.path, n)}})
    \ (UNION {CIds(c) : c \in chgs})

F2Marker(r, n, chgs) ==
    UNION {VlIds(F2NewestChg(r, c.path, n)) : c \in {y \in chgs : ~y.listed /\ F2Written(r, y.path, n)}}

F2Stored(objs) ==
    [x \in F2Ids |->
        IF \E o \in objs : o[1] = x
        THEN [where |-> (CHOOSE o \in objs : o[1] = x)[2], at |-> hour2, made |-> TRUE]
        ELSE store[x]]

\* A candidate list as the committing process queues it in memory.
F2Entry(v, rec) == [v |-> v, cands |-> rec.cands, paths |-> {c.path : c \in rec.changes}, aged |-> FALSE]

F2Validate(i) ==
    LET st == F2Story[next2]
        r == st.ref
        n == Len(vh[r])
        plan == F2Plan(st, n)
        rec == [push |-> next2, changes |-> plan.chgs, cands |-> F2Cands(r, n, plan.chgs),
                marker |-> F2Marker(r, n, plan.chgs), at |-> hour2, aged |-> FALSE, drop |-> plan.drop,
                cancel |-> plan.cancel, vseq |-> F2Total]
    IN  /\ att2[i].stage = "idle"
        /\ next2 <= Len(F2Story)
        /\ next2' = next2 + 1
        /\ IF plan.ok
           THEN /\ att2' = [att2 EXCEPT ![i] = [stage |-> "validated", ref |-> r, hl |-> n, rec |-> rec]]
                /\ store' = F2Stored(plan.objs)
                \* a twin: candidates queued before the push is seen committed, and purged with no reread
                /\ queue' = IF Twin = "PurgeUnseen" /\ rec.cands # {}
                            THEN [queue EXCEPT ![i] = @ \cup {F2Entry(<<r, n + 1>>, rec)}]
                            ELSE queue
           ELSE UNCHANGED <<att2, store, queue>>
        /\ UNCHANGED <<vh, holds, hour2, faults2, swept, collected, dt, jobLease, bad2>>

\* Step 7 lands. Its process queues the candidates once it sees the commit: its own 200, or a reread.
F2Put(i) ==
    LET a == att2[i]
        r == a.ref
        u == Len(vh[r]) + 1
        rec == [a.rec EXCEPT !.at = hour2]
        entry == F2Entry(<<r, u>>, rec)
    IN  /\ a.stage = "validated"
        /\ Len(vh[r]) = a.hl
        /\ vh' = [vh EXCEPT ![r] = Append(@, rec)]
        /\ dt' = CASE rec.drop.path # "none" ->
                          [NoDrop EXCEPT !.state = "pending", !.ref = r, !.u = u, !.path = rec.drop.path,
                                         !.list = rec.drop.list, !.through = rec.drop.through, !.seq = F2Total + 1]
                   [] rec.cancel /\ dt.state = "pending" -> [dt EXCEPT !.state = "cancelled"]
                   [] OTHER -> dt
        /\ \/ /\ att2' = [att2 EXCEPT ![i] = [stage |-> "idle"]]
              /\ queue' = IF rec.cands = {} \/ Twin = "PurgeUnseen" THEN queue
                          ELSE [queue EXCEPT ![i] = @ \cup {entry}]
              /\ UNCHANGED faults2
           \/ /\ faults2 > 0
              /\ faults2' = faults2 - 1
              /\ att2' = [att2 EXCEPT ![i] = [stage |-> "lost", entry |-> entry]]
              /\ UNCHANGED queue
        /\ UNCHANGED <<store, holds, hour2, next2, swept, collected, jobLease, bad2>>

\* 412: the head moved since step 4. What the push uploaded is the M2 part's orphan.
F2PutFails(i) ==
    /\ att2[i].stage = "validated"
    /\ Len(vh[att2[i].ref]) # att2[i].hl
    /\ att2' = [att2 EXCEPT ![i] = [stage |-> "idle"]]
    /\ UNCHANGED <<vh, store, holds, hour2, faults2, next2, queue, swept, collected, dt, jobLease, bad2>>

\* An answer lost, then a reread showing the commit.
F2Reread(i) ==
    /\ att2[i].stage = "lost"
    /\ queue' = IF att2[i].entry.cands = {} \/ Twin = "PurgeUnseen" THEN queue
                ELSE [queue EXCEPT ![i] = @ \cup {att2[i].entry}]
    /\ att2' = [att2 EXCEPT ![i] = [stage |-> "idle"]]
    /\ UNCHANGED <<vh, store, holds, hour2, faults2, next2, swept, collected, dt, jobLease, bad2>>

\* A crash loses the process's queue, which the sweep then covers.
F2Crash(i) ==
    /\ faults2 > 0
    /\ att2[i].stage # "idle" \/ queue[i] # {}
    /\ faults2' = faults2 - 1
    /\ att2' = [att2 EXCEPT ![i] = [stage |-> "idle"]]
    /\ queue' = [queue EXCEPT ![i] = {}]
    /\ UNCHANGED <<vh, store, holds, hour2, next2, swept, collected, dt, jobLease, bad2>>

\* I-EVS-9 at a purge's DELETE: every version naming x is versionless, names it as the purge's, and was
\* replaced by a version past the readers' allowance, and no hold the deleting process saw keeps it.
F2PurgeOk(x, seen) ==
    /\ x \notin seen
    /\ \A v \in F2Versions : \A c \in vh[v[1]][v[2]].changes :
           x \in CIds(c) => /\ c.vl
                            /\ x \in VlIds(c)
                            /\ F2ReplacedAged(v[1], v[2], c.path)

\* 60 s after it queued a list, the committing process rereads the replaced paths' newest versions
\* and hold/ (cached at most 5 s), and DELETEs each candidate at seg/ that neither keeps; a staged one
\* still in its batch is evacuation's, and a DELETE of what is gone is 204. A hold that reaches the
\* cache after the reread stops nothing already issued (FS-69), so the reread and its DELETEs are one
\* step; a crash before it, or a clock turning unsure, leaves the list to the sweep.
F2Purge(i, q) ==
    LET r == q.v[1]
        newest == UNION {CIds(F2NewestChg(r, p, Len(vh[r]))) : p \in {y \in q.paths : F2Written(r, y, Len(vh[r]))}}
        seen == F2HoldKept
        keep == (IF Twin = "PurgeUnseen" THEN {} ELSE newest) \cup (IF Twin = "PurgeIgnoresHold" THEN {} ELSE seen)
        ids == {x \in q.cands : x \notin keep /\ store[x].where = "seg"}
    IN  /\ q \in queue[i]
        /\ q.aged \/ Twin = "PurgeNoAllowance"
        /\ store' = [x \in F2Ids |-> IF x \in ids THEN [store[x] EXCEPT !.where = "none"] ELSE store[x]]
        /\ bad2' = (bad2 \/ \E x \in ids : ~F2PurgeOk(x, seen))
        /\ queue' = [queue EXCEPT ![i] = @ \ {q}]
        /\ UNCHANGED <<vh, holds, hour2, faults2, next2, att2, swept, collected, dt, jobLease>>

\* The newest versions of the paths a version touched name these.
F2NewestOf(r, u) ==
    UNION {CIds(F2NewestChg(r, c.path, Len(vh[r]))) : c \in {y \in vh[r][u].changes : F2Written(r, y.path, Len(vh[r]))}}

\* Evacuation of a committed record 25 h on (11.13): each staged segment it introduced goes to seg/
\* while its version is its path's newest, was replaced under 60 s ago or a hold keeps it, and is
\* dropped otherwise; the sweep DELETEs each of its candidates at seg/ that the replaced paths'
\* newest versions do not name and no hold keeps.
F2Evacuate(r, u) ==
    LET rec == vh[r][u]
        kept == F2HoldKept
        stagedChgs == {c \in rec.changes : KindIds(c, {"staged"}) # {}}
        stagedIds == UNION {KindIds(c, {"staged"}) : c \in stagedChgs}
        retained(x) == LET c == CHOOSE y \in stagedChgs : x \in KindIds(y, {"staged"})
                       IN  \/ F2Last(r, c.path, Len(vh[r])) = u
                           \/ ~F2ReplacedAged(r, u, c.path)
                           \/ x \in kept
        written == {x \in stagedIds : store[x].where = "batch" /\ retained(x) /\ Twin # "EvacDropsNewest"}
        dropped == {x \in stagedIds : store[x].where = "batch"} \ written
        newest == F2NewestOf(r, u)
        swept1 == {x \in rec.cands : x \notin newest /\ x \notin kept /\ store[x].where = "seg"}
    IN  /\ <<r, u>> \notin swept
        /\ hour2 - rec.at >= EvacuateAge
        /\ store' = [x \in F2Ids |->
               CASE x \in written -> [store[x] EXCEPT !.where = "seg", !.at = hour2]
                 [] x \in dropped \cup swept1 -> [store[x] EXCEPT !.where = "none"]
                 [] OTHER -> store[x]]
        /\ bad2' = (bad2 \/ \E x \in dropped \cup swept1 : ~F2PurgeOk(x, kept))
        /\ swept' = swept \cup {<<r, u>>}
        /\ UNCHANGED <<vh, holds, hour2, faults2, next2, att2, queue, collected, dt, jobLease>>

\* Once a hold ends, one pass rereads the versions flagged since before its placement and deletes what
\* it kept.
F2Resweep(r, u) ==
    LET kept == F2HoldKept
        newest == F2NewestOf(r, u)
        ids == {x \in vh[r][u].cands : x \notin newest /\ x \notin kept /\ store[x].where = "seg"}
    IN  /\ <<r, u>> \in swept
        /\ \E h \in DOMAIN holds : holds[h].state = "ended"
        /\ ids # {}
        /\ store' = [x \in F2Ids |-> IF x \in ids THEN [store[x] EXCEPT !.where = "none"] ELSE store[x]]
        /\ bad2' = (bad2 \/ \E x \in ids : ~F2PurgeOk(x, kept))
        /\ UNCHANGED <<vh, holds, hour2, faults2, next2, att2, queue, swept, collected, dt, jobLease>>

\* 11.7's collection: once the removal's marker is past the horizon, it deletes the kind-5 segments
\* and slot the marker carries that no hold keeps, leaving the marker while a hold kept part of it.
F2Collect(r, u) ==
    LET kept == F2HoldKept
        carried == {x \in vh[r][u].marker : store[x].where = "seg"}
        ids == carried \ kept
    IN  /\ <<r, u>> \notin collected
        /\ vh[r][u].marker # {}
        /\ vh[r][u].aged
        /\ store' = [x \in F2Ids |-> IF x \in ids THEN [store[x] EXCEPT !.where = "none"] ELSE store[x]]
        /\ bad2' = (bad2 \/ \E x \in ids : ~F2PurgeOk(x, kept))
        /\ collected' = IF carried \cap kept = {} THEN collected \cup {<<r, u>>} ELSE collected
        /\ UNCHANGED <<vh, holds, hour2, faults2, next2, att2, queue, swept, dt, jobLease>>

\* A retry of the push that introduced a kind-5 segment uploads it again while its statement lasts,
\* racing the purge's DELETE; the sweep, later, removes it.
F2Reupload(x) ==
    /\ ~F2Present(x)
    /\ \E v \in F2Versions : \E c \in vh[v[1]][v[2]].changes :
           /\ x \in KindIds(c, {"k5"})
           /\ \A u2 \in 1..(v[2] - 1) : \A c2 \in vh[v[1]][u2].changes : x \notin CIds(c2)
           /\ hour2 < vh[v[1]][v[2]].at + StatementMarks
    /\ store' = [store EXCEPT ![x] = [@ EXCEPT !.where = "seg", !.at = hour2]]
    /\ UNCHANGED <<vh, holds, hour2, faults2, next2, att2, queue, swept, collected, dt, jobLease, bad2>>

\* §21.9's holds: one keeps what existed at its placement, from when every 5 s cache shows it.
F2HoldPlace ==
    /\ Len(holds) < F2MaxHolds
    /\ holds' = Append(holds, [keeps |-> {x \in F2Ids : F2Present(x)}, state |-> "placed"])
    /\ UNCHANGED <<vh, store, hour2, faults2, next2, att2, queue, swept, collected, dt, jobLease, bad2>>

F2HoldVisible(h) ==
    /\ holds[h].state = "placed"
    /\ holds' = [holds EXCEPT ![h].state = "visible"]
    /\ UNCHANGED <<vh, store, hour2, faults2, next2, att2, queue, swept, collected, dt, jobLease, bad2>>

F2HoldEnd(h) ==
    /\ holds[h].state = "visible"
    /\ holds' = [holds EXCEPT ![h].state = "ended"]
    /\ UNCHANGED <<vh, store, hour2, faults2, next2, att2, queue, swept, collected, dt, jobLease, bad2>>

\* A minute passes: past the readers' allowance, past every 5 s cache, past every step 7's deadline,
\* and past a drop's 25 min once its window ended.
F2Aged ==
    /\ vh' = [r \in F2Refs |-> [u \in 1..Len(vh[r]) |-> [vh[r][u] EXCEPT !.aged = TRUE]]]
    /\ queue' = [i \in Instances |-> {[q EXCEPT !.aged = TRUE] : q \in queue[i]}]
    /\ holds' = [h \in DOMAIN holds |-> IF holds[h].state = "placed" THEN [holds[h] EXCEPT !.state = "visible"]
                                         ELSE holds[h]]
    /\ att2' = [i \in Instances |-> IF att2[i].stage = "validated" THEN [stage |-> "idle"] ELSE att2[i]]
    /\ dt' = IF dt.ended THEN [dt EXCEPT !.waited = TRUE] ELSE dt

F2Minute ==
    /\ \/ \E v \in F2Versions : ~vh[v[1]][v[2]].aged
       \/ \E i \in Instances : (\E q \in queue[i] : ~q.aged) \/ att2[i].stage = "validated"
       \/ \E h \in DOMAIN holds : holds[h].state = "placed"
       \/ dt.ended /\ ~dt.waited
    /\ F2Aged
    /\ UNCHANGED <<store, hour2, faults2, next2, swept, collected, jobLease, bad2>>

F2Tick ==
    /\ hour2 < F2MaxHour
    /\ hour2' = hour2 + 1
    /\ F2Aged
    /\ UNCHANGED <<store, faults2, next2, swept, collected, jobLease, bad2>>

(* The drop job (11.13): one a repo, by jobLease; each phase a CAS of its checkpoint in drops/. *)

F2DropChanged == UNCHANGED <<vh, store, holds, hour2, faults2, next2, att2, queue, swept, collected, bad2>>

\* The window ends: not_before_ms. evs takes a cancel only 60 s before it, so one in flight lands first.
F2WindowEnds ==
    /\ dt.state = "pending"
    /\ ~dt.ended
    /\ \A i \in Instances : ~(att2[i].stage = "validated" /\ att2[i].rec.cancel)
    /\ dt' = [dt EXCEPT !.ended = TRUE]
    /\ UNCHANGED jobLease
    /\ F2DropChanged

\* An instance takes the job when no jobLease is live; a crash or a lapsed jobLease stops its owner, whose
\* next CAS would fail, and which issues nothing in the jobLease's last second.
F2JobTake(k) ==
    /\ jobLease = "none"
    /\ dt.state \in {"pending", "executing", "held"}
    /\ jobLease' = k
    /\ UNCHANGED dt
    /\ F2DropChanged

F2JobLapse ==
    /\ jobLease # "none"
    /\ faults2 > 0
    /\ jobLease' = "none"
    /\ faults2' = faults2 - 1
    /\ UNCHANGED <<vh, store, holds, hour2, next2, att2, queue, swept, collected, dt, bad2>>

\* pending -> executing 25 min past the window; a committed cancel made it cancelled already.
F2DropStart(k) ==
    /\ jobLease = k
    /\ dt.state = "pending"
    /\ dt.waited
    /\ dt' = [dt EXCEPT !.state = "executing", !.phase = "resolve"]
    /\ UNCHANGED jobLease
    /\ F2DropChanged

\* The list must equal the lineage below through_version, else {mismatch}; the candidates are what
\* listed versions name through kind-1 locators or as a versioned version's slot, kind-5 and staged
\* content staying the purge's.
F2DropResolve(k) ==
    LET listed == {F2Chg(dt.ref, u, dt.path) : u \in dt.list}
        cands == UNION {KindIds(c, {"k1"}) \cup (IF c.slot # NoSlot /\ ~c.vl THEN {c.slot} ELSE {}) : c \in listed}
    IN  /\ jobLease = k
        /\ dt.state = "executing"
        /\ dt.phase = "resolve"
        /\ dt' = IF dt.list = F2Lin(dt.ref, dt.path, dt.through - 1)
                 THEN [dt EXCEPT !.phase = "mark", !.cands = cands]
                 ELSE [dt EXCEPT !.state = "refused", !.why = "mismatch"]
        /\ UNCHANGED jobLease
        /\ F2DropChanged

\* Mark at a snapshot after the fence: each live version marks the candidates it names.
F2DropMark(k) ==
    /\ jobLease = k
    /\ dt.state = "executing"
    /\ dt.phase = "mark"
    /\ dt' = [dt EXCEPT !.marks = @ \cup (dt.cands \cap F2LiveIds), !.phase = "verify"]
    /\ UNCHANGED jobLease
    /\ F2DropChanged

\* Verify at a later snapshot, apart from the mark: an unmarked candidate a live version names refuses
\* the job {verify}.
F2DropVerify(k) ==
    LET d == dt.cands \ dt.marks
    IN  /\ jobLease = k
        /\ dt.state = "executing"
        /\ dt.phase = "verify"
        /\ dt' = IF d \cap F2LiveIds # {} THEN [dt EXCEPT !.state = "refused", !.why = "verify"]
                 ELSE [dt EXCEPT !.phase = "delete", !.todo = d, !.vAt = hour2, !.deleting = TRUE]
        /\ UNCHANGED jobLease
        /\ F2DropChanged

\* I-EVS-15 at a drop's DELETE: every version naming x is listed by the executed drop, no hold the job
\* saw keeps it, and it is over 25 h old.
F2DropOk(x) ==
    /\ x \notin F2HoldKept
    /\ hour2 - store[x].at >= OrphanAge
    /\ \A v \in F2Versions : \A c \in vh[v[1]][v[2]].changes :
           x \in CIds(c) /\ c.op = "write" => F2Listed(v[1], v[2], c.path)

\* A batch of D's DELETEs: hold/ reread first (a covering hold moves the rest of D to held), then per
\* id a HEAD (404: done; under 25 h before V's read: young, for a later round) and the DELETE. The
\* cursor advances only past answered ids, so a crash mid-batch redoes the rest, each HEAD of a deleted
\* id finding 404: one step here.
F2DropDelete(k) ==
    LET d == dt.todo
        held == d \cap F2HoldKept # {} /\ Twin # "DropIgnoresHold"
        young == {x \in d : F2Present(x) /\ dt.vAt - store[x].at < OrphanAge /\ Twin # "DropNoAgeCheck"}
        ids == {x \in d : F2Present(x)} \ young
    IN  /\ jobLease = k
        /\ dt.state = "executing"
        /\ dt.phase = "delete"
        /\ d # {}
        /\ IF held
           THEN /\ dt' = [dt EXCEPT !.state = "held"]
                /\ UNCHANGED <<store, bad2>>
           ELSE /\ store' = [x \in F2Ids |-> IF x \in ids THEN [store[x] EXCEPT !.where = "none"] ELSE store[x]]
                /\ bad2' = (bad2 \/ \E x \in ids : ~F2DropOk(x))
                /\ dt' = [dt EXCEPT !.todo = {}, !.young = @ \cup young]
        /\ UNCHANGED <<vh, holds, hour2, faults2, next2, att2, queue, swept, collected, jobLease>>

\* Young candidates wait for a later round, whose mark and verify read the versions since.
F2DropRound(k) ==
    /\ jobLease = k
    /\ dt.state = "executing"
    /\ dt.phase = "delete"
    /\ dt.todo = {}
    /\ dt.young # {}
    /\ hour2 > dt.vAt
    /\ dt' = [dt EXCEPT !.cands = dt.young, !.young = {}, !.phase = "mark"]
    /\ UNCHANGED jobLease
    /\ F2DropChanged

F2DropDone(k) ==
    /\ jobLease = k
    /\ dt.state = "executing"
    /\ dt.phase = "delete"
    /\ dt.todo = {}
    /\ dt.young = {}
    /\ dt' = [dt EXCEPT !.state = "done"]
    /\ UNCHANGED jobLease
    /\ F2DropChanged

\* Once every covering hold ends, an incremental mark and verify, then the deletes held.
F2DropResume(k) ==
    /\ jobLease = k
    /\ dt.state = "held"
    /\ ~F2HoldStands
    /\ dt' = [dt EXCEPT !.state = "executing", !.phase = "mark", !.cands = dt.todo \cup dt.young,
                        !.todo = {}, !.young = {}]
    /\ UNCHANGED jobLease
    /\ F2DropChanged

F2JobStep(k) ==
    \/ F2DropStart(k)
    \/ F2DropResolve(k)
    \/ F2DropMark(k)
    \/ F2DropVerify(k)
    \/ F2DropDelete(k)
    \/ F2DropRound(k)
    \/ F2DropDone(k)
    \/ F2DropResume(k)

NextF2 ==
    \/ \E i \in Instances :
           \/ F2Validate(i)
           \/ F2Put(i)
           \/ F2PutFails(i)
           \/ F2Reread(i)
           \/ F2Crash(i)
           \/ \E q \in queue[i] : F2Purge(i, q)
           \/ F2JobTake(i)
           \/ F2JobStep(i)
    \/ \E v \in F2Versions : F2Evacuate(v[1], v[2]) \/ F2Resweep(v[1], v[2]) \/ F2Collect(v[1], v[2])
    \/ \E x \in F2Segs : F2Reupload(x)
    \/ F2HoldPlace
    \/ \E h \in DOMAIN holds : F2HoldVisible(h) \/ F2HoldEnd(h)
    \/ F2JobLapse
    \/ F2WindowEnds
    \/ F2Minute
    \/ F2Tick

Init == InitM2 /\ InitF2

\* The M2 part, or an M10 run, each holding the other's variables at their start.
Next ==
    \/ F2Mode = "off" /\ NextM2 /\ UNCHANGED f2vars
    \/ F2Mode # "off" /\ NextF2 /\ UNCHANGED vars

allVars == <<vars, f2vars>>

Spec == Init /\ [][Next]_allVars

(***************************************************************************)
(* What TLC checks.                                                         *)
(***************************************************************************)

\* A shred takes everything, and FI-2 lets it take what it took.
Live == repo.state \notin {"shredding", "shredded"}

\* A record is at its place, or in a container of it that a pidx/ entry names.
Retrievable(place) ==
    \/ \E rec \in batch : rec.place = place
    \/ \E c \in pack : c.id = place /\ c \in pidx

Commits == {<<r, u>> \in Refs \X (1..MaxVersion) : u <= Committed(r)}

\* I-EVS-1, FI-1: a committed head's dependency closure stays readable.
ClosureHolds ==
    Live =>
    \A rv \in Commits :
        LET r == rv[1]
            u == rv[2]
            c == hist[r][u]
        IN  /\ \A place \in c.places : Retrievable(place)
            /\ c.seg # NoSegment => seg[c.seg].stored
            /\ c.newSlot => slot[c.push] = "stored"
            /\ Claimed(c.gen)
            /\ u < head[r].winFrom => (u \div FoldSize) \in log[r]

\* I-EVS-2: no answer deletes anything, so a slot goes only with a dead push.
AnswersDeleteNothing ==
    \A P \in PushIds : slot[P] = "deleted" => P \in reclaimed \/ ~Live

\* I-EVS-3, FI-2: one commit, the original version on every retry, and a refusal stays true.
OutcomesHold ==
    \A P \in 1..pushCount :
        LET r == push[P].ref
            versions == CommitVersions(r, P)
        IN  /\ Cardinality(versions) <= 1
            /\ answers[P].ok \subseteq versions
            /\ answers[P].refused /\ Live => versions = {}
            /\ P \in reclaimed => versions = {}

\* 11.6's read rule on the store as it stands.
BestEntry(r, p) ==
    LET h == head[r]
        cur == idx[r][h.pathEpoch][p]
        pre == IF Prefixes(p) = {} THEN Never ELSE idx[r][h.pathEpoch][Dir]
    IN  IF h.sources = {} THEN cur
        ELSE Settled(cur, pre, idx[r][CHOOSE x \in h.sources : TRUE][p])

\* I-EVS-4, I-EVS-6, FI-6: a path's newest committed version is in its entry or the head window, and
\* no delta leaves the window before its name table holds it.
NewestFound ==
    Live =>
    \A r \in Refs :
        LET h == head[r]
        IN  /\ h.foldedThrough + 1 >= h.winFrom
            /\ \A p \in Paths :
                   SameRead(Replay(r, p, BestEntry(r, p), h.foldedThrough, h.version),
                            Truth(r, p, h.version))

\* I-EVS-4: only committed versions reach an entry.
EntriesCommitted ==
    Live =>
    \A r \in Refs, e \in 1..MaxGeneration, p \in Paths :
        idx[r][e][p].at <= Committed(r)

\* I-EVS-5: no segment GC deleted is named by any commit, then or later.
GcSafe == \A s \in gcDecided : ~Introduced(s)

\* I-EVS-8, FI-15, at the newest commit of each ref, which covers every commit by induction.
CasAt(r, u) ==
    LET c == hist[r][u]
    IN  \A x \in c.changes :
            LET before == Truth(r, x.path, u - 1)
            IN  CASE x.op = "create" ->
                         /\ ~Exists(before)
                         /\ x.ver > before.ver
                         /\ x.ver = Max(c.base, before.ver) + 1
                  [] x.op \in {"write", "remove"} ->
                         /\ Exists(before)
                         /\ x.base = before.ver
                         /\ x.ver = before.ver + 1
                  [] OTHER -> TRUE

DirectoryChecksAt(r, u) ==
    LET c == hist[r][u]
    IN  \A x \in c.changes :
            /\ (x.path = Dir /\ x.op = "remove") => ~DirDeltaIn(r, c.base, u - 1)
            /\ (x.path = Dir /\ x.op \in {"add", "drop"}) => ~DirRemovedIn(r, c.base, u - 1)

FileCas ==
    \A r \in Refs :
        Committed(r) > 0 =>
        /\ CasAt(r, Committed(r))
        /\ DirectoryChecksAt(r, Committed(r))
        /\ ~GitMode(r) => hist[r][Committed(r)].base >= Committed(r) - 1 - BaseRange

\* Per-path version monotonicity, across collections and path-epoch copies.
VersionsRise ==
    \A r \in Refs, p \in Paths :
        Committed(r) > 0 =>
        LET u == Committed(r)
            before == Truth(r, p, u - 1)
            after == Truth(r, p, u)
        IN  /\ after.ver >= before.ver
            /\ after.at = u => after.ver > before.ver

\* FI-3, at the newest commit: pins never fall, and the pins passed the gate on the state validated.
PinsHold ==
    Live =>
    \A r \in Refs :
        Committed(r) > 0 =>
        LET u == Committed(r)
            c == hist[r][u]
        IN  /\ u > 1 => c.gen >= hist[r][u - 1].gen /\ c.auth >= hist[r][u - 1].auth
            /\ GatePasses(c.gen, c.view)
            /\ c.repoSeen = "active"

\* FI-4: one claim per generation, whichever path raised it, and epochs never fall.
OneLadder ==
    Live =>
    /\ \A rv \in Commits : hist[rv[1]][rv[2]].genBy = gen[hist[rv[1]][rv[2]].gen].by
    /\ \A k \in 1..(Len(epoch) - 1) : epoch[k].gen <= epoch[k + 1].gen

\* FI-5: restore and shred have one winner, and a shred's objects never return.
LifecycleHolds ==
    /\ repo.state \in {"active", "deleted"} => shred.stage = "idle"
    /\ repo.state = "shredded" =>
           /\ \A r \in Refs : head[r].version = 0
           /\ \A s \in Segments : ~seg[s].stored
           /\ \A P \in PushIds : slot[P] # "stored"

\* FI-9: a git-mode commit lands on its tip, and an acknowledged push is the one the version names.
GitTip ==
    /\ Committed(GitRef) > 0 =>
           hist[GitRef][Committed(GitRef)].base = Committed(GitRef) - 1
    /\ \A P \in 1..pushCount :
           \A u \in answers[P].ok : hist[push[P].ref][u].push = P

\* FI-15's reads: a head read or listing served each path's newest version through its v, none newer.
ReadsServeNewest == ~readBad

TypeOk ==
    /\ hour \in 0..MaxHour
    /\ \A r \in Refs : head[r].version <= MaxVersion
    /\ \A r \in Refs : head[r].version = Committed(r) \/ ~Live

(***************************************************************************)
(* What TLC checks of an M10 run.                                           *)
(***************************************************************************)

\* I-EVS-1, FI-1: every committed version keeps all it names, but what the purge may take from a
\* replaced versionless version and an executed drop from the versions it lists; so every path's
\* newest version keeps all its content.
F2Closure ==
    \A v \in F2Versions : \A c \in vh[v[1]][v[2]].changes :
        c.op = "write" =>
        \A x \in CIds(c) :
            \/ F2Present(x)
            \/ x \in VlIds(c) /\ F2Replaced(v[1], v[2], c.path)
            \/ F2Executed /\ F2Listed(v[1], v[2], c.path)

\* I-EVS-9 and FI-16 at each purge's DELETE, I-EVS-15 and FI-27 at each drop's, as the ghost bad2
\* records them: what every version naming the object is, the holds the deleting process saw, and
\* the object's age.
F2DeletesKeepRules == ~bad2

F2NamedEarlier(x, r, u) == \E u2 \in 1..(u - 1) : \E c2 \in vh[r][u2].changes : x \in CIds(c2)

F2NamedOnOtherRef(x, r) ==
    \E v \in F2Versions : v[1] # r /\ \E c2 \in vh[v[1]][v[2]].changes : x \in CIds(c2)

\* The version a change continues: its rename source's, or its path's previous one.
F2Pred(r, u, c) ==
    IF c.src.ref = r /\ c.src.u < u /\ F2Touch(r, u, c.src.path) THEN {F2Chg(r, c.src.u, c.src.path)}
    ELSE IF F2Last(r, c.path, u - 1) # 0 THEN {F2Chg(r, F2Last(r, c.path, u - 1), c.path)}
    ELSE {}

\* Introduced here, or named by the version this one continues, and never on another ref.
F2InTurn(x, r, u, c) ==
    /\ ~F2NamedOnOtherRef(x, r)
    /\ ~F2NamedEarlier(x, r, u) \/ \E pc \in F2Pred(r, u, c) : x \in CIds(pc)

\* I-EVS-10, FI-17: a kind-5 segment, or a versionless path's slot, is named only by the version that
\* introduced it and then, in turn, by its path's next versions on that ref or a rename target in the
\* push removing the path; a staged segment only by its introducing version; and no versionless
\* version commits on a git-mode ref.
F2Cites ==
    \A v \in F2Versions : \A c \in vh[v[1]][v[2]].changes :
        /\ c.vl => v[1] \in F2FileRefs
        /\ \A x \in KindIds(c, {"k5"}) : F2InTurn(x, v[1], v[2], c)
        /\ c.vl /\ c.slot # NoSlot => F2InTurn(c.slot, v[1], v[2], c)
        /\ \A x \in KindIds(c, {"staged"}) :
               \A w \in F2Versions : \A c2 \in vh[w[1]][w[2]].changes : x \in CIds(c2) => w = v /\ c2 = c

\* I-EVS-15, FI-27: no push validated after a DROP's fence cites a version it lists, as a base, a
\* deleted path or a reuse source. One validated before the fence may land after it (its late step 7),
\* which the job's mark, after every short timer, sees.
F2FenceHolds ==
    \A v \in F2Versions : \A c \in vh[v[1]][v[2]].changes :
        F2Listed(c.src.ref, c.src.u, c.src.path) => vh[v[1]][v[2]].vseq < dt.seq

(***************************************************************************)
(* Weak fairness: §22.8's two liveness checks, in their own config.         *)
(***************************************************************************)

\* An M2 action under fairness, which only the M2 run takes.
M2Fair(A) == F2Mode = "off" /\ A /\ UNCHANGED f2vars

Fairness ==
    /\ \A i \in Instances : WF_vars(M2Fair(AuthRefresh(i)))
    /\ \A i \in Instances : WF_vars(M2Fair(EvsStep(i)))
    /\ \A i \in Instances : WF_vars(M2Fair(FoldStep(i)))
    /\ \A i \in Instances, r \in Refs : WF_vars(M2Fair(\E u \in 1..MaxVersion : FoldQueue(i, r, u)))
    /\ \A r \in Refs : WF_vars(M2Fair(MapUpload(r)))
    /\ \A r \in Refs : WF_vars(M2Fair(\E w \in Writers, m \in pmap[r] : EpochSign(w, r, m)))
    /\ \A i \in Instances : WF_vars(M2Fair(\E P \in 1..pushCount : Arrive(i, P)))
    \* §19.6 settles a stalled write once its drives answer (StoreSettle.tla's HeldKeyReleased)
    /\ \A r \in Refs, i \in Instances : WF_vars(M2Fair(StallLands(r, i) \/ StallReverts(r, i)))
    \* a step 7 whose If-Match no longer holds gets its 412
    /\ \A i \in Instances : WF_vars(M2Fair(PutFails(i)))

\* An M10 action under fairness, which only an M10 run takes.
F2Fair(A) == F2Mode # "off" /\ A /\ UNCHANGED vars

\* The drop job's phases, and the time they wait on, run once enabled; leases lapse at most F2MaxFaults
\* times.
FairnessF2 ==
    /\ WF_f2vars(F2Fair(\E k \in Instances : F2JobTake(k)))
    /\ \A k \in Instances : WF_f2vars(F2Fair(F2JobStep(k)))
    /\ WF_f2vars(F2Fair(F2WindowEnds))
    /\ WF_f2vars(F2Fair(F2Minute))
    /\ WF_f2vars(F2Fair(F2Tick))

LiveSpec == Spec /\ Fairness /\ FairnessF2

\* Every member removal eventually gates: each evs comes to hold it.
RemovalGates ==
    (proj.shrunkAt # 0) ~> (\A i \in Instances : authView[i] >= proj.shrunkAt)

\* A run's bounds leave a due epoch nothing to commit with: no statement or version is left to sign,
\* and every PATH_EPOCH statement of the ref has used its attempts, none still running.
EpochOutOfRoom(r) ==
    /\ pushCount = MaxPush \/ Committed(r) = MaxVersion
    /\ \A P \in 1..pushCount :
           push[P].kind = "epoch" /\ push[P].ref = r =>
               /\ attemptsMade[P] >= MaxAttempts
               /\ \A i \in Instances : att[i].stage = "idle" \/ att[i].push # P

\* Every due path epoch eventually commits, while the repo lives to commit it and the run's bounds
\* leave room to.
DueEpochCommits ==
    \A r \in Refs :
        (head[r].dueGen # 0) ~> (head[r].dueGen = 0 \/ repo.state # "active" \/ EpochOutOfRoom(r))

\* Every executing drop ends done, held or refused while no hold stands, unless the run's marks end
\* first with candidates still young.
F2DropsEnd ==
    (dt.state = "executing") ~>
        (dt.state \in {"done", "held", "refused"} \/ F2HoldStands \/ (hour2 = F2MaxHour /\ dt.young # {}))

=============================================================================
