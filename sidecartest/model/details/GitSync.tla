----------------------------- MODULE GitSync -----------------------------
(***************************************************************************)
(* Git and evs in both directions: DESIGN-DETAILS.md section 8.            *)
(*                                                                         *)
(* One git-mode ref on evs and, on each device, the daemon's side of it:   *)
(* the mirror's record of the ref (the version applied and its tip), the   *)
(* tip the local git ref was last settled to, the local git ref itself,    *)
(* the journal's open entry, the push ids it sent, and the conflict        *)
(* branches it made. A git client on each device pushes commits through    *)
(* the daemon's proc-receive hook; evs commits a push only on its tip      *)
(* (TIP); the sync engine applies evs's versions to the mirror and then    *)
(* settles the local ref; daemons crash and restart.                       *)
(*                                                                         *)
(* A commit is the set of the atoms of history it holds, so one commit is  *)
(* an ancestor of another exactly when it is a subset of it, and {} is a   *)
(* ref that does not exist. A push adds one fresh atom to the local ref,   *)
(* or, forced, replaces it with a fresh root.                              *)
(*                                                                         *)
(* LocalFirst = FALSE is a shared ref: the hook answers after evs's        *)
(* commit, and the local ref moves only to tips evs committed.             *)
(* LocalFirst = TRUE is an owned ref: the daemon moves the local ref at    *)
(* once and a queue pushes it. Two devices then stand for one sidecar      *)
(* whose state was copied or restored, the one way an owned ref's remote   *)
(* and local histories diverge.                                            *)
(*                                                                         *)
(* An attempt, once sent, stays in `net` and may reach evs at any step,    *)
(* any number of times, until it is dropped, which stands for its          *)
(* statement's time bound running out (11.8's 5b). A daemon learns an      *)
(* outcome only from the ref's history, never from an answer, which is     *)
(* the worst case of every lost reply, lb re-send and stalled write.       *)
(*                                                                         *)
(* Left out, each argued in 8.3: what a push carries and how a reader      *)
(* checks it (commits, blobs, sources, descent), which change no ref's     *)
(* value; parts, leases and refusals other than TIP's; several refs and    *)
(* several clients on one device (the publish lock makes them one); and    *)
(* liveness, whose only clause here is Converge, a property of states in   *)
(* which nothing more can happen.                                          *)
(*                                                                         *)
(* Twin = "none" is the design. Each other value breaks one rule, and its  *)
(* configuration names the invariant that must then fail.                  *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Devices,        \* the daemons
    MaxCommits,     \* atoms: the pushes clients make, over all devices
    MaxVer,         \* the ref's versions
    MaxPid,         \* push ids, over all devices
    MaxCrash,       \* daemon crashes, over all devices
    MaxCommitless,  \* versions that carry no commit: PATH_EPOCH pushes and rekeys
    LocalFirst,     \* TRUE an owned ref, FALSE a shared one
    AllowForce,     \* a client may push a commit that does not descend from the ref
    Twin

ASSUME Twin \in {"none", "EqualsOld", "BlindUpdateRef", "NgOnUnknown", "NoApplyLock", "RefusedDropOnly",
                 "NoRecognition"}
ASSUME LocalFirst \in BOOLEAN /\ AllowForce \in BOOLEAN

Atoms == 1..MaxCommits
Commits == SUBSET Atoms
Anc(x, y) == x \subseteq y
NoEntry == [st |-> "none", old |-> {}, new |-> {}, ans |-> "none", force |-> FALSE]
NoSnap == [taken |-> FALSE, ref |-> {}]

VARIABLES
    log,        \* evs: log[v] is version v, as [pid, tip, kind]
    net,        \* attempts that may still reach evs, as [pid, base, tip]
    nextAtom,   \* the next fresh atom
    nextPid,    \* the next fresh push id
    commitless, \* commitless versions so far
    crashes,    \* crashes so far
    mver,       \* mver[d]: the version d's mirror has applied
    mtip,       \* mtip[d]: the ref's tip at that version
    atip,       \* atip[d]: the evs tip d's local ref was last settled to
    lref,       \* lref[d]: d's local git ref
    jr,         \* jr[d]: the journal's open entry
    att,        \* att[d]: the attempts d sent for it (an owned ref: for its queue), as [pid, base]
    qforce,     \* qforce[d]: an owned ref's queue holds a forced update
    acked,      \* acked[d]: the commits d's daemon answered ok for
    conf,       \* conf[d]: the commits d put on conflict branches
    nack,       \* push ids of updates answered non-fast-forward
    snap,       \* snap[d]: a settle's read of the local ref, in the twin that takes no lock
    spurious,   \* a conflict branch was made for a commit evs's ref already held
    reconciled, \* an update whose answer a crash lost was found committed and applied
    resigned    \* an update committed on its second attempt

vars == <<log, net, nextAtom, nextPid, commitless, crashes, mver, mtip, atip, lref, jr, att, qforce, acked, conf,
          nack, snap, spurious, reconciled, resigned>>
evs == <<log, net, commitless>>
flags == <<spurious, reconciled, resigned>>

Tip == IF Len(log) = 0 THEN {} ELSE log[Len(log)].tip
TipAt(v) == IF v = 0 THEN {} ELSE log[v].tip
CommittedPids == {log[v].pid : v \in 1..Len(log)} \ {0}
InNet(pid) == \E x \in net : x.pid = pid
\* An attempt that may still commit.
Live(a) == a.pid \notin CommittedPids /\ a.base = Len(log)

Settled(d) == atip[d] = mtip[d]
KnownPids(d) == {log[v].pid : v \in 1..mver[d]}
\* d's history holds one of its own push ids.
Committed(d) == \E a \in att[d] : a.pid \in KnownPids(d)
\* The design recognizes its own push in the history; the twin takes every movement of the head for another's.
Recognized(d) == IF Twin = "NoRecognition" THEN FALSE ELSE Committed(d)
\* The head moved past every attempt's base and none of them is in the history: none can commit (TIP).
DeadKnown(d) == att[d] # {} /\ ~Recognized(d) /\ \A a \in att[d] : a.base < mver[d]
\* Every attempt's time bound has run out.
Expired(d) == \A a \in att[d] : ~InNet(a.pid)

Init ==
    /\ log = <<>> /\ net = {} /\ nextAtom = 1 /\ nextPid = 1 /\ commitless = 0 /\ crashes = 0
    /\ mver = [d \in Devices |-> 0]
    /\ mtip = [d \in Devices |-> {}]
    /\ atip = [d \in Devices |-> {}]
    /\ lref = [d \in Devices |-> {}]
    /\ jr = [d \in Devices |-> NoEntry]
    /\ att = [d \in Devices |-> {}]
    /\ qforce = [d \in Devices |-> FALSE]
    /\ acked = [d \in Devices |-> {}]
    /\ conf = [d \in Devices |-> {}]
    /\ nack = {}
    /\ snap = [d \in Devices |-> NoSnap]
    /\ spurious = FALSE /\ reconciled = FALSE /\ resigned = FALSE

(***************************************************************************)
(* evs                                                                     *)
(***************************************************************************)

\* 11.8's step 7 for a git-mode push: only on the tip, and a push id commits once. The attempt stays in flight: a
\* second delivery of it finds its push id committed.
EvsCommit(a) ==
    /\ a \in net /\ Live(a) /\ Len(log) < MaxVer
    /\ log' = Append(log, [pid |-> a.pid, tip |-> a.tip, kind |-> "update"])
    /\ UNCHANGED <<net, nextAtom, nextPid, commitless, crashes, mver, mtip, atip, lref, jr, att, qforce, acked,
                   conf, nack, snap, flags>>

\* An attempt's statement passes its time bound, or evs refuses it for good: it never commits afterwards.
EvsDrop(a) ==
    /\ a \in net
    /\ net' = net \ {a}
    /\ UNCHANGED <<log, nextAtom, nextPid, commitless, crashes, mver, mtip, atip, lref, jr, att, qforce, acked,
                   conf, nack, snap, flags>>

\* A PATH_EPOCH push or a rekey by any writer: a version, and no commit.
EvsCommitless ==
    /\ commitless < MaxCommitless /\ Len(log) < MaxVer
    /\ log' = Append(log, [pid |-> 0, tip |-> Tip, kind |-> "commitless"])
    /\ commitless' = commitless + 1
    /\ UNCHANGED <<net, nextAtom, nextPid, crashes, mver, mtip, atip, lref, jr, att, qforce, acked, conf, nack,
                   snap, flags>>

(***************************************************************************)
(* The sync engine: replay, then settle                                    *)
(***************************************************************************)

\* The mirror's record of the ref moves one version on. The local ref has not moved yet: atip keeps the tip it was
\* last settled to, so a crash between this and Settle is found by atip # mtip.
CatchUp(d) ==
    /\ mver[d] < Len(log)
    /\ mver' = [mver EXCEPT ![d] = @ + 1]
    /\ mtip' = [mtip EXCEPT ![d] = log[mver[d] + 1].tip]
    /\ UNCHANGED <<evs, nextAtom, nextPid, crashes, atip, lref, jr, att, qforce, acked, conf, nack, snap, flags>>

\* 8.2.7's settle: the rule for the local ref, on the value cur read under the ref's apply lock.
SettleRule(d, cur) ==
    IF cur = atip[d] THEN "follow"
    ELSE IF Anc(cur, mtip[d]) THEN "follow"
    ELSE IF Anc(mtip[d], cur) /\ LocalFirst THEN "keep"
    ELSE "conflict"

SettleTo(d, cur) ==
    LET r == SettleRule(d, cur) IN
    /\ lref' = [lref EXCEPT ![d] =
           IF r = "follow" \/ (r = "conflict" /\ Twin # "RefusedDropOnly") THEN mtip[d] ELSE @]
    /\ conf' = [conf EXCEPT ![d] = IF r = "conflict" /\ Twin # "RefusedDropOnly" THEN @ \cup {cur} ELSE @]
    /\ att' = [att EXCEPT ![d] = IF r = "conflict" THEN {} ELSE @]
    /\ qforce' = [qforce EXCEPT ![d] = IF r = "conflict" THEN FALSE ELSE @]
    /\ atip' = [atip EXCEPT ![d] = mtip[d]]

\* Read, decide and write under the ref's apply lock.
Settle(d) ==
    /\ Twin # "NoApplyLock"
    /\ ~Settled(d)
    /\ SettleTo(d, lref[d])
    /\ UNCHANGED <<evs, nextAtom, nextPid, crashes, mver, mtip, jr, acked, nack, snap, flags>>

\* The twin: the read and the write are two steps with no lock and no compare, so a receive can land between.
SettleRead(d) ==
    /\ Twin = "NoApplyLock"
    /\ ~Settled(d) /\ ~snap[d].taken
    /\ snap' = [snap EXCEPT ![d] = [taken |-> TRUE, ref |-> lref[d]]]
    /\ UNCHANGED <<evs, nextAtom, nextPid, crashes, mver, mtip, atip, lref, jr, att, qforce, acked, conf, nack,
                   flags>>

SettleWrite(d) ==
    /\ Twin = "NoApplyLock"
    /\ snap[d].taken
    /\ SettleTo(d, snap[d].ref)
    /\ snap' = [snap EXCEPT ![d] = NoSnap]
    /\ UNCHANGED <<evs, nextAtom, nextPid, crashes, mver, mtip, jr, acked, nack, flags>>

(***************************************************************************)
(* A shared ref: the hook answers after evs                                *)
(***************************************************************************)

NewCommit(d, f) == IF f THEN {nextAtom} ELSE lref[d] \cup {nextAtom}
ForceChoices(d) == IF AllowForce /\ lref[d] # {} THEN {FALSE, TRUE} ELSE {FALSE}

Close(d) ==
    /\ jr' = [jr EXCEPT ![d] = NoEntry]
    /\ att' = [att EXCEPT ![d] = {}]

\* proc-receive takes an update whose old is the local ref: the journal entry comes first.
Receive(d) ==
    /\ ~LocalFirst
    /\ jr[d].st = "none" /\ nextAtom <= MaxCommits
    /\ Settled(d) /\ lref[d] = mtip[d]
    /\ \E f \in ForceChoices(d) :
        jr' = [jr EXCEPT ![d] = [st |-> "recv", old |-> lref[d], new |-> NewCommit(d, f), ans |-> "none",
                                 force |-> f]]
    /\ nextAtom' = nextAtom + 1
    /\ UNCHANGED <<evs, nextPid, crashes, mver, mtip, atip, lref, att, qforce, acked, conf, nack, snap, flags>>

\* The first attempt, or, when only commitless versions moved the head, the same update signed again on the new
\* base. Each push id is journaled before it is sent, which is one step here.
Send(d) ==
    /\ ~LocalFirst
    /\ jr[d].st \in {"recv", "sent"} /\ jr[d].ans = "none"
    /\ nextPid <= MaxPid
    /\ Settled(d) /\ mtip[d] = jr[d].old /\ lref[d] = jr[d].old
    /\ (jr[d].st = "recv" \/ DeadKnown(d))
    /\ net' = net \cup {[pid |-> nextPid, base |-> mver[d], tip |-> jr[d].new]}
    /\ att' = [att EXCEPT ![d] = @ \cup {[pid |-> nextPid, base |-> mver[d]]}]
    /\ jr' = [jr EXCEPT ![d].st = "sent"]
    /\ nextPid' = nextPid + 1
    /\ UNCHANGED <<log, commitless, nextAtom, crashes, mver, mtip, atip, lref, qforce, acked, conf, nack, snap,
                   flags>>

\* ok: the history holds one of the update's push ids and the local ref is settled to at least that version. The
\* twin writes the ref itself, to new, whatever the sync engine has done since.
AnswerOk(d) ==
    /\ ~LocalFirst
    /\ jr[d].st = "sent" /\ jr[d].ans = "none" /\ Recognized(d)
    /\ IF Twin = "BlindUpdateRef"
           THEN lref' = [lref EXCEPT ![d] = jr[d].new]
           ELSE Settled(d) /\ UNCHANGED lref
    /\ acked' = [acked EXCEPT ![d] = @ \cup {jr[d].new}]
    /\ resigned' = (resigned \/ Cardinality(att[d]) > 1)
    /\ Close(d)
    /\ UNCHANGED <<evs, nextAtom, nextPid, crashes, mver, mtip, atip, qforce, conf, nack, snap, spurious,
                   reconciled>>

\* ng non-fast-forward: the head gained a commit and none of the update's attempts can commit. The twin says it of
\* an attempt whose outcome it does not know.
AnswerNonFf(d) ==
    /\ ~LocalFirst
    /\ jr[d].ans = "none"
    /\ \/ (jr[d].st = "recv" /\ Settled(d) /\ mtip[d] # jr[d].old)
       \/ (jr[d].st = "sent" /\ DeadKnown(d) /\ mtip[d] # jr[d].old)
       \/ (Twin = "NgOnUnknown" /\ jr[d].st = "sent" /\ ~Recognized(d))
    /\ nack' = nack \cup {a.pid : a \in att[d]}
    /\ Close(d)
    /\ UNCHANGED <<evs, nextAtom, nextPid, crashes, mver, mtip, atip, lref, qforce, acked, conf, snap, flags>>

\* The hook's time ran out with the outcome unknown: ng remote outcome pending, and the entry stays.
AnswerPending(d) ==
    /\ ~LocalFirst
    /\ jr[d].st = "sent" /\ jr[d].ans = "none" /\ ~Recognized(d) /\ ~DeadKnown(d)
    /\ jr' = [jr EXCEPT ![d].ans = "pending"]
    /\ UNCHANGED <<evs, nextAtom, nextPid, crashes, mver, mtip, atip, lref, att, qforce, acked, conf, nack, snap,
                   flags>>

\* An entry nobody waits on, resolved from the history: committed and applied; dead because the head moved; or,
\* after a read of the head that found no attempt in the history, past every attempt's time bound.
CloseLater(d) ==
    /\ ~LocalFirst
    /\ jr[d].st = "sent" /\ jr[d].ans \in {"pending", "lost"}
    /\ \/ (Recognized(d) /\ Settled(d))
       \/ DeadKnown(d)
       \/ (mver[d] = Len(log) /\ ~Committed(d) /\ Expired(d))
    /\ reconciled' = (reconciled \/ (jr[d].ans = "lost" /\ Recognized(d) /\ Anc(jr[d].new, lref[d])))
    /\ Close(d)
    /\ UNCHANGED <<evs, nextAtom, nextPid, crashes, mver, mtip, atip, lref, qforce, acked, conf, nack, snap,
                   spurious, resigned>>

\* The twin: 11.11's restart row as written. A committed entry updates the local ref if it still equals old, and
\* otherwise moves "the local commits" to a conflict branch.
ResolveWritten(d) ==
    /\ Twin = "EqualsOld"
    /\ ~LocalFirst
    /\ jr[d].st = "sent" /\ Committed(d)
    /\ IF lref[d] = jr[d].old
           THEN /\ lref' = [lref EXCEPT ![d] = jr[d].new]
                /\ UNCHANGED <<conf, spurious>>
           ELSE /\ conf' = [conf EXCEPT ![d] = @ \cup {jr[d].new}]
                /\ spurious' = (spurious \/ Anc(jr[d].new, lref[d]))
                /\ UNCHANGED lref
    /\ Close(d)
    /\ UNCHANGED <<evs, nextAtom, nextPid, crashes, mver, mtip, atip, qforce, acked, nack, snap, reconciled,
                   resigned>>

(***************************************************************************)
(* An owned ref: the local ref first, then the queue                       *)
(***************************************************************************)

\* The journal entry, then the local update.
ReceiveQ(d) ==
    /\ LocalFirst
    /\ jr[d].st = "none" /\ nextAtom <= MaxCommits
    /\ \E f \in ForceChoices(d) :
        jr' = [jr EXCEPT ![d] = [st |-> "recv", old |-> lref[d], new |-> NewCommit(d, f), ans |-> "none",
                                 force |-> f]]
    /\ nextAtom' = nextAtom + 1
    /\ UNCHANGED <<evs, nextPid, crashes, mver, mtip, atip, lref, att, qforce, acked, conf, nack, snap, flags>>

\* git update-ref <new> <old> under the apply lock, and ok. A local ref that moved since answers ng and changes
\* nothing. A restart finds the entry and does the same. A forced update is the client's own act of dropping what
\* the ref held and new does not, as in stock git, so those commits stop counting as acknowledged.
LocalApply(d) ==
    /\ LocalFirst
    /\ jr[d].st = "recv"
    /\ IF lref[d] = jr[d].old
           THEN /\ lref' = [lref EXCEPT ![d] = jr[d].new]
                /\ acked' = [acked EXCEPT ![d] =
                       {c \in @ : ~(jr[d].force /\ Anc(c, lref[d]) /\ ~Anc(c, jr[d].new))} \cup {jr[d].new}]
                /\ qforce' = [qforce EXCEPT ![d] = @ \/ jr[d].force]
           ELSE UNCHANGED <<lref, acked, qforce>>
    /\ jr' = [jr EXCEPT ![d] = NoEntry]
    /\ UNCHANGED <<evs, nextAtom, nextPid, crashes, mver, mtip, atip, att, conf, nack, snap, flags>>

\* The queue has something evs can take: the local ref is ahead of the mirror's tip, or holds a forced update, and
\* no earlier attempt can still land.
QueueReady(d) ==
    /\ Settled(d) /\ lref[d] # mtip[d]
    /\ (Anc(mtip[d], lref[d]) \/ qforce[d])
    /\ \A a \in att[d] : a.base < mver[d] \/ ~InNet(a.pid)

\* One push for everything queued: old is the mirror's tip, new the local ref.
SendQ(d) ==
    /\ LocalFirst
    /\ QueueReady(d) /\ nextPid <= MaxPid
    /\ net' = net \cup {[pid |-> nextPid, base |-> mver[d], tip |-> lref[d]]}
    /\ att' = [att EXCEPT ![d] = @ \cup {[pid |-> nextPid, base |-> mver[d]]}]
    /\ nextPid' = nextPid + 1
    /\ UNCHANGED <<log, commitless, nextAtom, crashes, mver, mtip, atip, lref, jr, qforce, acked, conf, nack, snap,
                   flags>>

\* The queue is empty once the mirror's tip is the local ref.
QueueDone(d) ==
    /\ LocalFirst
    /\ Settled(d) /\ lref[d] = mtip[d] /\ (att[d] # {} \/ qforce[d])
    /\ att' = [att EXCEPT ![d] = {}]
    /\ qforce' = [qforce EXCEPT ![d] = FALSE]
    /\ UNCHANGED <<evs, nextAtom, nextPid, crashes, mver, mtip, atip, lref, jr, acked, conf, nack, snap, flags>>

(***************************************************************************)
(* Crashes                                                                 *)
(***************************************************************************)

\* The daemon dies and restarts. The mirror, the local ref and the journal are on disk. What is lost is the
\* hook's connection, a shared ref's entry that sent nothing, and a settle between its read and its write.
Crash(d) ==
    /\ crashes < MaxCrash
    /\ crashes' = crashes + 1
    /\ IF LocalFirst
           THEN UNCHANGED <<jr, att>>
           ELSE IF jr[d].st = "recv"
                    THEN Close(d)
                    ELSE /\ jr' = [jr EXCEPT ![d].ans = IF jr[d].st = "sent" /\ @ = "none" THEN "lost" ELSE @]
                         /\ UNCHANGED att
    /\ snap' = [snap EXCEPT ![d] = NoSnap]
    /\ UNCHANGED <<evs, nextAtom, nextPid, mver, mtip, atip, lref, qforce, acked, conf, nack, flags>>

Next ==
    \/ \E a \in net : EvsCommit(a) \/ EvsDrop(a)
    \/ EvsCommitless
    \/ \E d \in Devices :
        \/ CatchUp(d) \/ Settle(d) \/ SettleRead(d) \/ SettleWrite(d)
        \/ Receive(d) \/ Send(d) \/ AnswerOk(d) \/ AnswerNonFf(d) \/ AnswerPending(d) \/ CloseLater(d)
        \/ ResolveWritten(d)
        \/ ReceiveQ(d) \/ LocalApply(d) \/ SendQ(d) \/ QueueDone(d)
        \/ Crash(d)

Spec == Init /\ [][Next]_vars

Symmetry == Permutations(Devices)

(***************************************************************************)
(* Invariants                                                              *)
(***************************************************************************)

TypeOK ==
    /\ \A v \in 1..Len(log) : log[v].pid \in 0..MaxPid /\ log[v].tip \in Commits
                              /\ log[v].kind \in {"update", "commitless"}
    /\ \A a \in net : a.pid \in 1..MaxPid /\ a.base \in 0..MaxVer /\ a.tip \in Commits
    /\ nextAtom \in 1..(MaxCommits + 1) /\ nextPid \in 1..(MaxPid + 1)
    /\ \A d \in Devices :
        /\ mver[d] \in 0..Len(log)
        /\ mtip[d] \in Commits /\ atip[d] \in Commits /\ lref[d] \in Commits
        /\ jr[d].st \in {"none", "recv", "sent"}
        /\ jr[d].ans \in {"none", "pending", "lost"}
        /\ acked[d] \subseteq Commits /\ conf[d] \subseteq Commits

\* The mirror is a prefix of evs's history.
MirrorExact == \A d \in Devices : mtip[d] = TipAt(mver[d])

\* A push id commits at most once, and no version repeats the update before it: one git update is at most one
\* version.
NoDuplicate ==
    /\ \A v, w \in 1..Len(log) : v # w /\ log[v].pid # 0 => log[v].pid # log[w].pid
    /\ \A v \in 1..Len(log) : log[v].kind = "update" => log[v].tip # TipAt(v - 1)

\* No acknowledged commit is lost: it is in a tip evs committed, or still in the local ref, or on a conflict
\* branch of the device that took it.
AckedDurable ==
    \A d \in Devices : \A c \in acked[d] :
        \/ \E v \in 1..Len(log) : Anc(c, log[v].tip)
        \/ Anc(c, lref[d])
        \/ \E x \in conf[d] : Anc(c, x)

\* A shared ref's local ref is never ahead of evs and never anywhere else: it is the tip it was settled to or the
\* tip the mirror holds, and it has no conflict branch. An acknowledged commit there is in evs.
SharedSafe ==
    ~LocalFirst =>
        \A d \in Devices :
            /\ lref[d] \in {atip[d], mtip[d]}
            /\ conf[d] = {}
            /\ \A c \in acked[d] : \E v \in 1..Len(log) : Anc(c, log[v].tip)

\* FI-9's per-ref outcome: an update answered non-fast-forward never commits.
TruthfulNg == nack \cap CommittedPids = {}

\* A conflict branch holds something evs's ref did not.
NoSpurious == ~spurious

\* The states in which nothing more can happen: every device has applied the whole history and settled, no entry
\* is open, no attempt can still land, and no queue has anything to send. Bounds that stop the model short are
\* not such states.
Quiescent ==
    /\ nextPid <= MaxPid /\ Len(log) < MaxVer
    /\ \A a \in net : ~Live(a)
    /\ \A d \in Devices :
        /\ mver[d] = Len(log) /\ Settled(d) /\ jr[d].st = "none" /\ ~snap[d].taken
        /\ (LocalFirst => ~QueueReady(d))

\* Then every local ref is evs's tip: what a device had beside it is on a conflict branch (AckedDurable).
Converge == Quiescent => \A d \in Devices : lref[d] = Tip

\* Reach configurations: each denies a state the design must reach, and must fail.
NoConflict == \A d \in Devices : conf[d] = {}
NeverReconciled == ~reconciled
NeverResigned == ~resigned
=============================================================================
