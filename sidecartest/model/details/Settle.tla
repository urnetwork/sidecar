------------------------------- MODULE Settle -------------------------------
(***************************************************************************)
(* DESIGN-DETAILS.md section 2's settle rules: §19.6's rules (1) to (6)     *)
(* (D-OPS-20) with the two changes that section makes, on one key of a set  *)
(* of drives read at N/2 and written at N/2 + 1.                            *)
(*                                                                          *)
(* It is StoreSettle.tla, which another lane owns and this file leaves as   *)
(* it is, with:                                                             *)
(*                                                                          *)
(*   stamps   rule (2) compares the drive's commit stamp for the key, not   *)
(*            only the version it holds: a drive commit applies only while  *)
(*            no commit has been applied to the key on that drive since the *)
(*            coordinator read it under the key's lock. fresh[w][d] is that *)
(*            fact, so no counter enters a state.                           *)
(*   deletes  rule (3) releases a failed DELETE only once every drive       *)
(*            commit of it has answered and each that landed is reverted:   *)
(*            nothing of a DELETE lands or is reverted after its release.   *)
(*                                                                          *)
(* A write takes the key's lock, reads each reachable drive's version and   *)
(* stamp under it and sends each drive a commit naming them. A drive commit *)
(* is a check step, which takes the drive's own lock, and a commit step,    *)
(* which applies it and drops that lock; any time may pass between the two. *)
(* The coordinator releases the key at a write quorum, or, once no more of  *)
(* its commits can begin, after reverting what it can: a PUT once fewer     *)
(* than N/2 drives may still hold it, a DELETE once none may. A dead        *)
(* coordinator's write is settled by the settler past its deadline; heal    *)
(* copies only a version N/2 drives hold.                                   *)
(*                                                                          *)
(* The ghost variable current is the state every request must see. FI-30 is *)
(* NoStaleQuorum, ReadsSeeCurrent and LateWritesNeverRead, with             *)
(* HeldKeyReleased for its last clause.                                     *)
(*                                                                          *)
(* A deadline is one fact per write, past by every clock, as in             *)
(* StoreSettle.tla. A stamp is remembered for ever here; the build keeps    *)
(* one for StampKeep, longer than any deadline a commit can carry, so a     *)
(* commit that could match a forgotten stamp is past its deadline (section  *)
(* 2.3's arithmetic).                                                       *)
(*                                                                          *)
(* Twin names a rule to break. "none" is the design. "Written" is §19.6 as  *)
(* DESIGN.md states it on 2026-11-10: no stamp, and a failed DELETE         *)
(* released and reverted as a PUT is. A twin config must make TLC refuse    *)
(* the model with the invariant its cfg names.                              *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    DriveCount,          \* N: 8 at EC:4
    DrivesPerHost,       \* 2
    Writes,              \* the writes on the key: model values
    CoordinatorCount,    \* coordinators: the handlers taking writes, one on each of hosts 1..n
    HostFailures,        \* how many times a host may go down in one behavior
    CoordinatorCrashes,  \* how many coordinators may die with a write under them
    MaxPuts,             \* how many of the writes may be PUTs
    MaxDeletes,          \* how many of the writes may be DELETEs
    Still,               \* parts held still in a run: a subset of {"heal", "cancel"}
    Twin                 \* "none", or the rule a twin config breaks

Drives == 1..DriveCount
Hosts == 1..(DriveCount \div DrivesPerHost)
HostOf(d) == (d + DrivesPerHost - 1) \div DrivesPerHost
Coordinators == 1..CoordinatorCount

WriteQuorum == (DriveCount \div 2) + 1
ReadQuorum == DriveCount \div 2

\* What a drive holds of the key.
Initial == "initial"
Absent == "absent"
Versions == Writes \cup {Initial, Absent}

NoHolder == "none"
Heal == "heal"

\* The twins of StoreSettle.tla, and this section's.
StoreTwins == {"ReleaseOnCancel", "NoDeadlineCheck", "NoVersionCheck", "RevertBelowQuorumOnly",
               "SettlerRevertsUnseen", "HealMinority", "NoDriveLock"}
DetailTwins == {"Written", "NoStamp", "DeleteReleasesEarly"}

ASSUME
    /\ DriveCount % DrivesPerHost = 0
    /\ CoordinatorCount <= DriveCount \div DrivesPerHost
    /\ Still \subseteq {"heal", "cancel"}
    /\ Twin \in {"none"} \cup StoreTwins \cup DetailTwins

\* Section 2's two rules, each off in the text as written and in its own twin.
Stamps == Twin \notin {"Written", "NoStamp"}
DeletesHeld == Twin \notin {"Written", "DeleteReleasesEarly"}

VARIABLES
    drive,        \* drive[d]: the version drive d holds
    driveLock,    \* driveLock[d]: whose commit holds drive d's own lock on the key
    keyHolder,    \* the write holding the key's lock, or NoHolder
    phase,        \* phase[w]: "waiting", "running", then "success", "failed" or "refused"
    kind,         \* kind[w]: "put" or "delete", chosen when the store takes it
    coordinator,  \* coordinator[w]: which coordinator took it
    past,         \* past[w]: its deadline has passed
    cancelled,    \* cancelled[w]: its request was cancelled
    orphan,       \* orphan[w]: its coordinator died holding it
    acked,        \* acked[w]: the store decided it took effect
    expect,       \* expect[w][d]: the version its coordinator read from d, under the lock
    fresh,        \* fresh[w][d]: no commit has been applied on d since that read: its stamp stands
    commit,       \* commit[w][d]: "none", "sent", "checked", "committed", or "clear": stale or reverted
    down,         \* the hosts no request reaches
    downLeft,     \* host failures left
    crashesLeft,  \* coordinator crashes left
    healing,      \* heal's commit between its check and its commit step, or NoHeal
    current,      \* ghost: what every request must see
    readBad       \* ghost: a read returned anything else

vars == <<drive, driveLock, keyHolder, phase, kind, coordinator, past, cancelled, orphan, acked,
          expect, fresh, commit, down, downLeft, crashesLeft, healing, current, readBad>>

NoHeal == [drive |-> 0, to |-> Absent]

\* A drive a request reaches.
Up(d) == HostOf(d) \notin down

UpDrives == {d \in Drives : Up(d)}

\* The version a write's commit leaves on a drive.
NewVersion(w) == IF kind[w] = "delete" THEN Absent ELSE w

\* Writes the store took, by kind.
Taken(k) == {w \in Writes : phase[w] \in {"running", "success", "failed"} /\ kind[w] = k}

\* Commits its coordinator or the settler knows landed: the drives that answered.
Known(w) == {d \in Drives : commit[w][d] = "committed" /\ Up(d)}

\* Drives that gave no answer yet, which a settler must count as committed.
Unanswered(w) == {d \in Drives : ~Up(d) /\ commit[w][d] \in {"sent", "checked", "committed"}}

\* Commits that can still begin.
CanBegin(w) == {d \in Drives : commit[w][d] = "sent" /\ ~past[w]}

\* Rule (3): drives that may still hold the write, committed and not reverted or still committing.
MayHold(w) ==
    {d \in Drives : commit[w][d] \in {"checked", "committed"}} \cup Unanswered(w) \cup CanBegin(w)

\* Rule (3)'s precondition for giving up.
NoMoreCanBegin(w) == CanBegin(w) = {}

\* A coordinator knows whether it acknowledged. A settler does not, so a write that could have held
\* a write quorum stays held until those hosts answer: reverting it could undo an acknowledged state.
\* acked is the oracle's, so only a live coordinator's step reads it.
MayRevert(w) ==
    /\ ~orphan[w] => ~acked[w]
    /\ NoMoreCanBegin(w)
    /\ Cardinality(Known(w)) < WriteQuorum
    /\ orphan[w] => past[w]
    /\ orphan[w] /\ Twin # "SettlerRevertsUnseen" =>
           Cardinality(Known(w)) + Cardinality(Unanswered(w)) < WriteQuorum

Holding(v) == {d \in UpDrives : drive[d] = v}

\* What a read may return. A version on N/2 of the drives it reaches wins, whatever the rest report;
\* with none, N/2 drives answering not found is a 404, and anything else a 503.
Readable ==
    LET found == {v \in Versions \ {Absent} : Cardinality(Holding(v)) >= ReadQuorum}
    IN  IF found # {} THEN found
        ELSE IF Cardinality(Holding(Absent)) >= ReadQuorum THEN {Absent}
        ELSE {}

\* A commit applied on drive d: every stamp read from d before it is spent.
Spent(d) == [w \in Writes |-> [x \in Drives |-> IF x = d THEN FALSE ELSE fresh[w][x]]]

Init ==
    /\ drive \in {[d \in Drives |-> Initial], [d \in Drives |-> Absent]}
    /\ driveLock = [d \in Drives |-> NoHolder]
    /\ keyHolder = NoHolder
    /\ phase = [w \in Writes |-> "waiting"]
    /\ kind = [w \in Writes |-> "put"]
    /\ coordinator = [w \in Writes |-> 0]
    /\ past = [w \in Writes |-> FALSE]
    /\ cancelled = [w \in Writes |-> FALSE]
    /\ orphan = [w \in Writes |-> FALSE]
    /\ acked = [w \in Writes |-> FALSE]
    /\ expect = [w \in Writes |-> [d \in Drives |-> Absent]]
    /\ fresh = [w \in Writes |-> [d \in Drives |-> FALSE]]
    /\ commit = [w \in Writes |-> [d \in Drives |-> "none"]]
    /\ down = {}
    /\ downLeft = HostFailures
    /\ crashesLeft = CoordinatorCrashes
    /\ healing = NoHeal
    /\ current = drive[1]
    /\ readBad = FALSE

\* Time reaches a write's deadline, before or after the store took it.
PassDeadline(w) ==
    /\ phase[w] \in {"waiting", "running"}
    /\ ~past[w]
    /\ past' = [past EXCEPT ![w] = TRUE]
    /\ UNCHANGED <<drive, driveLock, keyHolder, phase, kind, coordinator, cancelled, orphan, acked,
                   expect, fresh, commit, down, downLeft, crashesLeft, healing, current, readBad>>

\* Rule (1): a request past its deadline when it holds the key's lock is refused. Otherwise its
\* coordinator reads every drive it reaches, version and stamp; a host that is down misses the write.
Take(w, c, k) ==
    /\ phase[w] = "waiting"
    /\ keyHolder = NoHolder
    /\ c \notin down
    /\ IF past[w] /\ Twin # "NoDeadlineCheck"
       THEN /\ phase' = [phase EXCEPT ![w] = "refused"]
            /\ UNCHANGED <<keyHolder, kind, coordinator, expect, fresh, commit>>
       ELSE /\ Cardinality(Taken(k)) < (IF k = "put" THEN MaxPuts ELSE MaxDeletes)
            /\ keyHolder' = w
            /\ phase' = [phase EXCEPT ![w] = "running"]
            /\ kind' = [kind EXCEPT ![w] = k]
            /\ coordinator' = [coordinator EXCEPT ![w] = c]
            /\ expect' = [expect EXCEPT ![w] = drive]
            /\ fresh' = [fresh EXCEPT ![w] = [d \in Drives |-> Up(d)]]
            /\ commit' = [commit EXCEPT ![w] = [d \in Drives |-> IF Up(d) THEN "sent" ELSE "none"]]
    /\ UNCHANGED <<drive, driveLock, past, cancelled, orphan, acked, down, downLeft, crashesLeft,
                   healing, current, readBad>>

\* Rule (2)'s check, under the drive's own lock: only while the drive still holds what the
\* coordinator read, no commit has been applied there since (its stamp), and its deadline has not
\* passed, else stale, changing nothing. A DELETE of a key the drive lacked takes nothing, counts as
\* committed and is a commit all the same: it spends the drive's stamp. A cancel stops a PUT on the
\* coordinator's own drives. No request reaches a down host, but one may have reached it first: a
\* host that does not answer may still be committing.
Check(w, d) ==
    /\ commit[w][d] = "sent"
    /\ driveLock[d] = NoHolder \/ Twin = "NoDriveLock"
    /\ LET expired == past[w] /\ Twin # "NoDeadlineCheck"
           moved == /\ Twin # "NoVersionCheck"
                    /\ drive[d] # expect[w][d] \/ (Stamps /\ ~fresh[w][d])
           stopped == cancelled[w] /\ kind[w] = "put" /\ HostOf(d) = coordinator[w]
       IN  IF expired \/ moved \/ stopped
           THEN /\ commit' = [commit EXCEPT ![w][d] = "clear"]
                /\ UNCHANGED driveLock
           ELSE /\ commit' = [commit EXCEPT ![w][d] = "checked"]
                /\ driveLock' = [driveLock EXCEPT ![d] = w]
    /\ UNCHANGED <<drive, keyHolder, phase, kind, coordinator, past, cancelled, orphan, acked, expect,
                   fresh, down, downLeft, crashesLeft, healing, current, readBad>>

\* The commit rename. It may land at any time after its check, on a host no request reaches, and
\* after its key's release.
Commit(w, d) ==
    /\ commit[w][d] = "checked"
    /\ drive' = [drive EXCEPT ![d] = NewVersion(w)]
    /\ driveLock' = [driveLock EXCEPT ![d] = NoHolder]
    /\ commit' = [commit EXCEPT ![w][d] = "committed"]
    /\ fresh' = Spent(d)
    /\ UNCHANGED <<keyHolder, phase, kind, coordinator, past, cancelled, orphan, acked, expect, down,
                   downLeft, crashesLeft, healing, current, readBad>>

\* A cancel ends the handler's waits and stops its own drives' PUT commits before their rename; it
\* reaches no other host and no DELETE. The deployed build also released the lock here.
Cancel(w) ==
    /\ "cancel" \notin Still
    /\ phase[w] = "running"
    /\ ~cancelled[w]
    /\ cancelled' = [cancelled EXCEPT ![w] = TRUE]
    /\ IF Twin = "ReleaseOnCancel" /\ keyHolder = w /\ ~acked[w]
       THEN /\ keyHolder' = NoHolder
            /\ phase' = [phase EXCEPT ![w] = "failed"]
       ELSE UNCHANGED <<keyHolder, phase>>
    /\ UNCHANGED <<drive, driveLock, kind, coordinator, past, orphan, acked, expect, fresh, commit, down,
                   downLeft, crashesLeft, healing, current, readBad>>

\* A commit its cancel stopped between check and rename.
Stopped(w, d) ==
    /\ commit[w][d] = "checked"
    /\ cancelled[w]
    /\ kind[w] = "put"
    /\ HostOf(d) = coordinator[w]
    /\ driveLock' = [driveLock EXCEPT ![d] = NoHolder]
    /\ commit' = [commit EXCEPT ![w][d] = "clear"]
    /\ UNCHANGED <<drive, keyHolder, phase, kind, coordinator, past, cancelled, orphan, acked, expect,
                   fresh, down, downLeft, crashesLeft, healing, current, readBad>>

\* Rule (3)'s success, by the coordinator or, past the deadline, the settler: N/2 + 1 drives answered
\* committed. From here it stands, and a later commit of it only adds a copy.
Quorum(w) ==
    /\ keyHolder = w
    /\ ~acked[w]
    /\ orphan[w] => past[w]
    /\ Cardinality(Known(w)) >= WriteQuorum
    /\ acked' = [acked EXCEPT ![w] = TRUE]
    /\ current' = NewVersion(w)
    /\ UNCHANGED <<drive, driveLock, keyHolder, phase, kind, coordinator, past, cancelled, orphan,
                   expect, fresh, commit, down, downLeft, crashesLeft, healing, readBad>>

\* The coordinator may die between deciding and releasing; the settler then releases.
ReleaseSuccess(w) ==
    /\ keyHolder = w
    /\ acked[w]
    /\ orphan[w] => past[w]
    /\ keyHolder' = NoHolder
    /\ phase' = [phase EXCEPT ![w] = "success"]
    /\ UNCHANGED <<drive, driveLock, kind, coordinator, past, cancelled, orphan, acked, expect, fresh,
                   commit, down, downLeft, crashesLeft, healing, current, readBad>>

\* Rule (3)'s revert, by (2)'s check: only while the drive still holds this write. A PUT's goes on
\* after the key's release for a commit that landed late; a DELETE's never does, since its key is held
\* until none is left to revert. The text as written reverts a DELETE late too.
Revert(w, d) ==
    /\ commit[w][d] = "committed"
    /\ Up(d)
    /\ phase[w] \in {"running", "failed"}
    /\ phase[w] = "running" => MayRevert(w)
    /\ driveLock[d] = NoHolder
    /\ drive' = [drive EXCEPT ![d] = IF @ = NewVersion(w) THEN expect[w][d] ELSE @]
    /\ commit' = [commit EXCEPT ![w][d] = "clear"]
    \* a revert that finds nothing of its write changes nothing, the stamp included
    /\ fresh' = IF drive[d] = NewVersion(w) THEN Spent(d) ELSE fresh
    /\ UNCHANGED <<driveLock, keyHolder, phase, kind, coordinator, past, cancelled, orphan, acked,
                   expect, down, downLeft, crashesLeft, healing, current, readBad>>

\* How many drives may still hold a failed write when its key is released: a PUT under a read quorum,
\* since it can then never be read and carries its own version; a DELETE none, since every DELETE
\* leaves a drive in the one state, the key absent, which a read counts whichever DELETE left it.
ReleaseBound(w) ==
    IF kind[w] = "delete" /\ DeletesHeld THEN 1
    ELSE IF Twin = "RevertBelowQuorumOnly" THEN WriteQuorum
    ELSE ReadQuorum

\* Rule (3)'s release of a write that can never be read: every drive that took it and answers has
\* been reverted, and those that may still hold it number under its bound.
ReleaseFailed(w) ==
    /\ keyHolder = w
    /\ MayRevert(w)
    /\ Known(w) = {}
    /\ Cardinality(MayHold(w)) < ReleaseBound(w)
    /\ keyHolder' = NoHolder
    /\ phase' = [phase EXCEPT ![w] = "failed"]
    /\ UNCHANGED <<drive, driveLock, kind, coordinator, past, cancelled, orphan, acked, expect, fresh,
                   commit, down, downLeft, crashesLeft, healing, current, readBad>>

\* Rule (4): a coordinator dies with a write under it. No lock of it expires.
Crash(w) ==
    /\ phase[w] = "running"
    /\ ~orphan[w]
    /\ crashesLeft > 0
    /\ crashesLeft' = crashesLeft - 1
    /\ orphan' = [orphan EXCEPT ![w] = TRUE]
    /\ UNCHANGED <<drive, driveLock, keyHolder, phase, kind, coordinator, past, cancelled, acked, expect,
                   fresh, commit, down, downLeft, healing, current, readBad>>

HostDown(h) ==
    /\ h \notin down
    /\ downLeft > 0
    /\ downLeft' = downLeft - 1
    /\ down' = down \cup {h}
    /\ UNCHANGED <<drive, driveLock, keyHolder, phase, kind, coordinator, past, cancelled, orphan, acked,
                   expect, fresh, commit, crashesLeft, healing, current, readBad>>

HostUp(h) ==
    /\ h \in down
    /\ down' = down \ {h}
    /\ UNCHANGED <<drive, driveLock, keyHolder, phase, kind, coordinator, past, cancelled, orphan, acked,
                   expect, fresh, commit, downLeft, crashesLeft, healing, current, readBad>>

\* Rule (6): a heal takes the key, copies only a version N/2 drives hold, and so removes a dangling
\* one; with no such version it does nothing. Its commit is checked here and may stall past the key's
\* release like any other, which its drive's lock orders.
HealCheck(d) ==
    /\ "heal" \notin Still
    /\ keyHolder = NoHolder
    /\ healing = NoHeal
    /\ Up(d)
    /\ driveLock[d] = NoHolder
    /\ \E v \in Versions :
           /\ v \in Readable \/ (Twin = "HealMinority" /\ Holding(v) # {})
           /\ drive[d] # v
           /\ healing' = [drive |-> d, to |-> v]
    /\ driveLock' = [driveLock EXCEPT ![d] = Heal]
    /\ UNCHANGED <<drive, keyHolder, phase, kind, coordinator, past, cancelled, orphan, acked, expect,
                   fresh, commit, down, downLeft, crashesLeft, current, readBad>>

HealCommit ==
    /\ healing # NoHeal
    /\ drive' = [drive EXCEPT ![healing.drive] = healing.to]
    /\ driveLock' = [driveLock EXCEPT ![healing.drive] = NoHolder]
    /\ fresh' = Spent(healing.drive)
    /\ healing' = NoHeal
    /\ UNCHANGED <<keyHolder, phase, kind, coordinator, past, cancelled, orphan, acked, expect, commit,
                   down, downLeft, crashesLeft, current, readBad>>

\* The reader: a GET waits while the key is held, then takes a version on N/2 drives, or fails.
Read ==
    /\ keyHolder = NoHolder
    /\ readBad' = (readBad \/ \E v \in Readable : v # current)
    /\ UNCHANGED <<drive, driveLock, keyHolder, phase, kind, coordinator, past, cancelled, orphan, acked,
                   expect, fresh, commit, down, downLeft, crashesLeft, healing, current>>

\* Every step that moves a held key toward its release.
Settling(w) ==
    \/ PassDeadline(w)
    \/ \E d \in Drives : Check(w, d) \/ Commit(w, d) \/ Stopped(w, d) \/ Revert(w, d)
    \/ Quorum(w)
    \/ ReleaseSuccess(w)
    \/ ReleaseFailed(w)

Next ==
    \/ \E w \in Writes :
           \/ Settling(w)
           \/ Cancel(w)
           \/ Crash(w)
           \/ \E c \in Coordinators, k \in {"put", "delete"} : Take(w, c, k)
    \/ \E h \in Hosts : HostDown(h) \/ HostUp(h)
    \/ \E d \in Drives : HealCheck(d)
    \/ HealCommit
    \/ Read

\* Stalled commits answer and hosts come back; nothing else is assumed.
Fairness ==
    /\ \A w \in Writes : WF_vars(Settling(w))
    /\ \A h \in Hosts : WF_vars(HostUp(h))
    /\ WF_vars(HealCommit)

Spec == Init /\ [][Next]_vars

LiveSpec == Spec /\ Fairness

\* Safety only: TLC may miss a liveness failure under symmetry.
WriteSymmetry == Permutations(Writes)

\* A write with nothing left to land or revert has no more say: only what it left on the drives
\* counts, so states differing only in its records are one state to TLC.
Over(w) ==
    /\ phase[w] \in {"success", "failed", "refused"}
    /\ \A d \in Drives : commit[w][d] \in {"none", "clear"} \/ (commit[w][d] = "committed" /\ phase[w] = "success")

\* A stamp matters only to a commit that can still begin.
LiveFresh(w) == [d \in Drives |-> commit[w][d] = "sent" /\ fresh[w][d]]

View ==
    <<drive, driveLock, keyHolder, down, downLeft, crashesLeft, healing, current, readBad,
      [w \in Writes |->
          IF Over(w) THEN <<phase[w], IF phase[w] = "refused" THEN "put" ELSE kind[w]>>
          ELSE <<phase[w], kind[w], coordinator[w], past[w], cancelled[w], orphan[w], acked[w],
                 expect[w], LiveFresh(w), commit[w]>>]>>

TypeOk ==
    /\ drive \in [Drives -> Versions]
    /\ keyHolder \in Writes \cup {NoHolder}
    /\ \A w \in Writes : phase[w] \in {"waiting", "running", "success", "failed", "refused"}
    /\ down \subseteq Hosts

\* FI-30: no read can return anything but the state the store decided, so a write took effect
\* before the next request on its key or never, and nothing earlier undoes a later state.
NoStaleQuorum == keyHolder = NoHolder => Readable \subseteq {current}

ReadsSeeCurrent == ~readBad

\* A write that ended short of its quorum can never be read, whatever still lands.
LateWritesNeverRead ==
    \A w \in Writes :
        phase[w] = "failed" /\ kind[w] = "put" =>
            Cardinality({d \in Drives : drive[d] = w \/ commit[w][d] = "checked"}) < ReadQuorum

\* FI-30: nothing past its deadline takes effect.
RefusedNeverLands ==
    \A w \in Writes :
        phase[w] = "refused" => \A d \in Drives : commit[w][d] = "none"

\* Section 2's rule (3) for a DELETE: once its key is released, nothing of a failed DELETE can land or
\* be reverted.
FailedDeleteSettled ==
    \A w \in Writes :
        phase[w] = "failed" /\ kind[w] = "delete" =>
            \A d \in Drives : commit[w][d] \in {"none", "clear"} \/ (commit[w][d] = "sent" /\ past[w])

\* FI-30's last clause, and the row's liveness: every held key is released once its stalled commits
\* answer.
HeldKeyReleased == \A w \in Writes : (keyHolder = w) ~> (keyHolder # w)

=============================================================================
