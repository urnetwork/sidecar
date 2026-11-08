---------------------------- MODULE StoreSettle ----------------------------
(***************************************************************************)
(* §19.6's deadline and settle rules (D-OPS-20): one key on a set of drives *)
(* at EC:4, 4 hosts of 2, read at N/2 and written at N/2 + 1.               *)
(*                                                                          *)
(* A write takes the key's lock, reads each reachable drive's version under *)
(* it and sends each drive a commit naming that version. A drive commit is  *)
(* a check step, which takes the drive's own lock, and a commit step, which *)
(* applies it and drops that lock; any time may pass between the two, a     *)
(* stall past the drive timeout included. The coordinator releases the key  *)
(* at a write quorum, or, once no more of its commits can begin, after      *)
(* reverting what it can so that fewer than N/2 drives may still hold the   *)
(* write. A dead coordinator's write is settled by the settler past its     *)
(* deadline; heal copies only a version N/2 drives hold.                    *)
(*                                                                          *)
(* The ghost variable current is the state every request must see: the      *)
(* version of the newest write the store decided took effect. FI-30 is      *)
(* NoStaleQuorum, ReadsSeeCurrent and LateWritesNeverRead, with             *)
(* HeldKeyReleased for its last clause.                                     *)
(*                                                                          *)
(* A deadline is one fact per write here, past by every clock: §19.6 bounds *)
(* each clock that sets or checks one within 50 ms, and a settler waits     *)
(* that margin out, so the model reads "its deadline passed" as past on     *)
(* every host.                                                              *)
(*                                                                          *)
(* Twin names a rule to break; a twin config sets it, and TLC must then     *)
(* refuse the model (run-tlc.sh). "none" is the design.                     *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    DriveCount,          \* N: 8 at EC:4
    DrivesPerHost,       \* 2
    Writes,              \* the writes on the key: model values
    CoordinatorCount,    \* coordinators: the handlers taking writes, one on each of hosts 1..n
    HostFailures,        \* how many times a host may go down in one behavior
    CoordinatorCrashes,  \* how many coordinators may die with a write under them
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

ASSUME
    /\ DriveCount % DrivesPerHost = 0
    /\ CoordinatorCount <= DriveCount \div DrivesPerHost
    /\ Twin \in {"none", "ReleaseOnCancel", "NoDeadlineCheck", "NoVersionCheck", "RevertBelowQuorumOnly",
                 "SettlerRevertsUnseen", "HealMinority", "NoDriveLock", "AbsentCountsForDelete"}

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
    commit,       \* commit[w][d]: "none", "sent", "checked", "committed", or "clear": stale or reverted
    down,         \* the hosts no request reaches
    downLeft,     \* host failures left
    crashesLeft,  \* coordinator crashes left
    healing,      \* heal's commit between its check and its commit step, or NoHeal
    current,      \* ghost: what every request must see
    readBad       \* ghost: a read returned anything else

vars == <<drive, driveLock, keyHolder, phase, kind, coordinator, past, cancelled, orphan, acked,
          expect, commit, down, downLeft, crashesLeft, healing, current, readBad>>

NoHeal == [drive |-> 0, to |-> Absent]

\* A drive a request reaches.
Up(d) == HostOf(d) \notin down

UpDrives == {d \in Drives : Up(d)}

\* The version a write's commit leaves on a drive.
NewVersion(w) == IF kind[w] = "delete" THEN Absent ELSE w

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
MayRevert(w) ==
    /\ ~acked[w]
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
                   expect, commit, down, downLeft, crashesLeft, healing, current, readBad>>

\* Rule (1): a request past its deadline when it holds the key's lock is refused. Otherwise its
\* coordinator reads every drive it reaches; a host that is down misses the write.
Take(w, c, k) ==
    /\ phase[w] = "waiting"
    /\ keyHolder = NoHolder
    /\ c \notin down
    /\ IF past[w] /\ Twin # "NoDeadlineCheck"
       THEN /\ phase' = [phase EXCEPT ![w] = "refused"]
            /\ UNCHANGED <<keyHolder, kind, coordinator, expect, commit>>
       ELSE /\ keyHolder' = w
            /\ phase' = [phase EXCEPT ![w] = "running"]
            /\ kind' = [kind EXCEPT ![w] = k]
            /\ coordinator' = [coordinator EXCEPT ![w] = c]
            /\ expect' = [expect EXCEPT ![w] = drive]
            /\ commit' = [commit EXCEPT ![w] = [d \in Drives |-> IF Up(d) THEN "sent" ELSE "none"]]
    /\ UNCHANGED <<drive, driveLock, past, cancelled, orphan, acked, down, downLeft, crashesLeft,
                   healing, current, readBad>>

\* Rule (2)'s check, under the drive's own lock: only while the drive still holds what the
\* coordinator read and its deadline has not passed, else stale, changing nothing. A cancel stops
\* a PUT on the coordinator's own drives. No request reaches a down host, but one may have reached
\* it first: a host that does not answer may still be committing.
Check(w, d) ==
    /\ commit[w][d] = "sent"
    /\ driveLock[d] = NoHolder \/ Twin = "NoDriveLock"
    /\ LET expired == past[w] /\ Twin # "NoDeadlineCheck"
           moved == drive[d] # expect[w][d] /\ Twin # "NoVersionCheck"
           absentDelete == kind[w] = "delete" /\ expect[w][d] = Absent /\ Twin # "AbsentCountsForDelete"
           stopped == cancelled[w] /\ kind[w] = "put" /\ HostOf(d) = coordinator[w]
       IN  IF expired \/ moved \/ stopped \/ absentDelete
           THEN /\ commit' = [commit EXCEPT ![w][d] = "clear"]
                /\ UNCHANGED driveLock
           ELSE /\ commit' = [commit EXCEPT ![w][d] = "checked"]
                /\ driveLock' = [driveLock EXCEPT ![d] = w]
    /\ UNCHANGED <<drive, keyHolder, phase, kind, coordinator, past, cancelled, orphan, acked, expect,
                   down, downLeft, crashesLeft, healing, current, readBad>>

\* The commit rename. It may land at any time after its check, on a host no request reaches, and
\* after its key's release.
Commit(w, d) ==
    /\ commit[w][d] = "checked"
    /\ drive' = [drive EXCEPT ![d] = NewVersion(w)]
    /\ driveLock' = [driveLock EXCEPT ![d] = NoHolder]
    /\ commit' = [commit EXCEPT ![w][d] = "committed"]
    /\ UNCHANGED <<keyHolder, phase, kind, coordinator, past, cancelled, orphan, acked, expect, down,
                   downLeft, crashesLeft, healing, current, readBad>>

\* A cancel ends the handler's waits and stops its own drives' PUT commits before their rename; it
\* reaches no other host and no DELETE. The deployed build also released the lock here.
Cancel(w) ==
    /\ phase[w] = "running"
    /\ ~cancelled[w]
    /\ cancelled' = [cancelled EXCEPT ![w] = TRUE]
    /\ IF Twin = "ReleaseOnCancel" /\ keyHolder = w /\ ~acked[w]
       THEN /\ keyHolder' = NoHolder
            /\ phase' = [phase EXCEPT ![w] = "failed"]
       ELSE UNCHANGED <<keyHolder, phase>>
    /\ UNCHANGED <<drive, driveLock, kind, coordinator, past, orphan, acked, expect, commit, down,
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
                   down, downLeft, crashesLeft, healing, current, readBad>>

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
                   expect, commit, down, downLeft, crashesLeft, healing, readBad>>

\* The coordinator may die between deciding and releasing; the settler then releases.
ReleaseSuccess(w) ==
    /\ keyHolder = w
    /\ acked[w]
    /\ orphan[w] => past[w]
    /\ keyHolder' = NoHolder
    /\ phase' = [phase EXCEPT ![w] = "success"]
    /\ UNCHANGED <<drive, driveLock, kind, coordinator, past, cancelled, orphan, acked, expect, commit,
                   down, downLeft, crashesLeft, healing, current, readBad>>

\* Rule (3)'s revert, by (2)'s check: only while the drive still holds this write. It goes on after
\* the key's release for a commit that landed late.
Revert(w, d) ==
    /\ commit[w][d] = "committed"
    /\ Up(d)
    /\ phase[w] \in {"running", "failed"}
    /\ phase[w] = "running" => MayRevert(w)
    /\ driveLock[d] = NoHolder
    /\ drive' = [drive EXCEPT ![d] = IF @ = NewVersion(w) THEN expect[w][d] ELSE @]
    /\ commit' = [commit EXCEPT ![w][d] = "clear"]
    /\ UNCHANGED <<driveLock, keyHolder, phase, kind, coordinator, past, cancelled, orphan, acked,
                   expect, down, downLeft, crashesLeft, healing, current, readBad>>

\* Rule (3)'s release of a write that can never be read.
ReleaseFailed(w) ==
    /\ keyHolder = w
    /\ MayRevert(w)
    /\ Cardinality(MayHold(w)) < ReadQuorum \/
           (Twin = "RevertBelowQuorumOnly" /\ Cardinality(MayHold(w)) < WriteQuorum)
    /\ keyHolder' = NoHolder
    /\ phase' = [phase EXCEPT ![w] = "failed"]
    /\ UNCHANGED <<drive, driveLock, kind, coordinator, past, cancelled, orphan, acked, expect, commit,
                   down, downLeft, crashesLeft, healing, current, readBad>>

\* Rule (4): a coordinator dies with a write under it. No lock of it expires.
Crash(w) ==
    /\ phase[w] = "running"
    /\ ~orphan[w]
    /\ crashesLeft > 0
    /\ crashesLeft' = crashesLeft - 1
    /\ orphan' = [orphan EXCEPT ![w] = TRUE]
    /\ UNCHANGED <<drive, driveLock, keyHolder, phase, kind, coordinator, past, cancelled, acked, expect,
                   commit, down, downLeft, healing, current, readBad>>

HostDown(h) ==
    /\ h \notin down
    /\ downLeft > 0
    /\ downLeft' = downLeft - 1
    /\ down' = down \cup {h}
    /\ UNCHANGED <<drive, driveLock, keyHolder, phase, kind, coordinator, past, cancelled, orphan, acked,
                   expect, commit, crashesLeft, healing, current, readBad>>

HostUp(h) ==
    /\ h \in down
    /\ down' = down \ {h}
    /\ UNCHANGED <<drive, driveLock, keyHolder, phase, kind, coordinator, past, cancelled, orphan, acked,
                   expect, commit, downLeft, crashesLeft, healing, current, readBad>>

\* Rule (6): a heal takes the key, copies only a version N/2 drives hold, and so removes a dangling
\* one; with no such version it does nothing. Its commit is checked here and may stall past the key's
\* release like any other, which its drive's lock orders.
HealCheck(d) ==
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
                   commit, down, downLeft, crashesLeft, current, readBad>>

HealCommit ==
    /\ healing # NoHeal
    /\ drive' = [drive EXCEPT ![healing.drive] = healing.to]
    /\ driveLock' = [driveLock EXCEPT ![healing.drive] = NoHolder]
    /\ healing' = NoHeal
    /\ UNCHANGED <<keyHolder, phase, kind, coordinator, past, cancelled, orphan, acked, expect, commit,
                   down, downLeft, crashesLeft, current, readBad>>

\* The reader: a GET waits while the key is held, then takes a version on N/2 drives, or fails.
Read ==
    /\ keyHolder = NoHolder
    /\ readBad' = (readBad \/ \E v \in Readable : v # current)
    /\ UNCHANGED <<drive, driveLock, keyHolder, phase, kind, coordinator, past, cancelled, orphan, acked,
                   expect, commit, down, downLeft, crashesLeft, healing, current>>

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

View ==
    <<drive, driveLock, keyHolder, down, downLeft, crashesLeft, healing, current, readBad,
      [w \in Writes |->
          IF Over(w) THEN phase[w]
          ELSE <<phase[w], kind[w], coordinator[w], past[w], cancelled[w], orphan[w], acked[w],
                 expect[w], commit[w]>>]>>

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

\* FI-30's last clause, and the row's liveness: every held key is released once its stalled commits
\* answer.
HeldKeyReleased == \A w \in Writes : (keyHolder = w) ~> (keyHolder # w)

=============================================================================
