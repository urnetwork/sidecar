-------------------------------- MODULE EvsGc --------------------------------
(***************************************************************************)
(* DESIGN-DETAILS.md section 2's orphan GC: one repo's segments, the refs   *)
(* whose pushes adopt them, the batch records those pushes leave, the       *)
(* evacuator that settles each record, and segment GC, with the writes that *)
(* §19.6 lets stall: a head write whose drive commits stall holds its key   *)
(* and lands at any later time or never, and so does GC's DELETE.           *)
(*                                                                          *)
(* The repo has two refs: "old" has a head at the start, "new" has none, so *)
(* its first commit creates the head If-None-Match. Each attempt is one     *)
(* push id, holding a receipt for a segment it uploaded.                    *)
(*                                                                          *)
(* The design (Twin "none"):                                                *)
(*                                                                          *)
(*   record    an attempt writes its batch record, in the minute of its     *)
(*             last check, before it issues its head write (§11.8 steps 6   *)
(*             and 7)                                                       *)
(*   evacuate  a record's minute is settled once it is EvacAge old: a       *)
(*             committed record is kept, its container and pidx/ entry      *)
(*             written before its batch goes; a pending one has its ref     *)
(*             fenced first, a ref with no head by a placeholder head       *)
(*             created with its fence raised, and is then dead              *)
(*   horizon   GC deletes a segment only once no batch record is left in a  *)
(*             minute at or before the last one a receipt for it could have *)
(*             been checked in, and that minute is EvacAge old; it reads    *)
(*             the introduced segments after that, and deletes only the     *)
(*             object it listed (x-ur-if-unmodified-ms)                     *)
(*                                                                          *)
(* GC raises no fence of its own. Twin "Written" is §11.13's orphans row as *)
(* DESIGN.md states it on 2026-11-10: a 25 h mark, a fence on each ref with *)
(* a head idle since the 24 h mark, the store's deadline, a second check    *)
(* and an unconditional DELETE.                                             *)
(*                                                                          *)
(* What the model abstracts:                                                *)
(* - Time is ticks. A receipt is adopted for ReceiptLife ticks, and a tick  *)
(*   ends every short timer: a head write issued and not landed never will  *)
(*   (its deadline), unless its drive commits stalled, and an attempt that  *)
(*   checked and has not issued checks again (§11.8's 5 s rule). The        *)
(*   seconds between a check and its record, a receipt's stamp and the      *)
(*   object's LastModified, the clocks' 50 ms and a minute's length are the *)
(*   ASSUME's arithmetic, in the design's numbers.                          *)
(* - A paused attempt is a process stopped after its last clock check: it   *)
(*   sends its head write whenever it wakes, with a deadline it stamps then.*)
(* - A fence ends every attempt on its ref that arrived before it: such an  *)
(*   attempt holds the head as it read it before the fence, so its write    *)
(*   fails, and its next read of the head ends it (§11.8's fence row).      *)
(* - A record resolves dead only by its ref's fence. §11.8's other rule, a  *)
(*   head past its base's reach, is EvsCommit.tla's.                        *)
(*                                                                          *)
(* Twin names a rule to break; a twin config must make TLC refuse the model *)
(* with the invariant its cfg names.                                        *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Attempts,     \* pushes, one attempt each: model values
    Segments,     \* segment ids: model values
    Gcs,          \* GC runs that may be alive at once, a stalled one beside its successor: model values
    MaxTime,      \* ticks in one behavior
    ReceiptLife,  \* ticks a receipt is adopted for: 24 h
    EvacAge,      \* a minute is evacuated once this many ticks old: 25 h
    OrphanAge,    \* Twin "Written": GC's 25 h mark, in ticks
    MaxUploads,   \* uploads of one segment id in one behavior
    MaxStalls,    \* writes whose drive commits stall
    MaxPauses,    \* attempts stopped between their last check and their head write
    MaxCrashes,   \* evacuation runs killed at a step
    Twin          \* "none", or the rule a twin config breaks

\* The margins, in ms, on the design's numbers: the last minute directory that can hold a record
\* adopting a segment starts no later than the segment's LastModified plus AdoptionBound.
ReceiptMs == 24 * 3600 * 1000      \* 5h: a receipt under 24 h old by evs's clock
StampLagMs == 100                  \* upload_ms is evs's clock before the PUT, or LastModified: two clocks' 50 ms
StepSevenMs == 5000                \* a record is written, and step 7 issued, within 5 s of step 4's reads
ClockMs == 50                      \* each clock that checks an age or names a minute
MinuteMs == 60 * 1000              \* a batch key names the minute it opened in
AdoptionBoundMs == ReceiptMs + 2 * MinuteMs

ASSUME
    /\ ReceiptMs + StampLagMs + StepSevenMs + 2 * ClockMs + MinuteMs <= AdoptionBoundMs
    /\ ReceiptLife >= 1
    /\ EvacAge >= 1
    /\ Twin \in {"none", "Written", "GcIgnoresHorizon", "GcReadsIndexFirst", "UnconditionalDelete",
                 "FenceSkipsAbsentHead", "PendingStaysOnAbsentHead", "RecordAfterPut",
                 "DeleteBeforeIndex", "AdoptsOldReceipt"}

OldRef == "old"
NewRef == "new"
Refs == {OldRef, NewRef}

NoOne == "no one"
NoSegment == "no segment"
NoMinute == MaxTime + 1

VARIABLES
    now,          \* the tick
    head,         \* head[r]: whether it exists, its version, its fence, the tick of its last write
    held,         \* held[r]: the attempt whose stalled head write holds the key, or NoOne
    seg,          \* seg[s]: whether it is stored, its LastModified tick, how many times it was uploaded
    segHeld,      \* segHeld[s]: the GC run whose stalled DELETE holds the key, or NoOne
    att,          \* att[a]: one attempt
    rec,          \* batch records not yet evacuated: [att, minute]
    packed,       \* attempts whose committed record a container holds
    pidx,         \* segments the pidx/ entries say a committed record introduced
    committed,    \* attempts whose push a head names
    evac,         \* the evacuator's job
    gc,           \* gc[g]: one GC run
    uploadsLeft,  \* uploadsLeft[s]
    stallsLeft,
    pausesLeft,
    crashesLeft,
    gcDecided,    \* ghost: [seg, at] GC decided to delete
    lost          \* ghost: committed attempts whose segment a GC run deleted under them

vars == <<now, head, held, seg, segHeld, att, rec, packed, pidx, committed, evac, gc, uploadsLeft,
          stallsLeft, pausesLeft, crashesLeft, gcDecided, lost>>

NoAttempt == [stage |-> "idle", ref |-> OldRef, seg |-> NoSegment, at |-> 0, etag |-> <<FALSE, 0, 0>>,
              fenced |-> FALSE]
NoEvac == [stage |-> "idle", att |-> NoOne, minute |-> 0, fenced |-> FALSE]
NoGc == [stage |-> "idle", seg |-> NoSegment, at |-> 0, todo |-> {}]

\* An ETag never repeats: every head write raises the version or the fence.
Etag(h) == <<h.exists, h.version, h.fence>>

\* A receipt passes 5h while its segment's upload is under ReceiptLife ticks old.
ReceiptValid(a) == Twin = "AdoptsOldReceipt" \/ now - att[a].at < ReceiptLife

\* The last tick a receipt for an object uploaded at tick t can pass a check in, and so the last
\* minute a record adopting it can be filed under.
AdoptionBound(t) == t + ReceiptLife - 1

Records(a) == {r \in rec : r.att = a}

Init ==
    /\ now = 0
    /\ head = [r \in Refs |-> [exists |-> r = OldRef, version |-> IF r = OldRef THEN 1 ELSE 0,
                               fence |-> 0, written |-> 0]]
    /\ held = [r \in Refs |-> NoOne]
    /\ seg = [s \in Segments |-> [stored |-> FALSE, at |-> 0, uploads |-> 0]]
    /\ segHeld = [s \in Segments |-> NoOne]
    /\ att = [a \in Attempts |-> NoAttempt]
    /\ rec = {}
    /\ packed = {}
    /\ pidx = {}
    /\ committed = {}
    /\ evac = NoEvac
    /\ gc = [g \in Gcs |-> NoGc]
    /\ uploadsLeft = [s \in Segments |-> MaxUploads]
    /\ stallsLeft = MaxStalls
    /\ pausesLeft = MaxPauses
    /\ crashesLeft = MaxCrashes
    /\ gcDecided = {}
    /\ lost = {}

(***************************************************************************)
(* Uploads and pushes.                                                      *)
(***************************************************************************)

\* A segment PUT that stores the segment: If-None-Match, so only while it is absent, and after any
\* DELETE of it has settled. A re-upload of a stored one changes nothing and is the receipt below.
Upload(s) ==
    /\ ~seg[s].stored
    /\ segHeld[s] = NoOne
    /\ uploadsLeft[s] > 0
    /\ uploadsLeft' = [uploadsLeft EXCEPT ![s] = @ - 1]
    /\ seg' = [seg EXCEPT ![s] = [stored |-> TRUE, at |-> now, uploads |-> @.uploads + 1]]
    /\ UNCHANGED <<now, head, held, segHeld, att, rec, packed, pidx, committed, evac, gc, stallsLeft,
                   pausesLeft, crashesLeft, gcDecided, lost>>

\* The client takes its receipt, upload_ms the object's LastModified, and its push reaches evs on a
\* ref: step 4 reads the head. A receipt may be held any time before the push is sent.
Receipt(a, s) ==
    /\ att[a].stage = "idle"
    /\ seg[s].stored
    /\ segHeld[s] = NoOne
    /\ att' = [att EXCEPT ![a] = [NoAttempt EXCEPT !.stage = "client", !.seg = s, !.at = seg[s].at]]
    /\ UNCHANGED <<now, head, held, seg, segHeld, rec, packed, pidx, committed, evac, gc, uploadsLeft,
                   stallsLeft, pausesLeft, crashesLeft, gcDecided, lost>>

Arrive(a, r) ==
    /\ att[a].stage = "client"
    /\ held[r] = NoOne
    /\ att' = [att EXCEPT ![a].stage = "read", ![a].ref = r, ![a].etag = Etag(head[r])]
    /\ UNCHANGED <<now, head, held, seg, segHeld, rec, packed, pidx, committed, evac, gc, uploadsLeft,
                   stallsLeft, pausesLeft, crashesLeft, gcDecided, lost>>

\* Step 5h, then step 6: the record, filed under this tick's minute, written once per attempt. An
\* attempt whose receipt is too old is refused and ends.
CheckAndRecord(a) ==
    /\ att[a].stage = "read"
    /\ IF ReceiptValid(a)
       THEN /\ att' = [att EXCEPT ![a].stage = "ready"]
            /\ rec' = IF Records(a) = {} /\ Twin # "RecordAfterPut"
                      THEN rec \cup {[att |-> a, minute |-> now]} ELSE rec
       ELSE /\ att' = [att EXCEPT ![a].stage = "done"]
            /\ UNCHANGED rec
    /\ UNCHANGED <<now, head, held, seg, segHeld, packed, pidx, committed, evac, gc, uploadsLeft,
                   stallsLeft, pausesLeft, crashesLeft, gcDecided, lost>>

\* Step 7 is issued, within the tick of its check.
Issue(a) ==
    /\ att[a].stage = "ready"
    /\ att' = [att EXCEPT ![a].stage = "put"]
    /\ UNCHANGED <<now, head, held, seg, segHeld, rec, packed, pidx, committed, evac, gc, uploadsLeft,
                   stallsLeft, pausesLeft, crashesLeft, gcDecided, lost>>

\* A process stopped after its last check wakes at any later time and sends its write then.
Pause(a) ==
    /\ att[a].stage = "ready"
    /\ pausesLeft > 0
    /\ pausesLeft' = pausesLeft - 1
    /\ att' = [att EXCEPT ![a].stage = "paused"]
    /\ UNCHANGED <<now, head, held, seg, segHeld, rec, packed, pidx, committed, evac, gc, uploadsLeft,
                   stallsLeft, crashesLeft, gcDecided, lost>>

Wake(a) ==
    /\ att[a].stage = "paused"
    /\ att' = [att EXCEPT ![a].stage = "put"]
    /\ UNCHANGED <<now, head, held, seg, segHeld, rec, packed, pidx, committed, evac, gc, uploadsLeft,
                   stallsLeft, pausesLeft, crashesLeft, gcDecided, lost>>

\* The head after a commit: created If-None-Match on a ref with none, else If-Match.
Commits(a) ==
    LET r == att[a].ref
    IN  /\ head' = [head EXCEPT ![r] = [exists |-> TRUE, version |-> @.version + 1, fence |-> @.fence,
                                        written |-> now]]
        /\ committed' = committed \cup {a}
        /\ lost' = IF seg[att[a].seg].stored THEN lost ELSE lost \cup {a}

\* The write lands, or fails its precondition and the attempt reads the head again.
Land(a) ==
    LET r == att[a].ref
    IN  /\ att[a].stage = "put"
        /\ held[r] = NoOne
        /\ IF Etag(head[r]) = att[a].etag
           THEN /\ Commits(a)
                /\ att' = [att EXCEPT ![a].stage = "done"]
           ELSE /\ att' = [att EXCEPT ![a].stage = "reread"]
                /\ UNCHANGED <<head, committed, lost>>
        /\ UNCHANGED <<now, held, seg, segHeld, rec, packed, pidx, evac, gc, uploadsLeft, stallsLeft,
                       pausesLeft, crashesLeft, gcDecided>>

\* Its drive commits stall after their checks: it holds the head's key, which no request passes,
\* and §19.6 settles it at any later time, landed or reverted.
Stall(a) ==
    LET r == att[a].ref
    IN  /\ att[a].stage = "put"
        /\ held[r] = NoOne
        /\ Etag(head[r]) = att[a].etag
        /\ stallsLeft > 0
        /\ stallsLeft' = stallsLeft - 1
        /\ held' = [held EXCEPT ![r] = a]
        /\ att' = [att EXCEPT ![a].stage = "stalled"]
        /\ UNCHANGED <<now, head, seg, segHeld, rec, packed, pidx, committed, evac, gc, uploadsLeft,
                       pausesLeft, crashesLeft, gcDecided, lost>>

StallLands(a) ==
    LET r == att[a].ref
    IN  /\ att[a].stage = "stalled"
        /\ held[r] = a
        /\ Commits(a)
        /\ held' = [held EXCEPT ![r] = NoOne]
        /\ att' = [att EXCEPT ![a].stage = "done"]
        /\ UNCHANGED <<now, seg, segHeld, rec, packed, pidx, evac, gc, uploadsLeft, stallsLeft,
                       pausesLeft, crashesLeft, gcDecided>>

StallReverts(a) ==
    LET r == att[a].ref
    IN  /\ att[a].stage = "stalled"
        /\ held[r] = a
        /\ held' = [held EXCEPT ![r] = NoOne]
        /\ att' = [att EXCEPT ![a].stage = "reread"]
        /\ UNCHANGED <<now, head, seg, segHeld, rec, packed, pidx, committed, evac, gc, uploadsLeft,
                       stallsLeft, pausesLeft, crashesLeft, gcDecided, lost>>

\* The 412 and unknown rows: the head again from the cluster. A fence raised since the attempt
\* arrived ends it; otherwise step 5 runs again on the reread head, its record kept.
Reread(a) ==
    LET r == att[a].ref
    IN  /\ att[a].stage = "reread"
        /\ held[r] = NoOne
        /\ att' = [att EXCEPT ![a].stage = IF att[a].fenced THEN "done" ELSE "read",
                              ![a].etag = Etag(head[r])]
        /\ UNCHANGED <<now, head, held, seg, segHeld, rec, packed, pidx, committed, evac, gc, uploadsLeft,
                       stallsLeft, pausesLeft, crashesLeft, gcDecided, lost>>

(***************************************************************************)
(* The evacuator (§11.13's resolve, move and delete rows).                  *)
(***************************************************************************)

EvacStart(r) ==
    /\ evac.stage = "idle"
    /\ r \in rec
    /\ now - r.minute >= EvacAge
    /\ evac' = [NoEvac EXCEPT !.stage = "resolve", !.att = r.att, !.minute = r.minute]
    /\ UNCHANGED <<now, head, held, seg, segHeld, att, rec, packed, pidx, committed, gc, uploadsLeft,
                   stallsLeft, pausesLeft, crashesLeft, gcDecided, lost>>

\* Resolve reads the ref's head from the cluster, which waits on a held key: committed, dead once
\* this run's fence stands on the head it reads, else pending.
EvacResolve ==
    LET a == evac.att
        r == att[a].ref
        next == CASE a \in committed -> IF Twin = "DeleteBeforeIndex" THEN "delete" ELSE "keep"
                  [] evac.fenced -> "drop"
                  [] ~head[r].exists /\ Twin = "FenceSkipsAbsentHead" -> "drop"
                  [] ~head[r].exists /\ Twin = "PendingStaysOnAbsentHead" -> "idle"
                  [] OTHER -> "fence"
    IN  /\ evac.stage = "resolve"
        /\ held[r] = NoOne
        /\ evac' = IF next = "idle" THEN NoEvac ELSE [evac EXCEPT !.stage = next]
        /\ UNCHANGED <<now, head, held, seg, segHeld, att, rec, packed, pidx, committed, gc, uploadsLeft,
                       stallsLeft, pausesLeft, crashesLeft, gcDecided, lost>>

\* Pending: one head CAS raises the ref's fence; a ref with no head gets a placeholder head, created
\* If-None-Match at version 0 with its fence raised. Every attempt that reached the ref before it is
\* ended by it: its write names the head as it was, and its next read ends it.
EvacFence ==
    LET r == att[evac.att].ref
    IN  /\ evac.stage = "fence"
        /\ held[r] = NoOne
        /\ head' = [head EXCEPT ![r] = [exists |-> TRUE, version |-> @.version, fence |-> @.fence + 1,
                                        written |-> now]]
        /\ att' = [a \in Attempts |->
               IF att[a].ref = r /\ att[a].stage \in {"read", "ready", "put", "paused", "reread"}
               THEN [att[a] EXCEPT !.fenced = TRUE] ELSE att[a]]
        /\ evac' = [evac EXCEPT !.stage = "resolve", !.fenced = TRUE]
        /\ UNCHANGED <<now, held, seg, segHeld, rec, packed, pidx, committed, gc, uploadsLeft, stallsLeft,
                       pausesLeft, crashesLeft, gcDecided, lost>>

\* Committed: its container and pidx/ entry, which names the segment it introduced, before its batch.
EvacKeep ==
    LET a == evac.att
    IN  /\ evac.stage = "keep"
        /\ packed' = packed \cup {a}
        /\ pidx' = pidx \cup {att[a].seg}
        /\ evac' = IF Twin = "DeleteBeforeIndex" THEN NoEvac ELSE [evac EXCEPT !.stage = "delete"]
        /\ UNCHANGED <<now, head, held, seg, segHeld, att, rec, committed, gc, uploadsLeft, stallsLeft,
                       pausesLeft, crashesLeft, gcDecided, lost>>

\* The batch goes: a kept record's after its entry (I-EVS-7), a dead one's at once.
EvacDelete ==
    /\ evac.stage \in {"delete", "drop"}
    /\ rec' = rec \ {[att |-> evac.att, minute |-> evac.minute]}
    /\ evac' = IF evac.stage = "delete" /\ Twin = "DeleteBeforeIndex"
               THEN [evac EXCEPT !.stage = "keep"] ELSE NoEvac
    /\ UNCHANGED <<now, head, held, seg, segHeld, att, packed, pidx, committed, gc, uploadsLeft,
                   stallsLeft, pausesLeft, crashesLeft, gcDecided, lost>>

\* A killed run restarts the minute: what it wrote stands.
EvacCrash ==
    /\ evac.stage # "idle"
    /\ crashesLeft > 0
    /\ crashesLeft' = crashesLeft - 1
    /\ evac' = NoEvac
    /\ UNCHANGED <<now, head, held, seg, segHeld, att, rec, packed, pidx, committed, gc, uploadsLeft,
                   stallsLeft, pausesLeft, gcDecided, lost>>

(***************************************************************************)
(* Segment GC: the design's horizon rule.                                   *)
(***************************************************************************)

\* The nightly LIST of seg/: an object and its LastModified.
GcList(g, s) ==
    /\ Twin # "Written"
    /\ gc[g].stage = "idle"
    /\ seg[s].stored
    /\ segHeld[s] = NoOne
    /\ gc' = [gc EXCEPT ![g] = [NoGc EXCEPT !.stage = "listed", !.seg = s, !.at = seg[s].at]]
    /\ UNCHANGED <<now, head, held, seg, segHeld, att, rec, packed, pidx, committed, evac, uploadsLeft,
                   stallsLeft, pausesLeft, crashesLeft, gcDecided, lost>>

\* The horizon, from one LIST of pb/: no batch record is left in a minute at or before the object's
\* adoption bound, and that minute is old enough to have been evacuated, so none can appear there.
PastHorizon(t) ==
    IF Twin = "GcIgnoresHorizon" THEN now - t >= OrphanAge
    ELSE /\ now - EvacAge >= AdoptionBound(t)
         /\ \A r \in rec : r.minute > AdoptionBound(t)

\* The design reads the horizon, then the pidx/ entries. The twin reads the entries first.
GcHorizon(g) ==
    /\ gc[g].stage = IF Twin = "GcReadsIndexFirst" THEN "indexed" ELSE "listed"
    /\ PastHorizon(gc[g].at)
    /\ gc' = [gc EXCEPT ![g].stage = IF Twin = "GcReadsIndexFirst" THEN "decided" ELSE "horizon"]
    /\ gcDecided' = IF Twin = "GcReadsIndexFirst"
                    THEN gcDecided \cup {[seg |-> gc[g].seg, at |-> gc[g].at]} ELSE gcDecided
    /\ UNCHANGED <<now, head, held, seg, segHeld, att, rec, packed, pidx, committed, evac, uploadsLeft,
                   stallsLeft, pausesLeft, crashesLeft, lost>>

GcIndex(g) ==
    /\ gc[g].stage = IF Twin = "GcReadsIndexFirst" THEN "listed" ELSE "horizon"
    /\ IF gc[g].seg \in pidx
       THEN /\ gc' = [gc EXCEPT ![g] = NoGc]
            /\ UNCHANGED gcDecided
       ELSE /\ gc' = [gc EXCEPT ![g].stage = IF Twin = "GcReadsIndexFirst" THEN "indexed" ELSE "decided"]
            /\ gcDecided' = IF Twin = "GcReadsIndexFirst" THEN gcDecided
                            ELSE gcDecided \cup {[seg |-> gc[g].seg, at |-> gc[g].at]}
    /\ UNCHANGED <<now, head, held, seg, segHeld, att, rec, packed, pidx, committed, evac, uploadsLeft,
                   stallsLeft, pausesLeft, crashesLeft, lost>>

\* What the store does with the DELETE once it holds the key: only the object listed goes
\* (x-ur-if-unmodified-ms: its LastModified); the twin and the text as written delete whatever is there.
Deletes(g) ==
    /\ seg[gc[g].seg].stored
    /\ Twin \in {"UnconditionalDelete", "Written"} \/ seg[gc[g].seg].at = gc[g].at

AfterDelete(g) ==
    LET s == gc[g].seg
    IN  IF Deletes(g)
        THEN /\ seg' = [seg EXCEPT ![s].stored = FALSE]
             /\ lost' = lost \cup {a \in committed : att[a].seg = s}
        ELSE UNCHANGED <<seg, lost>>

\* A run sits decided for as long as it likes: a stalled process deletes late.
GcDelete(g) ==
    /\ gc[g].stage = "decided"
    /\ segHeld[gc[g].seg] = NoOne
    /\ AfterDelete(g)
    /\ gc' = [gc EXCEPT ![g] = NoGc]
    /\ UNCHANGED <<now, head, held, segHeld, att, rec, packed, pidx, committed, evac, uploadsLeft,
                   stallsLeft, pausesLeft, crashesLeft, gcDecided>>

\* The DELETE's drive commits stall: it holds the segment's key until §19.6 settles it, taking
\* effect before the next request on the key or never.
GcDeleteStalls(g) ==
    /\ gc[g].stage = "decided"
    /\ segHeld[gc[g].seg] = NoOne
    /\ stallsLeft > 0
    /\ stallsLeft' = stallsLeft - 1
    /\ segHeld' = [segHeld EXCEPT ![gc[g].seg] = g]
    /\ gc' = [gc EXCEPT ![g].stage = "deleting"]
    /\ UNCHANGED <<now, head, held, seg, att, rec, packed, pidx, committed, evac, uploadsLeft, pausesLeft, crashesLeft,
                   gcDecided, lost>>

GcStallSettles(g, lands) ==
    /\ gc[g].stage = "deleting"
    /\ IF lands THEN AfterDelete(g) ELSE UNCHANGED <<seg, lost>>
    /\ segHeld' = [segHeld EXCEPT ![gc[g].seg] = NoOne]
    /\ gc' = [gc EXCEPT ![g] = NoGc]
    /\ UNCHANGED <<now, head, held, att, rec, packed, pidx, committed, evac, uploadsLeft, stallsLeft,
                   pausesLeft, crashesLeft, gcDecided>>

\* A run gives up before it decides.
GcAbort(g) ==
    /\ gc[g].stage \in {"listed", "horizon", "indexed", "fence"}
    /\ gc' = [gc EXCEPT ![g] = NoGc]
    /\ UNCHANGED <<now, head, held, seg, segHeld, att, rec, packed, pidx, committed, evac, uploadsLeft,
                   stallsLeft, pausesLeft, crashesLeft, gcDecided, lost>>

(***************************************************************************)
(* Segment GC as §11.13's orphans row states it (Twin "Written").           *)
(***************************************************************************)

\* A committed push of the repo introduced it: pidx/ entries, and records still in batches.
Introduced(s) == \E a \in committed : att[a].seg = s

\* The 25 h mark; the refs to fence are those with a head written before LastModified + 24 h.
WrittenMark(g, s) ==
    /\ Twin = "Written"
    /\ gc[g].stage = "idle"
    /\ seg[s].stored
    /\ segHeld[s] = NoOne
    /\ now - seg[s].at >= OrphanAge
    /\ ~Introduced(s)
    /\ gc' = [gc EXCEPT ![g] = [stage |-> "fence", seg |-> s, at |-> seg[s].at,
                                todo |-> {r \in Refs : head[r].exists /\ head[r].written < seg[s].at + ReceiptLife}]]
    /\ UNCHANGED <<now, head, held, seg, segHeld, att, rec, packed, pidx, committed, evac, uploadsLeft,
                   stallsLeft, pausesLeft, crashesLeft, gcDecided, lost>>

WrittenFence(g, r) ==
    /\ Twin = "Written"
    /\ gc[g].stage = "fence"
    /\ r \in gc[g].todo
    /\ held[r] = NoOne
    /\ head' = [head EXCEPT ![r].fence = @ + 1, ![r].written = now]
    /\ att' = [a \in Attempts |->
           IF att[a].ref = r /\ att[a].stage \in {"read", "ready", "put", "paused", "reread"}
           THEN [att[a] EXCEPT !.fenced = TRUE] ELSE att[a]]
    /\ gc' = [gc EXCEPT ![g].todo = @ \ {r}]
    /\ UNCHANGED <<now, held, seg, segHeld, rec, packed, pidx, committed, evac, uploadsLeft, stallsLeft,
                   pausesLeft, crashesLeft, gcDecided, lost>>

\* Past the store's request deadline, so no write issued before it is still in flight unstalled:
\* the repo's commits again.
WrittenSecondCheck(g) ==
    /\ Twin = "Written"
    /\ gc[g].stage = "fence"
    /\ gc[g].todo = {}
    /\ \A a \in Attempts : att[a].stage # "put"
    /\ IF Introduced(gc[g].seg)
       THEN /\ gc' = [gc EXCEPT ![g] = NoGc]
            /\ UNCHANGED gcDecided
       ELSE /\ gc' = [gc EXCEPT ![g].stage = "decided"]
            /\ gcDecided' = gcDecided \cup {[seg |-> gc[g].seg, at |-> gc[g].at]}
    /\ UNCHANGED <<now, head, held, seg, segHeld, att, rec, packed, pidx, committed, evac, uploadsLeft,
                   stallsLeft, pausesLeft, crashesLeft, lost>>

(***************************************************************************)
(* Time.                                                                    *)
(***************************************************************************)

\* A tick ends every short timer: a write issued and not landed never will, and an attempt that
\* checked and has not issued checks again. A stalled write and a paused process outlast it.
Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ att' = [a \in Attempts |->
           IF att[a].stage \in {"ready", "put"} THEN [att[a] EXCEPT !.stage = "reread"] ELSE att[a]]
    /\ UNCHANGED <<head, held, seg, segHeld, rec, packed, pidx, committed, evac, gc, uploadsLeft,
                   stallsLeft, pausesLeft, crashesLeft, gcDecided, lost>>

Next ==
    \/ \E s \in Segments : Upload(s)
    \/ \E a \in Attempts :
           \/ \E s \in Segments : Receipt(a, s)
           \/ \E r \in Refs : Arrive(a, r)
           \/ CheckAndRecord(a)
           \/ Issue(a)
           \/ Pause(a)
           \/ Wake(a)
           \/ Land(a)
           \/ Stall(a)
           \/ StallLands(a)
           \/ StallReverts(a)
           \/ Reread(a)
    \/ \E r \in rec : EvacStart(r)
    \/ EvacResolve
    \/ EvacFence
    \/ EvacKeep
    \/ EvacDelete
    \/ EvacCrash
    \/ \E g \in Gcs :
           \/ \E s \in Segments : GcList(g, s) \/ WrittenMark(g, s)
           \/ GcHorizon(g)
           \/ GcIndex(g)
           \/ GcDelete(g)
           \/ GcDeleteStalls(g)
           \/ \E lands \in BOOLEAN : GcStallSettles(g, lands)
           \/ GcAbort(g)
           \/ \E r \in Refs : WrittenFence(g, r)
           \/ WrittenSecondCheck(g)
    \/ Tick

Spec == Init /\ [][Next]_vars

\* The evacuator keeps working, stalled writes settle, and time passes; nothing else is assumed.
EvacStep == (\E r \in rec : EvacStart(r)) \/ EvacResolve \/ EvacFence \/ EvacKeep \/ EvacDelete

Fairness ==
    /\ WF_vars(EvacStep)
    /\ WF_vars(Tick)
    /\ \A a \in Attempts : WF_vars(StallLands(a) \/ StallReverts(a))

LiveSpec == Spec /\ Fairness

Symmetry == Permutations(Attempts) \cup Permutations(Gcs)

TypeOk ==
    /\ now \in 0..MaxTime
    /\ \A r \in Refs : held[r] \in Attempts \cup {NoOne}
    /\ \A s \in Segments : segHeld[s] \in Gcs \cup {NoOne}
    /\ \A a \in Attempts : att[a].stage \in {"idle", "client", "read", "ready", "put", "paused", "stalled",
                                             "reread", "done"}
    /\ committed \subseteq Attempts
    /\ packed \subseteq Attempts

\* I-EVS-1 for segments: no committed head ever names a deleted segment.
ClosureHolds == lost = {}

\* I-EVS-5: no segment becomes reachable after GC decided to delete it.
GcSafe == \A d \in gcDecided : ~\E a \in committed : att[a].seg = d.seg /\ att[a].at = d.at

\* I-EVS-7 and I-EVS-2: a committed push's record is in its batch or in a container.
RecordsKept == \A a \in committed : Records(a) # {} \/ a \in packed

\* A placeholder head exists only with its fence raised.
HeadsRise == \A r \in Refs : head[r].exists /\ head[r].version = 0 => head[r].fence > 0

\* Every record old enough to evacuate before the behavior ends leaves its batch: no pending record
\* stays for want of a head to fence.
RecordsLeave ==
    \A a \in Attempts, m \in 0..MaxTime :
        ([att |-> a, minute |-> m] \in rec /\ m + EvacAge <= MaxTime) ~> ([att |-> a, minute |-> m] \notin rec)

=============================================================================
