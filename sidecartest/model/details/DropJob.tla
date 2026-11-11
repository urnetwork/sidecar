------------------------------- MODULE DropJob -------------------------------
(***************************************************************************)
(* DESIGN-DETAILS.md section 10's drop job: one repo, one DROP on ref A     *)
(* that lists the one version naming segment s1, the pushes on other refs   *)
(* that can still come to name s1, the batch records those pushes leave,    *)
(* the evacuator that settles each record, and the job that resolves,       *)
(* marks, verifies and deletes, with the writes §19.6 lets stall: a head    *)
(* write whose drive commits stall holds its key and lands at any later     *)
(* time or never.                                                           *)
(*                                                                          *)
(* The repo has four refs. A holds the listed version and takes the DROP.   *)
(* B is a file-mode ref with a head. N has no head, so its first commit     *)
(* creates the head If-None-Match. G is a git-mode ref with a head, whose   *)
(* one committed push introduced the history segment sh, which no entry     *)
(* version names (section 8's G11).                                         *)
(*                                                                          *)
(* A push comes to name s1 in one of three ways:                            *)
(*   cite     it names the listed version as a reuse source. 5h passes it    *)
(*            only while the DROP is not visible to its read of A's head:   *)
(*            before the DROP's commit, or within CacheLife of it on a      *)
(*            cached head (FS-91 (c))                                       *)
(*   adopt    it uploads s1's bytes again and takes a receipt, which 5h     *)
(*            passes while the object is under ReceiptLife old (FS-91 (e)) *)
(*   history  the same on the git-mode ref, s1 as a history segment: named  *)
(*            by the push's new-objects list and by no entry version        *)
(*                                                                          *)
(* The design (Twin "none"):                                                *)
(*   seen       the job reads the DROP committed from the cluster and       *)
(*              keeps that time                                             *)
(*   candidates the ids the listed version's chain names, and nothing else  *)
(*   horizon    before each round's scans: every batch record of a minute   *)
(*              before seen + CiteBound is settled, CiteBound covering the  *)
(*              cached head's life; the round keeps that horizon            *)
(*   mark       then the repo's refs, each head read from the cluster,      *)
(*              which waits on a held key; a candidate is marked by every   *)
(*              live entry version naming it and by every git-mode push     *)
(*              whose new-objects list holds it                             *)
(*   verify     the same again, later, on the refs as they then are; what  *)
(*              it finds named is marked too                                *)
(*   delete     a candidate unmarked and unnamed whose adoption bound       *)
(*              (LastModified + ReceiptLife) the round's horizon has        *)
(*              passed; any other is young and waits for a later round      *)
(*                                                                          *)
(* What the model abstracts:                                                *)
(* - Time is ticks, as EvsGc.tla's: a tick ends every short timer, so a     *)
(*   head write issued and not landed never will unless its drive commits   *)
(*   stalled, and an attempt that checked and has not issued checks again.  *)
(* - The DROP's window, its cancel, the lock, holds, the lease and the      *)
(*   lists' exactness are EvsCommit.tla's drop stories (EVSB-M10-07). This  *)
(*   model starts where they end: a DROP whose list is exact, committed.    *)
(* - A fence ends every attempt on its ref that arrived before it.          *)
(* - One job instance. A second instance's late DELETE is section 2's D,    *)
(*   which EvsGc.tla checks for a DELETE that names its object.             *)
(*                                                                          *)
(* Twin names a rule to break; a twin config must make TLC refuse the model *)
(* with the invariant its cfg names.                                        *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Attempts,     \* pushes, one attempt each: model values
    Kinds,        \* the ways an attempt may name s1: a subset of {"cite", "adopt", "history"}
    MaxTime,      \* ticks in one behavior
    ReceiptLife,  \* ticks a receipt is adopted for: 24 h
    EvacAge,      \* a minute is evacuated once this many ticks old: 25 h
    CacheLife,    \* ticks, from the DROP's commit, in which a cached head of A still hides it: 10 min
    CiteBound,    \* the job's margin past the time it saw the DROP committed
    OrphanAge,    \* Twin "YoungByAge": 11.13's 25 h, in ticks
    DropBy,       \* the DROP commits at or before this tick
    MaxStalls,    \* head writes whose drive commits stall
    MaxPauses,    \* attempts stopped between their last check and their head write
    Twin          \* "none", or the rule a twin config breaks

\* The margins, in ms, on the design's numbers. A push that cites a listed version was validated on a head
\* of the DROP's ref that did not show the DROP: a cluster read before the DROP was visible, or a cached
\* head, which is served for at most HeadCacheMs after the write it holds. Its record is written, and its
\* step 7 issued, within 5 s of that read, in a batch whose minute began no later.
HeadCacheMs == 10 * 60 * 1000      \* 11.9's cache row: a cached head is served within 10 min of its write
StepSevenMs == 5000                \* a record is written, and step 7 issued, within 5 s of step 4's reads
ClockMs == 50                      \* each clock that stamps a head, a cache entry or a minute
MinuteMs == 60 * 1000              \* a batch key names the minute it opened in
CiteBoundMs == 12 * 60 * 1000      \* DropCiteBound
ReceiptMs == 24 * 3600 * 1000
StampLagMs == 100
AdoptionBoundMs == ReceiptMs + 2 * MinuteMs   \* section 2.2.4's AdoptionBound

ASSUME
    /\ HeadCacheMs + StepSevenMs + 2 * ClockMs + MinuteMs <= CiteBoundMs
    /\ ReceiptMs + StampLagMs + StepSevenMs + 2 * ClockMs + MinuteMs <= AdoptionBoundMs
    /\ ReceiptLife >= 1
    /\ EvacAge >= 1
    /\ CacheLife >= 1
    /\ Kinds \subseteq {"cite", "adopt", "history"}
    /\ Twin \in {"none", "NoHorizon", "CiteBoundCommitOnly", "YoungByAge", "HorizonAfterScans",
                 "CandidatesBySweep", "MarkSkipsHistory", "ScanPastHeldKey"}
    \* the design's margin covers the cached head's life
    /\ Twin = "none" => CiteBound >= CacheLife

RefA == "A"
RefB == "B"
RefN == "N"
RefG == "G"
Refs == {RefA, RefB, RefN, RefG}
Segments == {"s1", "sh"}

NoOne == "no one"

\* The listed version, and the git-mode push's history segment.
Listed == [ref |-> RefA, seg |-> "s1", how |-> "entry"]
History == [ref |-> RefG, seg |-> "sh", how |-> "history"]

VARIABLES
    now,          \* the tick
    head,         \* head[r]: whether it exists, its version, its fence
    held,         \* held[r]: the attempt whose stalled head write holds the key, or NoOne
    seg,          \* seg[s]: whether it is stored, and its LastModified tick
    vers,         \* what committed pushes name: [ref, seg, how], how "entry" or "history"
    drop,         \* the DROP: whether it has committed, and the tick it did
    att,          \* att[a]: one attempt
    rec,          \* batch records not yet evacuated: [att, minute]
    evac,         \* the evacuator's job
    job,          \* the drop job
    stallsLeft,
    pausesLeft

vars == <<now, head, held, seg, vers, drop, att, rec, evac, job, stallsLeft, pausesLeft>>

NoAttempt == [stage |-> "idle", ref |-> RefB, kind |-> "cite", etag |-> <<FALSE, 0, 0>>, fenced |-> FALSE]
NoEvac == [stage |-> "idle", att |-> NoOne, minute |-> 0, fenced |-> FALSE]
NoJob == [stage |-> "idle", seen |-> 0, cands |-> {}, marks |-> {}, horizon |-> 0, gated |-> FALSE,
          todo |-> {}, young |-> {}, vAt |-> 0]

\* An ETag never repeats: every head write raises the version or the fence.
Etag(h) == <<h.exists, h.version, h.fence>>

Records(a) == {r \in rec : r.att = a}

\* A committed version is live unless a committed DROP lists it (11.13's mark row).
Live(v) == v # Listed \/ ~drop.committed

\* Evacuation's horizon (section 2.2.4), from one LIST of pb/: every batch record of a minute before it
\* has been settled.
Min(S) == CHOOSE x \in S : \A y \in S : x <= y
Floor == IF now >= EvacAge THEN now - EvacAge ELSE 0
Horizon == IF rec = {} THEN Floor
           ELSE LET oldest == Min({r.minute : r \in rec}) IN IF oldest < Floor THEN oldest ELSE Floor

\* The last tick a receipt for an object stored at tick t can pass a check in, and so the last minute a
\* record adopting it can be filed under.
AdoptionBound(t) == t + ReceiptLife - 1

Init ==
    /\ now = 0
    /\ head = [r \in Refs |-> [exists |-> r # RefN, version |-> IF r = RefN THEN 0 ELSE 1, fence |-> 0]]
    /\ held = [r \in Refs |-> NoOne]
    /\ seg = [s \in Segments |-> [stored |-> TRUE, at |-> 0]]
    /\ vers = {Listed, History}
    /\ drop = [committed |-> FALSE, at |-> 0]
    /\ att = [a \in Attempts |-> NoAttempt]
    /\ rec = {}
    /\ evac = NoEvac
    /\ job = NoJob
    /\ stallsLeft = MaxStalls
    /\ pausesLeft = MaxPauses

(***************************************************************************)
(* The DROP and the pushes that may come to name s1.                        *)
(***************************************************************************)

\* The DROP's step 7 on A: from here 5h refuses a citation that reads A's head from the cluster.
DropCommit ==
    /\ ~drop.committed
    /\ now <= DropBy
    /\ held[RefA] = NoOne
    /\ drop' = [committed |-> TRUE, at |-> now]
    /\ head' = [head EXCEPT ![RefA].version = @ + 1]
    /\ UNCHANGED <<now, held, seg, vers, att, rec, evac, job, stallsLeft, pausesLeft>>

\* A push reaches evs on a ref: step 4 reads the head. The git-mode ref takes only the history kind.
Arrive(a, r, k) ==
    /\ att[a].stage = "idle"
    /\ k \in Kinds
    /\ (k = "history") = (r = RefG)
    /\ r # RefA
    /\ held[r] = NoOne
    /\ att' = [att EXCEPT ![a] = [NoAttempt EXCEPT !.stage = "read", !.ref = r, !.kind = k,
                                                   !.etag = Etag(head[r])]]
    /\ UNCHANGED <<now, head, held, seg, vers, drop, rec, evac, job, stallsLeft, pausesLeft>>

\* 5h. A citation passes while the DROP is not visible to its read of A's head: not committed, or
\* committed under CacheLife ticks ago and read from a cached head. A receipt passes while the object is
\* stored and under ReceiptLife old.
Passes(a) ==
    IF att[a].kind = "cite"
    THEN ~drop.committed \/ now - drop.at < CacheLife
    ELSE seg["s1"].stored /\ now - seg["s1"].at < ReceiptLife

\* Step 5h, then step 6: the record, filed under this tick's minute, written once per attempt.
CheckAndRecord(a) ==
    /\ att[a].stage = "read"
    /\ IF Passes(a)
       THEN /\ att' = [att EXCEPT ![a].stage = "ready"]
            /\ rec' = IF Records(a) = {} THEN rec \cup {[att |-> a, minute |-> now]} ELSE rec
       ELSE /\ att' = [att EXCEPT ![a].stage = "done"]
            /\ UNCHANGED rec
    /\ UNCHANGED <<now, head, held, seg, vers, drop, evac, job, stallsLeft, pausesLeft>>

Issue(a) ==
    /\ att[a].stage = "ready"
    /\ att' = [att EXCEPT ![a].stage = "put"]
    /\ UNCHANGED <<now, head, held, seg, vers, drop, rec, evac, job, stallsLeft, pausesLeft>>

\* A process stopped after its last check wakes at any later time and sends its write then.
Pause(a) ==
    /\ att[a].stage = "ready"
    /\ pausesLeft > 0
    /\ pausesLeft' = pausesLeft - 1
    /\ att' = [att EXCEPT ![a].stage = "paused"]
    /\ UNCHANGED <<now, head, held, seg, vers, drop, rec, evac, job, stallsLeft>>

Wake(a) ==
    /\ att[a].stage = "paused"
    /\ att' = [att EXCEPT ![a].stage = "put"]
    /\ UNCHANGED <<now, head, held, seg, vers, drop, rec, evac, job, stallsLeft, pausesLeft>>

\* The head after a commit, created If-None-Match on a ref with none, and what the push names.
Commits(a) ==
    LET r == att[a].ref
    IN  /\ head' = [head EXCEPT ![r] = [exists |-> TRUE, version |-> @.version + 1, fence |-> @.fence]]
        /\ vers' = vers \cup {[ref |-> r, seg |-> "s1",
                               how |-> IF att[a].kind = "history" THEN "history" ELSE "entry"]}

Land(a) ==
    LET r == att[a].ref
    IN  /\ att[a].stage = "put"
        /\ held[r] = NoOne
        /\ IF Etag(head[r]) = att[a].etag
           THEN /\ Commits(a)
                /\ att' = [att EXCEPT ![a].stage = "done"]
           ELSE /\ att' = [att EXCEPT ![a].stage = "reread"]
                /\ UNCHANGED <<head, vers>>
        /\ UNCHANGED <<now, held, seg, drop, rec, evac, job, stallsLeft, pausesLeft>>

\* Its drive commits stall after their checks: it holds the head's key, which no request passes, and
\* §19.6 settles it at any later time, landed or reverted.
Stall(a) ==
    LET r == att[a].ref
    IN  /\ att[a].stage = "put"
        /\ held[r] = NoOne
        /\ Etag(head[r]) = att[a].etag
        /\ stallsLeft > 0
        /\ stallsLeft' = stallsLeft - 1
        /\ held' = [held EXCEPT ![r] = a]
        /\ att' = [att EXCEPT ![a].stage = "stalled"]
        /\ UNCHANGED <<now, head, seg, vers, drop, rec, evac, job, pausesLeft>>

StallLands(a) ==
    LET r == att[a].ref
    IN  /\ att[a].stage = "stalled"
        /\ held[r] = a
        /\ Commits(a)
        /\ held' = [held EXCEPT ![r] = NoOne]
        /\ att' = [att EXCEPT ![a].stage = "done"]
        /\ UNCHANGED <<now, seg, drop, rec, evac, job, stallsLeft, pausesLeft>>

StallReverts(a) ==
    LET r == att[a].ref
    IN  /\ att[a].stage = "stalled"
        /\ held[r] = a
        /\ held' = [held EXCEPT ![r] = NoOne]
        /\ att' = [att EXCEPT ![a].stage = "reread"]
        /\ UNCHANGED <<now, head, seg, vers, drop, rec, evac, job, stallsLeft, pausesLeft>>

\* The 412 and unknown rows: the head again from the cluster. A fence raised since the attempt arrived
\* ends it; otherwise step 5 runs again on the reread head, its record kept.
Reread(a) ==
    LET r == att[a].ref
    IN  /\ att[a].stage = "reread"
        /\ held[r] = NoOne
        /\ att' = [att EXCEPT ![a].stage = IF att[a].fenced THEN "done" ELSE "read",
                              ![a].etag = Etag(head[r])]
        /\ UNCHANGED <<now, head, held, seg, vers, drop, rec, evac, job, stallsLeft, pausesLeft>>

(***************************************************************************)
(* The evacuator (§11.13's resolve row, section 2.2.3's fence).             *)
(***************************************************************************)

EvacStart(r) ==
    /\ evac.stage = "idle"
    /\ r \in rec
    /\ now - r.minute >= EvacAge
    /\ evac' = [NoEvac EXCEPT !.stage = "resolve", !.att = r.att, !.minute = r.minute]
    /\ UNCHANGED <<now, head, held, seg, vers, drop, att, rec, job, stallsLeft, pausesLeft>>

\* Resolve reads the ref's head from the cluster, which waits on a held key: committed or dead, the
\* record leaves its batch; pending, its ref is fenced first.
EvacResolve ==
    LET a == evac.att
        r == att[a].ref
        settled == att[a].stage = "done" \/ evac.fenced
    IN  /\ evac.stage = "resolve"
        /\ held[r] = NoOne
        /\ IF settled
           THEN /\ rec' = rec \ {[att |-> a, minute |-> evac.minute]}
                /\ evac' = NoEvac
           ELSE /\ evac' = [evac EXCEPT !.stage = "fence"]
                /\ UNCHANGED rec
        /\ UNCHANGED <<now, head, held, seg, vers, drop, att, job, stallsLeft, pausesLeft>>

\* One head CAS raises the ref's fence; a ref with no head gets a placeholder head with its fence raised.
\* Every attempt that reached the ref before it is ended by it.
EvacFence ==
    LET r == att[evac.att].ref
    IN  /\ evac.stage = "fence"
        /\ held[r] = NoOne
        /\ head' = [head EXCEPT ![r] = [exists |-> TRUE, version |-> @.version, fence |-> @.fence + 1]]
        /\ att' = [a \in Attempts |->
               IF att[a].ref = r /\ att[a].stage \in {"read", "ready", "put", "paused", "reread"}
               THEN [att[a] EXCEPT !.fenced = TRUE] ELSE att[a]]
        /\ evac' = [evac EXCEPT !.stage = "resolve", !.fenced = TRUE]
        /\ UNCHANGED <<now, held, seg, vers, drop, rec, job, stallsLeft, pausesLeft>>

(***************************************************************************)
(* The drop job (section 10.2.7).                                           *)
(***************************************************************************)

\* The job reads the DROP committed, from the cluster, and keeps the time: no push whose read of A's
\* head comes later misses the DROP but one served a cached head, for CacheLife more.
JobStart ==
    /\ job.stage = "idle"
    /\ drop.committed
    /\ held[RefA] = NoOne
    /\ job' = [NoJob EXCEPT !.stage = "resolve", !.seen = now]
    /\ UNCHANGED <<now, head, held, seg, vers, drop, att, rec, evac, stallsLeft, pausesLeft>>

\* Candidates: what the listed version's chain names. The twin sweeps the repo for every stored segment
\* no live entry version names, which takes a git-mode push's history segment.
JobResolve ==
    LET named == {v.seg : v \in {w \in vers : Live(w) /\ w.how = "entry"}}
        swept == {s \in Segments : seg[s].stored /\ s \notin named}
    IN  /\ job.stage = "resolve"
        /\ job' = [job EXCEPT !.stage = "wait",
                              !.cands = IF Twin = "CandidatesBySweep" THEN swept ELSE {Listed.seg}]
        /\ UNCHANGED <<now, head, held, seg, vers, drop, att, rec, evac, stallsLeft, pausesLeft>>

\* The margin the job waits out past the time it saw the DROP committed.
Margin == IF Twin = "CiteBoundCommitOnly" THEN 1 ELSE CiteBound

\* Every record of a minute before seen + Margin is settled.
PastCiteBound == Horizon >= job.seen + Margin

\* The horizon first, kept for the round. Two twins take no horizon here.
JobHorizon ==
    /\ job.stage = "wait"
    /\ Twin \in {"NoHorizon", "HorizonAfterScans"} \/ PastCiteBound
    /\ job' = [job EXCEPT !.stage = "mark", !.horizon = Horizon,
                          !.gated = Twin \notin {"NoHorizon", "HorizonAfterScans"}]
    /\ UNCHANGED <<now, head, held, seg, vers, drop, att, rec, evac, stallsLeft, pausesLeft>>

\* What a scan of the repo's refs finds naming an id: every live entry version, and every git-mode push
\* whose new-objects list holds it; two twins count entry versions alone. A scan reads each head from the
\* cluster, so it waits on a held key; the probe ScanPastHeldKey reads past one, taking what the ref
\* showed before.
ScanReady == Twin = "ScanPastHeldKey" \/ \A r \in Refs : head[r].exists => held[r] = NoOne
Named ==
    {v.seg : v \in {w \in vers : /\ head[w.ref].exists
                                 /\ Live(w)
                                 /\ w.how = "entry" \/ Twin \notin {"MarkSkipsHistory", "CandidatesBySweep"}}}

JobMark ==
    /\ job.stage = "mark"
    /\ ScanReady
    /\ job' = [job EXCEPT !.stage = "verify", !.marks = @ \cup (job.cands \cap Named)]
    /\ UNCHANGED <<now, head, held, seg, vers, drop, att, rec, evac, stallsLeft, pausesLeft>>

\* Verify, apart from the mark, on the refs as they now are. A candidate it finds named by a version
\* that committed since the mark is marked too. One named by a version the mark read and did not mark
\* refuses the job in the build (the two implementations disagree); here both scans are one definition,
\* so that case has no state.
JobVerify ==
    LET marks == job.marks \cup (job.cands \cap Named)
    IN  /\ job.stage = "verify"
        /\ ScanReady
        /\ job' = [job EXCEPT !.stage = IF Twin = "HorizonAfterScans" THEN "gate" ELSE "delete",
                              !.marks = marks, !.todo = job.cands \ marks, !.vAt = now]
        /\ UNCHANGED <<now, head, held, seg, vers, drop, att, rec, evac, stallsLeft, pausesLeft>>

\* Twin HorizonAfterScans: the horizon is read only once both scans are done.
JobLateGate ==
    /\ job.stage = "gate"
    /\ PastCiteBound
    /\ job' = [job EXCEPT !.stage = "delete", !.horizon = Horizon, !.gated = TRUE]
    /\ UNCHANGED <<now, head, held, seg, vers, drop, att, rec, evac, stallsLeft, pausesLeft>>

\* A candidate is young until the round's horizon has passed its adoption bound: until then a push
\* holding a receipt for it may have a record unsettled. 11.13 as written goes by its age at V.
YoungNow(s) ==
    IF Twin \in {"YoungByAge", "NoHorizon"} THEN job.vAt - seg[s].at < OrphanAge
    ELSE ~(job.horizon > AdoptionBound(seg[s].at))

\* One id of the delete set: HEAD, then a DELETE that names its LastModified.
JobDelete(s) ==
    /\ job.stage = "delete"
    /\ s \in job.todo
    /\ IF YoungNow(s)
       THEN /\ job' = [job EXCEPT !.todo = @ \ {s}, !.young = @ \cup {s}]
            /\ UNCHANGED seg
       ELSE /\ job' = [job EXCEPT !.todo = @ \ {s}]
            /\ seg' = [seg EXCEPT ![s].stored = FALSE]
    /\ UNCHANGED <<now, head, held, vers, drop, att, rec, evac, stallsLeft, pausesLeft>>

\* Young candidates wait for a later round, which takes the horizon again before its scans: once the
\* horizon has passed a young candidate's adoption bound, or, as 11.13 is written, once time has passed.
RoundDue ==
    IF Twin \in {"YoungByAge", "NoHorizon"} THEN now > job.vAt
    ELSE \E s \in job.young : Horizon > AdoptionBound(seg[s].at)

JobRound ==
    /\ job.stage = "delete"
    /\ job.todo = {}
    /\ job.young # {}
    /\ RoundDue
    /\ job' = [job EXCEPT !.stage = "wait", !.cands = job.young, !.young = {}]
    /\ UNCHANGED <<now, head, held, seg, vers, drop, att, rec, evac, stallsLeft, pausesLeft>>

JobDone ==
    /\ job.stage = "delete"
    /\ job.todo = {}
    /\ job.young = {}
    /\ job' = [job EXCEPT !.stage = "done"]
    /\ UNCHANGED <<now, head, held, seg, vers, drop, att, rec, evac, stallsLeft, pausesLeft>>

(***************************************************************************)
(* Time.                                                                    *)
(***************************************************************************)

\* A tick ends every short timer: a write issued and not landed never will, and an attempt that checked
\* and has not issued checks again. A stalled write and a paused process outlast it.
Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ att' = [a \in Attempts |->
           IF att[a].stage \in {"ready", "put"} THEN [att[a] EXCEPT !.stage = "reread"] ELSE att[a]]
    /\ UNCHANGED <<head, held, seg, vers, drop, rec, evac, job, stallsLeft, pausesLeft>>

JobStep ==
    \/ JobStart
    \/ JobResolve
    \/ JobHorizon
    \/ JobMark
    \/ JobVerify
    \/ JobLateGate
    \/ \E s \in Segments : JobDelete(s)
    \/ JobRound
    \/ JobDone

EvacStep == (\E r \in rec : EvacStart(r)) \/ EvacResolve \/ EvacFence

Next ==
    \/ DropCommit
    \/ \E a \in Attempts :
           \/ \E r \in Refs, k \in Kinds : Arrive(a, r, k)
           \/ CheckAndRecord(a)
           \/ Issue(a)
           \/ Pause(a)
           \/ Wake(a)
           \/ Land(a)
           \/ Stall(a)
           \/ StallLands(a)
           \/ StallReverts(a)
           \/ Reread(a)
    \/ EvacStep
    \/ JobStep
    \/ Tick

Spec == Init /\ [][Next]_vars

\* The job and the evacuator keep working, stalled writes settle, the DROP commits and time passes.
Fairness ==
    /\ WF_vars(JobStep)
    /\ WF_vars(EvacStep)
    /\ WF_vars(Tick)
    /\ WF_vars(DropCommit)
    /\ \A a \in Attempts : WF_vars(StallLands(a) \/ StallReverts(a))

LiveSpec == Spec /\ Fairness

Symmetry == Permutations(Attempts)

TypeOk ==
    /\ now \in 0..MaxTime
    /\ \A r \in Refs : held[r] \in Attempts \cup {NoOne}
    /\ \A a \in Attempts : att[a].stage \in {"idle", "read", "ready", "put", "paused", "stalled", "reread", "done"}
    /\ job.stage \in {"idle", "resolve", "wait", "mark", "verify", "gate", "delete", "done"}
    /\ job.cands \subseteq Segments
    /\ job.marks \subseteq Segments

\* I-EVS-1 and I-EVS-15: every committed version that no executed drop lists keeps what it names, a
\* git-mode push's history segment included (G11), however late its head write landed.
ClosureHolds == \A v \in vers : Live(v) => seg[v.seg].stored

\* FI-27 (2): the job deletes only what it resolved from the listed version's chain.
OnlyCandidates == seg["sh"].stored

\* The job deletes nothing before a round took the horizon.
DeletesGated == ~seg["s1"].stored => job.gated

\* A placeholder head exists only with its fence raised.
HeadsRise == \A r \in Refs : head[r].exists /\ head[r].version = 0 => head[r].fence > 0

\* Reachability, each refuted by a Reach config: the job does delete the candidate; it does end done with
\* the candidate kept for a version that came to name it; it does meet a young candidate; and a first
\* commit to a ref with no head does land naming the candidate after the job began.
NeverDeletes == seg["s1"].stored
NeverKeeps == ~(job.stage = "done" /\ seg["s1"].stored)
NeverYoung == job.young = {}
NeverLateCreation == ~(job.stage # "idle" /\ [ref |-> RefN, seg |-> "s1", how |-> "entry"] \in vers)

\* Every job that starts with room for its waits ends (weak fairness): the horizon reaches
\* MaxTime - EvacAge once every older record is settled, which must cover the cite bound and, in the
\* config, the candidate's adoption bound.
JobEnds == (job.stage = "resolve" /\ job.seen + CiteBound + EvacAge <= MaxTime) ~> (job.stage = "done")

=============================================================================
