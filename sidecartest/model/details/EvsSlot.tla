-------------------------------- MODULE EvsSlot --------------------------------
(***************************************************************************)
(* DESIGN-DETAILS.md section 14's slot rule: one slot id of one repo, the   *)
(* pushes whose statements list it as a new slot with the same bytes, the   *)
(* batch records those pushes leave, the evacuator that settles each        *)
(* record and deletes a dead one's slot, and the deleters that remove a     *)
(* committed version with the slots it names (a CONSUME, a purge, a         *)
(* marker's collection).                                                    *)
(*                                                                          *)
(* A slot's id is drawn by the client and its body is not signed, so any    *)
(* statement may list any id it has seen, with the bytes it read there: a   *)
(* retoken lists its refused statement's slots again (DESIGN-DETAILS 9.2.5),*)
(* and a reader of the slot can list it on purpose. Every push here does.   *)
(*                                                                          *)
(* The design (Twin "none"):                                                *)
(*                                                                          *)
(*   stamp     step 6 creates a new slot If-None-Match with its statement   *)
(*             as the object's origin, after its record is written          *)
(*   own       an attempt that finds the slot there takes it only under its *)
(*             own statement's origin                                       *)
(*   take      it takes over the object of another statement only when that *)
(*             statement declared a lower path epoch than the head this one *)
(*             passed step 5 on and that head does not show it committed,   *)
(*             so it never commits; it deletes the object, settled, by a    *)
(*             DELETE that names its LastModified (x-ur-if-unmodified-ms),  *)
(*             and creates its own; any other object is 409 SLOT_STALE      *)
(*   evacuate  a dead record's slot is deleted only when a HEAD shows the   *)
(*             record's own statement as its origin and a LastModified the  *)
(*             settle age has passed, by a DELETE that names it             *)
(*                                                                          *)
(* So a slot object is its creator's for as long as it stands, an object    *)
(* goes only once its creator can no longer commit or its version is        *)
(* removed, and no two committed pushes introduce one object.               *)
(*                                                                          *)
(* Twin "Landed" is the code as it stood on 2026-11-12: step 6 takes any    *)
(* object of equal bytes, and evacuation deletes every slot a dead record   *)
(* lists, unconditionally. Twin "Interim" is the fix that lands first:      *)
(* evacuation keeps every dead record's slots, and step 6 is as landed.     *)
(*                                                                          *)
(* What the model abstracts:                                                *)
(* - Bytes are equal throughout: a statement that lists the id with other   *)
(*   bytes is refused by the design whoever it is, as it is today.          *)
(* - Each statement has one attempt, which may read the head again. Another *)
(*   attempt of a dead statement that arrives later is refused by the       *)
(*   statement's time checks (§11.8's Resolve row), which the model does    *)
(*   not hold; an attempt stopped at any step is held: no step is ever      *)
(*   forced, and time passes under every stage.                             *)
(* - Time is ticks, each longer than the settle age and than the second of  *)
(*   slack the store's conditional DELETE allows: a DELETE that names a     *)
(*   LastModified takes any object stored in that tick, and a HEAD finds an *)
(*   object stored in its own tick unsettled.                               *)
(* - A fence ends every attempt on the ref that arrived before it: its      *)
(*   head write fails on the ETag, and its next read ends it. Move is       *)
(*   another push's commit and Cut a PATH_EPOCH's, which raises the ref's   *)
(*   path epoch; a statement whose head passed its window or its epoch is   *)
(*   refused for good at step 5.                                            *)
(* - Every statement is on the one ref, and any of them may take over a     *)
(*   dead one's object: the design also asks for the same signer, which     *)
(*   only removes behaviors.                                                *)
(* - A removed version's slot is deleted with it, in one step. An ERASE's   *)
(*   rewrite replaces the object, so its LastModified moves.                *)
(* - Holds, parts and seals, re-seeds and repos' deletion are left out:     *)
(*   each keeps a slot or removes every object of the repo.                 *)
(*                                                                          *)
(* Twin names a rule to break; a twin config must make TLC refuse the model *)
(* with the invariant its cfg names.                                        *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Pushes,       \* statements that list the slot id as new, one attempt each: model values
    Evacs,        \* evacuation runs that may be alive at once, a stalled one beside its successor: model values
    Window,       \* a statement built on version b commits at b+1 .. b+Window: 64, in git mode 1
    MaxTime,      \* ticks in one behavior
    EvacAge,      \* a minute is evacuated once this many ticks old: 25 h
    MaxMoves,     \* other pushes' commits
    MaxCuts,      \* PATH_EPOCH commits
    MaxStalls,    \* head writes whose drive commits stall
    MaxCrashes,   \* evacuation runs killed at a step
    MaxConsumes,  \* committed versions removed with the slots they name
    MaxRewrites,  \* ERASE rewrites of the slot
    Twin          \* "none", or the rule a twin config breaks

ASSUME
    /\ Window >= 1
    /\ EvacAge >= 1
    /\ Twin \in {"none", "Landed", "Interim", "TakesForeign", "TakesLive", "TakesCommitted", "TakesUnsettled",
                 "NoOriginAtDelete", "UnconditionalDelete", "NoSettle", "StampBeforeRecord", "DeadUnfenced",
                 "RewriteDropsOrigin"}

NoOne == "no one"

VARIABLES
    now,          \* the tick
    head,         \* the ref's head: its version, its path epoch and its fence
    held,         \* the push whose stalled head write holds the head's key, or NoOne
    slot,         \* the slot object: whether it is stored, its origin, its LastModified tick
    att,          \* att[p]: one statement's attempt
    rec,          \* batch records not yet evacuated: [push, minute]
    commitAt,     \* commitAt[p]: the version p committed at, or 0
    consumed,     \* committed pushes whose version was removed with its slots
    evac,         \* evac[e]: one evacuation run
    left,         \* what the behavior may still do: moves, cuts, stalls, crashes, consumes, rewrites
    seen          \* ghost: what the behavior did

vars == <<now, head, held, slot, att, rec, commitAt, consumed, evac, left, seen>>

NoAttempt == [stage |-> "idle", base |-> 0, epoch |-> 0, view |-> [version |-> 0, epoch |-> 0, fence |-> 0],
              fenced |-> FALSE, recorded |-> FALSE, slotted |-> FALSE, saw |-> 0]
NoSlot == [stored |-> FALSE, origin |-> NoOne, at |-> 0]
NoEvac == [stage |-> "idle", push |-> NoOne, minute |-> 0, fenced |-> FALSE, at |-> 0]

\* The committed pushes whose version stands: each names the slot.
Standing == {p \in Pushes : commitAt[p] # 0 /\ p \notin consumed}

\* What a delete of the slot takes from the committed pushes that still name it.
Losses(by, pushes) == {[push |-> q, made |-> slot.origin, by |-> by] : q \in pushes}

\* Step 6 as landed: any object of equal bytes is the attempt's own.
TakesAny == Twin \in {"Landed", "Interim", "TakesForeign"}

Init ==
    /\ now = 0
    /\ head = [version |-> 1, epoch |-> 1, fence |-> 0]
    /\ held = NoOne
    /\ slot = NoSlot
    /\ att = [p \in Pushes |-> NoAttempt]
    /\ rec = {}
    /\ commitAt = [p \in Pushes |-> 0]
    /\ consumed = {}
    /\ evac = [e \in Evacs |-> NoEvac]
    /\ left = [moves |-> MaxMoves, cuts |-> MaxCuts, stalls |-> MaxStalls, crashes |-> MaxCrashes,
               consumes |-> MaxConsumes, rewrites |-> MaxRewrites]
    /\ seen = [lost |-> {}, refused |-> {}, judged |-> {}, took |-> {}, deleted |-> FALSE, young |-> FALSE]

(***************************************************************************)
(* Pushes (§11.8 steps 4 to 7).                                             *)
(***************************************************************************)

\* The statement is built on the head, in its path epoch, and reaches evs: step 4 reads the head.
Arrive(p) ==
    /\ att[p].stage = "idle"
    /\ held = NoOne
    /\ att' = [att EXCEPT ![p].stage = "read", ![p].base = head.version, ![p].epoch = head.epoch, ![p].view = head]
    /\ UNCHANGED <<now, head, held, slot, rec, commitAt, consumed, evac, left, seen>>

\* The record, filed under this tick's minute, once per attempt.
Recorded(p, attempts) ==
    IF attempts[p].recorded THEN attempts ELSE [attempts EXCEPT ![p].recorded = TRUE]

RecordOf(p) == IF att[p].recorded THEN rec ELSE rec \cup {[push |-> p, minute |-> now]}

\* Step 5 on the head as read, then step 6's record: a head past the statement's window, or in a
\* later path epoch than it declares (412 PATH_EPOCH), refuses it for good. A rerun keeps the record
\* and the slot (once per attempt).
Check(p) ==
    /\ att[p].stage = "read"
    /\ IF att[p].view.version < att[p].base + Window /\ att[p].view.epoch = att[p].epoch
       THEN IF Twin = "StampBeforeRecord"
            THEN /\ att' = [att EXCEPT ![p].stage = IF att[p].slotted THEN "ready" ELSE "slot"]
                 /\ UNCHANGED rec
            ELSE /\ att' = [Recorded(p, att) EXCEPT ![p].stage = IF att[p].slotted THEN "ready" ELSE "slot"]
                 /\ rec' = RecordOf(p)
       ELSE /\ att' = [att EXCEPT ![p].stage = "done"]
            /\ UNCHANGED rec
    /\ UNCHANGED <<now, head, held, slot, commitAt, consumed, evac, left, seen>>

\* The slot is the attempt's: step 7 is next. The twin's record is still to write.
Slotted(p) ==
    att' = [att EXCEPT ![p].stage = IF Twin = "StampBeforeRecord" THEN "late" ELSE "ready", ![p].slotted = TRUE]

\* Twin StampBeforeRecord: the record after the slots.
LateRecord(p) ==
    /\ att[p].stage = "late"
    /\ att' = [Recorded(p, att) EXCEPT ![p].stage = "ready"]
    /\ rec' = RecordOf(p)
    /\ UNCHANGED <<now, head, held, slot, commitAt, consumed, evac, left, seen>>

\* Step 6's PUT If-None-Match, the statement as the object's origin: it creates the slot, or 412.
SlotPut(p) ==
    /\ att[p].stage = "slot"
    /\ IF slot.stored
       THEN /\ att' = [att EXCEPT ![p].stage = "found"]
            /\ UNCHANGED slot
       ELSE /\ slot' = [stored |-> TRUE, origin |-> p, at |-> now]
            /\ Slotted(p)
    /\ UNCHANGED <<now, head, held, rec, commitAt, consumed, evac, left, seen>>

\* The object's statement can no longer commit, as this attempt knows it: it declared a lower path
\* epoch than the head this attempt passed step 5 on, and that head does not show it committed.
Takeable(p) ==
    LET o == slot.origin
    IN  /\ slot.stored
        /\ o \in Pushes \ {p}
        /\ Twin = "TakesLive" \/ att[o].epoch < att[p].epoch
        /\ Twin = "TakesCommitted" \/ ~(commitAt[o] # 0 /\ commitAt[o] <= att[p].view.version)

\* The 412's GET: the attempt's own origin is success. Another statement's object that can no
\* longer commit is taken over once it has settled: the attempt waits out the settle age. Any other
\* object is 409 SLOT_STALE, recorded, and the client seals again with new ids. A 404 is the create
\* again.
SlotGet(p) ==
    /\ att[p].stage = "found"
    /\ CASE ~slot.stored ->
                /\ att' = [att EXCEPT ![p].stage = "slot"]
                /\ UNCHANGED seen
         [] slot.stored /\ (slot.origin = p \/ TakesAny) ->
                /\ Slotted(p)
                /\ UNCHANGED seen
         [] slot.stored /\ slot.origin # p /\ ~TakesAny /\ Takeable(p) ->
                /\ slot.at < now \/ Twin = "TakesUnsettled"
                /\ att' = [att EXCEPT ![p].stage = "take", ![p].saw = slot.at]
                /\ seen' = [seen EXCEPT !.judged = @ \cup {slot.origin}]
         [] OTHER ->
                /\ att' = [att EXCEPT ![p].stage = "done"]
                /\ seen' = [seen EXCEPT !.refused = @ \cup {p}]
    /\ UNCHANGED <<now, head, held, slot, rec, commitAt, consumed, evac, left>>

\* The takeover's DELETE, which names the LastModified its GET saw: the store takes only that
\* object, or one stored in the same tick. Then the create again, whatever the DELETE found.
SlotTake(p) ==
    /\ att[p].stage = "take"
    /\ IF slot.stored /\ slot.at = att[p].saw
       THEN /\ slot' = NoSlot
            /\ seen' = [seen EXCEPT !.lost = @ \cup Losses("takeover", Standing), !.took = @ \cup {p}]
       ELSE UNCHANGED <<slot, seen>>
    /\ att' = [att EXCEPT ![p].stage = "slot"]
    /\ UNCHANGED <<now, head, held, rec, commitAt, consumed, evac, left>>

\* The head after a commit. A commit whose slot is gone is a loss.
Commits(p) ==
    /\ head' = [head EXCEPT !.version = @ + 1]
    /\ commitAt' = [commitAt EXCEPT ![p] = head.version + 1]
    /\ seen' = IF slot.stored THEN seen
               ELSE [seen EXCEPT !.lost = @ \cup {[push |-> p, made |-> NoOne, by |-> "commit"]}]

\* Step 7: the write lands, or fails its precondition and the attempt reads the head again.
Land(p) ==
    /\ att[p].stage = "ready"
    /\ held = NoOne
    /\ IF head = att[p].view
       THEN /\ Commits(p)
            /\ att' = [att EXCEPT ![p].stage = "done"]
       ELSE /\ att' = [att EXCEPT ![p].stage = "reread"]
            /\ UNCHANGED <<head, commitAt, seen>>
    /\ UNCHANGED <<now, held, slot, rec, consumed, evac, left>>

\* Its drive commits stall after their checks: it holds the head's key, which no request passes,
\* and §19.6 settles it at any later time, landed or reverted.
Stall(p) ==
    /\ att[p].stage = "ready"
    /\ held = NoOne
    /\ head = att[p].view
    /\ left.stalls > 0
    /\ left' = [left EXCEPT !.stalls = @ - 1]
    /\ held' = p
    /\ att' = [att EXCEPT ![p].stage = "stalled"]
    /\ UNCHANGED <<now, head, slot, rec, commitAt, consumed, evac, seen>>

StallLands(p) ==
    /\ att[p].stage = "stalled"
    /\ held = p
    /\ Commits(p)
    /\ held' = NoOne
    /\ att' = [att EXCEPT ![p].stage = "done"]
    /\ UNCHANGED <<now, slot, rec, consumed, evac, left>>

StallReverts(p) ==
    /\ att[p].stage = "stalled"
    /\ held = p
    /\ held' = NoOne
    /\ att' = [att EXCEPT ![p].stage = "reread"]
    /\ UNCHANGED <<now, head, slot, rec, commitAt, consumed, evac, left, seen>>

\* The 412 and unknown rows: the head again from the cluster. A fence raised since the attempt
\* arrived ends it; otherwise step 5 runs again on the reread head.
Reread(p) ==
    /\ att[p].stage = "reread"
    /\ held = NoOne
    /\ att' = [att EXCEPT ![p].stage = IF att[p].fenced THEN "done" ELSE "read", ![p].view = head]
    /\ UNCHANGED <<now, head, held, slot, rec, commitAt, consumed, evac, left, seen>>

\* Another push commits on the ref.
Move ==
    /\ left.moves > 0
    /\ held = NoOne
    /\ left' = [left EXCEPT !.moves = @ - 1]
    /\ head' = [head EXCEPT !.version = @ + 1]
    /\ UNCHANGED <<now, held, slot, att, rec, commitAt, consumed, evac, seen>>

\* A PATH_EPOCH push commits: the ref's path epoch rises, and only rises.
Cut ==
    /\ left.cuts > 0
    /\ held = NoOne
    /\ left' = [left EXCEPT !.cuts = @ - 1]
    /\ head' = [head EXCEPT !.version = @ + 1, !.epoch = @ + 1]
    /\ UNCHANGED <<now, held, slot, att, rec, commitAt, consumed, evac, seen>>

(***************************************************************************)
(* The deleters and rewriters of a committed version's slot (§11.12, §11.13)*)
(***************************************************************************)

\* A committed version is removed and the slots it names deleted, unconditionally: a CONSUME of a
\* deposit, a purge, a removed entry's marker collected.
Consume(p) ==
    /\ p \in Standing
    /\ left.consumes > 0
    /\ left' = [left EXCEPT !.consumes = @ - 1]
    /\ consumed' = consumed \cup {p}
    /\ IF slot.stored
       THEN /\ slot' = NoSlot
            /\ seen' = [seen EXCEPT !.lost = @ \cup Losses("consume", Standing \ {p})]
       ELSE UNCHANGED <<slot, seen>>
    /\ UNCHANGED <<now, head, held, att, rec, commitAt, evac>>

\* An ERASE rewrites a slot a committed version names: the object is replaced, its origin kept.
Rewrite ==
    /\ left.rewrites > 0
    /\ slot.stored
    /\ Standing # {}
    /\ left' = [left EXCEPT !.rewrites = @ - 1]
    /\ slot' = [slot EXCEPT !.at = now, !.origin = IF Twin = "RewriteDropsOrigin" THEN NoOne ELSE @]
    /\ UNCHANGED <<now, head, held, att, rec, commitAt, consumed, evac, seen>>

(***************************************************************************)
(* The evacuator (§11.13's resolve row; DESIGN-DETAILS 2.2.3 and 14.2).     *)
(***************************************************************************)

EvacStart(e, r) ==
    /\ evac[e].stage = "idle"
    /\ r \in rec
    /\ now - r.minute >= EvacAge
    /\ evac' = [evac EXCEPT ![e] = [NoEvac EXCEPT !.stage = "resolve", !.push = r.push, !.minute = r.minute]]
    /\ UNCHANGED <<now, head, held, slot, att, rec, commitAt, consumed, left, seen>>

\* Resolve reads the ref's head from the cluster, which waits on a held key: committed; dead once
\* the head is past the statement's window or this run's fence stands; else pending.
EvacResolve(e) ==
    LET p == evac[e].push
        next == CASE commitAt[p] # 0 -> "keep"
                  [] head.version >= att[p].base + Window -> "dead"
                  [] evac[e].fenced -> "dead"
                  [] Twin = "DeadUnfenced" -> "dead"
                  [] OTHER -> "fence"
    IN  /\ evac[e].stage = "resolve"
        /\ held = NoOne
        /\ evac' = [evac EXCEPT ![e].stage = next]
        /\ seen' = IF next = "dead" THEN [seen EXCEPT !.judged = @ \cup {p}] ELSE seen
        /\ UNCHANGED <<now, head, held, slot, att, rec, commitAt, consumed, left>>

\* Pending: one head CAS raises the ref's fence, which ends every attempt that arrived before it.
EvacFence(e) ==
    /\ evac[e].stage = "fence"
    /\ held = NoOne
    /\ head' = [head EXCEPT !.fence = @ + 1]
    /\ att' = [p \in Pushes |->
           IF att[p].stage \in {"read", "slot", "found", "take", "late", "ready", "reread"}
           THEN [att[p] EXCEPT !.fenced = TRUE] ELSE att[p]]
    /\ evac' = [evac EXCEPT ![e].stage = "resolve", ![e].fenced = TRUE]
    /\ UNCHANGED <<now, held, slot, rec, commitAt, consumed, left, seen>>

\* Dead: the slot its record lists. The design HEADs it and goes on to the DELETE only for the
\* record's own statement's object, settled; the code as landed sends the DELETE; the interim
\* keeps the slot.
EvacHead(e) ==
    LET p == evac[e].push
    IN  /\ evac[e].stage = "dead"
        /\ CASE Twin = "Interim" ->
                    /\ evac' = [evac EXCEPT ![e].stage = "drop"]
                    /\ UNCHANGED seen
             [] Twin = "Landed" ->
                    /\ evac' = [evac EXCEPT ![e].stage = "delete"]
                    /\ UNCHANGED seen
             [] Twin \notin {"Interim", "Landed"} /\ ~slot.stored ->
                    /\ evac' = [evac EXCEPT ![e].stage = "drop"]
                    /\ UNCHANGED seen
             [] Twin \notin {"Interim", "Landed"} /\ slot.stored /\ slot.origin # p /\ Twin # "NoOriginAtDelete" ->
                    /\ evac' = [evac EXCEPT ![e].stage = "drop"]
                    /\ UNCHANGED seen
             [] Twin \notin {"Interim", "Landed"} /\ slot.stored /\ (slot.origin = p \/ Twin = "NoOriginAtDelete")
                    /\ slot.at = now /\ Twin # "NoSettle" ->
                    /\ evac' = [evac EXCEPT ![e].stage = "drop"]
                    /\ seen' = [seen EXCEPT !.young = TRUE]
             [] OTHER ->
                    /\ evac' = [evac EXCEPT ![e].stage = "delete", ![e].at = slot.at]
                    /\ UNCHANGED seen
        /\ UNCHANGED <<now, head, held, slot, att, rec, commitAt, consumed, left>>

\* What the store does with the DELETE: only the object the HEAD saw goes (x-ur-if-unmodified-ms,
\* which also takes one stored in the same tick); the twin and the code as landed delete whatever
\* is there.
Deletes(e) ==
    /\ slot.stored
    /\ Twin \in {"Landed", "UnconditionalDelete"} \/ slot.at = evac[e].at

EvacDelete(e) ==
    /\ evac[e].stage = "delete"
    /\ IF Deletes(e)
       THEN /\ slot' = NoSlot
            /\ seen' = [seen EXCEPT !.lost = @ \cup Losses("evacuation", Standing), !.deleted = TRUE]
       ELSE UNCHANGED <<slot, seen>>
    /\ evac' = [evac EXCEPT ![e].stage = "drop"]
    /\ UNCHANGED <<now, head, held, att, rec, commitAt, consumed, left>>

\* The record leaves its batch: a committed one for its container, a dead one for good.
EvacDrop(e) ==
    /\ evac[e].stage \in {"keep", "drop"}
    /\ rec' = rec \ {[push |-> evac[e].push, minute |-> evac[e].minute]}
    /\ evac' = [evac EXCEPT ![e] = NoEvac]
    /\ UNCHANGED <<now, head, held, slot, att, commitAt, consumed, left, seen>>

\* A killed run restarts the minute: what it wrote stands.
EvacCrash(e) ==
    /\ evac[e].stage # "idle"
    /\ left.crashes > 0
    /\ left' = [left EXCEPT !.crashes = @ - 1]
    /\ evac' = [evac EXCEPT ![e] = NoEvac]
    /\ UNCHANGED <<now, head, held, slot, att, rec, commitAt, consumed, seen>>

(***************************************************************************)
(* Time.                                                                    *)
(***************************************************************************)

Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<head, held, slot, att, rec, commitAt, consumed, evac, left, seen>>

Next ==
    \/ \E p \in Pushes :
           \/ Arrive(p)
           \/ Check(p)
           \/ SlotPut(p)
           \/ SlotGet(p)
           \/ SlotTake(p)
           \/ LateRecord(p)
           \/ Land(p)
           \/ Stall(p)
           \/ StallLands(p)
           \/ StallReverts(p)
           \/ Reread(p)
           \/ Consume(p)
    \/ Move
    \/ Cut
    \/ Rewrite
    \/ \E e \in Evacs :
           \/ \E r \in rec : EvacStart(e, r)
           \/ EvacResolve(e)
           \/ EvacFence(e)
           \/ EvacHead(e)
           \/ EvacDelete(e)
           \/ EvacDrop(e)
           \/ EvacCrash(e)
    \/ Tick

Spec == Init /\ [][Next]_vars

\* The evacuator keeps working, stalled writes settle, and time passes; nothing else is assumed.
EvacStep ==
    \E e \in Evacs :
        \/ \E r \in rec : EvacStart(e, r)
        \/ EvacResolve(e)
        \/ EvacFence(e)
        \/ EvacHead(e)
        \/ EvacDelete(e)
        \/ EvacDrop(e)

Fairness ==
    /\ WF_vars(EvacStep)
    /\ WF_vars(Tick)
    /\ \A p \in Pushes : WF_vars(StallLands(p) \/ StallReverts(p))

LiveSpec == Spec /\ Fairness

Symmetry == Permutations(Pushes) \cup Permutations(Evacs)

TypeOk ==
    /\ now \in 0..MaxTime
    /\ held \in Pushes \cup {NoOne}
    /\ slot.origin \in Pushes \cup {NoOne}
    /\ \A p \in Pushes : att[p].stage \in {"idle", "read", "slot", "found", "take", "late", "ready", "stalled",
                                           "reread", "done"}
    /\ \A e \in Evacs : evac[e].stage \in {"idle", "resolve", "fence", "keep", "dead", "delete", "drop"}
    /\ consumed \subseteq Pushes

\* I-EVS-1 for slots: no committed version that stands names a deleted slot.
ClosureHolds == seen.lost = {}

\* The three ways the code as landed loses one, each its own invariant: a push that took another
\* statement's object loses it to that statement's dead record (a retoken); a push loses the object
\* it created to the dead record of a statement that listed it again; a push loses it to the removal
\* of another committed version that listed it again.
AdopterKept == \A l \in seen.lost : ~(l.by = "evacuation" /\ l.made # l.push)
CreatorKept == \A l \in seen.lost : ~(l.by = "evacuation" /\ l.made = l.push)
ConsumeKeeps == \A l \in seen.lost : l.by # "consume"

\* A committed push's slot stands under its own statement's origin until its version is removed.
OriginStands == \A p \in Standing : slot.stored /\ slot.origin = p

\* No two committed versions that stand introduce the one slot.
OneIntroducer == Cardinality(Standing) <= 1

\* A statement's origin is on a slot only after its record was written.
StampHasRecord == slot.stored /\ slot.origin \in Pushes => att[slot.origin].recorded

\* A statement resolved dead, by evacuation or by a takeover of its slot, is dead for good.
DeadIsFinal == \A p \in seen.judged : commitAt[p] = 0

\* Every record old enough to evacuate before the behavior ends leaves its batch: a slot never
\* holds a minute back.
RecordsLeave ==
    \A p \in Pushes, m \in 0..MaxTime :
        ([push |-> p, minute |-> m] \in rec /\ m + EvacAge <= MaxTime) ~> ([push |-> p, minute |-> m] \notin rec)

\* States the design must be able to reach, each as an invariant that says it never does.
NeverDeletes == ~seen.deleted
NeverRefuses == seen.refused = {}
NeverYoung == ~seen.young
NeverSecondLife == ~(seen.deleted /\ Standing # {})
NeverTakes == \A p \in seen.took : commitAt[p] = 0
\* A slot left for good: its statement is dead and ended, and no record of it is left.
NeverLeaks ==
    ~(/\ slot.stored
      /\ slot.origin \in Pushes
      /\ commitAt[slot.origin] = 0
      /\ att[slot.origin].stage = "done"
      /\ \A r \in rec : r.push # slot.origin)

=============================================================================
