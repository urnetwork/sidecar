---------------------------- MODULE IndexMerge ----------------------------
(***************************************************************************)
(* DESIGN-DETAILS.md section 1's model of the search index's upkeep on one  *)
(* index ref (§11.14): writers' heads, sealed slots and large entries,      *)
(* merges, the roll-up of an expired bucket under its lock, and the journal *)
(* behind companion pushes and backfills. Every commit is one head CAS:     *)
(* each file it replaces at the version its builder read. The erasure's     *)
(* CUT, CLOSUREs and index_epoch are IndexRollup.tla's and are not here.    *)
(*                                                                          *)
(* The design (section 1.2), which the passing configurations run:          *)
(*   Bases = "own"        a diff rests on a full entry in another file of   *)
(*                        its own writer in its own bucket, a slot that is  *)
(*                        not the head or a large entry, which that writer  *)
(*                        keeps while the diff needs it (1.2.3)             *)
(*   head CAS             every push that writes a writer's file replaces   *)
(*                        that writer's head as the push's base showed it   *)
(*   Supersede = "content" a journaled entry is dropped when its content    *)
(*                        ref, read after the index, holds its document at  *)
(*                        a higher version (1.2.6)                          *)
(*   Step4 = "promote"    a roll-up moves a version or tombstone that a     *)
(*                        newer bucket holds only older entries of into     *)
(*                        that bucket's shards, replacing its manifest      *)
(*   Life = "short"       a built push lands within minutes or never        *)
(*                                                                          *)
(* §11.14 as written, which the Written configurations run and TLC refuses: *)
(*   Bases = "shard"      a diff rests on its document's previous version   *)
(*                        outside every head, merges read heads and keep a  *)
(*                        base (KeepBase "all"), composing each document's  *)
(*                        newest input (MergeCompose "newest")              *)
(*   Supersede = "index"  superseded is judged from the index alone         *)
(*   Step4 = "inplace"    a roll-up rewrites a newer bucket's files in      *)
(*                        place, replacing only those (RollupFence "files") *)
(* KeepBase "any", MergeCompose "composable" and RollupFence "manifests"    *)
(* are three of the questions' first options, kept so the patched rules can *)
(* be run beside the design; MergeCompose "covered" widens the second to a  *)
(* head entry at the same version. Both patched pairs fail too (1.1 E).     *)
(*                                                                          *)
(* Documents: d2 is edited four times and its edits may be diffs; d3 is     *)
(* created and deleted. A full entry of a document in BigDocs is past 8 KiB *)
(* and so a large entry, a file of its own; any other full entry sits in a  *)
(* slot. Story fixes the order of the content commits, which push nothing   *)
(* to the index themselves: the journaler and the backfiller do, as on      *)
(* ur/index. An in-ref push is the behavior in which an entry is built and  *)
(* committed with its content, so every in-ref behavior is one of these.    *)
(*                                                                          *)
(* What the model abstracts:                                                *)
(* - A document's text is its version. Sizes, chunks, ref tombstones,       *)
(*   capped and joined shards do not appear; a bucket has one shard file.   *)
(* - When a head is full is a choice: a push may seal its writer's head     *)
(*   while a slot is free. Whether an edit's delta is small enough for a    *)
(*   diff is a choice too.                                                  *)
(* - A push carries one entry. The design's push carries every entry due,   *)
(*   which is some sequence of these.                                       *)
(* - Time is three windows, each with an early and a late part (clock 1 to  *)
(*   5, bucket 1 expiring at 5). A push built late in a window may land     *)
(*   early in the next, none longer (Life "short"). Early in a window a     *)
(*   push's signed time may fall in the window before (Skew). An entry goes *)
(*   to the bucket of its signed time: D-EVS-45's move to a newer bucket    *)
(*   already holding its document is one of those choices, so no invariant  *)
(*   here rests on it.                                                      *)
(* - A writer's process may die with a push in flight and build again       *)
(*   (Restart); the first push may still land.                              *)
(*                                                                          *)
(* Still names what a run holds still, for focused runs: a process          *)
(* ("backfill", "merge", "rollup", "crash", "lapse"), time ("tick": every   *)
(* step in window 1), the backfiller's diffs ("bfdiff": it writes full      *)
(* entries only) or the Reach marks ("marks": not recorded). Twin names a   *)
(* rule to break; a twin config sets it, and TLC must then refuse the model *)
(* with the invariant that rule protects. "none" is the design.             *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Journaler,      \* the writer whose journal holds the story's entries
    Backfiller,     \* the writer that backfills what no head holds
    Rollers,        \* devices that may run the roll-up: model values
    MaxSlots,       \* slots a writer may hold in a bucket (16 in the design)
    MaxCrashes,     \* crashes of rollers in one behavior
    MaxLapses,      \* expiries of a live holder's lock in one behavior
    MaxRestarts,    \* writer processes that die with a push in flight
    Documents,      \* the documents whose content commits a run makes: any of "d2", "d3"
    BigDocs,        \* the documents whose full entries are large entries
    Events,         \* how many of those commits a run makes, in Story's order
    Skew,           \* whether a push's signed time may fall in the window before the current one
    Bases,          \* "own": the design; "shard": §11.14 as written
    KeepBase,       \* Bases "shard" only: "all" as written, "any" question keep-base-full-copy's option 1
    MergeCompose,   \* Bases "shard" only: "newest" as written, "composable" question merge-stale-diff's option 1,
                    \* "covered" that option widened to a head entry at the same version
    Supersede,      \* "content": the design; "index": §11.14 as written
    Step4,          \* "promote": the design; "inplace": §11.14 as written
    RollupFence,    \* Step4 "inplace" only: "files" as written, "manifests" question rollup-merge-race's option 1
    Life,           \* "short": the design; "long": a built push lands whenever
    Still,          \* held still: any of "backfill", "merge", "rollup", "crash", "lapse", "tick", "bfdiff", "marks"
    Twin            \* "none", or the rule a twin config breaks

Writers == {Journaler, Backfiller}
Docs == {"d2", "d3"}
Buckets == 1..3
LastClock == 5
NoRoller == "none"
NoPath == <<>>
None == [kind |-> "none"]

Twins == {"none", "NoOwnCas", "CleanupReferenced", "MergeRemovesLarge", "ReuseUnabsorbed", "ReusePinned",
          "MergeDropsTombstone", "NoPromote", "PromoteBlind", "RollupForgetsHeads"}

ASSUME
    /\ Journaler # Backfiller
    /\ MaxSlots \in 1..16
    /\ Twin \in Twins
    /\ Still \subseteq {"backfill", "merge", "rollup", "crash", "lapse", "tick", "bfdiff", "marks"}
    /\ Bases \in {"own", "shard"}
    /\ KeepBase \in {"all", "any"}
    /\ MergeCompose \in {"newest", "composable", "covered"}
    /\ Supersede \in {"index", "content"}
    /\ Step4 \in {"promote", "inplace"}
    /\ RollupFence \in {"files", "manifests"}
    /\ Life \in {"short", "long"}

\* The content commits, in order, each at or after its window. The journaler journals each one unless it skips
\* the index (an old client), which is left for the backfiller.
Story == <<
    [d |-> "d3", v |-> 1, op |-> "put", at |-> 1, skip |-> FALSE],
    [d |-> "d2", v |-> 1, op |-> "put", at |-> 1, skip |-> FALSE],
    [d |-> "d3", v |-> 2, op |-> "del", at |-> 1, skip |-> TRUE],
    [d |-> "d2", v |-> 2, op |-> "put", at |-> 1, skip |-> FALSE],
    [d |-> "d2", v |-> 3, op |-> "put", at |-> 1, skip |-> FALSE],
    [d |-> "d2", v |-> 4, op |-> "put", at |-> 1, skip |-> FALSE]
>>

Plot == SelectSeq(Story, LAMBDA s : s.d \in Documents)

ASSUME Documents \subseteq Docs /\ BigDocs \subseteq Docs /\ Events \in 0..Len(Plot)

Max(S) == CHOOSE m \in S : \A n \in S : n <= m
Min(S) == CHOOSE m \in S : \A n \in S : m <= n

IsBig(d) == d \in BigDocs

SlotPath(b, w, k) == <<"w", b, w, k>>
ShardPath(b) == <<"s", b>>
AllPath == <<"a">>
SlotPaths(b, w) == {SlotPath(b, w, k) : k \in 1..MaxSlots}
BucketSlots(b) == UNION {SlotPaths(b, w) : w \in Writers}
BucketPaths(b) == BucketSlots(b) \cup {ShardPath(b)}
Paths == (UNION {BucketPaths(b) : b \in Buckets}) \cup {AllPath}

VARIABLES
    clock,       \* 1 to 5: window (clock + 1) \div 2, early on odd clocks, late on even
    file,        \* file[p]: a slot, a bucket's shard or all's: live, ver, seq (slots) and ent
    large,       \* large[b][w]: w's large entries in bucket b, each {seq, d, v}, a full entry alone in a file
    man,         \* man[b]: bucket b's manifest: ver and abs, each writer's highest absorbed seq
    gone,        \* buckets a roll-up removed
    rolled,      \* a/m's rolled_through: 0, or 1 once bucket 1 is rolled
    lock,        \* <root>/lock: ver, holder and lapsed (its until_ms past)
    next,        \* the story's next content commit
    content,     \* content[d]: the newest committed version of d's content, v and op
    journal,     \* the journaler's entries not yet in a committed head push
    wpend,       \* wpend[w]: w's built head push, or None
    wlate,       \* wlate[w]: the push a dead process of w left in flight, or None
    mpend,       \* the merger's built merge, or None
    rphase,      \* rphase[r]: "idle", "holding", "crashed" or "done"
    rheld,       \* rheld[r]: the lock version r took, 0 for none
    rpend,       \* rpend[r]: r's built lock take or roll-up, or None
    crashes,     \* crashes left
    lapses,      \* expiries of a live holder's lock left
    restarts,    \* writer restarts left
    indexed,     \* ghost: indexed[d], the newest entry of d a committed push carried: v and k
    rollCommits, \* ghost: committed roll-ups of bucket 1
    fenceBad,    \* ghost: a roll-up committed from a lock version its runner did not take
    broken,      \* ghost: a merge or roll-up met an entry it could not compose from its inputs
    reached      \* ghost: what a behavior did, for the Reach configurations

storeVars == <<file, large, man, gone, rolled, lock>>
worldVars == <<clock, next, content, journal>>
procVars == <<wpend, wlate, mpend, rphase, rheld, rpend>>
budgetVars == <<crashes, lapses, restarts>>
ghostVars == <<indexed, rollCommits, fenceBad, broken, reached>>
vars == <<storeVars, worldVars, procVars, budgetVars, ghostVars>>

(***************************************************************************)
(* Reading the index at the head.                                           *)
(***************************************************************************)

Now == (clock + 1) \div 2
Early == clock % 2 = 1

Exists(p) == file[p].live
WriterSlots(b, w) == {p \in SlotPaths(b, w) : Exists(p)}
HeadOf(b, w) ==
    IF WriterSlots(b, w) = {} THEN NoPath
    ELSE CHOOSE p \in WriterSlots(b, w) : \A q \in WriterSlots(b, w) : file[q].seq <= file[p].seq
Heads(b) == {HeadOf(b, w) : w \in Writers} \ {NoPath}
IsAbsorbed(p) == file[p].seq <= man[p[2]].abs[p[3]]
\* A writer's slots other than its head that no merge has absorbed. An absorbed slot holds nothing.
Sealed(b) == {p \in BucketSlots(b) : Exists(p) /\ p \notin Heads(b) /\ ~IsAbsorbed(p)}
\* A writer's large entries no merge has absorbed. An absorbed one holds nothing but a diff's base.
LiveLarge(b, w) == {l \in large[b][w] : l.seq > man[b].abs[w]}
AsFull(l) == [d |-> l.d, v |-> l.v, k |-> "full", base |-> 0]
LargeEnts(b) == UNION {{AsFull(l) : l \in LiveLarge(b, w)} : w \in Writers}

EntsAt(P) == UNION {IF Exists(p) THEN file[p].ent ELSE {} : p \in P}
HeadEnts(b) == IF b \in gone THEN {} ELSE EntsAt(Heads(b))
\* What lies outside every writer's head in bucket b: its shard, its sealed slots and its large entries.
OutEnts(b) == IF b \in gone THEN {} ELSE EntsAt(Sealed(b) \cup {ShardPath(b)}) \cup LargeEnts(b)
BucketEnts(b) == HeadEnts(b) \cup OutEnts(b)
AllEnts == EntsAt({AllPath})
IndexEnts == AllEnts \cup (UNION {BucketEnts(b) : b \in Buckets})
BucketLive(b) == b \notin gone /\ ((\E p \in BucketPaths(b) : Exists(p)) \/ (\E w \in Writers : large[b][w] # {}))

Of(S, d) == {e \in S : e.d = d}
Top(S, d) == IF Of(S, d) = {} THEN 0 ELSE Max({e.v : e \in Of(S, d)})
TombAt(S, d, v) == \E e \in Of(S, d) : e.v = v /\ e.k = "tomb"

\* A search's answer per document over the entries S: its newest version, unless that is a tombstone (§11.14's
\* newest row); 0 for no hit.
ViewOf(S) == [d \in Docs |-> LET t == Top(S, d) IN IF t = 0 \/ TombAt(S, d, t) THEN 0 ELSE t]

\* What every search must answer: each document's newest indexed version.
Truth == [d \in Docs |-> IF indexed[d].v = 0 \/ indexed[d].k = "tomb" THEN 0 ELSE indexed[d].v]

\* A Reach mark, where a run records them.
Mark(S) == IF "marks" \in Still THEN reached ELSE reached \cup S

Row(S, d, v) == [d |-> d, v |-> v, k |-> IF TombAt(S, d, v) THEN "tomb" ELSE "full", base |-> 0]
Newer(old, e) == IF e.v > old.v THEN [v |-> e.v, k |-> IF e.k = "tomb" THEN "tomb" ELSE "live"] ELSE old

(***************************************************************************)
(* Bases "own": a diff in a slot of writer w in bucket b rests on the full  *)
(* entry of its document at its base version in another file of w's in b:   *)
(* a large entry, or a slot that is not w's head, absorbed or not.          *)
(***************************************************************************)

BaseVersions(b, w, d) ==
    {l.v : l \in {x \in large[b][w] : x.d = d}}
        \cup {x.v : x \in {y \in EntsAt(WriterSlots(b, w) \ {HeadOf(b, w)}) : y.d = d /\ y.k = "full"}}
HasBase(b, w, e) == e.base \in BaseVersions(b, w, e.d)
\* A slot's entries with each diff composed onto its base; a diff with no base composes to nothing.
SlotResolved(p) ==
    {IF e.k = "diff" THEN [d |-> e.d, v |-> e.v, k |-> "full", base |-> 0] ELSE e :
        e \in {x \in file[p].ent : x.k # "diff" \/ HasBase(p[2], p[3], x)}}
SlotBroken(p) == \E e \in file[p].ent : e.k = "diff" /\ ~HasBase(p[2], p[3], e)

(***************************************************************************)
(* Bases "shard", §11.14 as written: a diff resolves outside every head.    *)
(***************************************************************************)

RECURSIVE Resolves(_, _, _)
Resolves(b, d, v) ==
    \E e \in Of(OutEnts(b), d) :
        /\ e.v = v
        /\ e.k = "full" \/ (e.k = "diff" /\ Resolves(b, d, e.base))

RECURSIVE ComposesIn(_, _, _)
ComposesIn(S, d, v) ==
    \E e \in Of(S, d) :
        /\ e.v = v
        /\ e.k \in {"full", "tomb"} \/ (e.k = "diff" /\ ComposesIn(S, d, e.base))

\* The dependency row as written: the base a diff of d at version v may name in bucket b for w's push, or 0.
DiffBaseWritten(w, b, d, v) ==
    LET t == Top(IndexEnts, d)
        outTop == Top(OutEnts(b), d)
        own == IF HeadOf(b, w) = NoPath THEN {} ELSE Of(EntsAt({HeadOf(b, w)}), d)
        headDiffAt(u) == \E e \in Of(HeadEnts(b), d) : e.v = u /\ e.k = "diff"
    IN  IF b # Now \/ v = 1 \/ t # v - 1 \/ TombAt(IndexEnts, d, t) THEN 0
        ELSE IF /\ \E e \in Of(OutEnts(b), d) : e.v = v - 1 /\ e.k # "tomb"
                /\ ~headDiffAt(v - 1)
             THEN v - 1
        ELSE IF /\ outTop > 0
                /\ \E e \in own : e.v = v - 1 /\ e.k = "diff" /\ e.base = outTop
             THEN outTop
        ELSE 0

(***************************************************************************)
(* Writers: the journaler's companion pushes and the backfiller's.          *)
(***************************************************************************)

\* The windows a push built now may be signed in.
Windows == IF Skew /\ Early /\ Now > 1 THEN {Now, Now - 1} ELSE {Now}

\* A push lands only within minutes of its build: at its own clock, or, built late in a window, early in the
\* next (1.2.6's life). Life "long" is a client that sends a push it built long before.
Alive(P) == Life = "long" \/ P.t = clock \/ (P.t + 1 = clock /\ P.t % 2 = 0)

\* The versions of d below v that w's other files in b hold full: what a diff of d at v may rest on.
OwnBases(b, w, d, v) == {y \in BaseVersions(b, w, d) : y < v}

\* The entries w may write for content version j in bucket b. Under "own" an edit is a diff on the newest full
\* entry of its document in w's other files there, or full where the delta is too large or no such entry is;
\* under "shard" the journaler follows the dependency row as written and the backfiller writes full entries.
EntryOptions(w, b, j) ==
    LET full == [d |-> j.d, v |-> j.v, k |-> "full", base |-> 0] IN
    IF j.op = "del" THEN {[d |-> j.d, v |-> j.v, k |-> "tomb", base |-> 0]}
    ELSE IF Bases = "own"
         THEN {full} \cup
              (IF OwnBases(b, w, j.d, j.v) # {} /\ ~(w = Backfiller /\ "bfdiff" \in Still)
               THEN {[d |-> j.d, v |-> j.v, k |-> "diff", base |-> Max(OwnBases(b, w, j.d, j.v))]}
               ELSE {})
    ELSE IF w = Journaler /\ DiffBaseWritten(w, b, j.d, j.v) > 0
         THEN {[d |-> j.d, v |-> j.v, k |-> "diff", base |-> DiffBaseWritten(w, b, j.d, j.v)]}
         ELSE {full}

MaxSeq(b, w) ==
    Max({0} \cup {file[p].seq : p \in WriterSlots(b, w)} \cup {l.seq : l \in large[b][w]})
\* The slots of w in b, other than its head, holding a full entry that a diff in S names: w keeps them.
PinnedSlots(b, w, S) ==
    {q \in WriterSlots(b, w) \ {HeadOf(b, w)} :
        \E x \in file[q].ent : x.k = "full" /\ \E e \in S : e.k = "diff" /\ e.d = x.d /\ e.base = x.v}
\* The slot a seal opens when the push leaves w's unabsorbed slots holding S: the lowest the manifest shows
\* absorbed that no diff in S rests on, else a new one (§11.14's seal row with 1.2.3's keep rule).
Reusable(b, w, S) ==
    {k \in 1..MaxSlots :
        /\ Exists(SlotPath(b, w, k))
        /\ SlotPath(b, w, k) # HeadOf(b, w)
        /\ IsAbsorbed(SlotPath(b, w, k)) \/ Twin = "ReuseUnabsorbed"
        /\ SlotPath(b, w, k) \notin PinnedSlots(b, w, S) \/ Twin = "ReusePinned" \/ Bases = "shard"}
Unused(b, w) == {k \in 1..MaxSlots : ~Exists(SlotPath(b, w, k))}
SealSlot(b, w, S) ==
    IF Reusable(b, w, S) # {} THEN Min(Reusable(b, w, S))
    ELSE IF Unused(b, w) # {} THEN Min(Unused(b, w)) ELSE 0

\* What w's sealed, unabsorbed slots in b hold.
SealedEnts(b, w) == EntsAt(Sealed(b) \cap SlotPaths(b, w))
\* The large entries of w in b that a push may remove when it leaves w's unabsorbed slots holding S: those the
\* manifest shows absorbed that no diff in S names (1.2.3).
Removable(b, w, S) ==
    {l \in large[b][w] :
        /\ l.seq <= man[b].abs[w]
        /\ Twin = "CleanupReferenced" \/ ~\E e \in S : e.k = "diff" /\ e.d = l.d /\ e.base = l.v}

\* w's head push of entry e into bucket b: creating w's first slot there; appending to its head, a newer entry
\* replacing the head's entry of its document; sealing the head as it stood and opening the next slot with e;
\* or writing e and, the slot now full, opening the next slot for the push's other documents, which the model
\* does not follow (p2, an empty head). A full entry of a big document is a large entry numbered below a
\* renumbered head. hp and hv are the head as the base showed it, which the push replaces (1.2.3's head rule).
HeadPushes(w, b, e) ==
    LET head == HeadOf(b, w)
        big == Bases = "own" /\ IsBig(e.d) /\ e.k = "full"
        ms == MaxSeq(b, w)
        lg == IF big THEN {[seq |-> ms + 1, d |-> e.d, v |-> e.v]} ELSE {}
        push(p, hp, seq, ent, refs, p2, seq2) ==
            [kind |-> "head", b |-> b, w |-> w, hp |-> hp, hv |-> IF hp = NoPath THEN 0 ELSE file[hp].ver,
             p |-> p, ver |-> file[p].ver, seq |-> seq, ent |-> ent,
             p2 |-> p2, ver2 |-> IF p2 = NoPath THEN 0 ELSE file[p2].ver, seq2 |-> seq2, lgAdd |-> lg,
             lgDrop |-> IF Bases = "own" THEN Removable(b, w, refs) ELSE {}, entry |-> e, t |-> clock]
        first == IF big THEN {} ELSE {e}
    IN  IF head = NoPath
        THEN {push(SlotPath(b, w, 1), NoPath, IF big THEN ms + 2 ELSE ms + 1, first, first, NoPath, 0)}
             \cup (IF big \/ MaxSlots < 2 THEN {}
                   ELSE {push(SlotPath(b, w, 1), NoPath, ms + 1, first, first, SlotPath(b, w, 2), ms + 2)})
        ELSE LET kept == {y \in file[head].ent : y.d # e.d}
                 appended == IF big THEN kept ELSE kept \cup {e}
                 refsA == appended \cup SealedEnts(b, w)
                 refsO == {e} \cup file[head].ent \cup SealedEnts(b, w)
                 kA == SealSlot(b, w, refsA)
                 kO == SealSlot(b, w, refsO)
             IN  {push(head, head, IF big THEN ms + 2 ELSE file[head].seq, appended, refsA, NoPath, 0)}
                 \cup (IF big \/ kO = 0 THEN {}
                       ELSE {push(SlotPath(b, w, kO), head, ms + 1, {e}, refsO, NoPath, 0)})
                 \cup (IF big \/ kA = 0 THEN {}
                       ELSE {push(head, head, file[head].seq, appended, refsA, SlotPath(b, w, kA), ms + 1)})

\* §11.14's superseded rule. As written ("index") a journaled entry is dropped when the index at the push's base
\* holds its document at a higher version. The design ("content") drops it when the content ref, read after the
\* index, holds its document at a higher version or removed, and leaves the newer version to its own entry.
Superseded(j) ==
    IF Supersede = "content" THEN content[j.d].v > j.v ELSE Top(IndexEnts, j.d) > j.v

JournalBuild ==
    /\ wpend[Journaler] = None
    /\ journal # <<>>
    /\ LET j == Head(journal) IN
       IF Superseded(j)
       THEN /\ journal' = Tail(journal)
            /\ reached' = Mark({"dropped"})
            /\ UNCHANGED wpend
       ELSE /\ \E t0 \in Windows : \E e \in EntryOptions(Journaler, t0, j) :
                 \E push \in HeadPushes(Journaler, t0, e) :
                     wpend' = [wpend EXCEPT ![Journaler] = push]
            /\ UNCHANGED <<journal, reached>>
    /\ UNCHANGED <<storeVars, clock, next, content, wlate, mpend, rphase, rheld, rpend, budgetVars,
                   indexed, rollCommits, fenceBad, broken>>

\* A content version no index entry reaches yet, which the backfiller indexes into its own head from the
\* content as it stands (1.2.6).
BackfillBuild ==
    /\ "backfill" \notin Still
    /\ wpend[Backfiller] = None
    /\ \E d \in Docs :
           /\ content[d].v > 0
           /\ indexed[d].v < content[d].v
           /\ \E t0 \in Windows :
                  LET j == [d |-> d, v |-> content[d].v, op |-> content[d].op] IN
                  \E e \in EntryOptions(Backfiller, t0, j) :
                      \E push \in HeadPushes(Backfiller, t0, e) :
                          wpend' = [wpend EXCEPT ![Backfiller] = push]
    /\ UNCHANGED <<storeVars, worldVars, wlate, mpend, rphase, rheld, rpend, budgetVars, ghostVars>>

\* The head CAS of push P. Under "own" the push replaces its writer's head as its base showed it, creating the
\* writer's first slot only where it still has none, so a writer's pushes commit one at a time and every file of
\* the writer's is as the push read it. On 409 the builder rereads and builds again.
HeadOk(P) ==
    /\ P.b \notin gone
    /\ file[P.p].ver = P.ver
    /\ P.p2 = NoPath \/ file[P.p2].ver = P.ver2
    /\ (Bases = "own" /\ Twin # "NoOwnCas") =>
           IF P.hp = NoPath THEN WriterSlots(P.b, P.w) = {} ELSE file[P.hp].ver = P.hv

HeadApply(P) ==
    /\ file' = [q \in Paths |->
                   IF q = P.p THEN [live |-> TRUE, ver |-> file[q].ver + 1, seq |-> P.seq, ent |-> P.ent]
                   ELSE IF q = P.p2 THEN [live |-> TRUE, ver |-> file[q].ver + 1, seq |-> P.seq2, ent |-> {}]
                   ELSE IF Bases = "own" /\ Twin # "NoOwnCas" /\ q = P.hp THEN [file[q] EXCEPT !.ver = @ + 1]
                   ELSE file[q]]
    /\ large' = [large EXCEPT ![P.b][P.w] = (@ \ P.lgDrop) \cup P.lgAdd]
    /\ indexed' = [indexed EXCEPT ![P.entry.d] = Newer(@, P.entry)]

HeadCommit(w) ==
    LET P == wpend[w] IN
    /\ P.kind = "head"
    /\ Alive(P)
    /\ IF HeadOk(P)
       THEN /\ HeadApply(P)
            /\ journal' = IF w = Journaler THEN Tail(journal) ELSE journal
       ELSE UNCHANGED <<file, large, indexed, journal>>
    /\ wpend' = [wpend EXCEPT ![w] = None]
    /\ UNCHANGED <<man, gone, rolled, lock, clock, next, content, wlate, mpend, rphase, rheld, rpend,
                   budgetVars, rollCommits, fenceBad, broken, reached>>

\* A writer's process dies with a push in flight. The push may still land; the process that follows reads its
\* journal again and builds anew.
Restart(w) ==
    /\ restarts > 0
    /\ wpend[w] # None
    /\ wlate[w] = None
    /\ wlate' = [wlate EXCEPT ![w] = wpend[w]]
    /\ wpend' = [wpend EXCEPT ![w] = None]
    /\ restarts' = restarts - 1
    /\ UNCHANGED <<storeVars, worldVars, mpend, rphase, rheld, rpend, crashes, lapses, ghostVars>>

LateCommit(w) ==
    LET P == wlate[w] IN
    /\ P.kind = "head"
    /\ Alive(P)
    /\ IF HeadOk(P) THEN HeadApply(P) ELSE UNCHANGED <<file, large, indexed>>
    /\ wlate' = [wlate EXCEPT ![w] = None]
    /\ UNCHANGED <<man, gone, rolled, lock, worldVars, wpend, mpend, rphase, rheld, rpend, budgetVars,
                   rollCommits, fenceBad, broken, reached>>

(***************************************************************************)
(* The merger (§11.14's merges): a bucket's sealed slots and large entries  *)
(* into its shard.                                                          *)
(***************************************************************************)

\* The design's merge: each document's newest version among the shard, the sealed slots and the large entries,
\* every diff composed onto its own writer's base. It reads no head.
MergeInOwn(b) ==
    file[ShardPath(b)].ent \cup (UNION {SlotResolved(p) : p \in Sealed(b)}) \cup LargeEnts(b)

\* As written: the version a merge keeps of d from inputs In, given the heads' entries H.
MergeVersion(In, H, d) ==
    LET top == Top(In, d)
        hTop == Top(H, d)
        hn == {e \in Of(H, d) : e.v = hTop}
        hd == {e \in hn : e.k = "diff" /\ \E i \in Of(In, d) : i.v = e.base}
    IN  IF /\ hTop >= top
           /\ hd # {}
           /\ KeepBase = "any" \/ hd = hn
        THEN Min({e.base : e \in hd})
        ELSE top
Composable(In, d) == {e.v : e \in {y \in Of(In, d) : ComposesIn(In, d, y.v)}}
MergeKept(In, H, d) ==
    LET v == MergeVersion(In, H, d) IN
    IF /\ MergeCompose # "newest"
       /\ ~ComposesIn(In, d, v)
       /\ Top(H, d) > v \/ (MergeCompose = "covered" /\ Top(H, d) = v)
    THEN IF Composable(In, d) = {} THEN 0 ELSE Max(Composable(In, d))
    ELSE v

MergeRows(b) ==
    LET kept == IF Bases = "own"
                THEN LET In == MergeInOwn(b) IN {Row(In, d, Top(In, d)) : d \in {e.d : e \in In}}
                ELSE LET In == OutEnts(b)
                         H == HeadEnts(b)
                     IN  {Row(In, d, MergeKept(In, H, d)) : d \in {doc \in {e.d : e \in In} : MergeKept(In, H, doc) > 0}}
    IN  IF Twin = "MergeDropsTombstone" THEN {r \in kept : r.k # "tomb"} ELSE kept

MergeBroken(b) ==
    IF Bases = "own" THEN \E p \in Sealed(b) : SlotBroken(p)
    ELSE LET In == OutEnts(b)
             H == HeadEnts(b)
         IN  \E d \in {e.d : e \in In} : MergeKept(In, H, d) > 0 /\ ~ComposesIn(In, d, MergeKept(In, H, d))

MergeBuild(b) ==
    /\ "merge" \notin Still
    /\ mpend = None
    /\ BucketLive(b)
    /\ b >= Now - 1
    /\ Sealed(b) # {} \/ \E w \in Writers : LiveLarge(b, w) # {}
    /\ LET abs == [w \in Writers |->
                      Max({man[b].abs[w]} \cup {file[p].seq : p \in Sealed(b) \cap SlotPaths(b, w)}
                          \cup {l.seq : l \in LiveLarge(b, w)})]
       IN  mpend' = [kind |-> "merge", b |-> b, shard |-> file[ShardPath(b)].ver, man |-> man[b].ver,
                     rows |-> MergeRows(b), abs |-> abs, t |-> clock]
    /\ broken' = (broken \/ MergeBroken(b))
    /\ reached' = IF \E p \in Sealed(b) : \E e \in file[p].ent : e.k = "diff" /\ Top(OutEnts(b), e.d) = e.v
                  THEN Mark({"composed"}) ELSE reached
    /\ UNCHANGED <<storeVars, worldVars, wpend, wlate, rphase, rheld, rpend, budgetVars, indexed,
                   rollCommits, fenceBad>>

\* One push: the shard and the manifest, each at the version read. It writes no file of any writer; as written
\* (and under the twin) it also removes the large entries it absorbed.
MergeCommit ==
    LET P == mpend
        s == ShardPath(P.b)
        ok == /\ P.b \notin gone
              /\ file[s].ver = P.shard
              /\ man[P.b].ver = P.man
    IN  /\ P.kind = "merge"
        /\ Alive(P)
        /\ IF ok
           THEN /\ file' = [file EXCEPT ![s] = [live |-> TRUE, ver |-> @.ver + 1, seq |-> 0, ent |-> P.rows]]
                /\ man' = [man EXCEPT ![P.b] = [ver |-> @.ver + 1, abs |-> P.abs]]
                /\ large' = IF Bases = "shard" \/ Twin = "MergeRemovesLarge"
                            THEN [large EXCEPT ![P.b] = [w \in Writers |-> {l \in large[P.b][w] : l.seq > P.abs[w]}]]
                            ELSE large
           ELSE UNCHANGED <<file, man, large>>
        /\ mpend' = None
        /\ UNCHANGED <<gone, rolled, lock, worldVars, wpend, wlate, rphase, rheld, rpend, budgetVars,
                       ghostVars>>

(***************************************************************************)
(* The roll-up of bucket 1 (§11.14's roll-up), under the lock.              *)
(***************************************************************************)

\* Step 2's inputs: every entry of the bucket, writers' heads included, diffs composed.
RollSlots == IF Twin = "RollupForgetsHeads" THEN Sealed(1) ELSE Sealed(1) \cup Heads(1)
RollIn ==
    IF Bases = "own"
    THEN file[ShardPath(1)].ent \cup (UNION {SlotResolved(p) : p \in RollSlots}) \cup LargeEnts(1)
    ELSE EntsAt(RollSlots \cup {ShardPath(1)})
Carried(d) == Top(RollIn, d)
RollBroken ==
    IF Bases = "own" THEN \E p \in RollSlots : SlotBroken(p)
    ELSE \E d \in Docs : Carried(d) > 0 /\ ~ComposesIn(RollIn, d, Carried(d))

\* What the newer buckets hold of d, heads included, and the newest of them holding any of it.
NewerEnts == BucketEnts(2) \cup BucketEnts(3)
NewerTop(d) == Top(NewerEnts, d)
NewestHolding(d) == Max({b \in {2, 3} : Of(BucketEnts(b), d) # {}})

\* The design's step 4: a version or tombstone this roll-up carries, whose document the newer buckets hold only
\* at older versions, moves into the shards of the newest bucket holding it and stays there until that bucket
\* rolls, so no file of a newer bucket is rewritten in place and no tombstone is dropped above an older entry.
Promoted(d) ==
    /\ Step4 = "promote"
    /\ Twin # "NoPromote"
    /\ Carried(d) > 0
    /\ NewerTop(d) > 0
    /\ NewerTop(d) < Carried(d)
PromoBuckets == {NewestHolding(d) : d \in {x \in Docs : Promoted(x)}}
PromoEnt(nb) ==
    LET ds == {d \in Docs : Promoted(d) /\ NewestHolding(d) = nb} IN
    {e \in file[ShardPath(nb)].ent : e.d \notin ds} \cup {Row(RollIn, d, Carried(d)) : d \in ds}

\* Steps 3 and 4 for all: per document, the newer of the bucket's and all's stays, a tombstone taking all's row
\* and then going itself. A promoted tombstone takes all's row too; a promoted version leaves all's row be.
NewAll ==
    LET old == AllEnts
        keep(d) == [d |-> d, v |-> Top(old, d), k |-> "full", base |-> 0]
        row(d) == IF Promoted(d)
                  THEN (IF TombAt(RollIn, d, Carried(d)) THEN [d |-> d, v |-> 0, k |-> "full", base |-> 0] ELSE keep(d))
                  ELSE IF Carried(d) = 0 \/ Top(old, d) > Carried(d) THEN keep(d)
                  ELSE Row(RollIn, d, Carried(d))
    IN  {r \in {row(d) : d \in Docs} : r.v > 0 /\ r.k = "full"}

\* Step 4 as written: an entry of a newer bucket below a version or tombstone this roll-up carries leaves its
\* file, rewritten in place; RollupFence "manifests" also replaces that bucket's manifest.
Stale(p) == {e \in file[p].ent : Carried(e.d) > 0 /\ e.v < Carried(e.d)}
Rewrites ==
    IF Step4 = "inplace"
    THEN {p \in BucketPaths(2) \cup BucketPaths(3) : Exists(p) /\ Stale(p) # {}}
    ELSE {}
Fenced == IF RollupFence = "manifests" THEN {p[2] : p \in Rewrites} ELSE {}

TakeBuild(r) ==
    /\ "rollup" \notin Still
    /\ rphase[r] = "idle"
    /\ rpend[r] = None
    /\ Now = 3
    /\ BucketLive(1)
    /\ lock.holder = NoRoller \/ lock.lapsed
    /\ rpend' = [rpend EXCEPT ![r] = [kind |-> "take", lock |-> lock.ver, t |-> clock]]
    /\ UNCHANGED <<storeVars, worldVars, wpend, wlate, mpend, rphase, rheld, budgetVars, ghostVars>>

\* The lock push: from the version read, free or lapsed, to {r, until now + 30 min}.
TakeCommit(r) ==
    LET P == rpend[r] IN
    /\ P.kind = "take"
    /\ Alive(P)
    /\ IF lock.ver = P.lock
       THEN /\ lock' = [ver |-> lock.ver + 1, holder |-> r, lapsed |-> FALSE]
            /\ rheld' = [rheld EXCEPT ![r] = lock.ver + 1]
            /\ rphase' = [rphase EXCEPT ![r] = IF @ = "crashed" THEN @ ELSE "holding"]
       ELSE UNCHANGED <<lock, rheld, rphase>>
    /\ rpend' = [rpend EXCEPT ![r] = None]
    /\ UNCHANGED <<file, large, man, gone, rolled, worldVars, wpend, wlate, mpend, budgetVars, ghostVars>>

\* Steps 1 to 5 at the head; a runner that finds the bucket gone and rolled_through at it stops.
RollBuild(r) ==
    /\ "rollup" \notin Still
    /\ rphase[r] = "holding"
    /\ rpend[r] = None
    /\ IF 1 \in gone /\ rolled >= 1
       THEN /\ rphase' = [rphase EXCEPT ![r] = "done"]
            /\ UNCHANGED <<rpend, broken>>
       ELSE /\ rpend' = [rpend EXCEPT ![r] =
                   [kind |-> "roll", lock |-> rheld[r], all |-> file[AllPath].ver, man |-> man[1].ver,
                    bucket |-> [p \in BucketPaths(1) |-> file[p].ver],
                    promos |-> [nb \in PromoBuckets |->
                                   [shard |-> file[ShardPath(nb)].ver, man |-> man[nb].ver, ent |-> PromoEnt(nb)]],
                    rewrites |-> [p \in Rewrites |-> [ver |-> file[p].ver, ent |-> file[p].ent \ Stale(p)]],
                    fenced |-> [b \in Fenced |-> man[b].ver],
                    live |-> \E d \in Docs : Promoted(d) /\ ~TombAt(RollIn, d, Carried(d)),
                    rows |-> NewAll, t |-> clock]]
            /\ broken' = (broken \/ RollBroken)
            /\ UNCHANGED rphase
    /\ UNCHANGED <<storeVars, worldVars, wpend, wlate, mpend, rheld, budgetVars, indexed, rollCommits,
                   fenceBad, reached>>

\* Step 6: one push writing all and each promotion's shard and manifest (as written: the rewrites), removing
\* every file of bucket 1, setting a/m's rolled_through and freeing the lock from the version the runner holds.
\* A runner whose lock was taken stops; any other 409 reruns from step 1.
RollCommit(r) ==
    LET P == rpend[r]
        blind == Twin = "PromoteBlind"
        ok == /\ lock.ver = P.lock
              /\ file[AllPath].ver = P.all
              /\ man[1].ver = P.man
              /\ \A p \in BucketPaths(1) : file[p].ver = P.bucket[p]
              /\ \A nb \in DOMAIN P.promos :
                     blind \/ (file[ShardPath(nb)].ver = P.promos[nb].shard /\ man[nb].ver = P.promos[nb].man)
              /\ \A p \in DOMAIN P.rewrites : file[p].ver = P.rewrites[p].ver
              /\ \A b \in DOMAIN P.fenced : man[b].ver = P.fenced[b]
    IN  /\ P.kind = "roll"
        /\ Alive(P)
        /\ IF ok
           THEN /\ file' = [p \in Paths |->
                      IF p = AllPath THEN [live |-> TRUE, ver |-> file[p].ver + 1, seq |-> 0, ent |-> P.rows]
                      ELSE IF p \in BucketPaths(1)
                           THEN (IF Exists(p) THEN [live |-> FALSE, ver |-> file[p].ver + 1, seq |-> 0, ent |-> {}]
                                 ELSE file[p])
                      ELSE IF p[1] = "s" /\ p[2] \in DOMAIN P.promos
                           THEN [live |-> TRUE, ver |-> file[p].ver + 1, seq |-> 0, ent |-> P.promos[p[2]].ent]
                      ELSE IF p \in DOMAIN P.rewrites
                           THEN [file[p] EXCEPT !.ver = @ + 1, !.ent = P.rewrites[p].ent]
                      ELSE file[p]]
                /\ large' = [large EXCEPT ![1] = [w \in Writers |-> {}]]
                /\ man' = [b \in Buckets |->
                      IF b = 1 \/ b \in DOMAIN P.promos \/ b \in DOMAIN P.fenced
                      THEN [man[b] EXCEPT !.ver = @ + 1]
                      ELSE man[b]]
                /\ gone' = gone \cup {1}
                /\ rolled' = 1
                /\ lock' = [ver |-> lock.ver + 1, holder |-> NoRoller, lapsed |-> FALSE]
                /\ rollCommits' = rollCommits + 1
                /\ fenceBad' = (fenceBad \/ lock.ver # P.lock)
                /\ reached' = Mark({"rolled"} \cup (IF DOMAIN P.promos # {} THEN {"promoted"} ELSE {})
                                     \cup (IF P.live THEN {"promotedLive"} ELSE {}))
                /\ rphase' = [rphase EXCEPT ![r] = IF @ = "crashed" THEN @ ELSE "done"]
                /\ UNCHANGED rheld
           ELSE /\ IF lock.ver # P.lock
                   THEN /\ rphase' = [rphase EXCEPT ![r] = IF @ = "crashed" THEN @ ELSE "idle"]
                        /\ rheld' = [rheld EXCEPT ![r] = 0]
                   ELSE UNCHANGED <<rphase, rheld>>
                /\ UNCHANGED <<file, large, man, gone, rolled, lock, rollCommits, fenceBad, reached>>
        /\ rpend' = [rpend EXCEPT ![r] = None]
        /\ UNCHANGED <<worldVars, wpend, wlate, mpend, budgetVars, indexed, broken>>

\* The lock's until_ms passes: a crashed holder's always, a live holder's while lapses last.
Lapse ==
    /\ lock.holder # NoRoller
    /\ ~lock.lapsed
    /\ \/ rphase[lock.holder] = "crashed"
       \/ lapses > 0 /\ "lapse" \notin Still
    /\ lock' = [lock EXCEPT !.lapsed = TRUE]
    /\ lapses' = IF rphase[lock.holder] = "crashed" THEN lapses ELSE lapses - 1
    /\ UNCHANGED <<file, large, man, gone, rolled, worldVars, procVars, crashes, restarts, ghostVars>>

\* A roller dies holding the lock or with its take in flight; a push it sent may still land.
RollerCrash(r) ==
    /\ "crash" \notin Still
    /\ crashes > 0
    /\ rphase[r] = "holding" \/ (rphase[r] = "idle" /\ rpend[r] # None)
    /\ crashes' = crashes - 1
    /\ rphase' = [rphase EXCEPT ![r] = "crashed"]
    /\ UNCHANGED <<storeVars, worldVars, wpend, wlate, mpend, rheld, rpend, lapses, restarts, ghostVars>>

(***************************************************************************)
(* Content and time.                                                        *)
(***************************************************************************)

Write ==
    /\ next <= Events
    /\ Now >= Plot[next].at
    /\ LET s == Plot[next] IN
       /\ content' = [content EXCEPT ![s.d] = [v |-> s.v, op |-> s.op]]
       /\ journal' = IF s.skip THEN journal ELSE Append(journal, [d |-> s.d, v |-> s.v, op |-> s.op])
    /\ next' = next + 1
    /\ UNCHANGED <<storeVars, clock, procVars, budgetVars, ghostVars>>

\* Time moves on; every built push that can no longer land is dropped by its builder.
Tick ==
    /\ "tick" \notin Still
    /\ clock < LastClock
    /\ clock' = clock + 1
    /\ LET live(P) == P = None \/ Life = "long" \/ (P.t = clock /\ clock % 2 = 0) IN
       /\ wpend' = [w \in Writers |-> IF live(wpend[w]) THEN wpend[w] ELSE None]
       /\ wlate' = [w \in Writers |-> IF live(wlate[w]) THEN wlate[w] ELSE None]
       /\ mpend' = IF live(mpend) THEN mpend ELSE None
       /\ rpend' = [r \in Rollers |-> IF live(rpend[r]) THEN rpend[r] ELSE None]
    /\ UNCHANGED <<storeVars, next, content, journal, rphase, rheld, budgetVars, ghostVars>>

Init ==
    /\ clock = 1
    /\ file = [p \in Paths |-> [live |-> FALSE, ver |-> 0, seq |-> 0, ent |-> {}]]
    /\ large = [b \in Buckets |-> [w \in Writers |-> {}]]
    /\ man = [b \in Buckets |-> [ver |-> 0, abs |-> [w \in Writers |-> 0]]]
    /\ gone = {}
    /\ rolled = 0
    /\ lock = [ver |-> 0, holder |-> NoRoller, lapsed |-> FALSE]
    /\ next = 1
    /\ content = [d \in Docs |-> [v |-> 0, op |-> "put"]]
    /\ journal = <<>>
    /\ wpend = [w \in Writers |-> None]
    /\ wlate = [w \in Writers |-> None]
    /\ mpend = None
    /\ rphase = [r \in Rollers |-> "idle"]
    /\ rheld = [r \in Rollers |-> 0]
    /\ rpend = [r \in Rollers |-> None]
    /\ crashes = MaxCrashes
    /\ lapses = MaxLapses
    /\ restarts = MaxRestarts
    /\ indexed = [d \in Docs |-> [v |-> 0, k |-> "live"]]
    /\ rollCommits = 0
    /\ fenceBad = FALSE
    /\ broken = FALSE
    /\ reached = {}

RollerStep(r) ==
    \/ TakeBuild(r) \/ TakeCommit(r) \/ RollBuild(r) \/ RollCommit(r)

Next ==
    \/ Write
    \/ Tick
    \/ JournalBuild
    \/ BackfillBuild
    \/ \E w \in Writers : HeadCommit(w) \/ Restart(w) \/ LateCommit(w)
    \/ \E b \in Buckets : MergeBuild(b)
    \/ MergeCommit
    \/ \E r \in Rollers : RollerStep(r) \/ RollerCrash(r)
    \/ Lapse

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* What TLC checks.                                                         *)
(***************************************************************************)

TypeOk ==
    /\ clock \in 1..LastClock
    /\ rollCommits \in 0..2
    \* no file of a bucket a roll-up removed comes back
    /\ \A b \in gone : ~BucketLive(b) /\ (\A p \in BucketPaths(b) : ~Exists(p)) /\ (\A w \in Writers : large[b][w] = {})
    \* one entry a key in each slot (§11.14's slot row), and no diff in a shard or in all
    /\ \A b \in Buckets : \A p \in BucketSlots(b) : \A d \in Docs : Cardinality(Of(file[p].ent, d)) <= 1
    /\ \A b \in Buckets : \A e \in file[ShardPath(b)].ent : e.k # "diff"

\* FI-18: every search at the head, over the buckets and all, answers each document's newest indexed version,
\* so no seal, merge, slot reuse or roll-up changes a result set, no tombstoned version counts, and no late
\* entry brings a deleted document back.
ResultsHold == ViewOf(IndexEnts) = Truth

\* A device keeping only the buckets shows no document at an older version than its newest.
BucketsExact ==
    LET v == ViewOf(UNION {BucketEnts(b) : b \in Buckets}) IN
    \A d \in Docs : v[d] # 0 => v[d] = Truth[d]

\* The design (I1): every diff in a slot no merge has absorbed, a head or a sealed one, has its base in another
\* file of its own writer in its bucket, so no reader, merge or roll-up meets a diff it cannot compose. As
\* written: every current diff's chain resolves outside every head of its bucket.
ChainsResolve ==
    /\ ~broken
    /\ IF Bases = "own"
       THEN \A b \in Buckets \ gone : \A p \in Sealed(b) \cup Heads(b) : ~SlotBroken(p)
       ELSE \A d \in Docs :
               LET t == Top(IndexEnts, d) IN
               (t > 0 /\ ~TombAt(IndexEnts, d, t)) =>
                   \/ \E e \in Of(IndexEnts, d) : e.v = t /\ e.k = "full"
                   \/ \E b \in Buckets \ gone :
                          \E e \in Of(BucketEnts(b), d) : e.v = t /\ e.k = "diff" /\ Resolves(b, d, e.base)

\* I-EVS-11: at most one version of a document in all and in each bucket's shards, and no tombstone in all.
OneVersionEach ==
    /\ \A d \in Docs : Cardinality(Of(file[AllPath].ent, d)) <= 1
    /\ \A b \in Buckets : \A d \in Docs : Cardinality(Of(file[ShardPath(b)].ent, d)) <= 1
    /\ \A e \in file[AllPath].ent : e.k = "full"

\* I-EVS-12 and FI-20: the bucket is rolled by at most one committed roll-up, which committed from the lock
\* version its runner took.
RollsOnce == rollCommits <= 1 /\ ~fenceBad

(***************************************************************************)
(* Reach: states the design must reach. A Reach configuration names one of  *)
(* these as its invariant, and TLC must refuse it with a witness.           *)
(***************************************************************************)

NeverRolled == "rolled" \notin reached
NeverPromoted == "promoted" \notin reached
NeverPromotedLive == "promotedLive" \notin reached
NeverComposed == "composed" \notin reached
NeverDropped == "dropped" \notin reached
\* A head holds a diff whose base sits in a file a merge has absorbed and its writer still keeps.
NeverKeptBase ==
    ~\E b \in Buckets \ gone : \E w \in Writers :
        /\ HeadOf(b, w) # NoPath
        /\ \E e \in file[HeadOf(b, w)].ent :
               /\ e.k = "diff"
               /\ \/ \E l \in large[b][w] : l.d = e.d /\ l.v = e.base /\ l.seq <= man[b].abs[w]
                  \/ \E q \in WriterSlots(b, w) \ {HeadOf(b, w)} :
                         IsAbsorbed(q) /\ \E x \in file[q].ent : x.k = "full" /\ x.d = e.d /\ x.v = e.base

RollerSymmetry == Permutations(Rollers)

=============================================================================
