---------------------------- MODULE IndexRollup ----------------------------
(***************************************************************************)
(* §22.8's model of the search index's upkeep on one ref (§11.14), on the  *)
(* rules of DESIGN-DETAILS.md section 1: writers' heads, sealed slots and  *)
(* large entries, merges, the roll-up of an expired bucket under its lock, *)
(* the journal behind companion pushes and backfills, and an erasure's     *)
(* CUT, CLOSUREs and ERASEs, none joined to another by a transaction.      *)
(* Every commit is one head CAS: each file it replaces at the version its  *)
(* builder read, and, but for a CLOSURE, the head's index_epoch as its     *)
(* builder read it (I-EVS-17). Section 1's own model,                      *)
(* details/IndexMerge.tla, holds the same rules beside §11.14's as written *)
(* and has no erasure; this model joins its rules to the erasure.          *)
(*                                                                         *)
(* The rules (section 1.2):                                                *)
(* - R1, own bases: a diff rests on a full entry of its document in        *)
(*   another file of its own writer in its own bucket, a slot that is not  *)
(*   the head or a large entry, at a version the erasure set does not      *)
(*   list; the writer reuses no slot and removes no large entry that a     *)
(*   diff of its unabsorbed slots rests on, and removes its other absorbed *)
(*   large entries at its next push there.                                 *)
(* - R2, the head rule: every push that writes a file of a writer's in a   *)
(*   bucket replaces that writer's head there as the push's base showed    *)
(*   it, a head sealed as it stood written again. The bucket's manifest    *)
(*   fences no head push: §11.14 never had that fence, and SEARCH-M10-02's *)
(*   model checked it, which hid every race between a head push and a      *)
(*   merge.                                                                *)
(* - R3, merges: a merge reads no head; its output is each document's      *)
(*   newest version among the shard, the sealed slots and the unabsorbed   *)
(*   large entries, each diff composed onto its own writer's base; it      *)
(*   writes only the shard and the manifest.                               *)
(* - R4, promotion: a roll-up rewrites no file of a newer bucket in place. *)
(*   A version or tombstone it carries whose document a newer bucket holds *)
(*   only at older versions goes into the shard of the newest such bucket, *)
(*   whose shard and manifest the roll-up replaces at the versions it      *)
(*   read.                                                                 *)
(* - R5, the pin: a journaled entry is dropped when its content ref, read  *)
(*   after the index in the push's own build, holds its document at a      *)
(*   higher version or removed, and a built push lands within minutes of   *)
(*   its signed time or never.                                             *)
(*                                                                         *)
(* The erasure is SEARCH-M10-02's. A CUT lists d1 up to a version and      *)
(* moves index_epoch, so no push but a CLOSURE built before it commits     *)
(* after it. Every builder leaves the listed versions out of what it       *)
(* writes, and no diff rests on a listed version (R1). CLOSUREs rewrite    *)
(* each file whose live key held a listed version, kept and absorbed slots *)
(* included, without it, under a fresh key, replacing the version read; a  *)
(* CLOSURE rewrites no head it has no other reason to touch, since the     *)
(* CUT's epoch and R1 fence it. ERASEs then destroy the old keys. A        *)
(* CLOSURE takes a listed base and the listed diffs on it in separate      *)
(* pushes, so readers, merges and roll-ups leave the listed versions out   *)
(* before composing.                                                       *)
(*                                                                         *)
(* Objects: the head's index_epoch; each index file's version, key and     *)
(* entries (slots of each writer, a shard a bucket, all's shard); each     *)
(* writer's large entries a bucket; each bucket's manifest with its        *)
(* absorbed seqs; a/m's rolled_through; the lock; the erasure set.         *)
(* Processes: a journaler, whose companion pushes trail their content; a   *)
(* backfiller, which indexes what no entry reaches; a writer process that  *)
(* may die with a push in flight that still lands; a merger; two rollers,  *)
(* each of which may crash at any step, lose its lock at expiry or have    *)
(* its push land late; an eraser whose CUT, ERASE and CLOSURE steps may    *)
(* each be its last before a crash; and a finishing device, which resumes  *)
(* the erasure from evs's state alone.                                     *)
(*                                                                         *)
(* Documents: d1 is created, edited and erased, by a CUT that may list it  *)
(* before or after its edit; d2 is edited four times, by diffs where a     *)
(* base stands; d3 is created and then deleted by a commit that skips the  *)
(* index, which the backfiller indexes. Story fixes the order of their     *)
(* content commits, each of which may come in any window; they push        *)
(* nothing to the index themselves: the journaler and the backfiller do,   *)
(* as on ur/index.                                                         *)
(*                                                                         *)
(* What the model abstracts:                                               *)
(* - A document's text is its version: an entry or row holds a version, a  *)
(*   diff names its base, and a full row is a self-contained copy. Sizes,  *)
(*   chunks, ref tombstones, coverage rows, joined and capped shards do    *)
(*   not appear; a bucket has one shard file. KeepSlots and the delta      *)
(*   bound only turn diffs into full entries, and either may be chosen.    *)
(* - A full entry of a document in BigDocs is past 8 KiB and so a large    *)
(*   entry, a file of its own; any other full entry sits in a slot. d1 is  *)
(*   never large: a large entry holds one entry, so its CLOSURE and ERASE  *)
(*   are a slot's on a file of one entry.                                  *)
(* - When a head is full is a choice: a push may seal its writer's head    *)
(*   while a slot is free. A push carries one entry; the design's carries  *)
(*   every entry due, which is some sequence of these.                     *)
(* - Versions are per object and never restart, a removal included, so a   *)
(*   CAS compares the version its builder read.                            *)
(* - Time is three windows, each with an early and a late part (clock 1 to *)
(*   5, bucket 1 expiring at 5). A push built late in a window may land    *)
(*   early in the next, none longer. Early in a window a push's signed     *)
(*   time may fall in the window before (Skew). An entry goes to the       *)
(*   bucket of its signed time: D-EVS-45's move to a newer bucket holding  *)
(*   its document is one of those choices, so no invariant here rests on   *)
(*   it.                                                                   *)
(* - Each index path keeps one key, gen, which only a CLOSURE replaces;    *)
(*   stored1 is every stored version that held d1, since a hold may keep   *)
(*   any (11.14's holds row), and readers open a file only under a key no  *)
(*   ERASE destroyed. An ERASE is the step that destroys keys.             *)
(*                                                                         *)
(* CutVersion says which version of d1 the CUT lists. "commit" is the      *)
(* newest committed when the CUT lands, so every entry of d1 built before  *)
(* the CUT is listed, and the design passes. "read" is the newest the      *)
(* eraser read when it built the CUT: an edit committed between the two    *)
(* may land, as a diff on a version the CUT then lists, before the CUT,    *)
(* and a CLOSURE then takes its base, which no rule of section 1 or §11.14 *)
(* covers (question search-m10-46-erased-base-of-a-live-diff).             *)
(*                                                                         *)
(* The lock is a fence the file CAS already backs: a second roll-up's      *)
(* removal of the bucket's files fails on their versions, so I-EVS-12      *)
(* holds whatever the lock says, and fenceBad records the lock check       *)
(* alone.                                                                  *)
(*                                                                         *)
(* Still holds the named processes still, for focused runs. Twin names a   *)
(* rule to break; a twin's run sets it, and TLC must then refuse the model *)
(* with the invariant that rule protects. "none" is the design.            *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Journaler,      \* the writer whose companion journal holds the story's entries
    Backfiller,     \* the writer that backfills what no entry reaches
    Rollers,        \* devices that may run the roll-up: model values
    MaxSlots,       \* slots a writer may hold in a bucket (16 in the design)
    MaxCrashes,     \* crashes of rollers and the eraser in one behavior
    MaxLapses,      \* expiries of a live holder's lock in one behavior
    MaxRestarts,    \* writer processes that die with a push in flight
    ForeignCuts,    \* CUTs of other erasures, which move the epoch and list nothing here
    Documents,      \* the documents whose content commits a run makes: any of "d1", "d2", "d3"
    BigDocs,        \* the documents whose full entries are large entries: "d2" or none
    Events,         \* how many of those commits a run makes, in Story's order
    Skew,           \* whether a push's signed time may fall in the window before the current one
    CutVersion,     \* "commit": the CUT lists d1's newest version when it commits; "read": when it was built
    Still,          \* held still: any of "backfill", "merge", "rollup", "erase", "crash", "lapse", "tick",
                    \* "bfdiff" (the backfiller writes full entries only)
    Twin            \* "none", or the rule a twin's run breaks

Writers == {Journaler, Backfiller}
Docs == {"d1", "d2", "d3"}
Erased == "d1"
Buckets == 1..3
LastClock == 5
NoRoller == "none"
NoPath == <<>>
None == [kind |-> "none"]
Actors == {"eraser", "finisher"}

Twins == {"none",
          \* the erasure's
          "NoEpochCheck", "BuildIgnoresSet", "EraseLiveFirst", "EarlyComplete", "ClosureNoCas",
          "DiffOnListed", "EraseSkipsAbsorbed",
          \* merges, slots and the roll-up
          "MergeDropsTombstone", "ReuseUnabsorbed", "RollupForgetsHeads", "MergeKeepsOld", "NoLockFence",
          "MergeIgnoresEpoch",
          \* section 1's
          "NoOwnCas", "ReusePinned", "CleanupReferenced", "MergeRemovesLarge", "NoPromote", "NoPromoteLive",
          "PromoteBlind", "IndexSupersede", "LongLife"}

ASSUME
    /\ Journaler # Backfiller
    /\ MaxSlots \in 1..16
    /\ Twin \in Twins
    /\ Still \subseteq {"backfill", "merge", "rollup", "erase", "crash", "lapse", "tick", "bfdiff"}
    /\ CutVersion \in {"commit", "read"}

\* The content commits, in order, each in any window from the first. The journaler journals each one
\* unless it skips the index (an old client), which is left for the backfiller.
Story == <<
    [d |-> "d3", v |-> 1, op |-> "put", skip |-> FALSE],
    [d |-> "d1", v |-> 1, op |-> "put", skip |-> FALSE],
    [d |-> "d2", v |-> 1, op |-> "put", skip |-> FALSE],
    [d |-> "d3", v |-> 2, op |-> "del", skip |-> TRUE],
    [d |-> "d2", v |-> 2, op |-> "put", skip |-> FALSE],
    [d |-> "d1", v |-> 2, op |-> "put", skip |-> FALSE],
    [d |-> "d2", v |-> 3, op |-> "put", skip |-> FALSE],
    [d |-> "d2", v |-> 4, op |-> "put", skip |-> FALSE]
>>

\* Story's commits of the run's documents.
Plot == SelectSeq(Story, LAMBDA s : s.d \in Documents)

ASSUME
    /\ Documents \subseteq Docs
    /\ BigDocs \subseteq Docs \ {Erased}
    /\ Events \in 0..Len(Plot)

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
    ep,          \* the head's index_epoch (11.8's 5d), which only a CUT moves
    clock,       \* 1 to 5: window (clock + 1) \div 2, early on odd clocks, late on even
    file,        \* file[p]: a slot, a bucket's shard or all's: live, ver, gen (its key), seq (slots) and ent
    large,       \* large[b][w]: w's large entries in bucket b, each {seq, d, v}, a full entry alone in a file
    man,         \* man[b]: bucket b's manifest: ver and abs, each writer's highest absorbed seq
    gone,        \* buckets a roll-up removed
    rolled,      \* a/m's rolled_through: 0, or 1 once bucket 1 is rolled
    lock,        \* <root>/lock: ver, holder and lapsed (its until_ms past)
    x,           \* the erasure set: ver, listed (d1 pending) and upto, the newest version of d1 erased
    next,        \* the story's next content commit
    content,     \* content[d]: the newest committed version of d's content, v and op
    journal,     \* the journaler's entries not yet in a committed head push
    wpend,       \* wpend[w]: w's built head push, or None
    wlate,       \* wlate[w]: the push a dead process of w left in flight, or None
    mpend,       \* the merger's built merge, or None
    rphase,      \* rphase[r]: "idle", "holding", "crashed" or "done"
    rheld,       \* rheld[r]: the lock version r took, 0 for none
    rpend,       \* rpend[r]: r's built lock take or roll-up, or None
    ephase,      \* the eraser: "idle", "cut" once its CUT committed, or "crashed"
    epend,       \* epend[a]: the built CUT or CLOSURE of the eraser or the finishing device
    crashes,     \* crashes left
    lapses,      \* expiries of a live holder's lock left
    restarts,    \* writer restarts left
    fcuts,       \* foreign CUTs left
    destroyed,   \* the <<path, gen>> keys an ERASE destroyed
    contentGone, \* the first ERASE destroyed the erased versions' own keys
    complete,    \* the erasure judged itself finished
    indexed,     \* ghost: indexed[d], the newest entry of d a committed push carried: v and k
    stored1,     \* ghost: <<path, gen, v>> for each committed index file version that held d1 at version v
    rollCommits, \* ghost: committed roll-ups of bucket 1
    leaked,      \* ghost: a push but a CLOSURE wrote a listed version of d1 into an index file after the CUT
    epochBad,    \* ghost: a push but a CLOSURE committed at an index_epoch not the head's
    fenceBad,    \* ghost: a roll-up committed from a lock version its runner did not take
    broken       \* ghost: a merge or roll-up met an entry it could not compose from its inputs

storeVars == <<ep, file, large, man, gone, rolled, lock, x>>
worldVars == <<clock, next, content, journal>>
procVars == <<wpend, wlate, mpend, rphase, rheld, rpend, ephase, epend>>
budgetVars == <<crashes, lapses, restarts, fcuts>>
eraseVars == <<destroyed, contentGone, complete>>
ghostVars == <<indexed, stored1, rollCommits, leaked, epochBad, fenceBad, broken>>
vars == <<storeVars, worldVars, procVars, budgetVars, eraseVars, ghostVars>>

(***************************************************************************)
(* Reading the index at the head.                                          *)
(***************************************************************************)

Now == (clock + 1) \div 2
Early == clock % 2 = 1

Exists(p) == file[p].live
Readable(p) == <<p, file[p].gen>> \notin destroyed
KeyOf(p) == IF file[p].gen = 0 THEN 1 ELSE file[p].gen

WriterSlots(b, w) == {p \in SlotPaths(b, w) : Exists(p)}
HeadOf(b, w) ==
    IF WriterSlots(b, w) = {} THEN NoPath
    ELSE CHOOSE p \in WriterSlots(b, w) : \A q \in WriterSlots(b, w) : file[q].seq <= file[p].seq
Heads(b) == {HeadOf(b, w) : w \in Writers} \ {NoPath}
IsAbsorbed(p) == file[p].seq <= man[p[2]].abs[p[3]]
\* A writer's slots other than its head that no merge has absorbed. An absorbed slot holds nothing
\* for search, merges and roll-ups; it is read only as a diff's base.
Sealed(b) == {p \in BucketSlots(b) : Exists(p) /\ p \notin Heads(b) /\ ~IsAbsorbed(p)}
\* A writer's large entries no merge has absorbed. An absorbed one holds nothing but a diff's base.
LiveLarge(b, w) == {l \in large[b][w] : l.seq > man[b].abs[w]}
AsFull(l) == [d |-> l.d, v |-> l.v, k |-> "full", base |-> 0]
LargeEnts(b) == UNION {{AsFull(l) : l \in LiveLarge(b, w)} : w \in Writers}

EntsAt(P) == UNION {IF Exists(p) /\ Readable(p) THEN file[p].ent ELSE {} : p \in P}
HeadEnts(b) == IF b \in gone THEN {} ELSE EntsAt(Heads(b))
\* What lies outside every writer's head in bucket b: its shard, its sealed slots and its large entries.
OutEnts(b) == IF b \in gone THEN {} ELSE EntsAt(Sealed(b) \cup {ShardPath(b)}) \cup LargeEnts(b)
BucketEnts(b) == HeadEnts(b) \cup OutEnts(b)
AllEnts == EntsAt({AllPath})
IndexEnts == AllEnts \cup (UNION {BucketEnts(b) : b \in Buckets})
BucketLive(b) ==
    b \notin gone /\ ((\E p \in BucketPaths(b) : Exists(p)) \/ (\E w \in Writers : large[b][w] # {}))

Of(S, d) == {e \in S : e.d = d}
Top(S, d) == IF Of(S, d) = {} THEN 0 ELSE Max({e.v : e \in Of(S, d)})
TombAt(S, d, v) == \E e \in Of(S, d) : e.v = v /\ e.k = "tomb"
\* A version the erasure set lists: d1's, at or below the newest version its CUT erased.
Masked(d, v) == x.listed /\ d = Erased /\ v <= x.upto
HoldsListed(S) == \E e \in S : Masked(e.d, e.v)
\* What a reader keeps of S: every version the erasure set does not list (11.14's cut row).
Unlisted(S) == {e \in S : ~Masked(e.d, e.v)}
\* What a builder keeps of S: the same (11.14's epoch row), unless twin BuildIgnoresSet.
Clean(S) == IF Twin = "BuildIgnoresSet" THEN S ELSE Unlisted(S)

\* A search's answer per document over the entries S: its newest version, unless that is a tombstone
\* or the erasure masks it (11.14's newest row); 0 for no hit.
ViewOf(S) == [d \in Docs |->
    LET t == Top(S, d) IN IF t = 0 \/ TombAt(S, d, t) \/ Masked(d, t) THEN 0 ELSE t]

\* What every search must answer: each document's newest indexed version.
Truth == [d \in Docs |->
    IF indexed[d].v = 0 \/ indexed[d].k = "tomb" \/ Masked(d, indexed[d].v) THEN 0 ELSE indexed[d].v]

Row(S, d, v) == [d |-> d, v |-> v, k |-> IF TombAt(S, d, v) THEN "tomb" ELSE "full", base |-> 0]
Newer(old, e) == IF e.v > old.v THEN [v |-> e.v, k |-> IF e.k = "tomb" THEN "tomb" ELSE "live"] ELSE old

\* The <<path, key, version>> of each version of d1 that the entries S, written at p under key g, hold.
Stored1(p, g, S) == {<<p, g, e.v>> : e \in Of(S, Erased)}

(***************************************************************************)
(* Bases (R1): a diff in a slot of writer w in bucket b rests on the full  *)
(* entry of its document at its base version in another file of w's in b:  *)
(* a large entry, or a slot that is not w's head, absorbed or not.         *)
(***************************************************************************)

BaseVersions(b, w, d) ==
    {l.v : l \in {y \in large[b][w] : y.d = d}}
        \cup {y.v : y \in {z \in EntsAt(WriterSlots(b, w) \ {HeadOf(b, w)}) : z.d = d /\ z.k = "full"}}
HasBase(b, w, e) == e.base \in BaseVersions(b, w, e.d)
\* A diff in slot p whose base is gone (I1).
Orphan(p, e) == e.k = "diff" /\ ~HasBase(p[2], p[3], e)
\* A slot's entries a builder keeps, each diff composed onto its base; a diff with no base composes
\* to nothing.
SlotResolved(p) ==
    {IF e.k = "diff" THEN [d |-> e.d, v |-> e.v, k |-> "full", base |-> 0] ELSE e :
        e \in {y \in Clean(file[p].ent) : ~Orphan(p, y)}}
SlotBroken(p) == \E e \in Clean(file[p].ent) : Orphan(p, e)

(***************************************************************************)
(* Writers: the journaler's companion pushes and the backfiller's.         *)
(***************************************************************************)

\* The windows a push built now may be signed in.
Windows == IF Skew /\ Early /\ Now > 1 THEN {Now, Now - 1} ELSE {Now}

\* A push lands only within minutes of its signed time: at its own clock, or, built late in a window,
\* early in the next (R5's life). Twin LongLife is a client that sends a push it built long before.
Alive(P) == Twin = "LongLife" \/ P.t = clock \/ (P.t + 1 = clock /\ P.t % 2 = 0)

\* The versions of d below v that w's other files in b hold full, and that the erasure set does not
\* list: what a diff of d at v may rest on (section 1.2.3's choose).
OwnBases(b, w, d, v) ==
    {y \in BaseVersions(b, w, d) : y < v /\ (~Masked(d, y) \/ Twin = "DiffOnListed")}

\* The entries w may write for content version j in bucket b: a removal's tombstone; else a full entry,
\* or a diff on the newest of OwnBases where one stands, whether the delta is small enough being a
\* choice.
EntryOptions(w, b, j) ==
    LET full == [d |-> j.d, v |-> j.v, k |-> "full", base |-> 0] IN
    IF j.op = "del" THEN {[d |-> j.d, v |-> j.v, k |-> "tomb", base |-> 0]}
    ELSE {full} \cup
         (IF OwnBases(b, w, j.d, j.v) # {} /\ ~(w = Backfiller /\ "bfdiff" \in Still)
          THEN {[d |-> j.d, v |-> j.v, k |-> "diff", base |-> Max(OwnBases(b, w, j.d, j.v))]}
          ELSE {})

MaxSeq(b, w) ==
    Max({0} \cup {file[p].seq : p \in WriterSlots(b, w)} \cup {l.seq : l \in large[b][w]})
\* The slots of w in b, other than its head, holding a full entry that a diff in S names: w keeps them.
PinnedSlots(b, w, S) ==
    {q \in WriterSlots(b, w) \ {HeadOf(b, w)} :
        \E y \in file[q].ent : y.k = "full" /\ \E e \in S : e.k = "diff" /\ e.d = y.d /\ e.base = y.v}
\* The slot a seal opens when the push leaves w's unabsorbed slots holding S: the lowest the manifest
\* shows absorbed that no diff in S rests on, else a new one (§11.14's seal row with 1.2.3's keep rule).
Reusable(b, w, S) ==
    {k \in 1..MaxSlots :
        /\ Exists(SlotPath(b, w, k))
        /\ SlotPath(b, w, k) # HeadOf(b, w)
        /\ IsAbsorbed(SlotPath(b, w, k)) \/ Twin = "ReuseUnabsorbed"
        /\ SlotPath(b, w, k) \notin PinnedSlots(b, w, S) \/ Twin = "ReusePinned"}
Unused(b, w) == {k \in 1..MaxSlots : ~Exists(SlotPath(b, w, k))}
SealSlot(b, w, S) ==
    IF Reusable(b, w, S) # {} THEN Min(Reusable(b, w, S))
    ELSE IF Unused(b, w) # {} THEN Min(Unused(b, w)) ELSE 0

\* What w's sealed, unabsorbed slots in b hold.
SealedEnts(b, w) == EntsAt(Sealed(b) \cap SlotPaths(b, w))
\* The large entries of w in b that a push may remove when it leaves w's unabsorbed slots holding S:
\* those the manifest shows absorbed that no diff in S names (1.2.3).
Removable(b, w, S) ==
    {l \in large[b][w] :
        /\ l.seq <= man[b].abs[w]
        /\ Twin = "CleanupReferenced" \/ ~\E e \in S : e.k = "diff" /\ e.d = l.d /\ e.base = l.v}

\* w's head push of entry e into bucket b: creating w's first slot there; appending to its head, a
\* newer entry replacing the head's entry of its document; sealing the head as it stood and opening
\* the next slot with e; or writing e and, the slot now full, opening the next slot for the push's
\* other documents, which the model does not follow (p2, an empty head). A full entry of a big
\* document is a large entry numbered below a renumbered head. hp and hv are the head as the base
\* showed it, which the push replaces (R2); hent is what it holds, the erasure set's versions left out
\* (the epoch row), which a push that commits finds there still, so a head sealed as it stood is
\* written again from what it holds then.
HeadPushes(w, b, e) ==
    LET head == HeadOf(b, w)
        big == IsBig(e.d) /\ e.k = "full"
        ms == MaxSeq(b, w)
        lg == IF big THEN {[seq |-> ms + 1, d |-> e.d, v |-> e.v]} ELSE {}
        hent == IF head = NoPath THEN {} ELSE Clean(file[head].ent)
        push(p, hp, seq, ent, refs, p2, seq2) ==
            [kind |-> "head", b |-> b, w |-> w, hp |-> hp, hv |-> IF hp = NoPath THEN 0 ELSE file[hp].ver,
             p |-> p, ver |-> file[p].ver, seq |-> seq, ent |-> ent,
             p2 |-> p2, ver2 |-> IF p2 = NoPath THEN 0 ELSE file[p2].ver, seq2 |-> seq2, lgAdd |-> lg,
             lgDrop |-> Removable(b, w, refs), entry |-> e, epoch |-> ep, t |-> clock]
        first == IF big THEN {} ELSE {e}
    IN  IF head = NoPath
        THEN {push(SlotPath(b, w, 1), NoPath, IF big THEN ms + 2 ELSE ms + 1, first, first, NoPath, 0)}
             \cup (IF big \/ MaxSlots < 2 THEN {}
                   ELSE {push(SlotPath(b, w, 1), NoPath, ms + 1, first, first, SlotPath(b, w, 2), ms + 2)})
        ELSE LET kept == {y \in hent : y.d # e.d}
                 appended == IF big THEN kept ELSE kept \cup {e}
                 refsA == appended \cup SealedEnts(b, w)
                 refsO == {e} \cup hent \cup SealedEnts(b, w)
                 kA == SealSlot(b, w, refsA)
                 kO == SealSlot(b, w, refsO)
             IN  {push(head, head, IF big THEN ms + 2 ELSE file[head].seq, appended, refsA, NoPath, 0)}
                 \cup (IF big \/ kO = 0 THEN {}
                       ELSE {push(SlotPath(b, w, kO), head, ms + 1, {e}, refsO, NoPath, 0)})
                 \cup (IF big \/ kA = 0 THEN {}
                       ELSE {push(head, head, file[head].seq, appended, refsA, SlotPath(b, w, kA), ms + 1)})

\* R5's pin: a journaled entry whose content ref, read after the index in this build, holds its
\* document at a higher version or removed is dropped, the newer version left to its own entry. Twin
\* IndexSupersede judges it from the index alone, as §11.14 had it.
Superseded(j) ==
    IF Twin = "IndexSupersede" THEN Top(IndexEnts, j.d) > j.v ELSE content[j.d].v > j.v

JournalBuild ==
    /\ wpend[Journaler] = None
    /\ journal # <<>>
    /\ LET j == Head(journal) IN
       IF Superseded(j) \/ (Masked(j.d, j.v) /\ Twin # "BuildIgnoresSet")
       THEN /\ journal' = Tail(journal)
            /\ UNCHANGED wpend
       ELSE /\ \E t0 \in Windows : \E e \in EntryOptions(Journaler, t0, j) :
                 \E push \in HeadPushes(Journaler, t0, e) :
                     wpend' = [wpend EXCEPT ![Journaler] = push]
            /\ UNCHANGED journal
    /\ UNCHANGED <<storeVars, clock, next, content, wlate, mpend, rphase, rheld, rpend, ephase, epend,
                   budgetVars, eraseVars, ghostVars>>

\* A content version no index entry reaches yet, which the backfiller indexes into its own head from
\* the content as it stands, skipping the erasure set's versions and any an ERASE left unopenable.
BackfillBuild ==
    /\ "backfill" \notin Still
    /\ wpend[Backfiller] = None
    /\ \E d \in Docs :
           /\ content[d].v > 0
           /\ indexed[d].v < content[d].v
           /\ ~Masked(d, content[d].v) \/ Twin = "BuildIgnoresSet"
           /\ ~(d = Erased /\ contentGone /\ content[d].v <= x.upto)
           /\ \E t0 \in Windows :
                  LET j == [d |-> d, v |-> content[d].v, op |-> content[d].op] IN
                  \E e \in EntryOptions(Backfiller, t0, j) :
                      \E push \in HeadPushes(Backfiller, t0, e) :
                          wpend' = [wpend EXCEPT ![Backfiller] = push]
    /\ UNCHANGED <<storeVars, worldVars, wlate, mpend, rphase, rheld, rpend, ephase, epend, budgetVars,
                   eraseVars, ghostVars>>

\* The head CAS of push P: the files it writes at the versions read, its writer's head as the base
\* showed it (R2), creating the writer's first slot only where it still has none, and the epoch. No
\* manifest. On 409 the builder rereads and builds again.
HeadOk(P) ==
    /\ P.b \notin gone
    /\ file[P.p].ver = P.ver
    /\ P.p2 = NoPath \/ file[P.p2].ver = P.ver2
    /\ Twin # "NoOwnCas" =>
           IF P.hp = NoPath THEN WriterSlots(P.b, P.w) = {} ELSE file[P.hp].ver = P.hv
    /\ P.epoch = ep \/ Twin = "NoEpochCheck"

\* The head a push sealed as it stood is written again with its own entries, less the listed ones.
Rewrites(P) == Twin # "NoOwnCas" /\ P.hp # NoPath /\ P.hp # P.p

HeadApply(P) ==
    /\ file' = [q \in Paths |->
                   IF q = P.p
                   THEN [live |-> TRUE, ver |-> file[q].ver + 1, gen |-> KeyOf(q), seq |-> P.seq, ent |-> P.ent]
                   ELSE IF q = P.p2
                   THEN [live |-> TRUE, ver |-> file[q].ver + 1, gen |-> KeyOf(q), seq |-> P.seq2, ent |-> {}]
                   ELSE IF Rewrites(P) /\ q = P.hp
                   THEN [file[q] EXCEPT !.ver = @ + 1, !.ent = Clean(@)]
                   ELSE file[q]]
    /\ large' = [large EXCEPT ![P.b][P.w] = (@ \ P.lgDrop) \cup P.lgAdd]
    /\ indexed' = [indexed EXCEPT ![P.entry.d] = Newer(@, P.entry)]
    /\ stored1' = stored1 \cup Stored1(P.p, KeyOf(P.p), P.ent)
                      \cup (IF Rewrites(P) THEN Stored1(P.hp, file[P.hp].gen, Clean(file[P.hp].ent)) ELSE {})
    /\ leaked' = (leaked \/ HoldsListed(P.ent) \/ (Rewrites(P) /\ HoldsListed(Clean(file[P.hp].ent))))
    /\ epochBad' = (epochBad \/ P.epoch # ep)

HeadCommit(w) ==
    LET P == wpend[w] IN
    /\ P.kind = "head"
    /\ Alive(P)
    /\ IF HeadOk(P)
       THEN /\ HeadApply(P)
            /\ journal' = IF w = Journaler THEN Tail(journal) ELSE journal
       ELSE UNCHANGED <<file, large, indexed, stored1, leaked, epochBad, journal>>
    /\ wpend' = [wpend EXCEPT ![w] = None]
    /\ UNCHANGED <<ep, man, gone, rolled, lock, x, clock, next, content, wlate, mpend, rphase, rheld,
                   rpend, ephase, epend, budgetVars, eraseVars, rollCommits, fenceBad, broken>>

\* A writer's process dies with a push in flight. The push may still land; the process that follows
\* reads its journal again and builds anew.
Restart(w) ==
    /\ restarts > 0
    /\ wpend[w] # None
    /\ wlate[w] = None
    /\ wlate' = [wlate EXCEPT ![w] = wpend[w]]
    /\ wpend' = [wpend EXCEPT ![w] = None]
    /\ restarts' = restarts - 1
    /\ UNCHANGED <<storeVars, worldVars, mpend, rphase, rheld, rpend, ephase, epend, crashes, lapses,
                   fcuts, eraseVars, ghostVars>>

LateCommit(w) ==
    LET P == wlate[w] IN
    /\ P.kind = "head"
    /\ Alive(P)
    /\ IF HeadOk(P) THEN HeadApply(P) ELSE UNCHANGED <<file, large, indexed, stored1, leaked, epochBad>>
    /\ wlate' = [wlate EXCEPT ![w] = None]
    /\ UNCHANGED <<ep, man, gone, rolled, lock, x, worldVars, wpend, mpend, rphase, rheld, rpend,
                   ephase, epend, budgetVars, eraseVars, rollCommits, fenceBad, broken>>

(***************************************************************************)
(* The merger (R3): a bucket's sealed slots and large entries into its     *)
(* shard.                                                                  *)
(***************************************************************************)

\* Each document's newest version among the shard, the sealed slots and the large entries, every diff
\* composed onto its own writer's base, the erasure set's versions left out first. It reads no head.
MergeIn(b) ==
    Clean(EntsAt({ShardPath(b)}))
        \cup (UNION {SlotResolved(p) : p \in {q \in Sealed(b) : Readable(q)}})
        \cup Clean(LargeEnts(b))

\* Each document's winner, a live one as a full row and a tombstone kept for the older partitions until
\* the roll-up; twin MergeKeepsOld leaves the shard's older entry of a key beside its winner.
MergeRows(b) ==
    LET In == MergeIn(b)
        kept == {Row(In, d, Top(In, d)) : d \in {e.d : e \in In}}
        rows == IF Twin = "MergeDropsTombstone" THEN {r \in kept : r.k # "tomb"} ELSE kept
    IN  IF Twin = "MergeKeepsOld" THEN rows \cup Clean(EntsAt({ShardPath(b)})) ELSE rows

MergeBroken(b) == \E p \in Sealed(b) : Readable(p) /\ SlotBroken(p)

\* A merge names no bucket expired at its signed time (1.2.7).
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
                     rows |-> MergeRows(b), abs |-> abs, epoch |-> ep, t |-> clock]
    /\ broken' = (broken \/ MergeBroken(b))
    /\ UNCHANGED <<storeVars, worldVars, wpend, wlate, rphase, rheld, rpend, ephase, epend, budgetVars,
                   eraseVars, indexed, stored1, rollCommits, leaked, epochBad, fenceBad>>

\* One push: the shard and the manifest, each at the version read, and the epoch. It writes and
\* removes no file of any writer's; under twin MergeRemovesLarge it removes the large entries it
\* absorbed, as §11.14's merges row had it.
MergeCommit ==
    LET P == mpend
        s == ShardPath(P.b)
        ok == /\ P.b \notin gone
              /\ file[s].ver = P.shard
              /\ man[P.b].ver = P.man
              /\ P.epoch = ep \/ Twin \in {"NoEpochCheck", "MergeIgnoresEpoch"}
    IN  /\ P.kind = "merge"
        /\ Alive(P)
        /\ IF ok
           THEN /\ file' = [file EXCEPT ![s] = [live |-> TRUE, ver |-> @.ver + 1, gen |-> KeyOf(s), seq |-> 0,
                                               ent |-> P.rows]]
                /\ man' = [man EXCEPT ![P.b] = [ver |-> @.ver + 1, abs |-> P.abs]]
                /\ large' = IF Twin = "MergeRemovesLarge"
                            THEN [large EXCEPT ![P.b] = [w \in Writers |-> {l \in large[P.b][w] : l.seq > P.abs[w]}]]
                            ELSE large
                /\ stored1' = stored1 \cup Stored1(s, KeyOf(s), P.rows)
                /\ leaked' = (leaked \/ HoldsListed(P.rows))
                /\ epochBad' = (epochBad \/ P.epoch # ep)
           ELSE UNCHANGED <<file, man, large, stored1, leaked, epochBad>>
        /\ mpend' = None
        /\ UNCHANGED <<ep, gone, rolled, lock, x, worldVars, wpend, wlate, rphase, rheld, rpend, ephase,
                       epend, budgetVars, eraseVars, indexed, rollCommits, fenceBad, broken>>

(***************************************************************************)
(* The roll-up of bucket 1 (§11.14's roll-up with R4), under the lock.     *)
(***************************************************************************)

\* Step 2's inputs: every entry of the bucket, writers' heads included, diffs composed, the erasure
\* set's versions left out.
RollSlots == IF Twin = "RollupForgetsHeads" THEN Sealed(1) ELSE Sealed(1) \cup Heads(1)
RollIn ==
    Clean(EntsAt({ShardPath(1)}))
        \cup (UNION {SlotResolved(p) : p \in {q \in RollSlots : Readable(q)}})
        \cup Clean(LargeEnts(1))
Carried(d) == Top(RollIn, d)
RollBroken == \E p \in RollSlots : Readable(p) /\ SlotBroken(p)

\* What the newer buckets hold of d, heads included, and the newest of them holding any of it.
NewerEnts == Clean(BucketEnts(2) \cup BucketEnts(3))
NewerTop(d) == Top(NewerEnts, d)
NewestHolding(d) == Max({b \in {2, 3} : Of(Clean(BucketEnts(b)), d) # {}})

\* Step 4 (R4): a version or tombstone this roll-up carries, whose document the newer buckets hold
\* only at older versions, goes into the shard of the newest bucket holding it and stays there until
\* that bucket rolls, so no file of a newer bucket is rewritten in place and no tombstone is dropped
\* above an older entry. Twin NoPromoteLive promotes tombstones only, a live version going to all.
Promoted(d) ==
    /\ Twin # "NoPromote"
    /\ Twin = "NoPromoteLive" => TombAt(RollIn, d, Carried(d))
    /\ Carried(d) > 0
    /\ NewerTop(d) > 0
    /\ NewerTop(d) < Carried(d)
PromoBuckets == {NewestHolding(d) : d \in {y \in Docs : Promoted(y)}}
PromoEnt(nb) ==
    LET ds == {d \in Docs : Promoted(d) /\ NewestHolding(d) = nb} IN
    {e \in Clean(EntsAt({ShardPath(nb)})) : e.d \notin ds} \cup {Row(RollIn, d, Carried(d)) : d \in ds}

\* Steps 3 and 4 for all: per document, the newer of the bucket's and all's stays, a tombstone taking
\* all's row and then going itself. A promoted tombstone takes all's row too; a promoted version leaves
\* all's row be.
NewAll ==
    LET old == Clean(AllEnts)
        keep(d) == [d |-> d, v |-> Top(old, d), k |-> "full", base |-> 0]
        row(d) == IF Promoted(d)
                  THEN (IF TombAt(RollIn, d, Carried(d)) THEN [d |-> d, v |-> 0, k |-> "full", base |-> 0]
                        ELSE keep(d))
                  ELSE IF Carried(d) = 0 \/ Top(old, d) > Carried(d) THEN keep(d)
                  ELSE Row(RollIn, d, Carried(d))
    IN  {r \in {row(d) : d \in Docs} : r.v > 0 /\ r.k = "full"}

TakeBuild(r) ==
    /\ "rollup" \notin Still
    /\ rphase[r] = "idle"
    /\ rpend[r] = None
    /\ Now = 3
    /\ BucketLive(1)
    /\ lock.holder = NoRoller \/ lock.lapsed
    /\ rpend' = [rpend EXCEPT ![r] = [kind |-> "take", lock |-> lock.ver, epoch |-> ep, t |-> clock]]
    /\ UNCHANGED <<storeVars, worldVars, wpend, wlate, mpend, rphase, rheld, ephase, epend, budgetVars,
                   eraseVars, ghostVars>>

\* The lock push: from the version read, free or lapsed, to {r, until now + 30 min}. A 409 shows
\* another holder, left alone until its until_ms.
TakeCommit(r) ==
    LET P == rpend[r] IN
    /\ P.kind = "take"
    /\ Alive(P)
    /\ IF lock.ver = P.lock /\ (P.epoch = ep \/ Twin = "NoEpochCheck")
       THEN /\ lock' = [ver |-> lock.ver + 1, holder |-> r, lapsed |-> FALSE]
            /\ rheld' = [rheld EXCEPT ![r] = lock.ver + 1]
            /\ rphase' = [rphase EXCEPT ![r] = IF @ = "crashed" THEN @ ELSE "holding"]
            /\ epochBad' = (epochBad \/ P.epoch # ep)
       ELSE UNCHANGED <<lock, rheld, rphase, epochBad>>
    /\ rpend' = [rpend EXCEPT ![r] = None]
    /\ UNCHANGED <<ep, file, large, man, gone, rolled, x, worldVars, wpend, wlate, mpend, ephase, epend,
                   budgetVars, eraseVars, indexed, stored1, rollCommits, leaked, fenceBad, broken>>

\* Steps 1 to 5 at the head; a runner that finds the bucket gone and rolled_through at it stops.
RollBuild(r) ==
    /\ "rollup" \notin Still
    /\ rphase[r] = "holding"
    /\ rpend[r] = None
    /\ IF 1 \in gone /\ rolled >= 1
       THEN /\ rphase' = [rphase EXCEPT ![r] = "done"]
            /\ UNCHANGED <<rpend, broken>>
       ELSE /\ rpend' = [rpend EXCEPT ![r] =
                   [kind |-> "roll", lock |-> rheld[r], epoch |-> ep, all |-> file[AllPath].ver,
                    man |-> man[1].ver, bucket |-> [p \in BucketPaths(1) |-> file[p].ver],
                    promos |-> [nb \in PromoBuckets |->
                                   [shard |-> file[ShardPath(nb)].ver, man |-> man[nb].ver, ent |-> PromoEnt(nb)]],
                    rows |-> NewAll, t |-> clock]]
            /\ broken' = (broken \/ RollBroken)
            /\ UNCHANGED rphase
    /\ UNCHANGED <<storeVars, worldVars, wpend, wlate, mpend, rheld, ephase, epend, budgetVars, eraseVars,
                   indexed, stored1, rollCommits, leaked, epochBad, fenceBad>>

\* Step 6: one push writing all and each promotion's shard and manifest, removing every file of
\* bucket 1, setting a/m's rolled_through and freeing the lock from the version the runner holds, the
\* fencing token. A runner whose lock was taken stops; any other 409 reruns from step 1.
RollCommit(r) ==
    LET P == rpend[r]
        ok == /\ lock.ver = P.lock \/ Twin = "NoLockFence"
              /\ P.epoch = ep \/ Twin = "NoEpochCheck"
              /\ file[AllPath].ver = P.all
              /\ man[1].ver = P.man
              /\ \A p \in BucketPaths(1) : file[p].ver = P.bucket[p]
              /\ \A nb \in DOMAIN P.promos :
                     Twin = "PromoteBlind"
                     \/ (file[ShardPath(nb)].ver = P.promos[nb].shard /\ man[nb].ver = P.promos[nb].man)
        promoted == UNION {P.promos[nb].ent : nb \in DOMAIN P.promos}
    IN  /\ P.kind = "roll"
        /\ Alive(P)
        /\ IF ok
           THEN /\ file' = [p \in Paths |->
                      IF p = AllPath
                      THEN [live |-> TRUE, ver |-> file[p].ver + 1, gen |-> KeyOf(p), seq |-> 0, ent |-> P.rows]
                      ELSE IF p \in BucketPaths(1)
                      THEN (IF Exists(p) THEN [file[p] EXCEPT !.live = FALSE, !.ver = @ + 1, !.seq = 0, !.ent = {}]
                            ELSE file[p])
                      ELSE IF p[1] = "s" /\ p[2] \in DOMAIN P.promos
                      THEN [live |-> TRUE, ver |-> file[p].ver + 1, gen |-> KeyOf(p), seq |-> 0,
                            ent |-> P.promos[p[2]].ent]
                      ELSE file[p]]
                /\ large' = [large EXCEPT ![1] = [w \in Writers |-> {}]]
                /\ man' = [b \in Buckets |->
                      IF b = 1 \/ b \in DOMAIN P.promos THEN [man[b] EXCEPT !.ver = @ + 1] ELSE man[b]]
                /\ gone' = gone \cup {1}
                /\ rolled' = 1
                /\ lock' = [ver |-> lock.ver + 1, holder |-> NoRoller, lapsed |-> FALSE]
                /\ rollCommits' = rollCommits + 1
                /\ fenceBad' = (fenceBad \/ lock.ver # P.lock)
                /\ epochBad' = (epochBad \/ P.epoch # ep)
                /\ stored1' = stored1 \cup Stored1(AllPath, KeyOf(AllPath), P.rows)
                                  \cup UNION {Stored1(ShardPath(nb), KeyOf(ShardPath(nb)), P.promos[nb].ent) :
                                                 nb \in DOMAIN P.promos}
                /\ leaked' = (leaked \/ HoldsListed(P.rows \cup promoted))
                /\ rphase' = [rphase EXCEPT ![r] = IF @ = "crashed" THEN @ ELSE "done"]
                /\ UNCHANGED rheld
           ELSE /\ IF lock.ver # P.lock
                   THEN /\ rphase' = [rphase EXCEPT ![r] = IF @ = "crashed" THEN @ ELSE "idle"]
                        /\ rheld' = [rheld EXCEPT ![r] = 0]
                   ELSE UNCHANGED <<rphase, rheld>>
                /\ UNCHANGED <<file, large, man, gone, rolled, lock, rollCommits, fenceBad, epochBad, stored1,
                               leaked>>
        /\ rpend' = [rpend EXCEPT ![r] = None]
        /\ UNCHANGED <<ep, x, worldVars, wpend, wlate, mpend, ephase, epend, budgetVars, eraseVars, indexed,
                       broken>>

\* The lock's until_ms passes: a crashed holder's always, a live holder's while lapses last.
Lapse ==
    /\ lock.holder # NoRoller
    /\ ~lock.lapsed
    /\ \/ rphase[lock.holder] = "crashed"
       \/ lapses > 0 /\ "lapse" \notin Still
    /\ lock' = [lock EXCEPT !.lapsed = TRUE]
    /\ lapses' = IF rphase[lock.holder] = "crashed" THEN lapses ELSE lapses - 1
    /\ UNCHANGED <<ep, file, large, man, gone, rolled, x, worldVars, procVars, crashes, restarts, fcuts,
                   eraseVars, ghostVars>>

LapseOfCrashed == lock.holder # NoRoller /\ rphase[lock.holder] = "crashed" /\ Lapse

\* A roller dies holding the lock or with its take in flight; a push it sent may still land.
RollerCrash(r) ==
    /\ "crash" \notin Still
    /\ crashes > 0
    /\ rphase[r] = "holding" \/ (rphase[r] = "idle" /\ rpend[r] # None)
    /\ crashes' = crashes - 1
    /\ rphase' = [rphase EXCEPT ![r] = "crashed"]
    /\ UNCHANGED <<storeVars, worldVars, wpend, wlate, mpend, rheld, rpend, ephase, epend, lapses,
                   restarts, fcuts, eraseVars, ghostVars>>

(***************************************************************************)
(* The erasure of d1 (11.12's closure, rekey and cut rows; 11.14's erase). *)
(***************************************************************************)

\* The CUT: from the erasure set read and at the head's epoch, it lists d1 up to a version and moves
\* index_epoch to its own version (D-EVS-66).
CutBuild ==
    /\ "erase" \notin Still
    /\ ephase = "idle"
    /\ epend["eraser"] = None
    /\ content[Erased].v > 0
    /\ ~x.listed
    /\ epend' = [epend EXCEPT !["eraser"] =
                    [kind |-> "cut", x |-> x.ver, epoch |-> ep, t |-> clock,
                     upto |-> IF CutVersion = "read" THEN content[Erased].v ELSE 0]]
    /\ UNCHANGED <<storeVars, worldVars, wpend, wlate, mpend, rphase, rheld, rpend, ephase, budgetVars,
                   eraseVars, ghostVars>>

CutCommit ==
    LET P == epend["eraser"] IN
    /\ P.kind = "cut"
    /\ Alive(P)
    /\ IF x.ver = P.x /\ P.epoch = ep
       THEN /\ x' = [ver |-> x.ver + 1, listed |-> TRUE,
                     upto |-> IF CutVersion = "read" THEN P.upto ELSE content[Erased].v]
            /\ ep' = ep + 1
            /\ ephase' = IF ephase = "crashed" THEN ephase ELSE "cut"
       ELSE UNCHANGED <<x, ep, ephase>>
    /\ epend' = [epend EXCEPT !["eraser"] = None]
    /\ UNCHANGED <<file, large, man, gone, rolled, lock, worldVars, wpend, wlate, mpend, rphase, rheld,
                   rpend, budgetVars, eraseVars, ghostVars>>

\* The eraser works while it lives; once it dies after its CUT, the finishing device resumes from
\* evs's state: the set lists the erasure, and the history shows each version that held d1.
Active(a) ==
    /\ "erase" \notin Still
    /\ \/ a = "eraser" /\ ephase = "cut"
       \/ a = "finisher" /\ ephase = "crashed" /\ x.listed

\* The key of every stored index file version that held a listed version of d1.
ErasedKeys == {<<s[1], s[2]>> : s \in {t \in stored1 : Masked(Erased, t[3])}}
\* Of those, the keys no ERASE has destroyed yet.
KeysToGo == ErasedKeys \ destroyed
\* The files the eraser lists: every index file, absorbed slots included, since a slot a writer keeps
\* for its diffs' bases, or has not reused yet, still holds what it held. Under twin
\* EraseSkipsAbsorbed it lists only what a search reads, as if an absorbed slot held nothing.
ListedFile(p) ==
    \/ Twin # "EraseSkipsAbsorbed"
    \/ ~(p[1] = "w" /\ Exists(p) /\ p \notin Heads(p[2]) /\ IsAbsorbed(p))
\* A live file whose key is one of them is rewritten under a fresh key first.
NeedsClosure(p) == Exists(p) /\ <<p, file[p].gen>> \in KeysToGo /\ ListedFile(p)

\* The first ERASE: the erased versions' own keys.
EraseContent(a) ==
    /\ Active(a)
    /\ ~contentGone
    /\ contentGone' = TRUE
    /\ UNCHANGED <<storeVars, worldVars, procVars, budgetVars, destroyed, complete, ghostVars>>

\* A CLOSURE: a file whose live key must go, rewritten in place without the listed versions under a
\* fresh key, replacing the version read; no epoch, since it only replaces versions, and no head but
\* the file's own. Files go one at a time in a fixed order, since each one's CLOSURE and ERASE touch no
\* other file.
ClosureBuild(a) ==
    /\ Active(a)
    /\ epend[a] = None
    /\ \E q \in Paths : NeedsClosure(q)
    /\ LET p == CHOOSE q \in Paths : NeedsClosure(q) IN
       epend' = [epend EXCEPT ![a] = [kind |-> "closure", p |-> p, ver |-> file[p].ver,
                                       ent |-> Unlisted(file[p].ent), t |-> clock]]
    /\ UNCHANGED <<storeVars, worldVars, wpend, wlate, mpend, rphase, rheld, rpend, ephase, budgetVars,
                   eraseVars, ghostVars>>

ClosureCommit(a) ==
    LET P == epend[a] IN
    /\ P.kind = "closure"
    /\ Alive(P)
    /\ IF file[P.p].ver = P.ver \/ Twin = "ClosureNoCas"
       THEN /\ file' = [file EXCEPT ![P.p] = [live |-> TRUE, ver |-> @.ver + 1, gen |-> @.gen + 1,
                                                 seq |-> @.seq, ent |-> P.ent]]
            /\ stored1' = stored1 \cup Stored1(P.p, file[P.p].gen + 1, P.ent)
            /\ leaked' = (leaked \/ (HoldsListed(P.ent) /\ ~HoldsListed(file[P.p].ent)))
       ELSE UNCHANGED <<file, stored1, leaked>>
    /\ epend' = [epend EXCEPT ![a] = None]
    /\ UNCHANGED <<ep, large, man, gone, rolled, lock, x, worldVars, wpend, wlate, mpend, rphase, rheld,
                   rpend, ephase, budgetVars, eraseVars, indexed, rollCommits, epochBad, fenceBad, broken>>

\* An ERASE of a file's keys that held a listed version: once the file is gone, or its live version is
\* under a fresh key.
Erasable(p) ==
    /\ \E s \in KeysToGo : s[1] = p
    /\ ListedFile(p)
    /\ ~NeedsClosure(p) \/ Twin = "EraseLiveFirst"
EraseKeys(a) ==
    /\ Active(a)
    /\ \E q \in Paths : Erasable(q)
    /\ LET p == CHOOSE q \in Paths : Erasable(q) IN
       destroyed' = destroyed \cup {s \in KeysToGo : s[1] = p}
    /\ UNCHANGED <<storeVars, worldVars, procVars, budgetVars, contentGone, complete, ghostVars>>

\* The erasure is complete when no stored version holding a listed version keeps a key it lists.
Finish(a) ==
    /\ Active(a)
    /\ ~complete
    /\ contentGone
    /\ IF Twin = "EarlyComplete"
       THEN \A p \in Paths : Exists(p) => ~HoldsListed(file[p].ent)
       ELSE \A s \in KeysToGo : ~ListedFile(s[1])
    /\ complete' = TRUE
    /\ UNCHANGED <<storeVars, worldVars, procVars, budgetVars, destroyed, contentGone, ghostVars>>

EraserCrash ==
    /\ "crash" \notin Still
    /\ crashes > 0
    /\ ephase = "cut" \/ (ephase = "idle" /\ epend["eraser"] # None)
    /\ crashes' = crashes - 1
    /\ ephase' = "crashed"
    /\ UNCHANGED <<storeVars, worldVars, wpend, wlate, mpend, rphase, rheld, rpend, epend, lapses,
                   restarts, fcuts, eraseVars, ghostVars>>

\* Another erasure's CUT: it moves the epoch, keeping this set's listing.
ForeignCut ==
    /\ fcuts > 0
    /\ x' = [x EXCEPT !.ver = @ + 1]
    /\ ep' = ep + 1
    /\ fcuts' = fcuts - 1
    /\ UNCHANGED <<file, large, man, gone, rolled, lock, worldVars, procVars, crashes, lapses, restarts,
                   eraseVars, ghostVars>>

(***************************************************************************)
(* Content and time.                                                       *)
(***************************************************************************)

Write ==
    /\ next <= Events
    /\ LET s == Plot[next] IN
       /\ content' = [content EXCEPT ![s.d] = [v |-> s.v, op |-> s.op]]
       /\ journal' = IF s.skip THEN journal ELSE Append(journal, [d |-> s.d, v |-> s.v, op |-> s.op])
    /\ next' = next + 1
    /\ UNCHANGED <<storeVars, clock, procVars, budgetVars, eraseVars, ghostVars>>

\* Time moves on; every built push that can no longer land is dropped by its builder.
Tick ==
    /\ "tick" \notin Still
    /\ clock < LastClock
    /\ clock' = clock + 1
    /\ LET live(P) == P = None \/ Twin = "LongLife" \/ (P.t = clock /\ clock % 2 = 0) IN
       /\ wpend' = [w \in Writers |-> IF live(wpend[w]) THEN wpend[w] ELSE None]
       /\ wlate' = [w \in Writers |-> IF live(wlate[w]) THEN wlate[w] ELSE None]
       /\ mpend' = IF live(mpend) THEN mpend ELSE None
       /\ rpend' = [r \in Rollers |-> IF live(rpend[r]) THEN rpend[r] ELSE None]
       /\ epend' = [a \in Actors |-> IF live(epend[a]) THEN epend[a] ELSE None]
    /\ UNCHANGED <<storeVars, next, content, journal, rphase, rheld, ephase, budgetVars, eraseVars,
                   ghostVars>>

Init ==
    /\ ep = 0
    /\ clock = 1
    /\ file = [p \in Paths |-> [live |-> FALSE, ver |-> 0, gen |-> 0, seq |-> 0, ent |-> {}]]
    /\ large = [b \in Buckets |-> [w \in Writers |-> {}]]
    /\ man = [b \in Buckets |-> [ver |-> 0, abs |-> [w \in Writers |-> 0]]]
    /\ gone = {}
    /\ rolled = 0
    /\ lock = [ver |-> 0, holder |-> NoRoller, lapsed |-> FALSE]
    /\ x = [ver |-> 0, listed |-> FALSE, upto |-> 0]
    /\ next = 1
    /\ content = [d \in Docs |-> [v |-> 0, op |-> "put"]]
    /\ journal = <<>>
    /\ wpend = [w \in Writers |-> None]
    /\ wlate = [w \in Writers |-> None]
    /\ mpend = None
    /\ rphase = [r \in Rollers |-> "idle"]
    /\ rheld = [r \in Rollers |-> 0]
    /\ rpend = [r \in Rollers |-> None]
    /\ ephase = "idle"
    /\ epend = [a \in Actors |-> None]
    /\ crashes = MaxCrashes
    /\ lapses = MaxLapses
    /\ restarts = MaxRestarts
    /\ fcuts = ForeignCuts
    /\ destroyed = {}
    /\ contentGone = FALSE
    /\ complete = FALSE
    /\ indexed = [d \in Docs |-> [v |-> 0, k |-> "live"]]
    /\ stored1 = {}
    /\ rollCommits = 0
    /\ leaked = FALSE
    /\ epochBad = FALSE
    /\ fenceBad = FALSE
    /\ broken = FALSE

RollerStep(r) ==
    \/ TakeBuild(r) \/ TakeCommit(r) \/ RollBuild(r) \/ RollCommit(r)

ErasureStep(a) ==
    \/ EraseContent(a)
    \/ ClosureBuild(a)
    \/ ClosureCommit(a)
    \/ EraseKeys(a)
    \/ Finish(a)

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
    \/ CutBuild
    \/ CutCommit
    \/ \E a \in Actors : ErasureStep(a)
    \/ EraserCrash
    \/ ForeignCut

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* What TLC checks.                                                        *)
(***************************************************************************)

TypeOk ==
    /\ clock \in 1..LastClock
    /\ rollCommits \in 0..2
    /\ \A p \in Paths : Exists(p) => file[p].gen > 0
    \* no file of a bucket a roll-up removed comes back
    /\ \A b \in gone :
           /\ ~BucketLive(b)
           /\ \A p \in BucketPaths(b) : ~Exists(p)
           /\ \A w \in Writers : large[b][w] = {}
    \* one entry a key in each slot (§11.14's slot row), and no diff in a shard or in all
    /\ \A b \in Buckets : \A p \in BucketSlots(b) : \A d \in Docs : Cardinality(Of(file[p].ent, d)) <= 1
    /\ \A p \in {ShardPath(b) : b \in Buckets} \cup {AllPath} : \A e \in file[p].ent : e.k # "diff"
    \* a large entry holds a full entry of a document whose full entries are large
    /\ \A b \in Buckets : \A w \in Writers : \A l \in large[b][w] : l.d \in BigDocs

\* FI-18: every search at the head, over the buckets and all, answers each document's newest indexed
\* version, so no seal, merge, slot reuse, large-entry removal, promotion or roll-up changes a result
\* set, no tombstoned or masked version counts, and no late entry brings a deleted document back.
ResultsHold == ViewOf(IndexEnts) = Truth

\* I4: a device keeping only the buckets shows no document at an older version than its newest (no all
\* row is newer than the newest bucket entry of its key).
BucketsExact ==
    LET v == ViewOf(UNION {BucketEnts(b) : b \in Buckets}) IN
    \A d \in Docs : v[d] # 0 => v[d] = Truth[d]

\* I1 (proposed I-EVS-18): every diff in a slot no merge has absorbed, a head or a sealed one, of a
\* version the erasure set does not list, has its base in another file of its own writer in its
\* bucket, and no merge or roll-up met a diff it could not compose.
ChainsResolve ==
    /\ ~broken
    /\ \A b \in Buckets \ gone : \A p \in Sealed(b) \cup Heads(b) :
           Readable(p) => ~\E e \in Unlisted(file[p].ent) : Orphan(p, e)

\* I-EVS-11: at most one version of a document in all and in each bucket's shard, and no tombstone in
\* all.
OneVersionEach ==
    /\ \A d \in Docs : Cardinality(Of(file[AllPath].ent, d)) <= 1
    /\ \A b \in Buckets : \A d \in Docs : Cardinality(Of(file[ShardPath(b)].ent, d)) <= 1
    /\ \A e \in file[AllPath].ent : e.k = "full"

\* I-EVS-12 and FI-20: the bucket is rolled by at most one committed roll-up, which committed from the
\* lock version its runner took.
RollsOnce == rollCommits <= 1 /\ ~fenceBad

\* I-EVS-17: no push but a CLOSURE commits at an index_epoch other than the head's.
EpochHolds == ~epochBad

\* FI-19 and I-EVS-13: after the CUT no index file version but a CLOSURE's holds a listed version of
\* d1, a CLOSURE only where the version it replaced did; and once the erasure completes, every stored
\* version that held one shares a key an ERASE destroyed.
CutFences == ~leaked
ErasedUnreadable == complete => ErasedKeys \subseteq destroyed

(***************************************************************************)
(* Reach: states the joined rules must reach, so that a passing run on a    *)
(* ground is not vacuous there. A run naming one as its only invariant must *)
(* end with it violated, the trace being the witness. Section 1's own       *)
(* reach states are details/IndexMerge.tla's.                               *)
(***************************************************************************)

\* A CUT takes d1's base and a diff resting on it in separate CLOSUREs: between them the listed diff
\* waits with no base, which readers mask and I1 excepts.
NeverListedOrphan ==
    ~\E b \in Buckets \ gone : \E p \in Sealed(b) \cup Heads(b) :
        \E e \in file[p].ent : Masked(e.d, e.v) /\ Orphan(p, e)

\* A CLOSURE rewrites, under a fresh key, a slot a merge has absorbed: the eraser lists kept slots.
NeverAbsorbedClosure ==
    ~\E b \in Buckets \ gone : \E p \in BucketSlots(b) :
        Exists(p) /\ p \notin Heads(b) /\ IsAbsorbed(p) /\ file[p].gen > 1

\* A CLOSURE rewrites, under a fresh key, a kept slot: absorbed, and holding the base of a diff in its
\* writer's unabsorbed slots, which the rewrite keeps.
NeverKeptClosure ==
    ~\E b \in Buckets \ gone : \E w \in Writers : \E p \in WriterSlots(b, w) :
        /\ p # HeadOf(b, w)
        /\ IsAbsorbed(p)
        /\ file[p].gen > 1
        /\ p \in PinnedSlots(b, w, EntsAt((Sealed(b) \cap SlotPaths(b, w)) \cup {HeadOf(b, w)}))

\* An edit of d1 made after its CUT is indexed full by a writer whose other file holds the listed
\* version below it, the base R1 refuses it.
NeverFullAfterCut ==
    ~\E b \in Buckets \ gone : \E w \in Writers :
        /\ x.listed
        /\ x.upto \in BaseVersions(b, w, Erased)
        /\ \E e \in EntsAt(WriterSlots(b, w)) : e.d = Erased /\ e.v > x.upto /\ e.k = "full"

(***************************************************************************)
(* Weak fairness: the two liveness checks, in their own run.               *)
(***************************************************************************)

Fairness ==
    /\ \A r \in Rollers : WF_vars(rphase[r] # "crashed" /\ RollerStep(r))
    /\ WF_vars(LapseOfCrashed)
    /\ \A a \in Actors : WF_vars(ErasureStep(a))
    /\ WF_vars(Tick)

LiveSpec == Spec /\ Fairness

\* Every expired bucket rolls while a roller lives.
BucketRolls == (Now = 3 /\ BucketLive(1)) ~> (1 \in gone)

\* Every erasure whose CUT committed finishes while a finishing device lives.
ErasureFinishes == x.listed ~> complete

\* Safety only: TLC may miss a liveness failure under symmetry.
RollerSymmetry == Permutations(Rollers)

=============================================================================
