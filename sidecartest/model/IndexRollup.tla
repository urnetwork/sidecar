---------------------------- MODULE IndexRollup ----------------------------
(***************************************************************************)
(* §22.8's model of the search index's upkeep on one ref (§11.14): writers' *)
(* heads and sealed slots, merges, the roll-up of an expired bucket under   *)
(* its lock, and an erasure's CUT, CLOSUREs and ERASEs, none joined to      *)
(* another by a transaction. Every commit is one head CAS: each file it     *)
(* replaces at the version its builder read, and, but for a CLOSURE, the    *)
(* head's index_epoch as its builder read it (I-EVS-17).                    *)
(*                                                                          *)
(* Objects: the head's index_epoch; each index file's version, key and      *)
(* entries (slots of each writer, a shard a bucket, the all shard); each    *)
(* bucket's manifest with its absorbed seqs; a/m's rolled_through; the      *)
(* lock; the erasure set. Processes: a journaler, whose companion pushes    *)
(* are built at any epoch and land late; a backfiller, which indexes what   *)
(* no head holds; a merger, which absorbs sealed slots that their writers   *)
(* then reuse; two rollers, each of which may crash at any step, lose its   *)
(* lock at expiry or have its push land late; an eraser whose CUT, ERASE    *)
(* and CLOSURE steps may each be its last before a crash; and a finishing   *)
(* device, which resumes the erasure from evs's state alone.                *)
(*                                                                          *)
(* Documents: d1 is erased; d2 is edited by diffs across a bucket boundary; *)
(* d3 is deleted while all holds its old row. Story fixes the order of      *)
(* their content commits, which push nothing to the index themselves: the   *)
(* journaler and the backfiller do, as on ur/index (11.14's companion row). *)
(*                                                                          *)
(* What the model abstracts:                                                *)
(* - A document's text is its version: an entry or row holds a version, a   *)
(*   diff names its base, and a full row is a self-contained copy. Sizes,   *)
(*   chunks, large entries, ref tombstones, joined and capped shards and    *)
(*   the 16-diff chain bound do not appear; a bucket has one shard file.    *)
(* - When a head is full is a choice: any push may seal its writer's head   *)
(*   while a slot is free.                                                  *)
(* - Versions are per object and never restart, a removal included, so a    *)
(*   CAS compares the version its builder read; commits in another order    *)
(*   reaching the same objects are one state.                               *)
(* - Time is three windows, each with an early and a late part (clock 1 to  *)
(*   5, bucket 1 expiring at 5). A push lives minutes: one built late in a  *)
(*   window may land early in the next, none longer. A push's signed time   *)
(*   may fall in the window before the current one early in a window (two   *)
(*   writers' clocks 10 min apart at a boundary).                           *)
(* - In this slot-keyed repo each index path keeps one key, gen, which only *)
(*   a CLOSURE replaces; stored1 is every stored version that held d1,      *)
(*   since a hold may keep any (11.14's holds row), and readers open a file *)
(*   only under a key no ERASE destroyed.                                   *)
(* - An ERASE is the step that destroys keys, on the content ref.           *)
(*                                                                          *)
(* Three rules of §11.14 as written fail here, each with a question raised *)
(* and held out of the passing configuration by a constant: Supersede =     *)
(* "index" lets a journaled entry outlast the roll-up that dropped a newer  *)
(* tombstone of its document (search-m10-07-late-journal-tombstone);        *)
(* RollupFence = "files" lets a merge of a newer bucket race a roll-up's    *)
(* step 4 (search-m10-07-rollup-merge-race); and MergeCompose = "newest"    *)
(* leaves a merge nothing to compose for a stale sealed diff whose base an  *)
(* earlier merge dropped (search-m10-07-merge-stale-diff). The cfg runs     *)
(* each question's first option: "content", "manifests" and "composable".   *)
(*                                                                          *)
(* The lock is a fence the file CAS already backs: a second roll-up's       *)
(* removal of the bucket's files fails on their versions, so I-EVS-12 holds *)
(* whatever the lock says, and fenceBad records the lock check alone.       *)
(*                                                                          *)
(* Still holds the named processes still, for focused runs. Twin names a    *)
(* rule to break; a twin config sets it, and TLC must then refuse the model *)
(* with the invariant that rule protects. "none" is the design.             *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Journaler,      \* the writer whose companion journal holds the story's entries
    Backfiller,     \* the writer that backfills what no head holds
    Rollers,        \* devices that may run the roll-up: model values
    MaxSlots,       \* slots a writer may hold in a bucket (16 in the design)
    MaxCrashes,     \* crashes of rollers and the eraser in one behavior
    MaxLapses,      \* expiries of a live holder's lock in one behavior
    ForeignCuts,    \* CUTs of other erasures, which move the epoch and list nothing here
    Documents,      \* the documents whose content commits a run makes: any of "d1", "d2", "d3"
    Events,         \* how many of those commits a run makes, in Story's order
    Skew,           \* whether a push's signed time may fall in the window before the current one
    Supersede,      \* "index": the design as written; "content": question search-m10-07-late-journal-tombstone
    RollupFence,    \* "files": the design as written; "manifests": question search-m10-07-rollup-merge-race
    MergeCompose,   \* "newest": the design as written; "composable": question search-m10-07-merge-stale-diff
    Still,          \* processes held still: any of "backfill", "merge", "rollup", "erase", "crash", "lapse"
    Twin            \* "none", or the rule a twin config breaks

Writers == {Journaler, Backfiller}
Docs == {"d1", "d2", "d3"}
Erased == "d1"
Buckets == 1..3
LastClock == 5
NoRoller == "none"
None == [kind |-> "none"]
Actors == {"eraser", "finisher"}

Twins == {"none", "NoEpochCheck", "BuildIgnoresSet", "MergeDropsBase", "DiffOnHeadDiff",
          "MergeDropsTombstone", "NoStep4", "EraseLiveFirst", "EarlyComplete", "ClosureNoCas",
          "ReuseUnabsorbed", "RollupForgetsHeads"}

ASSUME
    /\ Journaler # Backfiller
    /\ MaxSlots \in 1..16
    /\ Twin \in Twins
    /\ Still \subseteq {"backfill", "merge", "rollup", "erase", "crash", "lapse"}
    /\ Supersede \in {"index", "content"}
    /\ RollupFence \in {"files", "manifests"}
    /\ MergeCompose \in {"newest", "composable"}

\* The content commits, in order: each at or after its window, and each one the journaler journals
\* unless it skips the index (an old client), left for the backfiller.
Story == <<
    [d |-> "d2", v |-> 1, op |-> "put", at |-> 1, skip |-> FALSE],
    [d |-> "d1", v |-> 1, op |-> "put", at |-> 1, skip |-> FALSE],
    [d |-> "d2", v |-> 2, op |-> "put", at |-> 1, skip |-> FALSE],
    [d |-> "d3", v |-> 1, op |-> "put", at |-> 1, skip |-> FALSE],
    [d |-> "d2", v |-> 3, op |-> "put", at |-> 2, skip |-> FALSE],
    [d |-> "d3", v |-> 2, op |-> "del", at |-> 2, skip |-> TRUE],
    [d |-> "d2", v |-> 4, op |-> "put", at |-> 2, skip |-> FALSE]
>>

\* Story's commits of the run's documents.
Plot == SelectSeq(Story, LAMBDA s : s.d \in Documents)

ASSUME Documents \subseteq Docs /\ Events \in 0..Len(Plot)

Max(S) == CHOOSE m \in S : \A n \in S : n <= m
Min(S) == CHOOSE m \in S : \A n \in S : m <= n

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
    file,        \* file[p]: index file p: live, ver, gen (its key), seq (slots) and ent
    man,         \* man[b]: bucket b's manifest: live, ver and abs, each writer's highest absorbed seq
    gone,        \* buckets a roll-up removed
    rolled,      \* a/m's rolled_through: 0, or 1 once bucket 1 is in all
    lock,        \* <root>/lock: ver, holder and lapsed (its until_ms past)
    x,           \* the erasure set: ver, listed (d1 pending) and upto, the newest version of d1 erased
    next,        \* the story's next content commit
    content,     \* content[d]: the newest committed version of d's content, v and op
    journal,     \* the journaler's entries not yet in a committed head push
    wpend,       \* wpend[w]: w's built head push, or None
    mpend,       \* the merger's built merge, or None
    rphase,      \* rphase[r]: "idle", "holding", "crashed" or "done"
    rheld,       \* rheld[r]: the lock version r took, 0 for none
    rpend,       \* rpend[r]: r's built lock take or roll-up, or None
    ephase,      \* the eraser: "idle", "cut" once its CUT committed, or "crashed"
    epend,       \* epend[a]: the built CUT or CLOSURE of the eraser or the finishing device
    crashes,     \* crashes left
    lapses,      \* expiries of a live holder's lock left
    fcuts,       \* foreign CUTs left
    destroyed,   \* the <<path, gen>> keys an ERASE destroyed
    contentGone, \* the first ERASE destroyed d1's own keys
    complete,    \* the erasure judged itself finished
    indexed,     \* ghost: indexed[d], the newest entry of d a committed push carried: v and k
    stored1,     \* ghost: the <<path, gen>> of every committed index file version that held d1
    rollCommits, \* ghost: committed roll-ups of bucket 1
    leaked,      \* ghost: a push but a CLOSURE wrote d1 into an index file after the CUT
    epochBad,    \* ghost: a push but a CLOSURE committed at an index_epoch not the head's
    fenceBad,    \* ghost: a roll-up committed from a lock version its runner did not take
    broken       \* ghost: a merge or roll-up met a version it could not compose from its inputs

storeVars == <<ep, file, man, gone, rolled, lock, x>>
worldVars == <<clock, next, content, journal>>
procVars == <<wpend, mpend, rphase, rheld, rpend, ephase, epend>>
budgetVars == <<crashes, lapses, fcuts>>
eraseVars == <<destroyed, contentGone, complete>>
ghostVars == <<indexed, stored1, rollCommits, leaked, epochBad, fenceBad, broken>>
vars == <<storeVars, worldVars, procVars, budgetVars, eraseVars, ghostVars>>

(***************************************************************************)
(* Reading the index at the head.                                           *)
(***************************************************************************)

Now == (clock + 1) \div 2
Early == clock % 2 = 1

Exists(p) == file[p].live
Readable(p) == <<p, file[p].gen>> \notin destroyed
BucketExists(b) == man[b].live

WriterSlots(b, w) == {p \in SlotPaths(b, w) : Exists(p)}
HeadOf(b, w) ==
    IF WriterSlots(b, w) = {} THEN <<>>
    ELSE CHOOSE p \in WriterSlots(b, w) : \A q \in WriterSlots(b, w) : file[q].seq <= file[p].seq
Heads(b) == {HeadOf(b, w) : w \in Writers} \ {<<>>}
IsAbsorbed(p) == file[p].seq <= man[p[2]].abs[p[3]]
Sealed(b) == {p \in BucketSlots(b) : Exists(p) /\ p \notin Heads(b) /\ ~IsAbsorbed(p)}

EntsAt(P) == UNION {IF Exists(p) /\ Readable(p) THEN file[p].ent ELSE {} : p \in P}
HeadEnts(b) == IF b \in gone THEN {} ELSE EntsAt(Heads(b))
\* What lies outside every writer's head in bucket b: its shard and its sealed, unabsorbed slots.
OutEnts(b) == IF b \in gone THEN {} ELSE EntsAt(Sealed(b) \cup {ShardPath(b)})
BucketEnts(b) == HeadEnts(b) \cup OutEnts(b)
AllEnts == EntsAt({AllPath})
IndexEnts == AllEnts \cup (UNION {BucketEnts(b) : b \in Buckets})

Of(S, d) == {e \in S : e.d = d}
Top(S, d) == IF Of(S, d) = {} THEN 0 ELSE Max({e.v : e \in Of(S, d)})
TombAt(S, d, v) == \E e \in Of(S, d) : e.v = v /\ e.k = "tomb"
Masked(d, v) == x.listed /\ d = Erased /\ v <= x.upto
Holds1(S) == \E e \in S : e.d = Erased
HoldsListed(S) == \E e \in S : Masked(e.d, e.v)

\* What a builder writes of S: nothing of a document the erasure set lists, at or below its version
\* (11.14's epoch row).
Clean(S) == IF Twin = "BuildIgnoresSet" THEN S ELSE {e \in S : ~Masked(e.d, e.v)}

\* A search's answer per document over the entries S: its newest version, unless that is a tombstone
\* or the erasure masks it (11.14's newest row); 0 for no hit.
ViewOf(S) == [d \in Docs |->
    LET t == Top(S, d) IN IF t = 0 \/ TombAt(S, d, t) \/ Masked(d, t) THEN 0 ELSE t]

\* What every search must answer: each document's newest indexed version.
Truth == [d \in Docs |->
    IF indexed[d].v = 0 \/ indexed[d].k = "tomb" \/ Masked(d, indexed[d].v) THEN 0 ELSE indexed[d].v]

\* Version v of d resolves in bucket b outside every head: a self-contained copy, or a diff whose base
\* does (11.14's chains row; copies of one version are one).
RECURSIVE Resolves(_, _, _)
Resolves(b, d, v) ==
    \E e \in Of(OutEnts(b), d) :
        /\ e.v = v
        /\ e.k = "full" \/ (e.k = "diff" /\ Resolves(b, d, e.base))

\* Version v of d composes from the entries S alone.
RECURSIVE ComposesIn(_, _, _)
ComposesIn(S, d, v) ==
    \E e \in Of(S, d) :
        /\ e.v = v
        /\ e.k \in {"full", "tomb"} \/ (e.k = "diff" /\ ComposesIn(S, d, e.base))

Row(S, d, v) == [d |-> d, v |-> v, k |-> IF TombAt(S, d, v) THEN "tomb" ELSE "full", base |-> 0]

Newer(old, e) == IF e.v > old.v THEN [v |-> e.v, k |-> IF e.k = "tomb" THEN "tomb" ELSE "live"] ELSE old

\* A file written: its next version, under key gen.
Written(p, gen, seq, ent) == [live |-> TRUE, ver |-> file[p].ver + 1, gen |-> gen, seq |-> seq, ent |-> ent]
\* A file removed: its next version is a removal, and its key stays its own.
Removed(p) == [file[p] EXCEPT !.live = FALSE, !.ver = @ + 1, !.seq = 0, !.ent = {}]

(***************************************************************************)
(* Writers: the journaler's companion pushes and the backfiller's.          *)
(***************************************************************************)

\* The windows a push built now may be signed in.
Windows == IF Skew /\ Early /\ Now > 1 THEN {Now, Now - 1} ELSE {Now}

\* A push lands only within minutes of its build: at its own clock, or, built late in a window,
\* early in the next.
Alive(P) == P.t = clock \/ (P.t + 1 = clock /\ P.t % 2 = 0)

\* The bucket an entry of d goes to from a push signed in window t0: that window's, or the newest
\* bucket already holding an entry of d where that is newer (11.14's entry row).
Target(d, t0) ==
    LET held == {b \in Buckets \ gone : Of(BucketEnts(b), d) # {}} IN
    IF held = {} THEN t0 ELSE Max(held \cup {t0})

\* The base a diff of d at version v may name in bucket b for w's push, or 0 when it must be full
\* (11.14's dependency row): d's newest entry is at v - 1 and no tombstone, in the current bucket,
\* and either (a) a copy of it there lies outside every head while no head holds a diff of that
\* version, or (b) w's own head holds it as a diff whose base is d's newest entry outside every head,
\* whose base the new entry then takes.
DiffBase(w, b, d, v) ==
    LET t == Top(IndexEnts, d)
        outTop == Top(OutEnts(b), d)
        own == IF HeadOf(b, w) = <<>> THEN {} ELSE Of(EntsAt({HeadOf(b, w)}), d)
        headDiffAt(u) == \E e \in Of(HeadEnts(b), d) : e.v = u /\ e.k = "diff"
    IN  IF b # Now \/ v = 1 \/ t # v - 1 \/ TombAt(IndexEnts, d, t) THEN 0
        ELSE IF /\ \E e \in Of(OutEnts(b), d) : e.v = v - 1 /\ e.k # "tomb"
                /\ ~headDiffAt(v - 1) \/ Twin = "DiffOnHeadDiff"
             THEN v - 1
        ELSE IF /\ outTop > 0
                /\ \E e \in own : e.v = v - 1 /\ e.k = "diff" /\ e.base = outTop
             THEN outTop
        ELSE 0

\* The entry w writes for content version j in bucket b. The backfiller writes full entries.
EntryFor(w, b, j) ==
    IF j.op = "del" THEN [d |-> j.d, v |-> j.v, k |-> "tomb", base |-> 0]
    ELSE IF w = Journaler /\ DiffBase(w, b, j.d, j.v) > 0
         THEN [d |-> j.d, v |-> j.v, k |-> "diff", base |-> DiffBase(w, b, j.d, j.v)]
         ELSE [d |-> j.d, v |-> j.v, k |-> "full", base |-> 0]

MaxSeq(b, w) == IF WriterSlots(b, w) = {} THEN 0 ELSE Max({file[p].seq : p \in WriterSlots(b, w)})
\* The slot a seal opens: the lowest the manifest shows absorbed, else a new one (11.14's seal row).
Reusable(b, w) ==
    {k \in 1..MaxSlots :
        /\ Exists(SlotPath(b, w, k))
        /\ SlotPath(b, w, k) # HeadOf(b, w)
        /\ IsAbsorbed(SlotPath(b, w, k)) \/ Twin = "ReuseUnabsorbed"}
Unused(b, w) == {k \in 1..MaxSlots : ~Exists(SlotPath(b, w, k))}
SealSlot(b, w) ==
    IF Reusable(b, w) # {} THEN Min(Reusable(b, w))
    ELSE IF Unused(b, w) # {} THEN Min(Unused(b, w)) ELSE 0
KeyOf(p) == IF file[p].gen = 0 THEN 1 ELSE file[p].gen

\* w's head push of entry e into bucket b: appending to its head, replacing the head's entry of e's
\* document, or sealing the head and opening the next slot. The first push into a bucket creates its
\* manifest, so a push into a bucket a roll-up removed meets a manifest it did not read.
HeadPushes(w, b, e) ==
    LET head == HeadOf(b, w)
        open(k) == [kind |-> "head", p |-> SlotPath(b, w, k), ver |-> file[SlotPath(b, w, k)].ver,
                    gen |-> KeyOf(SlotPath(b, w, k)), seq |-> MaxSeq(b, w) + 1, ent |-> {e},
                    entry |-> e, epoch |-> ep, man |-> man[b], t |-> clock]
        append == [kind |-> "head", p |-> head, ver |-> file[head].ver, gen |-> file[head].gen,
                   seq |-> file[head].seq,
                   ent |-> Clean({y \in file[head].ent : y.d # e.d}) \cup {e},
                   entry |-> e, epoch |-> ep, man |-> man[b], t |-> clock]
    IN  IF head = <<>> THEN {open(SealSlot(b, w))}
        ELSE {append} \cup (IF SealSlot(b, w) = 0 THEN {} ELSE {open(SealSlot(b, w))})

\* An entry the index at the base holds at a higher version is superseded (11.14's companion row).
\* Read so (Supersede = "index"), a journaled entry that waits on its device past the roll-up of the
\* bucket holding a newer tombstone of its document finds nothing newer, since the roll-up dropped the
\* tombstone, and resurrects the deleted version: ResultsHold fails. Question
\* search-m10-07-late-journal-tombstone asks for a rule; "content" is its first option, the entry
\* superseded also where the content ref's head, which a companion push's coverage pins, holds its
\* document at a higher version, the newer one left to its own entry or a backfill.
Superseded(j) ==
    \/ Top(IndexEnts, j.d) > j.v
    \/ Supersede = "content" /\ content[j.d].v > j.v

JournalBuild ==
    /\ wpend[Journaler] = None
    /\ journal # <<>>
    /\ LET j == Head(journal) IN
       IF Superseded(j) \/ (Masked(j.d, j.v) /\ Twin # "BuildIgnoresSet")
       THEN /\ journal' = Tail(journal)
            /\ UNCHANGED wpend
       ELSE /\ \E t0 \in Windows :
                 \E push \in HeadPushes(Journaler, Target(j.d, t0), EntryFor(Journaler, Target(j.d, t0), j)) :
                     wpend' = [wpend EXCEPT ![Journaler] = push]
            /\ UNCHANGED journal
    /\ UNCHANGED <<storeVars, clock, next, content, mpend, rphase, rheld, rpend, ephase, epend,
                   budgetVars, eraseVars, ghostVars>>

\* A content version no index entry reaches yet, which the backfiller indexes into its own head,
\* skipping the erasure set's documents and any whose content an ERASE left unopenable.
BackfillBuild ==
    /\ "backfill" \notin Still
    /\ wpend[Backfiller] = None
    /\ \E d \in Docs :
           /\ content[d].v > 0
           \* a push no index entry reached: readers' indexed_through, from the coverage pushes carry
           /\ indexed[d].v < content[d].v
           /\ ~Masked(d, content[d].v) \/ Twin = "BuildIgnoresSet"
           /\ ~(d = Erased /\ contentGone)
           /\ \E t0 \in Windows :
                  LET j == [d |-> d, v |-> content[d].v, op |-> content[d].op]
                      b == Target(d, t0)
                  IN  \E push \in HeadPushes(Backfiller, b, EntryFor(Backfiller, b, j)) :
                          wpend' = [wpend EXCEPT ![Backfiller] = push]
    /\ UNCHANGED <<storeVars, worldVars, mpend, rphase, rheld, rpend, ephase, epend, budgetVars,
                   eraseVars, ghostVars>>

\* The head CAS: the slot at the version read, a new bucket's manifest still as read, and the epoch.
\* On 409 the builder rereads and builds again.
HeadCommit(w) ==
    LET P == wpend[w]
        b == P.p[2]
        ok == /\ file[P.p].ver = P.ver
              /\ man[b].ver = P.man.ver
              /\ P.epoch = ep \/ Twin = "NoEpochCheck"
    IN  /\ P.kind = "head"
        /\ Alive(P)
        /\ IF ok
           THEN /\ file' = [file EXCEPT ![P.p] = Written(P.p, P.gen, P.seq, P.ent)]
                /\ man' = IF P.man.live THEN man
                          ELSE [man EXCEPT ![b] = [live |-> TRUE, ver |-> @.ver + 1, abs |-> @.abs]]
                /\ indexed' = [indexed EXCEPT ![P.entry.d] = Newer(@, P.entry)]
                /\ stored1' = IF Holds1(P.ent) THEN stored1 \cup {<<P.p, P.gen>>} ELSE stored1
                /\ leaked' = (leaked \/ HoldsListed(P.ent))
                /\ epochBad' = (epochBad \/ P.epoch # ep)
                /\ journal' = IF w = Journaler THEN Tail(journal) ELSE journal
           ELSE UNCHANGED <<file, man, indexed, stored1, leaked, epochBad, journal>>
        /\ wpend' = [wpend EXCEPT ![w] = None]
        /\ UNCHANGED <<ep, gone, rolled, lock, x, clock, next, content, mpend, rphase, rheld, rpend,
                       ephase, epend, budgetVars, eraseVars, rollCommits, fenceBad, broken>>

(***************************************************************************)
(* The merger (11.14's merges): a bucket's sealed slots into its shard.     *)
(***************************************************************************)

\* The version a merge keeps of d from inputs In, given the heads' entries H: the newest, unless d's
\* newest entries in heads, at a version no input exceeds, are all diffs with a base among the
\* inputs, and then the oldest such base, so no merge drops a base a current head entry needs.
MergeVersion(In, H, d) ==
    LET top == Top(In, d)
        hTop == Top(H, d)
        hn == {e \in Of(H, d) : e.v = hTop}
    IN  IF /\ Twin # "MergeDropsBase"
           /\ hTop >= top
           /\ hn # {}
           /\ \A e \in hn : e.k = "diff" /\ \E i \in Of(In, d) : i.v = e.base
        THEN Min({e.base : e \in hn})
        ELSE top

\* The design's merge composes each document's newest input (MergeCompose = "newest"). An earlier merge
\* keeps only a base the newest head entries need, so a diff below a newer head entry, which §11.14's
\* chains row lets lose its base, can later be sealed and become a merge's newest input with no base
\* among the inputs: the merge cannot compose it (ChainsResolve's broken). Question
\* search-m10-07-merge-stale-diff asks for a rule; "composable" is its first option: such a diff,
\* below a head's newer entry, is no candidate there either, and the merge keeps the document's newest
\* version that composes, or no row.
Composable(In, d) == {e.v : e \in {y \in Of(In, d) : ComposesIn(In, d, y.v)}}
MergeKept(In, H, d) ==
    LET v == MergeVersion(In, H, d) IN
    IF /\ MergeCompose = "composable"
       /\ ~ComposesIn(In, d, v)
       /\ Top(H, d) > v
    THEN IF Composable(In, d) = {} THEN 0 ELSE Max(Composable(In, d))
    ELSE v

\* Each document's kept version, a live one as a full row and a tombstone kept for the older
\* partitions until the roll-up.
MergeRows(In, H) ==
    LET kept == {Row(In, d, MergeKept(In, H, d)) : d \in {doc \in {e.d : e \in In} : MergeKept(In, H, doc) > 0}} IN
    IF Twin = "MergeDropsTombstone" THEN {r \in kept : r.k # "tomb"} ELSE kept

MergeBuild(b) ==
    /\ "merge" \notin Still
    /\ mpend = None
    /\ b \notin gone
    /\ BucketExists(b)
    /\ b >= Now - 1
    /\ Sealed(b) # {}
    /\ LET In == Clean(OutEnts(b))
           H == HeadEnts(b)
           abs == [w \in Writers |->
                      Max({man[b].abs[w]} \cup {file[p].seq : p \in Sealed(b) \cap SlotPaths(b, w)})]
       IN  /\ mpend' = [kind |-> "merge", b |-> b, shard |-> file[ShardPath(b)].ver, man |-> man[b].ver,
                        rows |-> MergeRows(In, H), abs |-> abs, epoch |-> ep, t |-> clock]
           /\ broken' = (broken \/ \E d \in {e.d : e \in In} :
                             MergeKept(In, H, d) > 0 /\ ~ComposesIn(In, d, MergeKept(In, H, d)))
    /\ UNCHANGED <<storeVars, worldVars, wpend, rphase, rheld, rpend, ephase, epend, budgetVars,
                   eraseVars, indexed, stored1, rollCommits, leaked, epochBad, fenceBad>>

MergeCommit ==
    LET P == mpend
        s == ShardPath(P.b)
        ok == /\ file[s].ver = P.shard
              /\ man[P.b].ver = P.man
              /\ P.epoch = ep \/ Twin = "NoEpochCheck"
    IN  /\ P.kind = "merge"
        /\ Alive(P)
        /\ IF ok
           THEN /\ file' = [file EXCEPT ![s] = Written(s, KeyOf(s), 0, P.rows)]
                /\ man' = [man EXCEPT ![P.b] = [live |-> TRUE, ver |-> @.ver + 1, abs |-> P.abs]]
                /\ stored1' = IF Holds1(P.rows) THEN stored1 \cup {<<s, KeyOf(s)>>} ELSE stored1
                /\ leaked' = (leaked \/ HoldsListed(P.rows))
                /\ epochBad' = (epochBad \/ P.epoch # ep)
           ELSE UNCHANGED <<file, man, stored1, leaked, epochBad>>
        /\ mpend' = None
        /\ UNCHANGED <<ep, gone, rolled, lock, x, worldVars, wpend, rphase, rheld, rpend, ephase,
                       epend, budgetVars, eraseVars, indexed, rollCommits, fenceBad, broken>>

(***************************************************************************)
(* The roll-up of bucket 1 into all (11.14's roll-up), under the lock.      *)
(***************************************************************************)

\* Step 2's inputs: the bucket as a merge reads it, writers' heads included.
RollInputs == Clean(IF Twin = "RollupForgetsHeads" THEN OutEnts(1) ELSE BucketEnts(1))
Carried(d) == Top(RollInputs, d)
\* Steps 3 and 4: per document, the newer of the bucket's and all's stays, a tombstone taking all's
\* row and then going itself; every version the erasure set lists goes.
NewAll ==
    LET old == Clean(AllEnts) IN
    {r \in {IF Carried(d) = 0 \/ Top(old, d) > Carried(d)
            THEN [d |-> d, v |-> Top(old, d), k |-> "full", base |-> 0]
            ELSE Row(RollInputs, d, Carried(d)) : d \in Docs} :
        r.v > 0 /\ r.k = "full"}
\* Step 4's rewrites: an entry of a newer bucket below a version or tombstone this roll-up carries,
\* which leaves its file in place.
Stale(p) == {e \in file[p].ent : Carried(e.d) > 0 /\ e.v < Carried(e.d)}
Rewrites ==
    IF Twin = "NoStep4" THEN {}
    ELSE {p \in BucketPaths(2) \cup BucketPaths(3) : Exists(p) /\ Stale(p) # {}}
\* The design's roll-up replaces only the files it rewrites (RollupFence = "files"), so a merge of a
\* newer bucket landing between its build and its commit copies a stale entry from a slot it rewrites
\* into that bucket's shard, which it never listed, and both commit: ResultsHold fails. Question
\* search-m10-07-rollup-merge-race asks for a rule; "manifests" is its first option, a roll-up that
\* rewrites any file of a newer bucket also rewriting that bucket's manifest, which every merge
\* replaces, so whichever lands second gets 409.
Fenced == IF RollupFence = "manifests" THEN {p[2] : p \in Rewrites} ELSE {}

TakeBuild(r) ==
    /\ "rollup" \notin Still
    /\ rphase[r] = "idle"
    /\ rpend[r] = None
    /\ Now = 3
    /\ 1 \notin gone
    /\ BucketExists(1)
    /\ lock.holder = NoRoller \/ lock.lapsed
    /\ rpend' = [rpend EXCEPT ![r] = [kind |-> "take", lock |-> lock.ver, epoch |-> ep, t |-> clock]]
    /\ UNCHANGED <<storeVars, worldVars, wpend, mpend, rphase, rheld, ephase, epend, budgetVars,
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
    /\ UNCHANGED <<ep, file, man, gone, rolled, x, worldVars, wpend, mpend, ephase, epend,
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
                    rewrites |-> [p \in Rewrites |-> [ver |-> file[p].ver, ent |-> Clean(file[p].ent) \ Stale(p)]],
                    fenced |-> [b \in Fenced |-> man[b].ver],
                    rows |-> NewAll, t |-> clock]]
            /\ broken' = (broken \/ \E d \in Docs : Carried(d) > 0 /\ ~ComposesIn(RollInputs, d, Carried(d)))
            /\ UNCHANGED rphase
    /\ UNCHANGED <<storeVars, worldVars, wpend, mpend, rheld, ephase, epend, budgetVars, eraseVars,
                   indexed, stored1, rollCommits, leaked, epochBad, fenceBad>>

\* Step 6: one push writing all and the rewrites, removing every file of bucket 1, setting a/m's
\* rolled_through and freeing the lock from the version the runner holds, the fencing token. A runner
\* whose lock was taken stops; any other 409 reruns from step 1.
RollCommit(r) ==
    LET P == rpend[r]
        ok == /\ lock.ver = P.lock
              /\ P.epoch = ep \/ Twin = "NoEpochCheck"
              /\ file[AllPath].ver = P.all
              /\ man[1].ver = P.man
              /\ \A p \in BucketPaths(1) : file[p].ver = P.bucket[p]
              /\ \A p \in DOMAIN P.rewrites : file[p].ver = P.rewrites[p].ver
              /\ \A b \in DOMAIN P.fenced : man[b].ver = P.fenced[b]
        written == P.rows \cup (UNION {P.rewrites[p].ent : p \in DOMAIN P.rewrites})
    IN  /\ P.kind = "roll"
        /\ Alive(P)
        /\ IF ok
           THEN /\ file' = [p \in Paths |->
                      IF p = AllPath THEN Written(AllPath, KeyOf(AllPath), 0, P.rows)
                      ELSE IF p \in BucketPaths(1) THEN (IF Exists(p) THEN Removed(p) ELSE file[p])
                      ELSE IF p \in DOMAIN P.rewrites THEN Written(p, file[p].gen, file[p].seq, P.rewrites[p].ent)
                      ELSE file[p]]
                /\ man' = [b \in Buckets |->
                      IF b = 1 THEN [man[1] EXCEPT !.live = FALSE, !.ver = @ + 1]
                      ELSE IF b \in DOMAIN P.fenced THEN [man[b] EXCEPT !.ver = @ + 1]
                      ELSE man[b]]
                /\ gone' = gone \cup {1}
                /\ rolled' = 1
                /\ lock' = [ver |-> lock.ver + 1, holder |-> NoRoller, lapsed |-> FALSE]
                /\ rollCommits' = rollCommits + 1
                /\ fenceBad' = (fenceBad \/ lock.ver # P.lock)
                /\ epochBad' = (epochBad \/ P.epoch # ep)
                /\ stored1' = stored1
                       \cup (IF Holds1(P.rows) THEN {<<AllPath, KeyOf(AllPath)>>} ELSE {})
                       \cup {<<p, file[p].gen>> : p \in {q \in DOMAIN P.rewrites : Holds1(P.rewrites[q].ent)}}
                /\ leaked' = (leaked \/ HoldsListed(written))
                /\ rphase' = [rphase EXCEPT ![r] = IF @ = "crashed" THEN @ ELSE "done"]
                /\ UNCHANGED rheld
           ELSE /\ IF lock.ver # P.lock
                   THEN /\ rphase' = [rphase EXCEPT ![r] = IF @ = "crashed" THEN @ ELSE "idle"]
                        /\ rheld' = [rheld EXCEPT ![r] = 0]
                   ELSE UNCHANGED <<rphase, rheld>>
                /\ UNCHANGED <<file, man, gone, rolled, lock, rollCommits, fenceBad, epochBad, stored1,
                               leaked>>
        /\ rpend' = [rpend EXCEPT ![r] = None]
        /\ UNCHANGED <<ep, x, worldVars, wpend, mpend, ephase, epend, budgetVars, eraseVars, indexed,
                       broken>>

\* The lock's until_ms passes: a crashed holder's always, a live holder's while lapses last.
Lapse ==
    /\ lock.holder # NoRoller
    /\ ~lock.lapsed
    /\ \/ rphase[lock.holder] = "crashed"
       \/ lapses > 0 /\ "lapse" \notin Still
    /\ lock' = [lock EXCEPT !.lapsed = TRUE]
    /\ lapses' = IF rphase[lock.holder] = "crashed" THEN lapses ELSE lapses - 1
    /\ UNCHANGED <<ep, file, man, gone, rolled, x, worldVars, procVars, crashes, fcuts, eraseVars,
                   ghostVars>>

LapseOfCrashed == lock.holder # NoRoller /\ rphase[lock.holder] = "crashed" /\ Lapse

\* A roller dies holding the lock or with its take in flight; a push it sent may still land.
RollerCrash(r) ==
    /\ "crash" \notin Still
    /\ crashes > 0
    /\ rphase[r] = "holding" \/ (rphase[r] = "idle" /\ rpend[r] # None)
    /\ crashes' = crashes - 1
    /\ rphase' = [rphase EXCEPT ![r] = "crashed"]
    /\ UNCHANGED <<storeVars, worldVars, wpend, mpend, rheld, rpend, ephase, epend, lapses, fcuts,
                   eraseVars, ghostVars>>

(***************************************************************************)
(* The erasure of d1 (11.12's closure, rekey and cut rows; 11.14's erase).  *)
(***************************************************************************)

\* The CUT: from the erasure set read and at the head's epoch, it lists d1 at its newest version and
\* moves index_epoch to its own version (D-EVS-66).
CutBuild ==
    /\ "erase" \notin Still
    /\ ephase = "idle"
    /\ epend["eraser"] = None
    /\ content[Erased].v > 0
    /\ ~x.listed
    /\ epend' = [epend EXCEPT !["eraser"] = [kind |-> "cut", x |-> x.ver, epoch |-> ep, t |-> clock]]
    /\ UNCHANGED <<storeVars, worldVars, wpend, mpend, rphase, rheld, rpend, ephase, budgetVars,
                   eraseVars, ghostVars>>

CutCommit ==
    LET P == epend["eraser"] IN
    /\ P.kind = "cut"
    /\ Alive(P)
    /\ IF x.ver = P.x /\ P.epoch = ep
       THEN /\ x' = [ver |-> x.ver + 1, listed |-> TRUE, upto |-> content[Erased].v]
            /\ ep' = ep + 1
            /\ ephase' = IF ephase = "crashed" THEN ephase ELSE "cut"
       ELSE UNCHANGED <<x, ep, ephase>>
    /\ epend' = [epend EXCEPT !["eraser"] = None]
    /\ UNCHANGED <<file, man, gone, rolled, lock, worldVars, wpend, mpend, rphase, rheld, rpend,
                   budgetVars, eraseVars, ghostVars>>

\* The eraser works while it lives; once it dies after its CUT, the finishing device resumes from
\* evs's state: the set lists the erasure, and the history shows each version that held d1.
Active(a) ==
    /\ "erase" \notin Still
    /\ \/ a = "eraser" /\ ephase = "cut"
       \/ a = "finisher" /\ ephase = "crashed" /\ x.listed

\* Every stored version holding d1 whose key no ERASE has destroyed.
KeysToGo == stored1 \ destroyed
\* A live file whose key is one of them is rewritten under a fresh key first.
NeedsClosure(p) == Exists(p) /\ <<p, file[p].gen>> \in KeysToGo
Without1(S) == {e \in S : ~Masked(e.d, e.v)}

\* The first ERASE: the entry's own keys.
EraseContent(a) ==
    /\ Active(a)
    /\ ~contentGone
    /\ contentGone' = TRUE
    /\ UNCHANGED <<storeVars, worldVars, procVars, budgetVars, destroyed, complete, ghostVars>>

\* A CLOSURE: a file whose live key must go, rewritten in place without d1 under a fresh key,
\* replacing the version read; no epoch, since it only replaces versions. Files go one at a time in
\* a fixed order, since each one's CLOSURE and ERASE touch no other file.
ClosureBuild(a) ==
    /\ Active(a)
    /\ epend[a] = None
    /\ \E q \in Paths : NeedsClosure(q)
    /\ LET p == CHOOSE q \in Paths : NeedsClosure(q) IN
       epend' = [epend EXCEPT ![a] = [kind |-> "closure", p |-> p, ver |-> file[p].ver,
                                       ent |-> Without1(file[p].ent), t |-> clock]]
    /\ UNCHANGED <<storeVars, worldVars, wpend, mpend, rphase, rheld, rpend, ephase, budgetVars,
                   eraseVars, ghostVars>>

ClosureCommit(a) ==
    LET P == epend[a] IN
    /\ P.kind = "closure"
    /\ Alive(P)
    /\ IF file[P.p].ver = P.ver \/ Twin = "ClosureNoCas"
       THEN /\ file' = [file EXCEPT ![P.p] = Written(P.p, file[P.p].gen + 1, file[P.p].seq, P.ent)]
            /\ stored1' = IF Holds1(P.ent) THEN stored1 \cup {<<P.p, file[P.p].gen + 1>>} ELSE stored1
            /\ leaked' = (leaked \/ (HoldsListed(P.ent) /\ ~HoldsListed(file[P.p].ent)))
       ELSE UNCHANGED <<file, stored1, leaked>>
    /\ epend' = [epend EXCEPT ![a] = None]
    /\ UNCHANGED <<ep, man, gone, rolled, lock, x, worldVars, wpend, mpend, rphase, rheld, rpend,
                   ephase, budgetVars, eraseVars, indexed, rollCommits, epochBad, fenceBad, broken>>

\* An ERASE of a file's keys that held d1: once the file is gone, or its live version is under a
\* fresh key.
Erasable(p) == (\E s \in KeysToGo : s[1] = p) /\ (~NeedsClosure(p) \/ Twin = "EraseLiveFirst")
EraseKeys(a) ==
    /\ Active(a)
    /\ \E q \in Paths : Erasable(q)
    /\ LET p == CHOOSE q \in Paths : Erasable(q) IN
       destroyed' = destroyed \cup {s \in KeysToGo : s[1] = p}
    /\ UNCHANGED <<storeVars, worldVars, procVars, budgetVars, contentGone, complete, ghostVars>>

\* The erasure is complete when no stored version holding d1 keeps a key.
Finish(a) ==
    /\ Active(a)
    /\ ~complete
    /\ contentGone
    /\ IF Twin = "EarlyComplete"
       THEN \A p \in Paths : Exists(p) => ~Holds1(file[p].ent)
       ELSE KeysToGo = {}
    /\ complete' = TRUE
    /\ UNCHANGED <<storeVars, worldVars, procVars, budgetVars, destroyed, contentGone, ghostVars>>

EraserCrash ==
    /\ "crash" \notin Still
    /\ crashes > 0
    /\ ephase = "cut" \/ (ephase = "idle" /\ epend["eraser"] # None)
    /\ crashes' = crashes - 1
    /\ ephase' = "crashed"
    /\ UNCHANGED <<storeVars, worldVars, wpend, mpend, rphase, rheld, rpend, epend, lapses, fcuts,
                   eraseVars, ghostVars>>

\* Another erasure's CUT: it moves the epoch, keeping this set's listing.
ForeignCut ==
    /\ fcuts > 0
    /\ x' = [x EXCEPT !.ver = @ + 1]
    /\ ep' = ep + 1
    /\ fcuts' = fcuts - 1
    /\ UNCHANGED <<file, man, gone, rolled, lock, worldVars, procVars, crashes, lapses, eraseVars,
                   ghostVars>>

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
    /\ UNCHANGED <<storeVars, clock, procVars, budgetVars, eraseVars, ghostVars>>

\* Time moves on; every built push that can no longer land is dropped by its builder.
Tick ==
    /\ clock < LastClock
    /\ clock' = clock + 1
    /\ LET live(P) == P = None \/ (P.t = clock /\ clock % 2 = 0) IN
       /\ wpend' = [w \in Writers |-> IF live(wpend[w]) THEN wpend[w] ELSE None]
       /\ mpend' = IF live(mpend) THEN mpend ELSE None
       /\ rpend' = [r \in Rollers |-> IF live(rpend[r]) THEN rpend[r] ELSE None]
       /\ epend' = [a \in Actors |-> IF live(epend[a]) THEN epend[a] ELSE None]
    /\ UNCHANGED <<storeVars, next, content, journal, rphase, rheld, ephase, budgetVars, eraseVars,
                   ghostVars>>

Init ==
    /\ ep = 0
    /\ clock = 1
    /\ file = [p \in Paths |-> [live |-> FALSE, ver |-> 0, gen |-> 0, seq |-> 0, ent |-> {}]]
    /\ man = [b \in Buckets |-> [live |-> FALSE, ver |-> 0, abs |-> [w \in Writers |-> 0]]]
    /\ gone = {}
    /\ rolled = 0
    /\ lock = [ver |-> 0, holder |-> NoRoller, lapsed |-> FALSE]
    /\ x = [ver |-> 0, listed |-> FALSE, upto |-> 0]
    /\ next = 1
    /\ content = [d \in Docs |-> [v |-> 0, op |-> "put"]]
    /\ journal = <<>>
    /\ wpend = [w \in Writers |-> None]
    /\ mpend = None
    /\ rphase = [r \in Rollers |-> "idle"]
    /\ rheld = [r \in Rollers |-> 0]
    /\ rpend = [r \in Rollers |-> None]
    /\ ephase = "idle"
    /\ epend = [a \in Actors |-> None]
    /\ crashes = MaxCrashes
    /\ lapses = MaxLapses
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
    \/ \E w \in Writers : HeadCommit(w)
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
(* What TLC checks.                                                         *)
(***************************************************************************)

TypeOk ==
    /\ clock \in 1..LastClock
    /\ rollCommits \in 0..2
    /\ \A p \in Paths : Exists(p) => file[p].gen > 0
    \* no file of a bucket a roll-up removed comes back
    /\ \A b \in gone : ~BucketExists(b) /\ \A p \in BucketPaths(b) : ~Exists(p)
    \* one entry a key in each slot (11.14's slot row)
    /\ \A b \in Buckets : \A p \in BucketSlots(b) : \A d \in Docs : Cardinality(Of(file[p].ent, d)) <= 1

\* FI-18: every search at the head, over the buckets and all, answers each document's newest indexed
\* version, so no seal, merge, slot reuse or roll-up changes a result set, and no tombstoned or
\* masked version counts.
ResultsHold == ViewOf(IndexEnts) = Truth

\* A device keeping only the buckets shows no document at an older version than its newest (11.14's
\* newest row: every all row is older than each bucket entry of its key).
BucketsExact ==
    LET v == ViewOf(UNION {BucketEnts(b) : b \in Buckets}) IN
    \A d \in Docs : v[d] # 0 => v[d] = Truth[d]

\* Every current diff's chain resolves outside every head of its bucket (11.14's chains row), and no
\* merge or roll-up met a version it could not compose.
ChainsResolve ==
    /\ ~broken
    /\ \A d \in Docs :
           LET t == Top(IndexEnts, d) IN
           (t > 0 /\ ~TombAt(IndexEnts, d, t) /\ ~Masked(d, t)) =>
               \/ \E e \in Of(IndexEnts, d) : e.v = t /\ e.k = "full"
               \/ \E b \in Buckets \ gone :
                      \E e \in Of(BucketEnts(b), d) : e.v = t /\ e.k = "diff" /\ Resolves(b, d, e.base)

\* I-EVS-11: at most one version of a document in all and in each bucket's shards, and no tombstone
\* in all.
OneVersionEach ==
    /\ \A d \in Docs : Cardinality(Of(file[AllPath].ent, d)) <= 1
    /\ \A b \in Buckets : \A d \in Docs : Cardinality(Of(file[ShardPath(b)].ent, d)) <= 1
    /\ \A e \in file[AllPath].ent : e.k = "full"

\* I-EVS-12 and FI-20: the bucket is rolled into all by at most one committed roll-up, which committed
\* from the lock version its runner took.
RollsOnce == rollCommits <= 1 /\ ~fenceBad

\* I-EVS-17: no push but a CLOSURE commits at an index_epoch other than the head's.
EpochHolds == ~epochBad

\* FI-19 and I-EVS-13: after the CUT no index file version but a CLOSURE's holds d1, a CLOSURE only
\* where the version it replaced did; and once the erasure completes, every stored version that held
\* d1 shares a key an ERASE destroyed.
CutFences == ~leaked
ErasedUnreadable == complete => stored1 \subseteq destroyed

(***************************************************************************)
(* Weak fairness: the row's two liveness checks, in their own config.       *)
(***************************************************************************)

Fairness ==
    /\ \A r \in Rollers : WF_vars(rphase[r] # "crashed" /\ RollerStep(r))
    /\ WF_vars(LapseOfCrashed)
    /\ \A a \in Actors : WF_vars(ErasureStep(a))
    /\ WF_vars(Tick)

LiveSpec == Spec /\ Fairness

\* Every expired bucket rolls while a roller lives.
BucketRolls == (Now = 3 /\ BucketExists(1)) ~> (1 \in gone)

\* Every erasure whose CUT committed finishes while a finishing device lives.
ErasureFinishes == x.listed ~> complete

\* Safety only: TLC may miss a liveness failure under symmetry.
RollerSymmetry == Permutations(Rollers)

=============================================================================
