---------------------------- MODULE IndexErase ----------------------------
(***************************************************************************)
(* DESIGN-DETAILS.md section 15's model of an erasure on one index ref      *)
(* (§11.12, §11.14) under section 1's own bases: the CUT, the eraser's      *)
(* re-entry, its CLOSUREs and its end, beside the writers that keep         *)
(* pushing. Two specifications share the module, one a document.            *)
(*                                                                          *)
(* SpecPath: one path document d on an in-ref index. Writer w edits it;     *)
(* each edit's entry is full or, by 1.2.3's choose, a diff on a full entry  *)
(* in another file of w's that the erasure set does not list. w seals its   *)
(* head, a merge absorbs w's sealed slots into the bucket's shard, and w    *)
(* reuses an absorbed slot no unabsorbed diff rests on. The eraser reads    *)
(* d's version, and its CUT lists d up to the version it read, whatever     *)
(* landed since (IndexRollup.tla's CutVersion "read"). The design (15.2):   *)
(*   re-entry    a diff whose base version the set lists and whose own it   *)
(*               does not is a resting diff. For the highest version a      *)
(*               resting diff carries that no other entry a reader scans    *)
(*               holds at or above it, the eraser composes that version     *)
(*               from the diff and its base and enters it full in its own   *)
(*               head, before any CLOSURE                                   *)
(*   CLOSURE     rewrites a file without every listed entry and every       *)
(*               resting diff, since a resting diff and its version's set   *)
(*               give the erased base's set back                            *)
(*   readers     resolve a diff in one step from its writer's other files,  *)
(*               through a listed base while it stands; a diff whose base   *)
(*               is gone and listed is no candidate and alarms nothing      *)
(*   merges      compose a resting diff while its base stands, and leave    *)
(*               it out once the base is gone                               *)
(*                                                                          *)
(* SpecCard: one run card, a derived document of one stream. The stream     *)
(* takes entries, each a source of the card; a card is the fold of the      *)
(* stream's entries its builder can open. Devices w (the stream's writer),  *)
(* b (a backfiller) and x (the eraser) project it. The design (15.2):       *)
(*   version     (the index_epoch its push names, the stream version of     *)
(*               the run's newest entry), compared in that order            *)
(*   order       the eraser destroys the entry's body (ERASE) before its    *)
(*               CUT, and the CUT lists the card through the epoch it       *)
(*               names, so every version of that epoch or an older one      *)
(*   sync        a builder that reads an index_epoch it has not built at    *)
(*               brings the erasure ref to evs's head before it folds       *)
(*   block       a builder that cannot open an entry whose erasure has no   *)
(*               CUT yet builds no card                                     *)
(*   re-project  the eraser folds the card again after its CUT, in its own  *)
(*               head                                                       *)
(*                                                                          *)
(* What the model abstracts:                                                *)
(* - A version's text is its number, and a card's text is the set of        *)
(*   entries folded. Sizes, buckets, large entries, roll-ups, the journal   *)
(*   and coverage are IndexMerge.tla's and IndexRollup.tla's.               *)
(* - A file holds one entry of the document. w's sealed slots and absorbed  *)
(*   slots are sets of such files; a card's sealed and merged copies are    *)
(*   one set, since nothing here tells them apart.                          *)
(* - A push is built and committed in one step. The epoch guard refuses     *)
(*   every index push built before a CUT (I-EVS-17; IndexRollup.tla's       *)
(*   CutFences), so a push that commits was built at the epoch it names.    *)
(* - Whether an edit's delta is small enough for a diff is a choice.        *)
(* - Erasures run one after another on one eraser. The resume by another    *)
(*   device is the same steps from the same state, which every step here    *)
(*   reads from the files and the set alone.                                *)
(*                                                                          *)
(* Twin names a rule to break; a twin config sets it, and TLC must then     *)
(* refuse the model with the invariant that rule protects. "none" is the    *)
(* design.                                                                  *)
(*   NoReentry          the eraser enters nothing, and its CLOSUREs go on   *)
(*   ClosureFirst       a CLOSURE may precede the re-entry                  *)
(*   KeepResting        a CLOSURE leaves a resting diff in the file         *)
(*   MergeDropsResting  a merge leaves out a resting diff whose base stands *)
(*                      (evs_index_merge.go as landed)                      *)
(*   CutFirst           the CUT precedes the ERASE of the entry's body      *)
(*   NoSync             a builder folds at a new epoch without the erasure  *)
(*                      ref                                                 *)
(*   NoBlock            a builder that applied an ERASE with no CUT yet     *)
(*                      folds without the entry                             *)
(*   SeqVersion         a card's version is its stream version alone and    *)
(*                      the CUT lists it at the version its eraser read     *)
(*                      (RECORD.md 7.4 and §16.8 as written)                *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    MaxVer,         \* SpecPath: the versions d reaches
    MaxSeals,       \* seals of a head
    MaxMerges,      \* SpecPath: merges
    MaxReuses,      \* SpecPath: absorbed slots w takes again
    MaxEntries,     \* SpecCard: the entries the stream takes
    MaxErasures,    \* erasures, one after another
    Twin

VARIABLES
    \* SpecPath
    ver,            \* d's newest content version
    whead,          \* w's head: its entry of d, or None
    wsealed,        \* w's sealed slots that no merge has absorbed
    wabsorbed,      \* w's absorbed slots that it has not taken again
    shard,          \* the bucket's row of d, or None
    xhead,          \* the eraser's head: its entry of d, or None
    listed,         \* the erasure set lists d up to this version; 0 lists nothing
    readVer,        \* the version the eraser read
    phase,          \* idle, read, cut, closing
    erasures, seals, merges, reuses,
    \* SpecCard
    n,              \* the stream's entries, and its version
    body,           \* the entries whose body an ERASE destroyed
    applied,        \* per device, the ERASEs it has applied
    appliedEpoch,   \* per device, the epoch at which it last brought the erasure ref to evs's head
    epoch,          \* the index ref's index_epoch
    through,        \* the set lists the card at every version of an epoch at or below this
    listC,          \* Twin SeqVersion: the set lists the card up to this stream version
    readC,          \* the card's newest stream version when the eraser read it
    cutOf,          \* per entry, the epoch its erasure's CUT named; 0 before the CUT
    complete,       \* the entries whose erasure has ended
    chead,          \* per device, its head's entry of the card, or NoCard
    store,          \* the card's entries in sealed slots and shards
    cphase,         \* idle, read, erased, cutfirst, cut, closing
    target,         \* the entry the running erasure erases
    cerasures, cseals,
    stands          \* the eraser has folded the card again since its CUT

pvars == <<ver, whead, wsealed, wabsorbed, shard, xhead, listed, readVer, phase, erasures, seals, merges, reuses>>
cvars == <<n, body, applied, appliedEpoch, epoch, through, listC, readC, cutOf, complete, chead, store, cphase,
           target, cerasures, cseals, stands>>
vars == <<pvars, cvars>>

Max(S) == CHOOSE m \in S : \A o \in S : o <= m

----------------------------------------------------------------------------
\* SpecPath

None == [k |-> "none", v |-> 0, b |-> 0]
Full(v) == [k |-> "full", v |-> v, b |-> 0]
Diff(v, b) == [k |-> "diff", v |-> v, b |-> b]
Entries == {None} \cup {Full(v) : v \in 1..MaxVer} \cup {Diff(v, b) : v \in 1..MaxVer, b \in 1..MaxVer}

\* w's files that are not its head: where a base of w's sits (1.2.3).
Others == wsealed \cup wabsorbed
\* Every file of w's.
WFiles == ({whead} \cup wsealed \cup wabsorbed) \ {None}
\* What a reader scans: heads, unabsorbed slots and the shard (1.2.9).
Seen == ({whead, shard, xhead} \cup wsealed) \ {None}

\* A diff whose base version the set lists and whose own it does not.
IsResting(e) == e.k = "diff" /\ e.b <= listed /\ e.v > listed
Resting == {e \in WFiles : IsResting(e)}
\* A reader's one-step resolution.
Resolves(e) == e.k = "full" \/ Full(e.b) \in Others
\* The newest version a reader finds, 0 for none.
View == Max({e.v : e \in {s \in Seen : s.v > listed /\ Resolves(s)}} \cup {0})
\* The newest version indexed that the set does not list: every edit enters its version.
Want == IF ver > listed THEN ver ELSE 0

\* The version the eraser owes: the highest a resting diff carries, where no other entry a reader scans holds it
\* or a newer one.
Top == Max({e.v : e \in Resting})
Owed == Resting # {} /\ ~(\E e \in Seen : e.v >= Top /\ ~IsResting(e))
\* What a CLOSURE takes from a file: a listed entry, and a diff that rests on a listed version.
Stale(e) == e # None /\ (e.v <= listed \/ (e.k = "diff" /\ e.b <= listed))
Dirty(e) == e # None /\ (e.v <= listed \/ (Twin # "KeepResting" /\ e.k = "diff" /\ e.b <= listed))

PathInit ==
    /\ ver = 1 /\ whead = Full(1) /\ wsealed = {} /\ wabsorbed = {} /\ shard = None /\ xhead = None
    /\ listed = 0 /\ readVer = 0 /\ phase = "idle"
    /\ erasures = 0 /\ seals = 0 /\ merges = 0 /\ reuses = 0

\* w's push of the next version: choose's B leaves out the versions the set lists.
Edit ==
    /\ ver < MaxVer
    /\ LET v == ver + 1
           B == {e \in Others : e.k = "full" /\ e.v < v /\ e.v > listed}
       IN /\ ver' = v
          /\ \/ whead' = Full(v)
             \/ /\ B # {}
                /\ whead' = Diff(v, Max({e.v : e \in B}))
    /\ UNCHANGED <<wsealed, wabsorbed, shard, xhead, listed, readVer, phase, erasures, seals, merges, reuses>>

Seal ==
    /\ whead # None /\ seals < MaxSeals
    /\ wsealed' = wsealed \cup {whead} /\ whead' = None /\ seals' = seals + 1
    /\ UNCHANGED <<ver, wabsorbed, shard, xhead, listed, readVer, phase, erasures, merges, reuses>>

\* A merge absorbs w's sealed slots: the shard takes the newest version it can compose that the set does not list.
Merge ==
    /\ merges < MaxMerges /\ wsealed # {}
    /\ LET composes(e) == /\ e.v > listed
                          /\ \/ e.k = "full"
                             \/ /\ Full(e.b) \in Others
                                /\ Twin # "MergeDropsResting" \/ e.b > listed
           cands == {e.v : e \in {s \in wsealed : composes(s)}}
                        \cup (IF shard # None /\ shard.v > listed THEN {shard.v} ELSE {})
       IN shard' = IF cands = {} THEN None ELSE Full(Max(cands))
    /\ wabsorbed' = wabsorbed \cup wsealed /\ wsealed' = {} /\ merges' = merges + 1
    /\ UNCHANGED <<ver, whead, xhead, listed, readVer, phase, erasures, seals, reuses>>

\* w takes an absorbed slot again, which no diff of its unabsorbed slots rests on (1.2.3's keep set).
Reuse ==
    /\ reuses < MaxReuses
    /\ \E e \in wabsorbed :
        /\ ~(\E d \in ({whead} \cup wsealed) \ {None} : d.k = "diff" /\ e.k = "full" /\ d.b = e.v)
        /\ wabsorbed' = wabsorbed \ {e}
    /\ reuses' = reuses + 1
    /\ UNCHANGED <<ver, whead, wsealed, shard, xhead, listed, readVer, phase, erasures, seals, merges>>

Read ==
    /\ phase = "idle" /\ erasures < MaxErasures /\ ver > listed
    /\ readVer' = ver /\ phase' = "read"
    /\ UNCHANGED <<ver, whead, wsealed, wabsorbed, shard, xhead, listed, erasures, seals, merges, reuses>>

\* The CUT lists what its eraser read.
Cut ==
    /\ phase = "read"
    /\ listed' = readVer /\ phase' = "cut"
    /\ UNCHANGED <<ver, whead, wsealed, wabsorbed, shard, xhead, readVer, erasures, seals, merges, reuses>>

\* The eraser composes the version it owes from the diff and its base, and enters it full in its own head.
Reenter ==
    /\ phase \in {"cut", "closing"} /\ Twin # "NoReentry"
    /\ Owed
    /\ \E e \in Resting : e.v = Top /\ Full(e.b) \in Others
    /\ xhead' = Full(Top)
    /\ UNCHANGED <<ver, whead, wsealed, wabsorbed, shard, listed, readVer, phase, erasures, seals, merges, reuses>>

\* One CLOSURE: one file without what it takes.
Closure ==
    /\ phase \in {"cut", "closing"}
    /\ Twin \in {"NoReentry", "ClosureFirst"} \/ ~Owed
    /\ \/ /\ Dirty(whead) /\ whead' = None /\ UNCHANGED <<wsealed, wabsorbed, shard, xhead>>
       \/ /\ \E e \in wsealed : Dirty(e) /\ wsealed' = wsealed \ {e}
          /\ UNCHANGED <<whead, wabsorbed, shard, xhead>>
       \/ /\ \E e \in wabsorbed : Dirty(e) /\ wabsorbed' = wabsorbed \ {e}
          /\ UNCHANGED <<whead, wsealed, shard, xhead>>
       \/ /\ Dirty(shard) /\ shard' = None /\ UNCHANGED <<whead, wsealed, wabsorbed, xhead>>
       \/ /\ Dirty(xhead) /\ xhead' = None /\ UNCHANGED <<whead, wsealed, wabsorbed, shard>>
    /\ phase' = "closing"
    /\ UNCHANGED <<ver, listed, readVer, erasures, seals, merges, reuses>>

\* The erasure ends when no file holds what a CLOSURE takes.
Finish ==
    /\ phase \in {"cut", "closing"}
    /\ Twin \in {"NoReentry", "ClosureFirst"} \/ ~Owed
    /\ \A e \in WFiles \cup {shard, xhead} : ~Dirty(e)
    /\ phase' = "idle" /\ erasures' = erasures + 1
    /\ UNCHANGED <<ver, whead, wsealed, wabsorbed, shard, xhead, listed, readVer, seals, merges, reuses>>

PathNext == Edit \/ Seal \/ Merge \/ Reuse \/ Read \/ Cut \/ Reenter \/ Closure \/ Finish

----------------------------------------------------------------------------
\* SpecCard

Devices == {"w", "b", "x"}
NoCard == [e |-> 0, c |-> 0, f |-> {}]
Cards == {NoCard} \cup [e : 1..(MaxErasures + 1), c : 1..MaxEntries, f : (SUBSET (1..MaxEntries)) \ {{}}]

\* Every stored entry of the card.
Index == ({chead[d] : d \in Devices} \cup store) \ {NoCard}
\* Whether the set lists an entry of the card.
Listed(en) == IF Twin = "SeqVersion" THEN en.c <= listC ELSE en.e <= through

CardInit ==
    /\ n = 0 /\ body = {} /\ applied = [d \in Devices |-> {}] /\ appliedEpoch = [d \in Devices |-> 1]
    /\ epoch = 1 /\ through = 0 /\ listC = 0 /\ readC = 0 /\ cutOf = [t \in 1..MaxEntries |-> 0]
    /\ complete = {} /\ chead = [d \in Devices |-> NoCard] /\ store = {} /\ cphase = "idle" /\ target = 0
    /\ cerasures = 0 /\ cseals = 0 /\ stands = FALSE

Append ==
    /\ n < MaxEntries
    /\ n' = n + 1
    /\ UNCHANGED <<body, applied, appliedEpoch, epoch, through, listC, readC, cutOf, complete, chead, store, cphase,
                   target, cerasures, cseals, stands>>

\* A device applies the erasure ref as it stands, on a hint or a sync.
Sync(d) ==
    /\ applied[d] # body
    /\ applied' = [applied EXCEPT ![d] = body]
    /\ UNCHANGED <<n, body, appliedEpoch, epoch, through, listC, readC, cutOf, complete, chead, store, cphase, target,
                   cerasures, cseals, stands>>

\* w's companion push or b's backfill carrying the card, at the epoch it read.
Project(d) ==
    /\ d \in {"w", "b"} /\ n >= 1
    /\ LET sync == appliedEpoch[d] # epoch /\ Twin # "NoSync"
           ap == IF sync THEN body ELSE applied[d]
           fold == (1..n) \ ap
           blocked == \E t \in ap : cutOf[t] = 0
       IN /\ Twin = "NoBlock" \/ ~blocked
          /\ fold # {}
          /\ chead' = [chead EXCEPT ![d] = [e |-> epoch, c |-> n, f |-> fold]]
          /\ applied' = [applied EXCEPT ![d] = ap]
          /\ appliedEpoch' = [appliedEpoch EXCEPT ![d] = IF sync THEN epoch ELSE @]
    /\ UNCHANGED <<n, body, epoch, through, listC, readC, cutOf, complete, store, cphase, target, cerasures, cseals,
                   stands>>

\* A head's entry passes into a sealed slot, and from there a shard.
SealCard(d) ==
    /\ chead[d] # NoCard /\ cseals < MaxSeals
    /\ store' = store \cup {chead[d]} /\ chead' = [chead EXCEPT ![d] = NoCard] /\ cseals' = cseals + 1
    /\ UNCHANGED <<n, body, applied, appliedEpoch, epoch, through, listC, readC, cutOf, complete, cphase, target,
                   cerasures, stands>>

CRead ==
    /\ cphase = "idle" /\ cerasures < MaxErasures
    /\ \E t \in (1..n) \ body : target' = t
    /\ readC' = Max({en.c : en \in Index} \cup {0})
    /\ cphase' = "read"
    /\ UNCHANGED <<n, body, applied, appliedEpoch, epoch, through, listC, cutOf, complete, chead, store, cerasures,
                   cseals, stands>>

\* The ERASE of the entry's body.
CErase ==
    /\ cphase = (IF Twin = "CutFirst" THEN "cutfirst" ELSE "read")
    /\ body' = body \cup {target}
    /\ applied' = [applied EXCEPT !["x"] = @ \cup {target}]
    /\ cphase' = (IF Twin = "CutFirst" THEN "cut" ELSE "erased")
    /\ UNCHANGED <<n, appliedEpoch, epoch, through, listC, readC, cutOf, complete, chead, store, target, cerasures,
                   cseals, stands>>

\* The CUT names the head's epoch, lists the card through it and moves the epoch.
CCut ==
    /\ cphase = (IF Twin = "CutFirst" THEN "read" ELSE "erased")
    /\ cutOf' = [cutOf EXCEPT ![target] = epoch]
    /\ through' = epoch /\ epoch' = epoch + 1 /\ listC' = readC /\ stands' = FALSE
    /\ cphase' = (IF Twin = "CutFirst" THEN "cutfirst" ELSE "cut")
    /\ UNCHANGED <<n, body, applied, appliedEpoch, readC, complete, chead, store, target, cerasures, cseals>>

\* The eraser folds the card again, in its own head.
CReproject ==
    /\ cphase \in {"cut", "closing"} /\ ~stands
    /\ (1..n) \ body # {}
    /\ chead' = [chead EXCEPT !["x"] = [e |-> epoch, c |-> n, f |-> (1..n) \ body]]
    /\ applied' = [applied EXCEPT !["x"] = body]
    /\ appliedEpoch' = [appliedEpoch EXCEPT !["x"] = epoch]
    /\ stands' = TRUE
    /\ UNCHANGED <<n, body, epoch, through, listC, readC, cutOf, complete, store, cphase, target, cerasures, cseals>>

\* One CLOSURE: one file without the card's listed entry.
CClosure ==
    /\ cphase \in {"cut", "closing"}
    /\ \/ \E en \in store : Listed(en) /\ store' = store \ {en} /\ chead' = chead
       \/ \E d \in Devices : /\ chead[d] # NoCard /\ Listed(chead[d])
                             /\ chead' = [chead EXCEPT ![d] = NoCard] /\ store' = store
    /\ cphase' = "closing"
    /\ UNCHANGED <<n, body, applied, appliedEpoch, epoch, through, listC, readC, cutOf, complete, target, cerasures,
                   cseals, stands>>

CFinish ==
    /\ cphase \in {"cut", "closing"}
    /\ \A en \in Index : ~Listed(en)
    /\ stands \/ (1..n) \ body = {}
    /\ complete' = complete \cup {target} /\ cphase' = "idle" /\ cerasures' = cerasures + 1
    /\ UNCHANGED <<n, body, applied, appliedEpoch, epoch, through, listC, readC, cutOf, chead, store, target, cseals,
                   stands>>

CardNext ==
    \/ Append \/ CRead \/ CErase \/ CCut \/ CReproject \/ CClosure \/ CFinish
    \/ \E d \in Devices : Sync(d) \/ Project(d) \/ SealCard(d)

----------------------------------------------------------------------------

Init == PathInit /\ CardInit
SpecPath == Init /\ [][PathNext /\ UNCHANGED cvars]_vars
SpecCard == Init /\ [][CardNext /\ UNCHANGED pvars]_vars

----------------------------------------------------------------------------
\* Invariants of SpecPath

PathTypeOk ==
    /\ ver \in 1..MaxVer /\ whead \in Entries /\ wsealed \subseteq Entries /\ wabsorbed \subseteq Entries
    /\ shard \in Entries /\ xhead \in Entries /\ listed \in 0..MaxVer /\ readVer \in 0..MaxVer
    /\ phase \in {"idle", "read", "cut", "closing"}
    /\ shard.k # "diff" /\ xhead.k # "diff"

\* I1 as section 15 words it: every diff in an unabsorbed slot whose base version the set does not list has its
\* base in another file of its writer. Where it holds, no honest writer's diff reads index_malformed.
OwnBases ==
    \A e \in ({whead} \cup wsealed) \ {None} : (e.k = "diff" /\ e.b > listed) => Full(e.b) \in Others

\* I9: the newest version indexed that the set does not list is the one a reader finds (FI-18).
Searchable == View = Want

\* I10: once an erasure ends, no file holds a listed entry or a diff resting on a listed version (FI-19).
ErasedGone == phase = "idle" => \A e \in WFiles \cup {shard, xhead} : ~Stale(e)

\* What the eraser owes it can compose: the base of the diff still stands.
Composable ==
    (phase \in {"cut", "closing"} /\ Owed) => \E e \in Resting : e.v = Top /\ Full(e.b) \in Others

\* I1 as section 1 had it, and §11.14's chains row: every diff in an unabsorbed slot, of a version the set does
\* not list, has its base.
ChainsResolveLanded ==
    \A e \in ({whead} \cup wsealed) \ {None} : (e.k = "diff" /\ e.v > listed) => Full(e.b) \in Others

\* Reach: states the design must be able to reach, each stated as an invariant that says it never does.
NeverOwed == ~(phase = "cut" /\ Owed)
NeverReentered == xhead = None
NeverExcused == ~(\E e \in ({whead} \cup wsealed) \ {None} : IsResting(e) /\ Full(e.b) \notin Others)
NeverComposedThrough ==
    ~(phase \in {"cut", "closing"} /\ shard # None /\ shard.v > listed /\ xhead = None
      /\ \E e \in wabsorbed : IsResting(e) /\ e.v = shard.v)

----------------------------------------------------------------------------
\* Invariants of SpecCard

CardTypeOk ==
    /\ n \in 0..MaxEntries /\ body \subseteq 1..n
    /\ \A d \in Devices : applied[d] \subseteq body /\ appliedEpoch[d] \in 1..epoch /\ chead[d] \in Cards
    /\ epoch \in 1..(MaxErasures + 1) /\ through \in 0..MaxErasures /\ store \subseteq Cards
    /\ cphase \in {"idle", "read", "erased", "cutfirst", "cut", "closing"}
    /\ complete \subseteq body

\* I11: an entry of the card that folds an entry an erasure erased was written at the epoch that erasure's CUT
\* named or an older one, so the CUT lists it.
Fence ==
    \A en \in Index : \A t \in en.f :
        cutOf[t] # 0 => (IF Twin = "SeqVersion" THEN Listed(en) ELSE en.e <= cutOf[t])

\* I10 for a card: once an erasure ends, no stored entry of the card folds the entry it erased.
CardGone == \A t \in complete : \A en \in Index : t \notin en.f

\* I12: copies of one version are equal.
CopiesEqual == \A a \in Index : \A o \in Index : (a.e = o.e /\ a.c = o.c) => a.f = o.f

\* I13: once the eraser has folded the card again, an entry of it the set does not list stands, with no entry an
\* erasure with a CUT erased.
CardStands == stands => \E en \in Index : ~Listed(en) /\ \A t \in en.f : cutOf[t] = 0

\* Reach
NeverRaced == ~(\E en \in Index : cphase = "cut" /\ en.c > readC /\ target \in en.f)
NeverBlocked ==
    ~(\E d \in {"w", "b"} : n >= 1 /\ appliedEpoch[d] = epoch /\ \E t \in applied[d] : cutOf[t] = 0)
NeverReturns == ~(cerasures = MaxErasures /\ cphase = "idle" /\ stands)
NeverTwice == ~(cerasures = 2 /\ stands /\ \E en \in Index : en.e = 3)

=============================================================================
