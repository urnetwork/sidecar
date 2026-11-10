----------------------------- MODULE PathEpoch -----------------------------
(***************************************************************************)
(* Client path epochs and re-tokenizing: DESIGN-DETAILS.md section 9.      *)
(*                                                                         *)
(* One ref of a name-bearing repo. Its paths are files under one directory *)
(* whose name table every client can read without a token (the root, as    *)
(* section 9.2.8 has it). evs holds, per path epoch, an entry for each     *)
(* path; the head names the current epoch and the source epochs that       *)
(* still hold entries. Writers create, change and remove paths; mappers    *)
(* build a map of the live paths into a newer generation's tokens and      *)
(* commit it as a PATH_EPOCH; the copy moves entries out of the sources    *)
(* and translates the table's rows; readers find paths through tokens      *)
(* they choose by the floor rule.                                          *)
(*                                                                         *)
(* What the model keeps of a token is the pair <<path, epoch>>: `seen` is  *)
(* every pair any request has shown evs. A removed key holder holds the    *)
(* path key of every epoch below a REMOVE generation, and every rotation   *)
(* here is one, so a pair <<x, e>> with a newer generation standing is one *)
(* a removed holder can test with the server's help.                       *)
(*                                                                         *)
(* Left out, each argued in 9.3: the 64-version window and the age of map  *)
(* parts, the creation block, parts and seals, git mode's lease, a read    *)
(* racing a single move between its GETs (FS-4 holds it on evs), nested    *)
(* directories (a prefix's floor is at most its child's), and time: a      *)
(* client's read of the head and the request it then sends are one step,   *)
(* which the implementation approximates within EpochFreshFor.             *)
(*                                                                         *)
(* Twin = "none" is the design. Each other value breaks one rule, and its  *)
(* configuration names the invariant that must then fail.                  *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Paths,       \* the names under the directory
    Clients,     \* devices that read and write
    Mappers,     \* devices that hold the ref's name index and map
    MaxEpoch,    \* generations 1..MaxEpoch; every rotation is REMOVE and immediate
    MaxVersion,  \* the ref's versions
    MaxSources,  \* 11.6: at most 3 sources stand
    Twin

ASSUME Twin \in {"none", "NoBetweenFence", "NoTailCheck", "BlindRetoken", "SendAllSources", "MapAllSources",
                 "MissIsAbsent", "StaleEpochSend", "NoNewNameRule", "RowsBeforeMoves", "RemoveCurrentRowOnly",
                 "FoldKeepsSources"}

Epochs == 1..MaxEpoch
Inf == MaxEpoch + 1
Devices == Clients \cup Mappers
NoEntry == [st |-> "none", v |-> 0]
Nil == [op |-> "nil", x |-> "-", base |-> 0, epoch |-> 0, src |-> {}, refused |-> FALSE]
Unknown == [st |-> "unknown", v |-> 0]
Idle == [st |-> "idle", pnew |-> 0, src |-> 0, moves |-> [x \in Paths |-> {}]]

Max(S) == CHOOSE m \in S : \A n \in S : n <= m
Min(S) == CHOOSE m \in S : \A n \in S : m <= n
MinOf(a, b) == IF a <= b THEN a ELSE b

VARIABLES
    gen,       \* the newest generation gkm holds
    ver,       \* the head's version
    cur,       \* the head's current path epoch
    srcs,      \* the head's listed sources
    hist,      \* hist[u]: version u's statement, as [kind, x, epoch]
    truth,     \* truth[x]: the path's newest committed change, as [st, v]: what a replaying reader holds
    idx,       \* idx[e][x]: the entry evs holds for x in epoch e
    row,       \* row[x]: the epoch whose token x's row in the directory's table carries, 0 for no row
    cmap,      \* cmap[x]: the committed map's and tail's source epochs for x, {} for no move
    rowsDone,  \* the copy translated the table's carried rows
    seen,      \* every <<path, epoch>> a request showed evs
    leak,      \* a token a removed holder can test reached evs for a name it could not test before
    wrong,     \* a reader took a conclusive answer that was not the path's newest
    lost,      \* a push committed on a view of its path that was not the path's newest
    kgen,      \* kgen[d]: the newest generation device d holds
    hcur,      \* hcur[d], hsrc[d]: the head's epoch state as d last read it
    hsrc,
    floor,     \* floor[d][x]: the lowest epoch d holds evidence evs was shown x's token in, Inf for none
    know,      \* know[d][x]: d's last conclusive read of x
    pend,      \* pend[d]: d's push in flight
    mp         \* mp[m]: mapper m's map

vars == <<gen, ver, cur, srcs, hist, truth, idx, row, cmap, rowsDone, seen, leak, wrong, lost,
          kgen, hcur, hsrc, floor, know, pend, mp>>
server == <<ver, cur, srcs, hist, truth, idx, row, cmap, rowsDone>>
flags == <<leak, wrong, lost>>

Init ==
    /\ gen = 1 /\ ver = 0 /\ cur = 1 /\ srcs = {}
    /\ hist = <<>>
    /\ truth = [x \in Paths |-> NoEntry]
    /\ idx = [e \in Epochs |-> [x \in Paths |-> NoEntry]]
    /\ row = [x \in Paths |-> 0]
    /\ cmap = [x \in Paths |-> {}]
    /\ rowsDone = TRUE
    /\ seen = {}
    /\ leak = FALSE /\ wrong = FALSE /\ lost = FALSE
    /\ kgen = [d \in Devices |-> 1]
    /\ hcur = [d \in Devices |-> 1]
    /\ hsrc = [d \in Devices |-> {}]
    /\ floor = [d \in Devices |-> [x \in Paths |-> Inf]]
    /\ know = [d \in Devices |-> [x \in Paths |-> Unknown]]
    /\ pend = [d \in Devices |-> Nil]
    /\ mp = [m \in Mappers |-> Idle]

\* 11.6's read rule on evs: the current entry, else the newest listed source's among those the request names.
ServerNewest(x, asked) ==
    IF idx[cur][x].st # "none" THEN idx[cur][x]
    ELSE LET held == {s \in asked \cap srcs : idx[s][x].st # "none"}
         IN IF held = {} THEN NoEntry ELSE idx[Max(held)][x]

\* What a view of a path says, against what stands.
SameAs(view, stands) ==
    /\ (view.st = "live") = (stands.st = "live")
    /\ view.st = "live" => view.v = stands.v

\* Sending x's token under each epoch of E: a leak when one of them is an epoch a removed holder holds the key of,
\* by the head or by what the sender knows, and evs was shown no token of x at or below it before.
Leaks(d, x, E) ==
    \E e \in E : /\ e < cur \/ e < kgen[d]
                 /\ ~(\E e2 \in 1..e : <<x, e2>> \in seen)

Shown(x, E) == {<<x, e>> : e \in E}

\* 9.2.3's floor rule: the current epoch as the device knows it, and each listed source at or above the floor.
AskedFor(d, x) ==
    {hcur[d]} \cup (IF Twin = "SendAllSources" THEN hsrc[d] ELSE {s \in hsrc[d] : s >= floor[d][x]})

\* A device may tokenize under an epoch only with that generation's key.
HoldsKey(d, e) == kgen[d] >= e

\* 9.2.3's rule for a name with no floor: its token goes only under the head's current epoch as just read, and
\* only while the device knows no generation past it.
MaySendNew(d) ==
    /\ Twin = "StaleEpochSend" \/ (hcur[d] = cur /\ hsrc[d] = srcs)
    /\ Twin = "NoNewNameRule" \/ kgen[d] = hcur[d]

----------------------------------------------------------------------------
\* Keys and heads.

Rotate ==
    /\ gen < MaxEpoch
    /\ gen' = gen + 1
    /\ UNCHANGED <<server, seen, flags, kgen, hcur, hsrc, floor, know, pend, mp>>

LearnGen(d) ==
    /\ kgen[d] < gen
    /\ kgen' = [kgen EXCEPT ![d] = gen]
    /\ UNCHANGED <<gen, server, seen, flags, hcur, hsrc, floor, know, pend, mp>>

ReadHead(d) ==
    /\ hcur[d] # cur \/ hsrc[d] # srcs
    /\ hcur' = [hcur EXCEPT ![d] = cur]
    /\ hsrc' = [hsrc EXCEPT ![d] = srcs]
    /\ UNCHANGED <<gen, server, seen, flags, kgen, floor, know, pend, mp>>

----------------------------------------------------------------------------
\* Reads.

\* The directory's listing, which needs no token: a row gives its path a floor, and no row is the path's absence.
Lookup(d, x) ==
    /\ pend[d].op = "nil"
    /\ hcur' = [hcur EXCEPT ![d] = cur]
    /\ hsrc' = [hsrc EXCEPT ![d] = srcs]
    /\ IF row[x] # 0
       THEN /\ floor' = [floor EXCEPT ![d][x] = MinOf(@, row[x])]
            /\ UNCHANGED <<know, wrong>>
       ELSE /\ know' = [know EXCEPT ![d][x] = [st |-> "absent", v |-> 0]]
            /\ wrong' = (wrong \/ truth[x].st = "live")
            /\ UNCHANGED floor
    /\ UNCHANGED <<gen, server, seen, leak, lost, kgen, pend, mp>>

\* A read of x by its tokens. A path with no floor is read this way only while no source stands; otherwise its
\* directory decides first (Lookup).
Read(d, x) ==
    LET asked == AskedFor(d, x)
        direct == floor[d][x] = Inf
    IN  /\ pend[d].op = "nil"
        /\ \A e \in asked : HoldsKey(d, e)
        /\ direct => /\ MaySendNew(d)
                     /\ Twin = "MissIsAbsent" \/ hsrc[d] = {}
        /\ seen' = seen \cup Shown(x, asked)
        /\ leak' = (leak \/ Leaks(d, x, asked))
        /\ IF hcur[d] # cur \/ hsrc[d] # srcs
           THEN \* the reply's head names another epoch state: the reader takes it and asks again
                /\ hcur' = [hcur EXCEPT ![d] = cur]
                /\ hsrc' = [hsrc EXCEPT ![d] = srcs]
                /\ UNCHANGED <<floor, know, wrong>>
           ELSE LET view == ServerNewest(x, asked)
                    conclusive == view.st # "none" \/ srcs \subseteq asked \/ Twin = "MissIsAbsent"
                IN  /\ UNCHANGED <<hcur, hsrc>>
                    /\ IF conclusive
                       THEN /\ know' = [know EXCEPT ![d][x] =
                                           IF view.st = "live" THEN [st |-> "live", v |-> view.v]
                                           ELSE [st |-> "absent", v |-> view.v]]
                            /\ wrong' = (wrong \/ ~SameAs(view, truth[x]))
                            \* the version's own statement names x's token in the epoch it committed in
                            /\ floor' = [floor EXCEPT ![d][x] =
                                            IF view.st = "none" THEN MinOf(@, hcur[d])
                                            ELSE MinOf(@, hist[view.v].epoch)]
                       ELSE /\ floor' = [floor EXCEPT ![d][x] = MinOf(@, hcur[d])]
                            /\ UNCHANGED <<know, wrong>>
        /\ UNCHANGED <<gen, server, lost, kgen, pend, mp>>

----------------------------------------------------------------------------
\* Writes.

\* A plan is made on a fresh head. A creation and a removal change the directory's table, so the planner reads its
\* listing: a creation needs no row there, and a removal takes its floor from the row it will drop (9.2.5).
Plan(d, op, x) ==
    LET f == IF op = "remove" /\ row[x] # 0 THEN MinOf(floor[d][x], row[x]) ELSE floor[d][x]
    IN  /\ pend[d].op = "nil"
        /\ ver < MaxVersion
        /\ hcur[d] = cur /\ hsrc[d] = srcs
        /\ HoldsKey(d, hcur[d])
        /\ \/ op = "create" /\ know[d][x].st = "absent" /\ row[x] = 0
           \/ op \in {"modify", "remove"} /\ know[d][x].st = "live"
        /\ floor' = [floor EXCEPT ![d][x] = f]
        /\ pend' = [pend EXCEPT ![d] = [op |-> op, x |-> x, base |-> know[d][x].v, epoch |-> hcur[d],
                                        src |-> {s \in hsrc[d] : s >= f}, refused |-> FALSE]]
        /\ UNCHANGED <<gen, server, seen, flags, kgen, hcur, hsrc, know, mp>>

\* The push reaches evs: its tokens are shown whatever the answer.
Push(d) ==
    LET p == pend[d]
        x == p.x
        shown == {p.epoch} \cup p.src
        view == ServerNewest(x, p.src)
        passes == IF p.op = "create" THEN view.st # "live" ELSE view.st = "live" /\ view.v = p.base
        u == ver + 1
    IN  /\ p.op # "nil" /\ ~p.refused
        /\ ver < MaxVersion
        /\ floor[d][x] = Inf => (MaySendNew(d) /\ (Twin = "StaleEpochSend" \/ p.epoch = hcur[d]))
        /\ seen' = seen \cup Shown(x, shown)
        /\ leak' = (leak \/ Leaks(d, x, shown))
        /\ floor' = [floor EXCEPT ![d][x] = MinOf(@, p.epoch)]
        /\ IF p.epoch # cur
           THEN \* 412 PATH_EPOCH: final, and nothing commits
                /\ pend' = [pend EXCEPT ![d].refused = TRUE]
                /\ UNCHANGED <<server, know, lost, wrong>>
           ELSE IF ~passes
           THEN \* 409: the path moved since the read
                /\ pend' = [pend EXCEPT ![d] = Nil]
                /\ know' = [know EXCEPT ![d][x] = Unknown]
                /\ UNCHANGED <<server, lost, wrong>>
           ELSE /\ ver' = u
                /\ hist' = Append(hist, [kind |-> p.op, x |-> x, epoch |-> cur])
                /\ truth' = [truth EXCEPT ![x] = [st |-> IF p.op = "remove" THEN "gone" ELSE "live", v |-> u]]
                \* the fold writes the current epoch's entry, carried from a source the push named or fresh, and
                \* then deletes the source copies the push named (9.2.6)
                /\ idx' = [e \in Epochs |-> [y \in Paths |->
                              IF y # x THEN idx[e][y]
                              ELSE IF e = cur THEN [st |-> IF p.op = "remove" THEN "gone" ELSE "live", v |-> u]
                              ELSE IF e \in p.src \cap srcs /\ Twin # "FoldKeepsSources" THEN NoEntry
                              ELSE idx[e][x]]]
                /\ row' = [row EXCEPT ![x] =
                              IF p.op = "create" THEN cur
                              ELSE IF p.op = "remove"
                                   THEN (IF @ = cur \/ (@ \in p.src /\ Twin # "RemoveCurrentRowOnly") THEN 0 ELSE @)
                                   ELSE @]
                /\ lost' = (lost \/ ~SameAs(view, truth[x]))
                /\ pend' = [pend EXCEPT ![d] = Nil]
                /\ know' = [know EXCEPT ![d][x] = [st |-> IF p.op = "remove" THEN "absent" ELSE "live", v |-> u]]
                /\ UNCHANGED <<cur, srcs, cmap, rowsDone, wrong>>
        /\ UNCHANGED <<gen, kgen, hcur, hsrc, mp>>

\* 9.2.5: a push refused 412 PATH_EPOCH is re-tokenized on a fresh head. The refused attempt showed evs the path's
\* token in its epoch, so that epoch is at or above the path's floor and the change names it as a source.
Retoken(d) ==
    LET p == pend[d]
        f == MinOf(floor[d][p.x], p.epoch)
    IN  /\ p.op # "nil" /\ p.refused
        /\ HoldsKey(d, cur)
        /\ hcur' = [hcur EXCEPT ![d] = cur]
        /\ hsrc' = [hsrc EXCEPT ![d] = srcs]
        /\ pend' = [pend EXCEPT ![d] = [p EXCEPT !.epoch = cur, !.refused = FALSE,
                                           !.src = IF Twin = "BlindRetoken" THEN {} ELSE {s \in srcs : s >= f}]]
        /\ UNCHANGED <<gen, server, seen, flags, kgen, floor, know, mp>>

\* A writer whose plan names an epoch the head has left may give the push up and read again.
Abandon(d) ==
    /\ pend[d].op # "nil"
    /\ pend[d].epoch # hcur[d]
    /\ pend' = [pend EXCEPT ![d] = Nil]
    /\ know' = [know EXCEPT ![d][pend[d].x] = Unknown]
    /\ UNCHANGED <<gen, server, seen, flags, kgen, hcur, hsrc, floor, mp>>

----------------------------------------------------------------------------
\* The mapper.

\* A mapper holds every live name of the source head, and for each an epoch in which evs was shown its token and
\* which is at most its row's (9.2.7). An index kept by replaying statements gives the epoch the path's standing
\* creation committed in; an index read from evs's listings gives the epoch of the row itself. A map names the
\* sources at or above it.
Born(x) ==
    LET made == {u \in 1..ver : hist[u].kind = "create" /\ hist[u].x = x}
    IN  IF made = {} THEN cur ELSE hist[Max(made)].epoch
RowEpoch(x) == IF row[x] = 0 \/ row[x] = cur THEN cur ELSE row[x]

MapBuild(m, byRow) ==
    /\ mp[m].st = "idle"
    /\ kgen[m] > cur
    /\ LET from(x) == IF byRow THEN RowEpoch(x) ELSE Born(x)
           moves == [x \in Paths |->
                        IF truth[x].st # "live" THEN {}
                        ELSE {cur} \cup (IF Twin = "MapAllSources" THEN srcs ELSE {s \in srcs : s >= from(x)})]
           live == {x \in Paths : truth[x].st = "live"}
           shown == UNION {Shown(x, moves[x] \cup {kgen[m]}) : x \in live}
       IN  /\ mp' = [mp EXCEPT ![m] = [st |-> "built", pnew |-> kgen[m], src |-> ver, moves |-> moves]]
           /\ seen' = seen \cup shown
           /\ leak' = (leak \/ \E x \in live : Leaks(m, x, moves[x]))
    /\ UNCHANGED <<gen, server, wrong, lost, kgen, hcur, hsrc, floor, know, pend>>

\* Paths the versions after u create.
CreatedAfter(u) == {hist[w].x : w \in {w2 \in (u + 1)..ver : hist[w2].kind = "create"}}

\* The PATH_EPOCH push. evs commits it only if its epoch is newer, a source slot is free, no PATH_EPOCH committed
\* after its map's source, and its tail covers every creation after that source.
MapCommit(m) ==
    LET q == mp[m]
        between == \E w \in (q.src + 1)..ver : hist[w].kind = "epoch"
        tail == IF Twin = "NoTailCheck" THEN {} ELSE CreatedAfter(q.src)
        ok == /\ q.pnew > cur
              /\ Cardinality(srcs) < MaxSources
              /\ Twin = "NoBetweenFence" \/ ~between
    IN  /\ q.st = "built"
        /\ ver < MaxVersion
        /\ seen' = seen \cup UNION {Shown(x, {q.pnew, cur}) : x \in tail}
        /\ mp' = [mp EXCEPT ![m] = Idle]
        /\ IF ok
           THEN /\ ver' = ver + 1
                /\ hist' = Append(hist, [kind |-> "epoch", x |-> "-", epoch |-> q.pnew])
                /\ srcs' = srcs \cup {cur}
                /\ cur' = q.pnew
                /\ cmap' = [x \in Paths |-> q.moves[x] \cup (IF x \in tail THEN {cur} ELSE {})]
                /\ rowsDone' = FALSE
                /\ UNCHANGED <<truth, idx, row>>
           ELSE UNCHANGED server
    /\ UNCHANGED <<gen, flags, kgen, hcur, hsrc, floor, know, pend>>

----------------------------------------------------------------------------
\* The copy, for the newest map and its tail.

Holding(x) == {s \in cmap[x] \cap srcs : idx[s][x].st # "none"}

\* A move is two writes, and the job may die or be superseded between them: the PUT of the current entry, carried
\* from the newest source holding the path, and then the DELETE of every source copy the move names. Where a
\* fold wrote the current entry first, only the DELETE is left (11.6's 412 rule).
CopyPut(x) ==
    /\ srcs # {}
    /\ Holding(x) # {}
    /\ idx[cur][x].st = "none"
    /\ Twin = "RowsBeforeMoves" \/ ~rowsDone
    /\ idx' = [idx EXCEPT ![cur][x] = idx[Max(Holding(x))][x]]
    /\ UNCHANGED <<gen, ver, cur, srcs, hist, truth, row, cmap, rowsDone, seen, flags, kgen, hcur, hsrc, floor, know, pend, mp>>

CopyDelete(x) ==
    /\ srcs # {}
    /\ Holding(x) # {}
    /\ idx[cur][x].st # "none"
    /\ idx' = [e \in Epochs |-> [y \in Paths |->
                  IF y = x /\ e \in cmap[x] \cap srcs THEN NoEntry ELSE idx[e][y]]]
    /\ UNCHANGED <<gen, ver, cur, srcs, hist, truth, row, cmap, rowsDone, seen, flags, kgen, hcur, hsrc, floor, know, pend, mp>>

\* The directory moves after its children: each carried row a move names in the row's own epoch becomes the
\* child's row in the current epoch.
CopyRows ==
    /\ srcs # {} /\ ~rowsDone
    /\ Twin = "RowsBeforeMoves" \/ \A x \in Paths : Holding(x) = {}
    /\ row' = [x \in Paths |-> IF row[x] \in srcs /\ row[x] \in cmap[x] THEN cur ELSE row[x]]
    /\ rowsDone' = TRUE
    /\ UNCHANGED <<gen, ver, cur, srcs, hist, truth, idx, cmap, seen, flags, kgen, hcur, hsrc, floor, know, pend, mp>>

\* The end: markers left in the sources are deleted unmoved, and one fence write drops the sources, only when no
\* other entry and no carried row is left there.
DropSources ==
    /\ srcs # {} /\ rowsDone
    /\ \A x \in Paths : Holding(x) = {}
    /\ \A s \in srcs, x \in Paths : idx[s][x].st # "live"
    /\ \A x \in Paths : row[x] \notin srcs
    /\ idx' = [e \in Epochs |-> [x \in Paths |-> IF e \in srcs THEN NoEntry ELSE idx[e][x]]]
    /\ srcs' = {}
    /\ UNCHANGED <<gen, ver, cur, hist, truth, row, cmap, rowsDone, seen, flags, kgen, hcur, hsrc, floor, know, pend, mp>>

----------------------------------------------------------------------------

Next ==
    \/ Rotate
    \/ \E d \in Devices : LearnGen(d) \/ ReadHead(d)
    \/ \E d \in Clients, x \in Paths : Lookup(d, x) \/ Read(d, x)
    \/ \E d \in Clients, x \in Paths, op \in {"create", "modify", "remove"} : Plan(d, op, x)
    \/ \E d \in Clients : Push(d) \/ Retoken(d) \/ Abandon(d)
    \/ \E m \in Mappers : MapCommit(m) \/ \E byRow \in BOOLEAN : MapBuild(m, byRow)
    \/ \E x \in Paths : CopyPut(x) \/ CopyDelete(x)
    \/ CopyRows
    \/ DropSources

Spec == Init /\ [][Next]_vars

\* Clients are alike and mappers are alike; the configurations that say so name them as model values.
Symmetry == Permutations(Clients) \cup Permutations(Mappers)

----------------------------------------------------------------------------
\* Invariants.

TypeOK ==
    /\ gen \in Epochs /\ cur \in Epochs /\ cur <= gen
    /\ ver \in 0..MaxVersion /\ Len(hist) = ver
    /\ srcs \subseteq Epochs /\ \A s \in srcs : s < cur
    /\ Cardinality(srcs) <= MaxSources
    /\ \A d \in Devices : kgen[d] <= gen /\ hcur[d] <= cur

\* No source-epoch token of a name created after a cut-over reaches evs, and no new name is tokenized under an
\* epoch its sender knows a removed holder's key for.
NoLateToken == ~leak

\* A conclusive read is the path's newest committed version, or its absence.
ReadsNewest == ~wrong

\* Path-level CAS holds across epochs: a push commits only on the path's newest version, so no creation lands on
\* a path that stands and no change on a stale base.
NoLostUpdate == ~lost

\* Every device's floor is backed by a token evs was shown.
FloorsBacked ==
    \A d \in Devices, x \in Paths :
        floor[d][x] # Inf => \E e \in 1..floor[d][x] : <<x, e>> \in seen

\* A live path's entry stands in the current epoch or a listed source, and nowhere else is anything left.
EntriesHome ==
    /\ \A x \in Paths : truth[x].st = "live" =>
           \E e \in {cur} \cup srcs : idx[e][x] = [st |-> "live", v |-> truth[x].v]
    /\ \A e \in Epochs, x \in Paths : e \notin ({cur} \cup srcs) => idx[e][x].st = "none"

\* A live path has a row; an untagged row's child is in the current epoch; a carried row's child is in a listed
\* epoch at or above the row's.
RowsLead ==
    \A x \in Paths : truth[x].st = "live" =>
        /\ row[x] # 0
        /\ row[x] = cur \/ row[x] \in srcs
        /\ \E e \in {cur} \cup srcs : e >= row[x] /\ idx[e][x] = [st |-> "live", v |-> truth[x].v]

\* The copy can finish: every entry left in a source is one the newest map or its tail names there.
NoneMissed ==
    \A s \in srcs, x \in Paths : idx[s][x].st = "live" => s \in cmap[x]

\* The table lists no path that does not stand.
NoGhostRows ==
    \A x \in Paths : row[x] # 0 => truth[x].st = "live"

\* Reachability witnesses: each must be violated, by a trace that reaches the state it denies.
NeverTwoCutOvers == ~(cur = MaxEpoch /\ srcs = {} /\ \E x \in Paths : truth[x].st = "live" /\ row[x] = cur)
NeverRetokened == \A d \in Clients : ~(pend[d].op # "nil" /\ pend[d].epoch > 1 /\ pend[d].src # {})
=============================================================================
