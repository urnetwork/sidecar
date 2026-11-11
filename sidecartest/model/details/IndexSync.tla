------------------------------- MODULE IndexSync -------------------------------
(* DESIGN-DETAILS.md section 7: the sync engine that keeps one device's copy of one ref's search index
   (7.2.7). evs holds the index as versionless files: per bucket a writer's head and the bucket's shards,
   and the all partition. Writers push entries, merges fold a head into its bucket's shards, a roll-up
   moves the expired bucket into all by section 1's step 4 (a carried version above a newer bucket's
   entry is promoted into that bucket; a carried tombstone takes all's row and is dropped) and removes
   the bucket's files. A replaced version of a file is collected: only the newest is served.

   The device holds a snapshot: the latest set (every bucket file) whole at one ref version, its pin, and
   perhaps all, whole at a pin of its own that is never ahead. It syncs toward a target version: files
   are fetched one at a time, staged, and swapped in only when every one the target lists is held. A
   bucket a roll-up removed is retained while the device's all is older than the roll-up, but only if the
   device's copy of it is the roll-up's input; otherwise all is not searched until it is fetched again.

   What is checked. LatestWhole: the latest set is exactly the files its pin lists. NoGhost: every
   document a search of the snapshot finds is live at the pin, at the version found. Complete: with all
   usable, every document live at the pin is found. AllBehind, Bridged, and under LiveSpec Converges:
   once evs is quiet the device reaches its head.

   Twin breaks one rule:
     MixedPin          a fetch that finds its file replaced takes the newest version and the swap takes
                       it with the other files of the older target (11.14's collected row requires the
                       head to be read again)
     SwapPartial       the manifest is replaced before every file of the new pin is held
     StaleAllSearched  a retained bucket is dropped (an ERASE, or two windows passing) and the stale all
                       it bridged is still searched (11.14's retained row as written, for a search of
                       the cache)
     RetainStale       a bucket is retained as a bridge though the device's copy of it is older than
                       the roll-up's input
     AllAhead          all is swapped in at a version the latest set has not reached

   Left out: slots apart from the head, large entries, diffs, the erasure set and its masks, format
   checks, and every byte. Section 1's IndexMerge.tla owns what a merge and a roll-up write; here they
   are the functions section 1 gives. *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Docs,       \* documents
    InAll,      \* the documents all holds at the start, each live at version 1
    MaxV,       \* pushes
    MaxDocV,    \* versions of a document
    KeepAll,    \* whether the device keeps all (a desktop, an indexer, a phone in a window)
    Twin

VARIABLES
    ver,        \* the ref's version
    cur,        \* the bucket a push's signed time names: 1, then 2
    exists,     \* which files the ref lists
    fv,         \* per file, the ref version that last wrote it
    con,        \* per file, its entries: document -> [v, k]
    truth,      \* per document, its newest committed version: [v, k]
    rolled,     \* the ref version of bucket 1's roll-up; 0 before it
    hist,       \* hist[v + 1]: what the ref listed and held at version v

    pin,        \* the version the device's latest set is whole at
    held,       \* per file, the copy in the device's snapshot
    target,     \* the version the device is syncing toward; NoTarget for none
    repin,      \* the target was taken by listing, past the catch-up budget: no statements were replayed
    staged,     \* per file, a copy fetched for the target and not yet in the snapshot
    hasAll,     \* the device holds all
    allPin,     \* the version its all is whole at
    allOk,      \* all may be searched
    ret,        \* bucket 1's files as retained after its roll-up
    evicted     \* all was evicted once

evs == <<ver, cur, exists, fv, con, truth, rolled, hist>>
dev == <<pin, held, target, repin, staged, hasAll, allPin, allOk, ret, evicted>>
vars == <<evs, dev>>

Files == {"h1", "s1", "h2", "s2", "a"}
Latest == {"h1", "s1", "h2", "s2"}
NoTarget == MaxV + 1
None == [v |-> 0, k |-> "none"]
Empty == [d \in Docs |-> None]
NoFile == [has |-> FALSE, fv |-> 0, c |-> Empty]
NoRet == [has |-> FALSE, h |-> Empty, s |-> Empty]

Newer(x, y) == IF x.v >= y.v THEN x ELSE y
At(v) == hist[v + 1]
Here == [exists |-> exists, fv |-> fv, con |-> con, truth |-> truth]

Init ==
    /\ ver = 0 /\ cur = 1 /\ rolled = 0
    /\ exists = [f \in Files |-> TRUE]
    /\ fv = [f \in Files |-> 0]
    /\ truth = [d \in Docs |-> IF d \in InAll THEN [v |-> 1, k |-> "live"] ELSE None]
    /\ con = [f \in Files |-> IF f = "a" THEN truth ELSE Empty]
    /\ hist = <<[exists |-> exists, fv |-> fv, con |-> con, truth |-> truth]>>
    /\ pin = 0 /\ target = NoTarget /\ repin = FALSE
    /\ held = [f \in Files |-> IF f \in Latest \/ KeepAll THEN [has |-> TRUE, fv |-> 0, c |-> con[f]] ELSE NoFile]
    /\ staged = [f \in Files |-> NoFile]
    /\ hasAll = KeepAll /\ allPin = 0 /\ allOk = KeepAll
    /\ ret = NoRet /\ evicted = FALSE

Commit(exists2, fv2, con2, truth2) ==
    /\ ver' = ver + 1
    /\ exists' = exists2 /\ fv' = fv2 /\ con' = con2 /\ truth' = truth2
    /\ hist' = Append(hist, [exists |-> exists2, fv |-> fv2, con |-> con2, truth |-> truth2])

(* A push with an entry of d: a new version, or its removal. Into the current bucket's head, or, by a
   writer whose clock still reads the old window, into bucket 1's while that bucket stands. *)
Write(d, k, b) ==
    /\ ver < MaxV /\ truth[d].v < MaxDocV
    /\ b <= cur /\ exists[IF b = 1 THEN "h1" ELSE "h2"]
    /\ k = "tomb" => truth[d].k = "live"
    /\ LET h == IF b = 1 THEN "h1" ELSE "h2"
           e == [v |-> truth[d].v + 1, k |-> k]
       IN  Commit(exists, [fv EXCEPT ![h] = ver + 1], [con EXCEPT ![h][d] = e], [truth EXCEPT ![d] = e])
    /\ UNCHANGED <<cur, rolled, dev>>

(* A merge of bucket b: the head's entries go into the shards, the newest of each document, and the
   writer's slot is free again. *)
Merge(b) ==
    LET h == IF b = 1 THEN "h1" ELSE "h2"
        s == IF b = 1 THEN "s1" ELSE "s2"
    IN  /\ ver < MaxV /\ exists[h] /\ con[h] # Empty
        /\ Commit(exists, [fv EXCEPT ![h] = ver + 1, ![s] = ver + 1],
                  [con EXCEPT ![h] = Empty, ![s] = [d \in Docs |-> Newer(con[h][d], con[s][d])]], truth)
        /\ UNCHANGED <<cur, rolled, dev>>

Expire == cur = 1 /\ cur' = 2 /\ UNCHANGED <<ver, exists, fv, con, truth, rolled, hist, dev>>

(* The roll-up of bucket 1 (section 1.2.5's step 4). *)
Rollup ==
    /\ ver < MaxV /\ cur = 2 /\ exists["h1"]
    /\ LET C(d) == Newer(con["h1"][d], con["s1"][d])
           N(d) == Newer(con["h2"][d], con["s2"][d])
           A(d) == con["a"][d]
           Promote(d) == C(d).k # "none" /\ N(d).k # "none" /\ N(d).v < C(d).v
           s2 == [d \in Docs |-> IF Promote(d) THEN C(d) ELSE con["s2"][d]]
           a == [d \in Docs |->
                   IF C(d).k = "none" THEN A(d)
                   ELSE IF Promote(d) THEN (IF C(d).k = "tomb" THEN None ELSE A(d))
                   ELSE IF C(d).k = "tomb" THEN (IF A(d).v < C(d).v THEN None ELSE A(d))
                   ELSE Newer(C(d), A(d))]
       IN  Commit([exists EXCEPT !["h1"] = FALSE, !["s1"] = FALSE],
                  [fv EXCEPT !["a"] = ver + 1, !["s2"] = IF s2 = con["s2"] THEN fv["s2"] ELSE ver + 1,
                             !["h1"] = ver + 1, !["s1"] = ver + 1],
                  [con EXCEPT !["h1"] = Empty, !["s1"] = Empty, !["s2"] = s2, !["a"] = a], truth)
    /\ rolled' = ver + 1
    /\ UNCHANGED <<cur, dev>>

------------------------------------------------------------------------------------------
(* The device. *)

Kept(f) == f \in Latest \/ KeepAll
Listed(f, t) == At(t).exists[f]
Has(f, t) == held[f].has /\ held[f].fv = At(t).fv[f]
Ready(f, t) ==
    \/ Has(f, t)
    \/ staged[f].has /\ staged[f].fv = At(t).fv[f]
    \/ Twin = "MixedPin" /\ staged[f].has /\ staged[f].fv >= At(t).fv[f]

(* Read the head: replay the statements since the pin, or past the catch-up budget list the directories.
   What was staged for an older target stays only where the new target lists the same version. *)
Retarget(t, listing) ==
    /\ t \in pin..ver
    /\ target = NoTarget \/ t > target
    /\ t > pin \/ (KeepAll /\ ~(hasAll /\ allPin = pin))
    /\ target' = t
    /\ repin' = (repin \/ listing)
    /\ staged' = [f \in Files |->
                    IF staged[f].has /\ Listed(f, t) /\ staged[f].fv = At(t).fv[f] THEN staged[f] ELSE NoFile]
    /\ UNCHANGED <<evs, pin, held, hasAll, allPin, allOk, ret, evicted>>

(* Fetch one whole file the target lists and the device keeps. evs serves only a file's newest version:
   one replaced since the target answers collected, and the device reads the head again (Retarget). *)
Fetch(f) ==
    /\ target # NoTarget /\ Kept(f) /\ Listed(f, target) /\ ~Ready(f, target)
    /\ \/ fv[f] = At(target).fv[f]
       \/ Twin = "MixedPin" /\ exists[f]
    /\ staged' = [staged EXCEPT ![f] = [has |-> TRUE, fv |-> fv[f], c |-> con[f]]]
    /\ UNCHANGED <<evs, pin, held, target, repin, hasAll, allPin, allOk, ret, evicted>>

Take(f, t) == IF Has(f, t) THEN held[f] ELSE IF staged[f].has THEN staged[f] ELSE held[f]

(* Swap the latest set: the manifest of the new pin replaces the old one once every file it lists is
   held. A bucket that left the listing is retained when the device's all is older than its roll-up and
   the device's copy is the roll-up's input, which it knows only from the statements it replayed. *)
SwapLatest ==
    /\ target # NoTarget /\ target > pin
    /\ Twin = "SwapPartial" \/ \A f \in Latest : Listed(f, target) => Ready(f, target)
    /\ LET t == target
           gone == held["h1"].has /\ ~Listed("h1", t)
           whole == /\ ~repin
                    /\ held["h1"].fv = At(rolled - 1).fv["h1"]
                    /\ held["s1"].fv = At(rolled - 1).fv["s1"]
           bridge == gone /\ hasAll
       IN  /\ held' = [f \in Files |-> IF f \notin Latest THEN held[f]
                                       ELSE IF Listed(f, t) THEN Take(f, t) ELSE NoFile]
           /\ ret' = IF bridge /\ (whole \/ Twin = "RetainStale")
                       THEN [has |-> TRUE, h |-> held["h1"].c, s |-> held["s1"].c] ELSE ret
           /\ allOk' = IF bridge /\ ~(whole \/ Twin = "RetainStale") THEN FALSE ELSE allOk
           /\ pin' = t
           /\ staged' = [f \in Files |-> IF f \in Latest THEN NoFile ELSE staged[f]]
           /\ target' = IF KeepAll THEN t ELSE NoTarget
    /\ repin' = FALSE
    /\ UNCHANGED <<evs, hasAll, allPin, evicted>>

(* Swap all: only at the latest set's pin. Then nothing is left to bridge. *)
SwapAll ==
    /\ KeepAll /\ target # NoTarget
    /\ target = pin \/ Twin = "AllAhead"
    /\ ~(hasAll /\ allPin = target)
    /\ Ready("a", target)
    /\ held' = [held EXCEPT !["a"] = Take("a", target)]
    /\ hasAll' = TRUE /\ allPin' = target /\ allOk' = TRUE
    /\ ret' = IF target >= pin THEN NoRet ELSE ret
    /\ staged' = [staged EXCEPT !["a"] = NoFile]
    /\ target' = IF target = pin THEN NoTarget ELSE target
    /\ UNCHANGED <<evs, pin, repin, evicted>>

(* An ERASE in the repo, or two windows passing: the retained bucket goes, and with it all's bridge. *)
DropRetained ==
    /\ ret.has
    /\ ret' = NoRet
    /\ allOk' = IF Twin = "StaleAllSearched" THEN allOk ELSE FALSE
    /\ UNCHANGED <<evs, pin, held, target, repin, staged, hasAll, allPin, evicted>>

(* The cache's bound evicts all, and a retained bucket has nothing left to bridge. *)
EvictAll ==
    /\ hasAll /\ ~evicted
    /\ hasAll' = FALSE /\ allOk' = FALSE /\ ret' = NoRet /\ evicted' = TRUE
    /\ held' = [held EXCEPT !["a"] = NoFile]
    /\ staged' = [staged EXCEPT !["a"] = NoFile]
    /\ UNCHANGED <<evs, pin, target, repin, allPin>>

Next ==
    \/ \E d \in Docs, k \in {"live", "tomb"}, b \in {1, 2} : Write(d, k, b)
    \/ \E b \in {1, 2} : Merge(b)
    \/ Expire
    \/ Rollup
    \/ \E t \in 0..MaxV, l \in BOOLEAN : Retarget(t, l)
    \/ \E f \in Files : Fetch(f)
    \/ SwapLatest
    \/ SwapAll
    \/ DropRetained
    \/ EvictAll

Spec == Init /\ [][Next]_vars

LiveSpec ==
    /\ Spec
    /\ WF_vars(Retarget(ver, FALSE))
    /\ \A f \in Files : WF_vars(Fetch(f))
    /\ WF_vars(SwapLatest) /\ WF_vars(SwapAll)

------------------------------------------------------------------------------------------
(* What a search of the snapshot sees: every bucket file, the retained bucket, and all while it may be
   searched. Per document the entry with the highest version is current, tombstones included. *)
Parts ==
    {held[f].c : f \in {g \in Latest : held[g].has}}
        \cup (IF ret.has THEN {ret.h, ret.s} ELSE {})
        \cup (IF hasAll /\ allOk THEN {held["a"].c} ELSE {})

Cur(d) ==
    LET es == {p[d] : p \in Parts} \cup {None}
    IN  CHOOSE e \in es : \A x \in es : e.v >= x.v

Found(d) == Cur(d).k = "live"
True(d) == At(pin).truth[d]

TypeOk ==
    /\ ver \in 0..MaxV /\ pin \in 0..ver /\ Len(hist) = ver + 1
    /\ target = NoTarget \/ target \in pin..ver

LatestWhole ==
    \A f \in Latest :
        /\ held[f].has = At(pin).exists[f]
        /\ held[f].has => held[f].fv = At(pin).fv[f] /\ held[f].c = At(pin).con[f]

NoGhost == \A d \in Docs : Found(d) => True(d).k = "live" /\ Cur(d).v = True(d).v

Complete == (hasAll /\ allOk) => \A d \in Docs : True(d).k = "live" => Found(d)

AllBehind ==
    hasAll => /\ allPin <= pin
              /\ held["a"].has /\ held["a"].fv = At(allPin).fv["a"] /\ held["a"].c = At(allPin).con["a"]

Bridged == (hasAll /\ allOk /\ rolled # 0 /\ allPin < rolled /\ rolled <= pin) => ret.has

Converges == <>[](pin = ver /\ (KeepAll => hasAll /\ allPin = ver /\ allOk))
==========================================================================================
