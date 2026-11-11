------------------------------- MODULE RemoteMerge -------------------------------
(* DESIGN-DETAILS.md section 7: the merge of one document's claims on the asking device (7.2.6). A claim
   is what one source says of one doc_key: the device itself, from its own index, or an indexer, in a
   page it sent on its own session for a repo it was asked. The merge shows one row a document. An
   indexer that served the document's repo from its text also gives a span, the times it has checked,
   and the device's own possible or near hit inside a span that the indexer did not return is folded
   into "not matched by <device>".

   Either indexer may say anything the wire allows: this module holds no step, and TLC checks every
   invariant over every combination of claims and spans, so each holds whatever an indexer sends.

   What is checked. Labelled: a row names an indexer only with that indexer's own claim. Present: a
   document any source claims has a row. MatchesStay: a document some source claims as verified or
   confirmed is shown as a match, whatever the others say, so the device's own confirmed hits stay and
   no indexer demotes another's verified hit. FoldBounded: a row is folded only when the device's own
   possible or near claim is the document's only claim and an indexer's span holds it.

   Twin breaks one rule:
     VersionFirst    the higher version wins whatever the states (11.14's merge row as written)
     FoldOverClaims  a span folds the document though another indexer claims it

   Left out: display fields, ranks between rows, the open check and what it voids (7.2.6). *)
EXTENDS Naturals, FiniteSets

CONSTANTS MaxVersion, Twin

VARIABLES
    own,    \* the device's claim: [v, st], st none | confirmed | possible | near
    c1, c2, \* each indexer's claim: st none | verified | confirmed | possible | near
    s1, s2, \* whether the device's claim lies inside that indexer's span
    first   \* whose page arrived first, for ties

vars == <<own, c1, c2, s1, s2, first>>

NoClaim == [v |-> 0, st |-> "none"]
OwnClaims == {NoClaim} \cup [v : 1..MaxVersion, st : {"confirmed", "possible", "near"}]
IdxClaims == {NoClaim} \cup [v : 1..MaxVersion, st : {"verified", "confirmed", "possible", "near"}]

Init ==
    /\ own \in OwnClaims /\ c1 \in IdxClaims /\ c2 \in IdxClaims
    /\ s1 \in BOOLEAN /\ s2 \in BOOLEAN /\ first \in {"d1", "d2"}

Spec == Init /\ [][UNCHANGED vars]_vars

(* A claim's class: a match, a possible match, a near hit. *)
Class(c) == CASE c.st \in {"verified", "confirmed"} -> 3 [] c.st = "possible" -> 2 [] c.st = "near" -> 1 [] OTHER -> 0
(* Within a class: the higher version; at one version verified over confirmed, an indexer's claim over
   the device's, and of two indexers the one whose page came first. *)
Strength(c) == IF c.st = "verified" THEN 1 ELSE 0
Source(by) == CASE by = "self" -> 0 [] by = first -> 2 [] OTHER -> 1

Claims == {x \in {[by |-> "self", c |-> own], [by |-> "d1", c |-> c1], [by |-> "d2", c |-> c2]} : x.c.st # "none"}

Key(x) ==
    IF Twin = "VersionFirst"
    THEN <<x.c.v, Strength(x.c), Source(x.by)>>
    ELSE <<Class(x.c), x.c.v, Strength(x.c), Source(x.by)>>

Before(a, b) ==   \* a's key is below b's, lexicographically
    LET n == IF Twin = "VersionFirst" THEN 3 ELSE 4
    IN  \E i \in 1..n : a[i] < b[i] /\ \A j \in 1..(i - 1) : a[j] = b[j]

Winner == CHOOSE x \in Claims : \A y \in Claims : y = x \/ Before(Key(y), Key(x))

Folded ==
    /\ own.st \in {"possible", "near"}
    /\ s1 \/ s2
    /\ IF Twin = "FoldOverClaims" THEN TRUE ELSE c1.st = "none" /\ c2.st = "none"
    /\ \A x \in Claims : Class(x.c) < 3

(* The row: none, folded under the indexer whose span holds it, or the winning claim. *)
Row ==
    IF Claims = {} THEN [st |-> "none", by |-> "self", v |-> 0]
    ELSE IF Folded THEN [st |-> "unmatched", by |-> IF s1 /\ (first = "d1" \/ ~s2) THEN "d1" ELSE "d2", v |-> own.v]
    ELSE [st |-> Winner.c.st, by |-> Winner.by, v |-> Winner.c.v]

------------------------------------------------------------------------------------------
Labelled ==
    Row.st \notin {"none", "unmatched"} =>
        /\ Row.by = "d1" => c1 = [v |-> Row.v, st |-> Row.st]
        /\ Row.by = "d2" => c2 = [v |-> Row.v, st |-> Row.st]
        /\ Row.by = "self" => own = [v |-> Row.v, st |-> Row.st]

Present == Claims # {} => Row.st # "none"

MatchesStay == (\E x \in Claims : Class(x.c) = 3) => Row.st \in {"verified", "confirmed"}

FoldBounded ==
    Row.st = "unmatched" =>
        /\ own.st \in {"possible", "near"} /\ c1.st = "none" /\ c2.st = "none"
        /\ (Row.by = "d1" => s1) /\ (Row.by = "d2" => s2)

(* An indexer's verified claim is the row unless another match claim is at its version or above. *)
VerifiedShown ==
    \A x \in Claims : x.c.st = "verified" /\ x.by # "self" =>
        \/ Row.by = x.by
        \/ \E y \in Claims : y # x /\ Class(y.c) = 3 /\ y.c.v >= x.c.v
==========================================================================================
