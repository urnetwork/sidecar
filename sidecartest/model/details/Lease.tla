------------------------------- MODULE Lease -------------------------------
(* DESIGN-DETAILS.md section 13.2.2: edge leases on one transfer balance. Postgres holds the balance and the
   debit journal; Redis holds the balance's reservation tokens, a lease's own and the carved ones, and the
   credit floor; each host holds its lease in memory. Bytes are units.

   A host reads the balance's credit and keeps the reading. It reserves against the lower of its reading and
   the floor, less what the tokens hold. It spends what it reserved with no I/O. At a window's end it plans a
   batch of what it spent, carves those bytes out of its lease token into a token named for the batch, and
   only then posts the batch, which api journals once by its id. The flush commits the debit and then, in one
   Redis step, releases the carved token and lowers the floor to the balance it left. A host may crash at any
   step, a post's answer may be lost, an old carve may arrive again long after it ran, and a live host's
   token may reach its expiry, after which the host draws under a new token.

   What is checked: the balance never goes below what is journaled against it (NoOverdraw), no host is billed
   more than it spent (BilledOnce), and what a host may still spend is held by its token (Backed).

   Twin selects one rule to break:
     NoFloor          a reservation trusts the host's own reading of the credit
     FloorExpires     the floor is forgotten while a host still holds an older reading
     ReleaseFirst     the flush releases the carved token before its debit commits
     BlindCarve       a carve moves bytes whatever its lease token holds, so one that arrives again moves twice
     SpendPastExpiry  a host keeps spending what a token held after the token lapsed
     Replan           a batch whose post went unanswered is planned again under a new id

   Left out: more than one balance and more than one live token a lease (the draw order and the attribution
   of spent bytes to tokens are section 13.2.2's own argument), evs's debit after use, relayed reservations
   and the contract paths, which share the tokens and the floor rule. *)
EXTENDS Integers, FiniteSets

CONSTANTS
    Hosts,
    Credit,     \* the balance at the start
    Draw,       \* the most one reservation takes
    MaxInc,     \* lease tokens per host: every reservation, restart and expiry takes the next
    MaxSeq,     \* batches per process
    Twin

VARIABLES
    bal,        \* transfer_balance.balance_byte_count
    rows,       \* service_debit_journal
    seenIds,    \* service_usage_batch: batch ids applied
    leaseTok,   \* Redis: each lease token on the balance, by host and token number
    svcTok,     \* Redis: carved tokens, by batch id
    floor,      \* Redis: the lowest credit shown
    up, inc, fresh, cred, avail, view, spentU, batches, seq,
    oldCarves,  \* every carve that ran, which the network may deliver again
    spent, billed

vars == <<bal, rows, seenIds, leaseTok, svcTok, floor, up, inc, fresh, cred, avail, view, spentU, batches, seq,
          oldCarves, spent, billed>>

None == -1
NoFloor == Credit + Draw + 1
Min(a, b) == IF a < b THEN a ELSE b
Max(a, b) == IF a > b THEN a ELSE b
Incs == 1..MaxInc

RECURSIVE SumAmt(_)
SumAmt(S) == IF S = {} THEN 0 ELSE LET x == CHOOSE y \in S : TRUE IN x.amt + SumAmt(S \ {x})

RECURSIVE SumTok(_)
SumTok(D) == IF D = {} THEN 0 ELSE LET x == CHOOSE y \in D : TRUE IN leaseTok[x] + SumTok(D \ {x})

Total == SumTok(Hosts \X Incs) + SumAmt(svcTok)
Pending == SumAmt({r \in rows : ~r.applied})
Me(h) == <<h, inc[h]>>

(* Postgres's balance now, which is what a reading holds from then on. *)
Read(h) ==
    /\ up[h]
    /\ cred' = [cred EXCEPT ![h] = Max(bal, 0)]
    /\ UNCHANGED <<bal, rows, seenIds, leaseTok, svcTok, floor, up, inc, fresh, avail, view, spentU, batches, seq,
                   oldCarves, spent, billed>>

(* One script on the balance: what is free is the lower of the reading and the floor, less every token. Each
   reservation is a token of its own, so no token ever grows. Here a host draws again only once its last
   token is used up. *)
Reserve(h) ==
    /\ up[h] /\ cred[h] # None
    /\ avail[h] = 0 /\ view[h] = 0 /\ spentU[h] = 0
    /\ ~\E b \in batches[h] : ~b.carved /\ b.id[2] = inc[h]
    /\ LET g == IF fresh[h] THEN inc[h] ELSE inc[h] + 1
           eff == IF Twin = "NoFloor" THEN cred[h] ELSE Min(cred[h], floor)
           amount == Min(Draw, eff - Total)
       IN  /\ g <= MaxInc /\ amount > 0
           /\ leaseTok' = [leaseTok EXCEPT ![<<h, g>>] = amount]
           /\ inc' = [inc EXCEPT ![h] = g]
           /\ avail' = [avail EXCEPT ![h] = amount]
           /\ view' = [view EXCEPT ![h] = amount]
    /\ fresh' = [fresh EXCEPT ![h] = FALSE]
    /\ floor' = IF Twin = "NoFloor" THEN floor ELSE Min(floor, cred[h])
    /\ UNCHANGED <<bal, rows, seenIds, svcTok, up, cred, spentU, batches, seq, oldCarves, spent, billed>>

Spend(h) ==
    /\ up[h] /\ avail[h] > 0 /\ spent[h] <= Credit
    /\ avail' = [avail EXCEPT ![h] = @ - 1]
    /\ spentU' = [spentU EXCEPT ![h] = @ + 1]
    /\ spent' = [spent EXCEPT ![h] = @ + 1]
    /\ UNCHANGED <<bal, rows, seenIds, leaseTok, svcTok, floor, up, inc, fresh, cred, view, batches, seq, oldCarves, billed>>

(* A window ends: what the lease spent since the last becomes one batch, under an id it keeps. *)
Plan(h) ==
    /\ up[h] /\ spentU[h] > 0 /\ seq[h] < MaxSeq
    /\ batches' = [batches EXCEPT ![h] = @ \cup {[id |-> <<h, inc[h], seq[h]>>, amt |-> spentU[h],
                                                  carved |-> FALSE, sent |-> FALSE]}]
    /\ spentU' = [spentU EXCEPT ![h] = 0]
    /\ seq' = [seq EXCEPT ![h] = @ + 1]
    /\ UNCHANGED <<bal, rows, seenIds, leaseTok, svcTok, floor, up, inc, fresh, cred, avail, view, oldCarves, spent, billed>>

(* The carve as Redis runs it: nothing when the batch's token exists; else the bytes move only while the
   lease token holds exactly what the host names. *)
CarveRuns(c) ==
    IF \E t \in svcTok : t.id = c.id THEN FALSE
    ELSE IF Twin = "BlindCarve" THEN TRUE
    ELSE leaseTok[c.tok] = c.expect /\ c.expect >= c.amt

Carve(h, b) ==
    /\ up[h] /\ b \in batches[h] /\ ~b.carved
    /\ LET c == [id |-> b.id, amt |-> b.amt, tok |-> <<h, b.id[2]>>, expect |-> view[h]] IN
       IF b.id[2] # inc[h]
         THEN \* its bytes were spent under a lease token the host knows is gone: they are not billed
              /\ batches' = [batches EXCEPT ![h] = @ \ {b}]
              /\ UNCHANGED <<leaseTok, svcTok, view, oldCarves>>
       ELSE IF \E t \in svcTok : t.id = b.id
         THEN \* an earlier try ran: nothing moves, and the host learns it
              /\ batches' = [batches EXCEPT ![h] = (@ \ {b}) \cup {[b EXCEPT !.carved = TRUE]}]
              /\ UNCHANGED <<leaseTok, svcTok, view, oldCarves>>
         ELSE IF CarveRuns(c)
           THEN /\ leaseTok' = [leaseTok EXCEPT ![Me(h)] = Max(@ - b.amt, 0)]
                /\ svcTok' = svcTok \cup {[id |-> b.id, amt |-> b.amt]}
                /\ view' = [view EXCEPT ![h] = Max(@ - b.amt, 0)]
                /\ batches' = [batches EXCEPT ![h] = (@ \ {b}) \cup {[b EXCEPT !.carved = TRUE]}]
                /\ oldCarves' = oldCarves \cup {c}
           ELSE \* the lease token no longer holds the bytes: they are not billed
                /\ batches' = [batches EXCEPT ![h] = @ \ {b}]
                /\ UNCHANGED <<leaseTok, svcTok, view, oldCarves>>
    /\ UNCHANGED <<bal, rows, seenIds, floor, up, inc, fresh, cred, avail, spentU, seq, spent, billed>>

(* A carve that already ran reaches Redis again, at any later time. *)
LateCarve(c) ==
    /\ c \in oldCarves
    /\ CarveRuns(c)
    /\ leaseTok' = [leaseTok EXCEPT ![c.tok] = Max(@ - c.amt, 0)]
    /\ svcTok' = svcTok \cup {[id |-> c.id, amt |-> c.amt]}
    /\ UNCHANGED <<bal, rows, seenIds, floor, up, inc, fresh, cred, avail, view, spentU, batches, seq, oldCarves, spent, billed>>

(* api applies a batch once by its id. answered is whether the host hears of it. *)
Post(h, b, answered) ==
    /\ up[h] /\ b \in batches[h] /\ b.carved
    /\ LET again == Twin = "Replan" /\ b.sent /\ seq[h] < MaxSeq
           id == IF again THEN <<h, inc[h], seq[h]>> ELSE b.id
       IN  /\ IF id \in seenIds
                THEN UNCHANGED <<rows, seenIds, billed>>
                ELSE /\ rows' = rows \cup {[id |-> id, amt |-> b.amt, applied |-> FALSE, released |-> FALSE]}
                     /\ seenIds' = seenIds \cup {id}
                     /\ billed' = [billed EXCEPT ![h] = @ + b.amt]
           /\ seq' = IF again THEN [seq EXCEPT ![h] = @ + 1] ELSE seq
    /\ batches' = [batches EXCEPT ![h] = IF answered THEN @ \ {b} ELSE (@ \ {b}) \cup {[b EXCEPT !.sent = TRUE]}]
    /\ UNCHANGED <<bal, leaseTok, svcTok, floor, up, inc, fresh, cred, avail, view, spentU, oldCarves, spent>>

(* The host stops retrying a batch. Its carved token stays for the flush, or lapses. *)
Drop(h, b) ==
    /\ up[h] /\ b \in batches[h]
    /\ batches' = [batches EXCEPT ![h] = @ \ {b}]
    /\ UNCHANGED <<bal, rows, seenIds, leaseTok, svcTok, floor, up, inc, fresh, cred, avail, view, spentU, seq,
                   oldCarves, spent, billed>>

(* The flush: the debit commits, then one script releases the row's token and lowers the floor. *)
Commit(r) ==
    /\ r \in rows /\ ~r.applied
    /\ (Twin = "ReleaseFirst" => r.released)
    /\ bal' = bal - r.amt
    /\ rows' = IF Twin = "ReleaseFirst" THEN rows \ {r} ELSE (rows \ {r}) \cup {[r EXCEPT !.applied = TRUE]}
    /\ UNCHANGED <<seenIds, leaseTok, svcTok, floor, up, inc, fresh, cred, avail, view, spentU, batches, seq,
                   oldCarves, spent, billed>>

Release(r) ==
    /\ r \in rows
    /\ IF Twin = "ReleaseFirst"
         THEN /\ ~r.applied /\ ~r.released
              /\ rows' = (rows \ {r}) \cup {[r EXCEPT !.released = TRUE]}
              /\ UNCHANGED floor
         ELSE /\ r.applied
              /\ rows' = rows \ {r}
              /\ floor' = IF Twin = "NoFloor" THEN floor ELSE Min(floor, Max(bal, 0))
    /\ svcTok' = {t \in svcTok : t.id # r.id}
    /\ UNCHANGED <<bal, seenIds, leaseTok, up, inc, fresh, cred, avail, view, spentU, batches, seq, oldCarves, spent, billed>>

Crash(h) ==
    /\ up[h]
    /\ up' = [up EXCEPT ![h] = FALSE]
    /\ cred' = [cred EXCEPT ![h] = None]
    /\ avail' = [avail EXCEPT ![h] = 0]
    /\ view' = [view EXCEPT ![h] = 0]
    /\ spentU' = [spentU EXCEPT ![h] = 0]
    /\ batches' = [batches EXCEPT ![h] = {}]
    /\ UNCHANGED <<bal, rows, seenIds, leaseTok, svcTok, floor, inc, fresh, seq, oldCarves, spent, billed>>

Restart(h) ==
    /\ ~up[h] /\ inc[h] < MaxInc
    /\ up' = [up EXCEPT ![h] = TRUE]
    /\ inc' = [inc EXCEPT ![h] = @ + 1]
    /\ fresh' = [fresh EXCEPT ![h] = TRUE]
    /\ UNCHANGED <<bal, rows, seenIds, leaseTok, svcTok, floor, cred, avail, view, spentU, batches, seq, oldCarves, spent, billed>>

(* A dead process's lease token reaches its expiry. *)
LapseLease(h, i) ==
    /\ leaseTok[<<h, i>>] > 0
    /\ (i < inc[h] \/ ~up[h])
    /\ leaseTok' = [leaseTok EXCEPT ![<<h, i>>] = 0]
    /\ UNCHANGED <<bal, rows, seenIds, svcTok, floor, up, inc, fresh, cred, avail, view, spentU, batches, seq, oldCarves, spent, billed>>

(* A carved token nothing will ever release reaches its expiry: no row names it and no live host holds its batch. *)
LapseCarved(t) ==
    /\ t \in svcTok
    /\ ~\E r \in rows : r.id = t.id
    /\ ~\E h \in Hosts : up[h] /\ \E b \in batches[h] : b.id = t.id
    /\ svcTok' = svcTok \ {t}
    /\ UNCHANGED <<bal, rows, seenIds, leaseTok, floor, up, inc, fresh, cred, avail, view, spentU, batches, seq, oldCarves, spent, billed>>

(* A live host could not extend its token. Before Redis drops it the host stops spending those bytes, gives up
   what it spent under the token and had not carved, and draws from then on under a new token. *)
Expire(h) ==
    /\ up[h] /\ leaseTok[Me(h)] > 0
    /\ leaseTok' = [leaseTok EXCEPT ![Me(h)] = 0]
    /\ IF Twin = "SpendPastExpiry"
         THEN UNCHANGED <<avail, view, spentU, inc, fresh>>
         ELSE /\ inc[h] < MaxInc
              /\ avail' = [avail EXCEPT ![h] = 0]
              /\ view' = [view EXCEPT ![h] = 0]
              /\ spentU' = [spentU EXCEPT ![h] = 0]
              /\ inc' = [inc EXCEPT ![h] = @ + 1]
              /\ fresh' = [fresh EXCEPT ![h] = TRUE]
    /\ UNCHANGED <<bal, rows, seenIds, svcTok, floor, up, cred, batches, seq, oldCarves, spent, billed>>

(* The last handle closes: the token shrinks to what is spent and not yet carved, and the rest returns. *)
Close(h) ==
    /\ up[h] /\ avail[h] > 0
    /\ LET keep == spentU[h] + SumAmt({b \in batches[h] : ~b.carved /\ b.id[2] = inc[h]}) IN
       /\ view[h] >= keep /\ leaseTok[Me(h)] = view[h]
       /\ leaseTok' = [leaseTok EXCEPT ![Me(h)] = keep]
       /\ view' = [view EXCEPT ![h] = keep]
    /\ avail' = [avail EXCEPT ![h] = 0]
    /\ UNCHANGED <<bal, rows, seenIds, svcTok, floor, up, inc, fresh, cred, spentU, batches, seq, oldCarves, spent, billed>>

FloorForgotten ==
    /\ Twin = "FloorExpires"
    /\ floor' = NoFloor
    /\ UNCHANGED <<bal, rows, seenIds, leaseTok, svcTok, up, inc, fresh, cred, avail, view, spentU, batches, seq,
                   oldCarves, spent, billed>>

Init ==
    /\ bal = Credit /\ rows = {} /\ seenIds = {}
    /\ leaseTok = [x \in Hosts \X Incs |-> 0] /\ svcTok = {} /\ floor = NoFloor
    /\ up = [h \in Hosts |-> TRUE] /\ inc = [h \in Hosts |-> 1] /\ fresh = [h \in Hosts |-> TRUE]
    /\ cred = [h \in Hosts |-> None]
    /\ avail = [h \in Hosts |-> 0] /\ view = [h \in Hosts |-> 0] /\ spentU = [h \in Hosts |-> 0]
    /\ batches = [h \in Hosts |-> {}] /\ seq = [h \in Hosts |-> 0]
    /\ oldCarves = {}
    /\ spent = [h \in Hosts |-> 0] /\ billed = [h \in Hosts |-> 0]

Next ==
    \/ \E h \in Hosts : Read(h) \/ Reserve(h) \/ Spend(h) \/ Plan(h) \/ Crash(h) \/ Restart(h) \/ Expire(h) \/ Close(h)
    \/ \E h \in Hosts : \E b \in batches[h] : Carve(h, b) \/ Post(h, b, TRUE) \/ Post(h, b, FALSE) \/ Drop(h, b)
    \/ \E h \in Hosts, i \in Incs : LapseLease(h, i)
    \/ \E c \in oldCarves : LateCarve(c)
    \/ \E r \in rows : Commit(r) \/ Release(r)
    \/ \E t \in svcTok : LapseCarved(t)
    \/ FloorForgotten

Spec == Init /\ [][Next]_vars

(* The balance covers every debit journaled against it: nothing a lease does overdraws it. *)
NoOverdraw == bal - Pending >= 0

(* No byte is billed twice: a host's journaled debits never pass what it spent. *)
BilledOnce == \A h \in Hosts : billed[h] <= spent[h]

(* What a live host may still spend, its lease token holds: no host spends bytes Redis has given back. *)
Backed == \A h \in Hosts : up[h] => avail[h] <= leaseTok[Me(h)]

(* Reach: the whole balance spent by two hosts and debited to the byte, nothing left held. *)
NotSettled ==
    ~(/\ bal = 0 /\ rows = {} /\ Total = 0
      /\ \A h \in Hosts : spent[h] > 0 /\ billed[h] = spent[h])
=============================================================================
