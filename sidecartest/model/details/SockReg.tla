------------------------------ MODULE SockReg ------------------------------
(* DESIGN-DETAILS.md section 13.2.3: one listener's registration on one socket name, against revocation.

   The authorization log grows by entries that leave the listener's listen grant standing or not: Allow(n)
   is the verdict at position n, and position 0 allows. Each sockets process holds a verified position
   (pos), which only rises, and the highest position it has evidence of (seen): a key event, a fence it met
   in the store, or a lease a fresher process wrote. A process with seen above pos is behind and admits
   nothing. An event may never arrive, so a process can be stale and not know it.

   The store holds the listener's lease on the group, stamped with the position (pv) and the set version (sv)
   it was admitted under; a tombstone a removal left there; and the Service pair with its floor. A
   registration is two steps, the gate's check and the store's write, and a Find is two, the pick and the
   signing, so every other step can fall between them.

   What is checked:
     TicketSound    a ticket is signed only where the signer's own position allows the listener
     FencedLease    once a lease was removed for cause at position x, no lease admitted below x stands
     SetOrder       once a lease was unlistened at set version u, no lease of an older set stands
     PairFenced     once a pair was removed at position x, no pair written below x stands
     EvidenceBound  nothing is admitted or signed by a process that has evidence it is behind

   Twin selects one rule to break:
     NoTombstone    a removal for cause leaves nothing behind in the group
     NoRecheck      Find signs for whatever lease the pick returned
     NoPairFloor    a pair write is taken whatever position it was allowed at
     BehindAllows   a process that knows the log moved still admits on the state it holds
     NoSetVersion   the store takes a page whatever set version the group has seen

   Left out: the chain check behind pos, which section 5's model owns; the dialer's own grant, taken as
   standing; other listeners of the group; lease expiry, which only removes. *)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    Procs,
    MaxN,       \* log entries
    MaxSv,      \* pages the listener sends
    MaxCalls,   \* registration calls in flight at once
    Twin

VARIABLES
    log,        \* log[n]: whether the listener's grant stands at position n
    pos, seen,
    lease,      \* the listener's lease in the group, or None
    tomb,       \* the tombstone a removal left, or None
    pair,       \* the Service pair, or None
    pairFloor,
    calls,      \* registration calls between the gate's check and the store's write
    finds,      \* Finds between the pick and the signing
    tickets,
    sv,         \* the listener's next set version
    removedAt, unlistenedAt, pairRemovedAt, lapse   \* what the invariants remember

vars == <<log, pos, seen, lease, tomb, pair, pairFloor, calls, finds, tickets, sv, removedAt, unlistenedAt,
          pairRemovedAt, lapse>>

None == [none |-> TRUE]
Max(a, b) == IF a > b THEN a ELSE b
Allow(n) == IF n = 0 THEN TRUE ELSE log[n]
Behind(p) == seen[p] > pos[p]
MayAct(p) == Twin = "BehindAllows" \/ ~Behind(p)

Merge(t) == IF tomb = None THEN t ELSE [pv |-> Max(tomb.pv, t.pv), sv |-> Max(tomb.sv, t.sv)]

Grow(v) ==
    /\ Len(log) < MaxN
    /\ log' = Append(log, v)
    /\ UNCHANGED <<pos, seen, lease, tomb, pair, pairFloor, calls, finds, tickets, sv, removedAt, unlistenedAt,
                   pairRemovedAt, lapse>>

(* Evidence reaches a process: the key event of an append. It may never come. *)
Event(p) ==
    /\ seen[p] < Len(log)
    /\ seen' = [seen EXCEPT ![p] = Len(log)]
    /\ UNCHANGED <<log, pos, lease, tomb, pair, pairFloor, calls, finds, tickets, sv, removedAt, unlistenedAt,
                   pairRemovedAt, lapse>>

(* A load installs a higher verified position, never a lower one. *)
Load(p, n) ==
    /\ n > pos[p] /\ n <= Len(log)
    /\ pos' = [pos EXCEPT ![p] = n]
    /\ seen' = [seen EXCEPT ![p] = Max(@, n)]
    /\ UNCHANGED <<log, lease, tomb, pair, pairFloor, calls, finds, tickets, sv, removedAt, unlistenedAt,
                   pairRemovedAt, lapse>>

(* A page that holds the entry reaches process p: the gate judges it at p's position. *)
RegStart(p) ==
    /\ sv <= MaxSv /\ Cardinality(calls) < MaxCalls
    /\ MayAct(p)
    /\ calls' = calls \cup {[p |-> p, n |-> pos[p], ok |-> Allow(pos[p]), sv |-> sv, kind |-> "put"]}
    /\ sv' = sv + 1
    /\ lapse' = (lapse \/ Behind(p))
    /\ UNCHANGED <<log, pos, seen, lease, tomb, pair, pairFloor, finds, tickets, removedAt, unlistenedAt, pairRemovedAt>>

(* A page that lacks the entry: an unlisten, which no gate judges. *)
UnlistenStart(p) ==
    /\ sv <= MaxSv /\ Cardinality(calls) < MaxCalls
    /\ calls' = calls \cup {[p |-> p, n |-> pos[p], ok |-> TRUE, sv |-> sv, kind |-> "unlisten"]}
    /\ sv' = sv + 1
    /\ UNCHANGED <<log, pos, seen, lease, tomb, pair, pairFloor, finds, tickets, removedAt, unlistenedAt,
                   pairRemovedAt, lapse>>

Fenced(c) ==
    /\ tomb # None
    /\ \/ c.n < tomb.pv
       \/ (Twin # "NoSetVersion" /\ c.sv < tomb.sv)

(* The store's write, one script on the group. *)
RegApply(c) ==
    /\ c \in calls
    /\ calls' = calls \ {c}
    /\ IF c.kind = "put" /\ c.ok
         THEN IF Fenced(c)
                THEN \* a removal at a newer position or set stands: nothing is written, and p learns it is behind
                     /\ seen' = [seen EXCEPT ![c.p] = Max(@, tomb.pv)]
                     /\ UNCHANGED <<lease, tomb, removedAt, unlistenedAt>>
              ELSE IF Twin # "NoSetVersion" /\ lease # None /\ c.sv < lease.sv
                THEN UNCHANGED <<seen, lease, tomb, removedAt, unlistenedAt>>
              ELSE /\ lease' = [pv |-> IF lease = None THEN c.n ELSE Max(lease.pv, c.n), sv |-> c.sv]
                   /\ tomb' = None
                   /\ UNCHANGED <<seen, removedAt, unlistenedAt>>
       ELSE IF c.kind = "put"
         THEN \* the gate refused the entry: the lease it held, if this page is not older than it, ends for cause
              IF lease # None /\ lease.pv <= c.n /\ (Twin = "NoSetVersion" \/ lease.sv <= c.sv)
                THEN /\ lease' = None
                     /\ tomb' = IF Twin = "NoTombstone" THEN tomb ELSE Merge([pv |-> c.n, sv |-> c.sv])
                     /\ removedAt' = Max(removedAt, c.n)
                     /\ UNCHANGED <<seen, unlistenedAt>>
              ELSE UNCHANGED <<seen, lease, tomb, removedAt, unlistenedAt>>
       ELSE \* unlisten
            IF lease # None /\ (Twin = "NoSetVersion" \/ lease.sv < c.sv)
              THEN /\ lease' = None
                   /\ tomb' = IF Twin = "NoSetVersion" THEN tomb ELSE Merge([pv |-> 0, sv |-> c.sv])
                   /\ unlistenedAt' = Max(unlistenedAt, c.sv)
                   /\ UNCHANGED <<seen, removedAt>>
            ELSE UNCHANGED <<seen, lease, tomb, removedAt, unlistenedAt>>
    /\ UNCHANGED <<log, pos, pair, pairFloor, finds, tickets, sv, pairRemovedAt, lapse>>

(* The revocation sweep at a process whose position refuses the listener: the lease ends, with a tombstone. *)
Sweep(p) ==
    /\ MayAct(p) /\ ~Allow(pos[p])
    /\ lease # None /\ lease.pv < pos[p]
    /\ lease' = None
    /\ tomb' = IF Twin = "NoTombstone" THEN tomb ELSE Merge([pv |-> pos[p], sv |-> lease.sv])
    /\ removedAt' = Max(removedAt, pos[p])
    /\ UNCHANGED <<log, pos, seen, pair, pairFloor, calls, finds, tickets, sv, unlistenedAt, pairRemovedAt, lapse>>

(* The pair goes in a script of its own, on another slot. *)
SweepPair(p) ==
    /\ MayAct(p) /\ ~Allow(pos[p])
    /\ pair # None \/ pairFloor < pos[p]
    /\ pair' = None
    /\ pairFloor' = IF Twin = "NoPairFloor" THEN pairFloor ELSE Max(pairFloor, pos[p])
    /\ pairRemovedAt' = Max(pairRemovedAt, pos[p])
    /\ UNCHANGED <<log, pos, seen, lease, tomb, calls, finds, tickets, sv, removedAt, unlistenedAt, lapse>>

(* A Find's pick returns the lease as the group holds it. *)
FindPick(p) ==
    /\ MayAct(p) /\ lease # None /\ finds = {}
    /\ finds' = {[p |-> p, rec |-> lease]}
    /\ lapse' = (lapse \/ Behind(p))
    /\ UNCHANGED <<log, pos, seen, lease, tomb, pair, pairFloor, calls, tickets, sv, removedAt, unlistenedAt, pairRemovedAt>>

(* The signing, judged at the position the process holds by then. *)
FindSign(f) ==
    /\ f \in finds
    /\ finds' = {}
    /\ LET p == f.p
           n == pos[p]
       IN  IF ~MayAct(p)
             THEN UNCHANGED <<seen, lease, tomb, pair, tickets, removedAt, lapse>>
           ELSE IF Twin # "BehindAllows" /\ f.rec.pv > n
             THEN \* a fresher process admitted it: p is behind, and signs nothing
                  /\ seen' = [seen EXCEPT ![p] = Max(@, f.rec.pv)]
                  /\ UNCHANGED <<lease, tomb, pair, tickets, removedAt, lapse>>
           ELSE IF Twin # "NoRecheck" /\ ~Allow(n)
             THEN \* p's own state refuses the listener: no ticket, and the lease it picked ends for cause
                  /\ IF lease = f.rec
                       THEN /\ lease' = None
                            /\ tomb' = IF Twin = "NoTombstone" THEN tomb ELSE Merge([pv |-> n, sv |-> f.rec.sv])
                            /\ removedAt' = Max(removedAt, n)
                       ELSE UNCHANGED <<lease, tomb, removedAt>>
                  /\ UNCHANGED <<seen, pair, tickets, lapse>>
           ELSE IF Twin # "NoPairFloor" /\ n < pairFloor
             THEN \* the pair was removed at a newer position: p is behind, and signs nothing
                  /\ seen' = [seen EXCEPT ![p] = Max(@, pairFloor)]
                  /\ UNCHANGED <<lease, tomb, pair, tickets, removedAt, lapse>>
           ELSE /\ pair' = [pv |-> n]
                /\ tickets' = tickets \cup {[n |-> n]}
                /\ lapse' = (lapse \/ Behind(p))
                /\ UNCHANGED <<seen, lease, tomb, removedAt>>
    /\ UNCHANGED <<log, pos, pairFloor, calls, sv, unlistenedAt, pairRemovedAt>>

Init ==
    /\ log = <<>>
    /\ pos = [p \in Procs |-> 0] /\ seen = [p \in Procs |-> 0]
    /\ lease = None /\ tomb = None /\ pair = None /\ pairFloor = 0
    /\ calls = {} /\ finds = {} /\ tickets = {}
    /\ sv = 1
    /\ removedAt = 0 /\ unlistenedAt = 0 /\ pairRemovedAt = 0 /\ lapse = FALSE

Next ==
    \/ \E v \in BOOLEAN : Grow(v)
    \/ \E p \in Procs : Event(p) \/ RegStart(p) \/ UnlistenStart(p) \/ Sweep(p) \/ SweepPair(p) \/ FindPick(p)
    \/ \E p \in Procs, n \in 1..MaxN : Load(p, n)
    \/ \E c \in calls : RegApply(c)
    \/ \E f \in finds : FindSign(f)

Spec == Init /\ [][Next]_vars

TicketSound == \A t \in tickets : Allow(t.n)
FencedLease == lease # None => lease.pv >= removedAt
SetOrder == lease # None => lease.sv >= unlistenedAt
PairFenced == pair # None => pair.pv >= pairRemovedAt
EvidenceBound == ~lapse

(* Reach: revoked, swept, granted again, and listening again at the newer position with a ticket signed there. *)
NoRegrant == ~(removedAt >= 1 /\ lease # None /\ lease.pv > removedAt /\ \E t \in tickets : t.n > removedAt)
=============================================================================
