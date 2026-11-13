------------------------------ MODULE CertOrder ------------------------------
(* DESIGN-DETAILS.md section 17: one customer ACME account, several ordering desktops, and rows that all name one
   custom host, so that every order of the account is for the same name set and the CA may hand a newOrder an
   order it already holds (order reuse, 17.2.8's A9).

   The server is the account row's lock (a sequence, a holder, and whether its lease is still live on the
   server's clock) and each row's state, recorded order and registered order. The CA is its orders: pending,
   ready, valid or invalid, and for a valid one the row whose CSR finalized it. A desktop is what it holds in
   memory: the row and sequence it claimed, the order it knows and whether it was granted a newOrder.

   Anything may happen between two steps of a desktop. Crash forgets what a desktop held. Lapse ends a lease
   while its holder goes on, so a holder that only stalled acts later on what it remembers, beside the desktop
   that took over. The CA validates, fails or expires an order whenever it likes, and a newOrder returns a
   pending or ready order of the account or a new one, either way. A row's device may be removed at any time.

   What is checked:
     OneInFlight  at most one row is custom_ordering (C2)
     OneCert      the CA issues at most one certificate on a row's key (C1)
     KeyMatch     a registered order is valid and was finalized with its row's CSR (C3)
     Tracked      every certificate the CA issued and nobody revoked is registered, or is the recorded order of a
                  row still custom_ordering or custom_revoking, so the next claim finds it (C1's second half)
     Served       no certificate registered on a custom_issued row has been revoked
     NoForeign    no row's recorded order is valid on another row's key

   Twin selects one rule of the design to drop:
     NoRecord          a holder finalizes an order the server did not take under its claim
     NoResume          a takeover is granted a newOrder whatever is recorded, and its record replaces it
     ReplaceLive       order_invalid is sent for an order that is still pending or ready (a timeout)
     TwoInFlight       a row is claimed while another row has an order open
     TwoInFlightBlind  the same, and neither the desktop nor the server checks the leaf's key
     FailKeepsOrder    a row that ends with an order recorded goes to failed, not to custom_revoking

   Left out: the budgets and holds, which only refuse a claim or a grant, and a refused one is a step not taken
   or a Release; the challenge, which is the CA's Authorize or Dead here; a holder killing its own order
   (17.2.7), which is the CA's Dead followed by OrderInvalid; renewal, whose successor is one more row; the key
   change, which holds the same lock; lease renewals, which no invariant rests on. *)
EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    Desktops,
    Rows,
    None,
    MaxOrders,  \* orders the CA creates
    MaxClaims,  \* takes of the lock
    Twin

VARIABLES
    lockSeq,    \* the account row's lock_seq
    holder,     \* lock_sidecar_id, or None
    live,       \* whether the lease is unlapsed on the server's clock
    lockRow,    \* lock_cert_id
    state,      \* each row: queued, ordering, issued, revoking, failed, revoked
    url,        \* each row's order_url: an order, or 0
    reg,        \* each row's registered order, or 0
    orders,     \* the CA's orders
    nOrders,
    pc,         \* each desktop: idle, claimed, ordered, recorded, finalized, revoke
    dRow,
    dSeq,
    dOrder,
    dMay

server == <<lockSeq, holder, live, lockRow, state, url, reg>>
ca == <<orders, nOrders>>
vars == <<lockSeq, holder, live, lockRow, state, url, reg, orders, nOrders, pc, dRow, dSeq, dOrder, dMay>>

Ids == 1..MaxOrders
(* for: the row whose newOrder made it. key: the row whose CSR finalized it. by: the desktop that finalized. *)
NoOrder == [status |-> "absent", for |-> None, key |-> None, by |-> None, revoked |-> FALSE]

InFlightOff == Twin \in {"TwoInFlight", "TwoInFlightBlind"}
LeafOff == Twin = "TwoInFlightBlind"

(* The check every write of a holder passes: its claim is still the account's. The lease is not read. *)
Holds(d) == holder = d /\ lockSeq = dSeq[d]
Free == holder = None \/ ~live
(* A row with an order open: in flight, or ended under an order nobody has settled (17.2.12). *)
Open(r) == state[r] = "ordering" \/ (state[r] = "revoking" /\ url[r] # 0 /\ reg[r] = 0)
Ended(r) == IF url[r] = 0 \/ Twin = "FailKeepsOrder" THEN "failed" ELSE "revoking"

(* A desktop that stops, or crashes, forgets what it held. *)
Rest(d) ==
    /\ pc' = [pc EXCEPT ![d] = "idle"]
    /\ dRow' = [dRow EXCEPT ![d] = None]
    /\ dSeq' = [dSeq EXCEPT ![d] = 0]
    /\ dOrder' = [dOrder EXCEPT ![d] = 0]
    /\ dMay' = [dMay EXCEPT ![d] = FALSE]
Keep == UNCHANGED <<dRow, dSeq, dOrder, dMay>>
Freed == holder' = None /\ live' = FALSE /\ lockRow' = None
Held == UNCHANGED <<holder, live, lockRow>>

Take(d, r) ==
    /\ pc[d] = "idle"
    /\ Free
    /\ lockSeq < MaxClaims
    /\ lockSeq' = lockSeq + 1
    /\ holder' = d
    /\ live' = TRUE
    /\ lockRow' = r
    /\ dSeq' = [dSeq EXCEPT ![d] = lockSeq + 1]
    /\ dRow' = [dRow EXCEPT ![d] = r]

(* 17.2.6's claim, purpose order. *)
ClaimOrder(d, r) ==
    /\ state[r] \in {"queued", "ordering"}
    /\ InFlightOff \/ \A x \in Rows \ {r} : ~Open(x)
    /\ Take(d, r)
    /\ state' = [state EXCEPT ![r] = "ordering"]
    /\ pc' = [pc EXCEPT ![d] = "claimed"]
    /\ dOrder' = [dOrder EXCEPT ![d] = IF Twin = "NoResume" THEN 0 ELSE url[r]]
    /\ dMay' = [dMay EXCEPT ![d] = (Twin = "NoResume" \/ url[r] = 0)]
    /\ UNCHANGED <<url, reg, ca>>

(* One newOrder a grant. The CA answers with an order it holds for the name, or a new one. *)
NewOrder(d) ==
    /\ pc[d] = "claimed"
    /\ dMay[d]
    /\ dOrder[d] = 0
    /\ \E o \in Ids :
        /\ \/ /\ o <= nOrders
              /\ orders[o].status \in {"pending", "ready"}
              /\ UNCHANGED ca
           \/ /\ o = nOrders + 1
              /\ orders' = [orders EXCEPT ![o] = [NoOrder EXCEPT !.status = "pending", !.for = dRow[d]]]
              /\ nOrders' = o
        /\ dOrder' = [dOrder EXCEPT ![d] = o]
    /\ dMay' = [dMay EXCEPT ![d] = FALSE]
    /\ pc' = [pc EXCEPT ![d] = "ordered"]
    /\ UNCHANGED <<server, dRow, dSeq>>

(* progress order_recorded. A refusal ends the holder's work on the row. *)
Record(d) ==
    /\ pc[d] = "ordered"
    /\ LET r == dRow[d]
           taken == Holds(d) /\ state[r] = "ordering" /\ (url[r] = 0 \/ Twin = "NoResume")
       IN  /\ url' = IF taken THEN [url EXCEPT ![r] = dOrder[d]] ELSE url
           /\ IF taken \/ Twin = "NoRecord"
                THEN pc' = [pc EXCEPT ![d] = "recorded"] /\ Keep
                ELSE Rest(d)
    /\ UNCHANGED <<lockSeq, holder, live, lockRow, state, reg, ca>>

(* A claim that handed over a recorded order: no newOrder. *)
Resume(d) ==
    /\ pc[d] = "claimed"
    /\ dOrder[d] # 0
    /\ pc' = [pc EXCEPT ![d] = "recorded"]
    /\ UNCHANGED <<server, ca, dRow, dSeq, dOrder, dMay>>

(* The CA: the authorization passes; or it fails, or the order expires. *)
Authorize(o) ==
    /\ o <= nOrders
    /\ orders[o].status = "pending"
    /\ orders' = [orders EXCEPT ![o].status = "ready"]
    /\ UNCHANGED <<server, nOrders, pc, dRow, dSeq, dOrder, dMay>>

Dead(o) ==
    /\ o <= nOrders
    /\ orders[o].status \in {"pending", "ready"}
    /\ orders' = [orders EXCEPT ![o].status = "invalid"]
    /\ UNCHANGED <<server, nOrders, pc, dRow, dSeq, dOrder, dMay>>

(* An order issues once (A12): finalize takes a ready order, and finds a valid one already finalized. *)
Finalize(d) ==
    /\ pc[d] = "recorded"
    /\ LET o == dOrder[d] IN
        \/ /\ orders[o].status = "ready"
           /\ orders' = [orders EXCEPT ![o].status = "valid", ![o].key = dRow[d], ![o].by = d]
        \/ /\ orders[o].status = "valid"
           /\ UNCHANGED orders
    /\ pc' = [pc EXCEPT ![d] = "finalized"]
    /\ UNCHANGED <<server, nOrders, dRow, dSeq, dOrder, dMay>>

(* progress order_invalid: only for an order the CA called dead. It is granted another newOrder, or the row
   goes back to the queue. *)
OrderInvalid(d) ==
    /\ pc[d] = "recorded"
    /\ LET o == dOrder[d]
           r == dRow[d]
       IN  /\ \/ orders[o].status = "invalid"
              \/ Twin = "ReplaceLive" /\ orders[o].status \in {"pending", "ready"}
           /\ IF Holds(d) /\ state[r] = "ordering"
                THEN /\ url' = [url EXCEPT ![r] = 0]
                     /\ \/ /\ pc' = [pc EXCEPT ![d] = "claimed"]
                           /\ dOrder' = [dOrder EXCEPT ![d] = 0]
                           /\ dMay' = [dMay EXCEPT ![d] = TRUE]
                           /\ UNCHANGED <<dRow, dSeq, state>>
                           /\ Held
                        \/ /\ Rest(d)
                           /\ state' = [state EXCEPT ![r] = "queued"]
                           /\ Freed
                ELSE /\ Rest(d)
                     /\ UNCHANGED <<url, state>>
                     /\ Held
    /\ UNCHANGED <<lockSeq, reg, ca>>

(* The leaf check and POST /tls/cert-register. A chain on another key ends the row under its order. *)
Register(d) ==
    /\ pc[d] = "finalized"
    /\ LET o == dOrder[d]
           r == dRow[d]
           mine == orders[o].key = r \/ LeafOff
       IN  IF Holds(d) /\ state[r] = "ordering"
             THEN /\ state' = [state EXCEPT ![r] = IF mine THEN "issued" ELSE "revoking"]
                  /\ reg' = IF mine THEN [reg EXCEPT ![r] = o] ELSE reg
                  /\ Freed
             ELSE UNCHANGED <<state, reg>> /\ Held
    /\ Rest(d)
    /\ UNCHANGED <<lockSeq, url, ca>>

(* progress failed: the CSR, the attestation or the CA refused the row. *)
FailRow(d) ==
    /\ pc[d] \in {"claimed", "recorded"}
    /\ Holds(d)
    /\ state[dRow[d]] = "ordering"
    /\ state' = [state EXCEPT ![dRow[d]] = Ended(dRow[d])]
    /\ Freed
    /\ Rest(d)
    /\ UNCHANGED <<lockSeq, url, reg, ca>>

(* The row's device, host or domain is removed. *)
RemoveRow(r) ==
    /\ state[r] \in {"queued", "ordering", "issued"}
    /\ state' = [state EXCEPT ![r] = IF state[r] = "issued" THEN "revoking"
                                      ELSE IF state[r] = "queued" THEN "failed" ELSE Ended(r)]
    /\ IF lockRow = r THEN Freed ELSE Held
    /\ UNCHANGED <<lockSeq, url, reg, ca, pc, dRow, dSeq, dOrder, dMay>>

(* progress release: a row with an order recorded stays in flight. *)
Release(d) ==
    /\ pc[d] \in {"claimed", "ordered", "recorded"}
    /\ Holds(d)
    /\ state[dRow[d]] = "ordering"
    /\ state' = [state EXCEPT ![dRow[d]] = IF url[dRow[d]] = 0 THEN "queued" ELSE "ordering"]
    /\ Freed
    /\ Rest(d)
    /\ UNCHANGED <<lockSeq, url, reg, ca>>

Crash(d) ==
    /\ pc[d] # "idle"
    /\ Rest(d)
    /\ UNCHANGED <<server, ca>>

Lapse ==
    /\ holder # None
    /\ live
    /\ live' = FALSE
    /\ UNCHANGED <<lockSeq, holder, lockRow, state, url, reg, ca, pc, dRow, dSeq, dOrder, dMay>>

(* 17.2.12: the claim, purpose revoke, for a registered certificate or for the order a row ended under. *)
ClaimRevoke(d, r) ==
    /\ state[r] = "revoking"
    /\ Take(d, r)
    /\ pc' = [pc EXCEPT ![d] = "revoke"]
    /\ dOrder' = [dOrder EXCEPT ![d] = IF reg[r] # 0 THEN reg[r] ELSE url[r]]
    /\ UNCHANGED <<state, url, reg, ca, dMay>>

(* Revoke a certificate, or deactivate a live order's authorization, which no finalize survives. *)
Kill(d) ==
    /\ pc[d] = "revoke"
    /\ dOrder[d] # 0
    /\ LET o == dOrder[d] IN
        \/ /\ orders[o].status = "valid"
           /\ ~orders[o].revoked
           /\ orders' = [orders EXCEPT ![o].revoked = TRUE]
        \/ /\ orders[o].status \in {"pending", "ready"}
           /\ orders' = [orders EXCEPT ![o].status = "invalid"]
    /\ UNCHANGED <<server, nOrders, pc, dRow, dSeq, dOrder, dMay>>

(* progress revoked: only once the order is dead or its certificate revoked. *)
Report(d) ==
    /\ pc[d] = "revoke"
    /\ dOrder[d] = 0 \/ orders[dOrder[d]].status = "invalid" \/ orders[dOrder[d]].revoked
    /\ IF Holds(d) /\ state[dRow[d]] = "revoking"
         THEN /\ state' = [state EXCEPT ![dRow[d]] = "revoked"]
              /\ Freed
         ELSE UNCHANGED state /\ Held
    /\ Rest(d)
    /\ UNCHANGED <<lockSeq, url, reg, ca>>

Init ==
    /\ lockSeq = 0
    /\ holder = None
    /\ live = FALSE
    /\ lockRow = None
    /\ state = [r \in Rows |-> "queued"]
    /\ url = [r \in Rows |-> 0]
    /\ reg = [r \in Rows |-> 0]
    /\ orders = [o \in Ids |-> NoOrder]
    /\ nOrders = 0
    /\ pc = [d \in Desktops |-> "idle"]
    /\ dRow = [d \in Desktops |-> None]
    /\ dSeq = [d \in Desktops |-> 0]
    /\ dOrder = [d \in Desktops |-> 0]
    /\ dMay = [d \in Desktops |-> FALSE]

Next ==
    \/ Lapse
    \/ \E o \in Ids : Authorize(o) \/ Dead(o)
    \/ \E r \in Rows : RemoveRow(r)
    \/ \E d \in Desktops :
        \/ \E r \in Rows : ClaimOrder(d, r) \/ ClaimRevoke(d, r)
        \/ NewOrder(d) \/ Record(d) \/ Resume(d) \/ Finalize(d) \/ OrderInvalid(d) \/ Register(d)
        \/ FailRow(d) \/ Release(d) \/ Crash(d) \/ Kill(d) \/ Report(d)

Spec == Init /\ [][Next]_vars

(* Desktops are alike and rows are alike, so a state and its renamings are checked once. *)
Alike == Permutations(Desktops) \cup Permutations(Rows)

Issued(o) == o <= nOrders /\ orders[o].status = "valid"

TypeOk ==
    /\ lockSeq \in 0..MaxClaims
    /\ holder \in Desktops \cup {None}
    /\ live \in BOOLEAN
    /\ lockRow \in Rows \cup {None}
    /\ state \in [Rows -> {"queued", "ordering", "issued", "revoking", "failed", "revoked"}]
    /\ url \in [Rows -> 0..MaxOrders]
    /\ reg \in [Rows -> 0..MaxOrders]
    /\ nOrders \in 0..MaxOrders
    /\ \A o \in Ids : orders[o].status \in {"absent", "pending", "ready", "valid", "invalid"}
    /\ pc \in [Desktops -> {"idle", "claimed", "ordered", "recorded", "finalized", "revoke"}]
    /\ dOrder \in [Desktops -> 0..MaxOrders]

OneInFlight == Cardinality({r \in Rows : state[r] = "ordering"}) <= 1

OneCert == \A r \in Rows : Cardinality({o \in Ids : Issued(o) /\ orders[o].key = r}) <= 1

KeyMatch == \A r \in Rows : reg[r] # 0 => Issued(reg[r]) /\ orders[reg[r]].key = r

Tracked ==
    \A o \in Ids : Issued(o) /\ ~orders[o].revoked =>
        \E r \in Rows :
            \/ reg[r] = o /\ state[r] \in {"issued", "revoking"}
            \/ url[r] = o /\ reg[r] = 0 /\ state[r] \in {"ordering", "revoking"}

Served == \A r \in Rows : state[r] = "issued" => ~orders[reg[r]].revoked

NoForeign == \A r \in Rows : url[r] # 0 /\ Issued(url[r]) => orders[url[r]].key = r

(* States the design must reach, each denied by the invariant a Reach configuration names. *)
(* A desktop holds the chain of an order another desktop finalized, and registers it. *)
NotResumed == ~\E d \in Desktops : pc[d] = "finalized" /\ Holds(d) /\ orders[dOrder[d]].by # d
(* An order one row's newOrder made is registered on another row, finalized with that row's CSR. *)
NotReused == ~\E r \in Rows : reg[r] # 0 /\ orders[reg[r]].for # r
(* A row ended under its order, a stalled holder finalized it, and the revoke pass revoked the certificate. *)
NotKilled == ~\E r \in Rows : state[r] = "revoked" /\ reg[r] = 0 /\ url[r] # 0 /\ orders[url[r]].revoked
(* A row whose first order died is certified on a second. *)
NotReordered == ~\E r \in Rows : state[r] = "issued" /\ \E o \in Ids : orders[o].for = r /\ orders[o].status = "invalid"
=============================================================================
