------------------------------- MODULE Fwd -------------------------------
(* DESIGN-DETAILS.md section 4: one sidecar S's forwarding key at one host's forwarding role (owner decision
   197). The log holds S's forwarding Delegations, their revocations, and S's suspension and revocation. A
   host runs two tiers. The judge is the shared rows-only verifier, which runs only inside a compile and
   produces the state: the pin it compiled at and the key live there. Between compiles the posture applies
   entries as an overlay of denials. It cannot judge them, so an entry the judge refused (ok = FALSE: api
   sequenced a statement that verifies under its signer's key and that the rule table refuses) denies until a
   compiled state at or past it says otherwise, and no entry opens anything. A denial the posture cannot check
   at all (seen = FALSE: its signer is not in the rows the posture holds) waits for a compile. The posture
   goes on admitting by its last compiled state meanwhile, however long that is: once the entry has waited
   past the deadline it raises an alarm, again while the entry waits, and does nothing else (Tick marks the
   waiting entries overdue; question details-4-compile-deadline, option 2, QD-621).

   What is checked. Safety: a host admits a window delegation under key k only while k is S's live forwarding
   key at the highest log position the host ever applied, or while a revocation of k that it could not check
   waits for a compile, whatever the order of fetches, compiles, restarts and a rollback of its store.
   Liveness, under LiveSpec, where fetches go on and compiles start and finish: in the end every key the
   host admits is S's live key at the newest entry (EventuallyRefused). Where no compile runs that does not
   hold, and RefusedByDeadline, the rule the owner declined, is the invariant FwdReach-NoCompile denies to
   show it: a revocation the posture cannot check, its deadline past, its key still admitted. That trace is
   accepted (QD-621).

   Twin selects one rule to break:
     NoDelegationOverlay  the posture applies no DelegationRevoke and no newer Delegation as a denial (the
                          overlay kinds DESIGN.md 17.8 lists on 2026-11-09)
     OverlayLifts         an Unsuspend lifts an overlay Suspend on the posture's own check (the landed posture)
     OverlayOpens         the posture takes a newer Delegation's key at once, with no compile
     StateDropsOverlay    a compiled state clears the whole overlay, the entries after its pin included
     LowerStateAccepted   a compile that finishes below the state's pin replaces it
     NoFloor              a rolled-back store is taken as it stands, with no pin kept in the key store

   Left out: the delegation's other fields, share signers, the window client's strict_exp, the cascade's void
   (an S revocation here) and every other subject. Positions are the clock, but for the one deadline. *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    MaxN,       \* log entries
    Keys,       \* forwarding Delegations, each named by its key
    Slots,      \* compiles in flight at once; 2 lets them finish out of order
    Rollbacks,  \* whether the store can be copied and put back
    Twin

VARIABLES
    log,      \* the authorization log, entries 1..Len(log)
    hPin,     \* the posture's pin: the newest entry it applied
    sPin,     \* the pin its compiled state was judged at
    sKey,     \* S's forwarding key in that state; 0 none
    overlay,  \* positions of the entries applied since the state
    comp,     \* per slot, the pin a running compile captured, or NoComp
    floor,    \* the highest pin ever committed, kept in the key store
    snap,     \* a copy of the store an attacker holds
    old       \* positions whose compile deadline has passed: the alarm is raised for them

vars == <<log, hPin, sPin, sKey, overlay, comp, floor, snap, old>>

NoComp == MaxN + 1
NoSnap == [h |-> NoComp, s |-> 0, k |-> 0, o |-> {}]

Entries ==
    [kind : {"deleg"}, key : Keys, ok : BOOLEAN, seen : {TRUE}]
        \cup [kind : {"revoke"}, key : Keys, ok : BOOLEAN, seen : BOOLEAN]
        \cup [kind : {"suspend", "srevoke"}, key : {0}, ok : {TRUE}, seen : {TRUE}]
        \cup [kind : {"unsuspend"}, key : {0}, ok : BOOLEAN, seen : {TRUE}]

(* The judge's state after entry n: section 5's S(n), reduced to S's forwarding row. An entry takes effect when
   its signer's rule passes (ok) and S still stands. A newer Delegation supersedes at its position; a revoked
   or superseded key never returns; the key drops while S is suspended and returns with it. *)
RECURSIVE Judge(_)
Judge(n) ==
    IF n = 0 THEN [key |-> 0, susp |-> FALSE, gone |-> FALSE]
    ELSE LET p == Judge(n - 1)
             e == log[n]
         IN  IF ~e.ok \/ p.gone THEN p
             ELSE CASE e.kind = "deleg" -> [p EXCEPT !.key = e.key]
                    [] e.kind = "revoke" -> IF p.key = e.key THEN [p EXCEPT !.key = 0] ELSE p
                    [] e.kind = "suspend" -> [p EXCEPT !.susp = TRUE]
                    [] e.kind = "unsuspend" -> [p EXCEPT !.susp = FALSE]
                    [] e.kind = "srevoke" -> [p EXCEPT !.gone = TRUE, !.key = 0]
                    [] OTHER -> p

Verdict(q) == log[q].ok /\ ~Judge(q - 1).gone

Live(n) == LET s == Judge(n) IN IF s.gone \/ s.susp THEN 0 ELSE s.key

(* What the posture does with an entry it applied since its state. It lifts nothing: an Unsuspend is an
   opening and waits for a compile. *)
Lifted(q) == Twin = "OverlayLifts" /\ \E r \in (q + 1)..hPin : log[r].kind = "unsuspend"

DenialFor(q, k) ==
    LET e == log[q]
    IN  /\ e.seen
        /\ \/ Twin # "NoDelegationOverlay" /\ e.kind = "revoke" /\ e.key = k
           \/ Twin # "NoDelegationOverlay" /\ e.kind = "deleg" /\ e.key # k
           \/ e.kind = "suspend" /\ ~Lifted(q)
           \/ e.kind = "srevoke"

Denied(k) == \E q \in overlay : DenialFor(q, k)

(* Entries the posture could not check, which only a compile resolves. *)
Waiting == {q \in overlay : ~log[q].seen}

(* The alarm stands: an entry the posture could not check has waited past its deadline. It changes nothing the
   host admits. *)
Alarmed == Waiting \cap old # {}

Current == Twin = "NoFloor" \/ hPin >= floor

Admits(k) == k # 0 /\ sKey = k /\ Current /\ ~Denied(k)

Init ==
    /\ log = <<>>
    /\ hPin = 0 /\ sPin = 0 /\ sKey = 0 /\ overlay = {}
    /\ comp = [i \in 1..Slots |-> NoComp]
    /\ floor = 0
    /\ snap = NoSnap
    /\ old = {}

Sequence(e) ==
    /\ Len(log) < MaxN
    /\ e.kind = "deleg" => \A q \in 1..Len(log) : ~(log[q].kind = "deleg" /\ log[q].key = e.key)
    /\ log' = Append(log, e)
    /\ UNCHANGED <<hPin, sPin, sKey, overlay, comp, floor, snap, old>>

Fetch ==
    /\ hPin < Len(log)
    /\ hPin' = hPin + 1
    /\ overlay' = overlay \cup {hPin + 1}
    /\ floor' = IF hPin + 1 > floor THEN hPin + 1 ELSE floor
    /\ sKey' = IF Twin = "OverlayOpens" /\ log[hPin + 1].kind = "deleg" THEN log[hPin + 1].key ELSE sKey
    /\ UNCHANGED <<log, sPin, comp, snap, old>>

StartCompile(i) ==
    /\ comp[i] = NoComp
    /\ hPin >= floor
    /\ comp' = [comp EXCEPT ![i] = hPin]
    /\ UNCHANGED <<log, hPin, sPin, sKey, overlay, floor, snap, old>>

FinishCompile(i) ==
    /\ comp[i] # NoComp
    /\ Twin = "LowerStateAccepted" \/ comp[i] >= sPin
    /\ sPin' = comp[i]
    /\ sKey' = Live(comp[i])
    /\ overlay' = IF Twin = "StateDropsOverlay" THEN {} ELSE {q \in overlay : q > comp[i]}
    /\ comp' = [comp EXCEPT ![i] = NoComp]
    /\ UNCHANGED <<log, hPin, floor, snap, old>>

DropCompile(i) ==
    /\ comp[i] # NoComp
    /\ comp[i] < sPin
    /\ comp' = [comp EXCEPT ![i] = NoComp]
    /\ UNCHANGED <<log, hPin, sPin, sKey, overlay, floor, snap, old>>

Restart ==
    /\ \E i \in 1..Slots : comp[i] # NoComp
    /\ comp' = [i \in 1..Slots |-> NoComp]
    /\ UNCHANGED <<log, hPin, sPin, sKey, overlay, floor, snap, old>>

Snapshot ==
    /\ Rollbacks
    /\ snap' = [h |-> hPin, s |-> sPin, k |-> sKey, o |-> overlay]
    /\ UNCHANGED <<log, hPin, sPin, sKey, overlay, comp, floor, old>>

Rollback ==
    /\ Rollbacks
    /\ snap # NoSnap
    /\ hPin' = snap.h /\ sPin' = snap.s /\ sKey' = snap.k /\ overlay' = snap.o
    /\ comp' = [i \in 1..Slots |-> NoComp]
    /\ UNCHANGED <<log, floor, snap, old>>

Tick ==
    /\ Waiting \ old # {}
    /\ old' = old \cup Waiting
    /\ UNCHANGED <<log, hPin, sPin, sKey, overlay, comp, floor, snap>>

Next ==
    \/ \E e \in Entries : Sequence(e)
    \/ Fetch
    \/ \E i \in 1..Slots : StartCompile(i) \/ FinishCompile(i) \/ DropCompile(i)
    \/ Restart
    \/ Snapshot
    \/ Rollback
    \/ Tick

Spec == Init /\ [][Next]_vars

(* Where a compile eventually runs: the host goes on fetching, a compile starts whenever none is running in a
   slot, and a compile that keeps being started is in the end let finish, restarts or not. *)
Fairness == WF_vars(Fetch) /\ \A i \in 1..Slots : WF_vars(StartCompile(i)) /\ SF_vars(FinishCompile(i))
LiveSpec == Spec /\ Fairness
(* Where no compile need finish: fetches go on, and nothing is asked of a compile. *)
FetchSpec == Spec /\ WF_vars(Fetch)

(* A host admits a key only while it is S's live forwarding key at the highest position the host ever applied,
   or while a revocation of that key which it could not check waits for a compile. *)
OnlyLiveKeysAdmitted ==
    \A k \in Keys : Admits(k) =>
        (Live(floor) = k \/ \E q \in Waiting : log[q].kind = "revoke" /\ log[q].key = k)

(* Under LiveSpec: in the end every key the host admits is S's live key at the newest entry of the log. Under
   FetchSpec it fails, which FwdReach-NoCompileLive shows. *)
EventuallyRefused == <>[](\A k \in Keys : Admits(k) => Live(Len(log)) = k)

(* The rule the owner declined (option 1 of the question): no key that is not live is admitted once every
   entry the posture could not check is past its deadline. The design does not hold it, and FwdReach-NoCompile
   denies it to show the accepted trace. *)
RefusedByDeadline ==
    \A k \in Keys : Admits(k) => (Live(floor) = k \/ \E q \in Waiting : q \notin old)

(* While that trace stands, the alarm stands with it. *)
StaleIsAlarmed ==
    \A k \in Keys : (Admits(k) /\ Live(floor) # k /\ Waiting \subseteq old) => Alarmed

(* The overlay holds only entries after the state's pin, up to the posture's. *)
OverlayAfterState == \A q \in overlay : sPin < q /\ q <= hPin
==========================================================================
