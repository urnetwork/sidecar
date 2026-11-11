---------------------------- MODULE BridgeNat ----------------------------
(* DESIGN-DETAILS.md section 12: the bridge engine against the host's NAT (D-BRIDGE-7, D-BRIDGE-18, D-BRIDGE-21).

   One host, one subject. The authorization log is a sequence of entries, each a grant or a revocation of one
   rule. A revocation is either one the posture can check by signature (chk) or one only a judge can (a proposal,
   a tick, a cascade). A grant is an opening and takes effect only through a compile. The engine fetches entries
   in order, applies each revocation it can as a denial over the compiled state, starts compiles that capture
   the fetched position and finish in any order, and publishes a policy with a generation after every change.
   After a publish it queues CloseFlows for each rule the new policy no longer admits, and the queued closes run
   later, outside the engine's lock, in any order.

   The NAT's flows are connect's C5 contract. A flow resolves against the published policy and holds the
   decision and its generation, registers it, dials, and re-reads the generation when the dial completes: a newer
   one re-resolves the flow, and only an admission keeps it. CloseFlows(rule) ends every registered flow of that
   rule whose generation is below the published one.

   Durable: the log as fetched, the compiled state's pin, and the overlay of checkable denials above it. Volatile:
   the judge's denials held in memory (Bridge.Revoke), compiles in flight, the policy and its generation, the
   queued closes, every flow, and whether the hook is installed and the provider takes frames. A restart loses
   the volatile part. Section 12's start order is restore, then catch up, then start the provider.

   Judge is TRUE on a daemon, whose root follower judges every entry as it arrives, and FALSE in an app's VPN
   component, where a revocation the posture cannot check waits for a compile (section 4; QD-621).

   Twin breaks one fence:
     CloseBeforePublish     CloseFlows runs before the policy swap
     NoRecheck              a flow whose dial completes does not re-read the generation
     StateDropsOverlay      a compiled state clears the denials above its pin
     LowerStateAccepted     a compile that finishes below the state in force replaces it
     RevokeAtZero           the judge's denial is held at the state's pin plus one, not at its own position
     ProviderBeforeCatchUp  after a restart the provider takes frames before the judge's denials are replayed
     ProviderBeforeHook     after a restart the provider takes frames before the hook is installed *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Rules, Flows, MaxLog, MaxCompiles, MaxRestarts, Judge, Twin

VARIABLES log,       \* the authorization log, as api sequenced it
          fetched,   \* durable: how far the device has fetched, verified and applied
          statePin,  \* durable: the pin of the compiled state in force
          overlay,   \* durable: positions of checkable revocations applied above the state
          mem,       \* volatile: the judge's denials, each [pos, rule]
          compiles,  \* volatile: the pins compiles in flight captured
          nc,        \* compiles started, to bound the run
          policy,    \* volatile: [gen, allow], what the hook reads
          closeQ,    \* volatile: rules whose CloseFlows is issued and has not run
          flows,     \* volatile: the NAT's flows
          restored,  \* the hook is installed with the restored state published
          caughtUp,  \* the judge's denials above the state are replayed since the last start
          up,        \* the provider takes frames
          restarts,
          badOpen    \* history: a flow passed its first byte while the published policy denied its rule

vars == <<log, fetched, statePin, overlay, mem, compiles, nc, policy, closeQ, flows, restored, caughtUp, up,
          restarts, badOpen>>

Entry == [rule : Rules, kind : {"grant", "revoke"}, chk : BOOLEAN]
Idle == [stage |-> "idle", rule |-> CHOOSE r \in Rules : TRUE, gen |-> 0]

Max(S) == CHOOSE x \in S : \A y \in S : y <= x
About(r, n) == {p \in 1..n : log[p].rule = r}
AllowedAt(r, n) == About(r, n) # {} /\ log[Max(About(r, n))].kind = "grant"
StateAllow(n) == {r \in Rules : AllowedAt(r, n)}

\* what the engine enforces from a state at sp with denials ov and mm on top
Enf(sp, ov, mm) == {r \in StateAllow(sp) : /\ ~\E p \in ov : log[p].rule = r
                                           /\ ~\E m \in mm : m.rule = r}

Kill(fl, lost, g) == [f \in Flows |-> IF /\ fl[f].stage \in {"dialing", "open"}
                                         /\ fl[f].rule \in lost
                                         /\ fl[f].gen < g
                                      THEN Idle ELSE fl[f]]

\* D-BRIDGE-21's order: swap the policy, generation g+1, then queue CloseFlows for what it no longer admits
Publish(newAllow) ==
  LET lost == policy.allow \ newAllow IN
  /\ policy' = [gen |-> policy.gen + 1, allow |-> newAllow]
  /\ IF Twin = "CloseBeforePublish"
     THEN /\ flows' = Kill(flows, lost, policy.gen)
          /\ closeQ' = closeQ
     ELSE /\ flows' = flows
          /\ closeQ' = closeQ \cup lost

Init ==
  /\ log = <<>> /\ fetched = 0 /\ statePin = 0 /\ overlay = {} /\ mem = {}
  /\ compiles = {} /\ nc = 0
  /\ policy = [gen |-> 1, allow |-> {}]
  /\ closeQ = {}
  /\ flows = [f \in Flows |-> Idle]
  /\ restored = TRUE /\ caughtUp = TRUE /\ up = TRUE
  /\ restarts = 0 /\ badOpen = FALSE

Sequence ==
  /\ Len(log) < MaxLog
  /\ \E e \in Entry :
       /\ e.kind = "grant" => e.chk = FALSE
       /\ log' = Append(log, e)
  /\ UNCHANGED <<fetched, statePin, overlay, mem, compiles, nc, policy, closeQ, flows, restored, caughtUp, up,
                 restarts, badOpen>>

\* fetch one entry, verify and persist it, and apply it: a denial at once, an opening not at all
Fetch ==
  /\ restored /\ fetched < Len(log)
  /\ LET n == fetched + 1
         e == log[n]
         ov == IF e.kind = "revoke" /\ e.chk THEN overlay \cup {n} ELSE overlay
         mm == IF e.kind = "revoke" /\ ~e.chk /\ Judge
               THEN mem \cup {[pos |-> IF Twin = "RevokeAtZero" THEN statePin + 1 ELSE n, rule |-> e.rule]}
               ELSE mem
     IN /\ fetched' = n
        /\ overlay' = ov
        /\ mem' = mm
        /\ Publish(Enf(statePin, ov, mm))
  /\ UNCHANGED <<log, statePin, compiles, nc, restored, caughtUp, up, restarts, badOpen>>

StartCompile ==
  /\ restored /\ nc < MaxCompiles
  /\ compiles' = compiles \cup {fetched}
  /\ nc' = nc + 1
  /\ UNCHANGED <<log, fetched, statePin, overlay, mem, policy, closeQ, flows, restored, caughtUp, up, restarts,
                 badOpen>>

\* a compile hands its state over: one below the state in force is dropped, and the denials above its pin stay
FinishCompile(c) ==
  /\ restored /\ c \in compiles
  /\ compiles' = compiles \ {c}
  /\ IF c < statePin /\ Twin # "LowerStateAccepted"
     THEN UNCHANGED <<statePin, overlay, mem, policy, closeQ, flows>>
     ELSE LET ov == IF Twin = "StateDropsOverlay" THEN {} ELSE {p \in overlay : p > c}
              mm == IF Twin = "StateDropsOverlay" THEN {} ELSE {m \in mem : m.pos > c}
          IN /\ statePin' = c
             /\ overlay' = ov
             /\ mem' = mm
             /\ Publish(Enf(c, ov, mm))
  /\ UNCHANGED <<log, fetched, nc, restored, caughtUp, up, restarts, badOpen>>

\* a queued CloseFlows runs, against the generation published when it runs
ExecClose(r) ==
  /\ r \in closeQ
  /\ closeQ' = closeQ \ {r}
  /\ flows' = Kill(flows, {r}, policy.gen)
  /\ UNCHANGED <<log, fetched, statePin, overlay, mem, compiles, nc, policy, restored, caughtUp, up, restarts,
                 badOpen>>

\* ResolveEgress: the decision and its generation are in hand, not yet registered
Resolve(f, r) ==
  /\ up /\ flows[f].stage = "idle"
  /\ r \in policy.allow \/ ~restored
  /\ flows' = [flows EXCEPT ![f] = [stage |-> "resolved", rule |-> r, gen |-> policy.gen]]
  /\ UNCHANGED <<log, fetched, statePin, overlay, mem, compiles, nc, policy, closeQ, restored, caughtUp, up,
                 restarts, badOpen>>

\* register: the decision is on the flow's sequence before its dial starts
Register(f) ==
  /\ flows[f].stage = "resolved"
  /\ flows' = [flows EXCEPT ![f].stage = "dialing"]
  /\ UNCHANGED <<log, fetched, statePin, overlay, mem, compiles, nc, policy, closeQ, restored, caughtUp, up,
                 restarts, badOpen>>

\* recheck: the dial completed; a newer generation re-resolves the flow before its first byte
Complete(f) ==
  /\ flows[f].stage = "dialing"
  /\ IF Twin = "NoRecheck" \/ flows[f].gen = policy.gen
     THEN /\ flows' = [flows EXCEPT ![f].stage = "open"]
          /\ badOpen' = (badOpen \/ flows[f].rule \notin policy.allow)
     ELSE /\ flows' = [flows EXCEPT ![f] = IF flows[f].rule \in policy.allow
                                           THEN [stage |-> "open", rule |-> flows[f].rule, gen |-> policy.gen]
                                           ELSE Idle]
          /\ badOpen' = badOpen
  /\ UNCHANGED <<log, fetched, statePin, overlay, mem, compiles, nc, policy, closeQ, restored, caughtUp, up,
                 restarts>>

End(f) ==
  /\ flows[f].stage = "open"
  /\ flows' = [flows EXCEPT ![f] = Idle]
  /\ UNCHANGED <<log, fetched, statePin, overlay, mem, compiles, nc, policy, closeQ, restored, caughtUp, up,
                 restarts, badOpen>>

\* the process dies: the NAT, the policy, the queued closes, the compiles and the judge's denials go with it
Restart ==
  /\ restarts < MaxRestarts
  /\ restarts' = restarts + 1
  /\ flows' = [f \in Flows |-> Idle]
  /\ compiles' = {} /\ mem' = {} /\ closeQ' = {}
  /\ policy' = [gen |-> 0, allow |-> {}]
  /\ overlay' = {p \in (statePin + 1)..fetched : log[p].kind = "revoke" /\ log[p].chk}
  /\ restored' = FALSE /\ caughtUp' = FALSE /\ up' = FALSE
  /\ UNCHANGED <<log, fetched, statePin, nc, badOpen>>

\* the posture restores and the hook is installed, which cancels every flow that holds no decision of it
Restore ==
  /\ ~restored
  /\ restored' = TRUE
  /\ policy' = [gen |-> 1, allow |-> Enf(statePin, overlay, {})]
  /\ closeQ' = {}
  /\ flows' = [f \in Flows |-> Idle]
  /\ UNCHANGED <<log, fetched, statePin, overlay, mem, compiles, nc, caughtUp, up, restarts, badOpen>>

\* the judge replays its verdicts for the entries above the state: every denial it holds durably applies again
CatchUp ==
  /\ restored /\ ~caughtUp
  /\ caughtUp' = TRUE
  /\ LET mm == IF Judge
               THEN mem \cup {[pos |-> p, rule |-> log[p].rule] :
                                p \in {q \in (statePin + 1)..fetched : log[q].kind = "revoke" /\ ~log[q].chk}}
               ELSE mem
     IN /\ mem' = mm
        /\ Publish(Enf(statePin, overlay, mm))
  /\ UNCHANGED <<log, fetched, statePin, overlay, compiles, nc, restored, up, restarts, badOpen>>

ProviderUp ==
  /\ ~up
  /\ \/ restored /\ caughtUp
     \/ restored /\ Twin = "ProviderBeforeCatchUp"
     \/ Twin = "ProviderBeforeHook"
  /\ up' = TRUE
  /\ UNCHANGED <<log, fetched, statePin, overlay, mem, compiles, nc, policy, closeQ, flows, restored, caughtUp,
                 restarts, badOpen>>

Next ==
  \/ Sequence \/ Fetch \/ StartCompile \/ Restart \/ Restore \/ CatchUp \/ ProviderUp
  \/ \E c \in compiles : FinishCompile(c)
  \/ \E r \in Rules : ExecClose(r)
  \/ \E f \in Flows : Register(f) \/ Complete(f) \/ End(f) \/ \E r \in Rules : Resolve(f, r)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
TypeOK ==
  /\ fetched \in 0..Len(log) /\ statePin \in 0..fetched
  /\ overlay \subseteq 1..fetched
  /\ \A m \in mem : m.pos \in 1..(MaxLog + 1) /\ m.rule \in Rules
  /\ compiles \subseteq 0..fetched
  /\ policy.allow \subseteq Rules /\ closeQ \subseteq Rules
  /\ \A f \in Flows : flows[f].stage \in {"idle", "resolved", "dialing", "open"}

\* the device durably knows r is revoked: a revocation it can apply, with no later grant inside the compiled state
KnownRevoked(r) ==
  \E p \in 1..fetched :
    /\ log[p].rule = r /\ log[p].kind = "revoke" /\ (log[p].chk \/ Judge)
    /\ ~\E q \in (p + 1)..statePin : log[q].rule = r /\ log[q].kind = "grant"

\* the dial fence: no flow passes its first byte while the published policy denies its rule
DialFence == ~badOpen

\* an open flow under a rule the policy denies exists only while its CloseFlows is queued
NoStaleFlow ==
  \A f \in Flows : flows[f].stage = "open" => flows[f].rule \in policy.allow \/ flows[f].rule \in closeQ

\* once the engine runs, what it publishes never admits a rule it durably knows is revoked
PolicySound ==
  (restored /\ caughtUp) => \A r \in policy.allow : ~KnownRevoked(r)

\* end to end: no open flow under a rule the device durably knows is revoked, but while its close is queued
FlowSound ==
  \A f \in Flows : flows[f].stage = "open" => ~KnownRevoked(flows[f].rule) \/ flows[f].rule \in closeQ

\* reach: the design does open flows, and does keep one across an unrelated publish
NoFlowOpens == \A f \in Flows : flows[f].stage # "open"
=============================================================================
