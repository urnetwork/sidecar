---------------------------- MODULE BridgeFold ----------------------------
(* DESIGN-DETAILS.md section 12: one body-level verdict at every reader that compiles, whatever base it started
   from (R-BRIDGE-3; section 5's principle carried to §17.8's sealed bodies).

   The log holds two kinds of entry. A filing is a bridge rule filed under an approval by one approver; whether
   that approval is spendable depends on the policy in force, which only config heads carry, and api cannot
   judge it, because the approval rides the rule's sealed body. A base names a config head: a policy (the
   approvers it makes eligible), a folded_through, and the head's bridge ledger, which holds the frozen verdict
   of every filing at or below folded_through.

   A reader that stands on the log judges a filing at its position, on the state the entry lands on, which is
   the newest base's rows with the entries since applied. At a base it takes the ledger for what the base
   folded and judges the base's tail again on the new base's rows, as section 5 re-applies a tail. A writer that
   folds freezes the verdicts it holds, which are the ones every reader standing under the previous base
   computed. A device that starts at a base takes the ledger and judges the tail on that base's rows.

   L is a reader present since the bootstrap, and the writer. N starts at any base. Section 5's fold rule holds:
   a base's folded_through is the previous base's, or at least the previous base's position.

   Twin breaks one rule:
     KeepOwnVerdict   a reader keeps the verdict it judged at a filing's position across a later base
     NewDeviceVoid    a device that starts at a base voids the tail's filings, having no state to judge them on
     NoLedger         a head carries no ledger, and a device that starts at a base judges every filing on its rows
     FreezeNewPolicy  a writer freezes what it folds by the policy of the head it is writing *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Approvers, MaxLog, Twin

VARIABLES log, L, N, checkFail

vars == <<log, L, N, checkFail>>

Positions == 1..MaxLog
NoVerdicts == [k \in Positions |-> FALSE]

IsFiling(k) == k \in 1..Len(log) /\ log[k].kind = "file"
IsBase(k) == k \in 1..Len(log) /\ log[k].kind = "base"

\* the bootstrap base makes every approver eligible and folds nothing
PolAt(b) == IF b = 0 THEN Approvers ELSE log[b].pol
FtAt(b) == IF b = 0 THEN 0 ELSE log[b].ft

Init ==
  /\ log = <<>>
  /\ L = [on |-> TRUE, pos |-> 0, base |-> 0, v |-> NoVerdicts]
  /\ N = [on |-> FALSE, pos |-> 0, base |-> 0, v |-> NoVerdicts]
  /\ checkFail = FALSE

\* api sequences a filing; nobody without the config key can judge its approval
File ==
  /\ Len(log) < MaxLog
  /\ \E a \in Approvers :
       log' = Append(log, [kind |-> "file", by |-> a, pol |-> {}, ft |-> 0, tab |-> NoVerdicts])
  /\ UNCHANGED <<L, N, checkFail>>

\* the writer, standing at the tip, publishes a base: a policy, a fold, and the ledger of what it folds
WriteBase ==
  /\ Len(log) < MaxLog /\ L.pos = Len(log)
  /\ \E pol \in SUBSET Approvers, ft \in {FtAt(L.base)} \cup (L.base..Len(log)) :
       LET frozen == [k \in Positions |->
                        IF ~IsFiling(k) \/ k > ft THEN FALSE
                        ELSE IF Twin = "FreezeNewPolicy" /\ k > FtAt(L.base) THEN log[k].by \in pol
                        ELSE L.v[k]]
       IN log' = Append(log, [kind |-> "base", by |-> CHOOSE a \in Approvers : TRUE, pol |-> pol, ft |-> ft,
                              tab |-> IF Twin = "NoLedger" THEN NoVerdicts ELSE frozen])
  /\ UNCHANGED <<L, N, checkFail>>

\* a reader applies the next entry
Step(r) ==
  LET n == r.pos + 1
      e == log[n]
  IN IF e.kind = "file"
     THEN [on |-> TRUE, pos |-> n, base |-> r.base, v |-> [r.v EXCEPT ![n] = e.by \in PolAt(r.base)]]
     ELSE [on |-> TRUE, pos |-> n, base |-> n,
           v |-> [k \in Positions |->
                    IF ~IsFiling(k) \/ k > n THEN FALSE
                    ELSE IF k <= e.ft THEN (IF Twin = "NoLedger" THEN r.v[k] ELSE e.tab[k])
                    ELSE IF Twin = "KeepOwnVerdict" THEN r.v[k]
                    ELSE log[k].by \in e.pol]]

\* whether a reader that applies the base at its next position finds the ledger other than its own verdicts
Differs(r) ==
  /\ r.pos < Len(log) /\ log[r.pos + 1].kind = "base" /\ Twin # "NoLedger"
  /\ \E k \in Positions : IsFiling(k) /\ k <= log[r.pos + 1].ft /\ r.v[k] # log[r.pos + 1].tab[k]

StepL ==
  /\ L.on /\ L.pos < Len(log)
  /\ checkFail' = (checkFail \/ Differs(L))
  /\ L' = Step(L)
  /\ UNCHANGED <<log, N>>

StepN ==
  /\ N.on /\ N.pos < Len(log)
  /\ checkFail' = (checkFail \/ Differs(N))
  /\ N' = Step(N)
  /\ UNCHANGED <<log, L>>

\* a new device starts at base b: the ledger for what b folded, and b's tail judged on b's rows
Join(b) ==
  /\ ~N.on /\ IsBase(b)
  /\ N' = [on |-> TRUE, pos |-> b, base |-> b,
           v |-> [k \in Positions |->
                    IF ~IsFiling(k) \/ k > b THEN FALSE
                    ELSE IF k <= log[b].ft
                         THEN (IF Twin = "NoLedger" THEN log[k].by \in log[b].pol ELSE log[b].tab[k])
                    ELSE IF Twin = "NewDeviceVoid" THEN FALSE
                    ELSE log[k].by \in log[b].pol]]
  /\ UNCHANGED <<log, L, checkFail>>

Next == File \/ WriteBase \/ StepL \/ StepN \/ \E b \in Positions : Join(b)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
TypeOK ==
  /\ L.pos \in 0..Len(log) /\ N.pos \in 0..Len(log)
  /\ L.base \in 0..L.pos /\ N.base \in 0..N.pos

\* two readers at one position hold one verdict for every filing
Equal == (L.on /\ N.on /\ L.pos = N.pos) => L.v = N.v

\* a reader that holds verdicts for what a base folds finds the base's ledger equal to them
LedgerChecks == ~checkFail

\* a verdict, once folded, is the same in every later ledger
FoldedStays ==
  \A b1, b2 \in Positions :
    (IsBase(b1) /\ IsBase(b2) /\ b1 < b2 /\ Twin # "NoLedger") =>
      \A k \in Positions : (IsFiling(k) /\ k <= log[b1].ft) => log[b2].tab[k] = log[b1].tab[k]

\* reach: a base's policy does turn a filing's verdict while it is unfolded, the case 12.2.3 states
\* (L holds a filing true, and a base that does not fold it makes it false)
NoTurn ==
  \A k \in Positions :
    (IsFiling(k) /\ k <= L.pos /\ L.base > k /\ k > FtAt(L.base)) =>
      (L.v[k] = (log[k].by \in PolAt(0)))
=============================================================================
