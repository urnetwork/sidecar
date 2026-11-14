---------------------------- MODULE BridgeVoid ----------------------------
(* DESIGN-DETAILS.md section 12.2.3 as amended for QD-761: a bridge body sealed to a generation that does not form
   is frozen void at the fold, and every reader still holds one verdict.

   The log holds filings and bases, each with the time api sequenced it at. A filing's sealed body names a
   generation of the config repo. An honest filer seals to a generation it holds, so one gkm has formed. Any
   standing sidecar can seal to a generation above every formed one: with bytes no key opens (junk, sealed here
   to MaxGen + 1, which never forms), or under a key it made beforehand and means to claim that generation with
   (pre). gkm forms generations in order, each by an honest rotator or by that sidecar with its key, and holds
   a GenRotate's time within Skew of its clock.

   A reader judges a filing where it holds the body's generation: pending while it does not, void where the seal
   does not open, void where the generation's GenRotate is more than Grace after the filing's entry (no such
   generation at its entry), else valid. BridgeFold.tla has the approval's verdict; here an opened body is valid.

   A writer at its tip publishes a base. Its fold stops below the first filing it holds pending, except that
   it freezes void a pending filing sealed above every generation gkm names when a fresh read shows it holds
   them all and the tip's entry is at least its wait after the filing's. A checker that holds a pending filing
   at or below the fold takes the head's rows unchecked; one that holds none compares.

   Readers: w1 and w2, both full readers and writers, with waits of their own. w1 stands at the tip: it applies
   each entry before anything else happens. w2 may fall behind in the log, and either may fall behind in the
   generations it holds, so each is the other's checker and w2 the reader that gains a generation late. Every
   reader holds generations 1..held, as the ladder gives them. A device that starts at a base takes its rows
   and is BridgeFold.tla's N; rule ids are not modelled, each filing being its own.

   Twin breaks one rule:
     Landed        no void: the fold stops below every pending filing, the code as it stood
     NoGrace       a reader that gains the generation judges the body with no regard to when it formed
     NoWait        the writer voids with no wait
     StaleRead     the writer judges "above every generation gkm names" on a listing it read earlier
     CheckerVoids  a checker applies the wait itself to a filing it holds pending, and compares *)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS MaxLog, MaxGen, MaxTime, Wait1, Wait2, Grace, Skew, Twin

VARIABLES log, now, formed, rd, seen, checkFail, unchecked

vars == <<log, now, formed, rd, seen, checkFail, unchecked>>

Readers == {"w1", "w2"}
Positions == 1..MaxLog
NoRows == [k \in Positions |-> "none"]

WaitOf(w) == IF w = "w1" THEN Wait1 ELSE Wait2

\* the generations gkm names: formed is a sequence of [at, by], generation g the g-th
G == Len(formed)

IsFiling(k) == k \in 1..Len(log) /\ log[k].kind = "file"
IsBase(k) == k \in 1..Len(log) /\ log[k].kind = "base"
FtAt(b) == IF b = 0 THEN 0 ELSE log[b].ft

Min(S) == CHOOSE x \in S : \A y \in S : x <= y

Init ==
  /\ log = <<>>
  /\ now = 0
  /\ formed = << [at |-> 0, by |-> "honest"] >>
  /\ rd = [x \in Readers |-> [pos |-> 0, base |-> 0, held |-> 1, v |-> NoRows]]
  /\ seen = [w \in Readers |-> 1]
  /\ checkFail = FALSE
  /\ unchecked = FALSE

Tick ==
  /\ now < MaxTime
  /\ now' = now + 1
  /\ UNCHANGED <<log, formed, rd, seen, checkFail, unchecked>>

Filing(gen, key) ==
  [kind |-> "file", gen |-> gen, key |-> key, t |-> now, by |-> "w1", ft |-> 0, tab |-> NoRows, top |-> 0,
   complete |-> FALSE, tipT |-> 0, prev |-> 0]

\* api sequences a filing; it reads the body's generation and bounds nothing
File ==
  /\ Len(log) < MaxLog
  /\ \/ log' = Append(log, Filing(G, "ok"))
     \/ log' = Append(log, Filing(MaxGen + 1, "junk"))
     \/ \E g \in (G + 1)..MaxGen : log' = Append(log, Filing(g, "pre"))
  /\ UNCHANGED <<now, formed, rd, seen, checkFail, unchecked>>

\* gkm takes the next generation's claim, its GenRotate's time within Skew of now
Rotate ==
  /\ G < MaxGen
  /\ \E who \in {"honest", "attacker"}, at \in (now - Skew)..(now + Skew) :
       /\ at >= 0
       /\ formed' = Append(formed, [at |-> at, by |-> who])
  /\ UNCHANGED <<log, now, rd, seen, checkFail, unchecked>>

\* whether a filing's seal opens under its generation's key, once that generation has formed
Opens(k) == log[k].key = "ok" \/ (log[k].key = "pre" /\ formed[log[k].gen].by = "attacker")

\* JudgeBridgeBody's part that reads generations, at a reader holding 1..held
Judge(held, k) ==
  IF log[k].gen > held THEN "pending"
  ELSE IF ~Opens(k) THEN "void"
  ELSE IF Twin # "NoGrace" /\ formed[log[k].gen].at > log[k].t + Grace THEN "void"
  ELSE "valid"

\* a reader gains its next generation and judges the filings it held pending (RejudgeBridgeBodies)
Deliver(x) ==
  /\ rd[x].held < G
  /\ LET held == rd[x].held + 1
     IN rd' = [rd EXCEPT ![x] = [@ EXCEPT !.held = held,
                 !.v = [k \in Positions |->
                          IF IsFiling(k) /\ k <= rd[x].pos /\ rd[x].v[k] = "pending" THEN Judge(held, k)
                          ELSE rd[x].v[k]]]]
  /\ UNCHANGED <<log, now, formed, seen, checkFail, unchecked>>

\* a writer reads gkm's listing; only the StaleRead twin plans on what it remembers
Read(w) ==
  /\ Twin = "StaleRead" /\ seen[w] # G
  /\ seen' = [seen EXCEPT ![w] = G]
  /\ UNCHANGED <<log, now, formed, rd, checkFail, unchecked>>

\* FoldBridgeLedger inside a writer's plan, at its tip
WriteBase(w) ==
  /\ rd[w].pos = Len(log) /\ 0 < Len(log) /\ Len(log) < MaxLog
  /\ LET me == rd[w]
         tip == Len(log)
         ftPrev == FtAt(me.base)
         top == IF Twin = "StaleRead" THEN seen[w] ELSE G
         complete == me.held >= top
         tipT == log[tip].t
         Overdue(k) == /\ Twin # "Landed"
                       /\ complete /\ log[k].gen > top
                       /\ (Twin = "NoWait" \/ tipT - log[k].t >= WaitOf(w))
         stops == {k \in (ftPrev + 1)..tip : IsFiling(k) /\ me.v[k] = "pending" /\ ~Overdue(k)}
         reach == IF stops = {} THEN tip ELSE Min(stops) - 1
         ft == IF reach = ftPrev \/ reach >= me.base THEN reach ELSE ftPrev
         tab == [k \in Positions |->
                   IF ~IsFiling(k) \/ k > ft THEN "none"
                   ELSE IF me.v[k] = "pending" THEN "void" ELSE me.v[k]]
     IN /\ \E k \in (ftPrev + 1)..tip : IsFiling(k)
        /\ log' = Append(log, [kind |-> "base", gen |-> 0, key |-> "none", t |-> now, by |-> w, ft |-> ft,
                               tab |-> tab, top |-> top, complete |-> complete, tipT |-> tipT, prev |-> me.base])
  /\ UNCHANGED <<now, formed, rd, seen, checkFail, unchecked>>

\* the filings a base folds that reader x held unfolded
Folded(x, e) == {k \in (FtAt(rd[x].base) + 1)..e.ft : IsFiling(k)}

\* a checker's own verdict; under the CheckerVoids twin, the wait applied to what it lacks
Own(x, e, k) ==
  IF Twin = "CheckerVoids" /\ rd[x].v[k] = "pending" /\ e.tipT - log[k].t >= Wait1 THEN "void"
  ELSE rd[x].v[k]

\* CheckBridgeLedgerFold: unchecked where the reader holds a pending filing at or below the fold
Unchecked(x, e) == \E k \in Folded(x, e) : Own(x, e, k) = "pending"
Differs(x, e) == ~Unchecked(x, e) /\ \E k \in Folded(x, e) : Own(x, e, k) # e.tab[k]

\* a reader applies the next entry
Step(x) ==
  /\ rd[x].pos < Len(log)
  /\ LET n == rd[x].pos + 1
         e == log[n]
     IN IF e.kind = "file"
        THEN /\ rd' = [rd EXCEPT ![x] = [@ EXCEPT !.pos = n, !.v = [@ EXCEPT ![n] = Judge(rd[x].held, n)]]]
             /\ UNCHANGED <<checkFail, unchecked>>
        ELSE /\ checkFail' = (checkFail \/ Differs(x, e))
             /\ unchecked' = (unchecked \/ Unchecked(x, e))
             /\ rd' = [rd EXCEPT ![x] = [@ EXCEPT !.pos = n, !.base = n,
                         !.v = [k \in Positions |-> IF k <= e.ft THEN e.tab[k] ELSE rd[x].v[k]]]]
  /\ UNCHANGED <<log, now, formed, seen>>

\* w1 applies an entry as soon as it is sequenced
AtTip == rd["w1"].pos = Len(log)

Next ==
  \/ Step("w1")
  \/ AtTip /\ (Tick \/ File \/ Rotate \/ Step("w2") \/ \E x \in Readers : Deliver(x) \/ Read(x) \/ WriteBase(x))

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
TypeOK ==
  /\ now \in 0..MaxTime /\ G \in 1..MaxGen
  /\ \A x \in Readers : rd[x].pos \in 0..Len(log) /\ rd[x].base \in 0..rd[x].pos /\ rd[x].held \in 1..G
  /\ \A k \in 1..Len(log) : log[k].gen \in 0..(MaxGen + 1) /\ log[k].ft \in 0..(k - 1)

\* no checker that could compare finds a base's rows other than its own verdicts: no FORK on an honest writer
NoFork == ~checkFail

\* two readers at one position that have both judged a filing hold one verdict for it
Equal ==
  \A x, y \in Readers :
    rd[x].pos = rd[y].pos =>
      \A k \in Positions :
        (IsFiling(k) /\ k <= rd[x].pos /\ rd[x].v[k] # "pending" /\ rd[y].v[k] # "pending") => rd[x].v[k] = rd[y].v[k]

\* a row, once folded, is the same in every later ledger, and no row is pending
FoldedStays ==
  \A b1, b2 \in Positions :
    (IsBase(b1) /\ IsBase(b2) /\ b1 < b2) =>
      \A k \in Positions : (IsFiling(k) /\ k <= log[b1].ft) => log[b2].tab[k] = log[b1].tab[k]
NoPendingRow == \A b, k \in Positions : IsBase(b) => log[b].tab[k] # "pending"

\* the stall is bounded: a writer that held every generation gkm named, publishing when every filing sealed
\* above them had waited out its wait, folded through its tip
Bounded ==
  \A b \in Positions :
    (IsBase(b) /\ log[b].complete
       /\ \A k \in (FtAt(log[b].prev) + 1)..(b - 1) :
            (IsFiling(k) /\ log[k].gen > log[b].top) => log[b].tipT - log[k].t >= WaitOf(log[b].by))
    => log[b].ft = b - 1

\* a frozen void is one every reader that comes to hold the body's generation judges void too
VoidsAgree ==
  \A b, k \in Positions :
    (IsBase(b) /\ IsFiling(k) /\ k <= log[b].ft /\ log[b].tab[k] = "void" /\ log[k].gen <= G) =>
      Judge(log[k].gen, k) = "void"

\* an honest filing, sealed to a generation formed before it, is never void for its generation
HonestValid ==
  \A k \in Positions : (IsFiling(k) /\ log[k].key = "ok") => Judge(log[k].gen, k) = "valid"

\* reach: the design does freeze a void for a generation gkm does not name
NoVoid ==
  \A b, k \in Positions :
    (IsBase(b) /\ IsFiling(k) /\ k <= log[b].ft /\ log[b].tab[k] = "void") => log[k].gen <= log[b].top
\* reach: a generation does form after its filing was frozen void, under the key the filing was sealed with
NoLateForm ==
  \A b, k \in Positions :
    (IsBase(b) /\ IsFiling(k) /\ k <= log[b].ft /\ log[b].tab[k] = "void" /\ log[k].gen > log[b].top) =>
      ~(log[k].gen <= G /\ Opens(k))
\* reach: a checker does take a base's rows unchecked
NoUnchecked == ~unchecked
\* reach: a fold does hold below a filing that has waited out its wait, where a younger one sits at or below the
\* previous base: section 5's rule (the previous fold, or at least the previous base) lets it stop nowhere between
NoHeld ==
  \A b, k \in Positions :
    (IsBase(b) /\ IsFiling(k) /\ k < b /\ log[b].complete /\ log[k].gen > log[b].top
       /\ log[b].tipT - log[k].t >= WaitOf(log[b].by))
    => k <= log[b].ft
=============================================================================
