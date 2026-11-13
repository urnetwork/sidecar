---------------------------- MODULE PrefixRules ----------------------------
(* DESIGN-DETAILS.md section 16: client-checked prefix write rules on one file-mode ref of one repo.

   The authorization log holds RepoPrefixRules statements (sets), bases, and, under one twin only, changes of a
   group's membership. A set says what the writers it names may write: every path (open), the path "in" alone
   (inOnly), or nothing (closed). No set in force is open. A is a repo admin's device, which every set names for
   every path, as the command that files a set writes it. B and W are the writers the sets hold to their paths:
   B runs the design's code, W any code at all.

   The ref holds pushes, each one change: a signer, the auth pin it carries, the log's length when evs committed
   it (at), a path, what it does to the path's content (write, remove, keep), what its parent's delta does to the
   path's row (add, remove, none), and for a write its lineage: the versions whose bytes its record chain rests
   on, its own included. evs holds a push's pin at or above the head's (§11.8's fence row) and folds every row
   into its name table, since it sees no path.

   A reader's verdict on a push is the design's one function: the newest set at or below the push's pin, read
   from the positions the rows keep for the repo's life, allows the signer the path. Readers are the long-running
   full reader (0) and a device started at each base b, which holds the rows of b and the entries after it.

   Derived from the ref and the verdicts, never stored:
     EffC(X)       the newest allowed content event of X: what every reader shows, and what a writer builds on
     MList(X)      X's row at a mirror, which folds only allowed rows from the ref's first version
     HList(X, v)   X's row at a head reader whose first pin is version v: evs's table at v, taken on evs's word
                   (§11.9's trusts row), then the allowed rows after v

   A design device that writes a path whose newest event it ignores writes a repair: a checkpoint built on the
   effective version, with the path's row stated again. Repair is the same push with no edit.

   Twin breaks one rule:
     NoCheck           a reader shows evs's newest version (no rule is checked: ACL-M6-04 unbuilt)
     NewestOnly        the rows keep only the newest set, as RepoVersioning's lock is kept
     JudgeAtTip        a reader judges a push in the state at its own tip, not at the push's pin
     HeadAtoms         a set's subject is a group whose members a head gives, judged in the oldest state held
     DiffOnNewest      a writer builds its record chain on evs's newest version, ignored or not
     NoHeadFence       evs takes a push whose pin is below the head's
     RepairSkipsNames  a repair writes content and no row *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS MaxLog, MaxRef, RuleSets, Honest, Twin

ASSUME Twin \in {"none", "NoCheck", "NewestOnly", "JudgeAtTip", "HeadAtoms", "DiffOnNewest", "NoHeadFence", "RepairSkipsNames"}
ASSUME RuleSets \subseteq {"open", "inOnly", "closed"}
ASSUME Honest \subseteq {"A", "B"}

VARIABLES log, ref

vars == <<log, ref>>

Paths == {"in", "out"}

Max(S) == CHOOSE x \in S : \A y \in S : y <= x
MaxOr0(S) == IF S = {} THEN 0 ELSE Max(S)

\* what a set lets B and W write; A it names for every path
May(rules) == IF rules = "open" THEN Paths ELSE IF rules = "inOnly" THEN {"in"} ELSE {}

Tip == Len(log)
IsSet(i) == log[i].kind = "set"
Bases == {i \in 1..Len(log) : log[i].kind = "base"}

\* 0: the long-running full reader. b: a device started at the base at position b.
Readers == {0} \cup Bases

\* the positions of the repo's sets a reader knows: the rows' list for the repo's life, and the entries after its base
Known(r) ==
  LET all == {i \in 1..Len(log) : IsSet(i)}
      before == {i \in all : i <= r}
  IN IF r = 0 \/ Twin # "NewestOnly" THEN all
     ELSE (IF before = {} THEN {} ELSE {Max(before)}) \cup {i \in all : i > r}

SetPos(r, p) == MaxOr0({i \in Known(r) : i <= p})
InForce(r, p) == IF SetPos(r, p) = 0 THEN "open" ELSE log[SetPos(r, p)].rules

\* the state a reader judges a push in
JudgedAt(r, u) == IF Twin = "JudgeAtTip" THEN (IF r = 0 THEN u.at ELSE Tip) ELSE u.pin

\* twin HeadAtoms: the writers are in the set's group until a regroup, out until the next; a device started at a
\* base holds no state below it and reads the group there
InGroup(p) == Cardinality({i \in 1..p : log[i].kind = "regroup"}) % 2 = 0
GroupSeen(r, u) == IF Twin # "HeadAtoms" THEN TRUE ELSE InGroup(IF r = 0 \/ u.pin >= r THEN u.pin ELSE r)

Allows(r, u) ==
  \/ u.signer = "A"
  \/ u.path = "-"
  \/ GroupSeen(r, u) /\ u.path \in May(InForce(r, JudgedAt(r, u)))

Good(j) == Allows(0, ref[j])

Ev(X) == {j \in 1..Len(ref) : ref[j].path = X}
CEv(X) == {j \in Ev(X) : ref[j].content # "keep"}
NewestC(X) == MaxOr0(CEv(X))
EffC(X) == MaxOr0({j \in CEv(X) : Good(j)})
Stands(j) == j # 0 /\ ref[j].content = "write"
Present(X) == Stands(EffC(X))
Dirty(X) == Ev(X) # {} /\ ~Good(Max(Ev(X)))
LinOf(j) == IF Stands(j) THEN ref[j].lineage ELSE {}
HeadPin == IF ref = <<>> THEN 0 ELSE ref[Len(ref)].pin

\* what a writer builds a new record chain on
BaseOf(X) == IF Twin = "DiffOnNewest" THEN NewestC(X) ELSE EffC(X)

Cand(s, pin, X, c, row, lin, honest, assert) ==
  [signer |-> s, pin |-> pin, at |-> Tip, path |-> X, content |-> c, row |-> row, lineage |-> lin,
   honest |-> honest, assert |-> assert]

Init == log = <<>> /\ ref = <<>>

\* ---- the log

File(rules) ==
  /\ Len(log) < MaxLog
  /\ log' = Append(log, [kind |-> "set", rules |-> rules])
  /\ UNCHANGED ref

Base ==
  /\ Len(log) < MaxLog
  /\ log' = Append(log, [kind |-> "base", rules |-> "-"])
  /\ UNCHANGED ref

Regroup ==
  /\ Twin = "HeadAtoms"
  /\ Len(log) < MaxLog
  /\ log' = Append(log, [kind |-> "regroup", rules |-> "-"])
  /\ UNCHANGED ref

\* ---- a design device: it pins its tip, refuses locally what the state at that pin does not allow it, builds on
\* the effective version, and states the row again where the newest event is one it ignores

HonestWrite(s, X) ==
  /\ Len(ref) < MaxRef
  /\ LET dirty == Dirty(X)
         row == IF ~Present(X) THEN "add" ELSE IF dirty /\ Twin # "RepairSkipsNames" THEN "add" ELSE "none"
         u == Cand(s, Tip, X, "write", row, LinOf(BaseOf(X)) \cup {Len(ref) + 1}, TRUE, dirty)
     IN /\ Allows(0, u)
        /\ ref' = Append(ref, u)
  /\ UNCHANGED log

HonestRemove(s, X) ==
  /\ Len(ref) < MaxRef
  /\ Present(X)
  /\ LET u == Cand(s, Tip, X, "remove", "remove", {}, TRUE, Dirty(X))
     IN /\ Allows(0, u)
        /\ ref' = Append(ref, u)
  /\ UNCHANGED log

\* the effective state written again over an ignored event, with no edit
Repair(s, X) ==
  /\ Len(ref) < MaxRef
  /\ Dirty(X)
  /\ LET c == IF NewestC(X) = EffC(X) THEN "keep" ELSE IF Present(X) THEN "write" ELSE "remove"
         row == IF Twin = "RepairSkipsNames" THEN "none" ELSE IF Present(X) THEN "add" ELSE "remove"
         u == Cand(s, Tip, X, c, row, IF c = "write" THEN LinOf(EffC(X)) ELSE {}, TRUE, TRUE)
     IN /\ c # "keep" \/ row # "none"
        /\ Allows(0, u)
        /\ ref' = Append(ref, u)
  /\ UNCHANGED log

\* the push of no change that carries the filer's pin onto the ref
PinPush ==
  /\ "A" \in Honest
  /\ Len(ref) < MaxRef
  /\ HeadPin < Tip
  /\ ref' = Append(ref, Cand("A", Tip, "-", "keep", "none", {}, TRUE, FALSE))
  /\ UNCHANGED log

\* ---- W: any change, any row, any pin evs takes

Shapes == {<<"write", "add">>, <<"write", "none">>, <<"remove", "remove">>, <<"keep", "remove">>, <<"keep", "add">>}

WPush(X, shape, pin) ==
  /\ Len(ref) < MaxRef
  /\ pin \in (IF Twin = "NoHeadFence" THEN 0 ELSE HeadPin)..Tip
  /\ ref' = Append(ref, Cand("W", pin, X, shape[1], shape[2], IF shape[1] = "write" THEN {Len(ref) + 1} ELSE {},
                             FALSE, FALSE))
  /\ UNCHANGED log

Next ==
  \/ \E rules \in RuleSets : File(rules)
  \/ Base
  \/ Regroup
  \/ \E s \in Honest, X \in Paths : HonestWrite(s, X) \/ HonestRemove(s, X) \/ Repair(s, X)
  \/ PinPush
  \/ \E X \in Paths, shape \in Shapes, pin \in 0..MaxLog : WPush(X, shape, pin)

Spec == Init /\ [][Next]_vars

\* ---- invariants

TypeOK ==
  /\ Len(log) <= MaxLog
  /\ Len(ref) <= MaxRef
  /\ \A i \in 1..Len(log) : log[i].kind \in {"set", "base", "regroup"}
  /\ \A j \in 1..Len(ref) : ref[j].pin <= ref[j].at /\ ref[j].lineage \subseteq 1..j

\* every reader, wherever it started, reaches the long-running reader's verdict on every push
Agreement == \A r \in Readers : \A j \in 1..Len(ref) : Allows(r, ref[j]) = Good(j)

\* a design device's push is never ignored: what it refused locally is what readers refuse
HonestStands == \A j \in 1..Len(ref) : ref[j].honest => Good(j)

\* what a reader shows of a path is a version its rules allowed
Shown(X) == IF Twin = "NoCheck" THEN NewestC(X) ELSE EffC(X)
ShownAllowed == \A X \in Paths : Shown(X) # 0 => Good(Shown(X))

\* no byte of an ignored version is in what a reader shows
CleanLineage == \A X \in Paths : Present(X) => \A j \in ref[EffC(X)].lineage : Good(j)

\* a later push is never judged under an older set than an earlier push of the ref
Fence == \A i, j \in 1..Len(ref) : i < j => SetPos(0, ref[i].pin) <= SetPos(0, ref[j].pin)

RowEv(X, S) == {j \in S : ref[j].path = X /\ ref[j].row # "none"}
Listed(S) == S # {} /\ ref[Max(S)].row = "add"
EvsTable(X, v) == Listed(RowEv(X, 1..v))
MList(X) == Listed({j \in RowEv(X, 1..Len(ref)) : Good(j)})
HList(X, v) ==
  LET later == {j \in RowEv(X, (v + 1)..Len(ref)) : Good(j)}
  IN IF later = {} THEN EvsTable(X, v) ELSE Listed(later)

LastIgnored(X) == MaxOr0({j \in Ev(X) : ~Good(j)})
Repaired(X) == LastIgnored(X) = 0 \/ \E j \in Ev(X) : j > LastIgnored(X) /\ ref[j].assert

\* once a design device has written a path after its last ignored event, a head reader that starts anywhere lists
\* the path as a mirror does
ListingAfterRepair == \A X \in Paths : Repaired(X) => \A v \in 0..Len(ref) : HList(X, v) = MList(X)

\* ---- states the design must reach, each as the invariant that says it never does

NeverIgnored == \A j \in 1..Len(ref) : Good(j)

NeverWalkedBack == \A X \in Paths : EffC(X) = NewestC(X)

\* a push by W that readers allow though the set in force when evs committed it forbade it: an old pin
NeverStalePin ==
  \A j \in 1..Len(ref) : (ref[j].signer = "W" /\ Good(j)) => ref[j].path \in May(InForce(0, ref[j].at))

\* a head reader and a mirror list a path differently
NeverHidden == \A X \in Paths : \A v \in 0..Len(ref) : HList(X, v) = MList(X)

NeverRepaired == \A X \in Paths : LastIgnored(X) = 0 \/ ~Repaired(X)

\* a writer the sets name is allowed a path under one set and refused it under the next
NeverTightened ==
  \A i, j \in 1..Len(ref) :
    (i < j /\ ref[i].signer = "B" /\ ref[j].signer = "W" /\ ref[i].path = ref[j].path /\ Good(i)) => Good(j)
=============================================================================
