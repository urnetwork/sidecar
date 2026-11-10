-------------------------------- MODULE Gkm --------------------------------
(***************************************************************************)
(* DESIGN-DETAILS.md section 6: the gkm flows of one repo A (§10), as      *)
(* every device runs them against one strongly consistent store. The      *)
(* store's objects are the only shared state: the epoch chain, the        *)
(* generation chain with its staged deliveries, late deliveries, Welcomes  *)
(* and their pointers. Devices keep their own verified log position (tip), *)
(* the epoch they adopted and what they sealed; what a device can open is  *)
(* derived from the store (Reach), never stored, so a party that fetches   *)
(* everything, as a removed device colluding with the server can, opens    *)
(* exactly what the invariants say it may.                                  *)
(*                                                                          *)
(* The authorization log is a sequence of admissions, revocations and      *)
(* expiries, applied alike by every verifier (section 5 gives agreement);  *)
(* its position is the clock. A device judges every commit, claim and      *)
(* delivery at the object's own pin and waits while its tip is below it.   *)
(*                                                                          *)
(* Sidecars: a the creator and a writer leaf, b a writer leaf, c a         *)
(* read_only leaf (a page Worker), d an agent that reads by ReaderWraps    *)
(* and rotates but never commits, e the device a member's recovery code    *)
(* admits, which also plays the squatter: a reader of A that is admin of   *)
(* another repo B. Deliveries to a holder abstract the ReaderKey it holds; *)
(* the recovery binding is a holder of every generation (D-KEYS-9).        *)
(*                                                                          *)
(* Twin names a rule to break; "none" is the design. "PointerByRef",       *)
(* "FormsUnchecked" and "GenWrapIgnoresRoster" are §10 as written on       *)
(* 2026-11-09 (6.1's three failures); "SelfJoinCarriesGenWrap",            *)
(* "LateBelowClaimPin", "ClaimBelowParent", "LeafWrapDirtyTree" and        *)
(* "NoGate" each break one rule of the design. Story fixes the actions of  *)
(* a run, so a twin's violation is reached directly; the design runs with  *)
(* no story. The tasks' twins (6.6): "AddWithoutRemove" (KEYS-M2-21) has   *)
(* an Add commit leave a dropped leaf; "StagedToNonHolder" (KEYS-M2-20)    *)
(* has a rotation stage a delivery to a party outside its holder set;      *)
(* "AdoptNonCoveringWinner" (KEYS-M2-20) has a writer seal to another      *)
(* rotator's generation that does not cover the shrink it knows;           *)
(* "FormWithoutMarker" (KEYS-M2-25) has a re-form's GroupForm filed with   *)
(* no owner marker written first, so B's re-form naming A's group stands   *)
(* as an unchecked form does.                                              *)
(*                                                                          *)
(* The poison rule (6.2.3, §10.9; question keys-m2-19-members-skip-roster- *)
(* twin, QD-644). Hostile names leaves that may inject one commit no       *)
(* honest leaf makes: its tree holds a party dropped at its own header and *)
(* its GenWrap carries the newest generation. The store invariants cannot  *)
(* hold past it, since the dropped party opens that generation the moment  *)
(* the commit stands. What a member's refusal buys is modeled instead:     *)
(* poisoned holds, per device, the generations it refused a commit for,    *)
(* Seal never takes one of them, and NoContentPastRefusal says nothing a   *)
(* device seals after its refusal opens to a party dropped at the seal's   *)
(* state. "MembersSkipRosterCheck" (KEYS-M2-19) has members adopt the      *)
(* injected commit and seal on to the generation it carried.               *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    MaxLog,       \* entries in one behavior
    MaxEpochs,    \* epoch objects in one behavior, epoch 0 included
    MaxGens,      \* generations in one behavior
    MaxSeals,     \* content writes in one behavior
    Writers,      \* sidecars that write A in every state they are admitted
    ReadOnly,     \* read_only member devices: leaves that commit only a path
    Agents,       \* wrapped readers: never leaves, rotate but never commit
    Recovered,    \* the device the member's recovery code admits
    Squatter,     \* a reader of A that is admin of repo B
    InitReaders,  \* admitted before the first entry
    InitLeaves,   \* leaves beside the creator at Init, added at epoch 1
    WithB,        \* repo B adds devices too (the Welcome pointer twin)
    Losers,       \* member devices that may lose their group state
    StaleTargets, \* leaves a writer may remove as stale
    Hostile,      \* leaves that may inject one commit that breaks the roster rule
    Story,        \* <<>>, or the pattern each action must match in turn
    Twin          \* "none", or the rule a twin breaks

Sidecars == {"a", "b", "c", "d", "e"}
Creator == "a"
MemberDevices == Sidecars \ Agents

Max(S) == IF S = {} THEN 0 ELSE CHOOSE x \in S : \A y \in S : y <= x

VARIABLES
    log,       \* the authorization log: [k, s]
    tip,       \* each sidecar's verified position
    epochs,    \* gkm/<A>/epoch/<n>, index n+1: [c, roster, gen, auth, time, k]
    gens,      \* gkm/<A>/gen/<g>, index g: [r, holders, auth, time, wraps, leafEpoch]
    late,      \* LATE deliveries: [g, r]
    welcomes,  \* Welcomes with their pointer: [grp, epoch, r, key, lost]
    kp,        \* one-time KeyPackages a member device has at gkm
    at,        \* the epoch index a device adopted; 0 with no group state
    reached,   \* the newest epoch index a device ever adopted (I-16)
    sealed,    \* content writes: [g, n, j], j when its sealer had refused an injected commit
    squat,     \* repo B's newest form names A's group
    epochB,    \* repo B's newest epoch, for its Welcomes
    poisoned,  \* the generations each device refused a commit for and never seals to again
    step       \* the story's next action

vars == <<log, tip, epochs, gens, late, welcomes, kp, at, reached, sealed, squat, epochB, poisoned, step>>

(***************************************************************************)
(* The log and the sets every verifier derives from it.                    *)
(***************************************************************************)
Clock == Len(log)
Admitted(n) == {s \in Sidecars :
                  /\ \/ s \in InitReaders
                     \/ \E i \in 1..n : log[i].k \in {"admit", "radmit"} /\ log[i].s = s
                  /\ ~\E j \in 1..n : log[j].k = "revoke" /\ log[j].s = s}
Expired(c) == {s \in Sidecars : \E i \in 1..c : log[i].k = "expire" /\ log[i].s = s}
Readers(n, c) == Admitted(n) \ Expired(c)
\* holders_shrunk_at and the newest expiry, as a verifier at (n, c) sees them
ShrunkAt(n) == Max({i \in 1..n : log[i].k = "revoke"})
LastExpiry(c) == Max({i \in 1..c : log[i].k = "expire"})
Dropped(s, n, c) == (\E j \in 1..n : log[j].k = "revoke" /\ log[j].s = s) \/ s \in Expired(c)
\* §7.9's coverage: generation g covers the shrinks and expiries a verifier at (n, c) knows
Covers(g, n, c) == gens[g].auth >= ShrunkAt(n) /\ gens[g].time >= LastExpiry(c)

E == Len(epochs)
G == Len(gens)
Roster(i) == epochs[i].roster
Tree == Roster(E)

(***************************************************************************)
(* What a sidecar can open, from the store alone: a GenWrap in any epoch   *)
(* whose tree holds its leaf, a leaf_wrap under an epoch its leaf is in, a  *)
(* STAGED or LATE delivery to it, its member's recovery wraps, and through *)
(* the ladder every generation below.                                       *)
(***************************************************************************)
Reach(s) ==
    LET viaEpochs == {epochs[i].gen : i \in {i \in 1..E : s \in Roster(i)}}
        viaWraps  == {g \in 1..G : s \in gens[g].wraps
                                   \/ (gens[g].leafEpoch > 0 /\ s \in Roster(gens[g].leafEpoch))}
        viaLate   == {w.g : w \in {w \in late : w.r = s}}
        viaRecov  == IF s = Recovered THEN 1..G ELSE {}
    IN Max(viaEpochs \cup viaWraps \cup viaLate \cup viaRecov)
Holds(s) == Reach(s) = G    \* the newest generation

(***************************************************************************)
(* Stories: a pattern names only the fields an action must match.          *)
(***************************************************************************)
Match(label) ==
    \/ Story = <<>>
    \/ /\ step <= Len(Story)
       /\ \A f \in DOMAIN Story[step] : f \in DOMAIN label /\ Story[step][f] = label[f]
Step == step' = IF Story = <<>> THEN step ELSE step + 1

(***************************************************************************)
(* Init: a created the group (epoch 0) and generation 1, whose staged      *)
(* deliveries reach the agents; then, with InitLeaves, added them in one   *)
(* Add commit at epoch 1, whose Welcomes they took.                         *)
(***************************************************************************)
Init ==
    /\ log = <<>>
    /\ tip = [s \in Sidecars |-> 0]
    /\ epochs = IF InitLeaves = {}
                THEN <<[c |-> Creator, roster |-> {Creator}, gen |-> 1, auth |-> 0, time |-> 0, k |-> "create"]>>
                ELSE <<[c |-> Creator, roster |-> {Creator}, gen |-> 1, auth |-> 0, time |-> 0, k |-> "create"],
                       [c |-> Creator, roster |-> {Creator} \cup InitLeaves, gen |-> 1, auth |-> 0, time |-> 0, k |-> "add"]>>
    /\ gens = <<[r |-> Creator, holders |-> InitReaders, auth |-> 0, time |-> 0,
                 wraps |-> InitReaders \cap Agents, leafEpoch |-> 0]>>
    /\ late = {}
    /\ welcomes = {}
    /\ kp = [s \in MemberDevices |-> 1]
    /\ at = [s \in Sidecars |-> IF s = Creator \/ s \in InitLeaves THEN Len(epochs) ELSE 0]
    /\ reached = at
    /\ sealed = {}
    /\ squat = FALSE
    /\ epochB = 0
    /\ poisoned = [s \in Sidecars |-> {}]
    /\ step = 1

(***************************************************************************)
(* The log grows: an admission, the recovery key's admission of e, a        *)
(* revocation, or an agent's grant expiring. Every verifier applies it     *)
(* alike; devices reach it by Advance.                                      *)
(***************************************************************************)
Enter(k, s) ==
    /\ Len(log) < MaxLog
    /\ Match([a |-> "Enter", k |-> k, s |-> s])
    /\ \/ k = "admit" /\ s \notin Admitted(Clock) /\ s # Recovered
                      /\ ~\E j \in 1..Clock : log[j].s = s
       \/ k = "radmit" /\ s = Recovered /\ s \notin Admitted(Clock)
                       /\ ~\E j \in 1..Clock : log[j].s = s
       \/ k = "revoke" /\ s \in Admitted(Clock) /\ s # Recovered
       \/ k = "expire" /\ s \in Agents /\ s \in Admitted(Clock) /\ s \notin Expired(Clock)
    /\ log' = Append(log, [k |-> k, s |-> s])
    /\ Step
    /\ UNCHANGED <<tip, epochs, gens, late, welcomes, kp, at, reached, sealed, squat, epochB, poisoned>>

Advance(s) ==
    /\ tip[s] < Clock /\ (s \in Admitted(Clock) \/ s \in Tree)
    /\ Match([a |-> "Advance", s |-> s])
    /\ tip' = [tip EXCEPT ![s] = @ + 1]
    /\ Step
    /\ UNCHANGED <<log, epochs, gens, late, welcomes, kp, at, reached, sealed, squat, epochB, poisoned>>

(***************************************************************************)
(* A member processes the next epoch once its tip reaches the commit's     *)
(* pin: it adopts the epoch, or finds itself removed and leaves. An        *)
(* injected commit breaks the roster rule at its own header, so the member *)
(* refuses it: it never adopts that epoch and holds the generation its     *)
(* GenWrap carried as poisoned (6.2.3), once. Under MembersSkipRosterCheck *)
(* it adopts the epoch, and poisoned still records the generation the      *)
(* skipped check would have named, so the invariant can tell its seals.    *)
(***************************************************************************)
Process(s) ==
    /\ at[s] > 0 /\ at[s] < E
    /\ tip[s] >= epochs[at[s] + 1].auth
    /\ LET next == epochs[at[s] + 1]
           bad == next.k = "inject"
       IN /\ ~(bad /\ next.gen \in poisoned[s])
          /\ Match([a |-> "Process", s |-> s])
          /\ poisoned' = IF bad THEN [poisoned EXCEPT ![s] = @ \cup {next.gen}] ELSE poisoned
          /\ IF bad /\ Twin # "MembersSkipRosterCheck"
             THEN UNCHANGED <<at, reached>>
             ELSE IF s \in next.roster
                  THEN /\ at' = [at EXCEPT ![s] = @ + 1]
                       /\ reached' = [reached EXCEPT ![s] = at[s] + 1]
                  ELSE /\ at' = [at EXCEPT ![s] = 0]
                       /\ reached' = [reached EXCEPT ![s] = at[s] + 1]
    /\ Step
    /\ UNCHANGED <<log, tip, epochs, gens, late, welcomes, kp, sealed, squat, epochB>>

(***************************************************************************)
(* A hostile leaf commits what no honest leaf does: at the newest epoch, a *)
(* commit whose tree holds a party x dropped at the commit's own header,   *)
(* its GenWrap carrying the newest generation. gkm cannot refuse it: the   *)
(* commit is a PrivateMessage, the leaf holds a writer's token and the     *)
(* generation, and the pin it names passes the epoch PUT check (at or past *)
(* the previous epoch's and the carried generation's, not ahead of gkm).   *)
(* x opens the generation the moment the commit stands. One injection in a *)
(* behavior.                                                                *)
(***************************************************************************)
Inject(c, x, n) ==
    /\ c \in Hostile /\ E < MaxEpochs
    /\ ~\E i \in 1..E : epochs[i].k = "inject"
    /\ at[c] = E /\ c \in Tree /\ c \in Readers(Clock, Clock) /\ Holds(c)
    /\ n <= Clock /\ n >= gens[G].auth /\ n >= epochs[E].auth
    /\ x # c /\ Dropped(x, n, Clock)
    /\ Match([a |-> "Inject", s |-> c, d |-> x])
    /\ epochs' = Append(epochs, [c |-> c, roster |-> Tree \cup {x}, gen |-> G, auth |-> n,
                                 time |-> Clock, k |-> "inject"])
    /\ at' = [at EXCEPT ![c] = E + 1]
    /\ reached' = [reached EXCEPT ![c] = E + 1]
    /\ Step
    /\ UNCHANGED <<log, tip, gens, late, welcomes, kp, sealed, squat, epochB, poisoned>>

(***************************************************************************)
(* A member's commit at the newest epoch, carrying the newest generation's  *)
(* GenWrap, which it must hold and have judged, at its own pin. It carries *)
(* every pending Remove its committer may commit (the pending-change       *)
(* engine), so the new roster lies within the holders at its pin, the      *)
(* roster rule. A read_only leaf commits only a path and may not remove,  *)
(* so it waits while the tree holds a dropped leaf; under                  *)
(* GenWrapIgnoresRoster it commits anyway, as §10.4's self-update interval *)
(* alone would have it do.                                                  *)
(***************************************************************************)
Commit(c, kind, d) ==
    /\ E < MaxEpochs
    /\ at[c] = E /\ c \in Tree
    /\ Holds(c) /\ tip[c] >= gens[G].auth /\ tip[c] >= epochs[E].auth
    /\ Match([a |-> "Commit", s |-> c, k |-> kind, d |-> d])
    /\ LET H == Readers(tip[c], Clock)
           pendingRemoves == IF c \in ReadOnly \/ (Twin = "AddWithoutRemove" /\ kind = "add")
                             THEN {} ELSE Tree \ H
           newRoster == CASE kind = "add" -> (Tree \ pendingRemoves) \cup {d}
                          [] kind = "remove" -> Tree \ pendingRemoves
                          [] kind = "path" -> Tree \ pendingRemoves
                          [] kind = "stale" -> (Tree \ pendingRemoves) \ {d}
           key == IF Twin = "PointerByRef"
                  THEN (IF kp[d] > 0 THEN <<"ot", d, Clock, E>> ELSE <<"lr", d>>)
                  ELSE <<"A", E + 1>>
           lost == \E w \in welcomes : w.key = key
       IN /\ \/ kind = "add" /\ c \in Writers /\ c \notin ReadOnly
                /\ d \in H /\ d \in MemberDevices /\ d \notin Tree /\ at[d] = 0
             \/ kind = "remove" /\ c \in Writers /\ c \notin ReadOnly /\ Tree \ H # {} /\ d = c
             \/ kind = "path" /\ d = c
             \/ kind = "stale" /\ c \in Writers /\ c \notin ReadOnly /\ d \in Tree /\ d \in H /\ d # c
                                /\ d \in StaleTargets
          \* the roster rule, as the committer checks it before it commits (6.2.3)
          /\ Twin \in {"GenWrapIgnoresRoster", "AddWithoutRemove"} \/ newRoster \subseteq H
          /\ epochs' = Append(epochs, [c |-> c, roster |-> newRoster, gen |-> G, auth |-> tip[c],
                                       time |-> Clock, k |-> kind])
          /\ at' = [at EXCEPT ![c] = E + 1]
          /\ reached' = [reached EXCEPT ![c] = E + 1]
          /\ IF kind = "add"
             THEN /\ welcomes' = welcomes \cup {[grp |-> "A", epoch |-> E + 1, r |-> d, key |-> key, lost |-> lost]}
                  /\ kp' = [kp EXCEPT ![d] = IF @ > 0 THEN @ - 1 ELSE 0]
             ELSE UNCHANGED <<welcomes, kp>>
    /\ Step
    /\ UNCHANGED <<log, tip, gens, late, sealed, squat, epochB, poisoned>>

(***************************************************************************)
(* A joiner takes the newest Welcome it can reach for the group, never one *)
(* at or below the newest epoch it reached (I-16).                          *)
(***************************************************************************)
Join(d) ==
    /\ \E w \in welcomes :
        /\ w.grp = "A" /\ w.r = d /\ ~w.lost /\ w.epoch > reached[d] /\ at[d] = 0
        /\ ~\E v \in welcomes : v.grp = "A" /\ v.r = d /\ ~v.lost /\ v.epoch > w.epoch
        /\ Match([a |-> "Join", s |-> d])
        /\ at' = [at EXCEPT ![d] = w.epoch]
        /\ reached' = [reached EXCEPT ![d] = w.epoch]
        /\ welcomes' = welcomes \ {w}
    /\ Step
    /\ UNCHANGED <<log, tip, epochs, gens, late, kp, sealed, squat, epochB, poisoned>>

(***************************************************************************)
(* Repo B adds d through d's KeyPackages too: with one-time ones gone, its *)
(* last-resort KeyPackage serves both repos, and under PointerByRef both   *)
(* Welcomes want one pointer key.                                          *)
(***************************************************************************)
AddInB(d) ==
    /\ WithB /\ epochB < 2 /\ d \in MemberDevices /\ d # Creator
    /\ Match([a |-> "AddInB", s |-> d])
    /\ LET key == IF Twin = "PointerByRef"
                  THEN (IF kp[d] > 0 THEN <<"ot", d, Clock, epochB>> ELSE <<"lr", d>>)
                  ELSE <<"B", epochB + 1>>
       IN /\ welcomes' = welcomes \cup {[grp |-> "B", epoch |-> epochB + 1, r |-> d, key |-> key,
                                         lost |-> \E w \in welcomes : w.key = key]}
          /\ kp' = [kp EXCEPT ![d] = IF @ > 0 THEN @ - 1 ELSE 0]
    /\ epochB' = epochB + 1
    /\ Step
    /\ UNCHANGED <<log, tip, epochs, gens, late, at, reached, sealed, squat, poisoned>>

(***************************************************************************)
(* Rotate (§10.5): a writer holding the newest generation, at a tip at or  *)
(* past its pin, computes the holders at its state, stages a delivery to   *)
(* each it cannot cover by a leaf_wrap, and claims gen/<g+1>. A leaf whose *)
(* epoch's tree holds only holders uses one leaf_wrap under that epoch's   *)
(* KEK; else every leaf gets a ReaderWrap, as every agent does. Racing     *)
(* rotators are two Rotate steps: the second claims the next generation.   *)
(***************************************************************************)
Rotate(r) ==
    /\ G < MaxGens
    /\ r \in Writers /\ r \in Readers(tip[r], Clock)
    /\ Holds(r)
    /\ Twin = "ClaimBelowParent" \/ tip[r] >= gens[G].auth
    /\ Match([a |-> "Rotate", s |-> r])
    /\ LET H == Readers(tip[r], Clock)
           leafCase == /\ r \in MemberDevices /\ at[r] > 0
                       /\ (Twin = "LeafWrapDirtyTree" \/ Roster(at[r]) \subseteq H)
           leaves == IF r \in MemberDevices /\ at[r] > 0 THEN Roster(at[r]) \cap H ELSE H \cap MemberDevices
           \* under StagedToNonHolder the rotation also stages to the parent's holders its own state dropped
           strays == IF Twin = "StagedToNonHolder" THEN gens[G].holders \ H ELSE {}
           wraps == (H \cap Agents) \cup (IF leafCase THEN {} ELSE leaves) \cup strays
       IN gens' = Append(gens, [r |-> r, holders |-> H, auth |-> tip[r], time |-> Clock,
                                wraps |-> wraps, leafEpoch |-> IF leafCase THEN at[r] ELSE 0])
    /\ Step
    /\ UNCHANGED <<log, tip, epochs, late, welcomes, kp, at, reached, sealed, squat, epochB, poisoned>>

(***************************************************************************)
(* A LATE delivery of the newest generation (§10.6's late wraps, §10.9's   *)
(* late row): by any holder but a read_only one, at its own state, which   *)
(* must be at or past the generation's pin, to a recipient that state      *)
(* lists as a holder.                                                       *)
(***************************************************************************)
LateDeliver(d, x) ==
    /\ d \notin ReadOnly /\ d \in Readers(tip[d], Clock) /\ Holds(d)
    /\ Twin = "LateBelowClaimPin" \/ tip[d] >= gens[G].auth
    /\ x # d /\ x \in Readers(tip[d], Clock)
    /\ x \notin gens[G].wraps /\ ~\E w \in late : w.g = G /\ w.r = x
    /\ Match([a |-> "Late", s |-> d, d |-> x])
    /\ late' = late \cup {[g |-> G, r |-> x]}
    /\ Step
    /\ UNCHANGED <<log, tip, epochs, gens, welcomes, kp, at, reached, sealed, squat, epochB, poisoned>>

(***************************************************************************)
(* KF5: a leaf that lost or fell behind resyncs by external commit from    *)
(* the newest GroupInfo, removing at most its own old leaf; it carries the *)
(* newest generation, which it must hold, so the roster rule applies and   *)
(* it waits while the tree holds another dropped leaf.                     *)
(***************************************************************************)
Resync(s) ==
    /\ E < MaxEpochs
    /\ s \in MemberDevices /\ s \in Readers(tip[s], Clock)
    /\ at[s] < E /\ (s \in Tree \/ at[s] = 0)
    /\ Holds(s) /\ tip[s] >= gens[G].auth /\ tip[s] >= epochs[E].auth
    /\ Match([a |-> "Resync", s |-> s])
    /\ LET H == Readers(tip[s], Clock)
           newRoster == (Tree \ {s}) \cup {s}
       IN /\ newRoster \subseteq H
          /\ epochs' = Append(epochs, [c |-> s, roster |-> newRoster, gen |-> G, auth |-> tip[s],
                                       time |-> Clock, k |-> "ext"])
    /\ at' = [at EXCEPT ![s] = E + 1]
    /\ reached' = [reached EXCEPT ![s] = E + 1]
    /\ Step
    /\ UNCHANGED <<log, tip, gens, late, welcomes, kp, sealed, squat, epochB, poisoned>>

(***************************************************************************)
(* §10.8: the recovered device self-joins by external commit. While the    *)
(* tree holds leaves outside the holders at its pin (the lost devices), it *)
(* carries no GenWrap (generation 0) and its next commit removes them.     *)
(***************************************************************************)
SelfJoin(s) ==
    /\ E < MaxEpochs
    /\ s = Recovered /\ s \in Readers(tip[s], Clock) /\ at[s] = 0 /\ s \notin Tree
    /\ Holds(s) /\ tip[s] >= gens[G].auth /\ tip[s] >= epochs[E].auth
    /\ Match([a |-> "SelfJoin", s |-> s])
    /\ LET H == Readers(tip[s], Clock)
           clean == Tree \subseteq H
           gen == IF clean \/ Twin = "SelfJoinCarriesGenWrap" THEN G ELSE 0
       IN epochs' = Append(epochs, [c |-> s, roster |-> Tree \cup {s}, gen |-> gen, auth |-> tip[s],
                                    time |-> Clock, k |-> "self"])
    /\ at' = [at EXCEPT ![s] = E + 1]
    /\ reached' = [reached EXCEPT ![s] = E + 1]
    /\ Step
    /\ UNCHANGED <<log, tip, gens, late, welcomes, kp, sealed, squat, epochB, poisoned>>

(***************************************************************************)
(* A member device loses its group state (a wiped phone): its leaf stays   *)
(* in the tree until it resyncs or a writer removes it as stale.           *)
(***************************************************************************)
LoseState(s) ==
    /\ s \in Losers /\ at[s] > 0
    /\ Match([a |-> "Lose", s |-> s])
    /\ at' = [at EXCEPT ![s] = 0]
    /\ Step
    /\ UNCHANGED <<log, tip, epochs, gens, late, welcomes, kp, reached, sealed, squat, epochB, poisoned>>

(***************************************************************************)
(* A writer seals content to the newest generation it holds; evs's gate   *)
(* passes it only if that generation covers every shrink and expiry evs   *)
(* knows (§10.6's predicate; evs is current here). A device never seals to *)
(* a generation it holds as poisoned (§10.9; EnsureWritable's step 4): it  *)
(* waits for the rotation past it.                                          *)
(***************************************************************************)
Seal(w) ==
    /\ Cardinality(sealed) < MaxSeals
    /\ w \in Writers /\ w \in Readers(tip[w], Clock) /\ Reach(w) > 0
    \* under AdoptNonCoveringWinner a writer that lost the claim seals to the winner's generation uncovered
    /\ \/ Twin = "NoGate"
       \/ Twin = "AdoptNonCoveringWinner" /\ Reach(w) > 1 /\ gens[Reach(w)].r # w
       \/ Covers(Reach(w), Clock, Clock)
    /\ Twin = "MembersSkipRosterCheck" \/ Reach(w) \notin poisoned[w]
    /\ Match([a |-> "Seal", s |-> w])
    /\ sealed' = sealed \cup {[g |-> Reach(w), n |-> Clock, j |-> poisoned[w] # {}]}
    /\ Step
    /\ UNCHANGED <<log, tip, epochs, gens, late, welcomes, kp, at, reached, squat, epochB, poisoned>>

(***************************************************************************)
(* The squatter, admin of B and a reader of A, files B's form naming A's   *)
(* group; with no check at the form (FormsUnchecked), or a re-form that    *)
(* writes no owner marker before its form (FormWithoutMarker), gkm then    *)
(* honors B's rw on A's group, and the squatter claims A's next            *)
(* generation.                                                             *)
(***************************************************************************)
SquatForm ==
    /\ Twin \in {"FormsUnchecked", "FormWithoutMarker"} /\ ~squat
    /\ Squatter \in Readers(tip[Squatter], Clock)
    /\ Match([a |-> "SquatForm"])
    /\ squat' = TRUE
    /\ Step
    /\ UNCHANGED <<log, tip, epochs, gens, late, welcomes, kp, at, reached, sealed, epochB, poisoned>>

SquatClaim ==
    /\ squat /\ G < MaxGens
    /\ Match([a |-> "SquatClaim"])
    /\ gens' = Append(gens, [r |-> Squatter, holders |-> {Squatter}, auth |-> tip[Squatter], time |-> Clock,
                             wraps |-> {Squatter}, leafEpoch |-> 0])
    /\ Step
    /\ UNCHANGED <<log, tip, epochs, late, welcomes, kp, at, reached, sealed, squat, epochB, poisoned>>

Next ==
    \/ \E s \in Sidecars : \E k \in {"admit", "radmit", "revoke", "expire"} : Enter(k, s)
    \/ \E s \in Sidecars : Advance(s)
    \/ \E s \in Sidecars : Process(s)
    \/ \E c \in Sidecars : \E k \in {"add", "remove", "path", "stale"} : \E d \in Sidecars : Commit(c, k, d)
    \/ \E d \in Sidecars : Join(d)
    \/ \E d \in Sidecars : AddInB(d)
    \/ \E r \in Sidecars : Rotate(r)
    \/ \E d, x \in Sidecars : LateDeliver(d, x)
    \/ \E s \in Sidecars : Resync(s)
    \/ \E s \in Sidecars : SelfJoin(s)
    \/ \E s \in Sidecars : LoseState(s)
    \/ \E w \in Sidecars : Seal(w)
    \/ \E c, x \in Sidecars : \E n \in 0..MaxLog : Inject(c, x, n)
    \/ SquatForm
    \/ SquatClaim

Spec == Init /\ [][Next]_vars

Fairness ==
    /\ \A s \in Sidecars : WF_vars(Advance(s)) /\ WF_vars(Process(s)) /\ WF_vars(Join(s)) /\ WF_vars(Resync(s))
    /\ \A d, x \in Sidecars : WF_vars(LateDeliver(d, x))
    /\ \A c, d \in Sidecars : WF_vars(Commit(c, "add", d)) /\ WF_vars(Commit(c, "remove", d))
LiveSpec == Spec /\ Fairness

(***************************************************************************)
(* Invariants (6.3).                                                        *)
(***************************************************************************)
\* a party is entitled to generation g if it was a holder at g's claim or was admitted after it, since a
\* joiner takes the whole history down the ladder (§10.5)
Entitled(s, g) ==
    \/ s \in gens[g].holders
    \/ s = Recovered    \* the member's recovery binding is a holder of every generation (D-KEYS-9)
    \/ \E i \in 1..Clock : i > gens[g].auth /\ log[i].k \in {"admit", "radmit"} /\ log[i].s = s

\* no party outside a generation's entitlement opens it or anything after it
RemovedReadsNothingNew ==
    \A g \in 1..G : \A s \in Sidecars : ~Entitled(s, g) => Reach(s) < g

\* no content sealed at a state is readable by a party dropped at that state
NoContentToDropped ==
    \A w \in sealed : \A s \in Sidecars : Dropped(s, w.n, w.n) => Reach(s) < w.g

\* what a member's refusal buys: nothing a device seals after it refused an injected commit opens to a party
\* dropped at the seal's state. Content sealed to the carried generation by a writer that has not processed the
\* commit (a wrapped writer, which reads no commit, until the REMOVE rotation's delivery reaches it; a leaf whose
\* seal races the injection) is the leak 6.2.3 states and no refusal undoes, so the store invariants above are
\* not checked where Hostile is not empty.
NoContentPastRefusal ==
    \A w \in sealed : w.j => \A s \in Sidecars : Dropped(s, w.n, w.n) => Reach(s) < w.g

\* denied by GkmReach-SealsPastRefusal: the design must reach a seal made after a refusal
NeverSealedPastRefusal == \A w \in sealed : ~w.j

\* every tree lies within the holders at its commit's pin, but a generation-0 self-join's
RosterWithinHolders ==
    \A i \in 2..E : epochs[i].gen = 0 \/ Roster(i) \subseteq Readers(epochs[i].auth, epochs[i].time)

\* every generation is claimed by a writer of A that holds the key at its pin
GenerationsFromWriters ==
    \A g \in 1..G : gens[g].r \in Writers /\ gens[g].r \in Readers(gens[g].auth, gens[g].time)

\* every Welcome has a pointer its recipient can read
WelcomesReachable == \A w \in welcomes : ~w.lost

\* pins never fall along either chain
ChainsMonotone ==
    /\ \A g \in 2..G : gens[g].auth >= gens[g - 1].auth
    /\ \A i \in 2..E : epochs[i].auth >= epochs[i - 1].auth

\* every holder of the newest generation holds it, once the run quiesces
HoldersReach == \A s \in gens[G].holders : Reach(s) = G
Live == <>[]HoldersReach

(***************************************************************************)
(* Stories: the runs that reach each twin's violation directly.            *)
(***************************************************************************)
StoryNone == <<>>
\* one pointer key per KeyPackage ref: e's last-resort KeyPackage serves repo B, then A, then B again
StoryPointer == <<[a |-> "Enter", k |-> "radmit", s |-> "e"], [a |-> "Advance", s |-> "a"],
                  [a |-> "AddInB", s |-> "e"], [a |-> "Commit", s |-> "a", k |-> "add", d |-> "e"],
                  [a |-> "AddInB", s |-> "e"]>>
\* no check at the form: a reader of A, admin of B, names A's group in B's form and claims A's next generation
StorySquat == <<[a |-> "Enter", k |-> "admit", s |-> "e"], [a |-> "Advance", s |-> "e"],
                [a |-> "SquatForm"], [a |-> "SquatClaim"]>>
\* a read_only leaf's path-only commit, due by the interval alone, wraps the REMOVE generation into a tree
\* that still holds the removed leaf
StoryGenWrap == <<[a |-> "Enter", k |-> "revoke", s |-> "b"], [a |-> "Advance", s |-> "d"],
                  [a |-> "Rotate", s |-> "d"], [a |-> "Advance", s |-> "c"],
                  [a |-> "Commit", s |-> "c", k |-> "path", d |-> "c"]>>
\* the recovered device's self-join carries a GenWrap into a tree holding the lost device's leaf
StorySelfJoin == <<[a |-> "Enter", k |-> "revoke", s |-> "b"], [a |-> "Enter", k |-> "radmit", s |-> "e"],
                   [a |-> "Advance", s |-> "d"], [a |-> "Rotate", s |-> "d"],
                   [a |-> "Advance", s |-> "e"], [a |-> "Advance", s |-> "e"], [a |-> "SelfJoin", s |-> "e"]>>
\* a late delivery at a state before the generation's pin reaches the leaf that generation excludes
StoryLate == <<[a |-> "Enter", k |-> "revoke", s |-> "b"], [a |-> "Advance", s |-> "d"],
               [a |-> "Rotate", s |-> "d"], [a |-> "Late", s |-> "a", d |-> "b"]>>
\* a claim at a pin below its parent's computes holders that include the removed leaf
StoryClaim == <<[a |-> "Enter", k |-> "revoke", s |-> "b"], [a |-> "Advance", s |-> "d"],
                [a |-> "Rotate", s |-> "d"], [a |-> "Rotate", s |-> "a"]>>
\* a leaf_wrap under an epoch whose tree holds the removed leaf
StoryLeafWrap == <<[a |-> "Enter", k |-> "revoke", s |-> "b"], [a |-> "Advance", s |-> "a"],
                   [a |-> "Rotate", s |-> "a"]>>
\* content sealed past a shrink under the generation the removed leaf holds
StoryGate == <<[a |-> "Enter", k |-> "revoke", s |-> "b"], [a |-> "Seal", s |-> "a"]>>
\* an Add commit that leaves the revoked leaf in the tree it wraps the generation into
StoryAddWithoutRemove == <<[a |-> "Enter", k |-> "revoke", s |-> "b"], [a |-> "Enter", k |-> "radmit", s |-> "e"],
                           [a |-> "Advance", s |-> "a"], [a |-> "Advance", s |-> "a"],
                           [a |-> "Commit", s |-> "a", k |-> "add", d |-> "e"]>>
\* a rotation for a revocation that stages a delivery to the revoked leaf
StoryStaged == <<[a |-> "Enter", k |-> "revoke", s |-> "b"], [a |-> "Advance", s |-> "a"],
                 [a |-> "Rotate", s |-> "a"]>>
\* the agent claims at a state before the revocation; the writer that lost the claim seals to it past the shrink
StoryAdopt == <<[a |-> "Enter", k |-> "revoke", s |-> "b"], [a |-> "Rotate", s |-> "d"],
                [a |-> "Seal", s |-> "a"]>>
\* the hostile leaf's commit hands the revoked leaf the REMOVE generation; a member that processes it seals on to
\* that generation
StoryPoison == <<[a |-> "Enter", k |-> "revoke", s |-> "b"], [a |-> "Advance", s |-> "d"],
                 [a |-> "Rotate", s |-> "d"], [a |-> "Inject", s |-> "c", d |-> "b"],
                 [a |-> "Advance", s |-> "a"], [a |-> "Process", s |-> "a"], [a |-> "Seal", s |-> "a"]>>

=============================================================================
