------------------------------ MODULE AuthLog ------------------------------
(***************************************************************************)
(* DESIGN-DETAILS.md section 5: the authorization log (§7.9) as every      *)
(* verifier reads it, across folds. One linear log of statements, ticks    *)
(* and bases is the only shared object. Readers are derived from it and    *)
(* kept as variables, so the invariants compare them state by state:       *)
(*                                                                          *)
(*   L     the long-running full reader, present from the bootstrap base,  *)
(*         which is also the config writer that publishes every base       *)
(*   N[b]  a new full device that started at base b, from b's rows, the    *)
(*         retained entries and b's tail verdicts                          *)
(*   G     the rows-only gate (api, evs, gkm), cold-started at the newest  *)
(*         base, which never opens a config head; api sequences what G,    *)
(*         or L where no base exists yet, accepts                          *)
(*                                                                          *)
(* The log's clock is its position: an entry's time_ms is its n, so the    *)
(* recovery window and a proposal's not_after are counted in entries.      *)
(*                                                                          *)
(* What the model keeps: admissions with their signers, carrying position, *)
(* signer's at, confirmations, parks and revocations; one Delegation;      *)
(* recovery bindings and recovery-signed proposals with the 72 h window    *)
(* and its veto; AuthorityProposals and cosigns at threshold K; the        *)
(* compromise cascade P; the replay ring and the StatementHeader's at;     *)
(* bases with their folded_through, head-derived rows (self_admit and a    *)
(* tag's owner), tail verdict bits and, under LyingWriter, a lie. What it  *)
(* leaves out: presence countersignatures, read_only, expiries by          *)
(* not_after, EvsShares, key registrations, leaf ranks, the config head's  *)
(* own chain and api's ticks for reaps.                                    *)
(*                                                                          *)
(* Twin names a rule to break; "none" is the design. "JudgeTail",          *)
(* "NoProposalRows" and "NoSettingsRows" are §7.9 as written on            *)
(* 2026-11-09, the three divergences; "CloseAtBase" is the code that       *)
(* landed; "ReJudgeTail", "NoRingRows", "CascadeFromAt", "NoBitsCheck" and *)
(* "NoTailCap" each break one rule of the detailed design, and TEAM-M2-04  *)
(* adds "NewestConfirmOnly" (rows keep only each kind's newest             *)
(* confirmation) and "DelegationEndIgnored" (a Delegation's key admits     *)
(* after its end), and TEAM-M2-05 "WindowFromProposalEntry" (the window    *)
(* runs from the proposal's entry, not its newest recovery signature) and  *)
(* "VoidKeepsProposal" (a cascade's void leaves a proposal its voided key  *)
(* signed open). Story fixes the entries of a run, so a twin's violation   *)
(* is reached directly; the design runs with no story.                     *)
(*                                                                          *)
(* A recovery-signed proposal is pending until its tick, whoever cosigns   *)
(* it (§7.9; question details-5-model-recovery-cosign, QD-628): a device's *)
(* cosign that brings it to k counted members leaves it open, a recovery   *)
(* key's cosign, rcosign, restarts its window, and only a tick at or after *)
(* the window completes it. rcosign is in every run's alphabet.            *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    MaxN,            \* entries in one behavior
    MaxBases,        \* bases in one behavior
    K,               \* the AdminSet's threshold k
    Window,          \* 4,096: how far back at may lie, and the ring's reach
    TailMax,         \* 4,096: the most entries a base may leave unfolded
    RecoveryWindow,  \* 72 h, in entries
    Life,            \* a proposal's not_after, in entries after its entry
    MaxAdmits,       \* the Delegation's max_admits
    Adversary,       \* api sequences refused statements too
    LyingWriter,     \* a config writer may publish a base with a false verdict
    Narrow,          \* one at and one since_n per statement, so a deeper run finishes
    Story,           \* <<>>, or the pattern each entry must match in turn
    Twin             \* "none", or the rule a twin breaks

ASSUME K \in {1, 2}

Sidecars == {"a", "b", "c", "d"}
Members == {"m1", "m2", "m3"}
AdminMembers == {"m1", "m2"}            \* the AdminSet's Owners and Admins; m3 is outside
RecoveryKeys == {"rk1", "rk2", "rk3"}
KeyOf == ("m1" :> "rk1") @@ ("m2" :> "rk2") @@ ("m3" :> "rk3")
MemberOfKey == ("rk1" :> "m1") @@ ("rk2" :> "m2") @@ ("rk3" :> "m3")

Min(x, y) == IF x < y THEN x ELSE y
Max(x, y) == IF x < y THEN y ELSE x

VARIABLES
    log,      \* the authorization log; position 1 is the first entry after the bootstrap base
    L,        \* the long-running reader and writer
    N,        \* new devices by the base they started at
    G         \* the rows-only gate, restarted at each base

vars == <<log, L, N, G>>

(***************************************************************************)
(* Entries. A statement carries its signer s, target t, the member or tag  *)
(* an admission names (as), a revocation's reason and since_n, a cosign's  *)
(* or veto's pid, a confirmation's kind, the signer's at and, for a        *)
(* replay, the position of the statement whose bytes it repeats.           *)
(***************************************************************************)
Mk(k, s, t, as, reason, since, pid, ck, at, of) ==
    [k |-> k, s |-> s, t |-> t, as |-> as, reason |-> reason, since |-> since,
     pid |-> pid, ck |-> ck, at |-> at, of |-> of]
Stmt(k, s, t, as, at) == Mk(k, s, t, as, "", 0, 0, "", at, 0)
Proposed(e) ==
    IF e.as = "revoke" THEN Mk("revoke", "proposal", e.t, "", "comp", e.since, 0, "", e.at, 0)
    ELSE Stmt("admit", "proposal", e.t, e.as, e.at)

(***************************************************************************)
(* A reader's state: what rows hold, the head-derived values, and the base *)
(* it stands on.                                                            *)
(***************************************************************************)
NoAdm == [admitted |-> FALSE, as |-> "", byDeleg |-> FALSE, signers |-> {}, at |-> 0, sat |-> 0,
          revoked |-> 0, parked |-> 0, confirms |-> {}, genesis |-> FALSE, invited |-> FALSE]
Adm0(m) == [NoAdm EXCEPT !.admitted = TRUE, !.as = m, !.genesis = TRUE]
NoDeleg == [declared |-> FALSE, signer |-> "", at |-> 0, ended |-> 0, admits |-> 0]
NoBind == [signer |-> "", at |-> 0, void |-> FALSE]
NoProps == [p \in {} |-> 0]
InitSt == [adm |-> ("a" :> Adm0("m1")) @@ ("b" :> Adm0("m2")) @@ ("c" :> NoAdm) @@ ("d" :> NoAdm),
           deleg |-> NoDeleg, props |-> NoProps, binds |-> [m \in Members |-> NoBind], ring |-> {},
           selfAdmit |-> "on", tagOwner |-> "m1",
           floor |-> 0, ft |-> 0, prevBase |-> 0, base |-> 0]

Standing(st, s) == s \in Sidecars /\ st.adm[s].admitted /\ st.adm[s].revoked = 0 /\ st.adm[s].parked = 0
AdminDevice(st, s) == Standing(st, s) /\ st.adm[s].as \in AdminMembers
Admitted(st, t) == st.adm[t].admitted
Open(st, pid, n) == pid \in DOMAIN st.props /\ st.props[pid].closed = 0 /\ n <= st.props[pid].o + Life

(***************************************************************************)
(* §8.5's consented(d, M), with excl the signers whose signatures do not   *)
(* count: the cascade's P and the keys of the bindings it voids. A device  *)
(* of M is consented by genesis, by an invite (an admin's admission of M's *)
(* first device), by an admission M's consented device or recovery key     *)
(* signed, or by an OwnerConfirm from M's consented device.                *)
(***************************************************************************)
RECURSIVE ConsentedIn(_, _, _, _)
ConsentedIn(st, m, excl, depth) ==
    LET prev == IF depth = 0 THEN {} ELSE ConsentedIn(st, m, excl, depth - 1)
        more == {d \in Sidecars :
                  /\ st.adm[d].admitted /\ st.adm[d].as = m /\ st.adm[d].parked = 0
                  /\ \/ st.adm[d].genesis
                     \/ st.adm[d].invited
                     \/ \E s \in st.adm[d].signers :
                          \/ s \in prev /\ s \notin excl
                          \/ s = KeyOf[m] /\ ~st.binds[m].void /\ s \notin excl
                     \/ \E c \in st.adm[d].confirms :
                          c.ck = "owner" /\ c.signer \in prev /\ c.signer \notin excl}
    IN prev \cup more
Consented(st, m, excl) == ConsentedIn(st, m, excl, Cardinality(Sidecars))

(***************************************************************************)
(* §7.9's cascade: the closure P of a compromise revocation of x from      *)
(* since, each record counting from the entry that carried it (the design) *)
(* or, under CascadeFromAt, from its signer's at. DesignClosure is the     *)
(* design's rule whatever the twin, the oracle CascadeClosed checks.       *)
(***************************************************************************)
\* Whether a record carried at pos, signed at at, counts from since: byAt is the twin's rule
Counts(pos, at, since, byAt) == IF byAt THEN at >= since ELSE pos >= since
InP(st, s, P, since) ==
    \/ s \in Sidecars /\ s \in P
    \/ s = "deleg" /\ st.deleg.signer \in P /\ st.deleg.at >= since
    \/ s \in RecoveryKeys /\ st.binds[MemberOfKey[s]].signer \in P /\ st.binds[MemberOfKey[s]].at >= since
Grow(st, x, since, P, byAt) ==
    LET voidedKeys == {KeyOf[m] : m \in {m \in Members : st.binds[m].signer \in P /\ st.binds[m].at >= since}}
    IN P \cup {t \in Sidecars : st.adm[t].admitted /\ t \notin P /\
                 \/ Counts(st.adm[t].at, st.adm[t].sat, since, byAt) /\ \E s \in st.adm[t].signers : InP(st, s, P, since)
                 \/ \E c \in st.adm[t].confirms : c.lifted /\ Counts(c.pos, c.at, since, byAt) /\ c.signer \in P
                 \/ st.adm[t].byDeleg /\ st.adm[x].byDeleg /\ Counts(st.adm[t].at, st.adm[t].sat, since, byAt)
                 \/ /\ st.adm[t].as \in Members /\ ~st.adm[t].genesis
                    /\ t \in Consented(st, st.adm[t].as, {})
                    /\ t \notin Consented(st, st.adm[t].as, P \cup voidedKeys)
                    /\ \E c \in st.adm[t].confirms : c.ck = "owner" /\ c.signer \in P /\ Counts(c.pos, c.at, since, byAt)}
RECURSIVE ClosureIn(_, _, _, _, _)
ClosureIn(st, x, since, depth, byAt) ==
    IF depth = 0 THEN {x}
    ELSE Grow(st, x, since, ClosureIn(st, x, since, depth - 1, byAt), byAt)
Closure(st, x, since) == ClosureIn(st, x, since, Cardinality(Sidecars), Twin = "CascadeFromAt")
DesignClosure(st, x, since) == ClosureIn(st, x, since, Cardinality(Sidecars), FALSE)

(***************************************************************************)
(* Who counts toward k for a proposed statement: distinct Owners and      *)
(* Admins among standing member devices and the recovery keys of unvoided *)
(* bindings, never the target device.                                      *)
(***************************************************************************)
Counted(st, signers, stmt) ==
    {st.adm[s].as : s \in {s \in signers \cap Sidecars : Standing(st, s) /\ st.adm[s].as \in AdminMembers /\ s # stmt.t}}
    \cup {MemberOfKey[s] : s \in {s \in signers \cap RecoveryKeys :
                                    MemberOfKey[s] \in AdminMembers /\ ~st.binds[MemberOfKey[s]].void}}

MayAdmit(st, s, t, as) ==
    /\ Standing(st, s) /\ s # t
    /\ CASE as \in AdminMembers -> K = 1 /\ (AdminDevice(st, s) \/ st.adm[s].as = as)
         [] as = "m3" -> AdminDevice(st, s)
                         \/ (st.adm[s].as = "m3" /\ s \in Consented(st, "m3", {}) /\ st.selfAdmit = "on")
         [] as = "tag" -> st.adm[s].as = st.tagOwner
MayRevoke(st, s, t, reason) ==
    /\ st.adm[t].admitted /\ st.adm[t].revoked = 0
    /\ \/ s = t /\ reason = "lost"
       \/ /\ Standing(st, s) /\ s # t
          /\ \/ AdminDevice(st, s)
             \/ st.adm[s].as = st.adm[t].as /\ st.adm[s].as \in Members \ AdminMembers
                /\ s \in Consented(st, st.adm[s].as, {})
             \/ st.adm[t].as = "tag" /\ st.adm[s].as = st.tagOwner
    /\ st.adm[t].as \in AdminMembers => K = 1 \/ s = t

(***************************************************************************)
(* The type rules: 0 refused, 1 takes effect, 2 takes effect and completes *)
(* a proposal. A proposed statement's own rule is judged where it          *)
(* completes, its signer "proposal" standing for the counted signers.      *)
(***************************************************************************)
RECURSIVE TypeRule(_, _, _)
TypeRule(st, e, n) ==
    LET s == e.s
        t == e.t
        complete(stmt, signers) ==
            IF Cardinality(Counted(st, signers, stmt)) >= K
            THEN IF TypeRule(st, stmt, n) # 0 THEN 2 ELSE 0
            ELSE 1
    IN CASE e.k = "admit" ->
            IF ~Admitted(st, t) /\ e.as \in Members \cup {"tag"} /\ (s = "proposal" \/ MayAdmit(st, s, t, e.as))
            THEN 1 ELSE 0
       [] e.k = "dadmit" ->
            IF /\ st.deleg.declared /\ st.deleg.admits < MaxAdmits /\ ~Admitted(st, t)
               /\ (st.deleg.ended = 0 \/ Twin = "DelegationEndIgnored")
            THEN 1 ELSE 0
       [] e.k = "deleg" ->
            IF ~st.deleg.declared /\ (AdminDevice(st, s) \/ (Standing(st, s) /\ st.adm[s].as = st.tagOwner))
            THEN 1 ELSE 0
       [] e.k = "drevoke" ->
            IF st.deleg.declared /\ st.deleg.ended = 0 /\ AdminDevice(st, s) THEN 1 ELSE 0
       [] e.k = "revoke" ->
            IF /\ (s = "proposal" \/ MayRevoke(st, s, t, e.reason))
               /\ st.adm[t].admitted /\ st.adm[t].revoked = 0
               /\ e.reason = "comp" => e.since >= 1 /\ s \notin Closure(st, t, e.since)
            THEN 1 ELSE 0
       [] e.k = "confirm" ->
            IF /\ st.adm[t].admitted /\ st.adm[t].revoked = 0 /\ s # t /\ Standing(st, s)
               /\ \/ e.ck = "admission"
                     /\ IF st.adm[t].byDeleg THEN AdminDevice(st, s) \/ st.adm[s].as = st.tagOwner
                        ELSE MayAdmit(st, s, t, st.adm[t].as) \/ AdminDevice(st, s)
                  \/ e.ck = "owner" /\ st.adm[t].as \in Members /\ st.adm[s].as = st.adm[t].as
                     /\ s \in Consented(st, st.adm[t].as, {})
            THEN 1 ELSE 0
       [] e.k = "propose" ->
            LET stmt == Proposed(e)
            IN IF /\ Standing(st, s) /\ Cardinality(Counted(st, {s}, stmt)) = 1
                  /\ (e.as \in AdminMembers \/ (e.as = "revoke" /\ st.adm[t].as \in AdminMembers))
               THEN complete(stmt, {s}) ELSE 0
       [] e.k = "cosign" ->
            IF /\ Open(st, e.pid, n) /\ Standing(st, s)
               /\ Cardinality(Counted(st, {s}, st.props[e.pid].stmt)) = 1
               /\ st.adm[s].as \notin Counted(st, st.props[e.pid].signers, st.props[e.pid].stmt)
            THEN \* a recovery-signed proposal stays pending at any cosign: its tick completes it (§7.9)
                 IF st.props[e.pid].kind = "recovery" THEN 1
                 ELSE complete(st.props[e.pid].stmt, st.props[e.pid].signers \cup {s})
            ELSE 0
       [] e.k = "veto" ->
            IF /\ Open(st, e.pid, n) /\ st.props[e.pid].kind = "recovery"
               /\ AdminDevice(st, s) /\ s # st.props[e.pid].stmt.t
            THEN 1 ELSE 0
       [] e.k = "tick" ->
            IF /\ Open(st, e.pid, n) /\ st.props[e.pid].kind = "recovery"
               /\ n >= (IF Twin = "WindowFromProposalEntry" THEN st.props[e.pid].o ELSE st.props[e.pid].p) + RecoveryWindow
               /\ complete(st.props[e.pid].stmt, st.props[e.pid].signers) = 2
            THEN 2 ELSE 0
       [] e.k = "rpropose" ->
            IF /\ s \in RecoveryKeys /\ MemberOfKey[s] \in AdminMembers /\ e.as = MemberOfKey[s]
               /\ st.binds[e.as].signer # "" /\ ~st.binds[e.as].void /\ ~Admitted(st, t)
            THEN 1 ELSE 0
       [] e.k = "rcosign" ->
            IF /\ Open(st, e.pid, n) /\ st.props[e.pid].kind = "recovery"
               /\ s \in RecoveryKeys /\ MemberOfKey[s] \in AdminMembers /\ s \notin st.props[e.pid].signers
               /\ st.binds[MemberOfKey[s]].signer # "" /\ ~st.binds[MemberOfKey[s]].void
            THEN 1 ELSE 0
       [] e.k = "radmit" ->
            IF /\ s = "rk3" /\ e.as = "m3" /\ st.binds["m3"].signer # "" /\ ~st.binds["m3"].void
               /\ st.selfAdmit = "on" /\ ~Admitted(st, t)
            THEN 1 ELSE 0
       [] e.k = "bind" ->
            IF Standing(st, s) /\ st.adm[s].as = e.as /\ s \in Consented(st, e.as, {}) THEN 1 ELSE 0

(***************************************************************************)
(* §7.9's replay row, then the type rule. A replay repeats the bytes of an  *)
(* earlier entry, so it carries that entry's id (its position) and at.     *)
(***************************************************************************)
Original(e) == IF e.k = "replay" THEN [log[e.of] EXCEPT !.of = 0] ELSE e
StmtId(e, n) == IF e.k = "replay" THEN e.of ELSE n
RingHolds(st, id, n) == \E r \in st.ring : r.id = id /\ n - r.pos <= Window
Judge(st, e, n, floor) ==
    LET o == Original(e) IN
    IF e.k = "base" THEN 0
    ELSE IF e.k = "tick" THEN TypeRule(st, e, n)
    ELSE IF ~(o.at <= n - 1 /\ n - o.at <= Window /\ o.at >= floor) THEN 0
    ELSE IF RingHolds(st, StmtId(e, n), n) THEN 0
    ELSE TypeRule(st, o, n)

(***************************************************************************)
(* Effects. A proposed statement's effect carries the proposal's signers.  *)
(***************************************************************************)
Park(st, P, n) ==
    [st EXCEPT !.adm = [y \in Sidecars |-> IF y \in P /\ st.adm[y].revoked = 0 /\ st.adm[y].parked = 0
                                           THEN [st.adm[y] EXCEPT !.parked = n] ELSE st.adm[y]]]
AdmitAs(st, tgt, as, signers, byDeleg, invited, n, at) ==
    [st EXCEPT !.adm[tgt] = [NoAdm EXCEPT !.admitted = TRUE, !.as = as, !.byDeleg = byDeleg,
                              !.signers = signers, !.at = n, !.sat = at, !.invited = invited]]
Compromise(st, x, since, n, P) ==
    LET st2 == Park(st, P \ {x}, n)
    IN [st2 EXCEPT
         !.adm[x].revoked = n,
         !.binds = [m \in Members |-> IF st.binds[m].signer \in P /\ st.binds[m].at >= since
                                     THEN [st.binds[m] EXCEPT !.void = TRUE] ELSE st.binds[m]],
         !.deleg = IF st.deleg.declared /\ st.deleg.ended = 0
                      /\ ((st.deleg.signer \in P /\ st.deleg.at >= since) \/ st.adm[x].byDeleg)
                   THEN [st.deleg EXCEPT !.ended = n] ELSE st.deleg,
         !.props = [p \in DOMAIN st.props |->
                      IF Twin # "VoidKeepsProposal" /\ st.props[p].closed = 0 /\ \E rk \in st.props[p].signers \cap RecoveryKeys :
                            st.binds[MemberOfKey[rk]].signer \in P /\ st.binds[MemberOfKey[rk]].at >= since
                      THEN [st.props[p] EXCEPT !.closed = n, !.how = "voided"] ELSE st.props[p]]]
\* The effect of a proposed statement that completed with signers
Complete(st, stmt, signers, n) ==
    IF stmt.k = "admit" THEN AdmitAs(st, stmt.t, stmt.as, signers, FALSE, FALSE, n, stmt.at)
    ELSE Compromise(st, stmt.t, stmt.since, n, Closure(st, stmt.t, stmt.since))
Row(stmt, signers, n, p, kind, closed, how) ==
    [stmt |-> stmt, signers |-> signers, o |-> n, p |-> p, kind |-> kind, closed |-> closed, how |-> how, a |-> 0]

Effect(st, e, n, completed) ==
    LET o == Original(e)
        s == o.s
        t == o.t
        id == StmtId(e, n)
        withRing(st2) == [st2 EXCEPT !.ring = @ \cup {[id |-> id, pos |-> n]}]
    IN
    CASE o.k = "admit" ->
            withRing(AdmitAs(st, t, o.as, {s}, FALSE,
                             o.as = "m3" /\ AdminDevice(st, s) /\ ~\E y \in Sidecars : st.adm[y].admitted /\ st.adm[y].as = "m3",
                             n, o.at))
      [] o.k = "dadmit" ->
            withRing([AdmitAs(st, t, "tag", {"deleg"}, TRUE, FALSE, n, o.at) EXCEPT !.deleg.admits = @ + 1])
      [] o.k = "deleg" ->
            withRing([st EXCEPT !.deleg = [declared |-> TRUE, signer |-> s, at |-> n, ended |-> 0, admits |-> 0]])
      [] o.k = "drevoke" ->
            withRing([Park(st, {y \in Sidecars : st.adm[y].byDeleg /\ o.since > 0 /\ st.adm[y].at >= o.since}, n)
                      EXCEPT !.deleg.ended = n])
      [] o.k = "revoke" ->
            IF o.reason = "lost" THEN withRing([st EXCEPT !.adm[t].revoked = n])
            ELSE withRing(Compromise(st, t, o.since, n, Closure(st, t, o.since)))
      [] o.k = "confirm" ->
            withRing([st EXCEPT !.adm[t] = [@ EXCEPT !.parked = 0,
                                                   !.confirms = @ \cup {[signer |-> s, pos |-> n, at |-> o.at, ck |-> o.ck,
                                                                          lifted |-> st.adm[t].parked # 0]}]])
      [] o.k = "propose" ->
            LET stmt == Proposed(o)
                row == Row(stmt, {s}, n, 0, "authority", IF completed THEN n ELSE 0, IF completed THEN "completed" ELSE "")
                st2 == [st EXCEPT !.props = (id :> row) @@ @]
            IN withRing(IF completed THEN [Complete(st, stmt, {s}, n) EXCEPT !.props = st2.props] ELSE st2)
      [] o.k = "cosign" ->
            IF o.pid \notin DOMAIN st.props THEN st ELSE   \* a lie's effect on a proposal rows do not hold drops
            LET row == st.props[o.pid]
                signers == row.signers \cup {s}
                row2 == [row EXCEPT !.signers = signers, !.closed = IF completed THEN n ELSE 0,
                                    !.how = IF completed THEN "completed" ELSE ""]
                st2 == [st EXCEPT !.props[o.pid] = row2]
            IN withRing(IF completed THEN [Complete(st, row.stmt, signers, n) EXCEPT !.props = st2.props] ELSE st2)
      [] o.k = "veto" ->
            IF o.pid \notin DOMAIN st.props THEN st
            ELSE withRing([st EXCEPT !.props[o.pid] = [@ EXCEPT !.closed = n, !.how = "vetoed"]])
      [] o.k = "tick" ->
            IF o.pid \notin DOMAIN st.props THEN st ELSE
            LET row == st.props[o.pid]
                st2 == [st EXCEPT !.props[o.pid] = [row EXCEPT !.closed = n, !.how = "activated", !.a = n]]
            IN [Complete(st, row.stmt, row.signers, n) EXCEPT !.props = st2.props]
      [] o.k = "rcosign" ->
            IF o.pid \notin DOMAIN st.props THEN st
            ELSE withRing([st EXCEPT !.props[o.pid] = [@ EXCEPT !.signers = @ \cup {s}, !.p = n]])
      [] o.k = "rpropose" ->
            withRing([st EXCEPT !.props = (id :> Row(Stmt("admit", "proposal", t, o.as, o.at), {s}, n, n, "recovery", 0, "")) @@ @])
      [] o.k = "radmit" ->
            withRing(AdmitAs(st, t, "m3", {"rk3"}, FALSE, FALSE, n, o.at))
      [] o.k = "bind" ->
            withRing([st EXCEPT !.binds[o.as] = [signer |-> s, at |-> n, void |-> FALSE]])

(***************************************************************************)
(* Readers. A reader is its state, the verdict it holds at each position   *)
(* (judged, or taken from a base's bits), the first position it holds      *)
(* entries from, the base it started at, and whether it forked. L also     *)
(* keeps its state after every position, which the writer compiles from,   *)
(* and the targets of the revocations it applied.                          *)
(***************************************************************************)
OpenProps(st, n) == [p \in {p \in DOMAIN st.props : Open(st, p, n)} |-> st.props[p]]

ApplyStmt(R, e, n) ==
    IF R.forked THEN R
    ELSE LET v == Judge(R.st, e, n, R.st.floor)
             st2 == IF v = 0 THEN R.st ELSE Effect(R.st, e, n, v = 2)
         IN [R EXCEPT !.st = st2, !.verdict = @ @@ (n :> v),
                      !.revokedEver = IF v # 0 /\ e.k = "revoke" THEN @ \cup {e.t} ELSE @,
                      !.hist = IF R.keepsHist THEN @ @@ (n :> st2) ELSE @]

\* Re-applies the tail from..to on st by the verdicts bits, judging nothing
RECURSIVE Reapply(_, _, _, _)
Reapply(st, from, to, bits) ==
    IF from > to THEN st
    ELSE LET e == log[from]
             st2 == IF e.k = "base" \/ bits[from] = 0 THEN st ELSE Effect(st, e, from, bits[from] = 2)
         IN Reapply(st2, from + 1, to, bits)

\* Judges the tail from..to on st at floor, as §7.9's new device did on 2026-11-09
RECURSIVE JudgeTail(_, _, _, _, _)
JudgeTail(st, from, to, floor, verdict) ==
    IF from > to THEN [st |-> st, verdict |-> verdict]
    ELSE LET e == log[from]
             v == IF e.k = "base" THEN 0 ELSE Judge(st, e, from, floor)
             st2 == IF v = 0 THEN st ELSE Effect(st, e, from, v = 2)
         IN JudgeTail(st2, from + 1, to, floor, verdict @@ (from :> v))

\* Each kind's newest confirmation, all that rows kept before DESIGN-DETAILS 5.2.2's confirmations
NewestConfirms(confirms) == {c \in confirms : \A d \in confirms : d.ck = c.ck => d.pos <= c.pos}

\* The rows a base at n with folded_through ft carries: L's log-derived state at ft under head
Compile(S, head, ft) ==
    [S EXCEPT !.selfAdmit = head.selfAdmit, !.tagOwner = head.tagOwner,
              !.adm = IF Twin = "NewestConfirmOnly"
                      THEN [y \in Sidecars |-> [S.adm[y] EXCEPT !.confirms = NewestConfirms(@)]] ELSE @,
              !.props = IF Twin \in {"NoProposalRows", "CloseAtBase"} THEN NoProps ELSE OpenProps(S, ft),
              !.ring = IF Twin = "NoRingRows" THEN {} ELSE {r \in S.ring : r.pos > ft - Window}]

\* The state a base's rows give a reader whose previous base was prevBase
Stand(rows, e, n, prevBase, rowsOnly) ==
    [rows EXCEPT !.ft = e.ft, !.prevBase = prevBase, !.base = n,
                 !.floor = IF prevBase = 0 THEN e.ft + 1 ELSE Min(prevBase, e.ft + 1),
                 !.selfAdmit = IF rowsOnly /\ Twin = "NoSettingsRows" THEN "unknown" ELSE rows.selfAdmit]

BaseOk(R, e, n) ==
    /\ e.ft >= R.st.ft /\ (e.ft = R.st.ft \/ e.ft >= R.st.base)
    /\ n - 1 - e.ft <= TailMax \/ Twin = "NoTailCap"
    /\ Twin = "NoBitsCheck"
       \/ \A k \in e.ft + 1 .. n - 1 : log[k].k = "base" \/ k \notin DOMAIN R.verdict \/ e.bits[k] = R.verdict[k]

ApplyBase(R, e, n) ==
    IF R.forked THEN R
    ELSE IF ~BaseOk(R, e, n) THEN [R EXCEPT !.forked = TRUE]
    ELSE LET st0 == [Stand(e.rows, e, n, R.st.base, R.rowsOnly) EXCEPT
                       !.props = IF Twin = "NoProposalRows" THEN R.st.props ELSE @,
                       !.ring = IF Twin = "NoRingRows" THEN R.st.ring ELSE @,
                       \* a reader that kept every entry keeps its own confirmations where rows keep only the newest
                       !.adm = IF Twin = "NewestConfirmOnly" /\ R.keepsHist
                               THEN [y \in Sidecars |-> [@[y] EXCEPT !.confirms = R.st.adm[y].confirms]] ELSE @]
             own == [k \in e.ft + 1 .. n - 1 |-> IF k \in DOMAIN R.verdict THEN R.verdict[k] ELSE e.bits[k]]
             judged == JudgeTail(st0, e.ft + 1, n - 1, st0.floor, [k \in {} |-> 0])
             st1 == IF Twin = "ReJudgeTail" THEN judged.st
                    ELSE IF Twin = "CloseAtBase" THEN Reapply([st0 EXCEPT !.props = NoProps], e.ft + 1, n - 1, own)
                    ELSE Reapply(st0, e.ft + 1, n - 1, own)
             verdict2 == IF Twin = "ReJudgeTail" THEN judged.verdict @@ R.verdict @@ (n :> 0)
                         ELSE R.verdict @@ (n :> 0)
         IN [R EXCEPT !.st = st1, !.verdict = verdict2,
                      !.hist = IF R.keepsHist THEN @ @@ (n :> st1) ELSE @]

\* A reader that starts at base n from the retained entries, the rows and the bits
NewReader(e, n, rowsOnly) ==
    LET st0 == Stand(e.rows, e, n, e.prevBase, rowsOnly)
        judged == JudgeTail(st0, e.ft + 1, n - 1, st0.floor, [k \in {} |-> 0])
        st1 == IF Twin = "JudgeTail" THEN judged.st ELSE Reapply(st0, e.ft + 1, n - 1, e.bits)
        verdict == IF Twin = "JudgeTail" THEN judged.verdict @@ (n :> 0) ELSE e.bits @@ (n :> 0)
    IN [st |-> st1, verdict |-> verdict, held |-> st0.floor, start |-> n, forked |-> FALSE,
        rowsOnly |-> rowsOnly, keepsHist |-> FALSE, hist |-> [k \in {} |-> 0], revokedEver |-> {}]

Step(R, e, n) == IF e.k = "base" THEN ApplyBase(R, e, n) ELSE ApplyStmt(R, e, n)

(***************************************************************************)
(* Actions.                                                                 *)
(***************************************************************************)
n == Len(log) + 1
Bases == {b \in 1 .. Len(log) : log[b].k = "base"}
Pids == {j \in 1 .. Len(log) : log[j].k \in {"propose", "rpropose"}}

AtChoices == IF Narrow THEN {n - 1} ELSE {n - 1, Max(0, n - 3)}
SinceChoices == IF Narrow THEN {1} ELSE {1, Max(1, n - 2)}
ConfirmKinds == IF Narrow THEN {"admission"} ELSE {"admission", "owner"}
Candidates ==
    {Stmt("admit", s, t, as, at) : s \in Sidecars, t \in {"c", "d"}, as \in {"m2", "m3", "tag"}, at \in AtChoices}
    \cup {Stmt("dadmit", "deleg", t, "tag", n - 1) : t \in {"c", "d"}}
    \cup {Stmt("deleg", s, "", "", n - 1) : s \in Sidecars}
    \cup {Mk("drevoke", s, "", "", "", since, 0, "", n - 1, 0) : s \in Sidecars, since \in {0} \cup SinceChoices}
    \cup {Mk("revoke", s, t, "", "lost", 0, 0, "", n - 1, 0) : s \in Sidecars, t \in Sidecars}
    \cup {Mk("revoke", s, t, "", "comp", since, 0, "", n - 1, 0) : s \in Sidecars, t \in Sidecars, since \in SinceChoices}
    \cup {Mk("confirm", s, t, "", "", 0, 0, ck, n - 1, 0) : s \in Sidecars, t \in Sidecars, ck \in ConfirmKinds}
    \cup {Stmt("propose", s, t, "m2", n - 1) : s \in Sidecars, t \in {"c", "d"}}
    \cup {Mk("propose", s, t, "revoke", "comp", since, 0, "", n - 1, 0) : s \in Sidecars, t \in {"a", "b"}, since \in SinceChoices}
    \cup {Mk("cosign", s, "", "", "", 0, pid, "", n - 1, 0) : s \in Sidecars, pid \in Pids}
    \cup {Mk("veto", s, "", "", "", 0, pid, "", n - 1, 0) : s \in Sidecars, pid \in Pids}
    \cup {Stmt("rpropose", KeyOf[m], t, m, n - 1) : m \in AdminMembers, t \in {"c", "d"}}
    \cup {Stmt("radmit", "rk3", t, "m3", n - 1) : t \in {"c", "d"}}
    \cup {Stmt("bind", s, "", m, n - 1) : s \in Sidecars, m \in Members}
    \cup {Mk("replay", "", "", "", "", 0, 0, "", 0, of) : of \in {k \in 1 .. Len(log) : log[k].k \notin {"base", "tick", "replay"}}}
    \cup {Mk("tick", "api", "", "", "", 0, pid, "", n - 1, 0) : pid \in Pids}
    \* a recovery cosign, which restarts a window
    \cup {Mk("rcosign", KeyOf[m], "", m, "", 0, pid, "", n - 1, 0) : m \in AdminMembers, pid \in Pids}

Matches(pattern, e) == \A f \in DOMAIN pattern : e[f] = pattern[f]
StoryAllows(e) == IF Len(Story) < n THEN TRUE ELSE Matches(Story[n], e)

\* api's verdict: the rows-only gate's, or the full reader's before any base
ApiAccepts(e) == IF G.start = 0 THEN Judge(L.st, e, n, L.st.floor) # 0 ELSE Judge(G.st, e, n, G.st.floor) # 0

AppendStmt(e) ==
    /\ Len(log) < MaxN
    /\ StoryAllows(e)
    /\ IF Adversary THEN TRUE ELSE ApiAccepts(e) \/ Judge(L.st, e, n, L.st.floor) # 0
    /\ log' = Append(log, e)
    /\ L' = Step(L, e, n)
    /\ N' = [b \in DOMAIN N |-> Step(N[b], e, n)]
    /\ G' = IF G.start = 0 THEN G ELSE Step(G, e, n)

PublishBase(ft, selfAdmit, tagOwner, lie) ==
    /\ Len(log) < MaxN /\ Cardinality(Bases) < MaxBases
    /\ ~L.forked                                  \* a forked writer stops (§6.4's FORK)
    /\ ft \in {L.st.ft} \cup (Max(L.st.base, 1) .. n - 1)
    /\ n - 1 - ft <= TailMax \/ Twin = "NoTailCap"
    /\ lie => LyingWriter /\ ft < n - 1 /\ log[n - 1].k # "base"
    /\ LET head == [selfAdmit |-> selfAdmit, tagOwner |-> tagOwner]
           rows == Compile(L.hist[ft], head, ft)
           honest == [k \in ft + 1 .. n - 1 |-> IF log[k].k = "base" THEN 0 ELSE L.verdict[k]]
           bits == IF lie THEN [honest EXCEPT ![n - 1] = IF honest[n - 1] = 0 THEN 1 ELSE 0] ELSE honest
           e == [k |-> "base", ft |-> ft, head |-> head, rows |-> rows, bits |-> bits, lie |-> lie,
                 prevBase |-> L.st.base]
       IN /\ StoryAllows(e)
          /\ log' = Append(log, e)
          /\ L' = Step(L, e, n)
          /\ N' = [b \in DOMAIN N |-> Step(N[b], e, n)] @@ (n :> NewReader(e, n, FALSE))
          /\ G' = NewReader(e, n, TRUE)

Reader0(rowsOnly, keepsHist) ==
    [st |-> InitSt, verdict |-> [k \in {} |-> 0], held |-> 0, start |-> 0, forked |-> FALSE,
     rowsOnly |-> rowsOnly, keepsHist |-> keepsHist,
     hist |-> IF keepsHist THEN (0 :> InitSt) ELSE [k \in {} |-> 0], revokedEver |-> {}]

Init ==
    /\ log = <<>>
    /\ L = Reader0(FALSE, TRUE)
    /\ N = [b \in {} |-> 0]
    /\ G = Reader0(TRUE, FALSE)

Next ==
    \/ \E e \in Candidates : AppendStmt(e)
    \/ \E ft \in 0 .. n - 1, selfAdmit \in {"on", "off"}, tagOwner \in Members, lie \in BOOLEAN :
         PublishBase(ft, selfAdmit, tagOwner, lie)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants.                                                              *)
(***************************************************************************)
Proj(st, m) == [adm |-> st.adm, deleg |-> st.deleg, binds |-> st.binds, props |-> OpenProps(st, m)]
SameView(R, Q) ==
    /\ Proj(R.st, n) = Proj(Q.st, n)
    /\ \A k \in DOMAIN R.verdict \cap DOMAIN Q.verdict : R.verdict[k] = Q.verdict[k]

\* Every verifier that stands on the log holds one state and one verdict per entry
Agreement ==
    /\ \A b \in DOMAIN N : ~N[b].forked /\ ~L.forked => SameView(N[b], L)
    /\ G.start > 0 /\ ~G.forked /\ ~L.forked => SameView(G, L)

\* A revocation that took effect stays in effect at every later state
RevocationsStand == \A t \in L.revokedEver : L.st.adm[t].revoked # 0

\* The cascade parks what a stolen device admitted from since_n, however it dated its signatures
CascadeClosed ==
    \A k \in DOMAIN L.verdict :
        log[k].k = "revoke" /\ log[k].reason = "comp" /\ L.verdict[k] # 0 =>
            \A y \in DesignClosure(L.hist[k - 1], log[k].t, log[k].since) \ {log[k].t} :
                L.hist[k].adm[y].parked # 0 \/ L.hist[k].adm[y].revoked # 0

\* No admission by a Delegation takes effect after it ended
DelegationEnds ==
    \A k \in DOMAIN L.verdict :
        log[k].k = "dadmit" /\ L.verdict[k] # 0 => L.hist[k - 1].deleg.ended = 0

\* A proposal completes only with k distinct counted members at the completing entry's state
ProposalsNeedK ==
    \A p \in DOMAIN L.st.props :
        L.st.props[p].how \in {"completed", "activated"} =>
            Cardinality(Counted(L.hist[L.st.props[p].closed - 1], L.st.props[p].signers, L.st.props[p].stmt)) >= K

\* A recovery proposal takes effect only by its tick, once the window has run from its newest recovery
\* signature, with no veto between; no cosign completes one
WindowHolds ==
    \A p \in DOMAIN L.st.props :
        /\ L.st.props[p].kind = "recovery" => L.st.props[p].how # "completed"
        /\ L.st.props[p].how = "activated" =>
            /\ L.st.props[p].a >= L.st.props[p].p + RecoveryWindow
            /\ ~\E k \in L.st.props[p].o .. L.st.props[p].a :
                  log[k].k = "veto" /\ log[k].pid = p /\ L.verdict[k] # 0

\* No activation stands on a recovery key whose binding a cascade had voided: the void closed its proposal
VoidsCloseProposals ==
    \A p \in DOMAIN L.st.props :
        L.st.props[p].how = "activated" =>
            \A rk \in L.st.props[p].signers \cap RecoveryKeys : ~L.hist[L.st.props[p].a - 1].binds[MemberOfKey[rk]].void

\* No base leaves more than TailMax entries unfolded
TailBounded == \A b \in Bases : b - 1 - log[b].ft <= TailMax

\* A lying base forks every reader that judged its tail
LiesAreForks == \A b \in Bases : log[b].lie => L.forked

\* A counted member's cosign of a proposal that the log itself shows open takes effect
ProposalsSurviveFolds ==
    \A k \in DOMAIN L.verdict : log[k].k = "cosign" /\ log[k].pid \in DOMAIN L.verdict =>
        LET j == log[k].pid
            st == L.hist[k - 1]
            stmt == Proposed(log[j])
            earlier == {log[i].s : i \in {i \in j .. k - 1 : log[i].k \in {"propose", "cosign"} /\ log[i].pid \in {0, j}
                                                               /\ (i = j \/ log[i].pid = j) /\ L.verdict[i] # 0}}
            members == {st.adm[s].as : s \in {s \in earlier \cap Sidecars : TRUE}}
            closedByLog == \E i \in j + 1 .. k - 1 :
                              \/ log[i].k \in {"cosign", "tick"} /\ log[i].pid = j /\ L.verdict[i] = 2
                              \/ log[i].k = "veto" /\ log[i].pid = j /\ L.verdict[i] # 0
                              \/ log[i].k = "revoke" /\ log[i].reason = "comp" /\ L.verdict[i] # 0
        IN (/\ log[j].k = "propose" /\ L.verdict[j] = 1 /\ ~closedByLog /\ k <= j + Life
            /\ log[k].at = k - 1 /\ Standing(st, log[k].s) /\ st.adm[log[k].s].as \in AdminMembers
            /\ log[k].s # stmt.t /\ st.adm[log[k].s].as \notin members
            /\ (Cardinality(members \cup {st.adm[log[k].s].as}) < K \/ TypeRule(st, stmt, k) # 0))
           => L.verdict[k] # 0

(***************************************************************************)
(* Stories: the runs that reach each twin's violation directly. A pattern  *)
(* names only the fields an entry must match.                              *)
(***************************************************************************)
StoryNone == <<>>
\* §7.9's new device judges its base's tail on that base's head: a tag's owner moved
StoryTailHead == <<[k |-> "admit", s |-> "a", t |-> "d", as |-> "tag"],
                   [k |-> "base", ft |-> 0, head |-> [selfAdmit |-> "on", tagOwner |-> "m3"]]>>
\* §7.9's new device holds no A_k below its base's retention point: at under it
StoryTailAt == <<[k |-> "admit", s |-> "a", t |-> "c", as |-> "m3", at |-> 0],
                 [k |-> "base", ft |-> 0], [k |-> "base", ft |-> 0]>>
\* rows carry no open proposal: a cosign after the fold completes at L alone
StoryProposals == <<[k |-> "propose", s |-> "a", t |-> "c", as |-> "m2"],
                    [k |-> "base", ft |-> 1], [k |-> "cosign", s |-> "b", pid |-> 1]>>
\* rows carry no self_admit: the rows-only gate refuses what every device accepts
StorySettings == <<[k |-> "admit", s |-> "a", t |-> "d", as |-> "m3"],
                   [k |-> "base", ft |-> 1], [k |-> "admit", s |-> "d", t |-> "c", as |-> "m3"]>>
\* rows carry no ring: a vetoed recovery proposal replays after the fold
StoryRing == <<[k |-> "base", ft |-> 0], [k |-> "bind", s |-> "b", as |-> "m2"],
               [k |-> "rpropose", s |-> "rk2", t |-> "c"], [k |-> "veto", s |-> "a", pid |-> 3],
               [k |-> "base", ft |-> 4], [k |-> "replay", of |-> 3]>>
\* every reader re-judges the tail on the new head: a revocation comes undone
StoryReJudge == <<[k |-> "admit", s |-> "a", t |-> "d", as |-> "tag"],
                  [k |-> "revoke", s |-> "a", t |-> "d", reason |-> "lost"],
                  [k |-> "base", ft |-> 0, head |-> [selfAdmit |-> "on", tagOwner |-> "m3"]]>>
\* the cascade counts from the signer's at: a stolen device backdates its admission
StoryCascadeAt == <<[k |-> "admit", s |-> "a", t |-> "d", as |-> "m3", at |-> 0],
                    [k |-> "revoke", s |-> "b", t |-> "a", reason |-> "comp", since |-> 1]>>
\* a reader skips the bits check: a lying base splits the readers instead of forking
StoryLie == <<[k |-> "admit", s |-> "a", t |-> "d", as |-> "m3"], [k |-> "base", ft |-> 0, lie |-> TRUE]>>
\* the landed code closes every open proposal at a base
StoryClose == <<[k |-> "propose", s |-> "a", t |-> "c", as |-> "m2"],
                [k |-> "base", ft |-> 1], [k |-> "cosign", s |-> "b", pid |-> 1]>>
\* rows keep only the newest confirmation: a park b lifted, then a's confirmation, then a fold, then b's compromise
\* revocation pulls c back into P at the reader that kept every entry and at no reader that started from rows
StoryConfirms == <<[k |-> "deleg", s |-> "a"], [k |-> "dadmit", t |-> "c"], [k |-> "drevoke", s |-> "a", since |-> 1],
                   [k |-> "confirm", s |-> "b", t |-> "c", ck |-> "admission"],
                   [k |-> "confirm", s |-> "a", t |-> "c", ck |-> "admission"],
                   [k |-> "base", ft |-> 5, lie |-> FALSE],
                   [k |-> "revoke", s |-> "a", t |-> "b", reason |-> "comp", since |-> 1]>>
\* a Delegation's key admits after its DelegationRevoke
StoryDelegationEnd == <<[k |-> "deleg", s |-> "a"], [k |-> "drevoke", s |-> "a", since |-> 0],
                        [k |-> "dadmit", t |-> "c"]>>
\* the window from the proposal's entry: a recovery cosign at 4 restarts it, and a tick at 5 activates before 4 + 2
StoryWindowEntry == <<[k |-> "bind", s |-> "a", as |-> "m1"], [k |-> "bind", s |-> "b", as |-> "m2"],
                      [k |-> "rpropose", s |-> "rk1", t |-> "c", as |-> "m1"], [k |-> "rcosign", s |-> "rk2", pid |-> 3],
                      [k |-> "tick", pid |-> 3]>>
\* a void that keeps the proposal open: c bound m2's key, c's compromise voids it, and rk1 alone activates rk2's proposal
StoryVoidKeeps == <<[k |-> "admit", s |-> "b", t |-> "c", as |-> "m2"], [k |-> "bind", s |-> "c", as |-> "m2"],
                    [k |-> "bind", s |-> "a", as |-> "m1"], [k |-> "rpropose", s |-> "rk2", t |-> "d", as |-> "m2"],
                    [k |-> "rcosign", s |-> "rk1", pid |-> 4],
                    [k |-> "revoke", s |-> "a", t |-> "c", reason |-> "comp", since |-> 1], [k |-> "tick", pid |-> 4]>>
\* no cap on the tail
StoryTailCap == <<[k |-> "admit", s |-> "a", t |-> "d", as |-> "m3"], [k |-> "admit", s |-> "a", t |-> "c", as |-> "m3"],
                  [k |-> "base", ft |-> 0]>>

=============================================================================
