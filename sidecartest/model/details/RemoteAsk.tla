------------------------------- MODULE RemoteAsk -------------------------------
(* DESIGN-DETAILS.md section 7: one "search more" on an app host p, asked of the designated search
   indexers its network's config names (7.2.2 to 7.2.4). Each repo in scope goes to one indexer at a
   time: an own one first, a second own one in parallel when the first is slow (the hedge), then, in
   mode on and only once the person has answered that member's notice, one other member's. An indexer
   answers page 0 serving some of the repos and refusing others, or does not answer, or is revoked or
   retired in p's config while the search runs. Of a hedge's two legs the first to serve a repo wins it;
   the other, having answered, may be asked again if the winner fails. A repo no indexer answers falls
   back to the download.

   Eligibility is the design's predicate over what the config says of each device: its member, the
   scopes its search designation holds at, whether it is a consented device of that member, and the
   repos it reads. It is evaluated when a request is sent, never earlier.

   What is checked. Reach: a request naming repo R is sent to indexer d only while eligible(d, R, p)
   holds in p's state, d is own or the mode is on and d's member's notice is answered. OwnerBound: a
   repo bound to a member is named only to a consented device of that member. OneOther: no repo is
   asked of two other members' devices at once, and a hedge runs only among own indexers. ServedByLive:
   a repo counted as served has a live leg naming it. Under LiveSpec, Settles: every repo ends served,
   waiting on a notice, or in the fallback.

   Twin breaks one rule:
     PlanOnce       the indexers of a search are chosen once, at its start, and a failover or a hedge
                    sends to the next of that list without reading the config again
     HedgeOthers    the hedge may go to another member's indexer
     NoNotice       another member's indexer is asked before its member's notice is answered
     LandedRule     eligibility is ConfigState.SearchIndexersFor as landed (config_indexer.go): a device
                    of the asker's member, designated at member scope, answers its member over any
                    repo both read, an EvsShare'd vault of another member included
     KeepOnOwn      a leg to another member's indexer goes on being asked after the mode moves to own

   Left out: pages after the first, cursors, sizes, C19's windows, the rendezvous hash (Rank stands for
   it), stickiness across searches, and the merge (RemoteMerge.tla). *)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Repos,      \* the repos in the search's scope, all read by p
    Owner,      \* repo -> the member it is bound to, or "team"
    Shared,     \* the owner-bound repos p reads by an EvsShare (their owner is not p's member)
    Idx,        \* the devices whose search designation holds in p's config at the start
    Member,     \* indexer -> its member (a tagged one: "tag")
    Scope,      \* indexer -> the scopes its designation holds at, a subset of {"member", "network"}
    Reads,      \* indexer -> the repos it reads
    Rank,       \* indexer -> its place in the rendezvous order, lower first
    Me,         \* p's member
    Twin

VARIABLES
    mode,       \* on | own | off
    notice,     \* member -> unasked | shown | allowed
    gone,       \* indexers revoked, retired, parked or suspended in p's config since the search began
    skip,       \* indexers that failed and are skipped for now
    rs,         \* repo -> todo | asking | served | notice | fallback
    by,         \* repo -> the indexer asked or serving, or "none"
    tried,      \* repo -> the indexers already asked for it in this search
    leg,        \* indexer -> [st: none | sent | live | lost, repos, hedge]
    plan,       \* the eligibility read at the search's start (the twin PlanOnce sends by it)
    sent        \* every (indexer, repo) a request named, with whether the rules held at its send

vars == <<mode, notice, gone, skip, rs, by, tried, leg, plan, sent>>

Own(d) == Member[d] = Me
Others == {d \in Idx : ~Own(d)}
Members == {Member[d] : d \in Others}
Consented(d, m) == Member[d] = m /\ m # "tag"

(* 7.2.2's eligible(d, R, p), in p's newest state. *)
Design(d, r) ==
    /\ d \notin gone
    /\ r \in Reads[d]
    /\ IF Owner[r] = "team"
         THEN (Own(d) /\ "member" \in Scope[d]) \/ "network" \in Scope[d]
         ELSE /\ Consented(d, Owner[r]) /\ "member" \in Scope[d]
              /\ Owner[r] = Me \/ r \in Shared

(* ConfigState.SearchIndexersFor as landed. *)
Landed(d, r) ==
    /\ d \notin gone
    /\ r \in Reads[d]
    /\ Member[d] # "tag" \/ Owner[r] = "team"
    /\ \/ "network" \in Scope[d] /\ Owner[r] = "team"
       \/ "member" \in Scope[d] /\ Member[d] = Me /\ Member[d] # "tag"
       \/ "member" \in Scope[d] /\ r \in Shared /\ Owner[r] = Member[d]

Eligible(d, r) == IF Twin = "LandedRule" THEN Landed(d, r) ELSE Design(d, r)

(* What a send goes by: the config now, or under PlanOnce the reading taken at the start. *)
MayName(d, r) == IF Twin = "PlanOnce" THEN <<d, r>> \in plan ELSE Eligible(d, r)

Open(d) == leg[d].st \in {"sent", "live"}
Asking(r) == {d \in Idx : Open(d) /\ r \in leg[d].repos}

(* The indexers a repo may go to next: own ones first, then, in mode on, other members'. *)
OwnNext(r) == {d \in Idx : Own(d) /\ MayName(d, r) /\ d \notin skip /\ d \notin tried[r] /\ leg[d].st = "none"}
OtherNext(r) == {d \in Others : MayName(d, r) /\ d \notin skip /\ d \notin tried[r] /\ leg[d].st = "none"}
First(s) == CHOOSE d \in s : \A e \in s : Rank[d] <= Rank[e]

NoLeg == [st |-> "none", repos |-> {}, hedge |-> FALSE]

Init ==
    /\ mode \in {"on", "own", "off"}
    /\ notice = [m \in Members |-> "unasked"]
    /\ gone = {} /\ skip = {}
    /\ rs = [r \in Repos |-> "todo"]
    /\ by = [r \in Repos |-> "none"]
    /\ tried = [r \in Repos |-> {}]
    /\ leg = [d \in Idx |-> NoLeg]
    /\ plan = {<<d, r>> \in Idx \X Repos : Eligible(d, r)}
    /\ sent = {}

Rules(d, r) == Design(d, r) /\ mode # "off" /\ (IF Own(d) THEN TRUE ELSE mode = "on" /\ notice[Member[d]] = "allowed")

(* Send page 0 to d for every waiting repo d is next for. One request names them all. *)
Ask(d) ==
    /\ mode # "off" /\ leg[d].st = "none"
    /\ LET mine == {r \in Repos : rs[r] = "todo" /\
                       IF OwnNext(r) # {} THEN d = First(OwnNext(r))
                       ELSE mode = "on" /\ OtherNext(r) # {} /\ d = First(OtherNext(r))}
       IN  /\ mine # {}
           /\ IF Own(d) \/ Twin = "NoNotice" THEN TRUE ELSE notice[Member[d]] = "allowed"
           /\ leg' = [leg EXCEPT ![d] = [st |-> "sent", repos |-> mine, hedge |-> FALSE]]
           /\ rs' = [r \in Repos |-> IF r \in mine THEN "asking" ELSE rs[r]]
           /\ by' = [r \in Repos |-> IF r \in mine THEN d ELSE by[r]]
           /\ tried' = [r \in Repos |-> IF r \in mine THEN tried[r] \cup {d} ELSE tried[r]]
           /\ sent' = sent \cup {<<d, r, Rules(d, r)>> : r \in mine}
    /\ UNCHANGED <<mode, notice, gone, skip, plan>>

(* A repo whose next indexer is another member's waits on that member's notice, shown once. *)
ShowNotice(r) ==
    /\ mode = "on" /\ rs[r] = "todo" /\ OwnNext(r) = {} /\ OtherNext(r) # {}
    /\ notice[Member[First(OtherNext(r))]] # "allowed" /\ Twin # "NoNotice"
    /\ rs' = [rs EXCEPT ![r] = "notice"]
    /\ notice' = [notice EXCEPT ![Member[First(OtherNext(r))]] = "shown"]
    /\ UNCHANGED <<mode, gone, skip, by, tried, leg, plan, sent>>

(* The person answers: Search, or Only my devices. *)
Answer(m, allow) ==
    /\ notice[m] = "shown"
    /\ IF allow
         THEN /\ notice' = [notice EXCEPT ![m] = "allowed"]
              /\ rs' = [r \in Repos |-> IF rs[r] = "notice" THEN "todo" ELSE rs[r]]
              /\ UNCHANGED <<mode, leg>>
         ELSE /\ mode' = "own"
              /\ notice' = [notice EXCEPT ![m] = "unasked"]
              /\ rs' = [r \in Repos |->
                          IF rs[r] = "notice" THEN "todo"
                          ELSE IF rs[r] \in {"asking", "served"} /\ ~Own(by[r]) /\ Twin # "KeepOnOwn" THEN "todo"
                          ELSE rs[r]]
              /\ leg' = [d \in Idx |-> IF ~Own(d) /\ Open(d) /\ Twin # "KeepOnOwn" THEN [leg[d] EXCEPT !.st = "lost"] ELSE leg[d]]
    /\ UNCHANGED <<gone, skip, by, tried, plan, sent>>

(* The hedge: the first own indexer has not answered within the hedge delay, and the next own indexer
   is asked for the repos it may answer. One hedge a leg. *)
Hedge(d, e) ==
    /\ leg[d].st = "sent" /\ ~leg[d].hedge /\ Own(d) /\ leg[e].st = "none" /\ e \notin skip
    /\ Own(e) \/ Twin = "HedgeOthers"
    /\ LET mine == {r \in leg[d].repos : MayName(e, r) /\ e \notin tried[r]}
       IN  /\ mine # {}
           /\ leg' = [leg EXCEPT ![d].hedge = TRUE, ![e] = [st |-> "sent", repos |-> mine, hedge |-> TRUE]]
           /\ tried' = [r \in Repos |-> IF r \in mine THEN tried[r] \cup {e} ELSE tried[r]]
           /\ sent' = sent \cup {<<e, r, Rules(e, r)>> : r \in mine}
    /\ UNCHANGED <<mode, notice, gone, skip, rs, by, plan>>

(* Page 0 arrives from d, serving some of its repos and refusing the rest. A repo another leg already
   serves stays with that leg: the first answer wins, and the later one is dropped for it. A leg that
   wins nothing is ended. *)
Reply(d, served) ==
    /\ leg[d].st = "sent" /\ served \subseteq leg[d].repos
    /\ LET won == {r \in served : rs[r] = "asking"}
           lost == {r \in leg[d].repos \ served : rs[r] = "asking" /\ Asking(r) = {d}}
           beaten == served \ won
       IN  /\ leg' = [leg EXCEPT ![d] = IF won # {} THEN [leg[d] EXCEPT !.st = "live", !.repos = won]
                                        ELSE IF served # {} THEN NoLeg
                                        ELSE [leg[d] EXCEPT !.st = "lost"]]
           /\ rs' = [r \in Repos |-> IF r \in won THEN "served" ELSE IF r \in lost THEN "todo" ELSE rs[r]]
           /\ by' = [r \in Repos |-> IF r \in won THEN d ELSE by[r]]
           \* an indexer that answered and lost a repo to the other leg did not fail it: it may be asked
           \* for that repo again in this search
           /\ tried' = [r \in Repos |-> IF r \in beaten THEN tried[r] \ {d} ELSE tried[r]]
    /\ UNCHANGED <<mode, notice, gone, skip, plan, sent>>

(* What becomes of repo r when d's leg ends: a repo d was asking or serving waits for the hedge's other
   leg while that one still asks for it, and else returns to the plan. *)
After(d, r) ==
    IF r \in leg[d].repos /\ (rs[r] = "asking" \/ (rs[r] = "served" /\ by[r] = d))
    THEN (IF Asking(r) \ {d} = {} THEN "todo" ELSE "asking")
    ELSE rs[r]

(* No first page within the timeout, an Error, or a live leg that fails later: its repos go on, and the
   indexer is skipped. A repo waiting on a notice is planned again when the config moves. *)
Fail(d) ==
    /\ Open(d)
    /\ leg' = [leg EXCEPT ![d].st = "lost"]
    /\ skip' = skip \cup {d}
    /\ rs' = [r \in Repos |-> After(d, r)]
    /\ UNCHANGED <<mode, notice, gone, by, tried, plan, sent>>

(* p's config moves: d is revoked, retired, parked or suspended. An open leg to it ends. *)
Revoke(d) ==
    /\ d \notin gone
    /\ gone' = gone \cup {d}
    /\ leg' = [leg EXCEPT ![d] = IF Open(d) THEN [leg[d] EXCEPT !.st = "lost"] ELSE leg[d]]
    /\ rs' = [r \in Repos |-> IF rs[r] = "notice" THEN "todo" ELSE IF Open(d) THEN After(d, r) ELSE rs[r]]
    /\ UNCHANGED <<mode, notice, skip, by, tried, plan, sent>>

(* Nothing is left to ask for a repo: the download. *)
Fallback(r) ==
    /\ rs[r] = "todo"
    /\ mode = "off" \/ (OwnNext(r) = {} /\ (mode # "on" \/ OtherNext(r) = {}))
    /\ rs' = [rs EXCEPT ![r] = "fallback"]
    /\ UNCHANGED <<mode, notice, gone, skip, by, tried, leg, plan, sent>>

Next ==
    \/ \E d \in Idx : Ask(d) \/ Fail(d) \/ Revoke(d)
    \/ \E d \in Idx, s \in SUBSET Repos : Reply(d, s)
    \/ \E d, e \in Idx : Hedge(d, e)
    \/ \E r \in Repos : ShowNotice(r) \/ Fallback(r)
    \/ \E m \in Members, a \in BOOLEAN : Answer(m, a)

Spec == Init /\ [][Next]_vars

(* Every request is answered or times out, and what can be asked is asked. *)
LiveSpec ==
    /\ Spec
    /\ \A d \in Idx : WF_vars(Ask(d)) /\ WF_vars(leg[d].st = "sent" /\ (Fail(d) \/ \E s \in SUBSET Repos : Reply(d, s)))
    /\ \A r \in Repos : WF_vars(ShowNotice(r)) /\ WF_vars(Fallback(r))

------------------------------------------------------------------------------------------
Reach == \A x \in sent : x[3]

OwnerBound == \A x \in sent : Owner[x[2]] # "team" => Consented(x[1], Owner[x[2]])

OneOther ==
    \A r \in Repos :
        /\ Cardinality({d \in Asking(r) : ~Own(d)}) <= 1
        /\ Cardinality(Asking(r)) > 1 => \A d \in Asking(r) : Own(d)

ServedByLive == \A r \in Repos : rs[r] = "served" => leg[by[r]].st = "live" /\ r \in leg[by[r]].repos

OwnModeQuiet == mode = "own" => \A d \in Others : ~Open(d)

Settles == <>[](\A r \in Repos : rs[r] \in {"served", "notice", "fallback"})
------------------------------------------------------------------------------------------
(* The network the configurations name. p is a device of member me. Its vault is its own; the shared
   vault is member m2's, read by p and by p's own indexer o1 through EvsShares; the team repo is read by
   all. o1 and o2 are me's consented devices, designated at member scope; x1 is m2's consented device, at
   member and network scope; x2 is m3's, at network scope. *)
TheRepos == {"vault", "shared", "team"}
TheOwner == [r \in TheRepos |-> CASE r = "vault" -> "me" [] r = "shared" -> "m2" [] OTHER -> "team"]
TheShared == {"shared"}
TheIdx == {"o1", "o2", "x1", "x2"}
TheMember == [d \in TheIdx |-> CASE d \in {"o1", "o2"} -> "me" [] d = "x1" -> "m2" [] OTHER -> "m3"]
TheScope == [d \in TheIdx |-> CASE d \in {"o1", "o2"} -> {"member"} [] d = "x1" -> {"member", "network"} [] OTHER -> {"network"}]
TheReads == [d \in TheIdx |-> CASE d = "o1" -> {"vault", "shared", "team"} [] d = "o2" -> {"vault", "team"}
                                 [] d = "x1" -> {"shared", "team"} [] OTHER -> {"team"}]
TheRank == [d \in TheIdx |-> CASE d = "o1" -> 1 [] d = "o2" -> 2 [] d = "x1" -> 3 [] OTHER -> 4]
(* A smaller network for the liveness configuration: p's vault and the team repo, its two own indexers
   and m2's. *)
SmallRepos == {"vault", "team"}
SmallIdx == {"o1", "o2", "x1"}
==========================================================================================
