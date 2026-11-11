------------------------------- MODULE RemoteAsk -------------------------------
(* DESIGN-DETAILS.md section 7: one "search more" on an app host p, asked of the designated search
   indexers its network's config names (7.2.2 to 7.2.4), as amended for QD-707. The first two own
   indexers, the ones p keeps warm, are asked at once, each for the repos it may answer; a repo neither
   of them can be asked for goes to the next own indexer alone; then, in mode on and only once the person
   has answered that member's notice, to one other member's. An indexer answers page 0 serving some of
   the repos and refusing others, or does not answer, or is revoked or retired in p's config while the
   search runs. Of two legs that name one repo the first to serve it wins it and the other's reply is
   dropped for it; the other, having answered, may be asked again if the winner fails. A repo no indexer
   answers falls back to the download.

   Eligibility is the design's predicate over what the config says of each device: its member, the
   scopes its search designation holds at, whether it is a consented device of that member, and the
   repos it reads. It is evaluated when a request is sent, never earlier.

   What is checked. Reach: a request naming repo R is sent to indexer d only while eligible(d, R, p)
   holds in p's state, d is own or the mode is on and d's member's notice is answered. OwnerBound: a
   repo bound to a member is named only to a consented device of that member. OneOther: no repo is
   asked of two other members' devices at once, and two legs name one repo only when both go to own
   indexers. TwoAtOnce: at most two legs name a repo at once. WarmFirst: an own indexer that is not one
   of the warm two is asked for a repo only when neither of those can be. OneServes: a repo is served
   by at most one leg. ServedByLive: a repo counted as served has a live leg naming it. Under LiveSpec,
   Settles: every repo ends served, waiting on a notice, or in the fallback.

   Twin breaks one rule:
     PlanOnce       the indexers of a search are chosen once, at its start, and a later plan sends to
                    the next of that list without reading the config again
     PairOthers     where only one own indexer can be asked for a repo, another member's indexer is
                    asked beside it
     AskAllOwn      every own indexer that may answer a repo is asked at once, not the warm two
     KeepBoth       the second page 0 to serve a repo is kept as well as the first
     NoNotice       another member's indexer is asked before its member's notice is answered
     LandedRule     eligibility is ConfigState.SearchIndexersFor as landed (config_indexer.go): a device
                    of the asker's member, designated at member scope, answers its member over any
                    repo both read, an EvsShare'd vault of another member included
     KeepOnOwn      a leg to another member's indexer goes on being asked after the mode moves to own

   Left out: pages after the first, cursors, sizes, C19's windows and the foreground that names the warm
   pairs (Warm stands for the set it named), the rendezvous hash (Rank stands for it), stickiness across
   searches, and the merge (RemoteMerge.tla). *)
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
    leg,        \* indexer -> [st: none | sent | live | lost, repos]
    plan,       \* the eligibility read at the search's start (the twin PlanOnce sends by it)
    sent,       \* every (indexer, repo) a request named, with whether the rules held at its send
    cold        \* history: an own indexer outside the warm two was asked for a repo one of them could take

vars == <<mode, notice, gone, skip, rs, by, tried, leg, plan, sent, cold>>

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

NoLeg == [st |-> "none", repos |-> {}]

Init ==
    /\ mode \in {"on", "own", "off"}
    /\ notice = [m \in Members |-> "unasked"]
    /\ gone = {} /\ skip = {}
    /\ rs = [r \in Repos |-> "todo"]
    /\ by = [r \in Repos |-> "none"]
    /\ tried = [r \in Repos |-> {}]
    /\ leg = [d \in Idx |-> NoLeg]
    /\ plan = {<<d, r>> \in Idx \X Repos : Eligible(d, r)}
    /\ sent = {} /\ cold = FALSE

Rules(d, r) == Design(d, r) /\ mode # "off" /\ (IF Own(d) THEN TRUE ELSE mode = "on" /\ notice[Member[d]] = "allowed")

(* The warm two: the first two own indexers, by rank, that the config lets answer p for some repo. The
   foreground names them and keeps their pairs warm; a change of the config names them again. *)
Lower(S, d) == {e \in S : Rank[e] < Rank[d]}
WarmOwn ==
    LET cand == {d \in Idx : Own(d) /\ \E r \in Repos : MayName(d, r)}
    IN  {d \in cand : Cardinality(Lower(cand, d)) < 2}

(* Whom the plan asks for a waiting repo: those of the warm two that can be asked for it, both at once;
   with neither, the next own indexer, alone; with no own one, in mode on, one other member's, once its
   notice is answered. *)
Targets(r) ==
    IF OwnNext(r) # {}
    THEN LET own == IF Twin = "AskAllOwn" THEN OwnNext(r)
                    ELSE IF OwnNext(r) \cap WarmOwn # {} THEN OwnNext(r) \cap WarmOwn
                    ELSE {First(OwnNext(r))}
         IN  IF Twin = "PairOthers" /\ Cardinality(own) = 1 /\ OtherNext(r) # {}
             THEN own \cup {First(OtherNext(r))} ELSE own
    ELSE IF mode = "on" /\ OtherNext(r) # {}
              /\ (Twin = "NoNotice" \/ notice[Member[First(OtherNext(r))]] = "allowed")
         THEN {First(OtherNext(r))}
         ELSE {}

(* The plan: every waiting repo that has someone to ask is asked now, in one step, one request an
   indexer naming all its repos. Eligibility, the mode and the answers are read here. *)
Assign ==
    /\ mode # "off"
    /\ LET todo == {r \in Repos : rs[r] = "todo" /\ Targets(r) # {}}
           ds == UNION {Targets(r) : r \in todo}
           mine(d) == {r \in todo : d \in Targets(r)}
       IN  /\ todo # {}
           /\ leg' = [d \in Idx |-> IF d \in ds THEN [st |-> "sent", repos |-> mine(d)] ELSE leg[d]]
           /\ rs' = [r \in Repos |-> IF r \in todo THEN "asking" ELSE rs[r]]
           /\ by' = [r \in Repos |-> IF r \in todo THEN First(Targets(r)) ELSE by[r]]
           /\ tried' = [r \in Repos |-> IF r \in todo THEN tried[r] \cup Targets(r) ELSE tried[r]]
           /\ sent' = sent \cup UNION {{<<d, r, Rules(d, r)>> : r \in mine(d)} : d \in ds}
           /\ cold' = (cold \/ \E r \in todo : \E d \in Targets(r) :
                                  Own(d) /\ d \notin WarmOwn /\ OwnNext(r) \cap WarmOwn # {})
    /\ UNCHANGED <<mode, notice, gone, skip, plan>>

(* A repo whose next indexer is another member's waits on that member's notice, shown once. *)
ShowNotice(r) ==
    /\ mode = "on" /\ rs[r] = "todo" /\ OwnNext(r) = {} /\ OtherNext(r) # {}
    /\ notice[Member[First(OtherNext(r))]] # "allowed" /\ Twin # "NoNotice"
    /\ rs' = [rs EXCEPT ![r] = "notice"]
    /\ notice' = [notice EXCEPT ![Member[First(OtherNext(r))]] = "shown"]
    /\ UNCHANGED <<mode, gone, skip, by, tried, leg, plan, sent, cold>>

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
    /\ UNCHANGED <<gone, skip, by, tried, plan, sent, cold>>

(* Page 0 arrives from d, serving some of its repos and refusing the rest. A repo another leg already
   serves stays with that leg: the first answer wins, and the later one is dropped for it. A leg that
   wins nothing is ended. *)
Reply(d, served) ==
    /\ leg[d].st = "sent" /\ served \subseteq leg[d].repos
    /\ LET won == IF Twin = "KeepBoth" THEN served ELSE {r \in served : rs[r] = "asking"}
           lost == {r \in leg[d].repos \ served : rs[r] = "asking" /\ Asking(r) = {d}}
           beaten == served \ won
       IN  /\ leg' = [leg EXCEPT ![d] = IF won # {} THEN [leg[d] EXCEPT !.st = "live", !.repos = won]
                                        ELSE IF served # {} THEN NoLeg
                                        ELSE [leg[d] EXCEPT !.st = "lost"]]
           /\ rs' = [r \in Repos |-> IF r \in won THEN "served" ELSE IF r \in lost THEN "todo" ELSE rs[r]]
           /\ by' = [r \in Repos |-> IF r \in won /\ rs[r] = "asking" THEN d ELSE by[r]]
           \* an indexer that answered and lost a repo to the other leg did not fail it: it may be asked
           \* for that repo again in this search
           /\ tried' = [r \in Repos |-> IF r \in beaten THEN tried[r] \ {d} ELSE tried[r]]
    /\ UNCHANGED <<mode, notice, gone, skip, plan, sent, cold>>

(* What becomes of repo r when d's leg ends: a repo d was asking or serving waits for the other leg
   while that one still asks for it, and else returns to the plan. *)
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
    /\ UNCHANGED <<mode, notice, gone, by, tried, plan, sent, cold>>

(* p's config moves: d is revoked, retired, parked or suspended. An open leg to it ends. *)
Revoke(d) ==
    /\ d \notin gone
    /\ gone' = gone \cup {d}
    /\ leg' = [leg EXCEPT ![d] = IF Open(d) THEN [leg[d] EXCEPT !.st = "lost"] ELSE leg[d]]
    /\ rs' = [r \in Repos |-> IF rs[r] = "notice" THEN "todo" ELSE IF Open(d) THEN After(d, r) ELSE rs[r]]
    /\ UNCHANGED <<mode, notice, skip, by, tried, plan, sent, cold>>

(* Nothing is left to ask for a repo: the download. *)
Fallback(r) ==
    /\ rs[r] = "todo"
    /\ mode = "off" \/ (OwnNext(r) = {} /\ (mode # "on" \/ OtherNext(r) = {}))
    /\ rs' = [rs EXCEPT ![r] = "fallback"]
    /\ UNCHANGED <<mode, notice, gone, skip, by, tried, leg, plan, sent, cold>>

Next ==
    \/ Assign
    \/ \E d \in Idx : Fail(d) \/ Revoke(d)
    \/ \E d \in Idx, s \in SUBSET Repos : Reply(d, s)
    \/ \E r \in Repos : ShowNotice(r) \/ Fallback(r)
    \/ \E m \in Members, a \in BOOLEAN : Answer(m, a)

Spec == Init /\ [][Next]_vars

(* Every request is answered or times out, and what can be asked is asked. *)
LiveSpec ==
    /\ Spec
    /\ WF_vars(Assign)
    /\ \A d \in Idx : WF_vars(leg[d].st = "sent" /\ (Fail(d) \/ \E s \in SUBSET Repos : Reply(d, s)))
    /\ \A r \in Repos : WF_vars(ShowNotice(r)) /\ WF_vars(Fallback(r))

------------------------------------------------------------------------------------------
Reach == \A x \in sent : x[3]

OwnerBound == \A x \in sent : Owner[x[2]] # "team" => Consented(x[1], Owner[x[2]])

OneOther ==
    \A r \in Repos :
        /\ Cardinality({d \in Asking(r) : ~Own(d)}) <= 1
        /\ Cardinality(Asking(r)) > 1 => \A d \in Asking(r) : Own(d)

TwoAtOnce == \A r \in Repos : Cardinality(Asking(r)) <= 2

WarmFirst == ~cold

OneServes == \A r \in Repos : Cardinality({d \in Idx : leg[d].st = "live" /\ r \in leg[d].repos}) <= 1

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
(* o3 is a third consented device of me, designated at member scope, which the three-own configurations add. *)
AllIdx == TheIdx \cup {"o3"}
TheMember == [d \in AllIdx |-> CASE d \in {"o1", "o2", "o3"} -> "me" [] d = "x1" -> "m2" [] OTHER -> "m3"]
TheScope == [d \in AllIdx |-> CASE d \in {"o1", "o2", "o3"} -> {"member"} [] d = "x1" -> {"member", "network"} [] OTHER -> {"network"}]
TheReads == [d \in AllIdx |-> CASE d = "o1" -> {"vault", "shared", "team"} [] d \in {"o2", "o3"} -> {"vault", "team"}
                                 [] d = "x1" -> {"shared", "team"} [] OTHER -> {"team"}]
TheRank == [d \in AllIdx |-> CASE d = "o1" -> 1 [] d = "o2" -> 2 [] d = "o3" -> 3 [] d = "x1" -> 4 [] OTHER -> 5]
(* A smaller network for the liveness configuration: p's vault and the team repo, its two own indexers
   and m2's. *)
SmallRepos == {"vault", "team"}
SmallIdx == {"o1", "o2", "x1"}
(* Three own indexers and one other member's, over the same two repos: only the first two are asked at once. *)
ThreeIdx == {"o1", "o2", "o3", "x1"}
==========================================================================================
