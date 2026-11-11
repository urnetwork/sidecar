---------------------------- MODULE ShareSign ----------------------------
(* DESIGN-DETAILS.md section 12: a share's signers against removal and revocation (D-BRIDGE-17; §17.9's share
   signers).

   Network Y accepted a share of network X. Y's ShareKey holder, an admin's device that writes Y's config,
   certifies one ShareSigner per file it writes: a fresh seed and a ShareCert {generation, seed, not_after},
   in a config head sealed at the generation the cert names. Every sidecar that reads Y's config at that
   generation holds the seed and signs its share-link delegations with it. X's host admits a delegation whose
   cert verifies under the pinned ShareKey, is unexpired, runs at most Life from now, and names a generation at
   or above the newest it has verified, which it then raises and keeps.

   Y removes sidecar "r": the removal reaches evs as a rotation to the next generation with holders_shrunk_at
   raised to it, after which evs takes no head sealed below it (§10.6's write gate). "r" keeps every seed of a
   head sealed at a generation it held, and the operator hands it any ciphertext and any cert it has seen. The
   holder's view of the generation can be stale when it certifies, so a renewal races the removal.

   Time runs in days and Life stands for the cert's 7 days.

   Twin breaks one rule:
     NoWriteGate       evs takes a head sealed below holders_shrunk_at
     SeedReuse         the holder certifies a seed an earlier file already carried
     NoRatchet         X's host does not refuse a generation below the newest it verified
     RatchetVolatile   X's host loses its newest verified generation at a restart
     LongCert          the holder certifies for twice Life and X's host does not cap not_after
     RevokeKeepsKey    X's compiled state keeps the share's key after X revoked the share's grant *)
EXTENDS Naturals, FiniteSets

CONSTANTS MaxGen, MaxTime, Life, MaxFiles, RogueHolder, Twin

VARIABLES gen,        \* Y's config generation at evs
          shrunk,     \* holders_shrunk_at: the lowest generation a head may be sealed at
          time,
          member,     \* whether "r" still reads Y's config ("a" always does)
          lastGen,    \* the last generation "r" held, once removed
          removedAt,  \* when r's removal reached evs
          hGen,       \* the holder's view of the generation
          draft,      \* the holder's signer file not yet written, or None
          files,      \* the signer files that landed in a head
          nFiles,
          xMax,       \* X's host: the newest generation it verified, as it holds it
          xEver,      \* history: the newest generation X's host ever verified
          xRevoked,   \* X revoked the share's grant
          lateAdm, staleAdm, revokedAdm, memberAdm, removedAdm, rogueAdm   \* history

vars == <<gen, shrunk, time, member, lastGen, removedAt, hGen, draft, files, nFiles, xMax, xEver, xRevoked,
          lateAdm, staleAdm, revokedAdm, memberAdm, removedAdm, rogueAdm>>

None == [id |-> 0, g |-> 0, seed |-> 0, notAfter |-> 0]
MaxOf(a, b) == IF a >= b THEN a ELSE b

Init ==
  /\ gen = 1 /\ shrunk = 1 /\ time = 0
  /\ member = TRUE /\ lastGen = 0 /\ removedAt = 0
  /\ hGen = 1 /\ draft = None /\ files = {} /\ nFiles = 0
  /\ xMax = 0 /\ xEver = 0 /\ xRevoked = FALSE
  /\ lateAdm = FALSE /\ staleAdm = FALSE /\ revokedAdm = FALSE
  /\ memberAdm = FALSE /\ removedAdm = FALSE /\ rogueAdm = FALSE

Tick ==
  /\ time < MaxTime
  /\ time' = time + 1
  /\ UNCHANGED <<gen, shrunk, member, lastGen, removedAt, hGen, draft, files, nFiles, xMax, xEver, xRevoked,
                 lateAdm, staleAdm, revokedAdm, memberAdm, removedAdm, rogueAdm>>

\* r's removal reaches evs: a rotation, and no head below the new generation is taken from here on
Remove ==
  /\ member /\ gen < MaxGen
  /\ member' = FALSE /\ lastGen' = gen /\ removedAt' = time
  /\ gen' = gen + 1 /\ shrunk' = gen + 1
  /\ UNCHANGED <<time, hGen, draft, files, nFiles, xMax, xEver, xRevoked,
                 lateAdm, staleAdm, revokedAdm, memberAdm, removedAdm, rogueAdm>>

\* a rotation that removes nobody
Rotate ==
  /\ gen < MaxGen
  /\ gen' = gen + 1
  /\ UNCHANGED <<shrunk, time, member, lastGen, removedAt, hGen, draft, files, nFiles, xMax, xEver, xRevoked,
                 lateAdm, staleAdm, revokedAdm, memberAdm, removedAdm, rogueAdm>>

HolderReads ==
  /\ hGen' = gen
  /\ UNCHANGED <<gen, shrunk, time, member, lastGen, removedAt, draft, files, nFiles, xMax, xEver, xRevoked,
                 lateAdm, staleAdm, revokedAdm, memberAdm, removedAdm, rogueAdm>>

\* the holder certifies a signer for the generation it believes current: a fresh seed, not_after Life away
HolderCertifies ==
  /\ draft = None /\ nFiles < MaxFiles
  /\ \E s \in IF Twin = "SeedReuse" /\ files # {} THEN {f.seed : f \in files} ELSE {nFiles + 1} :
       draft' = [id |-> nFiles + 1, g |-> hGen, seed |-> s,
                 notAfter |-> time + IF Twin = "LongCert" THEN 2 * Life ELSE Life]
  /\ nFiles' = nFiles + 1
  /\ UNCHANGED <<gen, shrunk, time, member, lastGen, removedAt, hGen, files, xMax, xEver, xRevoked,
                 lateAdm, staleAdm, revokedAdm, memberAdm, removedAdm, rogueAdm>>

\* the holder writes the file in a head sealed at the cert's generation; the write gate refuses one below shrunk
HolderWrites ==
  /\ draft # None
  /\ draft' = None
  /\ files' = IF draft.g >= shrunk \/ Twin = "NoWriteGate" THEN files \cup {draft} ELSE files
  /\ UNCHANGED <<gen, shrunk, time, member, lastGen, removedAt, hGen, nFiles, xMax, xEver, xRevoked,
                 lateAdm, staleAdm, revokedAdm, memberAdm, removedAdm, rogueAdm>>

\* who holds a file's seed: a current reader, or r for a head sealed at a generation it held
Reads(x, f) == IF x = "a" \/ member THEN TRUE ELSE f.g <= lastGen
Holds(x, s) == \E f \in files : f.seed = s /\ Reads(x, f)

\* a contract carries a delegation x signed with f's seed under f's cert, and X's host admits it
Admit(x, f) ==
  /\ f \in files /\ Holds(x, f.seed)
  /\ ~xRevoked \/ Twin = "RevokeKeepsKey"
  /\ time <= f.notAfter
  /\ f.notAfter <= time + Life \/ Twin = "LongCert"
  /\ f.g >= xMax \/ Twin = "NoRatchet"
  /\ xMax' = MaxOf(xMax, f.g) /\ xEver' = MaxOf(xEver, f.g)
  /\ revokedAdm' = (revokedAdm \/ xRevoked)
  /\ IF x = "r" /\ ~member
     THEN /\ lateAdm' = (lateAdm \/ time > removedAt + Life)
          /\ staleAdm' = (staleAdm \/ xEver > lastGen)
          /\ removedAdm' = TRUE
          /\ memberAdm' = memberAdm
     ELSE /\ memberAdm' = TRUE
          /\ UNCHANGED <<lateAdm, staleAdm, removedAdm>>
  /\ UNCHANGED <<gen, shrunk, time, member, lastGen, removedAt, hGen, draft, files, nFiles, xRevoked, rogueAdm>>

\* a device that once held the ShareKey and left Y certifies a seed of its own
RogueAdmit ==
  /\ RogueHolder /\ ~xRevoked
  /\ rogueAdm' = TRUE
  /\ UNCHANGED <<gen, shrunk, time, member, lastGen, removedAt, hGen, draft, files, nFiles, xMax, xEver,
                 xRevoked, lateAdm, staleAdm, revokedAdm, memberAdm, removedAdm>>

XRevokes ==
  /\ ~xRevoked
  /\ xRevoked' = TRUE
  /\ UNCHANGED <<gen, shrunk, time, member, lastGen, removedAt, hGen, draft, files, nFiles, xMax, xEver,
                 lateAdm, staleAdm, revokedAdm, memberAdm, removedAdm, rogueAdm>>

XRestarts ==
  /\ xMax' = IF Twin = "RatchetVolatile" THEN 0 ELSE xMax
  /\ UNCHANGED <<gen, shrunk, time, member, lastGen, removedAt, hGen, draft, files, nFiles, xEver, xRevoked,
                 lateAdm, staleAdm, revokedAdm, memberAdm, removedAdm, rogueAdm>>

Next ==
  \/ Tick \/ Remove \/ Rotate \/ HolderReads \/ HolderCertifies \/ HolderWrites \/ RogueAdmit \/ XRevokes
  \/ XRestarts
  \/ \E x \in {"a", "r"}, f \in files : Admit(x, f)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
TypeOK ==
  /\ gen \in 1..MaxGen /\ shrunk \in 1..gen /\ time \in 0..MaxTime
  /\ hGen \in 1..gen /\ nFiles \in 0..MaxFiles
  /\ xMax \in 0..MaxGen /\ xEver \in 0..MaxGen

\* a removed sidecar is admitted no later than Life after its removal reached evs
SevenDayBound == ~lateAdm

\* a removed sidecar is never admitted once X's host has verified a generation it did not hold
RatchetBound == ~staleAdm

\* nothing is admitted on a share X revoked
RevokedAdmitsNothing == ~revokedAdm

\* in the design each seed rides exactly one file, sealed at the generation its cert names
OneSeedOneFile == \A f1, f2 \in files : f1.seed = f2.seed => f1 = f2

\* reach: a current reader is admitted; a removed one is, inside its bound; a departed holder is, until X revokes
NoMemberAdmitted == ~memberAdm
NoRemovedAdmitted == ~removedAdm
NoRogueAdmitted == ~rogueAdm
=============================================================================
