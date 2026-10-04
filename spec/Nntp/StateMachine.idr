-- SPDX-License-Identifier: MPL-2.0
||| NNTP client-session state machines (RFC 3977, RFC 4642, RFC 4643) — the
||| single source of truth for the news transport.
|||
||| The tables below ARE the protocol contract. Everything else derives from
||| them:
|||   * the proofs in this module constrain them (coverage, determinism,
|||     reachability, reply-code discipline, ordering),
|||   * `Smtp.EmitZig` serializes them into `src/generated/smtp_fsm.zig`
|||     (the `nntp_*` section), which the hand-written Zig client obeys,
|||   * CI regenerates and diffs, so the Zig tables cannot drift from this file.
|||
||| WHY THIS IS A SEPARATE MODULE, not more rows in `Smtp.StateMachine`:
||| NNTP is not SMTP with different verbs. Its greeting is 200/201 (the 201
||| being a *successful* greeting that forbids exactly what this client came
||| to do), its success codes are not one class (101, 340 and 382 are part of
||| a normal session), and the client's own AUTHINFO challenge (381) sits
||| outside the table exactly as SMTP's 334 does. Sharing one machine would
||| mean one table whose proofs no longer say anything definite about the
||| session actually run — the same reason the two SMTP shapes are split.
|||
||| `nScriptImplicit` (NNTPS on 563, or plaintext for a test sink):
|||
|||   Connect --200--> CAPABILITIES --101--> AUTHINFO --281--> POST --340-->
|||   article + CRLF "." CRLF --240--> QUIT --205--> Done
|||
||| `nScriptStartTls` (the news port, RFC 4642):
|||
|||   Connect --200--> CAPABILITIES --101--> STARTTLS --382--> [upgrade] -->
|||   CAPABILITIES again --101--> AUTHINFO --281--> ... (as above)
|||
||| The second CAPABILITIES is required, not defensive: RFC 4642 §2.2 says the
||| client MUST discard any capability information obtained before the
||| handshake, because the encrypted server may advertise differently —
||| including a different authentication mechanism. A table that kept the
||| cleartext list would be trusting a greeting an active attacker can edit.
|||
||| ON SCOPE, honestly: as with the SMTP machine, the TLS handshake itself is
||| not described here. The table locates it — it is the effect of NActStartTls
||| receiving its 382 — and what is proven is the *shape* of the session, not
||| the cryptography inside the upgrade.
module Nntp.StateMachine

%default total

-- See the note in Smtp.StateMachine: without this, a bare lowercase name in a
-- type signature is auto-bound as a fresh implicit variable, which would make
-- every property a claim about an arbitrary table instead of THE table.
%unbound_implicits off

||| Client-session phases. Each non-terminal phase has exactly one row in a
||| table that uses it, and none in a table that does not.
public export
data NPhase
  = NConnect      -- transport up, await the 200 greeting (server speaks first)
  | NCapabilities -- send CAPABILITIES, await 101 plus a dot-terminated list
  | NStartTls     -- send STARTTLS, await 382; the TLS upgrade follows the 382
  | NCapsTls      -- send CAPABILITIES again on the encrypted stream, await 101
  | NAuth         -- send AUTHINFO; the 381 demand for a password is client-driven
  | NPost         -- send POST, await 340
  | NPayload      -- send the article (dot-stuffed) + terminating ".", await 240
  | NQuit         -- send QUIT, await 205
  | NDone         -- success terminal

||| What the client emits on entering a phase.
public export
data NAction
  = NActNone         -- server speaks first (greeting)
  | NActCapabilities
  | NActStartTls     -- STARTTLS; on 382 the client upgrades the stream in place
  | NActAuthInfo     -- AUTHINFO; the USER/PASS sub-exchange is client-driven
  | NActPost
  | NActPayload      -- RFC 5536 article, dot-stuffed, terminated by CRLF "." CRLF
  | NActQuit

public export
nPhaseIndex : NPhase -> Nat
nPhaseIndex NConnect      = 0
nPhaseIndex NCapabilities = 1
nPhaseIndex NStartTls     = 2
nPhaseIndex NCapsTls      = 3
nPhaseIndex NAuth         = 4
nPhaseIndex NPost         = 5
nPhaseIndex NPayload      = 6
nPhaseIndex NQuit         = 7
nPhaseIndex NDone         = 8

public export
nPhaseEq : NPhase -> NPhase -> Bool
nPhaseEq a b = nPhaseIndex a == nPhaseIndex b

||| One row of an NNTP protocol script.
|||
||| The field names are prefixed because `Smtp.EmitZig` imports this module
||| and `Smtp.StateMachine` together; distinct names keep every field and
||| constructor unambiguous at the emission site, without qualification.
public export
record NStep where
  constructor MkNStep
  nphase   : NPhase
  nsend    : NAction
  ||| Reply codes accepted as success for this row. Any 4xx is transient
  ||| failure, any 5xx permanent failure, anything unlisted is a protocol
  ||| error — the client aborts in all three cases.
  nexpect  : List Nat
  nnext    : NPhase
  ||| Never true: NNTP posts one article per session, so no row repeats. It
  ||| is a field rather than an omission so that adding a repeating row would
  ||| break `nNoRepeats` instead of silently disagreeing with the client.
  nrepeats : Bool

||| Session over a stream that is already encrypted (NNTPS, port 563) or
||| deliberately not encrypted at all. One article per session.
public export
nScriptImplicit : List NStep
nScriptImplicit =
  [ MkNStep NConnect      NActNone         [200] NCapabilities False
  , MkNStep NCapabilities NActCapabilities [101] NAuth         False
  , MkNStep NAuth         NActAuthInfo     [281] NPost         False
  , MkNStep NPost         NActPost         [340] NPayload      False
  , MkNStep NPayload      NActPayload      [240] NQuit         False
  , MkNStep NQuit         NActQuit         [205] NDone         False
  ]

||| Session that begins in cleartext on the news port and upgrades
||| (RFC 4642). Identical to `nScriptImplicit` from NAuth onward; the two
||| extra rows are the upgrade and the mandatory re-advertisement.
public export
nScriptStartTls : List NStep
nScriptStartTls =
  [ MkNStep NConnect      NActNone         [200] NCapabilities False
  , MkNStep NCapabilities NActCapabilities [101] NStartTls     False
  , MkNStep NStartTls     NActStartTls     [382] NCapsTls      False
  , MkNStep NCapsTls      NActCapabilities [101] NAuth         False
  , MkNStep NAuth         NActAuthInfo     [281] NPost         False
  , MkNStep NPost         NActPost         [340] NPayload      False
  , MkNStep NPayload      NActPayload      [240] NQuit         False
  , MkNStep NQuit         NActQuit         [205] NDone         False
  ]

-- ---------------------------------------------------------------------------
-- Properties. All are decided by evaluation over the concrete tables, so each
-- proof is Refl — but only compiles while the property actually holds.
--
-- Every property is stated over BOTH tables, for the reason given in
-- Smtp.StateMachine: a property proven of only one of two tables the client
-- can run is not a property of the client.
-- ---------------------------------------------------------------------------

public export
nAllSteps : (NStep -> Bool) -> List NStep -> Bool
nAllSteps f []        = True
nAllSteps f (s :: ss) = f s && nAllSteps f ss

public export
nScriptLength : List NStep -> Nat
nScriptLength []        = 0
nScriptLength (_ :: ss) = S (nScriptLength ss)

nCountRows : NPhase -> List NStep -> Nat
nCountRows p [] = 0
nCountRows p (s :: ss) =
  (if nPhaseEq (nphase s) p then 1 else 0) + nCountRows p ss

||| Count the rows whose accepted-reply list contains `c`. Used to pin that
||| each intermediate reply of the protocol occurs exactly where it belongs.
nCountCode : Nat -> List NStep -> Nat
nCountCode c [] = 0
nCountCode c (s :: ss) =
  (if elem c (nexpect s) then 1 else 0) + nCountCode c ss

||| Every phase a table uses has exactly one row in it (determinism +
||| coverage), and the terminal phase has none.
export
nDeterministicCoverage :
  ( map (\p => nCountRows p nScriptImplicit)
        [NConnect, NCapabilities, NAuth, NPost, NPayload, NQuit]
      == [1, 1, 1, 1, 1, 1]
  , nCountRows NDone nScriptImplicit == 0
  , map (\p => nCountRows p nScriptStartTls)
        [NConnect, NCapabilities, NStartTls, NCapsTls, NAuth, NPost,
         NPayload, NQuit]
      == [1, 1, 1, 1, 1, 1, 1, 1]
  , nCountRows NDone nScriptStartTls == 0
  ) = (True, True, True, True)
nDeterministicCoverage = Refl

||| The implicit path contains no upgrade. This is what makes the split safe
||| rather than merely tidy: adding STARTTLS cannot have introduced a
||| cleartext-then-upgrade step into the session shape that ships first.
export
nImplicitHasNoUpgrade :
  ( nCountRows NStartTls nScriptImplicit == 0
  , nCountRows NCapsTls nScriptImplicit == 0
  ) = (True, True)
nImplicitHasNoUpgrade = Refl

nLookupStep : NPhase -> List NStep -> Maybe NStep
nLookupStep p [] = Nothing
nLookupStep p (s :: ss) = if nPhaseEq (nphase s) p then Just s else nLookupStep p ss

nWalk : List NStep -> Nat -> NPhase -> Bool
nWalk t Z p = nPhaseEq p NDone
nWalk t (S k) p =
  if nPhaseEq p NDone then True else
    case nLookupStep p t of
      Nothing => False
      Just s  => nWalk t k (nnext s)

||| From NConnect, following `nnext`, each session reaches NDone within the
||| length of its own script — no cycles, no dead ends, in either shape.
export
nReachesDone :
  ( nWalk nScriptImplicit (nScriptLength nScriptImplicit) NConnect
  , nWalk nScriptStartTls (nScriptLength nScriptStartTls) NConnect
  ) = (True, True)
nReachesDone = Refl

nReaches : List NStep -> Nat -> NPhase -> NPhase -> Bool
nReaches t Z from target = nPhaseEq from target
nReaches t (S k) from target =
  if nPhaseEq from target then True else
    case nLookupStep from t of
      Nothing => False
      Just s  => nReaches t k (nnext s) target

||| The upgrade is ON THE PATH, not merely present in the table (the failure
||| mode `upgradeIsOnThePath` in the SMTP spec was written to close), and the
||| article is POSTed only after authentication in both shapes.
export
nUpgradeIsOnThePath :
  ( nReaches nScriptStartTls (nScriptLength nScriptStartTls) NConnect NStartTls
  , nReaches nScriptStartTls (nScriptLength nScriptStartTls) NConnect NCapsTls
  , nReaches nScriptStartTls (nScriptLength nScriptStartTls) NConnect NAuth
  , nReaches nScriptImplicit (nScriptLength nScriptImplicit) NConnect NAuth
  ) = (True, True, True, True)
nUpgradeIsOnThePath = Refl

||| A code this protocol may legitimately accept. Unlike SMTP, NNTP's normal
||| session is not one class: 101 (capability list), 340 (send the article)
||| and 382 (proceed with the handshake) are all intermediate successes. So
||| the discipline is: every accepted code is 2xx, OR is one of those three
||| and occurs exactly where the counts below say.
nCodeOk : Nat -> Bool
nCodeOk c = (200 <= c && c < 300) || c == 101 || c == 340 || c == 382

nRowCodesOk : NStep -> Bool
nRowCodesOk s = all nCodeOk (nexpect s)

||| Reply-code discipline, part one: no row of either shape accepts a 4xx or
||| 5xx as success.
export
nCodesAreSuccesses :
  ( nAllSteps nRowCodesOk nScriptImplicit
  , nAllSteps nRowCodesOk nScriptStartTls
  ) = (True, True)
nCodesAreSuccesses = Refl

||| Reply-code discipline, part two: each of the three intermediate codes
||| occurs at the row that owns it, and the article is accepted (240) exactly
||| once per session.
|||
||| Split into one property per shape rather than one long conjunction: a
||| ten-element tuple type exceeds the elaborator's ambiguity depth and is
||| rejected outright (found by the first real run of the drift gate), and a
||| property per shape also says which session broke when one does.
export
nCodesLocatedImplicit :
  ( nCountCode 101 nScriptImplicit == 1
  , nCountCode 382 nScriptImplicit == 0
  , nCountCode 340 nScriptImplicit == 1
  , nCountCode 240 nScriptImplicit == 1
  ) = (True, True, True, True)
nCodesLocatedImplicit = Refl

||| 101 appears twice in the STARTTLS shape on purpose — before the upgrade
||| and after it — and once in the implicit shape. A table that dropped the
||| post-upgrade row would fail this conjunct, which is the point: it is the
||| row that makes the second advertisement mandatory.
export
nCodesLocatedStartTls :
  ( nCountCode 101 nScriptStartTls == 2
  , nCountCode 382 nScriptStartTls == 1
  , nCountCode 340 nScriptStartTls == 1
  , nCountCode 240 nScriptStartTls == 1
  ) = (True, True, True, True)
nCodesLocatedStartTls = Refl

nRowDoesNotRepeat : NStep -> Bool
nRowDoesNotRepeat s = not (nrepeats s)

||| One article per session: no row repeats. The client's driver consequently
||| has no repeat loop at all, and a table that grew one would fail here
||| rather than disagree with the code that walks it.
export
nNoRepeats :
  ( nAllSteps nRowDoesNotRepeat nScriptImplicit
  , nAllSteps nRowDoesNotRepeat nScriptStartTls
  ) = (True, True)
nNoRepeats = Refl

||| Wire-order soundness, stated on the phase index and so true of any table
||| that respects it. Split in two for the elaborator's depth limit, along the
||| line that matters: the upgrade half forbids authenticating on a cleartext
||| wire, and the article half forbids posting before authenticating.
export
nOrderingSoundUpgrade :
  ( nPhaseIndex NCapabilities < nPhaseIndex NStartTls
  , nPhaseIndex NStartTls     < nPhaseIndex NCapsTls
  , nPhaseIndex NCapsTls      < nPhaseIndex NAuth
  ) = (True, True, True)
nOrderingSoundUpgrade = Refl

export
nOrderingSoundArticle :
  ( nPhaseIndex NAuth    < nPhaseIndex NPost
  , nPhaseIndex NPost    < nPhaseIndex NPayload
  , nPhaseIndex NPayload < nPhaseIndex NQuit
  ) = (True, True, True)
nOrderingSoundArticle = Refl
