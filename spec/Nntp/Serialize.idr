-- SPDX-License-Identifier: MPL-2.0
||| NNTP article contract: the Newsgroups value grammar (RFC 5536 §3.1.4,
||| posting side) and its header-injection conjunct.
|||
||| The Zig implementation (`src/message.zig`) mirrors these rules and is
||| tested against golden vectors that `Smtp.EmitZig` computes FROM THIS MODEL
||| at generation time — so the implementation is checked against the spec's
||| own evaluation, not against a hand-written copy of it.
|||
||| This is a WELL-FORMEDNESS check, not a hierarchy lookup: it accepts the
||| shape of a newsgroup name without asking whether the group exists, is
||| carried by the server, or is one the caller may post to. A name that
||| passes may still name no group; a name that fails cannot be a group name.
|||
||| The value is REJECTED, never repaired — the same rule as every other
||| header-bound input.
module Nntp.Serialize

import Data.List   -- intersperse, replicate
import Data.List1  -- forget

import Smtp.Serialize  -- headerValueOk

%default total

||| Characters a newsgroup name component may contain. RFC 5536 §3.1.4
||| restricts the field to 7-bit printable ASCII and forbids the wildcard
||| '*'; this client is stricter still and admits only the set the hierarchy
||| actually uses in practice: letters, digits, '+', '-', '_'.
isGroupChar : Char -> Bool
isGroupChar c =
  (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
  (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '_'

maxComponentLen : Nat
maxComponentLen = 32

maxGroupNameLen : Nat
maxGroupNameLen = 255

||| One dot-separated component: 1-32 characters, none of them a separator.
nComponentOk : List Char -> Bool
nComponentOk cs =
  length cs >= 1 && length cs <= maxComponentLen && all isGroupChar cs

||| A newsgroup name: dot-separated components, each well-formed, so no
||| leading, trailing or doubled '.'. Case is NOT folded: the shape is
||| checked, the hierarchy's own case rules are the server's business.
nNameShaped : List Char -> Bool
nNameShaped cs = case forget (split (== '.') cs) of
  []            => False
  (c :: rest)   => nComponentOk c && all nComponentOk rest

nPrefixOf : List Char -> List Char -> Bool
nPrefixOf []       _        = True
nPrefixOf (_ :: _) []       = False
nPrefixOf (x :: xs) (y :: ys) = x == y && nPrefixOf xs ys

||| RFC 5536 §3.1.4: the `control` and `control.*` newsgroups are reserved
||| for control messages and MUST NOT be used for normal articles. Refusing
||| them is not paternalism — posting a notification into them would be a
||| protocol error the server is entitled to reject.
nReserved : List Char -> Bool
nReserved cs =
  cs == unpack "control" || nPrefixOf (unpack "control.") cs

||| One newsgroup name as this client accepts it: correctly shaped, not
||| reserved, not longer than the field's limit.
public export
newsgroupOk : List Char -> Bool
newsgroupOk cs =
  nNameShaped cs && not (nReserved cs) && length cs <= maxGroupNameLen

nTrimSpaces : List Char -> List Char
nTrimSpaces = reverse . dropWhile (== ' ') . reverse . dropWhile (== ' ')

||| A Newsgroups value: one or more names, comma-separated, optional spaces
||| around each (Newsgroups is comma-separated, unlike the dot-separated
||| hierarchy path inside one name).
public export
newsgroupListOk : List Char -> Bool
newsgroupListOk cs =
  all (newsgroupOk . nTrimSpaces) (forget (split (== ',') cs))

||| What the client accepts into the Newsgroups header: a well-formed name
||| list AND a value that passes the header-injection predicate. As with
||| Content-Language, the second conjunct is implied by the first in fact
||| (no name character is CR or LF), but it is stated rather than argued, so
||| the theorem below holds by construction and survives any future loosening
||| of the name grammar.
public export
newsgroupsOk : List Char -> Bool
newsgroupsOk cs = newsgroupListOk cs && headerValueOk cs

nAndRight : (a, b : Bool) -> (a && b) = True -> b = True
nAndRight True  _ prf = prf
nAndRight False _ prf = absurd prf

||| THEOREM (all inputs, structural): nothing the client accepts as a
||| Newsgroups value can inject a header. Removing the injection conjunct
||| from `newsgroupsOk` breaks this proof, not a test.
export
newsgroupsNoInjection : (cs : List Char) -> newsgroupsOk cs = True
                      -> headerValueOk cs = True
newsgroupsNoInjection cs prf =
  nAndRight (newsgroupListOk cs) (headerValueOk cs) prf

-- ---------------------------------------------------------------------------
-- Golden vectors. EmitZig evaluates `newsgroupsOk` over these and emits
-- (input, verdict) pairs into the generated Zig, where unit tests assert the
-- Zig implementation agrees byte-for-byte.
-- ---------------------------------------------------------------------------

||| A component one character past the limit: correctly shaped otherwise, so
||| the vector fails for the length rule and not for a stray character.
nOverlongComponent : List Char
nOverlongComponent = unpack "comp." ++ replicate 33 'a'

||| 399 characters of correctly-shaped name: long enough to exceed the field
||| limit for the right reason (length) rather than a malformed component.
nOverlongName : List Char
nOverlongName =
  concat (intersperse (unpack ".") (replicate 200 (unpack "a")))

public export
newsgroupCorpus : List (List Char)
newsgroupCorpus =
  [ unpack "comp.infosystems.www.authoring.html"
  , unpack "git.annex"
  , unpack "comp.lang.c++"
  , unpack "comp.lang.idris"
  , unpack "alt.test"
  , unpack "uk.rec.cycling"
  , unpack "gmane.comp.version-control.git"
  , unpack "comp.infosystems.www.authoring.html, alt.test"
  , unpack "comp.lang.idris , alt.test"
  , unpack "comp.lang.idris,alt.test"
  , unpack "control"
  , unpack "control.cancel"
  , unpack "comp..lang"
  , unpack ".comp"
  , unpack "comp."
  , unpack "comp lang"
  , unpack "comp/lang"
  , unpack "comp.lang.c#"
  , unpack "*"
  , unpack "*.*"
  , unpack ""
  , unpack "comp.lang.idris\r\nX-Injected: 1"
  , unpack "comp.lang.idris\nInjected: 1"
  , unpack "caf\233"
  , nOverlongComponent
  , nOverlongName
  ]
