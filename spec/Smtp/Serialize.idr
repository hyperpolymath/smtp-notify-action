-- SPDX-License-Identifier: MPL-2.0
||| Message-serialization contract: DATA dot-stuffing (RFC 5321 §4.5.2) and
||| CRLF rejection in header-bound inputs (header-injection defense).
|||
||| The Zig implementation (`src/message.zig`) mirrors these rules and is
||| tested against golden vectors that `Smtp.EmitZig` computes FROM THIS MODEL
||| at generation time — so the implementation is checked against the spec's
||| own evaluation, not against a hand-written copy of it.
module Smtp.Serialize

import Data.List  -- drop

%default total

||| A body line beginning with '.' must be transmitted with the dot doubled;
||| otherwise a line consisting of just "." would terminate DATA early
||| (silent message truncation — the classic unstuffed-dot bug).
public export
startsWithDot : List Char -> Bool
startsWithDot []       = False
startsWithDot (c :: _) = c == '.'

stuffLineB : Bool -> List Char -> List Char
stuffLineB True  cs = '.' :: cs
stuffLineB False cs = cs

||| Transmit-encode one body line.
public export
stuffLine : List Char -> List Char
stuffLine cs = stuffLineB (startsWithDot cs) cs

||| Safety predicate: a transmitted line may begin with '.' only if the very
||| next character is also '.' — i.e. it can never be mistaken for the DATA
||| terminator, and the receiver's un-stuffing recovers the original line.
public export
safeOnWire : List Char -> Bool
safeOnWire cs = if startsWithDot cs then startsWithDot (drop 1 cs) else True

lemmaStuff : (b : Bool) -> (cs : List Char) -> startsWithDot cs = b
          -> safeOnWire (stuffLineB b cs) = True
lemmaStuff True  cs h = h
lemmaStuff False cs h = rewrite h in Refl

||| THEOREM (all inputs, structural): every stuffed line is safe on the wire.
export
stuffSafe : (cs : List Char) -> safeOnWire (stuffLine cs) = True
stuffSafe cs = lemmaStuff (startsWithDot cs) cs Refl

||| Header-injection defense: a value interpolated into a header line (From,
||| To, Subject) must contain no CR and no LF. A CRLF smuggled into `subject`
||| would otherwise let the caller append arbitrary headers or start the body
||| early. The client REJECTS (aborts), never sanitizes — silent rewriting of
||| a subject is how injection bugs hide.
public export
headerValueOk : List Char -> Bool
headerValueOk = all (\c => c /= '\r' && c /= '\n')

-- ---------------------------------------------------------------------------
-- Golden vectors. EmitZig evaluates `stuffLine`/`headerValueOk` over these
-- and emits (input, expected) pairs into the generated Zig, where unit tests
-- assert the Zig implementation agrees byte-for-byte.
-- ---------------------------------------------------------------------------

public export
stuffCorpus : List (List Char)
stuffCorpus =
  [ unpack ""
  , unpack "."
  , unpack ".."
  , unpack ". leading dot with text"
  , unpack ".hidden"
  , unpack "ordinary line"
  , unpack " . dot after space is untouched"
  , unpack "trailing dot ."
  , unpack "...."
  ]

public export
headerCorpus : List (List Char)
headerCorpus =
  [ unpack "[repo] push to main by owner"
  , unpack "ordinary subject"
  , unpack "bad\r\ninjected: header"
  , unpack "bare\rcr"
  , unpack "bare\nlf"
  , unpack ""
  ]
