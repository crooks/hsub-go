package hsub

/*
Package hsub handles the encoding and decoding of a simple, anonymous message
identification scheme.  The system was develop for use on Usenet where
thousands of encrypted, anonymous messages are posted to the Newsgroup
alt.anonymous messages.  To assist users in finding their own messages, the
Subject header contains a Hexadecimal string that can be reproduced to generate
a collision if a secret passphrase is applied.

Structure of an hsub

The hsub is comprised of 64 random bits (R) and the SHA256 hash of these random
bits plus the secret (P).

	H = R + SHA256(R + P)

The resulting hsub is 320 bits long but can be truncated if required.  The
decoding functions will accommodate this truncation during collision detection.

Functions Overview

The core function of the hsub library is Generate().  It generates an hsub from
a provided R and P.  A wrapper function Encode() will generate R and pass it
and a given P to Generate().  A further wrapper EncodeToString() will Hex
encode the hsub and return it as a string.

The principle decoding function is Decode().  This takes an existing hsub and
secret (P) as Byte slices and generates a new hSub using them.  If the
resulting hsub matches the provided hsub, a boolean True is returned. A wrapper
function DecodeString takes the hsub as a Hex encoded string and converts it to
the Byte slice.

Error handling

The decoding functions are tolerant of many formating errors.  The functions
are designed to process Newsgroups where many of the messages will have
non-compliant subjects.  Although errors are returned from the library, it is
expected that during normal usage, these will be treated as non-colliding
messages and ignored.
*/
