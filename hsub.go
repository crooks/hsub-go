// Package hsub generates and tests the Hashed Subjects frequently used by
// Pseudonym services.
package hsub

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	ivByteLen      int = 8
	hashMinByteLen int = 16
	hsubMinByteLen int = ivByteLen + hashMinByteLen
	sha256ByteLen  int = 256 / 8
	hsubMaxByteLen int = ivByteLen + sha256ByteLen
	hsubGenByteLen int = 24
)

func init() {
	assertAvailablePRNG()
}

// Assert that a cryptographically secure PRNG is available.  If it's not,
// panic!
func assertAvailablePRNG() {
	buf := make([]byte, 1)

	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic(fmt.Sprintf("crypto/rand is unavailable: Read() failed with %#v", err))
	}
}

// HsubLen is a helper function that just returns the constant hsubGenByteLen.
func HsubLen() int {
	return hsubGenByteLen
}

// EncodeToString returns a Hexadecimal representation of a newly generated
// hSub.
func EncodeToString(pw []byte) string {
	return hex.EncodeToString(Encode(pw))
}

// Encode is a wrapper function that generates a random IV and passes it to
// Generate() with the given Passphrase.
func Encode(pw []byte) []byte {
	iv, err := generateRandomBytes(8)
	if err != nil {
		panic(fmt.Sprintf("Random bytes failed: %#v", err))
	}
	return Generate(iv, pw)[:hsubGenByteLen]
}

// Generate generates a new hSub from a given IV and passphrase.
func Generate(iv, pw []byte) (hsub []byte) {
	hash := sha256.New()
	hash.Write(iv)
	hash.Write(pw)
	hsub = append(iv, hash.Sum(nil)...)
	if len(hsub) != 40 {
		panic("Invalid hSub encoding")
	}
	return
}

// DecodeString is a wrapper for Decode().  It expects a string representation
// of an hSub and converts it to a Byte slice for Decode() to process.
func DecodeString(hsubTxt string, pw []byte) (bool, error) {
	hsub, err := hex.DecodeString(hsubTxt)
	if err != nil {
		err := errors.New("hSub string is not valid hexadecimal")
		return false, err
	}
	return Decode(hsub, pw)
}

// Decode generates a new hSub using a provided passphrase and compares it with
// a provided hSub.  If the provided hsub is deemed valid and collides with the
// generated hsub, the function returns True.
func Decode(hsub, pw []byte) (bool, error) {
	hsubLen := len(hsub)
	if hsubLen < hsubMinByteLen {
		err := fmt.Errorf(
			"hSub is too short. Length=%d, Min=%d",
			hsubLen,
			hsubMinByteLen,
		)
		return false, err
	}
	if hsubLen > hsubMaxByteLen {
		err := fmt.Errorf(
			"hSub is too long. Length=%d, Max=%d",
			hsubLen,
			hsubMaxByteLen,
		)
		return false, err
	}
	iv := hsub[:ivByteLen]
	hsubDecoded := Generate(iv, pw)[:hsubLen]
	return bytes.Equal(hsub, hsubDecoded), nil
}

// generateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}
