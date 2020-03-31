package hsub

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestReference(t *testing.T) {
	passphrase := []byte("Discombobulated Lurcher")
	iv, err := hex.DecodeString("40139416eb0de176")
	if err != nil {
		t.Fatal("Unable to decode IV from hex to byte slice")
	}
	result := "40139416eb0de1769b56b61f073986a4c6475886c05e6a8131cc7d75ee26ad7f32c4494009019394"
	hsub := Generate(iv, passphrase)
	hsubHex := hex.EncodeToString(hsub)
	if result != hsubHex {
		fmt.Println(result)
		fmt.Println(hsubHex)
		t.Fatalf("Collision failed with reference hsub")
	}
}

func TestGenLength(t *testing.T) {
	passphrase := []byte("Discombobulated Lurcher")
	hsub := Encode(passphrase)
	if len(hsub) != HsubLen() {
		t.Fatalf(
			"Incorrect hSub length. Wanted=%d, Got=%d.",
			HsubLen(),
			len(hsub),
		)
	}
}

func TestDecode(t *testing.T) {
	passphrase := []byte("Discombobulated Lurcher")
	reference := "0014d0cdba2030d319e5f70b8941bc86c2b9ac19c9a68ec4fb2bea0827a0e63844aefd595a0767bc"
	result, err := DecodeString(reference, passphrase)
	if err != nil {
		t.Fatalf("Error returned: %s", err)
	}
	if !result {
		t.Fatal("Expected hSub collision")
	}
}

func TestDecodeShort(t *testing.T) {
	passphrase := []byte("Discombobulated Lurcher")
	reference := "cd555213877e86ea64f17dcac3bfb4209348185ddcac43c9"
	result, err := DecodeString(reference, passphrase)
	if err != nil {
		t.Fatalf("Error returned: %s", err)
	}
	if !result {
		t.Fatal("Expected hSub collision")
	}
}

func TestDecodeTooShort(t *testing.T) {
	passphrase := []byte("Discombobulated Lurcher")
	reference := "436d8a7b23f55f76c4d0bef7a3a884347f9c4986b91496"
	result, err := DecodeString(reference, passphrase)
	if err == nil {
		t.Fatalf("Reference hSub is too short.  Should have failed.")
	}
	if result {
		t.Fatal("Unexpected collision with invalid hSub")
	}
	fmt.Println(err)
}

func TestDecodeTooLong(t *testing.T) {
	passphrase := []byte("Discombobulated Lurcher")
	reference := "f41184377f521cb0512b2de19f9bca3dd383193365fae34446a4139565e412647cc6d4656e6a6b1a00"
	result, err := DecodeString(reference, passphrase)
	if err == nil {
		t.Fatalf("Reference hSub is too long.  Should have failed.")
	}
	if result {
		t.Fatal("Unexpected collision with invalid hSub")
	}
	fmt.Println(err)
}

func TestDecodeInvalid(t *testing.T) {
	passphrase := []byte("Discombobulated Lurcher")
	reference := "f41184377f521cb0512b2de19f9bca3dd383193365fae34446a4139565e412647cc6d4656e6a6b1z"
	result, err := DecodeString(reference, passphrase)
	if err == nil {
		t.Fatalf("Reference hSub is invalid Hex.  Should have failed.")
	}
	if result {
		t.Fatal("Unexpected collision with invalid hSub")
	}
	fmt.Println(err)
}
