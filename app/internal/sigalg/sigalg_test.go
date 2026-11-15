package sigalg

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestLookup(t *testing.T) {
	validNames := []string{ProfileRSAPSS, ProfileECDSA, ProfileEd25519}
	for _, name := range validNames {
		alg, ok := Lookup(name)
		if !ok {
			t.Errorf("Lookup(%q) seharusnya ditemukan", name)
			continue
		}
		if alg.Name() != name {
			t.Errorf("Lookup(%q).Name() = %q, want %q", name, alg.Name(), name)
		}
	}

	invalidNames := []string{"rsa", "ED25519", ""}
	for _, name := range invalidNames {
		if alg, ok := Lookup(name); ok {
			t.Errorf("Lookup(%q) seharusnya tidak ditemukan, mendapat %v", name, alg)
		}
	}
}

func TestForKey(t *testing.T) {
	for _, name := range []string{ProfileRSAPSS, ProfileECDSA, ProfileEd25519} {
		alg, _ := Lookup(name)
		k, err := alg.Generate()
		if err != nil {
			t.Fatalf("%s Generate() gagal: %v", name, err)
		}

		gotAlg, err := ForKey(k.Public())
		if err != nil {
			t.Errorf("ForKey(%s valid) gagal: %v", name, err)
			continue
		}
		if gotAlg.Name() != name {
			t.Errorf("ForKey(%s valid).Name() = %q, want %q", name, gotAlg.Name(), name)
		}
	}

	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gagal membangkitkan RSA 2048: %v", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("gagal membangkitkan ECDSA P-384: %v", err)
	}

	invalidKeys := []struct {
		name string
		pub  crypto.PublicKey
	}{
		{name: "RSA 2048 bit", pub: &rsa2048.PublicKey},
		{name: "ECDSA P-384", pub: &p384.PublicKey},
		{name: "Ed25519 31 byte", pub: make([]byte, 31)},
		{name: "bukan kunci string", pub: "x"},
	}

	for _, tc := range invalidKeys {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ForKey(tc.pub); err == nil {
				t.Errorf("ForKey(%s) seharusnya galat, tetapi berhasil", tc.name)
			}
		})
	}
}
