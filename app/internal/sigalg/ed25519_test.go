package sigalg

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func TestEd25519RoundTrip(t *testing.T) {
	alg := ed25519Alg{}

	k, err := alg.Generate()
	if err != nil {
		t.Fatalf("Generate() gagal: %v", err)
	}

	msg := []byte("isi manifest")
	sig, err := alg.Sign(k, msg)
	if err != nil {
		t.Fatalf("Sign() gagal: %v", err)
	}

	if len(sig) != alg.SigLen() {
		t.Errorf("panjang signature = %d, want %d", len(sig), alg.SigLen())
	}

	if !alg.Verify(k.Public(), msg, sig) {
		t.Errorf("Verify() seharusnya true untuk pesan dan tanda tangan asli")
	}

	tamperedMsg := append([]byte(nil), msg...)
	tamperedMsg[0] ^= 0x01
	if alg.Verify(k.Public(), tamperedMsg, sig) {
		t.Errorf("Verify() seharusnya false ketika pesan diubah")
	}

	tamperedSig := append([]byte(nil), sig...)
	tamperedSig[0] ^= 0x01
	if alg.Verify(k.Public(), msg, tamperedSig) {
		t.Errorf("Verify() seharusnya false ketika bit signature dibalik")
	}

	if alg.Verify(k.Public(), msg, sig[:63]) {
		t.Errorf("Verify() seharusnya false ketika panjang signature kurang dari 64 byte")
	}

	k2, err := alg.Generate()
	if err != nil {
		t.Fatalf("Generate() kedua gagal: %v", err)
	}
	if alg.Verify(k2.Public(), msg, sig) {
		t.Errorf("Verify() seharusnya false ketika diverifikasi dengan kunci publik lain")
	}
}

func TestEd25519KAT(t *testing.T) {
	const (
		seedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
		pubHex  = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
		sigHex  = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
			"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
	)

	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatalf("gagal dekode seed hex: %v", err)
	}
	pubRFCBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatalf("gagal dekode public key hex: %v", err)
	}
	sigRFC, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("gagal dekode signature hex: %v", err)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pubDerived, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("priv.Public() bukan bertipe ed25519.PublicKey")
	}
	if !bytes.Equal(pubDerived, pubRFCBytes) {
		t.Errorf("kunci publik turunan = %x, want %x", pubDerived, pubRFCBytes)
	}

	alg := ed25519Alg{}
	gotSig, err := alg.Sign(priv, []byte{})
	if err != nil {
		t.Fatalf("Sign() gagal: %v", err)
	}
	if !bytes.Equal(gotSig, sigRFC) {
		t.Errorf("Sign() = %x, want %x", gotSig, sigRFC)
	}

	pubRFC := ed25519.PublicKey(pubRFCBytes)
	if !alg.Verify(pubRFC, []byte{}, sigRFC) {
		t.Errorf("Verify() seharusnya true untuk vektor RFC 8032 TEST 1")
	}
}
