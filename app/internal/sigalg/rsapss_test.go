package sigalg

import (
	"crypto/rsa"
	"testing"
)

func TestRSAPSSRoundTrip(t *testing.T) {
	alg := rsaPSS{}

	k, err := alg.Generate()
	if err != nil {
		t.Fatalf("Generate() gagal: %v", err)
	}

	pub, ok := k.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("k.Public() bukan bertipe *rsa.PublicKey")
	}
	if pub.N.BitLen() != 3072 {
		t.Errorf("N.BitLen() = %d, want 3072", pub.N.BitLen())
	}
	if pub.E != 65537 {
		t.Errorf("E = %d, want 65537", pub.E)
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

	tamperedFirst := append([]byte(nil), sig...)
	tamperedFirst[0] ^= 0x01
	if alg.Verify(k.Public(), msg, tamperedFirst) {
		t.Errorf("Verify() seharusnya false ketika bit pada sig[0] dibalik")
	}

	tamperedLast := append([]byte(nil), sig...)
	tamperedLast[383] ^= 0x01
	if alg.Verify(k.Public(), msg, tamperedLast) {
		t.Errorf("Verify() seharusnya false ketika bit pada sig[383] dibalik")
	}

	if alg.Verify(k.Public(), msg, sig[:383]) {
		t.Errorf("Verify() seharusnya false ketika panjang signature kurang (383 byte)")
	}

	longerSig := append(append([]byte(nil), sig...), 0x00)
	if alg.Verify(k.Public(), msg, longerSig) {
		t.Errorf("Verify() seharusnya false ketika panjang signature berlebih (385 byte)")
	}

	k2, err := alg.Generate()
	if err != nil {
		t.Fatalf("Generate() kedua gagal: %v", err)
	}
	if alg.Verify(k2.Public(), msg, sig) {
		t.Errorf("Verify() seharusnya false ketika diverifikasi dengan kunci publik lain")
	}
}
