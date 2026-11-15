package sigalg

import "testing"

func TestECDSARoundTrip(t *testing.T) {
	alg := ecdsaP256{}

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

	tamperedR := append([]byte(nil), sig...)
	tamperedR[0] ^= 0x01
	if alg.Verify(k.Public(), msg, tamperedR) {
		t.Errorf("Verify() seharusnya false ketika bit pada bagian r (sig[0]) dibalik")
	}

	tamperedS := append([]byte(nil), sig...)
	tamperedS[63] ^= 0x01
	if alg.Verify(k.Public(), msg, tamperedS) {
		t.Errorf("Verify() seharusnya false ketika bit pada bagian s (sig[63]) dibalik")
	}

	if alg.Verify(k.Public(), msg, sig[:63]) {
		t.Errorf("Verify() seharusnya false ketika panjang signature kurang (63 byte)")
	}

	longerSig := append(append([]byte(nil), sig...), 0x00)
	if alg.Verify(k.Public(), msg, longerSig) {
		t.Errorf("Verify() seharusnya false ketika panjang signature berlebih (65 byte)")
	}

	k2, err := alg.Generate()
	if err != nil {
		t.Fatalf("Generate() kedua gagal: %v", err)
	}
	if alg.Verify(k2.Public(), msg, sig) {
		t.Errorf("Verify() seharusnya false ketika diverifikasi dengan kunci publik lain")
	}
}
