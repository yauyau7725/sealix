package keys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FityatulhaqRosyidi/sealix/app/internal/sigalg"
)

func mustEncodePublicPEM(t *testing.T, pub crypto.PublicKey, label string) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey gagal: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  label,
		Bytes: der,
	})
}

func wrapBase64(b64 string, width int) string {
	var b strings.Builder
	for i := 0; i < len(b64); i += width {
		end := i + width
		if end > len(b64) {
			end = len(b64)
		}
		b.WriteString(b64[i:end])
		b.WriteByte('\n')
	}
	return b.String()
}

func TestParsePublicPEMAndFingerprint(t *testing.T) {
	profiles := []string{sigalg.ProfileEd25519, sigalg.ProfileECDSA, sigalg.ProfileRSAPSS}

	for _, name := range profiles {
		t.Run("valid_"+name, func(t *testing.T) {
			alg, ok := sigalg.Lookup(name)
			if !ok {
				t.Fatalf("Lookup(%q) gagal", name)
			}
			priv, err := alg.Generate()
			if err != nil {
				t.Fatalf("Generate() gagal: %v", err)
			}

			pemBytes := mustEncodePublicPEM(t, priv.Public(), "PUBLIC KEY")
			pub, gotAlg, err := ParsePublicPEM(pemBytes)
			if err != nil {
				t.Fatalf("ParsePublicPEM gagal: %v", err)
			}
			if gotAlg.Name() != name {
				t.Errorf("profil = %q, want %q", gotAlg.Name(), name)
			}

			fp, err := Fingerprint(pub)
			if err != nil {
				t.Fatalf("Fingerprint gagal: %v", err)
			}
			if len(fp) != 64 {
				t.Errorf("panjang Fingerprint = %d, want 64", len(fp))
			}
			for _, ch := range fp {
				if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
					t.Errorf("Fingerprint mengandung karakter non-hex huruf kecil: %q", fp)
					break
				}
			}

			// Uji variasi CRLF (\r\n)
			crlfPEM := bytes.ReplaceAll(pemBytes, []byte("\n"), []byte("\r\n"))
			pubCRLF, _, err := ParsePublicPEM(crlfPEM)
			if err != nil {
				t.Fatalf("ParsePublicPEM CRLF gagal: %v", err)
			}
			fpCRLF, err := Fingerprint(pubCRLF)
			if err != nil {
				t.Fatalf("Fingerprint CRLF gagal: %v", err)
			}
			if fpCRLF != fp {
				t.Errorf("Fingerprint CRLF = %q, want %q", fpCRLF, fp)
			}

			// Uji pemenggalan lebar baris berbeda (32 karakter per baris)
			der, _ := x509.MarshalPKIXPublicKey(priv.Public())
			b64 := base64.StdEncoding.EncodeToString(der)
			rewrappedPEM := []byte("-----BEGIN PUBLIC KEY-----\n" + wrapBase64(b64, 32) + "-----END PUBLIC KEY-----\n")
			pubRewrapped, _, err := ParsePublicPEM(rewrappedPEM)
			if err != nil {
				t.Fatalf("ParsePublicPEM lebar baris berbeda gagal: %v", err)
			}
			fpRewrapped, err := Fingerprint(pubRewrapped)
			if err != nil {
				t.Fatalf("Fingerprint lebar baris berbeda gagal: %v", err)
			}
			if fpRewrapped != fp {
				t.Errorf("Fingerprint lebar baris berbeda = %q, want %q", fpRewrapped, fp)
			}

			// Uji kunci berbeda menghasilkan Fingerprint berbeda
			priv2, err := alg.Generate()
			if err != nil {
				t.Fatalf("Generate() kedua gagal: %v", err)
			}
			fp2, err := Fingerprint(priv2.Public())
			if err != nil {
				t.Fatalf("Fingerprint kunci kedua gagal: %v", err)
			}
			if fp2 == fp {
				t.Errorf("dua kunci berbeda menghasilkan Fingerprint yang sama: %q", fp)
			}
		})
	}

	// Siapkan sampel PEM valid untuk kasus negatif
	edAlg, _ := sigalg.Lookup(sigalg.ProfileEd25519)
	edPriv, _ := edAlg.Generate()
	validPEM := mustEncodePublicPEM(t, edPriv.Public(), "PUBLIC KEY")

	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Generate RSA 2048 gagal: %v", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Generate ECDSA P-384 gagal: %v", err)
	}

	derEd, _ := x509.MarshalPKIXPublicKey(edPriv.Public())
	pemWithHeader := pem.EncodeToMemory(&pem.Block{
		Type:    "PUBLIC KEY",
		Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"},
		Bytes:   derEd,
	})

	invalidCases := []struct {
		name string
		data []byte
	}{
		{name: "label salah", data: mustEncodePublicPEM(t, edPriv.Public(), "RSA PUBLIC KEY")},
		{name: "ada header PEM", data: pemWithHeader},
		{name: "dua blok PEM digabung", data: append(append([]byte(nil), validPEM...), validPEM...)},
		{name: "teks acak bukan PEM", data: []byte("ini bukan blok PEM sama sekali")},
		{name: "kunci RSA 2048", data: mustEncodePublicPEM(t, &rsa2048.PublicKey, "PUBLIC KEY")},
		{name: "kunci ECDSA P-384", data: mustEncodePublicPEM(t, &p384.PublicKey, "PUBLIC KEY")},
	}

	for _, tc := range invalidCases {
		t.Run("invalid_"+tc.name, func(t *testing.T) {
			if _, _, err := ParsePublicPEM(tc.data); err == nil {
				t.Errorf("ParsePublicPEM(%s) seharusnya galat, tetapi berhasil", tc.name)
			}
		})
	}
}

func TestPrivatePEMAndMarshal(t *testing.T) {
	profiles := []string{sigalg.ProfileEd25519, sigalg.ProfileECDSA, sigalg.ProfileRSAPSS}

	for _, name := range profiles {
		t.Run("roundtrip_"+name, func(t *testing.T) {
			alg, _ := sigalg.Lookup(name)
			origPriv, err := alg.Generate()
			if err != nil {
				t.Fatalf("Generate() gagal: %v", err)
			}

			origFP, err := Fingerprint(origPriv.Public())
			if err != nil {
				t.Fatalf("Fingerprint asli gagal: %v", err)
			}

			// Uji MarshalPrivatePEM -> ParsePrivatePEM
			privPEM, err := MarshalPrivatePEM(origPriv)
			if err != nil {
				t.Fatalf("MarshalPrivatePEM gagal: %v", err)
			}

			parsedPriv, gotAlg, err := ParsePrivatePEM(privPEM)
			if err != nil {
				t.Fatalf("ParsePrivatePEM gagal: %v", err)
			}
			if gotAlg.Name() != name {
				t.Errorf("profil = %q, want %q", gotAlg.Name(), name)
			}

			parsedFP, err := Fingerprint(parsedPriv.Public())
			if err != nil {
				t.Fatalf("Fingerprint hasil parse gagal: %v", err)
			}
			if parsedFP != origFP {
				t.Errorf("Fingerprint = %q, want %q", parsedFP, origFP)
			}

			// Uji tanda tangan dengan kunci hasil parse dan verifikasi dengan kunci publik asli
			msg := []byte("uji tanda tangan kunci privat")
			sig, err := gotAlg.Sign(parsedPriv, msg)
			if err != nil {
				t.Fatalf("Sign() dengan kunci hasil parse gagal: %v", err)
			}
			if !alg.Verify(origPriv.Public(), msg, sig) {
				t.Errorf("Verify() gagal untuk tanda tangan dari kunci privat hasil parse")
			}

			// Uji MarshalPublicPEM -> ParsePublicPEM
			pubPEM, err := MarshalPublicPEM(origPriv.Public())
			if err != nil {
				t.Fatalf("MarshalPublicPEM gagal: %v", err)
			}
			parsedPub, _, err := ParsePublicPEM(pubPEM)
			if err != nil {
				t.Fatalf("ParsePublicPEM gagal: %v", err)
			}
			pubFP, err := Fingerprint(parsedPub)
			if err != nil {
				t.Fatalf("Fingerprint dari MarshalPublicPEM gagal: %v", err)
			}
			if pubFP != origFP {
				t.Errorf("Fingerprint MarshalPublicPEM = %q, want %q", pubFP, origFP)
			}
		})
	}

	// Kasus negatif ParsePrivatePEM
	edAlg, _ := sigalg.Lookup(sigalg.ProfileEd25519)
	edPriv, _ := edAlg.Generate()
	edPubPEM, _ := MarshalPublicPEM(edPriv.Public())

	pkcs8Ed, _ := x509.MarshalPKCS8PrivateKey(edPriv)
	wrongLabelPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pkcs8Ed,
	})

	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Generate RSA 2048 gagal: %v", err)
	}
	rsa2048PEM, _ := MarshalPrivatePEM(rsa2048)

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Generate ECDSA P-384 gagal: %v", err)
	}
	p384PEM, _ := MarshalPrivatePEM(p384)

	invalidPrivCases := []struct {
		name string
		data []byte
	}{
		{name: "PEM kunci publik", data: edPubPEM},
		{name: "label RSA PRIVATE KEY", data: wrongLabelPEM},
		{name: "kunci privat RSA 2048", data: rsa2048PEM},
		{name: "kunci privat ECDSA P-384", data: p384PEM},
	}

	for _, tc := range invalidPrivCases {
		t.Run("invalid_"+tc.name, func(t *testing.T) {
			if _, _, err := ParsePrivatePEM(tc.data); err == nil {
				t.Errorf("ParsePrivatePEM(%s) seharusnya galat, tetapi berhasil", tc.name)
			}
		})
	}

	// Tes keamanan: galat tidak membocorkan isi Base64 kunci privat
	t.Run("no_secret_leak_in_error", func(t *testing.T) {
		secretPayload := []byte("RAHASIA_KUNCI_PRIVAT_SUPER_SENSITIF_1234567890")
		malformedPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: secretPayload,
		})
		b64Secret := base64.StdEncoding.EncodeToString(secretPayload)

		_, _, err := ParsePrivatePEM(malformedPEM)
		if err == nil {
			t.Fatalf("ParsePrivatePEM dengan DER rusak seharusnya galat")
		}
		if strings.Contains(err.Error(), b64Secret) {
			t.Errorf("pesan galat membocorkan isi Base64 kunci privat: %v", err)
		}
	})
}

func TestWriteKeyPair(t *testing.T) {
	alg, _ := sigalg.Lookup(sigalg.ProfileEd25519)
	priv1, err := alg.Generate()
	if err != nil {
		t.Fatalf("Generate() 1 gagal: %v", err)
	}
	priv2, err := alg.Generate()
	if err != nil {
		t.Fatalf("Generate() 2 gagal: %v", err)
	}

	dir := t.TempDir()
	prefix := filepath.Join(dir, "publisher")
	privPath := prefix + ".key.pem"
	pubPath := prefix + ".pub.pem"

	// 1. Tulis kunci Ed25519 baru
	fp1, err := WriteKeyPair(prefix, priv1, false)
	if err != nil {
		t.Fatalf("WriteKeyPair baru gagal: %v", err)
	}

	privInfo, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("berkas privat tidak ditemukan: %v", err)
	}
	if perm := privInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("izin berkas privat = %o, want 0600", perm)
	}

	// 2. Baca balik dengan ParsePrivatePEM dan ParsePublicPEM
	privDisk, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("gagal membaca berkas privat: %v", err)
	}
	pubDisk, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("gagal membaca berkas publik: %v", err)
	}

	if _, _, err := ParsePrivatePEM(privDisk); err != nil {
		t.Fatalf("ParsePrivatePEM dari disk gagal: %v", err)
	}
	parsedPub, _, err := ParsePublicPEM(pubDisk)
	if err != nil {
		t.Fatalf("ParsePublicPEM dari disk gagal: %v", err)
	}
	fpDisk, err := Fingerprint(parsedPub)
	if err != nil {
		t.Fatalf("Fingerprint dari disk gagal: %v", err)
	}
	if fpDisk != fp1 {
		t.Errorf("fingerprint kembalian = %q, want %q", fp1, fpDisk)
	}

	// 3. Panggil lagi tanpa force -> galat, isi kedua berkas tidak berubah
	if _, err := WriteKeyPair(prefix, priv2, false); err == nil {
		t.Errorf("WriteKeyPair tanpa force pada berkas yang sudah ada seharusnya galat")
	}
	privAfter, _ := os.ReadFile(privPath)
	pubAfter, _ := os.ReadFile(pubPath)
	if !bytes.Equal(privAfter, privDisk) || !bytes.Equal(pubAfter, pubDisk) {
		t.Errorf("isi berkas berubah meskipun WriteKeyPair tanpa force gagal")
	}

	// 4 & 5. Ubah izin berkas privat menjadi longgar (0644), lalu timpa dengan force
	if err := os.Chmod(privPath, 0o644); err != nil {
		t.Fatalf("os.Chmod gagal: %v", err)
	}
	fp2, err := WriteKeyPair(prefix, priv2, true)
	if err != nil {
		t.Fatalf("WriteKeyPair dengan force gagal: %v", err)
	}
	if fp2 == fp1 {
		t.Errorf("fingerprint setelah force sama dengan kunci lama: %q", fp2)
	}
	privInfoAfterForce, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("os.Stat setelah force gagal: %v", err)
	}
	if perm := privInfoAfterForce.Mode().Perm(); perm != 0o600 {
		t.Errorf("izin berkas privat setelah force = %o, want 0600", perm)
	}

	// 6. Hanya .pub.pem yang sudah ada tanpa force -> galat, .key.pem tidak terbentuk
	partialPrefix := filepath.Join(dir, "partial")
	if err := os.WriteFile(partialPrefix+".pub.pem", []byte("dummy"), 0o644); err != nil {
		t.Fatalf("gagal menyiapkan dummy .pub.pem: %v", err)
	}
	if _, err := WriteKeyPair(partialPrefix, priv1, false); err == nil {
		t.Errorf("WriteKeyPair seharusnya galat ketika hanya .pub.pem yang sudah ada")
	}
	if _, err := os.Stat(partialPrefix + ".key.pem"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf(".key.pem seharusnya tidak terbentuk ketika .pub.pem sudah ada")
	}

	// 7. Prefix di folder yang belum ada (sub/dir/key) -> lolos, folder terbentuk
	nestedPrefix := filepath.Join(dir, "sub", "dir", "key")
	if _, err := WriteKeyPair(nestedPrefix, priv1, false); err != nil {
		t.Fatalf("WriteKeyPair pada direktori bertingkat gagal: %v", err)
	}
	if _, err := os.Stat(nestedPrefix + ".key.pem"); err != nil {
		t.Errorf("berkas privat di direktori baru tidak ditemukan: %v", err)
	}
	if _, err := os.Stat(nestedPrefix + ".pub.pem"); err != nil {
		t.Errorf("berkas publik di direktori baru tidak ditemukan: %v", err)
	}
}
