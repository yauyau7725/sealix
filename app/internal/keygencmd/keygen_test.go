package keygencmd

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FityatulhaqRosyidi/sealix/app/internal/keys"
	"github.com/FityatulhaqRosyidi/sealix/app/internal/sigalg"
)

func runKeygen(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := Run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestRunGeneratesKeyPairs(t *testing.T) {
	profiles := []string{
		sigalg.ProfileEd25519,
		sigalg.ProfileECDSA,
		sigalg.ProfileRSAPSS,
	}

	for _, profile := range profiles {
		t.Run(profile, func(t *testing.T) {
			prefix := filepath.Join(t.TempDir(), "publisher")

			code, output, errOutput := runKeygen(
				"--algorithm", profile,
				"--out", prefix,
			)
			if code != 0 {
				t.Fatalf("Run() exit code = %d, want 0; stderr: %s", code, errOutput)
			}
			if !strings.HasSuffix(output, "\n") {
				t.Fatalf("output tidak diakhiri newline: %q", output)
			}

			fingerprint := strings.TrimSuffix(output, "\n")
			if len(fingerprint) != 64 {
				t.Fatalf("fingerprint length = %d, want 64", len(fingerprint))
			}
			if _, err := hex.DecodeString(fingerprint); err != nil {
				t.Fatalf("fingerprint bukan hex valid: %v", err)
			}

			privPath := prefix + ".key.pem"
			pubPath := prefix + ".pub.pem"

			privPEM, err := os.ReadFile(privPath)
			if err != nil {
				t.Fatalf("gagal membaca private key: %v", err)
			}
			pubPEM, err := os.ReadFile(pubPath)
			if err != nil {
				t.Fatalf("gagal membaca public key: %v", err)
			}

			priv, gotPrivAlg, err := keys.ParsePrivatePEM(privPEM)
			if err != nil {
				t.Fatalf("ParsePrivatePEM() gagal: %v", err)
			}

			privFingerprint, err := keys.Fingerprint(priv.Public())
			if err != nil {
				t.Fatalf("Fingerprint(private.Public()) gagal: %v", err)
			}
			if privFingerprint != fingerprint {
				t.Errorf("fingerprint private key = %q, want %q", privFingerprint, fingerprint)
			}
			if gotPrivAlg.Name() != profile {
				t.Errorf("private key algorithm = %q, want %q", gotPrivAlg.Name(), profile)
			}

			pub, gotPubAlg, err := keys.ParsePublicPEM(pubPEM)
			if err != nil {
				t.Fatalf("ParsePublicPEM() gagal: %v", err)
			}
			if gotPubAlg.Name() != profile {
				t.Errorf("public key algorithm = %q, want %q", gotPubAlg.Name(), profile)
			}

			gotFingerprint, err := keys.Fingerprint(pub)
			if err != nil {
				t.Fatalf("Fingerprint() gagal: %v", err)
			}
			if gotFingerprint != fingerprint {
				t.Errorf("fingerprint = %q, want %q", gotFingerprint, fingerprint)
			}

			if strings.Contains(output, "PRIVATE KEY") {
				t.Error("stdout tidak boleh memuat isi private key")
			}

		})
	}
}

func TestRunRefusesExistingFilesWithoutForce(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "publisher")

	code, _, errOutput := runKeygen(
		"--algorithm", sigalg.ProfileEd25519,
		"--out", prefix,
	)
	if code != 0 {
		t.Fatalf("pembuatan awal gagal: %d (%s)", code, errOutput)
	}

	code, _, errOutput = runKeygen(
		"--algorithm", sigalg.ProfileEd25519,
		"--out", prefix,
	)
	if code != 2 {
		t.Errorf("Run() tanpa --force exit code = %d, want 2", code)
	}
	if errOutput == "" {
		t.Error("stderr kosong untuk berkas yang sudah ada")
	}
}

func TestRunForceOverwritesExistingFiles(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "publisher")

	args := []string{
		"--algorithm", sigalg.ProfileEd25519,
		"--out", prefix,
	}

	code, firstOutput, errOutput := runKeygen(args...)
	if code != 0 {
		t.Fatalf("pembuatan awal gagal: %d (%s)", code, errOutput)
	}
	firstFingerprint := strings.TrimSpace(firstOutput)

	code, output, errOutput := runKeygen(
		"--algorithm", sigalg.ProfileEd25519,
		"--out", prefix,
		"--force",
	)
	if code != 0 {
		t.Fatalf("Run() dengan --force exit code = %d; stderr: %s", code, errOutput)
	}

	secondFingerprint := strings.TrimSpace(output)
	if len(secondFingerprint) != 64 {
		t.Errorf("output fingerprint tidak valid: %q", output)
	}
	if secondFingerprint == firstFingerprint {
		t.Errorf("fingerprint dengan --force tidak berubah: %q", secondFingerprint)
	}
}

func TestRunRejectsMissingRequiredFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing algorithm",
			args: []string{"--out", filepath.Join(t.TempDir(), "publisher")},
			want: "--algorithm",
		},
		{
			name: "missing output",
			args: []string{"--algorithm", sigalg.ProfileEd25519},
			want: "--out",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, errOutput := runKeygen(tt.args...)
			if code != 2 {
				t.Errorf("exit code = %d, want 2", code)
			}
			if !strings.Contains(errOutput, tt.want) {
				t.Errorf("stderr = %q, want it to contain %q", errOutput, tt.want)
			}
		})
	}
}

func TestRunRejectsUnknownAlgorithm(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "publisher")

	code, _, errOutput := runKeygen(
		"--algorithm", "rsa",
		"--out", prefix,
	)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errOutput, sigalg.ProfileEd25519) ||
		!strings.Contains(errOutput, sigalg.ProfileECDSA) ||
		!strings.Contains(errOutput, sigalg.ProfileRSAPSS) {
		t.Errorf("stderr tidak mencantumkan semua profil valid: %q", errOutput)
	}

	if _, err := os.Stat(prefix + ".key.pem"); !os.IsNotExist(err) {
		t.Errorf("private key terbentuk untuk algoritma tidak dikenal")
	}
	if _, err := os.Stat(prefix + ".pub.pem"); !os.IsNotExist(err) {
		t.Errorf("public key terbentuk untuk algoritma tidak dikenal")
	}
}

func TestRunRejectsPositionalArguments(t *testing.T) {
	code, _, errOutput := runKeygen(
		"--algorithm", sigalg.ProfileEd25519,
		"--out", filepath.Join(t.TempDir(), "publisher"),
		"extra",
	)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if errOutput == "" {
		t.Error("stderr kosong untuk argumen posisional")
	}
}

func TestRunHelp(t *testing.T) {
	code, _, _ := runKeygen("-h")
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}
