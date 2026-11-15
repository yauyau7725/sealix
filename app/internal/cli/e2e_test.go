package cli

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yauyau7725/sealix/app/internal/bundle"
	"github.com/yauyau7725/sealix/app/internal/sigalg"
)

func run(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := Run(args, &out, &errOut, "test")
	return code, out.String(), errOut.String()
}

func setup(t *testing.T, profile string) (dir, fingerprint string) {
	t.Helper()

	dir = t.TempDir()
	keyPrefix := filepath.Join(dir, "k")

	code, out, errOut := run(
		"keygen",
		"--algorithm", profile,
		"--out", keyPrefix,
	)
	if code != 0 {
		t.Fatalf("keygen gagal (exit %d): %s", code, errOut)
	}
	fingerprint = strings.TrimSpace(out)

	code, _, errOut = run(
		"trust", "add",
		"--key", keyPrefix+".pub.pem",
		"--package", "contoh-app",
		"--store", filepath.Join(dir, "trust.json"),
	)
	if code != 0 {
		t.Fatalf("trust add gagal (exit %d): %s", code, errOut)
	}

	return dir, fingerprint
}

func TestU01(t *testing.T) {
	binary := make([]byte, 3000)
	if _, err := rand.New(rand.NewSource(1)).Read(binary); err != nil {
		t.Fatal(err)
	}

	profiles := []string{
		sigalg.ProfileEd25519,
		sigalg.ProfileECDSA,
		sigalg.ProfileRSAPSS,
	}
	contents := []struct {
		name string
		data []byte
	}{
		{name: "teks", data: []byte("isi uji\n")},
		{name: "kosong", data: []byte{}},
		{name: "biner", data: binary},
	}

	for _, profile := range profiles {
		t.Run(profile, func(t *testing.T) {
			dir, fingerprint := setup(t, profile)

			for _, content := range contents {
				t.Run(content.name, func(t *testing.T) {
					artifactPath := filepath.Join(dir, "artefak.bin")
					if err := os.WriteFile(artifactPath, content.data, 0600); err != nil {
						t.Fatal(err)
					}

					keyPath := filepath.Join(dir, "k.key.pem")
					bundlePath := filepath.Join(dir, "b.json")
					trustPath := filepath.Join(dir, "trust.json")
					t.Cleanup(func() {
						_ = os.Remove(bundlePath)
					})

					code, _, errOut := run(
						"sign",
						"--file", artifactPath,
						"--package", "contoh-app",
						"--version", "1.0.0",
						"--key", keyPath,
						"--out", bundlePath,
					)
					if code != 0 {
						t.Fatalf("sign gagal (exit %d): %s", code, errOut)
					}

					code, out, errOut := run(
						"verify",
						"--file", artifactPath,
						"--bundle", bundlePath,
						"--trust-store", trustPath,
						"--package", "contoh-app",
						"--version", "1.0.0",
						"--json",
					)
					if code != 0 {
						t.Fatalf("verify gagal (exit %d): stdout=%s stderr=%s", code, out, errOut)
					}
					if strings.Count(out, "\n") != 1 {
						t.Fatalf("jumlah newline stdout = %d, want 1: %q", strings.Count(out, "\n"), out)
					}

					var report map[string]any
					if err := json.Unmarshal([]byte(out), &report); err != nil {
						t.Fatalf("JSON tidak valid: %v", err)
					}

					wantKeys := []string{
						"valid",
						"status",
						"message",
						"algorithm",
						"keyid",
						"package",
						"version",
					}
					if len(report) != len(wantKeys) {
						t.Fatalf("jumlah field = %d, want %d: %#v", len(report), len(wantKeys), report)
					}
					for _, key := range wantKeys {
						if _, ok := report[key]; !ok {
							t.Fatalf("field %q tidak ada: %#v", key, report)
						}
					}

					assertEqual := func(key string, want any) {
						t.Helper()
						if report[key] != want {
							t.Errorf("report[%q] = %#v, want %#v", key, report[key], want)
						}
					}
					assertEqual("valid", true)
					assertEqual("status", "OK")
					assertEqual("algorithm", profile)
					assertEqual("keyid", fingerprint)
					assertEqual("package", "contoh-app")
					assertEqual("version", "1.0.0")
				})
			}
		})
	}
}

func TestU14(t *testing.T) {
	expectedLength := map[string]int{
		sigalg.ProfileEd25519: 64,
		sigalg.ProfileECDSA:   64,
		sigalg.ProfileRSAPSS:  384,
	}
	expectedIdentical := map[string]bool{
		sigalg.ProfileEd25519: true,
		sigalg.ProfileECDSA:   false,
		sigalg.ProfileRSAPSS:  false,
	}

	profiles := []string{
		sigalg.ProfileEd25519,
		sigalg.ProfileECDSA,
		sigalg.ProfileRSAPSS,
	}
	for _, profile := range profiles {
		t.Run(profile, func(t *testing.T) {
			dir, _ := setup(t, profile)
			artifactPath := filepath.Join(dir, "artefak.bin")
			if err := os.WriteFile(artifactPath, []byte("isi uji\n"), 0600); err != nil {
				t.Fatal(err)
			}

			keyPath := filepath.Join(dir, "k.key.pem")
			bundlePaths := []string{
				filepath.Join(dir, "b1.json"),
				filepath.Join(dir, "b2.json"),
			}
			for _, bundlePath := range bundlePaths {
				code, _, errOut := run(
					"sign",
					"--file", artifactPath,
					"--package", "contoh-app",
					"--version", "1.0.0",
					"--key", keyPath,
					"--out", bundlePath,
				)
				if code != 0 {
					t.Fatalf("sign gagal (exit %d): %s", code, errOut)
				}
			}

			manifests := make([][]byte, len(bundlePaths))
			signatures := make([][]byte, len(bundlePaths))
			for i, bundlePath := range bundlePaths {
				code, out, errOut := run(
					"verify",
					"--file", artifactPath,
					"--bundle", bundlePath,
					"--trust-store", filepath.Join(dir, "trust.json"),
					"--package", "contoh-app",
					"--version", "1.0.0",
					"--json",
				)
				if code != 0 || !strings.Contains(out, `"status":"OK"`) {
					t.Fatalf("verify %s gagal (exit %d): stdout=%s stderr=%s", bundlePath, code, out, errOut)
				}

				data, err := os.ReadFile(bundlePath)
				if err != nil {
					t.Fatal(err)
				}
				manifest, signature, err := bundle.Parse(data)
				if err != nil {
					t.Fatalf("bundle.Parse gagal: %v", err)
				}
				manifests[i] = manifest
				signatures[i] = signature
			}

			if !bytes.Equal(manifests[0], manifests[1]) {
				t.Fatal("manifest dari dua bundle tidak identik")
			}
			if len(signatures[0]) != expectedLength[profile] || len(signatures[1]) != expectedLength[profile] {
				t.Fatalf("panjang tanda tangan = %d dan %d, want %d", len(signatures[0]), len(signatures[1]), expectedLength[profile])
			}

			identical := bytes.Equal(signatures[0], signatures[1])
			if identical != expectedIdentical[profile] {
				t.Fatalf("tanda tangan identik = %t, want %t", identical, expectedIdentical[profile])
			}
			t.Logf("%s len=%d sig1[0:8]=%x sig2[0:8]=%x identical=%t",
				profile,
				len(signatures[0]),
				signatures[0][:8],
				signatures[1][:8],
				identical,
			)
		})
	}
}
