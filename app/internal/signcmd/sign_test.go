package signcmd

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yauyau7725/sealix/app/internal/bundle"
	"github.com/yauyau7725/sealix/app/internal/keys"
	"github.com/yauyau7725/sealix/app/internal/manifest"
	"github.com/yauyau7725/sealix/app/internal/sigalg"
)

func runSign(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := Run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func makeFixture(
	t *testing.T,
	profile string,
	filename string,
	content []byte,
) (artifactPath, keyPath string, pub crypto.PublicKey, alg sigalg.Algorithm) {
	t.Helper()

	dir := t.TempDir()

	alg, ok := sigalg.Lookup(profile)
	if !ok {
		t.Fatalf("algoritme %q tidak ditemukan", profile)
	}

	signer, err := alg.Generate()
	if err != nil {
		t.Fatalf("Generate() gagal: %v", err)
	}

	prefix := filepath.Join(dir, "publisher")
	if _, err := keys.WriteKeyPair(prefix, signer, false); err != nil {
		t.Fatalf("WriteKeyPair() gagal: %v", err)
	}

	artifactPath = filepath.Join(dir, filename)
	if err := os.WriteFile(artifactPath, content, 0o644); err != nil {
		t.Fatalf("gagal menulis artefak: %v", err)
	}

	return artifactPath, prefix + ".key.pem", signer.Public(), alg
}

func assertValidBundle(
	t *testing.T,
	bundlePath string,
	artifactPath string,
	pub crypto.PublicKey,
	alg sigalg.Algorithm,
	wantPackage string,
	wantVersion string,
) {
	t.Helper()

	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("gagal membaca bundle: %v", err)
	}

	rawManifest, signature, err := bundle.Parse(data)
	if err != nil {
		t.Fatalf("bundle.Parse() gagal: %v", err)
	}

	gotManifest, err := manifest.ParseStrict(rawManifest)
	if err != nil {
		t.Fatalf("manifest.ParseStrict() gagal: %v", err)
	}

	artifact, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatalf("gagal membaca artefak: %v", err)
	}

	sum := sha256.Sum256(artifact)
	wantHash := hex.EncodeToString(sum[:])

	if gotManifest.Package != wantPackage {
		t.Errorf("package = %q, want %q", gotManifest.Package, wantPackage)
	}
	if gotManifest.Version != wantVersion {
		t.Errorf("version = %q, want %q", gotManifest.Version, wantVersion)
	}
	if gotManifest.Algorithm != alg.Name() {
		t.Errorf("algorithm = %q, want %q", gotManifest.Algorithm, alg.Name())
	}
	if gotManifest.Artifact.Name != filepath.Base(artifactPath) {
		t.Errorf("artifact.name = %q, want %q",
			gotManifest.Artifact.Name, filepath.Base(artifactPath))
	}
	if gotManifest.Artifact.Size != int64(len(artifact)) {
		t.Errorf("artifact.size = %d, want %d",
			gotManifest.Artifact.Size, len(artifact))
	}
	if gotManifest.Artifact.SHA256 != wantHash {
		t.Errorf("artifact.sha256 = %q, want %q",
			gotManifest.Artifact.SHA256, wantHash)
	}
	if !alg.Verify(pub, rawManifest, signature) {
		t.Error("signature tidak valid")
	}
}

func signArgs(filePath, packageName, version, keyPath, outPath string) []string {
	return []string{
		"--file", filePath,
		"--package", packageName,
		"--version", version,
		"--key", keyPath,
		"--out", outPath,
	}
}

func TestRunSuccessForAllProfiles(t *testing.T) {
	profiles := []string{
		sigalg.ProfileEd25519,
		sigalg.ProfileECDSA,
		sigalg.ProfileRSAPSS,
	}

	for _, profile := range profiles {
		t.Run(profile, func(t *testing.T) {
			artifactPath, keyPath, pub, alg := makeFixture(
				t,
				profile,
				"artifact.txt",
				[]byte("isi artefak untuk pengujian"),
			)
			outPath := filepath.Join(t.TempDir(), "bundle.json")

			code, stdout, stderr := runSign(signArgs(
				artifactPath,
				"sealix",
				"1.0.0",
				keyPath,
				outPath,
			)...)

			if code != 0 {
				t.Fatalf("exit code = %d, want 0; stderr: %s", code, stderr)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want kosong", stdout)
			}
			if stderr == "" {
				t.Error("stderr seharusnya memuat informasi bundle")
			}

			assertValidBundle(
				t,
				outPath,
				artifactPath,
				pub,
				alg,
				"sealix",
				"1.0.0",
			)
		})
	}
}

func TestRunSuccessForEmptyAndBinaryArtifacts(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
	}{
		{name: "empty", content: []byte{}},
		{name: "binary", content: []byte{0x00, 0x01, 0xff, 0x7f}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifactPath, keyPath, pub, alg := makeFixture(
				t,
				sigalg.ProfileEd25519,
				"artifact.bin",
				tt.content,
			)
			outPath := filepath.Join(t.TempDir(), "bundle.json")

			code, _, stderr := runSign(signArgs(
				artifactPath,
				"sealix",
				"1.0.0",
				keyPath,
				outPath,
			)...)
			if code != 0 {
				t.Fatalf("exit code = %d, want 0; stderr: %s", code, stderr)
			}

			assertValidBundle(
				t,
				outPath,
				artifactPath,
				pub,
				alg,
				"sealix",
				"1.0.0",
			)
		})
	}
}

func TestRunRejectsMissingFlags(t *testing.T) {
	artifactPath, keyPath, _, _ := makeFixture(
		t,
		sigalg.ProfileEd25519,
		"artifact.txt",
		[]byte("data"),
	)
	outPath := filepath.Join(t.TempDir(), "bundle.json")

	allArgs := signArgs(
		artifactPath,
		"sealix",
		"1.0.0",
		keyPath,
		outPath,
	)

	flags := []string{"--file", "--package", "--version", "--key", "--out"}
	for _, missing := range flags {
		t.Run(missing, func(t *testing.T) {
			var args []string
			for i := 0; i < len(allArgs); i += 2 {
				if allArgs[i] != missing {
					args = append(args, allArgs[i], allArgs[i+1])
				}
			}

			code, _, stderr := runSign(args...)
			if code != 2 {
				t.Errorf("exit code = %d, want 2", code)
			}
			if !strings.Contains(stderr, missing) {
				t.Errorf("stderr = %q, want %q", stderr, missing)
			}
		})
	}
}

func TestRunRejectsMissingKey(t *testing.T) {
	artifactPath, _, _, _ := makeFixture(
		t,
		sigalg.ProfileEd25519,
		"artifact.txt",
		[]byte("data"),
	)
	keyPath := filepath.Join(t.TempDir(), "missing.key.pem")
	outPath := filepath.Join(t.TempDir(), "bundle.json")

	code, _, _ := runSign(signArgs(
		artifactPath,
		"sealix",
		"1.0.0",
		keyPath,
		outPath,
	)...)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Error("bundle terbentuk meskipun private key tidak ada")
	}
}

func TestRunRejectsMalformedKeyWithoutLeakingContents(t *testing.T) {
	artifactPath, _, _, _ := makeFixture(
		t,
		sigalg.ProfileEd25519,
		"artifact.txt",
		[]byte("data"),
	)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bad.key.pem")
	outPath := filepath.Join(dir, "bundle.json")
	secret := "PRIVATE-KEY-SECRET-CONTENT"

	if err := os.WriteFile(keyPath, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := runSign(signArgs(
		artifactPath,
		"sealix",
		"1.0.0",
		keyPath,
		outPath,
	)...)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if strings.Contains(stderr, secret) {
		t.Error("stderr membocorkan isi private key")
	}
}

func TestRunRejectsPublicKey(t *testing.T) {
	artifactPath, _, pub, _ := makeFixture(
		t,
		sigalg.ProfileEd25519,
		"artifact.txt",
		[]byte("data"),
	)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "public.pem")
	outPath := filepath.Join(dir, "bundle.json")

	publicPEM, err := keys.MarshalPublicPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, publicPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	code, _, _ := runSign(signArgs(
		artifactPath,
		"sealix",
		"1.0.0",
		keyPath,
		outPath,
	)...)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestRunRejectsMissingArtifact(t *testing.T) {
	_, keyPath, _, _ := makeFixture(
		t,
		sigalg.ProfileEd25519,
		"artifact.txt",
		[]byte("data"),
	)
	artifactPath := filepath.Join(t.TempDir(), "missing.txt")
	outPath := filepath.Join(t.TempDir(), "bundle.json")

	code, _, _ := runSign(signArgs(
		artifactPath,
		"sealix",
		"1.0.0",
		keyPath,
		outPath,
	)...)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Error("bundle terbentuk meskipun artefak tidak ada")
	}
}

func TestRunRejectsInvalidManifestFields(t *testing.T) {
	tests := []struct {
		name        string
		packageName string
		version     string
		filename    string
	}{
		{name: "uppercase package", packageName: "Sealix", version: "1.0.0", filename: "artifact.txt"},
		{name: "version starts dash", packageName: "sealix", version: "-1.0.0", filename: "artifact.txt"},
		{name: "filename contains space", packageName: "sealix", version: "1.0.0", filename: "artifact file.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifactPath, keyPath, _, _ := makeFixture(
				t,
				sigalg.ProfileEd25519,
				tt.filename,
				[]byte("data"),
			)
			outPath := filepath.Join(t.TempDir(), "bundle.json")

			code, _, _ := runSign(signArgs(
				artifactPath,
				tt.packageName,
				tt.version,
				keyPath,
				outPath,
			)...)
			if code != 2 {
				t.Errorf("exit code = %d, want 2", code)
			}
		})
	}
}

func TestRunRejectsExistingOutputWithoutForce(t *testing.T) {
	artifactPath, keyPath, _, _ := makeFixture(
		t,
		sigalg.ProfileEd25519,
		"artifact.txt",
		[]byte("data"),
	)
	outPath := filepath.Join(t.TempDir(), "bundle.json")
	original := []byte("existing bundle")

	if err := os.WriteFile(outPath, original, 0o644); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := runSign(signArgs(
		artifactPath,
		"sealix",
		"1.0.0",
		keyPath,
		outPath,
	)...)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "--force") {
		t.Errorf("stderr = %q, want --force", stderr)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Error("isi bundle berubah tanpa --force")
	}
}

func TestRunOverwritesExistingOutputWithForce(t *testing.T) {
	artifactPath, keyPath, _, _ := makeFixture(
		t,
		sigalg.ProfileEd25519,
		"artifact.txt",
		[]byte("data"),
	)
	outPath := filepath.Join(t.TempDir(), "bundle.json")

	if err := os.WriteFile(outPath, []byte("old bundle"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := runSign(
		append(signArgs(
			artifactPath,
			"sealix",
			"1.0.0",
			keyPath,
			outPath,
		), "--force")...,
	)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", code, stderr)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, []byte("old bundle")) {
		t.Error("isi bundle tidak berubah dengan --force")
	}
}

func TestRunRejectsSameArtifactAndOutput(t *testing.T) {
	artifactPath, keyPath, _, _ := makeFixture(
		t,
		sigalg.ProfileEd25519,
		"artifact.txt",
		[]byte("original artifact"),
	)
	original, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}

	code, _, _ := runSign(signArgs(
		artifactPath,
		"sealix",
		"1.0.0",
		keyPath,
		artifactPath,
	)...)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}

	got, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Error("artefak berubah ketika output sama dengan input")
	}
}
