
package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yauyau7725/sealix/app/internal/bundle"
	"github.com/yauyau7725/sealix/app/internal/manifest"
	"github.com/yauyau7725/sealix/app/internal/truststore"
)

type negativeFixture struct {
	dir, artifact, bundle, trust, key string
	raw, sig                          []byte
}

func negCommand(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	rc := Run(args, &stdout, &stderr, "test")
	return rc, stdout.String(), stderr.String()
}

func negMust(t *testing.T, args ...string) {
	t.Helper()
	rc, stdout, stderr := negCommand(args...)
	if rc != 0 {
		t.Fatalf(
			"%v: exit=%d stdout=%s stderr=%s",
			args, rc, stdout, stderr,
		)
	}
}

func newNegativeFixture(t *testing.T) *negativeFixture {
	t.Helper()
	dir := t.TempDir()

	f := &negativeFixture{
		dir:      dir,
		artifact: filepath.Join(dir, "app.bin"),
		bundle:   filepath.Join(dir, "release.json"),
		trust:    filepath.Join(dir, "trust.json"),
		key:      filepath.Join(dir, "signer"),
	}

	if err := os.WriteFile(
		f.artifact,
		[]byte("rilis-sealix-untuk-pengujian"),
		0600,
	); err != nil {
		t.Fatal(err)
	}

	negMust(
		t, "keygen",
		"--algorithm", "ed25519",
		"--out", f.key,
	)
	negMust(
		t, "trust", "add",
		"--key", f.key+".pub.pem",
		"--package", "contoh-app",
		"--store", f.trust,
	)
	negMust(
		t, "sign",
		"--file", f.artifact,
		"--package", "contoh-app",
		"--version", "1.0.0",
		"--key", f.key+".key.pem",
		"--out", f.bundle,
	)

	data, err := os.ReadFile(f.bundle)
	if err != nil {
		t.Fatal(err)
	}
	f.raw, f.sig, err = bundle.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *negativeFixture) writeBundle(
	t *testing.T,
	raw, sig []byte,
) {
	t.Helper()
	if err := os.WriteFile(
		f.bundle,
		bundle.Marshal(raw, sig),
		0600,
	); err != nil {
		t.Fatal(err)
	}
}

func (f *negativeFixture) verify(
	t *testing.T,
	expectedStatus string,
	expectedRC int,
	overrides ...string,
) {
	t.Helper()

	args := []string{
		"verify",
		"--file", f.artifact,
		"--bundle", f.bundle,
		"--trust-store", f.trust,
		"--package", "contoh-app",
		"--version", "1.0.0",
		"--json",
	}
	args = append(args, overrides...)

	rc, out, stderr := negCommand(args...)
	if rc != expectedRC {
		t.Fatalf(
			"exit=%d want=%d stdout=%q stderr=%q",
			rc, expectedRC, out, stderr,
		)
	}

	if strings.Count(out, "\n") != 1 {
		t.Fatalf(
			"output harus satu JSON + newline: %q",
			out,
		)
	}

	var report struct {
		Valid     bool    `json:"valid"`
		Status    string  `json:"status"`
		Algorithm *string `json:"algorithm"`
		KeyID     *string `json:"keyid"`
		Package   *string `json:"package"`
		Version   *string `json:"version"`
	}

	if err := json.Unmarshal(
		[]byte(out),
		&report,
	); err != nil {
		t.Fatal(err)
	}

	if report.Status != expectedStatus ||
		report.Valid != (expectedStatus == "OK") {

		t.Fatalf(
			"status/valid salah: %+v, stderr=%q",
			report, stderr,
		)
	}

	if expectedStatus == "INPUT_ERROR" ||
		expectedStatus == "FORMAT_ERROR" {

		if report.Algorithm != nil ||
			report.KeyID != nil ||
			report.Package != nil ||
			report.Version != nil {

			t.Fatalf(
				"metadata harus null: %+v",
				report,
			)
		}
	}
}

func TestNegativeU02ToU13(t *testing.T) {
	cases := []struct {
		name, want string
		rc         int
		mutate     func(*testing.T, *negativeFixture) []string
	}{
		{
			"U02", "ARTIFACT_MISMATCH", 1,
			func(t *testing.T, f *negativeFixture) []string {
				b, err := os.ReadFile(f.artifact)
				if err != nil {
					t.Fatal(err)
				}
				b[0] ^= 1
				if err := os.WriteFile(f.artifact, b, 0600); err != nil {
					t.Fatal(err)
				}
				return nil
			},
		},
		{
			"U03-append", "ARTIFACT_MISMATCH", 1,
			func(t *testing.T, f *negativeFixture) []string {
				fd, err := os.OpenFile(
					f.artifact,
					os.O_APPEND|os.O_WRONLY, 0,
				)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := fd.Write([]byte("X")); err != nil {
					t.Fatal(err)
				}
				if err := fd.Close(); err != nil {
					t.Fatal(err)
				}
				return nil
			},
		},
		{
			"U03-remove", "ARTIFACT_MISMATCH", 1,
			func(t *testing.T, f *negativeFixture) []string {
				b, err := os.ReadFile(f.artifact)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(
					f.artifact, b[:len(b)-1], 0600,
				); err != nil {
					t.Fatal(err)
				}
				return nil
			},
		},
		{
			"U04", "INVALID_SIGNATURE", 1,
			func(t *testing.T, f *negativeFixture) []string {
				m, err := manifest.ParseStrict(f.raw)
				if err != nil {
					t.Fatal(err)
				}
				m.Version = "1.0.1"
				modified, err := m.Serialize()
				if err != nil {
					t.Fatal(err)
				}
				f.writeBundle(t, modified, f.sig)
				return nil
			},
		},
		{
			"U05", "INVALID_SIGNATURE", 1,
			func(t *testing.T, f *negativeFixture) []string {
				sig := append([]byte(nil), f.sig...)
				sig[0] ^= 1
				f.writeBundle(t, f.raw, sig)
				return nil
			},
		},
		{
			"U06", "KEY_NOT_TRUSTED", 1,
			func(t *testing.T, f *negativeFixture) []string {
				if err := truststore.Empty().Save(f.trust); err != nil {
					t.Fatal(err)
				}
				return nil
			},
		},
		{
			"U07", "KEY_NOT_TRUSTED", 1,
			func(t *testing.T, f *negativeFixture) []string {
				s, err := truststore.Load(f.trust)
				if err != nil {
					t.Fatal(err)
				}
				s.Keys[0].Packages = []string{"paket-lain"}
				if err := s.Save(f.trust); err != nil {
					t.Fatal(err)
				}
				return nil
			},
		},
		{
			"U08", "METADATA_MISMATCH", 1,
			func(t *testing.T, f *negativeFixture) []string {
				return []string{"--version", "2.0.0"}
			},
		},
		{
			"U09", "METADATA_MISMATCH", 1,
			func(t *testing.T, f *negativeFixture) []string {
				renamed := filepath.Join(f.dir, "renamed.bin")
				if err := os.Rename(
					f.artifact, renamed,
				); err != nil {
					t.Fatal(err)
				}
				f.artifact = renamed
				return nil
			},
		},
		{
			"U10a", "FORMAT_ERROR", 1,
			func(t *testing.T, f *negativeFixture) []string {
				b, err := os.ReadFile(f.bundle)
				if err != nil {
					t.Fatal(err)
				}
				b = bytes.Replace(
					b,
					[]byte(`"schema":`),
					[]byte(`"schema":"minisign-bundle/v1","schema":`),
					1,
				)
				if err := os.WriteFile(f.bundle, b, 0600); err != nil {
					t.Fatal(err)
				}
				return nil
			},
		},
		{
			"U10b", "FORMAT_ERROR", 1,
			func(t *testing.T, f *negativeFixture) []string {
				b, err := os.ReadFile(f.bundle)
				if err != nil {
					t.Fatal(err)
				}
				var v map[string]any
				if err := json.Unmarshal(b, &v); err != nil {
					t.Fatal(err)
				}
				v["signature_b64"] = 42
				b, err = json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(f.bundle, b, 0600); err != nil {
					t.Fatal(err)
				}
				return nil
			},
		},
		{
			"U10c", "FORMAT_ERROR", 1,
			func(t *testing.T, f *negativeFixture) []string {
				b, err := os.ReadFile(f.bundle)
				if err != nil {
					t.Fatal(err)
				}
				var v map[string]any
				if err := json.Unmarshal(b, &v); err != nil {
					t.Fatal(err)
				}
				v["signature_b64"] = "%%%"
				b, err = json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(f.bundle, b, 0600); err != nil {
					t.Fatal(err)
				}
				return nil
			},
		},
		{
			"U10d", "FORMAT_ERROR", 1,
			func(t *testing.T, f *negativeFixture) []string {
				tooBig := append(
					append([]byte(nil), f.raw...),
					bytes.Repeat(
						[]byte{' '},
						manifest.MaxSize-len(f.raw)+1,
					)...,
				)
				f.writeBundle(t, tooBig, f.sig)
				return nil
			},
		},
		{
			"U11", "UNSUPPORTED_ALGORITHM", 1,
			func(t *testing.T, f *negativeFixture) []string {
				m, err := manifest.ParseStrict(f.raw)
				if err != nil {
					t.Fatal(err)
				}
				m.Algorithm = "algoritma-tidak-ada"
				raw, err := m.Serialize()
				if err != nil {
					t.Fatal(err)
				}
				f.writeBundle(t, raw, f.sig)
				return nil
			},
		},
		{
			"U12", "KEY_NOT_TRUSTED", 1,
			func(t *testing.T, f *negativeFixture) []string {
				other := filepath.Join(f.dir, "other")
				negMust(
					t, "keygen",
					"--algorithm", "ed25519",
					"--out", other,
				)
				negMust(
					t, "sign",
					"--file", f.artifact,
					"--package", "contoh-app",
					"--version", "1.0.0",
					"--key", other+".key.pem",
					"--out", f.bundle,
					"--force",
				)
				return nil
			},
		},
		{
			"U13", "OK", 0,
			func(t *testing.T, f *negativeFixture) []string {
				b := fmt.Sprintf(
					"{\n \"signature_b64\":%q,\n \"schema\":\"minisign-bundle/v1\",\n \"manifest_b64\":%q\n}\n",
					base64.StdEncoding.EncodeToString(f.sig),
					base64.StdEncoding.EncodeToString(f.raw),
				)
				if err := os.WriteFile(
					f.bundle, []byte(b), 0600,
				); err != nil {
					t.Fatal(err)
				}
				return nil
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newNegativeFixture(t)
			overrides := tc.mutate(t, f)
			f.verify(t, tc.want, tc.rc, overrides...)
		})
	}
}

func TestVerifyPrecedence(t *testing.T) {
	t.Run("INPUT_before_FORMAT", func(t *testing.T) {
		f := newNegativeFixture(t)
		if err := os.Remove(f.artifact); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			f.bundle, []byte("{}"), 0600,
		); err != nil {
			t.Fatal(err)
		}
		f.verify(t, "INPUT_ERROR", 2)
	})

	t.Run("TRUST_before_SIGNATURE", func(t *testing.T) {
		f := newNegativeFixture(t)
		if err := truststore.Empty().Save(f.trust); err != nil {
			t.Fatal(err)
		}
		sig := append([]byte(nil), f.sig...)
		sig[0] ^= 1
		f.writeBundle(t, f.raw, sig)
		f.verify(t, "KEY_NOT_TRUSTED", 1)
	})

	t.Run("SIGNATURE_before_METADATA", func(t *testing.T) {
		f := newNegativeFixture(t)
		sig := append([]byte(nil), f.sig...)
		sig[0] ^= 1
		f.writeBundle(t, f.raw, sig)
		f.verify(
			t, "INVALID_SIGNATURE", 1,
			"--version", "other",
		)
	})

	t.Run("METADATA_before_ARTIFACT", func(t *testing.T) {
		f := newNegativeFixture(t)
		if err := os.WriteFile(
			f.artifact, []byte("DIUBAH"), 0600,
		); err != nil {
			t.Fatal(err)
		}
		f.verify(
			t, "METADATA_MISMATCH", 1,
			"--version", "other",
		)
	})
}
