package manifest

import (
	"bytes"
	"strings"
	"testing"

	"github.com/yauyau7725/sealix/app/internal/result"
)

func validSampleManifest() Manifest {
	return Manifest{
		Package:   "sealix-cli",
		Version:   "1.0.0+build.1",
		Algorithm: "ed25519",
		KeyID:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Artifact: Artifact{
			Name:   "sealix-linux-amd64.tar.gz",
			Size:   1024,
			SHA256: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
		},
	}
}

func TestManifestSerialize(t *testing.T) {
	m := validSampleManifest()
	got, err := m.Serialize()
	if err != nil {
		t.Fatalf("Serialize() gagal: %v", err)
	}

	want := `{"schema":"minisign-manifest/v1","package":"sealix-cli","version":"1.0.0+build.1","algorithm":"ed25519","keyid":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","artifact":{"name":"sealix-linux-amd64.tar.gz","size":1024,"sha256":"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"}}`

	if string(got) != want {
		t.Errorf("Serialize() =\n%s\nwant:\n%s", string(got), want)
	}
	if bytes.ContainsAny(got, " \n\r\t") {
		t.Errorf("hasil Serialize() mengandung whitespace atau newline: %q", string(got))
	}

	invalid := validSampleManifest()
	invalid.Package = ""
	if _, err := invalid.Serialize(); err == nil {
		t.Errorf("Serialize() pada manifest tidak valid seharusnya galat")
	}
}

func TestManifestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Manifest)
		wantErr bool
	}{
		{name: "valid", mutate: func(m *Manifest) {}, wantErr: false},
		{name: "paket huruf besar", mutate: func(m *Manifest) { m.Package = "Sealix" }, wantErr: true},
		{name: "paket kosong", mutate: func(m *Manifest) { m.Package = "" }, wantErr: true},
		{name: "paket 65 karakter", mutate: func(m *Manifest) { m.Package = strings.Repeat("a", 65) }, wantErr: true},
		{name: "versi diawali -", mutate: func(m *Manifest) { m.Version = "-1.0.0" }, wantErr: true},
		{name: "nama artefak mengandung /", mutate: func(m *Manifest) { m.Artifact.Name = "dir/file.bin" }, wantErr: true},
		{name: "nama dengan spasi", mutate: func(m *Manifest) { m.Artifact.Name = "file name.bin" }, wantErr: true},
		{name: "nama 129 karakter", mutate: func(m *Manifest) { m.Artifact.Name = strings.Repeat("a", 129) }, wantErr: true},
		{name: "keyid huruf besar", mutate: func(m *Manifest) {
			m.KeyID = "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"
		}, wantErr: true},
		{name: "keyid 63 karakter", mutate: func(m *Manifest) { m.KeyID = strings.Repeat("a", 63) }, wantErr: true},
		{name: "sha256 bukan hex", mutate: func(m *Manifest) { m.Artifact.SHA256 = strings.Repeat("g", 64) }, wantErr: true},
		{name: "Size -1", mutate: func(m *Manifest) { m.Artifact.Size = -1 }, wantErr: true},
		{name: "Size 2^53", mutate: func(m *Manifest) { m.Artifact.Size = 9007199254740992 }, wantErr: true},
		{name: "Size 0", mutate: func(m *Manifest) { m.Artifact.Size = 0 }, wantErr: false},
		{name: "Size 2^53-1", mutate: func(m *Manifest) { m.Artifact.Size = 9007199254740991 }, wantErr: false},
		{name: "algorithm kosong", mutate: func(m *Manifest) { m.Algorithm = "" }, wantErr: true},
		{name: "algorithm mengandung kutip", mutate: func(m *Manifest) { m.Algorithm = `ed"25519` }, wantErr: true},
		{name: "algorithm unknown-alg", mutate: func(m *Manifest) { m.Algorithm = "unknown-alg" }, wantErr: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := validSampleManifest()
			tc.mutate(&m)
			err := m.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestManifestParseStrict(t *testing.T) {
	orig := validSampleManifest()
	raw, err := orig.Serialize()
	if err != nil {
		t.Fatalf("Serialize() gagal: %v", err)
	}

	parsed, err := ParseStrict(raw)
	if err != nil {
		t.Fatalf("ParseStrict(valid) gagal: %v", err)
	}
	if parsed != orig {
		t.Errorf("ParseStrict() = %+v, want %+v", parsed, orig)
	}

	validStr := string(raw)

	invalidInputs := []struct {
		name  string
		input []byte
	}{
		{
			name:  "ada spasi di antara token",
			input: []byte(strings.Replace(validStr, `,"package":`, `, "package":`, 1)),
		},
		{
			name:  "ada newline di akhir",
			input: append(append([]byte(nil), raw...), '\n'),
		},
		{
			name:  "urutan field tertukar",
			input: []byte(`{"package":"sealix-cli","schema":"minisign-manifest/v1","version":"1.0.0+build.1","algorithm":"ed25519","keyid":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","artifact":{"name":"sealix-linux-amd64.tar.gz","size":1024,"sha256":"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"}}`),
		},
		{
			name:  "field tambahan",
			input: []byte(`{"schema":"minisign-manifest/v1","package":"sealix-cli","version":"1.0.0+build.1","algorithm":"ed25519","keyid":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","artifact":{"name":"sealix-linux-amd64.tar.gz","size":1024,"sha256":"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"},"extra":"x"}`),
		},
		{
			name:  "field kurang",
			input: []byte(`{"schema":"minisign-manifest/v1","package":"sealix-cli","version":"1.0.0+build.1","algorithm":"ed25519","artifact":{"name":"sealix-linux-amd64.tar.gz","size":1024,"sha256":"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"}}`),
		},
		{
			name:  "schema salah",
			input: []byte(strings.Replace(validStr, `"minisign-manifest/v1"`, `"minisign-manifest/v2"`, 1)),
		},
		{
			name:  "key duplikat",
			input: []byte(`{"schema":"minisign-manifest/v1","schema":"minisign-manifest/v1","package":"sealix-cli","version":"1.0.0+build.1","algorithm":"ed25519","keyid":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","artifact":{"name":"sealix-linux-amd64.tar.gz","size":1024,"sha256":"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"}}`),
		},
		{
			name:  "size null",
			input: []byte(strings.Replace(validStr, `"size":1024`, `"size":null`, 1)),
		},
		{
			name:  "size string",
			input: []byte(strings.Replace(validStr, `"size":1024`, `"size":"10"`, 1)),
		},
		{
			name:  "size desimal 1.0",
			input: []byte(strings.Replace(validStr, `"size":1024`, `"size":1.0`, 1)),
		},
		{
			name:  "size bool true",
			input: []byte(strings.Replace(validStr, `"size":1024`, `"size":true`, 1)),
		},
		{
			name:  "size 2^53",
			input: []byte(strings.Replace(validStr, `"size":1024`, `"size":9007199254740992`, 1)),
		},
		{
			name:  "ada escape unicode \\u0041",
			input: []byte(strings.Replace(validStr, `"1.0.0+build.1"`, `"1.0.0+\u0041"`, 1)),
		},
		{
			name:  "masukan lebih dari 16384 byte",
			input: append(append([]byte(nil), raw...), bytes.Repeat([]byte(" "), MaxSize+1-len(raw))...),
		},
	}

	for _, tc := range invalidInputs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseStrict(tc.input)
			if err == nil {
				t.Fatalf("ParseStrict(%s) seharusnya galat, tetapi berhasil", tc.name)
			}
			if gotStatus := result.StatusOf(err); gotStatus != result.FormatError {
				t.Errorf("StatusOf(err) = %v, want %v (err: %v)", gotStatus, result.FormatError, err)
			}
		})
	}
}
