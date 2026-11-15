
package truststore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yauyau7725/sealix/app/internal/keys"
)

func sampleStore(t *testing.T) (*Store, string) {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	s := Empty()
	if _, err := s.Add(pub, "contoh-app"); err != nil {
		t.Fatal(err)
	}

	id, err := keys.Fingerprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	return s, id
}

func TestAddMergeIdempotentRemove(t *testing.T) {
	s, id := sampleStore(t)

	pub, _, err := keys.ParsePublicPEM(
		[]byte(s.Keys[0].PublicKeyPEM),
	)
	if err != nil {
		t.Fatal(err)
	}

	created, err := s.Add(pub, "contoh-app")
	if err != nil || created ||
		len(s.Keys) != 1 ||
		len(s.Keys[0].Packages) != 1 {
		t.Fatalf("idempotensi gagal: %v", err)
	}

	created, err = s.Add(pub, "paket-lain")
	if err != nil || created ||
		len(s.Keys) != 1 ||
		len(s.Keys[0].Packages) != 2 {
		t.Fatalf("merge paket gagal: %v", err)
	}

	if _, ok := s.Lookup(id); !ok {
		t.Fatal("key tidak ditemukan")
	}

	if err := s.Remove(id); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Lookup(id); ok {
		t.Fatal("key masih ada")
	}
	if err := s.Remove(id); err == nil {
		t.Fatal("menghapus key tak ada harus gagal")
	}
}

func TestParseRejectInvalidTrust(t *testing.T) {
	s, _ := sampleStore(t)
	valid, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"duplicate root": []byte(`{"schema":"minisign-trust/v1","keys":[],"keys":[]}`),
		"extra root":     []byte(`{"schema":"minisign-trust/v1","keys":[],"extra":1}`),
		"null keys":      []byte(`{"schema":"minisign-trust/v1","keys":null}`),
		"wrong type":     []byte(`{"schema":"minisign-trust/v1","keys":"invalid"}`),
		"oversize":       bytes.Repeat([]byte("x"), MaxSize+1),
	}

	clone := func() Store {
		var result Store
		if err := json.Unmarshal(valid, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}

	mut := clone()
	mut.Keys[0].Packages = []string{"contoh-app", "contoh-app"}
	cases["duplicate package"], _ = json.Marshal(mut)

	mut = clone()
	mut.Keys[0].Packages = []string{"*"}
	cases["wildcard package"], _ = json.Marshal(mut)

	mut = clone()
	mut.Keys[0].KeyID = strings.Repeat("a", 64)
	cases["wrong fingerprint"], _ = json.Marshal(mut)

	mut = clone()
	mut.Keys[0].Algorithm = "rsa-pss-sha256"
	cases["wrong algorithm"], _ = json.Marshal(mut)

	mut = clone()
	mut.Keys = append(mut.Keys, mut.Keys[0])
	cases["duplicate keyid"], _ = json.Marshal(mut)

	cases["extra entry"] = bytes.Replace(
		valid,
		[]byte(`"keyid":`),
		[]byte(`"extra":0,"keyid":`),
		1,
	)

	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(data); err == nil {
				t.Fatal("trust store invalid diterima")
			}
		})
	}
}

func TestSaveLoadAndPreserveOnFailure(t *testing.T) {
	s, id := sampleStore(t)
	path := filepath.Join(t.TempDir(), "trust.json")

	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}

	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.Lookup(id); !ok {
		t.Fatal("key hilang setelah load")
	}

	s.Keys[0].Packages = []string{"*"}
	if err := s.Save(path); err == nil {
		t.Fatal("Save seharusnya gagal")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, after) {
		t.Fatal("file lama berubah saat Save gagal")
	}
}
