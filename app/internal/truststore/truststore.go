package truststore

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/yauyau7725/sealix/app/internal/jsonstrict"
	"github.com/yauyau7725/sealix/app/internal/keys"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"io"
	"runtime"
)

const Schema = "minisign-trust/v1"

const MaxSize = 1024 * 1024

var packagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

var keyPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Entry struct {
	KeyID        string   `json:"keyid"`
	Algorithm    string   `json:"algorithm"`
	PublicKeyPEM string   `json:"public_key_pem"`
	Packages     []string `json:"packages"`
}

type Store struct {
	Schema string  `json:"schema"`
	Keys   []Entry `json:"keys"`
}

func Empty() *Store {
	return &Store{
		Schema: Schema,
		Keys:   []Entry{},
	}
}

func validate(s *Store) error {
	if s.Schema != Schema {
		return errors.New("Schema trust store tidak valid")
	}

	if s.Keys == nil {
		return errors.New("Key harus array")
	}

	seen := map[string]bool{}

	for i, e := range s.Keys {
		if !keyPattern.MatchString(e.KeyID) {
			return fmt.Errorf("keys[%d]: key id tidak valid", i)
		}

		if seen[e.KeyID] {
			return errors.New("key id duplikat")
		}

		seen[e.KeyID] = true

		pub, alg, err := keys.ParsePublicPEM([]byte(e.PublicKeyPEM))

		if err != nil {
			return fmt.Errorf("keys[%d]: %w", i, err)
		}

		fp, err := keys.Fingerprint(pub)
		if err != nil {
			return err
		}

		if fp != e.KeyID {
			return errors.New("fingerprint public key tidak cocok")
		}

		if alg.Name() != e.Algorithm {
			return errors.New("Algoritma public key tidak cocok")
		}

		if len(e.Packages) == 0 {
			return errors.New("Packages tidak boleh kosong")
		}

		ps := map[string]bool{}

		for _, pkg := range e.Packages {
			if !packagePattern.MatchString(pkg) || strings.Contains(pkg, "*") {
				return errors.New("nama package tidak valid")
			}

			if ps[pkg] {
				return errors.New("package duplikat")
			}

			ps[pkg] = true
		}
	}

	return nil
}

func Parse(data []byte) (*Store, error) {
	if len(data) > MaxSize {
		return nil, errors.New("trust store terlalu besar")
	}

	if _, err := jsonstrict.Parse(data); err != nil {
		return nil, err
	}

	var root map[string]json.RawMessage

	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	if len(root) != 2 ||
		root["schema"] == nil ||
		root["keys"] == nil ||
		bytes.Equal(bytes.TrimSpace(root["keys"]), []byte("null")) {
		return nil, errors.New("field trust store tidak tepat")
	}

	var entries []map[string]json.RawMessage

	if err := json.Unmarshal(root["keys"], &entries); err != nil {
		return nil, err
	}

	if entries == nil {
		return nil, errors.New("keys harus array")
	}

	for _, entry := range entries {
		if len(entry) != 4 {
			return nil, errors.New("field entry trust store tidak tepat")
		}

		for _, name := range []string{"keyid", "algorithm", "public_key_pem", "packages"} {
			if entry[name] == nil || bytes.Equal(bytes.TrimSpace(entry[name]), []byte("null")) {
				return nil, fmt.Errorf("field %s hilang atau null", name)
			}
		}
	}

	var s Store

	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}

	if err := validate(&s); err != nil {
		return nil, err
	}

	return &s, nil
}

func Load(path string) (*Store, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return nil, err
	}

	return Parse(data)
}

func (s *Store) Lookup(keyid string) (*Entry, bool) {
	for i := range s.Keys {
		if s.Keys[i].KeyID == keyid {
			return &s.Keys[i], true
		}
	}

	return nil, false
}

func (s *Store) Add(pub crypto.PublicKey, pkg string) (bool, error) {
	if !packagePattern.MatchString(pkg) {
		return false, errors.New("package tidak valid")
	}

	fp, err := keys.Fingerprint(pub)
	if err != nil {
		return false, err
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return false, err
	}

	pemBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: der,
		},
	)

	_, alg, err := keys.ParsePublicPEM(pemBytes)
	if err != nil {
		return false, err
	}

	if e, ok := s.Lookup(fp); ok {
		if e.Algorithm != alg.Name() {
			return false, errors.New("keyid memiliki algoritma berbeda")
		}

		if slices.Contains(e.Packages, pkg) {
			return false, nil
		}

		e.Packages = append(e.Packages, pkg)

		return false, nil // keyid udh ada, pkg nya belum ada
	}

	s.Keys = append(s.Keys,
		Entry{
			KeyID:        fp,
			Algorithm:    alg.Name(),
			PublicKeyPEM: string(pemBytes),
			Packages:     []string{pkg},
		},
	)
	return true, nil
}

func (s *Store) Remove(keyid string) error {
	for i := range s.Keys {
		if s.Keys[i].KeyID == keyid {
			s.Keys = append(s.Keys[:i], s.Keys[i+1:]...)
			return nil
		}
	}
	return errors.New("keyid tidak ditemukan")
}

func (s *Store) Save(path string) error {
	if err := validate(s); err != nil {
		return err
	}

	data, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return err
	}

	data = append(data, '\n')

	dir := filepath.Dir(path)

	f, err := os.CreateTemp(dir, ".sealix-trust-*")
	if err != nil {
		return err
	}

	temp := f.Name()

	defer os.Remove(temp)

	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}

	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}

	if err := f.Close(); err != nil {
		return err
	}

	if err = os.Rename(temp, path); err != nil {
		return err
	}

	if runtime.GOOS != "windows" {
		d, err := os.Open(dir)
		if err != nil {
			return err
		}
		defer d.Close()

		if err := d.Sync(); err != nil {
			return err
		}
	}

	return nil
}
