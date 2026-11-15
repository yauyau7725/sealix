package manifest

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/FityatulhaqRosyidi/sealix/app/internal/jsonstrict"
	"github.com/FityatulhaqRosyidi/sealix/app/internal/result"
)

const (
	Schema          = "minisign-manifest/v1"
	MaxSize         = 16384
	MaxArtifactSize = 9007199254740991
)

var (
	packagePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	versionPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	artifactPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	hex64Pattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	algorithmPattern = regexp.MustCompile(`^[\x20\x21\x23-\x5B\x5D-\x7E]{1,64}$`)
)

type Artifact struct {
	Name   string
	Size   int64
	SHA256 string
}

type Manifest struct {
	Package   string
	Version   string
	Algorithm string
	KeyID     string
	Artifact  Artifact
}

func (m Manifest) Validate() error {
	if !packagePattern.MatchString(m.Package) {
		return fmt.Errorf("field package tidak valid: %q", m.Package)
	}
	if !versionPattern.MatchString(m.Version) {
		return fmt.Errorf("field version tidak valid: %q", m.Version)
	}
	if !algorithmPattern.MatchString(m.Algorithm) {
		return fmt.Errorf("field algorithm tidak valid: %q", m.Algorithm)
	}
	if !hex64Pattern.MatchString(m.KeyID) {
		return fmt.Errorf("field keyid tidak valid: %q", m.KeyID)
	}
	if !artifactPattern.MatchString(m.Artifact.Name) {
		return fmt.Errorf("field artifact.name tidak valid: %q", m.Artifact.Name)
	}
	if m.Artifact.Size < 0 || m.Artifact.Size > MaxArtifactSize {
		return fmt.Errorf("field artifact.size di luar rentang [0, %d]: %d", MaxArtifactSize, m.Artifact.Size)
	}
	if !hex64Pattern.MatchString(m.Artifact.SHA256) {
		return fmt.Errorf("field artifact.sha256 tidak valid: %q", m.Artifact.SHA256)
	}
	return nil
}

func (m Manifest) Serialize() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}

	out := fmt.Sprintf(
		`{"schema":%q,"package":%q,"version":%q,"algorithm":%q,"keyid":%q,"artifact":{"name":%q,"size":%d,"sha256":%q}}`,
		Schema,
		m.Package,
		m.Version,
		m.Algorithm,
		m.KeyID,
		m.Artifact.Name,
		m.Artifact.Size,
		m.Artifact.SHA256,
	)
	return []byte(out), nil
}

func ParseStrict(raw []byte) (Manifest, error) {
	if len(raw) > MaxSize {
		return Manifest{}, result.New(result.FormatError, fmt.Sprintf("ukuran manifest melebihi batas maksimal %d byte", MaxSize))
	}

	val, err := jsonstrict.Parse(raw)
	if err != nil {
		return Manifest{}, result.New(result.FormatError, err.Error())
	}

	root, err := val.Object()
	if err != nil {
		return Manifest{}, result.New(result.FormatError, "manifest harus berupa objek JSON")
	}

	if err := root.Exactly("schema", "package", "version", "algorithm", "keyid", "artifact"); err != nil {
		return Manifest{}, result.New(result.FormatError, err.Error())
	}

	schema, err := root.Values["schema"].String()
	if err != nil || schema != Schema {
		return Manifest{}, result.New(result.FormatError, "field schema tidak valid")
	}

	pkg, err := root.Values["package"].String()
	if err != nil {
		return Manifest{}, result.New(result.FormatError, "field package harus berupa string")
	}

	version, err := root.Values["version"].String()
	if err != nil {
		return Manifest{}, result.New(result.FormatError, "field version harus berupa string")
	}

	algorithm, err := root.Values["algorithm"].String()
	if err != nil {
		return Manifest{}, result.New(result.FormatError, "field algorithm harus berupa string")
	}

	keyID, err := root.Values["keyid"].String()
	if err != nil {
		return Manifest{}, result.New(result.FormatError, "field keyid harus berupa string")
	}

	artObj, err := root.Values["artifact"].Object()
	if err != nil {
		return Manifest{}, result.New(result.FormatError, "field artifact harus berupa objek")
	}

	if err := artObj.Exactly("name", "size", "sha256"); err != nil {
		return Manifest{}, result.New(result.FormatError, err.Error())
	}

	artName, err := artObj.Values["name"].String()
	if err != nil {
		return Manifest{}, result.New(result.FormatError, "field artifact.name harus berupa string")
	}

	artSize, err := artObj.Values["size"].Int()
	if err != nil {
		return Manifest{}, result.New(result.FormatError, fmt.Sprintf("field artifact.size tidak valid: %v", err))
	}

	artSHA256, err := artObj.Values["sha256"].String()
	if err != nil {
		return Manifest{}, result.New(result.FormatError, "field artifact.sha256 harus berupa string")
	}

	m := Manifest{
		Package:   pkg,
		Version:   version,
		Algorithm: algorithm,
		KeyID:     keyID,
		Artifact: Artifact{
			Name:   artName,
			Size:   artSize,
			SHA256: artSHA256,
		},
	}

	if err := m.Validate(); err != nil {
		return Manifest{}, result.New(result.FormatError, err.Error())
	}

	canonical, err := m.Serialize()
	if err != nil {
		return Manifest{}, result.New(result.FormatError, err.Error())
	}
	if !bytes.Equal(canonical, raw) {
		return Manifest{}, result.New(result.FormatError, "serialisasi manifest tidak kanonik")
	}

	return m, nil
}
