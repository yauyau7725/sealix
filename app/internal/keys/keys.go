package keys

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yauyau7725/sealix/app/internal/sigalg"
)

func decodePEM(data []byte, label string) ([]byte, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("masukan bukan format PEM yang valid")
	}
	if block.Type != label {
		return nil, fmt.Errorf("label PEM tidak sesuai: mendapat %q, mengharapkan %q", block.Type, label)
	}
	if len(block.Headers) != 0 {
		return nil, errors.New("header PEM tidak diperbolehkan")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("terdapat data sisa setelah blok PEM")
	}
	return block.Bytes, nil
}

func ParsePublicPEM(data []byte) (crypto.PublicKey, sigalg.Algorithm, error) {
	der, err := decodePEM(data, "PUBLIC KEY")
	if err != nil {
		return nil, nil, err
	}

	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, nil, fmt.Errorf("gagal mengurai SPKI DER: %w", err)
	}

	alg, err := sigalg.ForKey(pub)
	if err != nil {
		return nil, nil, err
	}

	return pub, alg, nil
}

func ParsePrivatePEM(data []byte) (crypto.Signer, sigalg.Algorithm, error) {
	der, err := decodePEM(data, "PRIVATE KEY")
	if err != nil {
		return nil, nil, err
	}

	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, nil, fmt.Errorf("gagal mengurai PKCS#8 DER: %w", err)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("kunci privat tidak memenuhi interface crypto.Signer")
	}

	alg, err := sigalg.ForKey(signer.Public())
	if err != nil {
		return nil, nil, err
	}

	return signer, alg, nil
}

func MarshalPublicPEM(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("gagal mengekspor kunci publik ke SPKI DER: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), nil
}

func MarshalPrivatePEM(k crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, fmt.Errorf("gagal mengekspor kunci privat ke PKCS#8 DER: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}

func Fingerprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("gagal mengekspor kunci publik ke SPKI DER: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

func writeFileStrict(path string, data []byte, perm os.FileMode, force bool) error {
	flag := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flag = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}

	f, err := os.OpenFile(path, flag, perm)
	if err != nil {
		return err
	}

	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}

	return os.Chmod(path, perm)
}

func WriteKeyPair(prefix string, priv crypto.Signer, force bool) (string, error) {
	privPath := prefix + ".key.pem"
	pubPath := prefix + ".pub.pem"

	if !force {
		for _, p := range []string{privPath, pubPath} {
			if _, err := os.Stat(p); err == nil {
				return "", fmt.Errorf("berkas sudah ada: %s (gunakan --force untuk menimpa)", p)
			} else if !errors.Is(err, os.ErrNotExist) {
				return "", err
			}
		}
	}

	privPEM, err := MarshalPrivatePEM(priv)
	if err != nil {
		return "", err
	}
	pubPEM, err := MarshalPublicPEM(priv.Public())
	if err != nil {
		return "", err
	}
	fp, err := Fingerprint(priv.Public())
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(filepath.Dir(prefix), 0o755); err != nil {
		return "", err
	}

	if err := writeFileStrict(privPath, privPEM, 0o600, force); err != nil {
		return "", err
	}
	if err := writeFileStrict(pubPath, pubPEM, 0o644, force); err != nil {
		return "", err
	}

	return fp, nil
}
