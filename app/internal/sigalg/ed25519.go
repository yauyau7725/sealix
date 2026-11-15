package sigalg

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
)

type ed25519Alg struct{}

var _ Algorithm = ed25519Alg{}

func (ed25519Alg) Name() string {
	return ProfileEd25519
}

func (ed25519Alg) SigLen() int {
	return 64
}

func (ed25519Alg) Generate() (crypto.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func (ed25519Alg) CheckPublic(pub crypto.PublicKey) error {
	pk, ok := pub.(ed25519.PublicKey)
	if !ok {
		return errors.New("kunci publik bukan ed25519.PublicKey")
	}
	if len(pk) != ed25519.PublicKeySize {
		return errors.New("ukuran kunci publik Ed25519 harus 32 byte")
	}
	return nil
}

func (ed25519Alg) Sign(k crypto.Signer, msg []byte) ([]byte, error) {
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("jenis kunci privat bukan ed25519.PrivateKey")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("ukuran kunci privat Ed25519 tidak valid")
	}
	return ed25519.Sign(priv, msg), nil
}

func (e ed25519Alg) Verify(pub crypto.PublicKey, msg, sig []byte) bool {
	if err := e.CheckPublic(pub); err != nil {
		return false
	}
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	pk := pub.(ed25519.PublicKey)
	return ed25519.Verify(pk, msg, sig)
}
