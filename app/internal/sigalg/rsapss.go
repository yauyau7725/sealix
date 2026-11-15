package sigalg

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
)

type rsaPSS struct{}

var _ Algorithm = rsaPSS{}

func (rsaPSS) Name() string {
	return ProfileRSAPSS
}

func (rsaPSS) SigLen() int {
	return 384
}

func (rsaPSS) Generate() (crypto.Signer, error) {
	return rsa.GenerateKey(rand.Reader, 3072)
}

func (rsaPSS) CheckPublic(pub crypto.PublicKey) error {
	pk, ok := pub.(*rsa.PublicKey)
	if !ok || pk == nil || pk.N == nil {
		return errors.New("kunci publik bukan *rsa.PublicKey yang valid")
	}
	if pk.N.BitLen() != 3072 {
		return errors.New("panjang modulus RSA harus 3072 bit")
	}
	if pk.E != 65537 {
		return errors.New("eksponen publik RSA harus 65537")
	}
	return nil
}

func (rsaPSS) Sign(k crypto.Signer, msg []byte) ([]byte, error) {
	priv, ok := k.(*rsa.PrivateKey)
	if !ok || priv == nil || priv.N == nil {
		return nil, errors.New("jenis kunci privat bukan *rsa.PrivateKey yang valid")
	}
	if priv.N.BitLen() != 3072 || priv.E != 65537 {
		return nil, errors.New("parameter kunci RSA harus 3072-bit dengan eksponen 65537")
	}

	digest := sha256.Sum256(msg)
	return rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest[:], &rsa.PSSOptions{
		SaltLength: 32,
		Hash:       crypto.SHA256,
	})
}

func (r rsaPSS) Verify(pub crypto.PublicKey, msg, sig []byte) bool {
	if err := r.CheckPublic(pub); err != nil {
		return false
	}
	if len(sig) != 384 {
		return false
	}

	pk := pub.(*rsa.PublicKey)
	digest := sha256.Sum256(msg)
	err := rsa.VerifyPSS(pk, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{
		SaltLength: 32,
	})
	return err == nil
}
