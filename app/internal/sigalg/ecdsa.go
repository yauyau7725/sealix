package sigalg

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
)

type ecdsaP256 struct{}

var _ Algorithm = ecdsaP256{}

type ecdsaSig struct {
	R, S *big.Int
}

func (ecdsaP256) Name() string {
	return ProfileECDSA
}

func (ecdsaP256) SigLen() int {
	return 64
}

func (ecdsaP256) Generate() (crypto.Signer, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func (ecdsaP256) CheckPublic(pub crypto.PublicKey) error {
	pk, ok := pub.(*ecdsa.PublicKey)
	if !ok || pk == nil {
		return errors.New("kunci publik bukan *ecdsa.PublicKey yang valid")
	}
	if pk.Curve != elliptic.P256() {
		return errors.New("kurva kunci publik bukan P-256")
	}
	return nil
}

func (ecdsaP256) Sign(k crypto.Signer, msg []byte) ([]byte, error) {
	priv, ok := k.(*ecdsa.PrivateKey)
	if !ok || priv == nil {
		return nil, errors.New("jenis kunci privat bukan *ecdsa.PrivateKey yang valid")
	}
	if priv.Curve != elliptic.P256() {
		return nil, errors.New("kurva kunci privat bukan P-256")
	}

	digest := sha256.Sum256(msg)
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, err
	}

	var sig ecdsaSig
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("terdapat byte sisa setelah unmarshal DER")
	}

	out := make([]byte, 64)
	sig.R.FillBytes(out[:32])
	sig.S.FillBytes(out[32:])
	return out, nil
}

func (e ecdsaP256) Verify(pub crypto.PublicKey, msg, sig []byte) bool {
	if err := e.CheckPublic(pub); err != nil {
		return false
	}
	if len(sig) != 64 {
		return false
	}

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])

	der, err := asn1.Marshal(ecdsaSig{R: r, S: s})
	if err != nil {
		return false
	}

	pk := pub.(*ecdsa.PublicKey)
	digest := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(pk, digest[:], der)
}
