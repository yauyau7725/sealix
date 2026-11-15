package sigalg

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
)

const (
	ProfileRSAPSS  = "rsa-pss-sha256"
	ProfileECDSA   = "ecdsa-p256-sha2"
	ProfileEd25519 = "ed25519"
)

type Algorithm interface {
	Name() string
	SigLen() int
	Generate() (crypto.Signer, error)
	CheckPublic(pub crypto.PublicKey) error
	Sign(k crypto.Signer, msg []byte) ([]byte, error)
	Verify(pub crypto.PublicKey, msg, sig []byte) bool
}

var registry = map[string]Algorithm{
	ProfileRSAPSS:  rsaPSS{},
	ProfileECDSA:   ecdsaP256{},
	ProfileEd25519: ed25519Alg{},
}

func Lookup(name string) (Algorithm, bool) {
	alg, ok := registry[name]
	return alg, ok
}

func ForKey(pub crypto.PublicKey) (Algorithm, error) {
	var alg Algorithm
	switch pub.(type) {
	case *rsa.PublicKey:
		alg = rsaPSS{}
	case *ecdsa.PublicKey:
		alg = ecdsaP256{}
	case ed25519.PublicKey:
		alg = ed25519Alg{}
	default:
		return nil, fmt.Errorf("jenis kunci publik tidak didukung: %T", pub)
	}

	if err := alg.CheckPublic(pub); err != nil {
		return nil, err
	}
	return alg, nil
}
