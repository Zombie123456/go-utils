package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type Encryptor interface {
	Encryption(publicKey []byte, data []byte) (encrypted []byte, err error)
}

type encryptor struct {
}

func (e *encryptor) Encryption(publicKey []byte, data []byte) (encrypted []byte, err error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("publicKey is not illegal")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	pub := cert.PublicKey.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, data)
}

func NewEncryptor() Encryptor {
	return &encryptor{}
}
