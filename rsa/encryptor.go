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

func (e *encryptor) getPubInstance(blockBytes []byte) (*rsa.PublicKey, error) {
	cert, err := x509.ParseCertificate(blockBytes)
	if err == nil {
		return cert.PublicKey.(*rsa.PublicKey), nil
	}

	pubInterface, err := x509.ParsePKIXPublicKey(blockBytes)
	if err == nil {
		return pubInterface.(*rsa.PublicKey), nil
	}

	pub, err := x509.ParsePKCS1PublicKey(blockBytes)
	if err == nil {
		return pub, nil
	}
	return nil, errors.New("public key error")

}

func (e *encryptor) Encryption(publicKey []byte, data []byte) (encrypted []byte, err error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("publicKey is not illegal")
	}

	pub, err := e.getPubInstance(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptPKCS1v15(rand.Reader, pub, data)
}

func NewEncryptor() Encryptor {
	return &encryptor{}
}
