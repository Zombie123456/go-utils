package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type Decryptor interface {
	Decrypt(privateKey []byte, encrypted []byte) (data []byte, err error)
}

type decryptor struct {
}

func (d *decryptor) getPrivateInstance(blockBytes []byte) (*rsa.PrivateKey, error) {
	private, err := x509.ParsePKCS1PrivateKey(blockBytes)
	if err == nil {
		return private, nil
	}

	privateInterface, err := x509.ParsePKCS8PrivateKey(blockBytes)
	if err == nil {
		return privateInterface.(*rsa.PrivateKey), nil
	}
	return nil, errors.New("private key error")
}

func (d *decryptor) Decrypt(privateKey []byte, encrypted []byte) (data []byte, err error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("privateKey key format error")
	}
	private, err := d.getPrivateInstance(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, private, encrypted)
}

func NewDecryptor() Decryptor {
	return &decryptor{}
}
