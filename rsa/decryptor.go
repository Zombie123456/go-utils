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

func (d *decryptor) Decrypt(privateKey []byte, encrypted []byte) (data []byte, err error) {
	priBlock, _ := pem.Decode(privateKey)
	if priBlock == nil {
		return nil, errors.New("privateKey key format error")
	}
	priv, err := x509.ParsePKCS1PrivateKey(priBlock.Bytes) //解析pem.Decode（）返回的Block指针实例
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv, encrypted)
}

func NewDecryptor() Decryptor {
	return &decryptor{}
}
