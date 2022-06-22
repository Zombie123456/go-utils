## RSA Utils

### Usage

- Encryptor
```go
encryptor := rsa.NewEncryptor()
data := []byte("dsdssd") // example data
publicKey := []byte("your public key")
sigend, err := encryptor.Encryption(data, publicKey)

```

- Decryptor
```go
decryptor := rsa.NewDecryptor()
sigend := []byte("encrypted data") 
privateKey := []byte("your private key")
data, err := decryptor.Decrypt(sigend, privateKey)
```