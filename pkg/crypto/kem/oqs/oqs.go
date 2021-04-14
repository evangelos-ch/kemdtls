package oqs

import (
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func GetClient(algorithm string, privatekey []byte) (oqs.KeyEncapsulation, error) {
	client := oqs.KeyEncapsulation{}
	if err := client.Init(algorithm, privatekey); err != nil {
		return oqs.KeyEncapsulation{}, err
	}
	return client, nil
}

func GetKeypair(algorithm string) ([]byte, []byte, error) {
	client, err := GetClient(algorithm, nil)
	if err != nil {
		return nil, nil, err
	}
	publicKey, err := client.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	privateKey := client.ExportSecretKey()
	return publicKey, privateKey, nil
}

func Encapsulate(algorithm string, privateKey, publicKey []byte) (ciphertext []byte, sharedSecret []byte, err error) {
	client, err := GetClient(algorithm, privateKey)
	if err != nil {
		return nil, nil, err
	}
	return client.EncapSecret(publicKey)
}

func Decapsulate(algorithm string, privateKey, ciphertext []byte) (sharedSecret []byte, err error) {
	client, err := GetClient(algorithm, privateKey)
	if err != nil {
		return nil, err
	}
	return client.DecapSecret(ciphertext)
}
