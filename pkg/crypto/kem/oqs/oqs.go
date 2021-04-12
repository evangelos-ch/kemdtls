package oqs

import (
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func GetClient(algorithm string, privatekey []byte) (oqs.KeyEncapsulation, error) {
	client := oqs.KeyEncapsulation{}
	defer client.Clean()
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
