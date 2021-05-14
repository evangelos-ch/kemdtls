package kem

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestKemEncapsDecaps(t *testing.T) {
	// var err error
	algorithm := SABER_FIRESABER
	serverKeypair, err := GenerateKey(algorithm)
	if err != nil {
		t.Error(err)
	}
	clientKeypair, err := GenerateKey(algorithm)
	if err != nil {
		t.Error(err)
	}
	serverCiphertext, sharedSecretServer, err := Encapsulate(algorithm, clientKeypair.PublicKey)
	if err != nil {
		t.Error(err)
	}
	clientCiphertext, sharedSecretClient, err := Encapsulate(algorithm, serverKeypair.PublicKey)
	if err != nil {
		t.Error(err)
	}
	sharedSecretServer2, err := Decapsulate(algorithm, clientKeypair, serverCiphertext)
	if err != nil {
		t.Error(err)
	}
	sharedSecretClient2, err := Decapsulate(algorithm, serverKeypair, clientCiphertext)

	ciphertext := ""

	for _, b := range clientKeypair.PublicKey {
		ciphertext += fmt.Sprintf("%#v,", b)
	}

	buf := []byte{0x0, 0x0}
	binary.BigEndian.PutUint16(buf, uint16(len(clientCiphertext)))
	fmt.Println("Actual length ", len(clientCiphertext))
	fmt.Printf("PublicKey % X \n", buf)

	isValidServer := bytes.Equal(sharedSecretServer2, sharedSecretServer)
	isValidClient := bytes.Equal(sharedSecretClient2, sharedSecretClient)
	if !isValidServer {
		t.Error("Server secret invalid.")
	}
	if !isValidClient {
		t.Error("Client secret invalid.")
	}
}
