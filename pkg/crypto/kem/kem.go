package kem

import (
	"errors"
	"fmt"

	"github.com/pion/dtls/v2/pkg/crypto/kem/oqs"
)

type KEM uint16

// KEM enums
const (
	CLASSIC_MCELIECE_348864  KEM = 0x001e
	CLASSIC_MCELIECE_348864f KEM = 0x001f
	SABER_FIRESABER          KEM = 0x0020
)

func (k KEM) String() string {
	switch k {
	case CLASSIC_MCELIECE_348864:
		return "Classic-McEliece-348864"
	case CLASSIC_MCELIECE_348864f:
		return "Classic-McEliece-348864f"
	case SABER_FIRESABER:
		return "FireSaber-KEM"
	default:
		return fmt.Sprintf("unknown(%v)", uint16(k))
	}
}

// The payload size of the KEM for the KeyShare in bytes
func (k KEM) PayloadSize() int {
	switch k {
	case CLASSIC_MCELIECE_348864:
		return 261120
	case CLASSIC_MCELIECE_348864f:
		// TODO FIX THIS TO BE CORRECT
		return 5
	case SABER_FIRESABER:
		return 1312
	default:
		return -1
	}
}

// KEMs returns all KEMs we implement
func KEMs() map[KEM]bool {
	return map[KEM]bool{
		CLASSIC_MCELIECE_348864:  false,
		CLASSIC_MCELIECE_348864f: false,
		SABER_FIRESABER:          true,
	}
}

func DefaultKEMs() []KEM {
	return []KEM{
		SABER_FIRESABER,
	}
}

func IsLibOQS(k KEM) bool {
	liboqs_kems := []KEM{CLASSIC_MCELIECE_348864, CLASSIC_MCELIECE_348864f, SABER_FIRESABER}
	for _, kem := range liboqs_kems {
		if kem == k {
			return true
		}
	}
	return false
}

type Keypair struct {
	PublicKey  []byte
	PrivateKey []byte
}

func GenerateKey(k KEM) (Keypair, error) {
	if IsLibOQS(k) {
		publicKey, privateKey, err := oqs.GetKeypair(k.String())
		if err != nil {
			return Keypair{nil, nil}, err
		}
		return Keypair{PublicKey: publicKey, PrivateKey: privateKey}, nil
	} else {
		return Keypair{nil, nil}, errors.New("KEM not implemented.")
	}
}

func Encapsulate(k KEM, localKeypair Keypair, publicKey []byte) ([]byte, []byte, error) {
	if IsLibOQS(k) {
		ciphertext, sharedSecret, err := oqs.Encapsulate(k.String(), localKeypair.PrivateKey, publicKey)
		if err != nil {
			return nil, nil, err
		}
		return ciphertext, sharedSecret, nil
	} else {
		return nil, nil, errors.New("KEM not implemented.")
	}
}

func Decapsulate(k KEM, localKeypair Keypair, ciphertext []byte) ([]byte, error) {
	if IsLibOQS(k) {
		sharedSecret, err := oqs.Decapsulate(k.String(), localKeypair.PrivateKey, ciphertext)
		if err != nil {
			return nil, err
		}
		return sharedSecret, nil
	} else {
		return nil, errors.New("KEM not implemented.")
	}
}
