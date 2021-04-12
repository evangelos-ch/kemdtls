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
)

func (k KEM) String() string {
	switch k {
	case CLASSIC_MCELIECE_348864:
		return "Classic-McEliece-348864"
	case CLASSIC_MCELIECE_348864f:
		return "Classic-McEliece-348864f"
	default:
		return fmt.Sprintf("unknown(%v)", uint16(k))
	}
}

// The payload size of the KEM for the KeyShare in bytes
func (k KEM) PayloadSize() int {
	switch k {
	case CLASSIC_MCELIECE_348864:
		// TODO FIX THIS TO BE CORRECT
		return 4
	case CLASSIC_MCELIECE_348864f:
		// TODO FIX THIS TO BE CORRECT
		return 5
	default:
		return -1
	}
}

// KEMs returns all KEMs we implement
func KEMs() map[KEM]bool {
	return map[KEM]bool{
		CLASSIC_MCELIECE_348864:  true,
		CLASSIC_MCELIECE_348864f: true,
	}
}

func IsLibOQS(k KEM) bool {
	liboqs_kems := []KEM{CLASSIC_MCELIECE_348864, CLASSIC_MCELIECE_348864f}
	for _, kem := range liboqs_kems {
		if kem == k {
			return true
		}
	}
	return false
}

func LIBOQS_KEMS() []KEM {
	return []KEM{CLASSIC_MCELIECE_348864}
}

type Keypair struct {
	KEM        KEM
	PublicKey  []byte
	PrivateKey []byte
}

func GenerateKey(k KEM) (Keypair, error) {
	if IsLibOQS(k) {
		publicKey, privateKey, err := oqs.GetKeypair(k.String())
		if err != nil {
			return Keypair{0, nil, nil}, err
		}
		return Keypair{k, publicKey, privateKey}, nil
	} else {
		return Keypair{0, nil, nil}, errors.New("KEM not implemented.")
	}
}
